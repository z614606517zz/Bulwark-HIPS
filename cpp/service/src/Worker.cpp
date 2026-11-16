#include "bulwark/service/Worker.h"
#include "bulwark/service/InstallerDetect.h"
#include "bulwark/service/IpcServer.h"
#include "bulwark/service/EventSource.h"
#include "bulwark/service/RuleStore.h"
#include "bulwark/service/AuditLog.h"
#include "bulwark/service/FirstSeenStore.h"
#include "bulwark/service/QuarantineManager.h"
#include "bulwark/service/OccupiedFileAccess.h"
#include "bulwark/service/UserModeProcessContainment.h"
#include "bulwark/service/SystemHardening.h"
#include "bulwark/service/ThreatRemediator.h"
#include "bulwark/service/EventHistoryStore.h"
#include "bulwark/service/AlertExporter.h"
#include "bulwark/service/DurableExecBlockPolicy.h"
#include "bulwark/service/FilelessPolicy.h"
#include "bulwark/service/ResponsePolicy.h"
#include "bulwark/service/WorkerDurableExecBlockSeam.h"
#include "bulwark/service/monitoring/ProcessInspector.h"

#include <chrono>
#include <future>
#include "bulwark/service/monitoring/ProcessEnumerator.h"
#include "bulwark/service/monitoring/ProcessOriginResolver.h"
#include "bulwark/service/ServiceControlTracer.h"
#include "bulwark/engine/TrustPolicy.h"
#include "bulwark/engine/ThreatDetector.h"
#include "bulwark/engine/ScriptAnalyzer.h"
#include "bulwark/engine/SelfProtection.h"
#include "bulwark/engine/SystemPaths.h"

#include "bulwark/json/JsonSupport.h"

#include <QCoreApplication>
#include <QDateTime>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QStringDecoder>
#include <QJsonObject>
#include <QMutexLocker>

#include <optional>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QSysInfo>
#include <thread>
#include <chrono>
#include <QRegularExpression>
#include <windows.h>
#include <winioctl.h>
namespace bulwark::service {
using bulwark::VerdictAction;
using bulwark::VerdictSource;
using bulwark::SecurityEvent;
using bulwark::service::monitoring::ProcessInspector;
using bulwark::service::monitoring::ProcessOrigin;
using bulwark::service::monitoring::ProcessOriginResolver;
using bulwark::engine::TrustPolicy;

namespace {
constexpr int    kRecentDropWindowSecs = 5 * 60;
constexpr int    kMaxPendingPrompts    = 512;

using response_policy::isSessionCriticalImage;

bulwark::ipc::RemediationReportPayload makeRemediationPayload(
    const bulwark::SecurityEvent& e, const QString& reason, const RemediationReport& r) {
    bulwark::ipc::RemediationReportPayload p;
    p.timestampUtc = QDateTime::currentDateTimeUtc();
    p.actorPath = e.actorPath;
    p.actorPid = e.actorPid;
    p.reason = reason;
    p.actorQuarantined = r.quarantinedFiles.contains(e.actorPath, Qt::CaseInsensitive);
    p.quarantinedFiles = r.quarantinedFiles;
    p.removedRegistryValues = r.removedRegistryValues;
    p.skipped = r.skipped;
    return p;
}

int hardEvidenceSourceCount(const bulwark::SecurityEvent& e) {
    return e.hardEvidenceGroupCount();
}

bool isStandardInstallDir(const QString& path) {
    QString p = QDir::cleanPath(path.trimmed());
    p.replace(QLatin1Char('/'), QLatin1Char('\\'));
    p = p.toLower();
    if (p.isEmpty())
        return false;
    QStringList roots{
        qEnvironmentVariable("ProgramFiles"),
        qEnvironmentVariable("ProgramFiles(x86)"),
        qEnvironmentVariable("SystemRoot", QStringLiteral("C:/Windows")),
    };
    for (QString root : roots) {
        root = QDir::cleanPath(root.trimmed());
        root.replace(QLatin1Char('/'), QLatin1Char('\\'));
        root = root.toLower();
        if (!root.isEmpty() && p.startsWith(root + QLatin1Char('\\')))
            return true;
    }
    return false;
}

// 模块所在卷是否非固定(挂载的 ISO/VHD 或可移除盘)。银狐 2026 改用 .img/.vhd 容器投递绕过 MOTW:
// 模块从未在本机落地、也不是系统 DLL 名,前两条互证都认不出。
// 正规软件不会从挂载镜像或可移除卷加载私有模块,故作为第三条互证。
bool isNonFixedVolume(const QString& path) {
    QString p = path;
    p.replace(QLatin1Char('/'), QLatin1Char('\\'));
    // 只有带盘符的绝对路径才能取卷类型;UNC 与相对路径不判(避免误报)。
    if (p.size() < 3 || p.at(1) != QLatin1Char(':') || p.at(2) != QLatin1Char('\\'))
        return false;
    const QString root = p.left(3);
    const UINT type = ::GetDriveTypeW(reinterpret_cast<LPCWSTR>(root.utf16()));
    return type == DRIVE_CDROM || type == DRIVE_REMOVABLE;
}

// 原始磁盘 / 卷设备路径换成 CreateFile 能打开的形式;不是这类路径时返回空。
// 覆盖 \\.\PhysicalDriveN、\\.\E:、\Device\HarddiskN\DRN|Partition0、\Device\HarddiskVolumeN。
QString rawStorageDeviceOpenPath(const QString& target) {
    static const QRegularExpression win32Device(
        QStringLiteral(R"(^\\\\[.?]\\(physicaldrive\d+|[a-z]:)$)"),
        QRegularExpression::CaseInsensitiveOption);
    static const QRegularExpression ntDevice(
        QStringLiteral(R"(^(?:\\\\[.?]\\globalroot)?(\\device\\(?:harddisk\d+\\(?:dr\d+|partition0)|harddiskvolume\d+))$)"),
        QRegularExpression::CaseInsensitiveOption);
    QString t = target.trimmed();
    t.replace(QLatin1Char('/'), QLatin1Char('\\'));
    // 每个文件写入都会走到这里:普通文件路径先过滤掉,不跑正则。
    if (!t.startsWith(QLatin1String("\\\\")) && !t.startsWith(QLatin1String("\\device\\"), Qt::CaseInsensitive))
        return {};
    if (const QRegularExpressionMatch m = win32Device.match(t); m.hasMatch())
        return QStringLiteral("\\\\.\\") + m.captured(1);
    if (const QRegularExpressionMatch m = ntDevice.match(t); m.hasMatch())
        return QStringLiteral("\\\\?\\GLOBALROOT") + m.captured(1);
    return {};
}

// 设备是否为 U 盘、SD 卡、USB / 1394 硬盘等外接存储。打不开或查不到时按固定盘处理,不放宽。
bool isRemovableStorageDevice(const QString& target) {
    const QString openPath = rawStorageDeviceOpenPath(target);
    if (openPath.isEmpty())
        return false;
    // 只查属性,不申请读写权限。
    HANDLE h = ::CreateFileW(reinterpret_cast<LPCWSTR>(openPath.utf16()), 0,
                             FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
                             OPEN_EXISTING, 0, nullptr);
    if (h == INVALID_HANDLE_VALUE)
        return false;
    STORAGE_PROPERTY_QUERY query{};
    query.PropertyId = StorageDeviceProperty;
    query.QueryType = PropertyStandardQuery;
    alignas(STORAGE_DEVICE_DESCRIPTOR) unsigned char buf[1024] = {};
    DWORD bytes = 0;
    const BOOL ok = ::DeviceIoControl(h, IOCTL_STORAGE_QUERY_PROPERTY, &query, sizeof(query),
                                      buf, sizeof(buf), &bytes, nullptr);
    ::CloseHandle(h);
    if (!ok || bytes < sizeof(STORAGE_DEVICE_DESCRIPTOR))
        return false;
    const auto* desc = reinterpret_cast<const STORAGE_DEVICE_DESCRIPTOR*>(buf);
    return desc->RemovableMedia || desc->BusType == BusTypeUsb || desc->BusType == BusTypeSd
        || desc->BusType == BusTypeMmc || desc->BusType == BusType1394;
}

std::optional<monitoring::ProcessInspector::ProcessInstance>
expectedProcessInstance(const SecurityEvent& e) {
    if (e.actorPid <= 4 || !e.actorCreationFileTime.has_value()
        || *e.actorCreationFileTime == 0 || e.actorPath.trimmed().isEmpty())
        return std::nullopt;
    return monitoring::ProcessInspector::ProcessInstance{
        e.actorPid, *e.actorCreationFileTime, e.actorPath};
}

QString firstInstallerArg(const QString& cmdLine) {
    QStringList tokens;
    QString cur;
    bool inQuote = false;
    for (const QChar ch : cmdLine) {
        if (ch == QLatin1Char('"')) { inQuote = !inQuote; continue; }
        if (ch.isSpace() && !inQuote) { if (!cur.isEmpty()) { tokens << cur; cur.clear(); } continue; }
        cur += ch;
    }
    if (!cur.isEmpty()) tokens << cur;
    for (const QString& t : tokens) {
        const QString low = t.toLower();
        if (low.endsWith(QLatin1String(".msi")) || low.endsWith(QLatin1String(".msp")))
            return t;
    }
    return QString();
}
}

Worker::Worker(bulwark::engine::RuleEngine* engine, IpcServer* ipc, EventSource* source,
               RuleStore* ruleStore, AuditLog* audit, FirstSeenStore* firstSeen,
               QuarantineManager* quarantine,
               const bulwark::RuntimeSettings* settings, QObject* parent)
    : QObject(parent), engine_(engine), ipc_(ipc), ruleStore_(ruleStore), audit_(audit),
      firstSeen_(firstSeen), quarantine_(quarantine), settings_(settings) {
    if (quarantine)
        remediator_ = std::make_unique<ThreatRemediator>(*quarantine, Logger(QStringLiteral("Remediator")));
    source_ = source;
    connect(source, &EventSource::eventProduced, this, &Worker::onEvent);
    connect(ipc_, &IpcServer::promptResponse, this, &Worker::onPromptResponse);
    connect(ipc_, &IpcServer::promptAutoTimeout, this, &Worker::onPromptAutoTimeout);

    promptTimer_ = new QTimer(this);
    promptTimer_->setInterval(1000);
    connect(promptTimer_, &QTimer::timeout, this, &Worker::onPromptTimeoutTick);
    promptTimer_->start();

    taintPool_.setMaxThreadCount(1);
}

Worker::~Worker() {
    taintPool_.clear();
    taintPool_.waitForDone();
    sweepRunning_.store(false);
    if (sweepWorker_.joinable())
        sweepWorker_.join();
    preexistingRunning_.store(false);
    if (preexistingWorker_.joinable())
        preexistingWorker_.join();
}

QString Worker::describe(const SecurityEvent& e, VerdictAction action) const {
    QString act = action == VerdictAction::Block ? QString::fromUtf8("\xe6\x8b\xa6\xe6\x88\xaa")
                : action == VerdictAction::Ask   ? QString::fromUtf8("\xe8\xaf\xa2\xe9\x97\xae")
                                                 : QString::fromUtf8("\xe6\x94\xbe\xe8\xa1\x8c");
    if (e.kernelBlocked && action != VerdictAction::Block)
        act = QString::fromUtf8("\xe5\x86\x85\xe6\xa0\xb8\xe5\xb7\xb2\xe6\x8b\xa6")
            + QString::fromUtf8("\x28") + act + QString::fromUtf8("\x29");
    QString line = QStringLiteral("[%1] %2 %3 %4 -> %5 (%6 %7)")
        .arg(QDateTime::currentDateTime().toString(QStringLiteral("HH:mm:ss")),
             act, bulwark::eventTypeToString(e.type), e.actorPath, e.target,
             QString::fromUtf8("\xe9\xa3\x8e\xe9\x99\xa9"), QString::number(e.riskScore));
    if (action != VerdictAction::Allow && !e.matchedRuleNote.isEmpty())
        line += QStringLiteral(" [\xe8\xa7\x84\xe5\x88\x99: %1]").arg(e.matchedRuleNote);
    return line;
}

bool Worker::shouldLogAllow(const SecurityEvent& e, VerdictAction action, QString* summaryOut) {
    if (action != VerdictAction::Allow) return true;
    if (e.riskScore != 0) return true;
    if (e.hasThreatIndicator) return true;
    if (!e.matchedRuleNote.isEmpty()) return true;

    const QString key = e.actorPath.toLower() + QStringLiteral("|")
                      + QString::number(static_cast<int>(e.type));
    const qint64 nowMs = QDateTime::currentMSecsSinceEpoch();

    if (allowBursts_.size() > kAllowFoldMaxKeys && !allowBursts_.contains(key))
        allowBursts_.clear();

    auto it = allowBursts_.find(key);
    if (it == allowBursts_.end()) {
        AllowBurst b;
        b.firstMs = nowMs;
        allowBursts_.insert(key, b);
        return true;
    }

    AllowBurst& b = it.value();
    if (nowMs - b.firstMs >= kAllowFoldWindowMs) {
        if (b.folded > 0 && summaryOut) {
            *summaryOut = QString::fromUtf8("[%1] \xe5\xb7\xb2\xe6\x8a\x98\xe5\x8f\xa0 %2 "
                                            "\xe6\x9d\xa1\xe5\x90\x8c\xe7\xb1\xbb\xe9\x9b\xb6"
                                            "\xe9\xa3\x8e\xe9\x99\xa9\xe6\x94\xbe\xe8\xa1\x8c"
                                            "(%3 %4)\xef\xbc\x8c\xe7\xaa\x97\xe5\x8f\xa3 %5 "
                                            "\xe7\xa7\x92")
                .arg(QDateTime::currentDateTime().toString(QStringLiteral("HH:mm:ss")))
                .arg(QString::number(b.folded))
                .arg(bulwark::eventTypeToString(e.type))
                .arg(e.actorPath)
                .arg(QString::number((nowMs - b.firstMs) / 1000));
        }
        b.firstMs = nowMs;
        b.folded  = 0;
        return true;
    }

    ++b.folded;
    return false;
}

bool Worker::shouldRecordEvent(const SecurityEvent& e, QString* foldSummaryOut) {
    if (e.type != bulwark::EventType::SelfProtect)
        return true;

    const QString key = e.actorPath.toLower() + QStringLiteral("|")
                        + e.target.toLower() + QStringLiteral("|")
                        + QString::number(e.actorPid);
    const qint64 nowMs = QDateTime::currentMSecsSinceEpoch();
    const bool systemToolActor =
        e.actorSigned
        && (e.actorPublisher.contains(QLatin1String("Microsoft"), Qt::CaseInsensitive)
            || isStandardInstallDir(e.actorPath));
    const qint64 windowMs = systemToolActor ? kSelfProtectSystemToolFoldWindowMs
                                            : kSelfProtectFoldWindowMs;

    auto it = selfProtectBursts_.find(key);
    if (it == selfProtectBursts_.end()) {
        if (selfProtectBursts_.size() >= kAllowFoldMaxKeys)
            selfProtectBursts_.clear();
        SelfProtectBurst b;
        b.firstMs = nowMs;
        selfProtectBursts_.insert(key, b);
        return true;
    }

    SelfProtectBurst& b = it.value();
    if (nowMs - b.firstMs >= windowMs) {
        if (b.folded > 0 && foldSummaryOut) {
            *foldSummaryOut = QStringLiteral(
                "[%1] 已折叠 %2 条同类自我保护事件(%3 操作 %4),窗口 %5 秒")
                .arg(QDateTime::currentDateTime().toString(QStringLiteral("HH:mm:ss")))
                .arg(b.folded)
                .arg(e.actorPath)
                .arg(e.target)
                .arg((nowMs - b.firstMs) / 1000);
        }
        b.firstMs = nowMs;
        b.folded = 0;
        return true;
    }

    ++b.folded;
    return false;
}

void Worker::onEvent(const SecurityEvent& incoming) {
    processEvent(incoming);
}

void Worker::processEvent(const SecurityEvent& incoming) {
    SecurityEvent e = incoming;

    if (protectionSuspended_.load())
        return;

    if (settings_ && (!settings_->protectionEnabled || !isDimensionEnabled(e.type))) {
        QString offSummary;
        const bool emitOff = shouldLogAllow(e, VerdictAction::Allow, &offSummary);
        if (!offSummary.isEmpty())
            ipc_->sendLog(offSummary);
        if (emitOff)
            ipc_->sendLog(describe(e, VerdictAction::Allow));
        ipc_->sendEventLog(e, VerdictAction::Allow, VerdictSource::DefaultPolicy);
        writeAudit(e, VerdictAction::Allow, VerdictSource::DefaultPolicy);
        return;
    }

    if (e.actorPid > 0 && e.actorPid <= 4 && e.target.contains(QLatin1String("DoNotDelete"))) {
        log_.warning(QStringLiteral("诱饵命中但写入者被归因为 System(PID %1),事件源取证:type=%2 userModeObserved=%3 "
                                    "kernelBlocked=%4 fileCreatedNew=%5 originatorPid=%6 事件年龄=%7ms detail=[%8]")
                         .arg(e.actorPid)
                         .arg(static_cast<int>(e.type))
                         .arg(e.userModeObserved)
                         .arg(e.kernelBlocked)
                         .arg(e.fileCreatedNew)
                         .arg(e.originatorPid)
                         .arg(e.timestampUtc.isValid() ? e.timestampUtc.msecsTo(QDateTime::currentDateTimeUtc()) : -1)
                         .arg(e.detail));
    }

    enrich(e);

    chain_.record(e);
    e.chainContext = chain_.buildContext(e);
    const bulwark::Verdict v = engine_->evaluate(e);
    // 保留进入运行时策略层之前的裁决。后面的静默模式和安装管控都可能改动作；
    // 审计必须同时写原始裁决与最终动作，否则“默认放行理由 + action=Block”无从解释。
    const bulwark::Verdict policyInputVerdict = v;

    VerdictAction action = v.action;
    VerdictSource source = v.source;
    applySilentMode(e, action, source);

    // kernelBlocked 是已发生的权威事实:实际前拦优先于引擎 Allow。剥权事件的打开本身是成功的,
    // 系统组件 / 安全软件发起时照引擎的放行记录,否则任务管理器每看一眼本产品进程就记一次拦截。
    const bool benignRightsStrip =
        action == VerdictAction::Allow && response_policy::recordsRightsStripAsAllow(e);
    if (e.kernelBlocked && action != VerdictAction::Block && !benignRightsStrip) {
        action = VerdictAction::Block;
        source = VerdictSource::Heuristic;
    }

    const bool sideloadSuspect =
        !e.tamperedModulePath.isEmpty() || !e.sideloadedUnsignedModulePath.isEmpty();
    // 用户态 ImageLoad:模块自身也要有健康签名,签名宿主的信任才顺延给它。内核驱动加载(actorPid <= 0)
    // 不要改成判模块:那条路 actorSigned 恒假,BYOVD 名单的 Ask 档依赖这条降级永不触发。
    const bool imageLoadUnsignedModule =
        (e.type == bulwark::EventType::ImageLoad && e.actorPid > 0 &&
         !(e.targetSigned && !e.targetSignatureMismatch));
    if (action == VerdictAction::Ask && settings_ && settings_->trustSignedActors
        && e.actorSigned && !e.signatureMismatch && !e.certRevoked && !e.signedAfterCertExpiry
        && !sideloadSuspect && !e.hasThreatIndicator && !imageLoadUnsignedModule
        && !e.matchedRuleDisablesSignedAutoAllow
        && !(settings_->installControlEnabled && e.isInstaller)) {
        action = VerdictAction::Allow;
        source = VerdictSource::TrustedSigner;
        log_.info(QStringLiteral("已签名主体默认放行(信任签名,不弹询问):%1").arg(e.actorPath));
    } else if (action == VerdictAction::Ask && sideloadSuspect && settings_
               && settings_->trustSignedActors && e.actorSigned) {
        log_.warning(QStringLiteral("白加黑侧载嫌疑:主体签名健康,但不适用「已签名默认放行」,"
                                    "保留询问:%1").arg(e.actorPath));
    } else if (action == VerdictAction::Ask && e.hasThreatIndicator && settings_
               && settings_->trustSignedActors && e.actorSigned) {
        log_.warning(QStringLiteral("主体签名健康但带硬恶意指标(风险 %1),不适用「已签名默认放行」,"
                                    "保留询问:%2").arg(e.riskScore).arg(e.actorPath));
    } else if (action == VerdictAction::Ask && imageLoadUnsignedModule && settings_
               && settings_->trustSignedActors && e.actorSigned) {
        log_.warning(QStringLiteral("主体签名健康但加载的模块无健康签名,不适用「已签名默认放行」,"
                                    "保留询问:%1 -> %2").arg(e.actorPath, e.target));
    }

    if (settings_ && settings_->installControlEnabled && e.isInstaller
        && action == VerdictAction::Allow
        && source != VerdictSource::Rule
        && !e.userTrusted
        && !(engine_ && engine_->isSelfComponent(e))) {
        action = VerdictAction::Ask;
        source = VerdictSource::UserPrompt;
        if (e.matchedRuleNote.trimmed().isEmpty())
            e.matchedRuleNote = QStringLiteral("软件安装管控");
        e.addEvidence(QStringLiteral("软件安装管控"), bulwark::EvidenceKind::Info,
                      QStringLiteral("检测到软件安装程序运行,按设置向用户确认是否允许安装"),
                      0, true);
        log_.info(QStringLiteral("软件安装管控:检测到安装程序,转为询问用户是否允许安装:%1")
                      .arg(e.actorPath));
    }

    bulwark::EnforcementOutcome enforcement = bulwark::EnforcementOutcome::NotApplicable;
    switch (action) {
        case VerdictAction::Ask:
            enqueuePrompt(e, e.hasThreatIndicator && !(source_ && source_->wantsVerdict()));
            break;
        case VerdictAction::Block:
            {
                bool execBlocked = false;
                const bool usageRuleOnSignedActor =
                    v.source == VerdictSource::Rule && e.matchedRuleUsageOnly
                    && e.actorSigned && !e.signatureMismatch && !e.certRevoked
                    && !e.signedAfterCertExpiry;
                enforcement = enforceBlock(e, v.action == VerdictAction::Block
                                                  && !e.requiresTransientContainment()
                                                  && v.source != VerdictSource::Ai
                                                  && v.source != VerdictSource::SharedIntel
                                                  && !isTaintRuleNote(e.matchedRuleNote)
                                                  && !usageRuleOnSignedActor,
                                           &execBlocked);
                ipc_->sendBlock(e, enforcement, false, execBlocked);
            }
            maybeQuarantineOnBlock(e);
            {
                const bulwark::Verdict finalV =
                    action == v.action ? v : bulwark::Verdict::forEvent(e, action, source);
                remediateIfMalicious(e, finalV);
                if (!e.kernelBlocked || e.hasThreatIndicator) {
                    if (v.action == VerdictAction::Block) {
                        if (isDeterministicMaliciousBlock(e, finalV)) {
                            taintDroppedFiles(e, VerdictAction::Block,
                                              e.matchedRuleNote.isEmpty() ? QStringLiteral("引擎判定恶意")
                                                                          : e.matchedRuleNote);
                            maybeHandleLaunchingParent(e);
                        }
                    } else {
                        taintDroppedFiles(e, VerdictAction::Ask, QStringLiteral("静默模式升级拦截"));
                    }
                }
            }
            break;
        default:
            break;
    }
    if (source_ && source_->wantsVerdict() && action != VerdictAction::Ask)
        source_->submitVerdict(e, action);

    if (action != policyInputVerdict.action || source != policyInputVerdict.source) {
        e.addEvidence(QStringLiteral("WorkerPolicy"), bulwark::EvidenceKind::Info,
                      QStringLiteral("运行时策略覆盖：原始裁决 %1/%2，最终动作 %3/%4")
                          .arg(bulwark::verdictActionToString(policyInputVerdict.action),
                               bulwark::verdictSourceToString(policyInputVerdict.source),
                               bulwark::verdictActionToString(action),
                               bulwark::verdictSourceToString(source)),
                      0, true);
    }

    QString foldSummary;
    const bool emitLine = shouldLogAllow(e, action, &foldSummary);
    if (!foldSummary.isEmpty()) {
        ipc_->sendLog(foldSummary);
        log_.info(foldSummary);
    }
    if (emitLine) {
        const QString line = describe(e, action);
        ipc_->sendLog(line);
        log_.info(line);
    }
    QString selfFoldSummary;
    const bool recordEntry = shouldRecordEvent(e, &selfFoldSummary);
    if (!selfFoldSummary.isEmpty()) {
        ipc_->sendLog(selfFoldSummary);
        log_.info(selfFoldSummary);
    }
    if (recordEntry)
        recordEvent(e, action, source, enforcement);
    writeAudit(e, action, source, enforcement,
               policyInputVerdict.action, policyInputVerdict.source);
}

void Worker::applySilentMode(const SecurityEvent& e, VerdictAction& action,
                             VerdictSource& source) {
    if (action != VerdictAction::Ask || !settings_ || !settings_->silentMode)
        return;

    if (e.requiresTransientContainment()) {
        action = VerdictAction::Block;
        source = VerdictSource::Heuristic;
        const QString reason = e.ransomwareContainmentRequired
            ? QStringLiteral("勒索行为达到止损阈值")
            : QStringLiteral("高风险脚本执行达到止损阈值");
        log_.warning(QStringLiteral("静默模式:%1，收容本次主体（不写永久执行名单）:%2，风险 %3")
                         .arg(reason, e.actorPath).arg(e.riskScore));
        return;
    }
    const int hardSources = hardEvidenceSourceCount(e);
    const bool corroborated = hardSources >= 2;
    const bool explicitRuleHighRisk =
        !e.matchedRuleNote.trimmed().isEmpty()
        && e.matchedRuleIdentifiesSubject
        && e.riskScore >= bulwark::engine::ThreatDetector::HighRisk;
    const bool corroboratedHardRisk =
        e.hasThreatIndicator
        && e.riskScore >= bulwark::engine::ThreatDetector::Suspicious
        && corroborated;
    if (corroboratedHardRisk || explicitRuleHighRisk) {
        action = VerdictAction::Block;
        source = explicitRuleHighRisk ? VerdictSource::Rule : VerdictSource::Heuristic;
        log_.warning(QStringLiteral("静默模式:高置信询问升级为拦截(硬指标 %1 个来源%2 + 风险 %3):%4")
                         .arg(hardSources)
                         .arg(explicitRuleHighRisk ? QStringLiteral(" + 显式规则命中")
                                                  : QString())
                         .arg(e.riskScore).arg(e.actorPath));
    } else if (e.hasThreatIndicator
               && e.riskScore >= bulwark::engine::ThreatDetector::Suspicious) {
        action = VerdictAction::Allow;
        source = VerdictSource::DefaultPolicy;
        log_.warning(QStringLiteral("静默模式:硬指标只有 %1 个来源、风险 %2(高危线 %3),"
                                    "且无高风险显式规则,按静默放行并留痕(不升级为拦截 —— "
                                    "引擎对这一档的原始结论是『该问用户』):%4")
                         .arg(hardSources).arg(e.riskScore)
                         .arg(bulwark::engine::ThreatDetector::HighRisk)
                         .arg(e.actorPath));
    } else {
        QString pth = e.actorPath;
        pth.replace(QLatin1Char('/'), QLatin1Char('\\'));
        const QString pathLower = pth.toLower();
        const bool staging = pathLower.contains(QLatin1String("\\programdata\\"))
            || pathLower.contains(QLatin1String("\\appdata\\roaming\\config\\"))
            || pathLower.contains(QLatin1String("\\appdata\\roaming\\microsoft\\windows\\"));
        const bool tempDir = pathLower.contains(QLatin1String("\\appdata\\local\\temp\\"))
            || pathLower.contains(QLatin1String("\\windows\\temp\\"));
        if (e.isMemoryCarrierFinding() && !e.actorSigned && tempDir) {
            action = VerdictAction::Block;
            source = VerdictSource::Heuristic;
            log_.warning(QStringLiteral("静默模式:无文件内存形态升级为拦截(未签名 + Temp 下运行 + 风险 %1):%2")
                             .arg(e.riskScore).arg(e.actorPath));
        } else if (!e.actorSigned && staging
            && e.riskScore >= bulwark::engine::ThreatDetector::Suspicious) {
            action = VerdictAction::Block;
            source = VerdictSource::Heuristic;
            log_.warning(QStringLiteral("静默模式:投放器形态升级为拦截(未签名 + 暂存目录 + 风险 %1):%2")
                             .arg(e.riskScore).arg(e.actorPath));
        } else if (!e.actorSigned
                   && e.riskScore >= bulwark::engine::ThreatDetector::HighRisk) {
            action = VerdictAction::Allow;
            source = VerdictSource::DefaultPolicy;
            log_.warning(QStringLiteral("静默模式:纯软信号累计已达高危线(未签名、零硬指标、风险 %1,"
                                        "高危线 %2),按静默放行并留痕(不升级为拦截——没有「投放暂存"
                                        "目录」这类强先验撑底,软信号堆分不能当第二份硬证据):%3")
                             .arg(e.riskScore)
                             .arg(bulwark::engine::ThreatDetector::HighRisk)
                             .arg(e.actorPath));
        } else {
            action = VerdictAction::Allow;
            source = VerdictSource::DefaultPolicy;
        }
    }
}

void Worker::enqueuePrompt(const SecurityEvent& e, bool freezeWhilePending) {
    // 超量保护:先按默认策略收尾最旧的一条,再放新的进来。绝不静默丢弃 ——
    // 内核阻塞类事件靠这条回写才能放行/拦截,悄悄扔掉会让它永远等不到裁决。
    if (pending_.size() >= kMaxPendingPrompts) {
        QUuid oldestId;
        QDateTime oldest;
        for (auto it = pending_.constBegin(); it != pending_.constEnd(); ++it) {
            const QDateTime ts = it.value().event.timestampUtc;
            if (!oldest.isValid() || ts < oldest) { oldest = ts; oldestId = it.key(); }
        }
        const auto victim = pending_.find(oldestId);
        if (victim != pending_.end()) {
            const PendingPrompt old = victim.value();
            pending_.erase(victim);
            resolvePromptByDefault(
                old.event, QStringLiteral("待裁决队列已满(%1 条)").arg(kMaxPendingPrompts),
                false);
        }
    }
    const int timeoutSecs = settings_ ? settings_->promptTimeoutSeconds : 0;
    PendingPrompt p;
    p.event = e;
    if (timeoutSecs > 0)
        p.deadlineUtc = QDateTime::currentDateTimeUtc().addSecs(timeoutSecs);
    pending_.insert(e.id, p);
    if (containment_ && freezeOnDetect_ && freezeWhilePending && e.actorPid > 4) {
        containment_->freeze(e.actorPid, e.actorPath,
                             QStringLiteral("检出待裁决,弹窗期间冻结(风险 %1)")
                                 .arg(e.riskScore),
                             true);
    }
    ipc_->sendPrompt(e);
}

bool Worker::isDimensionEnabled(bulwark::EventType type) const {
    if (!settings_)
        return true;
    switch (type) {
        case bulwark::EventType::ProcessCreate:
        case bulwark::EventType::ProcessTerminate:
        case bulwark::EventType::RemoteThread:
        case bulwark::EventType::ImageLoad:
            return settings_->processProtection;
        case bulwark::EventType::FileWrite:
        case bulwark::EventType::FileDelete:
            return settings_->fileProtection;
        case bulwark::EventType::RegistryWrite:
            return settings_->registryProtection;
        case bulwark::EventType::SelfProtect:
            return settings_->selfProtection;
        case bulwark::EventType::NetworkConnect:
        case bulwark::EventType::DnsQuery:
            return settings_->networkProtection;
        default:
            return true;
    }
}

void Worker::rememberPromptDecided(const QUuid& id) {
    if (id.isNull() || decidedPrompts_.contains(id))
        return;
    decidedPrompts_.insert(id);
    decidedPromptsOrder_.enqueue(id);
    while (decidedPromptsOrder_.size() > kDecidedPromptMemory)
        decidedPrompts_.remove(decidedPromptsOrder_.dequeue());
}

void Worker::onPromptResponse(const QUuid& eventId, VerdictAction action,
                              bool remember, bulwark::RememberScope scope) {
    auto it = pending_.find(eventId);
    if (it == pending_.end()) {
        log_.warning(QStringLiteral("收到未在待裁决表中的 eventId 的裁决应答(已忽略):%1 "
                                    "—— 可能是超时/另一界面已先答,也可能是客户端乱答或探测")
                         .arg(eventId.toString(QUuid::WithoutBraces)));
        return;
    }
    const PendingPrompt pendingPrompt = it.value();
    SecurityEvent e = pendingPrompt.event;
    pending_.erase(it);
    // 记一笔「这条是人裁决的」:AI 的异步结论若随后才到,不得推翻用户的决定(见 decidedPrompts_)。
    rememberPromptDecided(eventId);

    log_.info(QStringLiteral("用户裁决: %1 -> %2%3")
                  .arg(e.actorPath, bulwark::verdictActionToString(action),
                       remember ? QStringLiteral(" (记住)") : QString()));

    if (remember && action != VerdictAction::Ask) {
        std::optional<QDateTime> expires;
        bool sessionOnly = false;
        const QDateTime now = QDateTime::currentDateTimeUtc();
        switch (scope) {
            case bulwark::RememberScope::Session:   sessionOnly = true; break;
            case bulwark::RememberScope::OneHour:   expires = now.addSecs(3600); break;
            case bulwark::RememberScope::OneDay:    expires = now.addSecs(86400); break;
            case bulwark::RememberScope::Permanent:
            default: break;
        }
        engine_->createRuleFrom(e, action, expires, sessionOnly);
        ruleStore_->save(engine_->getRules());
    }

    if (containment_ && action != VerdictAction::Block && e.actorPid > 4)
        containment_->thaw(e.actorPid, QStringLiteral("用户裁决为放行"));

    bulwark::EnforcementOutcome enforcement = bulwark::EnforcementOutcome::NotApplicable;
    if (action == VerdictAction::Block) {
        // 询问本身来自一条污点规则时,同 onEvent:不把它钉进内核持久名单(污点必须可被加白撤销)。
        bool execBlocked = false;
        const bool persistentBlacklist = !isTaintRuleNote(e.matchedRuleNote)
                                         && !e.requiresTransientContainment();
        enforcement = enforceBlock(e, persistentBlacklist, &execBlocked);
        ipc_->sendBlock(e, enforcement, false, execBlocked);
        maybeQuarantineOnBlock(e);
        remediateOnUserBlock(e);
        taintDroppedFiles(e, VerdictAction::Ask, QStringLiteral("用户选择阻止"));
    } else if (action == VerdictAction::Allow && isTaintRuleNote(e.matchedRuleNote)) {
        dropTaintRulesMatching(e);
    }
    if (source_ && source_->wantsVerdict())
        source_->submitVerdict(e, action);

    ipc_->sendLog(describe(e, action));
    recordEvent(e, action, VerdictSource::UserPrompt, enforcement);
    writeAudit(e, action, VerdictSource::UserPrompt, enforcement);
}

void Worker::onPromptTimeoutTick() {
    if (pending_.isEmpty())
        return;
    const QDateTime now = QDateTime::currentDateTimeUtc();

    QVector<PendingPrompt> expired;
    for (auto it = pending_.begin(); it != pending_.end(); ) {
        const QDateTime& deadline = it.value().deadlineUtc;
        if (deadline.isValid() && deadline <= now) {
            expired.append(it.value());
            it = pending_.erase(it);
        } else {
            ++it;
        }
    }
    for (const PendingPrompt& prompt : expired)
        resolvePromptByDefault(prompt.event, QStringLiteral("用户未在 %1 秒内裁决")
                                      .arg(settings_ ? settings_->promptTimeoutSeconds : 0),
                               true);
}

void Worker::onPromptAutoTimeout(const QUuid& eventId) {
    auto it = pending_.find(eventId);
    if (it == pending_.end()) {
        log_.info(QStringLiteral("界面倒计时到期:该询问已由服务端先行收尾,忽略(%1)")
                      .arg(eventId.toString(QUuid::WithoutBraces)));
        return;
    }
    const QDateTime deadline = it.value().deadlineUtc;
    if (!deadline.isValid() || deadline > QDateTime::currentDateTimeUtc().addSecs(5)) {
        log_.warning(QStringLiteral("界面报告倒计时到期,但服务端的 deadline 还没到(或没有 deadline),忽略(%1)")
                         .arg(eventId.toString(QUuid::WithoutBraces)));
        return;
    }
    const PendingPrompt pendingPrompt = it.value();
    pending_.erase(it);
    resolvePromptByDefault(pendingPrompt.event,
                           QStringLiteral("界面倒计时到期(用户未在 %1 秒内裁决)")
                               .arg(settings_ ? settings_->promptTimeoutSeconds : 0),
                           true);
}

void Worker::resolvePromptByDefault(const SecurityEvent& e, const QString& why,
                                    bool fromTimeout) {
    // 与用户裁决同一笔记账:这条已由策略收尾,AI 的事后结论不得再改它(见 decidedPrompts_)。
    rememberPromptDecided(e.id);

    const bool defaultBlock = settings_ && settings_->defaultBlock;
    const bool block = settings_ && (fromTimeout
        ? (e.requiresTransientContainment()
           || bulwark::promptTimeoutShouldBlock(*settings_, e.hasThreatIndicator, e.riskScore))
        : settings_->defaultBlock);
    const bool tierBlock = block && !defaultBlock;
    const VerdictAction action = block ? VerdictAction::Block : VerdictAction::Allow;

    const QString msg = e.requiresTransientContainment()
        ? QStringLiteral("弹窗超时 + 行为止损阈值 -> 自动收容本次主体（不写永久执行名单）(%1):%2")
              .arg(why, e.actorPath)
        : tierBlock
            ? QStringLiteral("弹窗超时 + 高风险(风险 %1 + 硬指标)-> 自动拦截(%2):%3")
                  .arg(e.riskScore).arg(why, e.actorPath)
            : QStringLiteral("弹窗超时按默认策略处置(%1):%2 -> %3")
                  .arg(why, e.actorPath,
                       block ? QStringLiteral("拦截") : QStringLiteral("放行"));
    log_.warning(msg);
    ipc_->sendLog(msg);

    if (containment_ && !block && e.actorPid > 4)
        containment_->thaw(e.actorPid, QStringLiteral("弹窗超时按默认策略放行"));

    bulwark::EnforcementOutcome enforcement = bulwark::EnforcementOutcome::NotApplicable;
    if (block) {
        bool execBlocked = false;
        enforcement = enforceBlock(e, false, &execBlocked);
        ipc_->sendBlock(e, enforcement, tierBlock, execBlocked);
        taintDroppedFiles(e, VerdictAction::Ask, QStringLiteral("弹窗超时按默认策略拦截"));
    }
    // 阻塞式源(内核驱动)必须收到回写,否则该操作在内核侧一直悬着。
    if (source_ && source_->wantsVerdict())
        source_->submitVerdict(e, action);

    recordEvent(e, action, VerdictSource::Timeout, enforcement);
    writeAudit(e, action, VerdictSource::Timeout, enforcement);
}

void Worker::enrich(SecurityEvent& e) {
    if (e.type == bulwark::EventType::RegistryWrite && e.actorPid > 0
        && ServiceControlTracer::isServiceDatabaseKey(e.target)) {
        const ServiceOriginator orig = ServiceControlTracer::trace(e.actorPid);
        // 仅高置信唯一候选才改写主体,否则保守留 SCM —— 绝不据此去结束 services.exe。
        if (orig.highConfidence()) {
            e.actorPid = orig.originatorPid;
            e.actorPath = orig.originatorPath;
            e.detail += QStringLiteral(" · 真凶溯源:%1(PID %2)")
                            .arg(QFileInfo(orig.originatorPath).fileName())
                            .arg(orig.originatorPid);
        }
    }

    if ((e.actorPath.isEmpty() || e.actorPath.startsWith(QLatin1String("PID "), Qt::CaseInsensitive))
        && e.actorPid > 0) {
        QString resolved = ProcessInspector::tryGetProcessImagePath(e.actorPid);
        if (resolved.isEmpty())
            resolved = chain_.lastKnownPath(e.actorPid);
        if (!resolved.isEmpty()) {
            e.actorPath = resolved;
            if (e.target.isEmpty() || e.target.startsWith(QLatin1String("PID "), Qt::CaseInsensitive))
                e.target = resolved;
        }
    }

    if (e.commandLine.isEmpty() && e.actorPid > 0)
        e.commandLine = ProcessInspector::tryGetCommandLine(e.actorPid);

    if (e.parentPath.isEmpty() && e.parentPid > 0)
        e.parentPath = ProcessInspector::tryGetProcessImagePath(e.parentPid);

    if (e.type == bulwark::EventType::ProcessCreate && e.creatorPid > 4 && e.creatorPid != e.parentPid
        && e.creatorPid != e.actorPid)
        attributeSpoofedParent(e);

    const bool selfComponent = engine_ && engine_->isSelfComponent(e);

    const std::optional<QString> enrichTrustNote =
        (engine_ && !selfComponent) ? engine_->trustNoteForEvent(e) : std::nullopt;
    if (enrichTrustNote.has_value())
        e.userTrusted = true;
    const bool skipForensics = selfComponent || enrichTrustNote.has_value();

    if (e.actorPid > 0 && !skipForensics) {
        const ProcessOrigin origin =
            ProcessOriginResolver::resolve(e.actorPid, e.actorPath, e.parentPid, e.commandLine);
        if (origin.resolved()) {
            e.originKind = origin.kind;
            e.originService = origin.serviceName;
            e.originServiceDisplay = origin.serviceDisplayName;
            e.originTask = origin.taskPath;
            e.originDetail = origin.detail;
            if (origin.kind == bulwark::ProcessOriginKind::Service
                || origin.kind == bulwark::ProcessOriginKind::ScheduledTask) {
                e.addEvidence(QStringLiteral("启动来源"), bulwark::EvidenceKind::Info,
                              QStringLiteral("%1%2")
                                  .arg(e.originLabel(),
                                       origin.detail.isEmpty()
                                           ? QString()
                                           : QStringLiteral("(%1)").arg(origin.detail)),
                              0, false);
            }
        }
    }

    if (!skipForensics)
        seedAncestryChain(e);

    if (e.type == bulwark::EventType::ProcessCreate && !s_productSignerThumbprint.isEmpty()
        && bulwark::engine::SelfProtection::enabled.load(std::memory_order_relaxed)
        && !e.commandLine.isEmpty()
        && bulwark::engine::SelfProtection::commandTargetsProduct(e.commandLine)) {
        e.productSignedAncestor = hasProductSignedAncestor(e);
        if (e.productSignedAncestor)
            log_.info(QStringLiteral("自保护告警:祖先进程是本产品自己签名的程序(证书指纹相同),"
                                     "该『停止/删除本产品』命令按维护操作放行:%1").arg(e.commandLine.left(160)));
    }

    if (e.type == bulwark::EventType::ImageLoad) {
        const QString mod = e.target.trimmed();
        if (!mod.isEmpty() && !mod.startsWith(QLatin1String("PID "), Qt::CaseInsensitive)) {
            const ProcessInspector::ForensicFacts mf =
                ProcessInspector::collectForensics(mod, false);
            e.targetSigned = mf.trustedSignature;
            if (!e.targetSigned)
                e.targetSignatureMismatch = mf.embeddedSignature;
            e.addEvidence(QStringLiteral("模块签名"), bulwark::EvidenceKind::Info,
                          e.targetSigned
                              ? (mf.publisher.isEmpty()
                                     ? QStringLiteral("被加载模块持有可信签名")
                                     : QStringLiteral("被加载模块持有可信签名:%1").arg(mf.publisher))
                              : (e.targetSignatureMismatch
                                     ? QStringLiteral("被加载模块内嵌签名但校验不过(篡改 / 盗用证书)")
                                     : QStringLiteral("被加载模块没有可信签名")),
                          0, false);
        }
    }

    if (e.type == bulwark::EventType::FileWrite && isRemovableStorageDevice(e.target)) {
        e.targetOnRemovableMedia = true;
        e.addEvidence(QStringLiteral("磁盘类型"), bulwark::EvidenceKind::Info,
                      QStringLiteral("直接写入的磁盘是 U 盘 / SD 卡 / USB 硬盘等外接存储"), 0, false);
    }

    const QString path = e.actorPath;
    if (path.isEmpty() || path.startsWith(QLatin1String("PID "), Qt::CaseInsensitive)) {
        e.actorSigned = false;
        return;
    }

    const ProcessInspector::ForensicFacts facts =
        ProcessInspector::collectForensics(path, !selfComponent);

    e.actorSigned    = facts.trustedSignature;
    e.actorPublisher = facts.publisher;
    e.actorHash      = facts.sha256;
    if (!e.actorSigned) {
        e.signatureMismatch = facts.embeddedSignature;
        e.signatureTampered = facts.signatureDigestMismatch;
    }

    if (skipForensics)
        return;

    const ProcessInspector::CertInfo& ci = facts.cert;
    if (!ci.thumbprint.isEmpty())    e.actorCertThumbprint = ci.thumbprint;
    if (ci.notAfterUtc.isValid())    e.certNotAfterUtc     = ci.notAfterUtc;
    if (ci.signingTimeUtc.isValid()) e.signingTimeUtc      = ci.signingTimeUtc;
    e.certRevoked           = ci.revoked;
    e.signedAfterCertExpiry = ci.signedAfterCertExpiry;

    detectSideloadedTamperedModule(e);

    scanScriptFileBody(e);

    if (facts.isRealFile)
        e.actorFileSize = facts.fileSize;

    if (firstSeen_ && !e.actorHash.isEmpty())
        e.isFirstSeen = firstSeen_->markAndCheckFirstSeen(e.actorHash);

    if (e.type == bulwark::EventType::ProcessCreate) {
        QString installName;
        if (bulwark::service::looksLikeInstaller(e, &installName)) {
            e.isInstaller = true;
            if (e.fileDescription.trimmed().isEmpty() && !installName.isEmpty())
                e.fileDescription = installName;
        }
        e.originalFileName = originalFileNameCached(e.actorPath);
        // 只认盘符路径、所在目录还在、进程仍在运行且系统报告的映像就是这个路径:
        // 设备路径换算失败、进程已经退出都不判。
        if (!facts.isRealFile && path.size() > 3 && path.at(1) == QLatin1Char(':')
            && QFileInfo(QFileInfo(path).absolutePath()).isDir()) {
            const QString live = ProcessInspector::tryGetProcessImagePath(e.actorPid);
            e.actorImageMissing = !live.isEmpty() && QDir::cleanPath(live).compare(QDir::cleanPath(path),
                                                                                   Qt::CaseInsensitive) == 0;
        }
    }
}

// 父进程可以在 CreateProcess 时任意指定。真实创建者是系统代办(UAC 提权、runas、服务 / WMI 宿主)时
// 那是代办的正常做法;否则把父进程换成真实创建者,父子关系规则与连带处置都落到真正的发起者身上。
void Worker::attributeSpoofedParent(bulwark::SecurityEvent& e) {
    QString creatorPath = ProcessInspector::tryGetProcessImagePath(e.creatorPid);
    if (creatorPath.isEmpty())
        creatorPath = chain_.lastKnownPath(e.creatorPid);
    if (creatorPath.isEmpty() || bulwark::engine::TrustPolicy::isProcessCreationBroker(creatorPath))
        return;
    e.spoofedParentPid = e.parentPid;
    e.spoofedParentPath = e.parentPath;
    e.parentPid = e.creatorPid;
    e.parentPath = creatorPath;
}

QString Worker::originalFileNameCached(const QString& path) {
    if (path.isEmpty() || path.startsWith(QLatin1String("PID "), Qt::CaseInsensitive))
        return QString();
    const QFileInfo fi(path);
    if (!fi.isFile())
        return QString();
    const QString key = path.toLower() + QLatin1Char('|') + QString::number(fi.size()) + QLatin1Char('|')
                      + QString::number(fi.lastModified().toMSecsSinceEpoch());
    const auto cached = originalNameCache_.constFind(key);
    if (cached != originalNameCache_.constEnd())
        return cached.value();
    constexpr int kMaxCache = 4096;
    if (originalNameCache_.size() >= kMaxCache)
        originalNameCache_.clear();
    const QString name = bulwark::service::originalFileNameOutsideInstallDirs(path);
    originalNameCache_.insert(key, name);
    return name;
}

bool Worker::hasProductSignedAncestor(const SecurityEvent& e) const {
    if (s_productSignerThumbprint.isEmpty())
        return false;
    constexpr int kMaxHops = 4;
    QSet<int> visited;
    int pid = e.parentPid;
    for (int hop = 0; hop < kMaxHops && pid > 4 && !visited.contains(pid); ++hop) {
        visited.insert(pid);
        const QString path = ProcessInspector::tryGetProcessImagePath(pid);
        // 取不到映像(祖先已退出 / 无权限)-> 到此为止,不豁免。绝不凭 PID 或名字猜。
        if (path.isEmpty())
            return false;
        if (ProcessInspector::isSigned(path)
            && ProcessInspector::tryGetSignerThumbprint(path)
                   .compare(s_productSignerThumbprint, Qt::CaseInsensitive) == 0)
            return true;
        pid = ProcessInspector::tryGetParentPid(pid);
    }
    return false;
}

void Worker::seedAncestryChain(SecurityEvent& e) {
    QSet<int> existingPids;
    for (const bulwark::ChainEventInfo& c : e.chainContext)
        if (c.actorPid > 0)
            existingPids.insert(c.actorPid);

    QSet<int> visited;
    int cur = e.actorPid;
    int depth = 0;
    QVector<bulwark::ChainEventInfo> seeded;
    while (cur > 0 && depth < 16 && !visited.contains(cur)) {
        visited.insert(cur);
        const int parent = (cur == e.actorPid && e.parentPid > 0)
                               ? e.parentPid
                               : ProcessInspector::tryGetParentPid(cur);
        if (!existingPids.contains(cur)) {
            const QString curPath = (cur == e.actorPid)
                                        ? e.actorPath
                                        : ProcessInspector::tryGetProcessImagePath(cur);
            if (cur == e.actorPid || !curPath.isEmpty()) {
                bulwark::ChainEventInfo node;
                node.timestampUtc = e.timestampUtc.isValid() ? e.timestampUtc
                                                             : QDateTime::currentDateTimeUtc();
                node.type = e.type;
                node.actorPid = cur;
                node.parentPid = parent;
                node.actorPath = curPath;
                node.target = (cur == e.actorPid) ? e.target : QString();
                node.riskScore = (cur == e.actorPid) ? e.riskScore : 0;
                if (cur == e.actorPid) {
                    node.originKind = e.originKind;
                    node.originLabel = e.originLabel();
                } else if (depth <= 6) {
                    const ProcessOrigin anc =
                        ProcessOriginResolver::resolve(cur, curPath, parent, QString());
                    if (anc.resolved()) {
                        node.originKind = anc.kind;
                        bulwark::SecurityEvent tmp;
                        tmp.originKind = anc.kind;
                        tmp.originService = anc.serviceName;
                        tmp.originServiceDisplay = anc.serviceDisplayName;
                        tmp.originTask = anc.taskPath;
                        node.originLabel = tmp.originLabel();
                    }
                }
                seeded.append(node);
            }
        }
        if (parent <= 0)
            break;
        cur = parent;
        ++depth;
    }
    if (!seeded.isEmpty())
        e.chainContext += seeded;
}

bool Worker::killMalicious(int pid) {
    if (pid <= 4)
        return false;
    if (!ProcessInspector::enumeratePids().contains(pid)) {
        log_.warning(QStringLiteral("处置中止:PID=%1 在当前进程快照里不存在 —— 该事件很可能没有"
                                    "归因到真实发起进程(用户态行为源在无法归因时会填合成 PID)。"
                                    "【没有可结束的进程】,本次不下发内核封禁、不做任何处置,"
                                    "也不报告「已终结」。")
                         .arg(pid));
        return false;
    }
    const QString img = ProcessInspector::tryGetProcessImagePath(pid);

    if (isSessionCriticalImage(img)) {
        log_.critical(QStringLiteral(
            "处置中止:PID=%1 是会话/系统基础设施进程(%2)—— 结束、封禁、冻结、断子这四种手段"
            "对它的后果都是毁掉用户会话或操作系统本身,一律不执行。本次【只告警,未做任何处置】,"
            "需要人工判断(该进程若确实被注入/打补丁,正确的做法是人工重启外壳或该服务,"
            "而不是由本产品把它杀掉)。")
                          .arg(pid).arg(img));
        return false;
    }

    // 结束前取根进程的创建时间:退出后就取不到了,而排队事件要靠它认出「是本产品结束的那个实例」。
    const std::optional<ProcessInspector::ProcessInstance> rootInstance =
        ProcessInspector::tryGetProcessInstance(pid);
    const quint64 rootCreation =
        rootInstance && rootInstance->imagePath.compare(img, Qt::CaseInsensitive) == 0
            ? rootInstance->creationFileTime
            : 0;

    const bool banned = source_ && source_->banProcess(pid);
    if (containment_) {
        containment_->freeze(pid, img, QStringLiteral("已确认恶意,处置前冻结"), false);
        containment_->cutOffChildren(pid, true, QStringLiteral("已确认恶意,处置前断子"));
    }
    QList<ProcessInspector::ProcessInstance> endedInTree;
    const int killed = ProcessInspector::terminateProcessTree(pid, &endedInTree);
    const bool kkill = source_ && source_->killProcess(pid);
    // 随整树一起结束的后代也要记:它们排队中的事件随后到达时,应记「主体已结束」而不是「仅告警」。
    for (const ProcessInspector::ProcessInstance& child : std::as_const(endedInTree)) {
        if (child.pid != pid)
            rememberTerminated(child.pid, child.imagePath, child.creationFileTime);
    }

    const bool gone = ProcessInspector::waitForExit(pid, 300);
    if (gone) {
        log_.info(QStringLiteral("恶意进程终结:PID=%1(用户态结束 %2 个%3)。")
                      .arg(pid).arg(killed)
                      .arg(kkill ? QStringLiteral(" + 驱动级内核结束") : QString()));
        rememberTerminated(pid, img, rootCreation);
        return true;
    }

    QStringList held;
    if (banned)
        held << QStringLiteral("已封禁主体(内核对其文件/注册表/网络/子进程一律拒绝)");
    if (containment_) {
        if (containment_->isFrozen(pid))
            held << QStringLiteral("已冻结(全部线程挂起,不再有新动作;在界面加白即可解除)");
        if (containment_->isChildrenCutOff(pid))
            held << QStringLiteral("已断子(无法再创建子进程)");
    }
    log_.warning(QStringLiteral("恶意进程未能终结:PID=%1 仍在运行(用户态结束 %2 个,内核结束命令%3)。"
                                "关键进程护栏=%4,映像=%5。已施加的收容:%6")
                     .arg(pid).arg(killed)
                     .arg(kkill ? QStringLiteral("已受理") : QStringLiteral("未受理"))
                     .arg(ProcessInspector::isCriticalProcess(pid) ? QStringLiteral("命中(按此判定不予结束)")
                                                                   : QStringLiteral("未命中"))
                     .arg(ProcessInspector::tryGetProcessImagePath(pid))
                     .arg(held.isEmpty()
                              ? QStringLiteral("【无】—— 本次处置实际没有对该进程起到任何作用,"
                                               "需要人工处理")
                              : held.join(QStringLiteral(";"))));
    return false;
}

bool Worker::blacklistExec(const DurableExecBlockAuthorization& authorization) {
    if (!source_)
        return false;
    QString p = authorization.imagePath().trimmed();
    if (p.isEmpty())
        return false;
    const bool looksPath =
        (p.size() >= 2 && p[1] == QLatin1Char(':')) || p.startsWith(QLatin1Char('\\'));
    if (!looksPath)
        return false;
    if (const std::optional<QString> note = engine_->trustNoteForPath(p)) {
        log_.info(QStringLiteral("执行前拦截已跳过(该主体已加白:%1):%2").arg(*note, p));
        return false;
    }
    if (isSweepExemptPath(p)) {
        log_.info(QStringLiteral("执行前拦截已跳过(系统目录 / 本产品自身,拦的是用法而非文件):%1").arg(p));
        return false;
    }
    {
        QString rel = p.toLower();
        rel.replace(QLatin1Char('/'), QLatin1Char('\\'));
        if (rel.size() >= 2 && rel.at(1) == QLatin1Char(':'))
            rel = rel.mid(2);
        if (rel.startsWith(QStringLiteral("\\windows\\microsoft.net\\")) ||
            rel.startsWith(QStringLiteral("\\program files\\powershell\\")) ||
            rel.startsWith(QStringLiteral("\\program files (x86)\\powershell\\")) ||
            (rel.startsWith(QStringLiteral("\\program files")) &&
             rel.contains(QStringLiteral("\\microsoft visual studio\\")) &&
             rel.endsWith(QStringLiteral("\\msbuild.exe")))) {
            log_.info(QStringLiteral("执行前拦截已跳过(.NET / PowerShell 系统级宿主,拦的是用法而非文件):%1").arg(p));
            return false;
        }
        // Windows 根目录下的系统程序与新版 WSL 不在 System32,isSweepExemptPath 覆盖不到;
        // 封住它们等于让注册表编辑器、帮助查看器、WSL 跨重启都打不开。
        static const QSet<QString> kWindowsRootHosts = {
            QStringLiteral("\\windows\\regedit.exe"),  QStringLiteral("\\windows\\hh.exe"),
            QStringLiteral("\\windows\\explorer.exe"), QStringLiteral("\\windows\\notepad.exe"),
            QStringLiteral("\\windows\\splwow64.exe"), QStringLiteral("\\windows\\write.exe"),
            QStringLiteral("\\windows\\helppane.exe"), QStringLiteral("\\windows\\winhlp32.exe"),
            QStringLiteral("\\windows\\bfsvc.exe"),
        };
        if (kWindowsRootHosts.contains(rel) || rel.startsWith(QStringLiteral("\\program files\\wsl\\"))) {
            log_.info(QStringLiteral("执行前拦截已跳过(Windows 根目录系统程序 / WSL,拦的是用法而非文件):%1").arg(p));
            return false;
        }
    }
    QString needle = p;
    if (needle.size() >= 2 && needle[1] == QLatin1Char(':'))
        needle = needle.mid(2);
    if (needle.size() < 6)
        return false;
    bool denied = false;
    if (source_->blockExecPath(needle)) {
        log_.info(QStringLiteral("执行前拦截:已把恶意映像加入内核禁止执行名单(下次启动将被内核前拦):%1").arg(p));
        denied = true;
    }

    if (hardening_ && denyExecuteEnabled_) {
        if (hardening_->denyExecute(p) || hardening_->hasDenyExecute(p))
            denied = true;
    }
    return denied;
}

bool Worker::denyExecuteRevocable(const QString& imagePath, const QString& why) {
    QString p = imagePath.trimmed();
    if (p.isEmpty())
        return false;
    const bool looksPath =
        (p.size() >= 2 && p[1] == QLatin1Char(':')) || p.startsWith(QLatin1Char('\\'));
    if (!looksPath)
        return false;
    if (const std::optional<QString> note = engine_->trustNoteForPath(p)) {
        log_.info(QStringLiteral("可撤销执行前拦截已跳过(该主体已加白:%1):%2").arg(*note, p));
        return false;
    }
    if (isSweepExemptPath(p)) {
        log_.info(QStringLiteral("可撤销执行前拦截已跳过(系统目录 / 本产品自身,拦的是用法而非文件):%1")
                      .arg(p));
        return false;
    }
    if (!QFileInfo::exists(p))
        return false;
    if (!hardening_) {
        log_.warning(QStringLiteral("【未做到执行前拦截】加固器不可用,%1 只做了事后结束进程 —— "
                                    "该映像再次被双击时仍会先运行起来:%2").arg(why, p));
        return false;
    }
    if (!denyExecuteEnabled_) {
        log_.warning(QStringLiteral("【未做到执行前拦截】%1。污点结论是关联推导而不是文件确认，"
                                    "且 FileDenyExecuteEnabled=false，因此不写跨重启拒绝执行 ACE。"
                                    "本次只做事后结束进程；该映像再次启动时仍可能先运行再被拦:%2。"
                                    "如需对所有此类拦截写 ACE，可显式启用 FileDenyExecuteEnabled；"
                                    "该 ACL 会跨重启并在卸载后保留，误判代价较高。")
                         .arg(why, p));
        return false;
    }
    if (hardening_->hasDenyExecute(p))
        return true;
    if (hardening_->denyExecute(p)) {
        const QString msg =
            QStringLiteral("执行前拦截(可撤销):已对 %1 加「拒绝执行」ACE —— 下次双击直接失败"
                           "(错误 5),不再先运行起来。原因:%2。撤销:在界面加白该程序即自动移除;"
                           "注意 ACE 不随污点规则到期而消失,且复制一份副本可绕过。")
                .arg(p, why);
        log_.warning(msg);
        ipc_->sendLog(msg);
        return true;
    }
    return false;
}

bool Worker::abortIfTrustedNow(const SecurityEvent& e, const QString& stage) {
    const std::optional<QString> note = engine_->trustNoteForPath(e.actorPath);
    if (!note)
        return false;
    const QString msg = QStringLiteral("%1 已确认恶意,但该主体此刻已被加白(%2)—— 按信任语义放弃处置:%3")
                            .arg(stage, *note, e.actorPath);
    log_.info(msg);
    ipc_->sendLog(msg);
    return true;
}

std::pair<bool, QString> Worker::forceQuarantine(const QString& path) {
    if (!remediator_)
        return { false, QStringLiteral("清理器不可用(隔离区未就绪)") };

    const QString p = path.trimmed();
    if (p.isEmpty())
        return { false, QStringLiteral("未提供文件路径") };

    if (isSweepExemptPath(p))
        return { false, QStringLiteral("拒绝隔离:该路径属于系统目录或本产品自身,隔离它会破坏系统或防护自身") };
    if (ProcessInspector::isSigned(p))
        return { false, QStringLiteral("拒绝隔离:该文件持有可信数字签名,隔离文件本体属于误伤(拦截的是行为,不是文件)") };

    const std::pair<bool, QString> r = remediator_->forceQuarantine(p);
    if (r.first)
        ipc_->sendQuarantineList();
    return r;
}

std::pair<bool, QString> Worker::forceHandle(const bulwark::ipc::ManualQuarantinePayload& req) {
    if (!remediator_)
        return { false, QStringLiteral("清理器不可用(隔离区未就绪)") };
    const QString kind = req.kind.trimmed().isEmpty() ? QStringLiteral("file") : req.kind.trimmed();

    if (kind != QLatin1String("file")) {
        RemediationReport report;
        const std::pair<bool, QString> r =
            remediator_->forceRemovePersistence(kind, req.location.trimmed(), req.name.trimmed(), report);
        if (r.first)
            applyRegHardening(report);
        const QString msg = QStringLiteral("强制处理[%1] %2\\%3 -> %4")
                                .arg(kind, req.location, req.name, r.second);
        log_.warning(msg);
        ipc_->sendLog(msg);
        return r;
    }

    const QString p = (req.location.trimmed().isEmpty() ? req.path : req.location).trimmed();
    if (p.isEmpty())
        return { false, QStringLiteral("未提供文件路径") };
    if (!QFileInfo::exists(p))
        return { false, QStringLiteral("文件不存在(可能已被移动或删除)") };
    if (isSweepExemptPath(p))
        return { false, QStringLiteral("拒绝:该路径属于系统目录或本产品自身,强制处理也不会动它") };
    const QString protectedWhy = ThreatRemediator::forceProtectedReason(p);
    if (!protectedWhy.isEmpty())
        return { false, QStringLiteral("拒绝:") + protectedWhy };

    QList<int> holders = occupied::holderPids(p);
    const QString lowP = QDir::toNativeSeparators(p).toLower();
    for (int pid : ProcessInspector::enumeratePids()) {
        if (holders.contains(pid))
            continue;
        if (QDir::toNativeSeparators(ProcessInspector::tryGetProcessImagePath(pid)).toLower() == lowP)
            holders << pid;
    }
    QStringList killed, spared;
    const int self = static_cast<int>(QCoreApplication::applicationPid());
    for (int pid : std::as_const(holders)) {
        if (pid <= 4 || pid == self)
            continue;
        const QString img = ProcessInspector::tryGetProcessImagePath(pid);
        const QString who = QStringLiteral("%1(PID %2)").arg(img.isEmpty() ? QStringLiteral("?") : QFileInfo(img).fileName()).arg(pid);
        if (isSessionCriticalImage(img) || isSweepExemptPath(img) || ProcessInspector::isCriticalProcess(pid)) {
            spared << who;
            continue;
        }
        ProcessInspector::tryTerminateProcess(pid);
        if (!ProcessInspector::waitForExit(pid, 300) && source_)
            source_->killProcess(pid);
        if (ProcessInspector::waitForExit(pid, 500)) {
            killed << who;
            rememberTerminated(pid, img);
        } else {
            spared << who + QStringLiteral("[结束失败]");
        }
    }

    const std::pair<bool, QString> r = remediator_->forceRemoveFile(p);
    QString message = r.second;
    if (!killed.isEmpty())
        message = QStringLiteral("已结束占用进程 %1;").arg(killed.join(QStringLiteral("、"))) + message;
    if (!spared.isEmpty())
        message += QStringLiteral("(未结束:%1)").arg(spared.join(QStringLiteral("、")));

    const QString msg = QStringLiteral("强制处理[file] %1 -> %2").arg(p, message);
    log_.warning(msg);
    ipc_->sendLog(msg);
    if (r.first)
        ipc_->sendQuarantineList();
    return { r.first, message };
}

bulwark::ipc::PersistenceCleanupResultPayload Worker::cleanupPersistence(
    const bulwark::ipc::PersistenceCleanupRequestPayload& req) {
    bulwark::ipc::PersistenceCleanupResultPayload res;
    res.requestId = req.requestId;
    res.entryId = req.entry.id;

    if (!remediator_) {
        res.message = QStringLiteral("清理器不可用(隔离区未就绪)");
        return res;
    }
    const bulwark::PersistenceEntry& entry = req.entry;
    if (entry.id.trimmed().isEmpty() || entry.location.trimmed().isEmpty()) {
        res.message = QStringLiteral("条目信息不完整,已放弃清理(未做任何处置)");
        return res;
    }

    if (!entry.imagePath.trimmed().isEmpty()) {
        if (const std::optional<QString> note = engine_->trustNoteForPath(entry.imagePath)) {
            res.message = QStringLiteral("该项目标已加白(%1),按信任语义放弃清理").arg(*note);
            log_.info(res.message + QStringLiteral(":") + entry.imagePath);
            return res;
        }
        // 护栏:本产品自身的自启动项绝不清理(否则用户一键把自己的防护开机自启删了)。
        if (isSweepExemptPath(entry.imagePath)) {
            res.message = QStringLiteral("系统组件 / 本产品自身的自启动项不允许从此处清理");
            log_.warning(res.message + QStringLiteral(":") + entry.imagePath);
            return res;
        }
    }

    const RemediationReport report = remediator_->cleanupPersistenceEntry(entry);
    applyRegHardening(report);

    res.quarantinedFiles = report.quarantinedFiles;
    res.removedRegistryValues = report.removedRegistryValues;
    res.skipped = report.skipped;
    res.success = report.totalActions() > 0;
    res.message = res.success
        ? QStringLiteral("已清理:隔离文件 %1 个,移除持久化 %2 项%3")
              .arg(report.quarantinedFiles.size())
              .arg(report.removedRegistryValues.size())
              .arg(report.skipped.isEmpty()
                       ? QString()
                       : QStringLiteral(",另有 %1 项未能处理").arg(report.skipped.size()))
        : (report.skipped.isEmpty()
               ? QStringLiteral("未产生任何动作(该项可能已被移除)")
               : QStringLiteral("清理失败:%1").arg(report.skipped.first().reason));

    const QString msg = QStringLiteral("自启动项清理[%1] %2 -> %3")
                            .arg(entry.name, entry.location, res.message);
    log_.warning(msg);
    ipc_->sendLog(msg);
    if (!report.quarantinedFiles.isEmpty())
        ipc_->sendQuarantineList();

    using namespace bulwark::json;
    QJsonObject o;
    o["timestampUtc"] = dateTimeToIso(QDateTime::currentDateTimeUtc());
    o["type"] = QStringLiteral("Persistence");
    o["actorPath"] = entry.imagePath;
    o["actorPid"] = 0;
    o["target"] = entry.location + QStringLiteral(" \\ ") + entry.name;
    o["action"] = QStringLiteral("Remediate");
    o["source"] = QStringLiteral("UserPrompt");
    o["riskScore"] = entry.riskScore;
    QStringList details;
    for (const QString& f : report.quarantinedFiles) details << (QStringLiteral("隔离文件:") + f);
    for (const QString& r : report.removedRegistryValues) details << (QStringLiteral("移除持久化:") + r);
    for (const bulwark::ipc::RemediationSkippedItem& s : report.skipped)
        details << (QStringLiteral("未清理:") + s.target + QStringLiteral("(") + s.reason + QStringLiteral(")"));
    o["reasons"] = strListToJson(details);
    audit_->writeRecord(o);

    return res;
}

void Worker::reconcileKernelBlocksAfterTrust() {
    if (!source_)
        return;

    source_->clearBannedProcesses();

    const QStringList kernelExec = source_->persistedExecBlockList();
    const QStringList kernelNoLoad = source_->persistedModuleNoLoadList();

    const QVector<bulwark::DefenseRule> rules = engine_->getRules();
    QStringList trustedNeedles;
    for (const bulwark::DefenseRule& r : rules) {
        if (!r.isTrustEntry() || r.action != VerdictAction::Allow || !r.enabled)
            continue;
        QString t = !r.actorPath.isEmpty() ? r.actorPath : r.actorPattern;
        if (t.isEmpty())
            continue;
        if (t.endsWith(QStringLiteral("\\*")))
            t.chop(2);
        if (t.size() >= 2 && t[1] == QLatin1Char(':'))
            t = t.mid(2);
        if (!t.isEmpty())
            trustedNeedles << t;
    }

    if (hardening_) {
        int removed = 0;
        for (const bulwark::DefenseRule& r : rules) {
            if (!r.isTrustEntry() || r.action != VerdictAction::Allow || !r.enabled)
                continue;
            const QString p = !r.actorPath.isEmpty() ? r.actorPath : r.actorPattern;
            if (p.isEmpty() || p.endsWith(QStringLiteral("\\*")))
                continue;
            if (hardening_->hasDenyExecute(p) && hardening_->undenyExecute(p))
                ++removed;
        }
        if (removed > 0) {
            log_.warning(QStringLiteral("加白对账:已移除 %1 个已加白程序上的跨重启「拒绝执行」ACE。")
                             .arg(removed));
        }
    }

    if (containment_) {
        int thawed = 0;
        for (const QString& t : trustedNeedles)
            thawed += containment_->thawByPathNeedle(t, QStringLiteral("用户已加白该程序"));
        if (thawed > 0) {
            log_.warning(QStringLiteral("加白对账:已解冻 %1 个被冻结的进程(其映像已在信任名单内)。")
                             .arg(thawed));
        }
    }

    const AuthoritativePolicyReplayPlan execReplay =
        DurableExecBlockPolicy::planAuthoritativeReplay(kernelExec, trustedNeedles);
    const QStringList& keepExec = execReplay.keep;
    const QStringList& dropExec = execReplay.drop;
    if (!dropExec.isEmpty()) {
        if (source_->clearExecBlock()) {
            for (const QString& entry : keepExec)
                source_->blockExecPath(entry);
            const QString msg =
                QStringLiteral("加白对账:已解除内核「禁止执行」名单中 %1 条会挡住已加白程序的条目"
                               "(保留 %2 条)。这些程序此后可正常启动。")
                    .arg(dropExec.size()).arg(keepExec.size());
            log_.warning(msg);
            ipc_->sendLog(msg);
            for (const QString& entry : dropExec)
                log_.info(QStringLiteral("  已解除执行前拦截:%1").arg(entry));
        } else {
            log_.warning(QStringLiteral("加白对账:内核未连接或不受理清空命令,「禁止执行」名单中 %1 条"
                                        "针对已加白程序的条目仍在生效(重启服务并连上驱动后会自动重试)。")
                             .arg(dropExec.size()));
        }
    }

    const AuthoritativePolicyReplayPlan loadReplay =
        DurableExecBlockPolicy::planAuthoritativeReplay(kernelNoLoad, trustedNeedles);
    const QStringList& keepLoad = loadReplay.keep;
    const QStringList& dropLoad = loadReplay.drop;
    if (!dropLoad.isEmpty()) {
        if (source_->clearModuleNoLoad()) {
            for (const QString& entry : keepLoad)
                source_->blockModuleLoad(entry);
            const QString msg =
                QStringLiteral("加白对账:已解除内核「禁止加载」名单中 %1 条会挡住已加白模块的条目(保留 %2 条)。")
                    .arg(dropLoad.size()).arg(keepLoad.size());
            log_.warning(msg);
            ipc_->sendLog(msg);
        } else {
            log_.warning(QStringLiteral("加白对账:内核未连接,「禁止加载」名单中 %1 条针对已加白模块的条目仍在生效。")
                             .arg(dropLoad.size()));
        }
    }
}

void Worker::applyRegHardening(const RemediationReport& report) {
    if (!source_ || report.hardenedRegTargets.isEmpty())
        return;
    QSet<QString> seen;
    int n = 0;
    QStringList fellBack;
    for (const QString& t : report.hardenedRegTargets) {
        const QString k = t.trimmed();
        if (k.size() < 8)
            continue;
        const QString low = k.toLower();
        if (seen.contains(low))
            continue;
        seen.insert(low);
        if (source_->hardenRegistryKey(k))
            ++n;
        else
            fellBack << k;
    }
    if (n > 0)
        log_.warning(
            QStringLiteral("持久化反重建:已把 %1 条已清理的自启动项加入内核注册表硬拦(阻止恶意软件立刻重建)。").arg(n));

    if (!fellBack.isEmpty() && hardening_ && regHardenEnabled_) {
        int watched = 0, denied = 0, denySkipped = 0;
        QStringList unusable;
        for (const QString& t : fellBack) {
            const int cut = t.lastIndexOf(QLatin1Char('\\'));
            if (cut <= 0) {
                unusable << t;
                continue;
            }
            const QString key = t.left(cut);
            if (!key.startsWith(QLatin1String("HK"), Qt::CaseInsensitive)) {
                unusable << t;
                continue;
            }
            if (SystemHardening::isExclusiveRegistryKey(key)) {
                if (!regDenyWriteEnabled_) {
                    ++denySkipped;
                    continue;
                }
                if (hardening_->denyRegistryWrite(key, true))
                    ++denied;
            } else {
                hardening_->watchKeyLive(key);
                ++watched;
            }
        }
        log_.warning(QStringLiteral("持久化反重建(用户态补位,内核未受理 %1 条):"
                                    "已对 %2 个共享键启用即时监视+回滚、对 %3 个恶意独占键加"
                                    "「拒绝写值」ACE%4%5。"
                                    "注意:回滚是【事后还原】,不是阻止写入 —— 恶意软件仍能写进去,"
                                    "只是会被立刻还原;真正的写入前阻断只有内核硬拦做得到。")
                         .arg(fellBack.size())
                         .arg(watched)
                         .arg(denied)
                         .arg(unusable.isEmpty()
                                  ? QString()
                                  : QStringLiteral(";另有 %1 条目标形态无法解析成注册表键,"
                                                   "用户态无从处理:%2")
                                        .arg(unusable.size())
                                        .arg(unusable.join(QStringLiteral(" | "))))
                         .arg(denySkipped == 0
                                  ? QString()
                                  : QStringLiteral(";另有 %1 个恶意独占键【未】加 ACE"
                                                   "(RegistryDenyWriteEnabled=false:该 ACE 跨重启,"
                                                   "且目前没有撤销入口,故默认不下发)")
                                        .arg(denySkipped)));
    } else if (!fellBack.isEmpty()) {
        log_.warning(QStringLiteral("持久化反重建:%1 条已清理的自启动项【未能下发任何反重建】——"
                                    "内核未受理(无驱动时 hardenRegistryKey 是空操作),"
                                    "用户态补位%2。恶意软件可以立刻把这些持久化项写回来,"
                                    "本服务既不会阻止也不会还原。要补上这一段,"
                                    "把 RegistryInstantRollbackEnabled 置为 true。")
                         .arg(fellBack.size())
                         .arg(hardening_ ? QStringLiteral("已按配置关闭"
                                                          "(RegistryInstantRollbackEnabled=false)")
                                         : QStringLiteral("未注入")));
    }
}

bulwark::EnforcementOutcome Worker::enforceBlock(const SecurityEvent& e, bool persistentBlacklist,
                                                 bool* execBlockedOut) {
    if (execBlockedOut)
        *execBlockedOut = false;
    using bulwark::EnforcementOutcome;

    if (e.kernelBlocked)
        return EnforcementOutcome::KernelBlocked;

    if (e.isMemoryCarrierFinding() && e.target.contains(fileless_policy::unbackedPeFinding())) {
        const bool healthySigned = e.actorSigned && !e.signatureMismatch && !e.certRevoked
            && !e.signedAfterCertExpiry && !TrustPolicy::isAbusedSigner(e).ok;
        if (!fileless_policy::mayTerminateUnbackedPeCarrier(e.actorPath, healthySigned)) {
            log_.warning(QStringLiteral("拦截处置:只告警,不结束承载方 PID=%1(签名健康或装在系统 / 安装目录,"
                                        "未落地的 PE 可能是其他软件注入的模块):%2")
                             .arg(e.actorPid).arg(e.actorPath));
            return EnforcementOutcome::AlertedOnly;
        }
    }
    if (engine_ && engine_->isCanaryTarget(e) && response_policy::canaryTouchIsAlertOnly(e)) {
        log_.warning(QStringLiteral("拦截处置:只告警,不结束 PID=%1(Windows 搜索 / 资源管理器打开了诱饵文件,"
                                    "多半是建索引或读属性):%2")
                         .arg(e.actorPid).arg(e.actorPath));
        return EnforcementOutcome::AlertedOnly;
    }

    // 主体若正是本产品先前结束的那个实例(含整树结束时一并带走的子进程),本条只是它退出前
    // 排队的动作,应记「主体已结束」。只查本产品的结束记录,不触碰当前占用该 PID 的进程,
    // 所以下面两处「不得触碰当前 PID」的提前返回之前也可以先查。
    const auto terminatedEarlierByUs = [&](int pid) {
        QDateTime killedAt;
        const quint64 creation = pid == e.actorPid ? e.actorCreationFileTime.value_or(0) : 0;
        if (!wasTerminatedByUs(pid, e.actorPath, &killedAt, creation))
            return false;
        const qint64 lagSecs = killedAt.secsTo(QDateTime::currentDateTimeUtc());
        const qint64 afterKill = e.timestampUtc.isValid() ? killedAt.secsTo(e.timestampUtc) : 0;
        log_.info(QStringLiteral("拦截处置:PID=%1 已在本次之前被本产品结束(%2;距处置 %3 秒才"
                                 "评估到本条),无需再处置:%4")
                      .arg(pid)
                      .arg(afterKill <= kQueuedBeforeExitGraceSecs
                               ? QStringLiteral("本条是它退出前排队的动作")
                               : QStringLiteral("本条动作的归因比处置晚 %1 秒,主体早已不在")
                                     .arg(afterKill))
                      .arg(lagSecs)
                      .arg(e.actorPath));
        return true;
    };

    // 异步裁决可能在 PID 已退出/复用后才到。带创建 FILETIME 的事件必须先重新核对同一
    // 进程实例；不匹配时不得封禁、冻结、断子、结束或提示用户处置后来占用该 PID 的进程。
    const auto expected = expectedProcessInstance(e);
    if (e.actorPid > 4 && !expected.has_value()) {
        if (terminatedEarlierByUs(e.actorPid))
            return EnforcementOutcome::ActorAlreadyGone;
        log_.warning(QStringLiteral("本地进程处置已跳过:事件没有可验证的 PID/创建 FILETIME/映像身份，"
                                    "不会触碰当前占用 PID %1 的进程。")
                         .arg(e.actorPid));
        return EnforcementOutcome::AlertedOnly;
    }
    if (expected.has_value()) {
        if (!ProcessInspector::isCurrentProcessInstance(*expected)) {
            if (terminatedEarlierByUs(e.actorPid))
                return EnforcementOutcome::ActorAlreadyGone;
            log_.warning(QStringLiteral("本地拦截已跳过:PID %1 的原进程实例已退出或被复用，"
                                        "未触碰当前 PID。映像:%2")
                             .arg(e.actorPid).arg(e.actorPath));
            return EnforcementOutcome::AlertedOnly;
        }
    }

    bool writeUndone = false;
    if (remediator_
        && (e.type == bulwark::EventType::RegistryWrite
            || e.type == bulwark::EventType::FileWrite)
        && !e.target.trimmed().isEmpty()) {
        RemediationReport undoRep;
        writeUndone = remediator_->undoBlockedWrite(e, undoRep);
        if (writeUndone) {
            log_.warning(QStringLiteral("目标侧撤销:已回滚被拦写入(注册表 %1 项 / 文件 %2 个):%3")
                             .arg(undoRep.removedRegistryValues.size())
                             .arg(undoRep.quarantinedFiles.size())
                             .arg(e.target));
            applyRegHardening(undoRep);
        }
    }

    bool blacklisted = false;
    if (persistentBlacklist && e.type == bulwark::EventType::ImageLoad
        && source_ && !e.target.trimmed().isEmpty()) {
        const QString mod = e.target.trimmed();
        if (const std::optional<QString> note = engine_->trustNoteForPath(mod)) {
            log_.info(QStringLiteral("禁止加载已跳过(该模块已加白:%1):%2").arg(*note, mod));
        } else if (e.actorPid <= 0) {
            log_.info(QStringLiteral("禁止加载未下发(内核驱动加载走内核态打开,minifilter 无法拦截,"
                                     "下发只会白占 64 槽之一并跨重启续留):%1").arg(mod));
        } else {
            QString needle = mod;
            needle.replace(QLatin1Char('/'), QLatin1Char('\\'));
            if (needle.size() >= 2 && needle[1] == QLatin1Char(':'))
                needle = needle.mid(2);
            if (needle.size() < 6) {
                log_.info(QStringLiteral("禁止加载未下发(去盘符后子串过短,风险大于收益):%1").arg(mod));
            } else {
                blacklisted = source_->blockModuleLoad(needle);
            }
        }
    }

    const int pid = e.originatorPid > 0 ? e.originatorPid : e.actorPid;
    bool execDenied = false;
    std::optional<bool> processContainment;
    if (e.type == bulwark::EventType::ProcessCreate) {
        if (persistentBlacklist) {
            const DurableExecBlockExecution execution = WorkerDurableExecBlockSeam::fromEnforceBlock(
                e, ProcessInspector::tryGetProcessInstance(e.actorPid), pid,
                [this](const DurableExecBlockAuthorization& authorization) {
                    return blacklistExec(authorization);
                },
                [this](int containmentPid) { return killMalicious(containmentPid); });
            execDenied = execution.persistenceSucceeded;
            processContainment = execution.containmentSucceeded;
            if (!execution.evaluation.authorization.has_value()) {
                log_.warning(QStringLiteral("持久执行阻断已拒绝:%1(PID=%2,事件映像=%3)——"
                                            "未写入 FileExecBlock 或拒绝执行 ACE；仍继续当次收容。")
                                 .arg(durableExecBlockDecisionName(execution.evaluation.decision))
                                 .arg(e.actorPid)
                                 .arg(e.actorPath));
            }
        } else if (isTaintRuleNote(e.matchedRuleNote)) {
            execDenied = denyExecuteRevocable(
                e.actorPath, QStringLiteral("命中污点规则(同批投递的确认恶意释放物)"));
        }
    }
    if (execBlockedOut)
        *execBlockedOut = execDenied;

    const bool terminated = processContainment.has_value()
        ? *processContainment
        : killMalicious(pid);
    if (terminated)
        return EnforcementOutcome::Terminated;

    if (terminatedEarlierByUs(pid))
        return EnforcementOutcome::ActorAlreadyGone;

    if (execDenied) {
        log_.info(QStringLiteral("拦截处置:本次没有可结束的进程,但该映像已被禁止再次启动"
                                 "(下次启动将直接失败):%1").arg(e.actorPath));
        return EnforcementOutcome::ExecDenied;
    }

    if (blacklisted) {
        log_.info(QStringLiteral("拦截处置:侧载模块已加入内核禁止加载名单(下次加载将被前拦):%1")
                      .arg(e.target));
        return EnforcementOutcome::ModuleBlacklisted;
    }

    if (writeUndone) {
        log_.info(QStringLiteral("拦截处置:无可结束进程,但被拦写入的目标侧副作用已撤销:%1")
                      .arg(e.target));
        return EnforcementOutcome::WriteUndone;
    }

    log_.warning(QStringLiteral("拦截处置:PID=%1 未能结束任何进程(已退出 / 受保护 / 关键进程 / "
                                "会话与系统基础设施进程),该事件仅告警、未实际拦截。").arg(pid));
    return EnforcementOutcome::AlertedOnly;
}

void Worker::rememberTerminated(int pid, const QString& imagePath, quint64 creationFileTime) {
    if (pid <= 4)
        return;
    const QDateTime now = QDateTime::currentDateTimeUtc();
    for (auto it = killedByUs_.begin(); it != killedByUs_.end();) {
        if (it.value().killedAtUtc.secsTo(now) > kKilledMemoryTtlSecs)
            it = killedByUs_.erase(it);
        else
            ++it;
    }
    while (killedByUs_.size() >= kKilledMemoryMax) {
        auto oldest = killedByUs_.begin();
        for (auto it = killedByUs_.begin(); it != killedByUs_.end(); ++it)
            if (it.value().killedAtUtc < oldest.value().killedAtUtc)
                oldest = it;
        killedByUs_.erase(oldest);
    }
    killedByUs_.insert(pid, KilledProcess{imagePath.trimmed(), creationFileTime, now});
}

bool Worker::wasTerminatedByUs(int pid, const QString& imagePath, QDateTime* killedAtUtc,
                               quint64 creationFileTime) const {
    const auto it = killedByUs_.constFind(pid);
    if (it == killedByUs_.constEnd())
        return false;
    const KilledProcess& killed = it.value();
    const QString asked = imagePath.trimmed();
    if (killed.imagePath.isEmpty() || asked.isEmpty())
        return false;
    if (killed.imagePath.compare(asked, Qt::CaseInsensitive) != 0)
        return false;
    if (creationFileTime != 0 && killed.creationFileTime != 0) {
        // 同 PID 同映像但创建时间不同:是另一个实例,不是本产品结束的那个。
        if (creationFileTime != killed.creationFileTime)
            return false;
        // 原实例已不在(PID 被复用也算),或句柄仍被别人持有但已退出,都算已结束。
        if (ProcessInspector::isCurrentProcessInstance({pid, killed.creationFileTime, killed.imagePath})
            && !ProcessInspector::waitForExit(pid, 0))
            return false;
    } else if (!ProcessInspector::waitForExit(pid, 0)) {
        return false;
    }
    if (killedAtUtc)
        *killedAtUtc = killed.killedAtUtc;
    return true;
}

void Worker::maybeQuarantineOnBlock(const SecurityEvent& e) {
    if (!settings_ || !settings_->quarantineOnBlock || !quarantine_)
        return;

    if (e.type == bulwark::EventType::ImageLoad) {
        log_.info(QStringLiteral("拦截时隔离已跳过(模块加载事件:宿主不是载荷,处置走「禁止加载」名单):"
                                 "%1 -> %2").arg(e.actorPath, e.target));
        return;
    }

    const QString path = e.actorPath.trimmed();
    if (path.isEmpty() || path.startsWith(QLatin1String("PID "), Qt::CaseInsensitive))
        return;

    // 护栏 1:已加白的主体绝不隔离(与所有后台处置路径同一口径)。
    if (const std::optional<QString> note = engine_->trustNoteForPath(path)) {
        log_.info(QStringLiteral("拦截时隔离已跳过(该主体已加白:%1):%2").arg(*note, path));
        return;
    }
    if (isSweepExemptPath(path)) {
        log_.info(QStringLiteral("拦截时隔离已跳过(系统目录 / 本产品自身):%1").arg(path));
        return;
    }
    if (bulwark::engine::TrustPolicy::isHealthySigned(e).ok) {
        log_.info(QStringLiteral("拦截时隔离已跳过(主体持健康签名,拦的是用法而非文件):%1").arg(path));
        return;
    }
    if (!QFileInfo::exists(path))
        return;

    const QString hash = QuarantineManager::tryComputeSha256(path);
    const auto entry = quarantine_->quarantine(
        path, QStringLiteral("拦截时自动隔离(设置:拦截时一并隔离载荷)"), e.actorPid, hash);
    if (entry.has_value() && entry->originalRemoved) {
        const QString msg = QStringLiteral("拦截时隔离:已把主体载荷移入隔离区(可还原):%1").arg(path);
        log_.warning(msg);
        ipc_->sendLog(msg);
        ipc_->sendQuarantineList();
    } else if (entry.has_value()) {
        const QString msg = entry->deleteOnRebootScheduled
            ? QStringLiteral("拦截时隔离仅部分完成:已保存可还原副本,但原文件仍在;已计划重启删除:%1")
                  .arg(path)
            : QStringLiteral("拦截时隔离仅部分完成:已保存可还原副本,但原文件仍在且重启删除调度失败:%1")
                  .arg(path);
        log_.warning(msg);
        ipc_->sendLog(msg);
        ipc_->sendQuarantineList();
    } else {
        log_.warning(QStringLiteral("拦截时隔离失败(文件被占用或权限不足):%1").arg(path));
    }
}

bool Worker::remediateIfMalicious(const SecurityEvent& e, const bulwark::Verdict& v) {
    if (!remediator_)
        return false;
    if (!isDeterministicMaliciousBlock(e, v))
        return false;
    if (!response_policy::footprintAttributableToActor(e)) {
        log_.info(QStringLiteral("足迹清理已跳过(%1):%2")
                      .arg(e.isMemoryCarrierFinding()
                               ? QStringLiteral("内存扫描的承载方,不是释放者")
                               : QStringLiteral("会话级系统进程,子孙与写入不归这一次行为"),
                           e.actorPath));
        return false;
    }
    if (e.type != bulwark::EventType::ProcessCreate && e.type != bulwark::EventType::RemoteThread
        && e.type != bulwark::EventType::RegistryWrite && e.type != bulwark::EventType::FileWrite)
        return false;
    if (e.actorPath.trimmed().isEmpty())
        return false;

    const RemediationReport report = remediator_->remediate(e, chain_.collectTreeEvents(e.actorPid));
    applyRegHardening(report);

    publishRemediation(
        e, report,
        v.source == VerdictSource::Rule
            ? (e.matchedRuleNote.isEmpty() ? QString::fromUtf8("命中防护规则") : e.matchedRuleNote)
            : QString::fromUtf8("启发式判定恶意"),
        v.source);
    return report.quarantinedFiles.contains(e.actorPath, Qt::CaseInsensitive);
}

void Worker::publishRemediation(const SecurityEvent& e, const RemediationReport& report,
                                const QString& reason, VerdictSource source) {
    if (report.totalActions() == 0 && report.skipped.isEmpty())
        return;

    const QString summary =
        QStringLiteral("恶意足迹清理:隔离文件 %1 个,移除持久化 %2 项,未清理 %3 项 [%4]")
            .arg(report.quarantinedFiles.size())
            .arg(report.removedRegistryValues.size())
            .arg(report.skipped.size())
            .arg(e.actorPath);
    ipc_->sendLog(summary);
    log_.warning(summary);

    ipc_->sendRemediationReport(makeRemediationPayload(e, reason, report));
    if (!report.quarantinedFiles.isEmpty())
        ipc_->sendQuarantineList();

    using namespace bulwark::json;
    QJsonObject o;
    o["timestampUtc"] = dateTimeToIso(QDateTime::currentDateTimeUtc());
    o["type"] = bulwark::eventTypeToString(e.type);
    o["actorPath"] = e.actorPath;
    o["actorPid"] = e.actorPid;
    o["target"] = QStringLiteral("足迹清理 · 成功 %1 · 未清理 %2")
                      .arg(report.totalActions()).arg(report.skipped.size());
    o["action"] = QStringLiteral("Remediate");
    o["source"] = bulwark::verdictSourceToString(source);
    o["riskScore"] = e.riskScore;
    QStringList details;
    for (const QString& f : report.quarantinedFiles)
        details << (QStringLiteral("隔离文件:") + f);
    for (const QString& r : report.removedRegistryValues)
        details << (QStringLiteral("移除持久化:") + r);
    for (const bulwark::ipc::RemediationSkippedItem& s : report.skipped)
        details << (QStringLiteral("未清理:") + s.target + QStringLiteral("(") + s.reason + QStringLiteral(")"));
    o["reasons"] = strListToJson(details);
    audit_->writeRecord(o);
}

bool Worker::isDeterministicMaliciousBlock(const SecurityEvent& e, const bulwark::Verdict& v) {
    if (v.action != VerdictAction::Block)
        return false;
    if (v.source != VerdictSource::Rule && v.source != VerdictSource::Heuristic)
        return false;
    if (e.type == bulwark::EventType::FileWrite || e.type == bulwark::EventType::RegistryWrite) {
        if (e.matchedRuleNote.startsWith(QStringLiteral("[情报")) || isTaintRuleNote(e.matchedRuleNote))
            return true;
        if (!e.hasActorHardIndicator())
            return false;
        if (e.actorHardEvidenceSourceCount() >= 2)
            return true;
        const bool actorLooksTrustworthy = e.actorSigned && !e.signatureMismatch && !e.certRevoked
            && isStandardInstallDir(e.actorPath);
        return !actorLooksTrustworthy;
    }
    return true;
}

namespace {
bool isHostOrShellProcessName(const QString& path) {
    static const QSet<QString> kNames = {
        QStringLiteral("explorer.exe"),
        QStringLiteral("services.exe"),   QStringLiteral("svchost.exe"),
        QStringLiteral("wininit.exe"),    QStringLiteral("winlogon.exe"),
        QStringLiteral("userinit.exe"),   QStringLiteral("lsass.exe"),
        QStringLiteral("lsaiso.exe"),     QStringLiteral("csrss.exe"),
        QStringLiteral("smss.exe"),       QStringLiteral("taskhostw.exe"),
        QStringLiteral("taskhost.exe"),   QStringLiteral("sihost.exe"),
        QStringLiteral("runtimebroker.exe"), QStringLiteral("dllhost.exe"),
        QStringLiteral("rundll32.exe"),   QStringLiteral("wmiprvse.exe"),
        QStringLiteral("searchindexer.exe"), QStringLiteral("fontdrvhost.exe"),
        QStringLiteral("dwm.exe"),        QStringLiteral("conhost.exe"),
        QStringLiteral("ctfmon.exe"),
    };
    return kNames.contains(QFileInfo(path).fileName().toLower());
}

bool unusableImagePath(const QString& p) {
    return p.isEmpty() || p.startsWith(QLatin1String("PID "), Qt::CaseInsensitive);
}

QString normalizedForCompare(const QString& p) {
    QString s = p.trimmed();
    s.replace(QLatin1Char('/'), QLatin1Char('\\'));
    return s;
}
}

void Worker::maybeHandleLaunchingParent(const SecurityEvent& e) {
    if (e.type != bulwark::EventType::ProcessCreate || !e.hasThreatIndicator)
        return;

    const int ppid = e.parentPid;
    if (ppid <= 4 || ppid == e.actorPid || ppid == e.originatorPid)
        return;

    QString parentPath = e.parentPath.trimmed();
    if (unusableImagePath(parentPath))
        parentPath = chain_.lastKnownPath(ppid).trimmed();
    if (unusableImagePath(parentPath))
        return;

    if (engine_->isSelfComponent(e))
        return;
    if (const std::optional<QString> note = engine_->trustNoteForPath(parentPath)) {
        log_.info(QStringLiteral("连带处置发起方已跳过(该发起方已加白:%1):%2").arg(*note, parentPath));
        return;
    }

    if (isSweepExemptPath(parentPath)) {
        log_.info(QStringLiteral("连带处置发起方已跳过(系统目录 / 本产品自身):%1").arg(parentPath));
        return;
    }

    if (isHostOrShellProcessName(parentPath)) {
        log_.warning(QStringLiteral("连带处置发起方已跳过(宿主 / 外壳进程,只记录不动手):%1(PID %2)"
                                    " —— 其派生的 %3 已被单独处置。")
                         .arg(parentPath).arg(ppid).arg(e.actorPath));
        return;
    }

    const QString livePath = ProcessInspector::tryGetProcessImagePath(ppid);
    if (livePath.isEmpty()
        || normalizedForCompare(livePath).compare(normalizedForCompare(parentPath),
                                                  Qt::CaseInsensitive) != 0) {
        log_.info(QStringLiteral("连带处置发起方已放弃(无法确认 PID %1 仍是该父进程:实时映像=%2,"
                                 "事件/链记录=%3)—— 已退出或 PID 被复用,不据陈旧归因动手。")
                      .arg(ppid)
                      .arg(livePath.isEmpty() ? QStringLiteral("(解析不到)") : livePath)
                      .arg(parentPath));
        return;
    }

    const ProcessInspector::ForensicFacts facts =
        ProcessInspector::collectForensics(parentPath, false);
    if (facts.trustedSignature) {
        log_.info(QStringLiteral("连带处置发起方已跳过(发起方持可信签名,不据子进程的结论反推它恶意):%1")
                      .arg(parentPath));
        return;
    }
    if (!facts.isRealFile) {
        log_.info(QStringLiteral("连带处置发起方已放弃(发起方路径指向的文件不存在,无法验签 / 隔离):%1")
                      .arg(parentPath));
        return;
    }

    const bool inDropDir = bulwark::engine::ThreatDetector::isSuspiciousDropDir(parentPath);
    const bool justDropped = chain_.wasRecentlyWritten(parentPath, kRecentDropWindowSecs);
    if (!inDropDir && !justDropped) {
        log_.info(QStringLiteral("连带处置发起方已跳过(发起方未签名,但既不在投递目录、也不是最近才"
                                 "落地 —— 互证不成立,只记录):%1(PID %2)").arg(parentPath).arg(ppid));
        return;
    }

    const QString childName = QFileInfo(e.actorPath).fileName();
    const QString suspicionWhy = inDropDir ? QStringLiteral("位于投递目录")
                                           : QStringLiteral("是最近才落地的文件");

    SecurityEvent ev;
    ev.type = bulwark::EventType::ProcessCreate;
    ev.actorPid = ppid;
    ev.actorPath = parentPath;
    ev.target = parentPath;
    ev.actorHash = facts.sha256;
    ev.actorFileSize = facts.fileSize;
    ev.actorPublisher = facts.publisher;
    ev.commandLine = ProcessInspector::tryGetCommandLine(ppid);
    if (const auto parentInstance = ProcessInspector::tryGetProcessInstance(ppid))
        ev.actorCreationFileTime = parentInstance->creationFileTime;
    ev.userModeObserved = true;               // 事后补偿处置,不是内核前拦 —— 别把它显示成真前拦
    ev.hasThreatIndicator = true;
    ev.riskScore = 90;
    ev.detail = QStringLiteral("因其派生进程被确认恶意而连带处置:%1(PID %2)%3")
                    .arg(childName)
                    .arg(e.actorPid)
                    .arg(e.matchedRuleNote.isEmpty() ? QString()
                                                     : QStringLiteral(" · 规则:") + e.matchedRuleNote);
    ev.addEvidence(QStringLiteral("LaunchingParent"), bulwark::EvidenceKind::HardIndicator, ev.detail);
    ev.addEvidence(QStringLiteral("LaunchingParent"), bulwark::EvidenceKind::Corroboration,
                   QStringLiteral("发起方未签名且%1").arg(suspicionWhy));

    const QString head =
        QStringLiteral("连带处置发起方:子进程 %1 已被确认恶意,其发起方 %2(PID %3)未签名且%4 ——"
                       "结束其进程树(含刚被拦下的该子进程)并清理足迹。")
            .arg(childName, parentPath)
            .arg(ppid)
            .arg(suspicionWhy);
    log_.warning(head);
    ipc_->sendLog(head);

    const DurableExecBlockExecution execution = WorkerDurableExecBlockSeam::fromLaunchingParent(
        ev, ProcessInspector::tryGetProcessInstance(ppid),
        [this](const DurableExecBlockAuthorization& authorization) {
            return blacklistExec(authorization);
        },
        [this](int containmentPid) { return killMalicious(containmentPid); });

    bulwark::EnforcementOutcome outcome = execution.containmentSucceeded
        ? bulwark::EnforcementOutcome::Terminated
        : bulwark::EnforcementOutcome::AlertedOnly;
    if (!execution.containmentSucceeded && wasTerminatedByUs(ppid, parentPath))
        outcome = bulwark::EnforcementOutcome::ActorAlreadyGone;

    bool execDenied = execution.persistenceSucceeded;
    if (!execution.evaluation.authorization.has_value()) {
        log_.warning(QStringLiteral("持久执行阻断已拒绝:%1(PID=%2,事件映像=%3)——"
                                    "未写入 FileExecBlock 或拒绝执行 ACE；仍继续当次收容。")
                         .arg(durableExecBlockDecisionName(execution.evaluation.decision))
                         .arg(ppid)
                         .arg(parentPath));
    }

    const bool actorVaulted =
        remediateIfMalicious(ev, bulwark::Verdict::forEvent(ev, VerdictAction::Block,
                                                            VerdictSource::Heuristic));
    if (outcome == bulwark::EnforcementOutcome::AlertedOnly) {
        if (actorVaulted)
            outcome = bulwark::EnforcementOutcome::PayloadQuarantined;
        else if (execDenied)
            outcome = bulwark::EnforcementOutcome::ExecDenied;
    }
    ipc_->sendBlock(ev, outcome, false, execDenied);
    recordEvent(ev, VerdictAction::Block, VerdictSource::Heuristic, outcome);
    taintDroppedFiles(ev, VerdictAction::Block, QStringLiteral("发起方因派生恶意进程被连带确认"));
}

void Worker::remediateOnUserBlock(const SecurityEvent& e) {
    if (!remediator_)
        return;
    if (e.type != bulwark::EventType::ProcessCreate && e.type != bulwark::EventType::RemoteThread
        && e.type != bulwark::EventType::RegistryWrite && e.type != bulwark::EventType::FileWrite)
        return;
    const QString actor = e.actorPath.trimmed();
    if (actor.isEmpty() || actor.startsWith(QLatin1String("PID "), Qt::CaseInsensitive))
        return;
    if (const std::optional<QString> note = engine_->trustNoteForPath(actor)) {
        log_.info(QStringLiteral("用户阻止后的足迹清理已跳过(该主体已加白:%1):%2").arg(*note, actor));
        return;
    }
    if (engine_->isSelfComponent(e))
        return;

    const int pid = e.originatorPid > 0 ? e.originatorPid : e.actorPid;
    const RemediationReport report = remediator_->remediate(e, chain_.collectTreeEvents(pid));
    applyRegHardening(report);
    publishRemediation(e, report, QString::fromUtf8("用户选择阻止"), VerdictSource::UserPrompt);
}

namespace {
constexpr int kTaintMaxPerBlock   = 20;
constexpr int kTaintMaxTotal      = 200;
constexpr int kTaintConfirmedDays = 30;
constexpr int kTaintUserDays      = 7;

const QString& taintPathMarker() {
    static const QString m = QStringLiteral(" · 路径=");
    return m;
}

QString taintNotePath(const QString& note) {
    const int i = note.lastIndexOf(taintPathMarker());
    return i < 0 ? QString() : note.mid(i + taintPathMarker().size()).trimmed();
}

enum class TaintKind { None, Exec, Script, Module };

TaintKind taintKindOf(const QString& path) {
    static const QSet<QString> kExec   = { QStringLiteral("exe"), QStringLiteral("scr"), QStringLiteral("com") };
    static const QSet<QString> kScript = {
        QStringLiteral("bat"), QStringLiteral("cmd"), QStringLiteral("ps1"), QStringLiteral("vbs"),
        QStringLiteral("vbe"), QStringLiteral("js"),  QStringLiteral("jse"), QStringLiteral("wsf"),
        QStringLiteral("hta"), QStringLiteral("jar"), QStringLiteral("msi"), QStringLiteral("msp") };
    static const QSet<QString> kModule = {
        QStringLiteral("dll"), QStringLiteral("ocx"), QStringLiteral("cpl"), QStringLiteral("drv"),
        QStringLiteral("sys") };
    const QString ext = QFileInfo(path).suffix().toLower();
    if (kExec.contains(ext))   return TaintKind::Exec;
    if (kScript.contains(ext)) return TaintKind::Script;
    if (kModule.contains(ext)) return TaintKind::Module;
    return TaintKind::None;
}

QString driveAgnostic(const QString& path) {
    QString p = path.trimmed();
    p.replace(QLatin1Char('/'), QLatin1Char('\\'));
    if (p.size() >= 2 && p[1] == QLatin1Char(':'))
        p = p.mid(2);
    return p;
}

bool isSharedDropRoot(const QString& dir) {
    QString d = dir.toLower();
    d.replace(QLatin1Char('/'), QLatin1Char('\\'));
    while (d.endsWith(QLatin1Char('\\')))
        d.chop(1);
    if (d.size() <= 3)
        return true;
    static const char* const kRoots[] = {
        "\\appdata\\local\\temp", "\\windows\\temp", "\\downloads", "\\desktop", "\\documents",
        "\\users\\public", "\\appdata\\roaming", "\\appdata\\local", "\\programdata", "\\temp", "\\tmp",
    };
    for (const char* r : kRoots)
        if (d.endsWith(QLatin1String(r)))
            return true;
    const int u = d.indexOf(QLatin1String("\\users\\"));
    if (u >= 0 && d.indexOf(QLatin1Char('\\'), u + 7) < 0)
        return true;
    return false;
}

struct TaintCandidate {
    QString path;
    TaintKind kind = TaintKind::None;
};

struct TaintDropperBatch {
    QString dropperPath;
    bool dropperIsSystem = false;
    QString subjectDir;
    QVector<TaintCandidate> files;
    TaintCandidate dropperSelf;
};

struct TaintResult {
    QString path;
    TaintKind kind = TaintKind::None;
    QString sha256;
    bool byAssociation = false;
};
}

QString Worker::taintRuleTag() {
    return QStringLiteral("[污点-释放物]");
}

bool Worker::isTaintRuleNote(const QString& note) {
    return note.startsWith(taintRuleTag());
}

void Worker::taintDroppedFiles(const SecurityEvent& e, VerdictAction grade, const QString& why) {
    if (!injectTaintRules_)
        return;
    if (grade != VerdictAction::Block && grade != VerdictAction::Ask)
        return;
    const QString actor = e.actorPath.trimmed();
    if (actor.isEmpty() || actor.startsWith(QLatin1String("PID "), Qt::CaseInsensitive))
        return;
    if (engine_->isSelfComponent(e))
        return;
    if (engine_->trustNoteForPath(actor))
        return;
    if (!response_policy::footprintAttributableToActor(e))
        return;

    QSet<QString> seen;
    auto eligible = [&](const QString& raw, TaintCandidate* out) -> bool {
        const QString p = raw.trimmed();
        if (p.isEmpty())
            return false;
        const QString key = p.toLower().replace(QLatin1Char('/'), QLatin1Char('\\'));
        if (seen.contains(key))
            return false;
        const TaintKind kind = taintKindOf(p);
        if (kind == TaintKind::None)
            return false;
        if (isSweepExemptPath(p))
            return false;
        if (!ThreatRemediator::isInUserDropZone(p))
            return false;
        if (engine_->trustNoteForPath(p))
            return false;
        seen.insert(key);
        out->path = p;
        out->kind = kind;
        return true;
    };

    QVector<TaintCandidate> direct;
    auto addDirect = [&](const QString& p) {
        TaintCandidate c;
        if (direct.size() < kTaintMaxPerBlock && eligible(p, &c))
            direct.append(c);
    };

    if (e.type == bulwark::EventType::ImageLoad)
        addDirect(e.target);

    const bool actorHealthySigned = TrustPolicy::isHealthySigned(e).ok;
    for (const QString& p : chain_.filesWrittenBy(e.actorPid, actor, !actorHealthySigned))
        addDirect(p);
    if (e.originatorPid > 0 && e.originatorPid != e.actorPid)
        for (const QString& p : chain_.filesWrittenBy(e.originatorPid, QString(), false))
            addDirect(p);

    QVector<TaintDropperBatch> batches;
    QStringList subjects{ actor };
    if (e.type == bulwark::EventType::ImageLoad && !e.target.trimmed().isEmpty())
        subjects << e.target.trimmed();
    for (const QString& subject : subjects) {
        const bulwark::engine::ProcessChainTracker::Writer w =
            chain_.lastWriterOf(subject, kRecentDropWindowSecs);
        if (!w.isValid() || w.pid == e.actorPid)
            continue;
        if (!w.path.isEmpty() && engine_->trustNoteForPath(w.path))
            continue;
        TaintDropperBatch b;
        b.dropperPath = w.path;
        b.dropperIsSystem = w.path.isEmpty() || isSweepExemptPath(w.path);
        b.subjectDir = QFileInfo(subject).absolutePath().replace(QLatin1Char('/'), QLatin1Char('\\'));
        for (const QString& p : chain_.filesWrittenBy(w.pid, w.path, true)) {
            TaintCandidate c;
            if (b.files.size() < kTaintMaxPerBlock && eligible(p, &c))
                b.files.append(c);
        }
        if (!b.dropperIsSystem)
            eligible(w.path, &b.dropperSelf);
        if (!b.files.isEmpty() || !b.dropperSelf.path.isEmpty())
            batches.append(b);
    }

    if (direct.isEmpty() && batches.isEmpty())
        return;

    QString reason = why.trimmed();
    if (isTaintRuleNote(reason))
        reason = QStringLiteral("关联释放物再次被拦");
    if (reason.size() > 60)
        reason = reason.left(60) + QStringLiteral("…");
    const QString subjectActor = actor;

    taintPool_.start([this, direct, batches, grade, reason, subjectActor]() {
        auto knownBad = [this](const QString& sha) {
            if (sha.isEmpty())
                return false;
            QMutexLocker lk(&maliciousHashMx_);
            return confirmedMaliciousHashes_.contains(sha);
        };
        QVector<TaintResult> results;
        int skippedSigned = 0;
        auto consider = [&](const TaintCandidate& c, bool byAssociation) {
            if (results.size() >= kTaintMaxPerBlock || c.path.isEmpty())
                return;
            if (!QFileInfo(c.path).isFile())
                return;
            const QString sha = QuarantineManager::tryComputeSha256(c.path).toLower();
            if (ProcessInspector::isSigned(c.path) && !knownBad(sha)) {
                ++skippedSigned;
                return;
            }
            results.append(TaintResult{ c.path, c.kind, sha, byAssociation });
        };
        for (const TaintCandidate& c : direct)
            consider(c, false);
        for (const TaintDropperBatch& b : batches) {
            const bool restricted = b.dropperIsSystem || ProcessInspector::isSigned(b.dropperPath);
            if (restricted && isSharedDropRoot(b.subjectDir))
                continue;
            const QString dirPrefix = b.subjectDir.toLower() + QLatin1Char('\\');
            for (const TaintCandidate& c : b.files) {
                if (restricted && !c.path.toLower().replace(QLatin1Char('/'), QLatin1Char('\\'))
                                       .startsWith(dirPrefix))
                    continue;
                consider(c, true);
            }
            if (!restricted) {
                consider(b.dropperSelf, false);
            }
        }
        if (results.isEmpty())
            return;
        QMetaObject::invokeMethod(
            this,
            [this, results, grade, reason, subjectActor, skippedSigned]() {
                const QDateTime now = QDateTime::currentDateTimeUtc();
                QVector<bulwark::DefenseRule> rules;
                QStringList tainted;
                QStringList askedOnly;
                for (const TaintResult& r : results) {
                    if (engine_->trustNoteForPath(r.path))
                        continue;
                    const bool hard = grade == VerdictAction::Block && !r.byAssociation;
                    const QDateTime expires = now.addDays(hard ? kTaintConfirmedDays : kTaintUserDays);
                    const QString verb = hard ? QStringLiteral("禁止运行/加载")
                                              : QStringLiteral("运行/加载前询问");
                    const QString why = r.byAssociation ? (reason + QStringLiteral("(同批解包的关联文件)"))
                                                        : reason;
                    const QString base = taintRuleTag() + QStringLiteral(" ") + why
                                       + QStringLiteral(" · ") + verb;
                    const QString tail = taintPathMarker() + r.path;
                    auto make = [&]() {
                        bulwark::DefenseRule d;
                        d.action = hard ? VerdictAction::Block : VerdictAction::Ask;
                        d.hardOverride = hard;
                        d.expiresUtc = expires;
                        return d;
                    };
                    const QString needle = driveAgnostic(r.path);
                    switch (r.kind) {
                        case TaintKind::Exec: {
                            bulwark::DefenseRule d = make();
                            d.type = bulwark::EventType::ProcessCreate;
                            d.actorPath = r.path;
                            d.note = base + tail;
                            rules.append(d);
                            if (r.sha256.size() == 64) {
                                bulwark::DefenseRule h = make();
                                h.type = bulwark::EventType::ProcessCreate;
                                h.actorHashes.insert(r.sha256);
                                h.note = base + QStringLiteral("(sha256 ") + r.sha256.left(12)
                                       + QStringLiteral("…)") + tail;
                                rules.append(h);
                            }
                            break;
                        }
                        case TaintKind::Script: {
                            if (needle.size() < 6)
                                continue;
                            bulwark::DefenseRule d = make();
                            d.type = bulwark::EventType::ProcessCreate;
                            d.commandLinePattern = QStringLiteral("*") + needle + QStringLiteral("*");
                            d.note = base + tail;
                            rules.append(d);
                            break;
                        }
                        case TaintKind::Module: {
                            if (needle.size() < 6)
                                continue;
                            bulwark::DefenseRule d = make();
                            d.type = bulwark::EventType::ImageLoad;
                            d.targetPattern = QStringLiteral("*") + needle;
                            d.note = base + tail;
                            rules.append(d);
                            break;
                        }
                        default:
                            continue;
                    }
                    if (hard)
                        tainted << r.path;
                    else
                        askedOnly << r.path;
                }
                if (rules.isEmpty())
                    return;

                const auto sameSubject = [](const bulwark::DefenseRule& a,
                                            const bulwark::DefenseRule& b) {
                    return a.type == b.type
                        && a.actorPath.compare(b.actorPath, Qt::CaseInsensitive) == 0
                        && a.actorPattern.compare(b.actorPattern, Qt::CaseInsensitive) == 0
                        && a.targetPattern.compare(b.targetPattern, Qt::CaseInsensitive) == 0
                        && a.commandLinePattern.compare(b.commandLinePattern, Qt::CaseInsensitive) == 0
                        && a.parentPattern.compare(b.parentPattern, Qt::CaseInsensitive) == 0
                        && a.actorHashes == b.actorHashes;
                };
                const QVector<bulwark::DefenseRule> existing = engine_->getRules();
                QVector<bulwark::DefenseRule> filtered;
                QSet<QUuid> replaceIds;
                for (const bulwark::DefenseRule& incoming : std::as_const(rules)) {
                    bool keep = true;
                    for (const bulwark::DefenseRule& old : existing) {
                        if (!isTaintRuleNote(old.note) || !sameSubject(incoming, old))
                            continue;
                        if (old.action == VerdictAction::Block
                            && incoming.action != VerdictAction::Block) {
                            keep = false; // 关联 Ask 不得降级已确认 Block
                            break;
                        }
                        replaceIds.insert(old.id);
                    }
                    if (keep)
                        filtered.append(incoming);
                }
                for (const QUuid& id : std::as_const(replaceIds))
                    engine_->removeRule(id);
                rules = std::move(filtered);
                if (rules.isEmpty())
                    return;

                evictOldTaintRules(static_cast<int>(rules.size()));
                const int added = injectTaintRules_ ? injectTaintRules_(rules) : 0;
                QStringList parts;
                if (!tainted.isEmpty())
                    parts << QStringLiteral("硬拦 %1 个(再次运行/加载即拦截,%2 天内有效):%3")
                                 .arg(tainted.size())
                                 .arg(kTaintConfirmedDays)
                                 .arg(tainted.join(QStringLiteral("; ")));
                if (!askedOnly.isEmpty())
                    parts << QStringLiteral("询问 %1 个(同批解包的关联文件,证据只到「关联」,"
                                            "故运行/加载前询问而不直接拦,%2 天内有效):%3")
                                 .arg(askedOnly.size())
                                 .arg(kTaintUserDays)
                                 .arg(askedOnly.join(QStringLiteral("; ")));
                const int total = tainted.size() + askedOnly.size();
                QString msg;
                if (added > 0) {
                    msg = QStringLiteral("释放物已布防:%1 被拦(%2),共登记 %3 个"
                                         "(新增规则 %4 条,跳过带可信签名 %5 个)。%6")
                              .arg(subjectActor, reason)
                              .arg(total)
                              .arg(added)
                              .arg(skippedSigned)
                              .arg(parts.join(QStringLiteral(" | ")));
                    log_.warning(msg);
                } else {
                    msg = QStringLiteral("释放物【未能布防】:%1 被拦(%2),找到释放物 %3 个,"
                                         "但一条规则都没能生效(已被标记过,或规则库预算已满)"
                                         "—— 这些文件再次运行时不会被本条策略管住。%4")
                              .arg(subjectActor, reason)
                              .arg(total)
                              .arg(parts.join(QStringLiteral(" | ")));
                    log_.warning(msg);
                }
                ipc_->sendLog(msg);
            },
            Qt::QueuedConnection);
    });
}

int Worker::evictOldTaintRules(int incoming) {
    QVector<QPair<QDateTime, QUuid>> taint;
    for (const bulwark::DefenseRule& r : engine_->getRules())
        if (isTaintRuleNote(r.note))
            taint.append(qMakePair(r.createdUtc, r.id));
    const int over = static_cast<int>(taint.size()) + incoming - kTaintMaxTotal;
    if (over <= 0)
        return 0;
    std::stable_sort(taint.begin(), taint.end(),
                     [](const QPair<QDateTime, QUuid>& a, const QPair<QDateTime, QUuid>& b) {
                         return a.first < b.first;
                     });
    int removed = 0;
    for (int i = 0; i < over && i < taint.size(); ++i)
        if (engine_->removeRule(taint[i].second))
            ++removed;
    if (removed > 0) {
        ruleStore_->save(engine_->getRules());
        log_.info(QStringLiteral("释放物污点:规则总量达上限 %1,已淘汰最旧的 %2 条。")
                      .arg(kTaintMaxTotal).arg(removed));
    }
    return removed;
}

void Worker::dropTaintRulesMatching(const SecurityEvent& e) {
    const QString selfPath = e.actorPath.trimmed();
    if (selfPath.isEmpty())
        return;
    const QString selfLower = selfPath.toLower();
    const QString selfHash = e.actorHash.trimmed().toLower();
    int removed = 0;
    QStringList dropped;
    const QVector<bulwark::DefenseRule> all = engine_->getRules();
    for (const bulwark::DefenseRule& r : all) {
        if (!isTaintRuleNote(r.note))
            continue;
        const QString p = taintNotePath(r.note).trimmed().toLower();
        const bool samePath = !p.isEmpty() && p == selfLower;
        const bool sameHash = !selfHash.isEmpty()
            && (r.actorHashes.contains(selfHash.toUpper())
                || r.note.contains(selfHash, Qt::CaseInsensitive));
        const bool sameActor = !r.actorPath.isEmpty()
            && r.actorPath.compare(selfPath, Qt::CaseInsensitive) == 0;
        if (!(samePath || sameActor || sameHash))
            continue;
        if (engine_->removeRule(r.id)) {
            ++removed;
            dropped << (p.isEmpty() ? selfLower : p);
        }
    }
    if (removed > 0) {
        ruleStore_->save(engine_->getRules());
        const QString msg = QStringLiteral("释放物污点:用户已放行,仅撤销该文件的污点规则 %1 条:%2")
                                .arg(removed).arg(dropped.join(QStringLiteral("; ")));
        log_.info(msg);
        ipc_->sendLog(msg);
    }
}

void Worker::purgeTaintRulesAfterTrust() {
    int removed = 0;
    for (const bulwark::DefenseRule& r : engine_->getRules()) {
        if (!isTaintRuleNote(r.note))
            continue;
        const QString p = taintNotePath(r.note);
        if (!p.isEmpty() && engine_->trustNoteForPath(p) && engine_->removeRule(r.id))
            ++removed;
    }
    if (removed > 0) {
        ruleStore_->save(engine_->getRules());
        log_.info(QStringLiteral("加白后撤销释放物污点规则 %1 条。").arg(removed));
    }
}

void Worker::reportPreBlockedEvent(const SecurityEvent& e) {
    using bulwark::EnforcementOutcome;
    ipc_->sendBlock(e, EnforcementOutcome::KernelBlocked, false, false);
    recordEvent(e, VerdictAction::Block, VerdictSource::Heuristic, EnforcementOutcome::KernelBlocked);
}

void Worker::scanScriptFileBody(bulwark::SecurityEvent& e) {
    using bulwark::engine::ScriptAnalyzer;
    using bulwark::engine::ScriptType;
    constexpr int kMaxCache = 512;

    if (e.type != bulwark::EventType::ProcessCreate || e.commandLine.isEmpty() || e.userTrusted)
        return;
    const QString host = bulwark::engine::detail::fileNameLower(e.actorPath);
    static const QSet<QString> kHosts = {
        QStringLiteral("cmd.exe"), QStringLiteral("powershell.exe"), QStringLiteral("pwsh.exe"),
        QStringLiteral("wscript.exe"), QStringLiteral("cscript.exe"), QStringLiteral("mshta.exe"),
    };
    if (!kHosts.contains(host))
        return;
    const QString scriptPath = ScriptAnalyzer::extractScriptFilePath(e.commandLine);
    const ScriptType type = ScriptAnalyzer::scriptTypeFromPath(scriptPath);
    if (scriptPath.isEmpty() || type == ScriptType::Unknown)
        return;
    const QFileInfo fi(scriptPath);
    if (!fi.isFile())
        return;

    const QString key = scriptPath.toLower() + QLatin1Char('|') + QString::number(fi.size())
                      + QLatin1Char('|') + QString::number(fi.lastModified().toMSecsSinceEpoch());
    auto cached = scriptBodyCache_.constFind(key);
    if (cached == scriptBodyCache_.constEnd()) {
        QFile f(scriptPath);
        if (!f.open(QIODevice::ReadOnly))
            return;
        const QByteArray raw = f.read(ScriptAnalyzer::kScanPrefixBytes);
        f.close();
        const bool utf16 = raw.size() >= 2 && static_cast<uchar>(raw[0]) == 0xFF
                           && static_cast<uchar>(raw[1]) == 0xFE;
        const QString body = utf16
            ? QString::fromUtf16(reinterpret_cast<const char16_t*>(raw.constData() + 2), (raw.size() - 2) / 2)
            : QString::fromUtf8(raw);
        const ScriptAnalyzer::Result r =
            ScriptAnalyzer::analyze(body, type, bulwark::snippet::titleFromName(fi.fileName()));
        if (scriptBodyCache_.size() >= kMaxCache)
            scriptBodyCache_.clear();
        cached = scriptBodyCache_.insert(key, ScriptBodyScan{ r.score, r.hardSignal, r.hits, r.reasons, r.snippets });
    }
    const ScriptBodyScan& scan = cached.value();
    if (scan.score <= 0 && !scan.hard)
        return;
    e.scriptFilePath          = scriptPath;
    e.scriptFileScore         = scan.score;
    e.scriptFileHardIndicator = scan.hard;
    e.scriptFileHits          = scan.hits;
    e.scriptFileReasons       = scan.reasons;
    for (const bulwark::ThreatSnippet& s : scan.snippets)
        e.addSnippet(s);
    if (scan.hard)
        log_.warning(QStringLiteral("脚本正文判据命中:%1 执行 %2 —— %3(%4 分)")
                         .arg(host, scriptPath, scan.hits.join(QStringLiteral(", ")))
                         .arg(scan.score));
}

void Worker::recordEvent(const SecurityEvent& e, VerdictAction action, VerdictSource source,
                         bulwark::EnforcementOutcome enforcement) {
    ipc_->sendEventLog(e, action, source, enforcement);
    if (eventHistory_) {
        bulwark::ipc::EventLogPayload p;
        p.event = e;
        p.action = action;
        p.source = source;
        p.enforcement = enforcement;
        eventHistory_->add(p);
    }
    if (alertExporter_)
        alertExporter_->exportAlert(e, bulwark::Verdict::forEvent(e, action, source));
}

void Worker::detectSideloadedTamperedModule(bulwark::SecurityEvent& e) {
    constexpr int kMaxVerify = 40;
    constexpr int kMaxCache  = 512;

    if (!e.actorSigned || e.signatureMismatch)
        return;
    const QString path = e.actorPath;
    if (path.isEmpty() || path.startsWith(QLatin1String("PID "), Qt::CaseInsensitive))
        return;

    const QString dir = QFileInfo(path).absolutePath();
    if (dir.isEmpty())
        return;

    QString dirLower = dir.toLower();
    dirLower.replace(QLatin1Char('/'), QLatin1Char('\\'));
    if (dirLower.contains(QLatin1String("\\program files\\")) ||
        dirLower.contains(QLatin1String("\\program files (x86)\\")) ||
        dirLower.startsWith(QLatin1String("c:\\windows\\")))
        return;

    const QDateTime dirMtime = QFileInfo(dir).lastModified();
    const QString key = dirLower + QLatin1Char('|')
                      + QString::number(dirMtime.toMSecsSinceEpoch());
    const auto cached = tamperScanCache_.constFind(key);
    if (cached != tamperScanCache_.constEnd()) {
        const SideloadScan& hit = cached.value();
        if (!hit.tamperedPath.isEmpty())
            e.tamperedModulePath = hit.tamperedPath;
        if (!hit.unsignedPath.isEmpty()) {
            e.sideloadedUnsignedModulePath = hit.unsignedPath;
            e.sideloadedUnsignedModuleWhy  = hit.unsignedWhy;
        }
        return;
    }

    SideloadScan scan;
    QDir d(dir);
    const QStringList filters{ QStringLiteral("*.dll"), QStringLiteral("*.ocx"),
                               QStringLiteral("*.cpl"), QStringLiteral("*.drv") };
    const QFileInfoList entries = d.entryInfoList(filters, QDir::Files | QDir::NoSymLinks, QDir::Name);
    int verified = 0;
    for (const QFileInfo& fi : entries) {
        if (verified >= kMaxVerify)
            break;
        const QString modPath = fi.absoluteFilePath();
        if (modPath.compare(path, Qt::CaseInsensitive) == 0)
            continue;
        ++verified;

        if (ProcessInspector::isSignatureMismatch(modPath)) {
            scan.tamperedPath = modPath;
            break;
        }

        if (!scan.unsignedPath.isEmpty())
            continue;
        QString why;
        if (bulwark::engine::ThreatDetector::isSideloadProneModuleName(modPath))
            why = QStringLiteral("系统同名模块");
        else if (chain_.wasRecentlyWritten(modPath, kRecentDropWindowSecs))
            why = QStringLiteral("最近落地");
        else if (isNonFixedVolume(modPath))
            why = QStringLiteral("位于挂载镜像/可移除卷");
        if (why.isEmpty())
            continue;
        if (ProcessInspector::isSigned(modPath))
            continue;
        scan.unsignedPath = modPath;
        scan.unsignedWhy  = why;
    }

    if (tamperScanCache_.size() >= kMaxCache)
        tamperScanCache_.clear();
    tamperScanCache_.insert(key, scan);

    if (!scan.tamperedPath.isEmpty()) {
        e.tamperedModulePath = scan.tamperedPath;
        log_.warning(QStringLiteral("侧载模块篡改:主体 %1 签名健康,但同目录 %2 内嵌签名校验不通过"
                                    "(签名壳 + 被篡改模块 = 白加黑)。")
                         .arg(path, scan.tamperedPath));
    }
    if (!scan.unsignedPath.isEmpty()) {
        e.sideloadedUnsignedModulePath = scan.unsignedPath;
        e.sideloadedUnsignedModuleWhy  = scan.unsignedWhy;
        log_.warning(QStringLiteral("白加黑侧载:主体 %1 签名健康,但同目录 %2 未签名且%3"
                                    "(签名壳 + 未签名模块 = 银狐主流落法)。")
                         .arg(path, scan.unsignedPath, scan.unsignedWhy));
    }
}

void Worker::writeAudit(const SecurityEvent& e, VerdictAction action, VerdictSource source,
                        bulwark::EnforcementOutcome enforcement,
                        std::optional<VerdictAction> rawAction,
                        std::optional<VerdictSource> rawSource) {
    using namespace bulwark::json;
    QJsonObject o;
    o["timestampUtc"] = dateTimeToIso(QDateTime::currentDateTimeUtc());
    o["type"] = bulwark::eventTypeToString(e.type);
    o["actorPath"] = e.actorPath;
    o["actorPid"] = e.actorPid;
    o["target"] = e.target;
    o["riskScore"] = e.riskScore;
    o["action"] = bulwark::verdictActionToString(action);       // 兼容字段：始终表示最终动作
    o["source"] = bulwark::verdictSourceToString(source);       // 兼容字段：始终表示最终来源
    o["finalAction"] = bulwark::verdictActionToString(action);
    o["finalSource"] = bulwark::verdictSourceToString(source);
    if (rawAction.has_value())
        o["rawAction"] = bulwark::verdictActionToString(*rawAction);
    if (rawSource.has_value())
        o["rawSource"] = bulwark::verdictSourceToString(*rawSource);
    if ((rawAction.has_value() && *rawAction != action)
        || (rawSource.has_value() && *rawSource != source))
        o["policyOverride"] = true;
    if (e.ransomwareContainmentRequired)
        o["ransomwareContainmentRequired"] = true;
    if (e.scriptContainmentRequired)
        o["scriptContainmentRequired"] = true;
    // 审计必须如实记录动作是否发生前被内核挡住、事件来自何种观测面，
    // 以及最终处置结果；Block 不能再靠 action 一项被误读成“必然已拦截”。
    o["kernelBlocked"] = e.kernelBlocked;
    o["userModeObserved"] = e.userModeObserved;
    o["enforcement"] = bulwark::enforcementOutcomeToString(enforcement);
    if (!e.correlationId.isEmpty())
        o["correlationId"] = e.correlationId;
    // 命中的规则说明(可空):只记 source=Rule 无法追溯是哪条规则,故落盘规则名,
    // 事后可直接查「被 [情报-行为]xxx / 未签名可疑目录 等拦/放」。
    if (!e.matchedRuleNote.isEmpty())
        o["matchedRule"] = e.matchedRuleNote;
    o["reasons"] = strListToJson(e.riskReasons);
    audit_->writeRecord(o);
}

void Worker::startMaliciousSweep() {
    if (sweepRunning_.load())
        return;
    seedMaliciousHashesFromRules();
    sweepRunning_.store(true);
    sweepWorker_ = std::thread([this] {
        try {
            sweepLoop();
        } catch (...) {
            // 后台兜底线程绝不因异常带崩服务。
        }
    });
    log_.info(QString::fromUtf8("兜底扫描已启动:定期复查在跑进程,逮住漏网的已确认恶意。"));
}

void Worker::seedMaliciousHashesFromRules() {
    if (engine_) {
        const QVector<bulwark::DefenseRule> rules = engine_->getRules();
        QMutexLocker lk(&maliciousHashMx_);
        for (const bulwark::DefenseRule& r : rules) {
            if (r.action != VerdictAction::Block)
                continue;
            for (const QString& h : r.actorHashes)
                if (h.size() == 64)
                    confirmedMaliciousHashes_.insert(h.toLower());
        }
    }
    // 旧版本里用户手动拉黑过的样本哈希。新版本不再写入这个文件,但已有条目继续生效,
    // 不能因为功能下线就悄悄放过用户明确拉黑的样本。
    QFile f(QDir(programDataDir()).filePath(QStringLiteral("blocked_hashes.txt")));
    if (f.open(QIODevice::ReadOnly | QIODevice::Text)) {
        QMutexLocker lk(&maliciousHashMx_);
        while (!f.atEnd()) {
            const QString line = QString::fromLatin1(f.readLine()).trimmed().toLower();
            if (line.size() == 64)
                confirmedMaliciousHashes_.insert(line);
        }
    }
}

QStringList Worker::s_sweepExemptDirs;
QMutex Worker::s_sweepExemptMx;

void Worker::setSelfExemptDirs(const QStringList& dirs) {
    QMutexLocker lk(&s_sweepExemptMx);
    s_sweepExemptDirs.clear();
    for (const QString& d : dirs) {
        QString n = d.trimmed().toLower();
        if (n.isEmpty()) continue;
        n.replace(QLatin1Char('/'), QLatin1Char('\\'));
        if (!n.endsWith(QLatin1Char('\\'))) n += QLatin1Char('\\');
        s_sweepExemptDirs << n;
    }
}

bool Worker::isSweepExemptPath(const QString& path) {
    if (path.isEmpty())
        return true;
    QString p = path.toLower();
    p.replace(QLatin1Char('/'), QLatin1Char('\\'));

    if (p.size() >= 2 && p.at(1) == QLatin1Char(':')) {
        const QStringView rel = QStringView(p).mid(2);
        if (rel.startsWith(QStringLiteral("\\windows\\system32\\")) ||
            rel.startsWith(QStringLiteral("\\windows\\syswow64\\")) ||
            rel.startsWith(QStringLiteral("\\windows\\winsxs\\")))
            return true;
    }

    {
        QMutexLocker lk(&s_sweepExemptMx);
        for (const QString& d : s_sweepExemptDirs)
            if (p.startsWith(d)) return true;
    }
    return false;
}

void Worker::sweepLoop() {
    struct HashEntry {
        QString hashUpper;
        qint64 size = 0;
        qint64 mtimeMs = 0;
    };
    QHash<QString, HashEntry> pathHashCache;
    constexpr int kSweepHashCacheMax = 2048;

    for (int i = 0; i < 15 && sweepRunning_.load(); ++i)
        std::this_thread::sleep_for(std::chrono::seconds(1));

    while (sweepRunning_.load()) {
        const bool enabled = sweepProtectionEnabled_.load() && !protectionSuspended_.load();
        if (enabled) {
            const QList<int> pids = ProcessInspector::enumeratePids();
            for (int pid : pids) {
                if (!sweepRunning_.load())
                    break;
                const QString path = ProcessInspector::tryGetProcessImagePath(pid);
                if (path.isEmpty() || isSweepExemptPath(path))
                    continue;

                const QFileInfo fi(path);
                const qint64 size = fi.size();
                const qint64 mtimeMs = fi.lastModified().toMSecsSinceEpoch();

                QString hashU;
                const auto it = pathHashCache.constFind(path);
                if (it != pathHashCache.constEnd()
                    && it.value().size == size && it.value().mtimeMs == mtimeMs) {
                    hashU = it.value().hashUpper;
                }
                if (hashU.isEmpty()) {
                    hashU = ProcessInspector::tryComputeSha256(path);
                    if (!hashU.isEmpty()) {
                        if (pathHashCache.size() >= kSweepHashCacheMax)
                            pathHashCache.clear();
                        pathHashCache.insert(path, HashEntry{ hashU, size, mtimeMs });
                    }
                }
                if (hashU.size() != 64)
                    continue;

                QString label;
                bool malicious = false;
                {
                    QMutexLocker lk(&maliciousHashMx_);
                    if (confirmedMaliciousHashes_.contains(hashU.toLower())) {
                        malicious = true;
                        label = QString::fromUtf8("已记忆恶意哈希");
                    }
                }
                if (!malicious)
                    continue;

                SecurityEvent e;
                e.type = bulwark::EventType::ProcessCreate;
                e.actorPid = pid;
                e.actorPath = path;
                e.target = path;
                e.actorHash = hashU;
                e.userModeObserved = true;
                e.hasThreatIndicator = true;
                e.riskScore = 95;
                e.detail = label;
                if (const auto inst = ProcessInspector::tryGetProcessInstance(pid))
                    e.actorCreationFileTime = inst->creationFileTime;
                QMetaObject::invokeMethod(
                    this, [this, e] { handleSweptMalicious(e, VerdictSource::Heuristic); },
                    Qt::QueuedConnection);
            }
        }
        for (int i = 0; i < 60 && sweepRunning_.load(); ++i)
            std::this_thread::sleep_for(std::chrono::seconds(1));
    }
}

void Worker::handleSweptMalicious(const SecurityEvent& e, VerdictSource source) {
    if (abortIfTrustedNow(e, QStringLiteral("兜底扫描")))
        return;
    SecurityEvent ev = e;
    ev.hasThreatIndicator = true;
    const QString msg = QString::fromUtf8("兜底扫描:发现漏网的已确认恶意进程 PID=%1 %2(%3)—— 补封禁+结束+隔离。")
                            .arg(QString::number(ev.actorPid), ev.actorPath, ev.detail);
    log_.warning(msg);
    ipc_->sendLog(msg);
    if (ev.riskScore < 95)
        ev.riskScore = 95;
    ev.addEvidence(QStringLiteral("Reputation"), bulwark::EvidenceKind::HardIndicator,
                   ev.detail.trimmed().isEmpty()
                       ? QString::fromUtf8("兜底扫描复查:已确认恶意")
                       : QString::fromUtf8("兜底扫描复查:已确认恶意(%1)").arg(ev.detail.trimmed()));

    const DurableExecBlockExecution execution = WorkerDurableExecBlockSeam::fromSweptMalicious(
        ev, ProcessInspector::tryGetProcessInstance(ev.actorPid),
        [this](const DurableExecBlockAuthorization& authorization) {
            return blacklistExec(authorization);
        },
        [this](int containmentPid) { return killMalicious(containmentPid); });

    bulwark::EnforcementOutcome outcome = execution.containmentSucceeded
        ? bulwark::EnforcementOutcome::Terminated
        : bulwark::EnforcementOutcome::AlertedOnly;
    if (!execution.containmentSucceeded && wasTerminatedByUs(ev.actorPid, ev.actorPath))
        outcome = bulwark::EnforcementOutcome::ActorAlreadyGone;
    bool execDenied = execution.persistenceSucceeded;
    if (!execution.evaluation.authorization.has_value()) {
        log_.warning(QStringLiteral("持久执行阻断已拒绝:%1(PID=%2,事件映像=%3)——"
                                    "未写入 FileExecBlock 或拒绝执行 ACE；仍继续当次收容。")
                         .arg(durableExecBlockDecisionName(execution.evaluation.decision))
                         .arg(ev.actorPid)
                         .arg(ev.actorPath));
    }

    const bool actorVaulted =
        remediateIfMalicious(ev, bulwark::Verdict::forEvent(ev, VerdictAction::Block, source));
    if (outcome == bulwark::EnforcementOutcome::AlertedOnly) {
        if (actorVaulted)
            outcome = bulwark::EnforcementOutcome::PayloadQuarantined;
        else if (execDenied)
            outcome = bulwark::EnforcementOutcome::ExecDenied;
    }
    ipc_->sendBlock(ev, outcome, false, execDenied);
    recordEvent(ev, VerdictAction::Block, source, outcome);
    taintDroppedFiles(ev, VerdictAction::Block, QStringLiteral("兜底扫描确认恶意"));
}

void Worker::startPreexistingAudit(int delaySeconds) {
    if (preexistingRunning_.load())
        return;
    if (preexistingWorker_.joinable())
        preexistingWorker_.join();
    preexistingRunning_.store(true);
    preexistingWorker_ = std::thread([this, delaySeconds] {
        try {
            preexistingAuditLoop(delaySeconds);
        } catch (...) {
            // 后台线程绝不因异常带崩服务。
        }
        preexistingRunning_.store(false);
    });
    log_.info(QString::fromUtf8("启动补判已排队:稍后对服务启动前就在跑的进程做一次回溯规则裁决。"));
}

void Worker::preexistingAuditLoop(int delaySeconds) {
    for (int i = 0; i < delaySeconds && preexistingRunning_.load(); ++i)
        std::this_thread::sleep_for(std::chrono::seconds(1));
    if (!preexistingRunning_.load() || protectionSuspended_.load())
        return;

    monitoring::ProcessEnumerator::Options opt;
    opt.includeCommandLine = true;
    opt.resolveOrigin = true;
    opt.verifySignature = true;
    QList<bulwark::ProcessEntry> procs;
    try {
        procs = monitoring::ProcessEnumerator::snapshot(opt);
    } catch (...) {
        log_.warning(QString::fromUtf8("启动补判:进程枚举失败,本轮跳过。"));
        return;
    }

    int considered = 0;
    for (const bulwark::ProcessEntry& p : procs) {
        if (!preexistingRunning_.load() || protectionSuspended_.load())
            break;
        if (p.pid <= 4)
            continue;
        if (p.imagePath.isEmpty())
            continue;
        if (isSweepExemptPath(p.imagePath))
            continue;
        if (p.isProtectedSelf || p.isTrusted || p.isCritical)
            continue;

        SecurityEvent e;
        e.type = bulwark::EventType::ProcessCreate;
        e.actorPid = p.pid;
        e.actorPath = p.imagePath;
        e.target = p.imagePath;
        e.commandLine = p.commandLine;
        e.parentPid = p.parentPid;
        e.parentPath = p.parentPid > 0 ? ProcessInspector::tryGetProcessImagePath(p.parentPid)
                                       : QString();
        e.actorSigned = p.isSigned;
        e.signatureMismatch = p.signatureMismatch;
        e.actorPublisher = p.publisher;
        e.fileDescription = p.fileDescription;
        if (!p.sha256.isEmpty())
            e.actorHash = p.sha256;
        e.originService = p.originService;
        e.originServiceDisplay = p.originServiceDisplay;
        e.originTask = p.originTask;
        e.originDetail = p.originDetail;
        e.userModeObserved = true;
        e.detail = QString::fromUtf8("启动补判(服务启动前已在运行)");
        e.timestampUtc = QDateTime::currentDateTimeUtc();
        if (const auto inst = ProcessInspector::tryGetProcessInstance(p.pid))
            e.actorCreationFileTime = inst->creationFileTime;
        ++considered;

        QMetaObject::invokeMethod(
            this, [this, e] { evaluatePreexisting(e); }, Qt::QueuedConnection);
    }
    log_.info(QString::fromUtf8("启动补判:已枚举 %1 个在跑进程,送入回溯裁决 %2 个(其余为系统目录/自身/已信任)。")
                  .arg(procs.size())
                  .arg(considered));
}

void Worker::evaluatePreexisting(const SecurityEvent& incoming) {
    if (protectionSuspended_.load())
        return;
    if (settings_ && (!settings_->protectionEnabled || !isDimensionEnabled(incoming.type)))
        return;

    const QString instanceKey = QStringLiteral("%1|%2").arg(incoming.actorPid).arg(
        incoming.actorCreationFileTime ? *incoming.actorCreationFileTime : 0);
    if (preexistingSeen_.contains(instanceKey))
        return;
    if (preexistingSeen_.size() >= 8192)
        preexistingSeen_.clear();
    preexistingSeen_.insert(instanceKey);

    SecurityEvent e = incoming;
    enrich(e);
    const bulwark::Verdict v = engine_->evaluate(e);

    const bool interesting = (v.action != VerdictAction::Allow) || e.hasThreatIndicator
                             || e.riskScore >= bulwark::engine::ThreatDetector::Suspicious;
    if (!interesting)
        return;

    if (v.action == VerdictAction::Block && e.hasThreatIndicator) {
        // 与兜底扫描同一处置路径:封禁 + 结束树 + 隔离 + 清持久化。
        // 只对硬指标动手 —— 软信号凑出来的高分按产品原则绝不单独定罪。
        log_.warning(QString::fromUtf8("启动补判:命中已驻留的恶意进程 PID=%1 %2(风险 %3)—— 补处置。")
                         .arg(e.actorPid)
                         .arg(e.actorPath)
                         .arg(e.riskScore));
        handleSweptMalicious(e, VerdictSource::Heuristic);
        return;
    }

    VerdictAction action = v.action;
    VerdictSource source = v.source;
    if (e.hasThreatIndicator)
        applySilentMode(e, action, source);
    if (action == VerdictAction::Block) {
        bool execBlocked = false;
        const bulwark::EnforcementOutcome outcome =
            enforceBlock(e, false, &execBlocked);
        ipc_->sendBlock(e, outcome, false, execBlocked);
        maybeQuarantineOnBlock(e);
        remediateIfMalicious(e, bulwark::Verdict::forEvent(e, action, source));
        taintDroppedFiles(e, VerdictAction::Ask,
                          v.action == VerdictAction::Ask ? QStringLiteral("静默模式升级拦截")
                                                         : QStringLiteral("启动补判规则拦截"));
        ipc_->sendLog(describe(e, action));
        recordEvent(e, action, source, outcome);
        writeAudit(e, action, source, outcome);
        return;
    }

    if (action == VerdictAction::Ask && e.hasThreatIndicator) {
        log_.warning(QString::fromUtf8("启动补判:已在运行的进程带硬恶意指标,弹窗询问并冻结 PID=%1 %2(风险 %3)")
                         .arg(e.actorPid)
                         .arg(e.actorPath)
                         .arg(e.riskScore));
        enqueuePrompt(e, true);
        ipc_->sendLog(describe(e, action));
        recordEvent(e, action, source);
        writeAudit(e, action, source);
        return;
    }

    const QString line = describe(e, action);
    if (action == VerdictAction::Ask)
        log_.warning(QString::fromUtf8("启动补判(仅记录,不弹窗):") + line);
    else
        log_.info(QString::fromUtf8("启动补判:")+ line);
    ipc_->sendLog(line);
    ipc_->sendEventLog(e, action, source);
    writeAudit(e, action, source);
}

}
