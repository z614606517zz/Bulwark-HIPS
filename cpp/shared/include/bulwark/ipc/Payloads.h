#pragma once
#include <QString>
#include <QStringList>
#include <QUuid>
#include <QList>
#include <QHash>
#include <QDateTime>
#include <QJsonObject>
#include <optional>
#include "bulwark/models/Enums.h"
#include "bulwark/models/SecurityEvent.h"
#include "bulwark/models/DefenseRule.h"
#include "bulwark/models/RuntimeSettings.h"
#include "bulwark/models/PersistenceEntry.h"
#include "bulwark/models/AttackGraph.h"
#include "bulwark/models/ProcessEntry.h"

namespace bulwark::ipc {

struct HelloPayload {
    int processId = 0;
    QString role = QStringLiteral("ui");

    QJsonObject toJson() const;
    static HelloPayload fromJson(const QJsonObject& o);
};

struct PromptResponsePayload {
    QUuid eventId;
    VerdictAction action = VerdictAction::Allow;
    bool remember = false;
    RememberScope scope = RememberScope::Permanent;
    bool autoTimeout = false;

    QJsonObject toJson() const;
    static PromptResponsePayload fromJson(const QJsonObject& o);
};

struct BlockNotificationPayload {
    bulwark::SecurityEvent event;
    bulwark::EnforcementOutcome enforcement = bulwark::EnforcementOutcome::NotApplicable;
    bool timeoutBlock = false;
    bool execBlocked = false;

    QJsonObject toJson() const;
    static BlockNotificationPayload fromJson(const QJsonObject& o);
};

struct EventLogPayload {
    bulwark::SecurityEvent event;
    VerdictAction action = VerdictAction::Allow;
    VerdictSource source = VerdictSource::DefaultPolicy;
    bulwark::EnforcementOutcome enforcement = bulwark::EnforcementOutcome::NotApplicable;

    QJsonObject toJson() const;
    static EventLogPayload fromJson(const QJsonObject& o);
};

struct EventHistoryResponsePayload {
    QList<EventLogPayload> events;

    QJsonObject toJson() const;
    static EventHistoryResponsePayload fromJson(const QJsonObject& o);
};

struct RemediationSkippedItem {
    QString target;
    QString reason;
    bool isFile = false;
    QString kind;
    QString location;
    QString name;
    bool forceable = false;

    QJsonObject toJson() const;
    static RemediationSkippedItem fromJson(const QJsonObject& o);
};

struct RulesResponsePayload {
    QList<bulwark::DefenseRule> rules;
    QJsonObject toJson() const;
    static RulesResponsePayload fromJson(const QJsonObject& o);
};

struct DeleteRulePayload {
    QUuid ruleId;
    QJsonObject toJson() const;
    static DeleteRulePayload fromJson(const QJsonObject& o);
};

struct AddRulePayload {
    QString actorPath;
    std::optional<bulwark::EventType> type;
    QString targetPattern;
    bulwark::VerdictAction action = bulwark::VerdictAction::Allow;
    QJsonObject toJson() const;
    static AddRulePayload fromJson(const QJsonObject& o);
    // 主体写法:带通配按模式;带盘符或 UNC 按完整路径;其余视为裸文件名,匹配任意目录下的同名程序。
    bulwark::DefenseRule toRule() const;
};

struct TrustListResponsePayload {
    QList<bulwark::DefenseRule> entries;
    QJsonObject toJson() const;
    static TrustListResponsePayload fromJson(const QJsonObject& o);
};

struct AddTrustPayload {
    QString actorPath;
    QString note;
    bool isDirectory = false;
    bool sessionOnly = false;
    std::optional<QDateTime> expiresUtc;
    QJsonObject toJson() const;
    static AddTrustPayload fromJson(const QJsonObject& o);
};

struct RemoveTrustPayload {
    QUuid ruleId;
    QJsonObject toJson() const;
    static RemoveTrustPayload fromJson(const QJsonObject& o);
};

struct QuarantineItemPayload {
    QUuid id;
    QString originalPath;
    QString fileName;
    QDateTime quarantinedUtc;
    qint64 size = 0;
    QString sha256;
    QString reason;
    int actorPid = 0;
    bool originalRemoved = true;
    bool deleteOnRebootScheduled = false;
    QJsonObject toJson() const;
    static QuarantineItemPayload fromJson(const QJsonObject& o);
};

struct QuarantineListResponsePayload {
    QList<QuarantineItemPayload> items;
    QJsonObject toJson() const;
    static QuarantineListResponsePayload fromJson(const QJsonObject& o);
};

struct QuarantineActionPayload {
    QUuid id;
    QJsonObject toJson() const;
    static QuarantineActionPayload fromJson(const QJsonObject& o);
};

struct QuarantineActionResultPayload {
    QUuid id;
    bool success = false;
    QString message;
    QJsonObject toJson() const;
    static QuarantineActionResultPayload fromJson(const QJsonObject& o);
};

struct ManualQuarantinePayload {
    QUuid requestId = QUuid::createUuid();
    QString path;
    bool force = false;
    QString kind;
    QString location;
    QString name;
    QJsonObject toJson() const;
    static ManualQuarantinePayload fromJson(const QJsonObject& o);
};

struct ManualQuarantineResultPayload {
    QUuid requestId;
    bool success = false;
    QString message;
    QJsonObject toJson() const;
    static ManualQuarantineResultPayload fromJson(const QJsonObject& o);
};

struct PersistenceListResponsePayload {
    QDateTime scannedUtc = QDateTime::currentDateTimeUtc();
    QList<bulwark::PersistenceEntry> entries;
    QString message;
    QJsonObject toJson() const;
    static PersistenceListResponsePayload fromJson(const QJsonObject& o);
};

struct PersistenceCleanupRequestPayload {
    QUuid requestId = QUuid::createUuid();
    bulwark::PersistenceEntry entry;
    QJsonObject toJson() const;
    static PersistenceCleanupRequestPayload fromJson(const QJsonObject& o);
};

struct PersistenceCleanupResultPayload {
    QUuid requestId;
    bool success = false;
    QString entryId;
    QString message;
    QStringList quarantinedFiles;
    QStringList removedRegistryValues;
    QList<RemediationSkippedItem> skipped;
    QJsonObject toJson() const;
    static PersistenceCleanupResultPayload fromJson(const QJsonObject& o);
};

struct RemediationReportPayload {
    QDateTime timestampUtc = QDateTime::currentDateTimeUtc();
    QString actorPath;
    int actorPid = 0;
    QString reason;
    bool actorQuarantined = false;
    QStringList quarantinedFiles;
    QStringList removedRegistryValues;
    QList<RemediationSkippedItem> skipped;
    QJsonObject toJson() const;
    static RemediationReportPayload fromJson(const QJsonObject& o);
};

struct IntelRefreshRequestPayload {
    QUuid requestId = QUuid::createUuid();
    bool previewOnly = false;
    QJsonObject toJson() const;
    static IntelRefreshRequestPayload fromJson(const QJsonObject& o);
};

struct IntelRefreshResultPayload {
    QUuid requestId;
    bool success = false;
    int iocCount = 0;
    int rulesApplied = 0;
    QList<bulwark::DefenseRule> generatedRules;
    QStringList threatContext;
    QString message;
    QJsonObject toJson() const;
    static IntelRefreshResultPayload fromJson(const QJsonObject& o);
};

struct IntelApplyRequestPayload {
    QUuid requestId = QUuid::createUuid();
    QList<bulwark::DefenseRule> rules;
    QJsonObject toJson() const;
    static IntelApplyRequestPayload fromJson(const QJsonObject& o);
};

struct TimelineRequestPayload {
    QUuid requestId = QUuid::createUuid();
    QDateTime fromUtc;
    QDateTime toUtc;
    QList<int> types;
    QList<int> actions;
    int minRiskScore = 0;
    int pid = 0;
    bool includeProcessTree = false;
    QString text;
    int limit = 500;                          // 返回上限(服务端硬上限 5000)
    QJsonObject toJson() const;
    static TimelineRequestPayload fromJson(const QJsonObject& o);
};

// 服务 -> UI:时间线查询结果。events 按时间升序(与实时推送一致,UI 自行决定倒序展示)。
struct TimelineResponsePayload {
    QUuid requestId;
    QList<EventLogPayload> events;
    int scanned = 0;
    int matched = 0;
    bool truncated = false;
    QDateTime earliestUtc;
    QString message;
    QJsonObject toJson() const;
    static TimelineResponsePayload fromJson(const QJsonObject& o);
};

struct AttackGraphRequestPayload {
    QUuid requestId = QUuid::createUuid();
    QUuid seedEventId;
    int rootPid = 0;
    int windowSeconds = 3600;
    QJsonObject toJson() const;
    static AttackGraphRequestPayload fromJson(const QJsonObject& o);
};

struct AttackGraphResponsePayload {
    QUuid requestId;
    bool success = false;
    QString message;
    bulwark::AttackGraph graph;
    QJsonObject toJson() const;
    static AttackGraphResponsePayload fromJson(const QJsonObject& o);
};

struct ProcessListRequestPayload {
    QUuid requestId = QUuid::createUuid();
    bool includeCommandLine = true;
    bool resolveOrigin = true;
    QJsonObject toJson() const;
    static ProcessListRequestPayload fromJson(const QJsonObject& o);
};

struct ProcessListResponsePayload {
    QUuid requestId;
    QDateTime snapshotUtc = QDateTime::currentDateTimeUtc();
    QList<bulwark::ProcessEntry> processes;
    QString message;
    QJsonObject toJson() const;
    static ProcessListResponsePayload fromJson(const QJsonObject& o);
};

enum class ProcessActionKind {
    Terminate = 0,
    TerminateTree,
    Suspend,
    Resume,
    QuarantineImage,
    TrustImage,
    ComputeHash,
};

struct ProcessActionRequestPayload {
    QUuid requestId = QUuid::createUuid();
    ProcessActionKind kind = ProcessActionKind::Terminate;
    int pid = 0;
    quint64 creationFileTime = 0;
    QString imagePath;
    QJsonObject toJson() const;
    static ProcessActionRequestPayload fromJson(const QJsonObject& o);
};

// 服务 -> UI:进程处置结果。failed 时 message 必须说明为什么没做成——
// 关键系统进程、自我保护、权限不足、进程已退出,都要如实回话,不允许静默成功。
struct ProcessActionResultPayload {
    QUuid requestId;
    ProcessActionKind kind = ProcessActionKind::Terminate;
    int pid = 0;
    bool success = false;
    QString message;
    QString sha256;
    QJsonObject toJson() const;
    static ProcessActionResultPayload fromJson(const QJsonObject& o);
};

struct PromptWithdrawPayload {
    QUuid eventId;
    QString action;
    QString by;
    QString reason;
    QString actorPath;
    QJsonObject toJson() const;
    static PromptWithdrawPayload fromJson(const QJsonObject& o);
};

struct HardeningItemPayload {
    QString id;
    QString group;
    QString title;
    QString current;
    QString recommended;
    QString cost;
    QString note;
    QString severity;
    bool satisfied = false;
    bool actionable = false;    // 界面能不能对它「应用」
    bool revertible = false;    // 界面现在能不能「撤销」(本产品施加过,且有撤销依据)
    bool needsReboot = false;
    QJsonObject toJson() const;
    static HardeningItemPayload fromJson(const QJsonObject& o);
};

struct HijackAlertPayload {
    QString id;
    QString surface;
    QString title;
    QString location;
    QString oldValue;
    QString newValue;
    QString detail;
    QString state = QStringLiteral("pending");
    QDateTime whenUtc = QDateTime::currentDateTimeUtc();
    bool restorable = true;
    bool preexisting = false;
    QJsonObject toJson() const;
    static HijackAlertPayload fromJson(const QJsonObject& o);
};

struct HardeningStatusResponsePayload {
    QDateTime scannedUtc = QDateTime::currentDateTimeUtc();
    QList<HardeningItemPayload> items;
    QList<HijackAlertPayload> alerts;
    bool actionsEnabled = true;
    bool hijackGuardActive = false;
    QString message;
    QJsonObject toJson() const;
    static HardeningStatusResponsePayload fromJson(const QJsonObject& o);
};

struct HardeningActionRequestPayload {
    QUuid requestId = QUuid::createUuid();
    QString action;
    QString id;
    QJsonObject toJson() const;
    static HardeningActionRequestPayload fromJson(const QJsonObject& o);
};

// 服务 -> UI:动作结果。ok=false 时 message 必须说明为什么没做成,不允许静默成功。
struct HardeningActionResultPayload {
    QUuid requestId;
    QString action;
    QString id;
    bool ok = false;
    bool needsReboot = false;
    QString message;
    QJsonObject toJson() const;
    static HardeningActionResultPayload fromJson(const QJsonObject& o);
};

struct NetTrafficSubscribePayload {
    bool on = true;
    QList<int> focusPids;
    QJsonObject toJson() const;
    static NetTrafficSubscribePayload fromJson(const QJsonObject& o);
};

struct NetTrafficConnPayload {
    QString proto;
    QString remoteIp;
    int remotePort = 0;
    int localPort = 0;
    QString domain;
    QString scope;
    QString proxyName;
    qint64 upBps = 0;
    qint64 downBps = 0;
    qint64 upTotal = 0;
    qint64 downTotal = 0;
    qint64 ageSecs = 0;
    qint64 idleSecs = -1;       // 距上一次有数据的秒数;-1 = 监控期间还没有过数据(只在连接表里)
    bool established = false;
    QJsonObject toJson() const;
    static NetTrafficConnPayload fromJson(const QJsonObject& o);
};

struct NetTrafficRowPayload {
    int pid = 0;
    QString name;
    QString path;
    qint64 upBps = 0;          // 上行 字节/秒
    qint64 downBps = 0;        // 下行 字节/秒
    qint64 upTotal = 0;
    qint64 downTotal = 0;
    int tcpConns = 0;
    QStringList remotes;
    bool critical = false;     // 关键系统进程:结束会蓝屏,界面必须禁用「结束」
    bool protectedSelf = false;
    QString proxyName;
    int proxyConns = 0;
    qint64 proxyUpBps = 0;     // 发给代理的 字节/秒
    qint64 proxyDownBps = 0;   // 从代理收到的 字节/秒
    QJsonObject toJson() const;
    static NetTrafficRowPayload fromJson(const QJsonObject& o);
};

struct NetTrafficSnapshotPayload {
    QDateTime atUtc = QDateTime::currentDateTimeUtc();
    qint64 totalUpBps = 0;
    qint64 totalDownBps = 0;
    qint64 sessionUpBytes = 0;
    qint64 sessionDownBytes = 0;
    bool perProcessAvailable = true;
    QString message;
    QList<NetTrafficRowPayload> rows;
    QHash<int, QList<NetTrafficConnPayload>> connections;
    QJsonObject toJson() const;
    static NetTrafficSnapshotPayload fromJson(const QJsonObject& o);
};

struct SystemBoostRequestPayload {
    QUuid requestId = QUuid::createUuid();
    QJsonObject toJson() const;
    static SystemBoostRequestPayload fromJson(const QJsonObject& o);
};

struct SystemBoostResultPayload {
    QUuid requestId;
    bool success = false;
    int processesTrimmed = 0;
    int processesTotal = 0;
    qint64 freedBytes = 0;       // 回收的物理内存字节数(before - after,夹到 >=0)
    qint64 inUseBefore = 0;
    qint64 inUseAfter = 0;
    qint64 totalPhysical = 0;
    int loadBefore = 0;
    int loadAfter = 0;
    QString message;
    QJsonObject toJson() const;
    static SystemBoostResultPayload fromJson(const QJsonObject& o);
};

struct YaraRuleSourcePayload {
    QString repository;
    int rules = 0;
    QJsonObject toJson() const;
    static YaraRuleSourcePayload fromJson(const QJsonObject& o);
};

struct YaraSkippedRulePayload {
    QString rule;
    int line = 0;
    QString reason;
    QJsonObject toJson() const;
    static YaraSkippedRulePayload fromJson(const QJsonObject& o);
};

// 进程启动扫描的一次命中。level:suspicious / malicious。
struct YaraScanHitPayload {
    QDateTime timeUtc;
    QString path;
    QString sha256;
    QString rule;
    QString author;
    QString level;
    int matchCount = 0;
    QJsonObject toJson() const;
    static YaraScanHitPayload fromJson(const QJsonObject& o);
};

// 进程启动扫描的运行状态。state:off / no-rules / idle / starting / ready / paused / error。
struct YaraScanStatusPayload {
    bool enabled = false;            // 部署配置是否开启进程启动扫描(YaraRules.ScanProcesses)
    QString state = QStringLiteral("off");
    QString detail;
    QString rulesLabel;              // 正在用的规则:联网更新的,或安装包内置的
    int rulesLoaded = 0;
    int verifiedRulePatterns = 0;    // YaraRules.MaliciousRules 的条目数:命中这些才判恶意
    int scannedFiles = 0;
    int suspiciousFiles = 0;
    int maliciousFiles = 0;
    int failedScans = 0;
    int pendingScans = 0;
    QList<YaraScanHitPayload> recentHits;
    QJsonObject toJson() const;
    static YaraScanStatusPayload fromJson(const QJsonObject& o);
};

// 服务 -> UI:YARA 规则库的下载 / 编译状态(查询的回复,也在每次状态变化时广播)。
// stage:idle / checking / downloading / compiling / installing。
struct YaraRulesStatusPayload {
    bool featureEnabled = false;     // 部署配置是否允许联网更新规则
    bool autoUpdate = false;         // 是否按周期自动检查
    bool compilerAvailable = false;  // 辅助程序 bulwark_yarac.exe 是否随包就位
    bool usedForDetection = false;   // 规则是否已接入检测(进程启动扫描在跑)
    QString engine;
    QString stage = QStringLiteral("idle");
    QString stageDetail;
    QString package;
    QString releaseTag;
    QDateTime releasePublishedUtc;
    QString packageSha256;
    qint64 packageBytes = 0;
    int rulesFound = 0;
    int rulesCompiled = 0;
    int rulesSkipped = 0;
    qint64 compiledBytes = 0;
    qint64 compileMs = 0;
    QString rulesPath;
    QString dataDir;
    QDateTime lastCheckUtc;
    QDateTime lastSuccessUtc;
    QDateTime nextCheckUtc;
    int checkIntervalHours = 24;
    bool lastCheckFailed = false;
    QString message;
    QList<YaraRuleSourcePayload> sources;
    QList<YaraSkippedRulePayload> skipped;
    YaraScanStatusPayload scan;
    QJsonObject toJson() const;
    static YaraRulesStatusPayload fromJson(const QJsonObject& o);
};

// UI -> 服务:action 为 "update"(立即检查并更新)或 "auto"(enabled 指定是否自动更新)。
struct YaraRulesActionRequestPayload {
    QUuid requestId = QUuid::createUuid();
    QString action;
    bool enabled = false;
    QJsonObject toJson() const;
    static YaraRulesActionRequestPayload fromJson(const QJsonObject& o);
};

// 服务 -> UI:动作是否被受理。ok=false 时 message 必须说明为什么没做。
struct YaraRulesActionResultPayload {
    QUuid requestId;
    QString action;
    bool ok = false;
    QString message;
    QJsonObject toJson() const;
    static YaraRulesActionResultPayload fromJson(const QJsonObject& o);
};

}
