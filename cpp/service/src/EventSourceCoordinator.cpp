#include "bulwark/service/EventSourceCoordinator.h"
#include "bulwark/service/DriverEventSource.h"
#include "bulwark/service/DriverControl.h"
#include "bulwark/service/UserModeBehaviorSource.h"
#include "bulwark/service/UserModeExecBlock.h"
#include "bulwark/service/UserModeNetworkBlock.h"
#include "bulwark/service/monitoring/ProcessInspector.h"

#include "bulwark/models/Enums.h"

#include <QDateTime>
#include <QDir>
#include <QTimer>

#include <utility>

namespace bulwark::service {

namespace {

QString remoteThreadDedupKey(const bulwark::SecurityEvent& e)
{
    if (e.actorPid <= 0)
        return {};
    const QString target = e.parentPid > 0
        ? QString::number(e.parentPid)
        : e.target.trimmed().toLower();
    if (target.isEmpty())
        return {};
    return QStringLiteral("%1|%2").arg(e.actorPid).arg(target);
}

QString imageLoadDedupKey(const bulwark::SecurityEvent& e)
{
    const QString target = QDir::cleanPath(e.target.trimmed()).toLower();
    if (target.isEmpty())
        return {};
    return QStringLiteral("%1|%2").arg(e.actorPid).arg(target);
}

QString observedIoDedupKey(const bulwark::SecurityEvent& e)
{
    if (e.kernelBlocked || e.actorPid <= 0 || e.target.trimmed().isEmpty())
        return {};
    if (e.type != bulwark::EventType::FileWrite
        && e.type != bulwark::EventType::FileDelete
        && e.type != bulwark::EventType::RegistryWrite)
        return {};
    QString target = QDir::cleanPath(e.target.trimmed());
    target.replace(QLatin1Char('/'), QLatin1Char('\\'));
    return QStringLiteral("%1|%2|%3|%4")
        .arg(static_cast<int>(e.type))
        .arg(e.actorPid)
        .arg(static_cast<int>(e.registryOp))
        .arg(target.toLower());
}

bulwark::SecurityEvent withProcessIdentity(bulwark::SecurityEvent e)
{
    if (e.actorPid <= 4 || e.actorCreationFileTime.has_value())
        return e;
    if (const auto instance = monitoring::ProcessInspector::tryGetProcessInstance(e.actorPid)) {
        e.actorCreationFileTime = instance->creationFileTime;
        if (e.actorPath.isEmpty()
            || e.actorPath.startsWith(QLatin1String("PID "), Qt::CaseInsensitive))
            e.actorPath = instance->imagePath;
    }
    return e;
}

}

EventSourceCoordinator::EventSourceCoordinator(EventSource* base, UserModeBehaviorSource* behavior,
                                               const BulwarkOptions& options, QObject* parent)
    : EventSource(parent), base_(base), behavior_(behavior), options_(options) {
    if (base_)
        connect(base_, &EventSource::eventProduced, this, &EventSourceCoordinator::onBaseEvent);
    if (behavior_)
        connect(behavior_, &EventSource::eventProduced, this, &EventSourceCoordinator::onBehaviorEvent);
    kernelRetry_ = new QTimer(this);
    kernelRetry_->setInterval(10000);
    connect(kernelRetry_, &QTimer::timeout, this, &EventSourceCoordinator::onKernelRetry);
    if (options_.UserModeExecBlockEnabled)
        execBlock_ = new UserModeExecBlock(options_.UserModeExecBlockMax, this);
    if (options_.UserModeNetworkBlockEnabled)
        netBlock_ = new UserModeNetworkBlock(options_.UserModeNetworkBlockMax);
}

EventSourceCoordinator::~EventSourceCoordinator() {
    stop();
    delete netBlock_;
    netBlock_ = nullptr;
}

void EventSourceCoordinator::addAuxSource(EventSource* s) {
    if (s == nullptr)
        return;
    for (const QPointer<EventSource>& p : aux_) {
        if (p.data() == s)
            return;
    }
    aux_.push_back(QPointer<EventSource>(s));
    connect(s, &EventSource::eventProduced, this, &EventSourceCoordinator::onBehaviorEvent);
    if (started_ && !suspended_)
        s->start();
}

void EventSourceCoordinator::start() {
    if (started_) return;
    started_ = true;
    if (base_) base_->start();
    if (behavior_) behavior_->start();
    for (const QPointer<EventSource>& s : aux_) if (s) s->start();
    // 重放上次的用户态禁止执行名单。句柄随进程消失,故必须在启动时重新加锁;replay 内部
    // 会把「服务未运行期间这些文件可以被执行」这个空窗如实写进日志。
    if (execBlock_) execBlock_->replay();

    pushConfiguredIpBlocks();
}

int EventSourceCoordinator::pushConfiguredIpBlocks() {
    if (!netBlock_ || !netBlock_->open())
        return 0;
    int pushed = 0, refused = 0;
    QStringList endpoints = options_.BlockedRemoteEndpoints;
    for (const QString& learned : std::as_const(runtimeBlockedEndpoints_)) {
        if (!endpoints.contains(learned, Qt::CaseInsensitive))
            endpoints << learned;
    }
    for (const QString& raw : endpoints) {
        const QString s = raw.trimmed();
        if (s.isEmpty())
            continue;
        QString ip = s;
        quint16 port = 0;
        const int colon = s.lastIndexOf(QLatin1Char(':'));
        if (colon > 0) {
            bool ok = false;
            const int p = s.mid(colon + 1).toInt(&ok);
            if (ok && p > 0 && p <= 65535) {
                ip = s.left(colon);
                port = static_cast<quint16>(p);
            }
        }
        if (netBlock_->blockIp(ip, port)) ++pushed; else ++refused;
    }
    if (pushed > 0 || refused > 0) {
        log_.info(QStringLiteral("用户态出站黑名单(appsettings BlockedRemoteEndpoints):已生效 %1 条%2。"
                                 "此前该配置仅在内核驱动连上时才被下发,无驱动时形同未配。")
                      .arg(pushed)
                      .arg(refused > 0 ? QStringLiteral(",被拒 %1 条(不可整段封禁的地址,原因见逐条警告)")
                                             .arg(refused)
                                       : QString()));
    }
    return pushed;
}

void EventSourceCoordinator::setFallbackEnforcement(bool active) {
    if (execBlock_)
        execBlock_->setSuspended(!active);
    if (!netBlock_)
        return;
    if (active) {
        pushConfiguredIpBlocks();
    } else {
        const int cleared = netBlock_->clearAll();
        if (cleared > 0) {
            log_.info(QStringLiteral("内核驱动已接管出站拦截:已移除 %1 条用户态重复过滤器。")
                          .arg(cleared));
        }
    }
}

void EventSourceCoordinator::stop() {
    if (kernelRetry_) kernelRetry_->stop();
    if (driver_) driver_->stop();
    for (const QPointer<EventSource>& s : aux_) if (s) s->stop();
    if (behavior_) behavior_->stop();
    if (base_) base_->stop();
    started_ = false;
}

bool EventSourceCoordinator::isAvailable() const {
    return base_ && base_->isAvailable();
}

bool EventSourceCoordinator::wantsVerdict() const {
    return driver_ && driver_->wantsVerdict();
}

bool EventSourceCoordinator::kernelConnected() const {
    return driver_ && driver_->isConnected();
}

bool EventSourceCoordinator::kernelProtocolMismatch() const {
    return driver_ && driver_->protocolMismatch();
}

QStringList EventSourceCoordinator::kernelMissingCapabilities() const {
    return driver_ ? driver_->missingCapabilities() : QStringList{};
}

QVector<EventSourceCoordinator::ProtectionCapability>
EventSourceCoordinator::protectionCapabilities() const {
    const bool sus = suspended_;
    const bool k = kernelConnected();
    const QStringList missing = kernelMissingCapabilities();
    const auto kernelHas = [&k, &missing](const QString& capKey) {
        if (!k)
            return false;
        for (const QString& m : missing) {
            if (m.contains(capKey, Qt::CaseInsensitive))
                return false;
        }
        return true;
    };
    const bool umExec = (execBlock_ != nullptr) && !execBlock_->isSuspended() && !sus;
    const bool umNet = (netBlock_ != nullptr) && !sus;

    QVector<ProtectionCapability> caps;
    const auto add = [&caps](const QString& dim, bool on, const QString& who,
                            const QString& limit = QString()) {
        ProtectionCapability c;
        c.dimension = dim;
        c.inForce = on;
        c.provider = on ? who : QStringLiteral("无");
        c.limit = limit;
        caps.push_back(c);
    };

    add(QStringLiteral("进程创建前阻断"), kernelHas(QStringLiteral("进程")),
        QStringLiteral("内核驱动"),
        k ? QString() : QStringLiteral("无驱动时不存在:用户态最早只能在进程已启动后介入"));
    add(QStringLiteral("按路径阻断再次启动"), umExec || kernelHas(QStringLiteral("执行")),
        k ? QStringLiteral("内核驱动") : QStringLiteral("用户态"),
        (!k && umExec) ? QStringLiteral("独占句柄,不跨重启;按路径不按内容") : QString());
    add(QStringLiteral("模块加载阻断"), umExec || kernelHas(QStringLiteral("加载")),
        k ? QStringLiteral("内核驱动") : QStringLiteral("用户态"),
        (!k && umExec) ? QStringLiteral("独占句柄,不跨重启") : QString());
    add(QStringLiteral("出站连接阻断"), umNet || kernelHas(QStringLiteral("网络")),
        k ? QStringLiteral("内核驱动") : QStringLiteral("用户态"),
        (!k && umNet) ? QStringLiteral("WFP 动态会话,不跨重启;仅 IPv4") : QString());
    add(QStringLiteral("命令行硬拦"), kernelHas(QStringLiteral("命令行")),
        QStringLiteral("内核驱动"),
        k ? QString() : QStringLiteral("无驱动时不存在:命令行要等进程起来后读 PEB,"
                                       "与毫秒级退出的 LOLBin 赛跑"));
    add(QStringLiteral("注册表写入阻断(写入前)"), kernelHas(QStringLiteral("注册表")),
        QStringLiteral("内核驱动"),
        k ? QString() : QStringLiteral("无驱动时不存在 —— 替代手段是下一行的即时回滚,"
                                       "但那是事后还原,不是阻断"));
    add(QStringLiteral("注册表持久化即时回滚"), regRollbackActive_ && !sus,
        QStringLiteral("用户态"),
        QStringLiteral("RegNotifyChangeKeyValue 唤醒后还原被改写的自启动项;"
                       "【事后还原不是阻断】,恶意软件仍能写进去,只是会被立刻改回来。"
                       "覆盖 HKLM 的 Run / RunOnce(含 Wow6432Node)与 Winlogon 的 Shell / Userinit;"
                       "【不覆盖】HKCU 与其它用户 hive 的 Run、IFEO 的 Debugger、服务键、COM —— "
                       "这些仍由 4 秒轮询与引擎处置。判据:值里的目标文件全部已加白或带有效签名则保留,"
                       "解析不出已存在文件则不动,脚本宿主 / LOLBin 光杆调用与未签名目标才回滚;"
                       "按原注册表类型写回。不跨重启。"));
    add(QStringLiteral("跨重启的执行阻断"), crossRebootDenyOn_ && !sus,
        QStringLiteral("用户态"),
        QStringLiteral("文件 DACL 上的 DENY Everyone:FILE_EXECUTE,开机即生效 —— "
                       "独占句柄『不跨重启』的补位。按文件不按路径:复制一份即可绕过。"
                       "FileDenyExecuteConfirmedEnabled 默认只用于隔离原文件删除失败时的兜底；"
                       "部署方显式打开 FileDenyExecuteEnabled 才会把一般拦截也写成持久 ACL。"
                       "ACE 在卸载后仍可能保留，误判代价较高。"
                       "撤销:凡落了 ACE / 内核禁止执行名单的拦截(不论通知写的是『已禁止启动』还是『已结束进程』),"
                       "通知卡片上都带『撤销拦截 · 信任 1 小时』;或在界面给该文件加白。"
                       "本位为真只表示该功能已启用,不表示当前有条目生效。"));
    add(QStringLiteral("结束进程"), !sus,
        k ? QStringLiteral("内核驱动 + 用户态") : QStringLiteral("用户态"),
        k ? QString() : QStringLiteral("TerminateProcess,可能被高级样本对抗"));
    add(QStringLiteral("冻结进程(可恢复)"), !sus, QStringLiteral("用户态"),
        QStringLiteral("挂起线程;不跨重启;已做过的动作不回滚"));
    add(QStringLiteral("阻断其创建子进程"), !sus, QStringLiteral("用户态"),
        QStringLiteral("Job 配额;【不可撤销】,仅用于即将结束该进程时"));
    add(QStringLiteral("读取/删除被占用文件"), !sus,
        k ? QStringLiteral("内核驱动 + 用户态") : QStringLiteral("用户态"),
        k ? QString()
          : QStringLiteral("备份特权只能绕 DACL 拒绝(错误 5),绕不过共享冲突(错误 32)"));
    add(QStringLiteral("受保护目录写入阻断(写入前)"),
        kernelHas(QStringLiteral("受保护目录")) && guardEnabled_ && !guardDirs_.isEmpty(),
        QStringLiteral("内核驱动"),
        !k ? QStringLiteral("无驱动时不存在:要在打开阶段拒绝一次写入只有文件系统过滤器做得到。"
                            "替代手段是把这些目录并入观测面,让勒索行为聚合尽早定罪并结束进程树 —— "
                            "那是事后补偿,首批文件可能已被加密")
           : (guardEnabled_ && guardDirs_.isEmpty()
                  ? QStringLiteral("已启用但【没有配置任何目录】,因此当前什么都不拦")
                  : QStringLiteral("只拦不可信写入者:Windows 自身、Program Files 下的程序、"
                                   "以及你信任的程序照常可写")));
    add(QStringLiteral("自身进程/文件自保护"), kernelHas(QStringLiteral("自保")),
        QStringLiteral("内核驱动"),
        k ? QString() : QStringLiteral("无驱动时不存在:管理员权限的样本可停服务、删文件。"
                                       "阶段 3 的服务 DACL 收紧只是把门槛从「任意进程」提到"
                                       "「需要管理员」,且需用户显式确认,不是自保护的等价物"));
    // 控制管道认证的前提:安装目录 / 服务 exe 对非管理员不可写(服务启动时只读自检,见
    // InstallDirAclCheck)。前提不成立时强制层(映像在安装目录下且叫 bulwark_ui.exe)不构成
    // 安全边界 —— 这一维必须如实报「未生效」。未自检(开关关闭)时不出现,不替没验证的事下结论。
    if (ipcBoundaryChecked_) {
        add(QStringLiteral("IPC 控制管道认证(依赖安装目录写保护)"), ipcBoundaryIntact_ && !sus,
            QStringLiteral("用户态"),
            ipcBoundaryIntact_
                ? QStringLiteral("已核对:安装目录与服务 / 界面 exe 对非管理员不可写。"
                                 "只验映像路径与文件名,不验签名(除非启用 EnforceUiClientSignature)")
                : ipcBoundaryNote_);
    }
    return caps;
}

void EventSourceCoordinator::setHardeningState(bool registryRollbackActive,
                                              bool crossRebootExecDeny) {
    regRollbackActive_ = registryRollbackActive;
    crossRebootDenyOn_ = crossRebootExecDeny;
}

void EventSourceCoordinator::setIpcAuthBoundary(bool checked, bool intact, const QString& note) {
    ipcBoundaryChecked_ = checked;
    ipcBoundaryIntact_ = checked && intact;
    ipcBoundaryNote_ = note;
}

QString EventSourceCoordinator::ipcAuthBoundaryNote() const {
    return (ipcBoundaryChecked_ && !ipcBoundaryIntact_) ? ipcBoundaryNote_ : QString();
}

QString EventSourceCoordinator::kernelOutboundEnforcementNote() const {
    if (!driver_)
        return QString();
    return DriverEventSource::describeWfpHealth(driver_->queryWfpStats());
}

QString EventSourceCoordinator::protectionTier() const {
    if (suspended_)
        return QStringLiteral("Standby");
    if (kernelConnected())
        return QStringLiteral("Driver");
    if (execBlock_ || netBlock_)
        return QStringLiteral("UserModeEnforcement");
    return QStringLiteral("ObserveOnly");
}

QString EventSourceCoordinator::protectionSummary() const {
    if (suspended_) {
        return QStringLiteral("待机中(界面已退出)· 本软件此刻不提供任何防护:事件源已停、"
                              "内核驱动已卸载、用户态拦截已放开。"
                              "已隔离的文件不会被放回,已施加的「拒绝执行」ACE 仍然拦着 —— "
                              "待机只是不再做新的处置,不撤销做过的。打开界面即恢复。");
    }
    const QVector<ProtectionCapability> caps = protectionCapabilities();
    QStringList on, off;
    for (const ProtectionCapability& c : caps) {
        if (c.inForce)
            on << c.dimension;
        else
            off << c.dimension;
    }
    const QString tier = protectionTier();
    QString head;
    if (tier == QLatin1String("Driver"))
        head = QStringLiteral("内核驱动已连接");
    else if (tier == QLatin1String("UserModeEnforcement"))
        head = QStringLiteral("用户态防护(内核驱动未启用/掉线)");
    else
        head = QStringLiteral("仅观测(用户态拦截原语也已关闭)");
    const QString ipcNote = ipcAuthBoundaryNote();
    const QString outNote = kernelOutboundEnforcementNote();
    return QStringLiteral("%1 · 生效 %2/%3 个维度:%4%5%6%7")
        .arg(head)
        .arg(on.size())
        .arg(caps.size())
        .arg(on.join(QStringLiteral("、")))
        .arg(off.isEmpty() ? QString()
                           : QStringLiteral(";未生效:") + off.join(QStringLiteral("、")))
        .arg(ipcNote.isEmpty() ? QString() : QStringLiteral(" · ⚠ ") + ipcNote)
        .arg(outNote.isEmpty() ? QString() : QStringLiteral(" · ⚠ ") + outNote);
}

void EventSourceCoordinator::submitVerdict(const bulwark::SecurityEvent& e, bulwark::VerdictAction action) {
    if (driver_ && driver_->wantsVerdict())
        driver_->submitVerdict(e, action);
}

void EventSourceCoordinator::setKernelEnabled(bool on) {
    if (suspended_) {
        kernelWantedBeforeSuspend_ = on;
        log_.info(QStringLiteral("待机中:内核驱动开关的改动(%1)已记下,唤醒时生效。")
                      .arg(on ? QStringLiteral("启用") : QStringLiteral("停用")));
        return;
    }
    applyKernelEnabled(on);
}

void EventSourceCoordinator::applyKernelEnabled(bool on) {
    if (on == kernelEnabled_) return;
    kernelEnabled_ = on;
    if (on) {
        if (!driver_) {
            driver_ = new DriverEventSource(options_, this);
            connect(driver_, &EventSource::eventProduced, this, &EventSourceCoordinator::onDriverEvent);
        }
        DriverControl::ensureLoaded();
        driver_->setMemoryProtectionEnabled(memProtEnabled_);
        driver_->applyRansomGuard(guardEnabled_, guardDirs_, guardWriters_);
        driver_->applyReadGuard(readGuardEnabled_, readGuardEntries_, readGuardReaders_);
        driver_->start();
        for (int pid : protectedPids_)
            driver_->addProtectedPid(pid);
        kernelRetry_->start();
        if (driver_->isAvailable()) {
            attachFailed_ = false;
            setFallbackEnforcement(false);
            log_.info(QStringLiteral("内核驱动事件源已连接(行为前拦截 + 用户态补偿)。"));
            notifyKernelState(true, QStringLiteral("内核驱动已连接 · 行为前拦截生效"));
        } else {
            attachFailed_ = true;
            setFallbackEnforcement(true);
            log_.warning(QStringLiteral("内核驱动暂不可用,已降级为用户态观测,后台将持续重试。"));
            notifyKernelState(false, QStringLiteral("内核驱动不可用(首次连接失败)· 已降级为"
                                                   "用户态观测,后台每 10 秒重试"));
        }
    } else {
        kernelRetry_->stop();
        attachFailed_ = false;
        if (driver_) driver_->stop();
        const bool unloaded = DriverControl::tryStop();
        setFallbackEnforcement(!suspended_);
        if (unloaded) {
            log_.info(QStringLiteral("内核驱动已按设置卸载(切回用户态观测)。"));
        } else {
            log_.warning(QStringLiteral("内核驱动开关已关闭,但卸载失败;内核持久硬拦可能仍在生效。"));
        }
        notifyKernelState(false,
                          unloaded
                              ? (suspended_
                                     ? QStringLiteral("已进入待机 · 内核驱动已卸载")
                                     : QStringLiteral("内核驱动已卸载 · 切回用户态观测"))
                              : QStringLiteral("内核驱动卸载失败 · 部分内核策略可能仍生效"));
    }
}

void EventSourceCoordinator::setSuspended(bool on) {
    if (suspended_ == on)
        return;
    suspended_ = on;

    if (on) {
        kernelWantedBeforeSuspend_ = kernelEnabled_;
        applyKernelEnabled(false);
        if (DriverControl::isRunning() && !DriverControl::tryStop())
            log_.warning(QStringLiteral("待机:检测到残留内核驱动且再次卸载失败,部分持久硬拦可能仍在生效。"));
        for (const QPointer<EventSource>& s : aux_) if (s) s->stop();
        if (behavior_) behavior_->stop();
        if (base_) base_->stop();
        if (execBlock_) execBlock_->setSuspended(true);
        const int netCleared = netBlock_ ? netBlock_->clearAll() : 0;
        started_ = false;
        log_.warning(QStringLiteral("已进入待机:ETW 会话已停、行为监控已停、用户态独占句柄已放开、"
                                    "出站封禁已清 %1 条%2。本软件此刻【不提供任何防护】,"
                                    "已隔离的文件与已施加的拒绝执行 ACE 保持原样。")
                         .arg(netCleared)
                         .arg(kernelWantedBeforeSuspend_ ? QStringLiteral("、内核驱动已卸载") : QString()));
        return;
    }

    if (execBlock_) execBlock_->setSuspended(false);
    start();
    if (kernelWantedBeforeSuspend_)
        applyKernelEnabled(true);
    log_.info(QStringLiteral("已退出待机:防护已恢复(%1)。").arg(protectionSummary()));
}

void EventSourceCoordinator::setKernelWantedOnResume(bool on) {
    kernelWantedBeforeSuspend_ = on;
}

void EventSourceCoordinator::onKernelRetry() {
    if (!kernelEnabled_ || !driver_) { kernelRetry_->stop(); return; }
    if (driver_->isAvailable()) {
        if (attachFailed_) {
            attachFailed_ = false;
            log_.info(QStringLiteral("内核驱动连接已恢复。"));
        }
        notifyKernelState(true, QStringLiteral("内核驱动已连接 · 行为前拦截生效"));
        return;
    }
    if (!attachFailed_) {
        attachFailed_ = true;
        log_.warning(QStringLiteral("内核驱动连接已断开(驱动被卸载或重载),正在尝试重新加载并接回。"));
    }
    notifyKernelState(false, QStringLiteral("内核驱动连接已断开(被卸载 / 重载)· 已降级为"
                                           "用户态观测,正在尝试接回"));
    setFallbackEnforcement(true);
    DriverControl::ensureLoaded();
    driver_->setMemoryProtectionEnabled(memProtEnabled_);
    driver_->applyRansomGuard(guardEnabled_, guardDirs_, guardWriters_);
    driver_->applyReadGuard(readGuardEnabled_, readGuardEntries_, readGuardReaders_);
    driver_->start();
    if (driver_->isAvailable()) {
        attachFailed_ = false;
        setFallbackEnforcement(false);
        for (int pid : protectedPids_)
            driver_->addProtectedPid(pid);
        log_.info(QStringLiteral("内核驱动连接已恢复。"));
        notifyKernelState(true, QStringLiteral("内核驱动连接已恢复 · 行为前拦截重新生效"));
    }
}

void EventSourceCoordinator::notifyKernelState(bool connected, const QString& detail) {
    if (!stateChanged_)
        return;
    if (notifiedConnected_.has_value() && *notifiedConnected_ == connected)
        return;
    notifiedConnected_ = connected;
    stateChanged_(connected, detail);
}

void EventSourceCoordinator::configureBehaviorMonitor(bool enabled, bool canaryEnabled) {
    if (!behavior_) return;
    behavior_->setEnabled(enabled);
    behavior_->setCanaryEnabled(canaryEnabled);
}

void EventSourceCoordinator::setMemoryProtectionEnabled(bool on) {
    memProtEnabled_ = on;
    if (driver_)
        driver_->setMemoryProtectionEnabled(on);
}

void EventSourceCoordinator::applyRansomGuard(bool enabled, const QStringList& dirs,
                                              const QStringList& writers) {
    guardEnabled_ = enabled;
    guardDirs_ = dirs;
    guardWriters_ = writers;
    if (driver_)
        driver_->applyRansomGuard(enabled, dirs, writers);
}

void EventSourceCoordinator::applyReadGuard(bool enabled, const QStringList& entries,
                                            const QStringList& readers) {
    readGuardEnabled_ = enabled;
    readGuardEntries_ = entries;
    readGuardReaders_ = readers;
    if (driver_)
        driver_->applyReadGuard(enabled, entries, readers);
}

void EventSourceCoordinator::addProtectedUiPid(int pid) {
    if (pid <= 0) return;
    protectedPids_.insert(pid);
    if (driver_) driver_->addProtectedPid(pid);
}

void EventSourceCoordinator::removeProtectedUiPid(int pid) {
    if (pid <= 0) return;
    // 驱动在进程退出回调中自行移除运行态 PID；这里清掉重连时会重放的用户态集合。
    protectedPids_.remove(pid);
}

bool EventSourceCoordinator::addBlockedIp(const QString& ip, quint16 port) {
    const QString key = port > 0 ? QStringLiteral("%1:%2").arg(ip.trimmed()).arg(port)
                                 : ip.trimmed();
    const QString normalizedKey = key.toLower();
    if (!normalizedKey.isEmpty())
        runtimeBlockedEndpoints_.insert(normalizedKey);

    if (driver_ && driver_->isConnected()) {
        driver_->addBlockedIp(ip, port);
        return true;
    }
    return netBlock_ && netBlock_->blockIp(ip, port);
}

int EventSourceCoordinator::unblockIp(const QString& ip, quint16 port) {
    const QString key = port > 0 ? QStringLiteral("%1:%2").arg(ip.trimmed()).arg(port)
                                 : ip.trimmed();
    runtimeBlockedEndpoints_.remove(key.toLower());
    return netBlock_ ? netBlock_->unblockIp(ip, port) : 0;
}

int EventSourceCoordinator::clearUserModeIpBlocks() {
    runtimeBlockedEndpoints_.clear();
    return netBlock_ ? netBlock_->clearAll() : 0;
}

QStringList EventSourceCoordinator::userModeBlockedIpList() const {
    return netBlock_ ? netBlock_->blockedList() : QStringList{};
}

bool EventSourceCoordinator::blockModuleLoad(const QString& modulePath) {
    if (driver_ && driver_->blockModuleLoad(modulePath))
        return true;
    return execBlock_ ? execBlock_->blockModuleLoad(modulePath) : false;
}

bool EventSourceCoordinator::blockExecPath(const QString& imagePath) {
    if (driver_ && driver_->blockExecPath(imagePath))
        return true;
    return execBlock_ ? execBlock_->blockExecPath(imagePath) : false;
}

bool EventSourceCoordinator::clearExecBlock() {
    const bool k = driver_ ? driver_->clearExecBlock() : false;
    const bool u = execBlock_ ? execBlock_->clearExecBlock() : false;
    return k || u;
}

bool EventSourceCoordinator::clearModuleNoLoad() {
    const bool k = driver_ ? driver_->clearModuleNoLoad() : false;
    const bool u = execBlock_ ? execBlock_->clearModuleNoLoad() : false;
    return k || u;
}

int EventSourceCoordinator::suspendUserModeLock(const QString& absPath) {
    return execBlock_ ? execBlock_->suspendForRemediation(absPath) : 0;
}

bool EventSourceCoordinator::clearBannedProcesses() {
    return driver_ ? driver_->clearBannedProcesses() : false;
}

QStringList EventSourceCoordinator::persistedExecBlockList() const {
    QStringList out = driver_ ? driver_->persistedExecBlockList() : QStringList{};
    if (execBlock_) {
        for (const QString& e : execBlock_->persistedExecBlockList())
            if (!out.contains(e, Qt::CaseInsensitive))
                out << e;
    }
    return out;
}

QStringList EventSourceCoordinator::persistedModuleNoLoadList() const {
    QStringList out = driver_ ? driver_->persistedModuleNoLoadList() : QStringList{};
    if (execBlock_) {
        for (const QString& e : execBlock_->persistedModuleNoLoadList())
            if (!out.contains(e, Qt::CaseInsensitive))
                out << e;
    }
    return out;
}

bool EventSourceCoordinator::hardenRegistryKey(const QString& keyOrValue) {
    return driver_ ? driver_->hardenRegistryKey(keyOrValue) : false;
}

bool EventSourceCoordinator::readLockedFile(const QString& path, QByteArray& out) {
    return driver_ ? driver_->readLockedFile(path, out) : false;
}

bool EventSourceCoordinator::forceDeleteFile(const QString& path) {
    return driver_ ? driver_->forceDeleteFile(path) : false;
}

bool EventSourceCoordinator::killProcess(int pid) {
    return driver_ ? driver_->killProcess(pid) : false;
}

bool EventSourceCoordinator::banProcess(int pid) {
    return driver_ ? driver_->banProcess(pid) : false;
}

void EventSourceCoordinator::onBaseEvent(const bulwark::SecurityEvent& e) {
    if (kernelConnected() && e.type == bulwark::EventType::RemoteThread &&
        remoteThreadDedup_.shouldSuppress(remoteThreadDedupKey(e),
                                          RemoteThreadSource::Base,
                                          QDateTime::currentMSecsSinceEpoch()))
        return;
    if (kernelConnected() && e.type == bulwark::EventType::ImageLoad &&
        imageLoadDedup_.shouldSuppress(imageLoadDedupKey(e),
                                       RemoteThreadSource::Base,
                                       QDateTime::currentMSecsSinceEpoch()))
        return;
    if (kernelConnected() && !observedIoDedupKey(e).isEmpty()
        && observedIoDedup_.shouldSuppress(observedIoDedupKey(e),
                                           RemoteThreadSource::Base,
                                           QDateTime::currentMSecsSinceEpoch()))
        return;

    if (kernelConnected() && event_routing_policy::suppressBaseWhenKernelConnected(e.type))
        return;
    emit eventProduced(withProcessIdentity(e));
}

void EventSourceCoordinator::onDriverEvent(const bulwark::SecurityEvent& e) {
    if (e.type == bulwark::EventType::RemoteThread &&
        remoteThreadDedup_.shouldSuppress(remoteThreadDedupKey(e),
                                          RemoteThreadSource::Driver,
                                          QDateTime::currentMSecsSinceEpoch()))
        return;
    if (e.type == bulwark::EventType::ImageLoad &&
        imageLoadDedup_.shouldSuppress(imageLoadDedupKey(e),
                                       RemoteThreadSource::Driver,
                                       QDateTime::currentMSecsSinceEpoch()))
        return;
    if (!observedIoDedupKey(e).isEmpty()
        && observedIoDedup_.shouldSuppress(observedIoDedupKey(e),
                                           RemoteThreadSource::Driver,
                                           QDateTime::currentMSecsSinceEpoch()))
        return;
    emit eventProduced(withProcessIdentity(e));
}

void EventSourceCoordinator::onBehaviorEvent(const bulwark::SecurityEvent& e) {
    emit eventProduced(withProcessIdentity(e));
}

}
