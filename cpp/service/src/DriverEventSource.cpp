#include "bulwark/service/DriverEventSource.h"
#include "bulwark/service/Logger.h"
#include "bulwark/service/monitoring/ProcessInspector.h"
#include "bulwark/service/VolumePathMap.h"

#include <QTimer>
#include <QMutex>
#include <QMutexLocker>
#include <QVector>
#include <QHash>
#include <QSet>
#include <QMap>
#include <QString>
#include <QStringList>
#include <QByteArray>
#include <QFileInfo>

#include <atomic>
#include <new>
#include <thread>
#include <vector>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <fltuser.h>
#include <tlhelp32.h>

#include "Protocol.h"

namespace bulwark::service {

namespace {

struct BlwGetMessage {
    FILTER_MESSAGE_HEADER Header;
    BLW_EVENT_MESSAGE     Event;
};

struct ReadSlot {
    OVERLAPPED    ov;
    BlwGetMessage msg;
};

// 驱动发送线程每条事件最多只等 100ms;读线程处理上一条事件期间,其余挂着的请求照样能接住后续事件。
constexpr int kReadSlots = 32;

constexpr int kDeliveryStatsIntervalMs = 60 * 1000;

inline bool isBenignDisconnect(HRESULT hr) {
    const DWORD e = static_cast<DWORD>(hr);
    return e == 0x80070103u
        || e == 0x800704CDu
        || e == 0x800703E3u
        || e == 0x80070006u;
}

QString normalizeNtPath(const QString& raw) {
    if (raw.isEmpty())
        return raw;
    if (raw.startsWith(QLatin1String("\\??\\")))
        return raw.mid(4);

    if (raw.startsWith(QLatin1String("\\SystemRoot\\"), Qt::CaseInsensitive)) {
        const QString winDir = qEnvironmentVariable("SystemRoot", QStringLiteral("C:\\Windows"));
        return winDir + raw.mid(QStringLiteral("\\SystemRoot").size());
    }
    if (raw.startsWith(QLatin1String("\\Windows\\"), Qt::CaseInsensitive)) {
        const QString winDir = qEnvironmentVariable("SystemRoot", QStringLiteral("C:\\Windows"));
        const QString sysDrive = winDir.left(2);
        return sysDrive + raw;
    }
    if (raw.startsWith(QLatin1String("\\Device\\"), Qt::CaseInsensitive)) {
        const QString mapped = volumepath::deviceToWin32Path(raw);
        if (!mapped.isEmpty())
            return mapped;
    }
    return raw;
}

QString formatIpv4Host(quint32 ipHostOrder) {
    return QStringLiteral("%1.%2.%3.%4")
        .arg((ipHostOrder >> 24) & 0xFF).arg((ipHostOrder >> 16) & 0xFF)
        .arg((ipHostOrder >> 8) & 0xFF).arg(ipHostOrder & 0xFF);
}

QString driveAgnostic(const QString& path) {
    QString p = path.trimmed();
    p.replace(QLatin1Char('/'), QLatin1Char('\\'));
    if (p.size() >= 2 && p[1] == QLatin1Char(':'))
        p = p.mid(2);
    return p;
}

bool parseIpEndpoint(const QString& entry, quint32& ipHostOrder, quint16& port) {
    ipHostOrder = 0;
    port = 0;
    const QString t = entry.trimmed();
    if (t.isEmpty())
        return false;
    const QStringList hp = t.split(QLatin1Char(':'));
    const QStringList oct = hp.at(0).split(QLatin1Char('.'));
    if (oct.size() != 4)
        return false;
    quint32 v = 0;
    for (const QString& o : oct) {
        bool ok = false;
        const int n = o.toInt(&ok);
        if (!ok || n < 0 || n > 255)
            return false;
        v = (v << 8) | static_cast<quint32>(n);
    }
    ipHostOrder = v;
    if (hp.size() > 1) {
        bool ok = false;
        const int p = hp.at(1).toInt(&ok);
        if (ok && p > 0 && p <= 0xFFFF)
            port = static_cast<quint16>(p);
    }
    return true;
}

QString resolvePidImagePath(quint32 pid) {
    if (pid == 0)
        return QString();
    HANDLE h = ::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (h == nullptr)
        return QString();
    wchar_t buf[BLW_MAX_PATH] = {};
    DWORD sz = BLW_MAX_PATH;
    QString out;
    if (::QueryFullProcessImageNameW(h, 0, buf, &sz))
        out = QString::fromWCharArray(buf, static_cast<int>(sz));
    ::CloseHandle(h);
    return out;
}

bulwark::EventType mapType(ULONG t) {
    switch (t) {
        case BlwEventProcessTerminate:     return bulwark::EventType::ProcessTerminate;
        case BlwEventFileDelete:           return bulwark::EventType::FileDelete;
        case BlwEventFileRename:           return bulwark::EventType::FileWrite;
        case BlwEventRegistrySetValue:     return bulwark::EventType::RegistryWrite;
        case BlwEventRegistryDeleteValue:  return bulwark::EventType::RegistryWrite;
        case BlwEventRegistryDeleteKey:    return bulwark::EventType::RegistryWrite;
        case BlwEventRegistrySetValueBlocked:    return bulwark::EventType::RegistryWrite;
        case BlwEventRegistryDeleteValueBlocked: return bulwark::EventType::RegistryWrite;
        case BlwEventRegistryDeleteKeyBlocked:   return bulwark::EventType::RegistryWrite;
        case BlwEventSelfProtect:          return bulwark::EventType::SelfProtect;
        case BlwEventMemoryProtect:        return bulwark::EventType::SelfProtect;
        case BlwEventNetworkConnect:       return bulwark::EventType::NetworkConnect;
        case BlwEventImageLoad:            return bulwark::EventType::ImageLoad;
        case BlwEventImageBlocked:         return bulwark::EventType::ImageLoad;
        case BlwEventRemoteThread:         return bulwark::EventType::RemoteThread;
        case BlwEventFileModify:           return bulwark::EventType::FileWrite;
        case BlwEventCommandBlocked:       return bulwark::EventType::ProcessCreate;
        case BlwEventRegistryHiveDump:     return bulwark::EventType::RegistryWrite;
        case BlwEventBootSectorBlocked:    return bulwark::EventType::FileWrite;
        case BlwEventTokenAttack:          return bulwark::EventType::SelfProtect;
        case BlwEventGuardDirBlocked:      return bulwark::EventType::FileWrite;
        case BlwEventRegistryRestore:        return bulwark::EventType::RegistryWrite;
        case BlwEventRegistryRestoreBlocked: return bulwark::EventType::RegistryWrite;
        case BlwEventCredDumpBlocked:      return bulwark::EventType::SelfProtect;
        case BlwEventDriverUnloadBlocked:  return bulwark::EventType::SelfProtect;
        case BlwEventUiLaunchBlocked:      return bulwark::EventType::SelfProtect;
        case BlwEventSensitiveReadBlocked: return bulwark::EventType::SelfProtect;
        default:                           return bulwark::EventType::ProcessCreate;
    }
}

}

struct DriverEventSource::Impl {
    HANDLE port = nullptr;
    std::thread readThread;
    HANDLE readThreadNative = nullptr;
    std::atomic<bool> running{false};
    std::atomic<bool> connected{false};
    std::atomic<bool> protocolMismatch{false};

    QMutex queueMutex;
    QVector<bulwark::SecurityEvent> queue;

    QMutex portMutex; // 保护 port 上的 Send/Reply 与关闭,避免与读线程 / 主线程竞态

    QStringList protectedPaths, fileHardBlocks, protectedRegKeys, regHardBlocks, blockedEndpoints;
    QStringList memProtTargets;
    QStringList cmdHardBlocks;
    bool cmdHardBaseline = true;

    bool guardEnabled = true;
    QStringList guardDirs;
    QStringList guardWriters;

    bool readGuardEnabled = true;
    QStringList readGuardEntries;
    QStringList readGuardReaders;

    quint32 selfPid = 0;
    QSet<int> protectedPids;
    QSet<int> pendingPids;
    QSet<QString> memProtNames;
    QSet<QString> credProtNames;
    bool memProtEnabled = true;

    static constexpr int kQueueMax = 4096;
    Logger log{QStringLiteral("bulwark.service.Driver")};

    std::atomic<quint64> userQueueDropped{0};
    BLW_EVENT_STATS_REPLY lastStats{};
    quint64 lastUserDropped = 0;
    bool statsUnsupported = false;

    void enqueue(bulwark::SecurityEvent&& e) {
        if (e.actorPid > 4 && !e.actorCreationFileTime.has_value()) {
            if (const auto instance = monitoring::ProcessInspector::tryGetProcessInstance(e.actorPid)) {
                e.actorCreationFileTime = instance->creationFileTime;
                if (e.actorPath.isEmpty()
                    || e.actorPath.startsWith(QLatin1String("PID "), Qt::CaseInsensitive))
                    e.actorPath = instance->imagePath;
            }
        }
        QMutexLocker lock(&queueMutex);
        if (queue.size() >= kQueueMax) {
            userQueueDropped.fetch_add(1, std::memory_order_relaxed);
            return;
        }
        queue.push_back(std::move(e));
    }

    // 调用方须持有 queueMutex。
    void clearQueueLocked() {
        queue.clear();
    }

    struct Capabilities {
        bool banned = false;
        bool selfGuard = false;
        bool cmdHardBlock = false;
        bool execBlock = false;
        bool credProt = false;
        bool memProt = false;
        bool fileTelemetry = false;
        bool guardDir = false;
        bool bootGuardFixedOnly = false;
        bool readGuard = false;
    };
    Capabilities caps;
    QStringList missingCapabilities() const;
    void logCapabilitySummary() const;

    bool connectPort();
    bool handshake();
    bool sendConfig(ULONG command, const QString& path = QString(),
                    ULONG pid = 0, ULONG blockIp = 0, USHORT blockPort = 0);
    bool queryWfpStats(BLW_WFP_STATS_REPLY& out);
    bool queryEventStats(BLW_EVENT_STATS_REPLY& out);
    void pushInitialConfig();
    void reconcileRansomGuard();
    void reconcileReadGuard();
    void initMemoryProtection();
    void addMemProtPidToKernel(int pid);
    void addCredProtPidToKernel(int pid);
    void closePort();
    void readLoop();
    void buildAndQueue(const BLW_EVENT_MESSAGE& ev, ULONG64 messageId);
    bool kernelReadFile(const QString& path, QByteArray& out);
    bool kernelForceDelete(const QString& path);
};

}

namespace bulwark::service {

bool DriverEventSource::Impl::connectPort() {
    HRESULT lastHr = S_OK;
    for (int attempt = 0; attempt < 5; ++attempt) {
        HANDLE h = nullptr;
        const HRESULT hr = ::FilterConnectCommunicationPort(
            BLW_PORT_NAME, 0, nullptr, 0, nullptr, &h);
        lastHr = hr;
        if (hr == S_OK && h != nullptr && h != INVALID_HANDLE_VALUE) {
            QMutexLocker lock(&portMutex);
            port = h;
            connected.store(true);
            log.info(QStringLiteral("已连接内核驱动通信端口 %1。").arg(QString::fromWCharArray(BLW_PORT_NAME)));
            return true;
        }
        ::Sleep(300);
    }
    const QString code = QStringLiteral("0x%1").arg(static_cast<quint32>(lastHr), 8, 16, QLatin1Char('0'));
    if (lastHr == HRESULT_FROM_WIN32(ERROR_CONNECTION_COUNT_LIMIT))
        log.warning(QStringLiteral("无法连接内核驱动端口 %1(%2:驱动在载,但它唯一的连接名额被占着 —— "
                                   "通常是上一条连接没释放,重启服务即可恢复)。")
                        .arg(QString::fromWCharArray(BLW_PORT_NAME), code));
    else
        log.warning(QStringLiteral("无法连接内核驱动端口 %1(%2;驱动未加载 / 无管理员权限 / 测试签名未开?)。")
                        .arg(QString::fromWCharArray(BLW_PORT_NAME), code));
    return false;
}

bool DriverEventSource::Impl::handshake() {
    BLW_CONFIG_MESSAGE cfg;
    ZeroMemory(&cfg, sizeof(cfg));
    cfg.Command = BLW_CMD_HANDSHAKE;

    BLW_HANDSHAKE_REPLY reply;
    ZeroMemory(&reply, sizeof(reply));
    DWORD returned = 0;
    HRESULT hr;
    {
        QMutexLocker lock(&portMutex);
        if (port == nullptr) return false;
        hr = ::FilterSendMessage(port, &cfg, sizeof(cfg), &reply, sizeof(reply), &returned);
    }
    if (FAILED(hr)) {
        log.warning(QStringLiteral("协议握手发送失败 0x%1(驱动可能为旧版,不支持握手命令)。")
                        .arg(static_cast<quint32>(hr), 8, 16, QLatin1Char('0')));
        return false;
    }
    if (returned < sizeof(reply)) {
        log.warning(QStringLiteral("协议握手应答长度异常:%1/%2。").arg(returned).arg((int)sizeof(reply)));
        return false;
    }

    const ULONG expectEvent   = static_cast<ULONG>(sizeof(BLW_EVENT_MESSAGE));
    const ULONG expectConfig  = static_cast<ULONG>(sizeof(BLW_CONFIG_MESSAGE));
    const ULONG expectVerdict = static_cast<ULONG>(sizeof(BLW_VERDICT_REPLY));
    const bool ok =
        reply.ProtocolVersion == BLW_PROTOCOL_VERSION &&
        reply.EventMessageSize == expectEvent &&
        reply.ConfigMessageSize == expectConfig &&
        reply.VerdictReplySize == expectVerdict;
    if (!ok) {
        log.error(QStringLiteral(
            "内核/服务协议不一致:内核(ver=%1 event=%2 config=%3 verdict=%4) vs "
            "服务(ver=%5 event=%6 config=%7 verdict=%8) —— 已拒绝启用内核拦截以防误判。")
            .arg(reply.ProtocolVersion).arg(reply.EventMessageSize)
            .arg(reply.ConfigMessageSize).arg(reply.VerdictReplySize)
            .arg(BLW_PROTOCOL_VERSION).arg(expectEvent).arg(expectConfig).arg(expectVerdict));
        return false;
    }
    // 能力以驱动在握手时声明的位图为准,不靠下发命令的成败反推。
    caps.cmdHardBlock  = (reply.Capabilities & BLW_CAP_CMD_HARDBLOCK)  != 0;
    caps.banned        = (reply.Capabilities & BLW_CAP_BANNED)         != 0;
    caps.selfGuard     = (reply.Capabilities & BLW_CAP_SELFGUARD)      != 0;
    caps.execBlock     = (reply.Capabilities & BLW_CAP_EXECBLOCK)      != 0;
    caps.credProt      = (reply.Capabilities & BLW_CAP_CRED_PROTECT)   != 0;
    caps.memProt       = (reply.Capabilities & BLW_CAP_MEM_PROTECT)    != 0;
    caps.fileTelemetry = (reply.Capabilities & BLW_CAP_FILE_TELEMETRY) != 0;
    caps.guardDir      = (reply.Capabilities & BLW_CAP_GUARD_DIR)      != 0;
    caps.bootGuardFixedOnly = (reply.Capabilities & BLW_CAP_BOOTGUARD_FIXED_ONLY) != 0;
    caps.readGuard     = (reply.Capabilities & BLW_CAP_READ_GUARD)     != 0;

    log.info(QStringLiteral("协议握手通过(ver=%1 event=%2 config=%3 verdict=%4 caps=0x%5)。")
                 .arg(reply.ProtocolVersion).arg(reply.EventMessageSize)
                 .arg(reply.ConfigMessageSize).arg(reply.VerdictReplySize)
                 .arg(reply.Capabilities, 8, 16, QLatin1Char('0')));
    return true;
}

bool DriverEventSource::Impl::sendConfig(ULONG command, const QString& path,
                                        ULONG pid, ULONG blockIp, USHORT blockPort) {
    BLW_CONFIG_MESSAGE cfg;
    ZeroMemory(&cfg, sizeof(cfg));
    cfg.Command = command;
    cfg.Pid = pid;
    cfg.BlockIpV4 = blockIp;
    cfg.BlockPort = blockPort;

    QString p = path;
    const int maxChars = BLW_MAX_PATH - 1;
    if (p.size() > maxChars) p = p.left(maxChars);
    cfg.PathLength = static_cast<USHORT>(p.size());
    const int copied = p.isEmpty() ? 0 : p.toWCharArray(cfg.Path);
    cfg.Path[copied] = L'\0';

    QMutexLocker lock(&portMutex);
    if (port == nullptr) return false;
    DWORD returned = 0;
    const HRESULT hr = ::FilterSendMessage(port, &cfg, sizeof(cfg), nullptr, 0, &returned);
    if (FAILED(hr)) {
        log.warning(QStringLiteral("FilterSendMessage(config=%1) 失败 0x%2")
                        .arg(command).arg(static_cast<quint32>(hr), 8, 16, QLatin1Char('0')));
        return false;
    }
    return true;
}

QStringList DriverEventSource::Impl::missingCapabilities() const {
    QStringList missing;
    if (!caps.cmdHardBlock)  missing << QStringLiteral("命令行硬拦(反勒索删卷影的执行前阻断)");
    if (!caps.banned)        missing << QStringLiteral("已封禁主体全维拦截");
    if (!caps.selfGuard)     missing << QStringLiteral("自保护足迹(反勒索加密本产品)");
    if (!caps.execBlock)     missing << QStringLiteral("执行前拦截(恶意映像禁止启动)");
    if (!caps.credProt)      missing << QStringLiteral("凭据反转储(lsass 防读)");
    if (!caps.memProt)       missing << QStringLiteral("内存防护(反注入)");
    if (!caps.fileTelemetry) missing << QStringLiteral("文件行为遥测(勒索时序聚合)");
    if (guardEnabled && !caps.guardDir)
        missing << QStringLiteral("受保护目录(反勒索:系统目录与自定义目录的写入前拦截)");
    if (readGuardEnabled && !caps.readGuard)
        missing << QStringLiteral("窃密防护(浏览器 / 通讯 / 钱包数据只许指定程序读)");
    return missing;
}

void DriverEventSource::Impl::logCapabilitySummary() const {
    const QStringList missing = missingCapabilities();
    if (missing.isEmpty()) {
        log.info(QStringLiteral("内核能力探测:全部维度就绪(命令行硬拦 / 封禁主体 / 自保足迹 / "
                                "执行前拦截 / 凭据反转储 / 反注入 / 文件遥测)。"));
        return;
    }
    log.error(QStringLiteral(
        "内核能力探测:已连接的驱动【未声明】以下 %1 个维度,这些防护当前实际不生效 —— %2。"
        "能力取自握手回复的 Capabilities 位图(Protocol.h 的 BLW_CAP_*),"
        "所以这表示「System32\\drivers\\Bulwark.sys 比 bulwark_service.exe 旧」。"
        "请用同源编译的驱动替换后重新加载(停服务 -> fltmc unload Bulwark -> 覆盖 .sys -> 启动服务)。")
        .arg(missing.size()).arg(missing.join(QStringLiteral("、"))));
}

void DriverEventSource::Impl::pushInitialConfig() {
    sendConfig(BLW_CMD_CLEAR_PATHS);
    for (const QString& s : protectedPaths)
        if (!s.trimmed().isEmpty()) sendConfig(BLW_CMD_ADD_PATH, s.trimmed());

    sendConfig(BLW_CMD_CLEAR_FILEHARD);
    for (const QString& s : fileHardBlocks)
        if (!s.trimmed().isEmpty()) sendConfig(BLW_CMD_ADD_FILEHARD, s.trimmed());

    sendConfig(BLW_CMD_CLEAR_REGKEYS);
    for (const QString& s : protectedRegKeys)
        if (!s.trimmed().isEmpty()) sendConfig(BLW_CMD_ADD_REGKEY, s.trimmed());

    // 注册表硬拦截(必须精确键值,命中即内核本地拒绝)。先把旧版本内置的方向不可辨项
    // 从运行期和持久化基线精确删除；仅 CLEAR 不会擦磁盘，重启后它们会复活。
    static const char* const kDeprecatedRegHard[] = {
        "\\Windows NT\\CurrentVersion\\Windows\\AppInit_DLLs",
        "\\Windows NT\\CurrentVersion\\Windows\\LoadAppInit_DLLs",
        "\\Control\\Session Manager\\AppCertDlls",
        "\\Control\\Session Manager\\KnownDLLs",
    };
    for (const char* k : kDeprecatedRegHard)
        sendConfig(BLW_CMD_DEL_REGHARD, QString::fromLatin1(k));
    sendConfig(BLW_CMD_CLEAR_REGHARD);
    for (const QString& s : regHardBlocks)
        if (!s.trimmed().isEmpty()) sendConfig(BLW_CMD_ADD_REGHARD, s.trimmed());

    sendConfig(BLW_CMD_ADD_REGHARD, QStringLiteral("\\Services\\Bulwark"));
    log.info(QStringLiteral("自我保护 · 注册表:已把服务键(\\Services\\Bulwark*)纳入内核注册表硬拦(防禁用/劫持)。"));

    {
        static const char* const kComponentKeys[] = {
            "\\Image File Execution Options\\bulwark_service.exe",
            "\\Image File Execution Options\\bulwark_ui.exe",
        };
        int n = 0;
        for (const char* k : kComponentKeys) {
            if (sendConfig(BLW_CMD_ADD_REGHARD, QString::fromLatin1(k)))
                ++n;
        }
        log.info(QStringLiteral("组件攻击防护 · 注册表:已把 %1 项本产品 IFEO 入口纳入内核硬拦；"
                                "AppInit_DLLs / AppCertDlls / KnownDLLs 因当前遥测缺少值数据和增删方向，"
                                "已改为受关注键遥测 + 用户态询问，清理/关闭动作不再被内核误拒。").arg(n));
    }

    {
        const bool accepted = sendConfig(BLW_CMD_SET_BOOTGUARD, QString(), 1u);
        if (accepted && caps.bootGuardFixedOnly) {
            log.info(QStringLiteral("引导区防护(内核侧):已确认开启 —— 非本产品进程通过裸卷句柄"
                                    "(\\\\.\\C: 等)写入固定磁盘卷头 32KB(VBR / 引导代码)一律被内核本地拒绝;"
                                    "U 盘、SD 卡等可移动介质的格式化与制作启动盘不受限。"
                                    "对固定磁盘做引导修复 / 格式化前请先停服务并卸载驱动。"));
        } else if (accepted) {
            log.info(QStringLiteral("引导区防护(内核侧):已确认开启 —— 非本产品进程通过裸卷句柄"
                                    "(\\\\.\\C: 等)写入卷头 32KB(VBR / 引导代码)一律被内核本地拒绝。"
                                    "做引导修复 / 格式化前请先停服务并卸载驱动。"));
        } else {
            log.warning(QStringLiteral("引导区防护(内核侧):已部署的驱动不认识该命令,说明 "
                                       "System32\\drivers\\Bulwark.sys 比本服务旧 —— 【卷引导区(VBR)"
                                       "的内核前拦截当前不存在】。物理磁盘 MBR/GPT 那一层由用户态 "
                                       "BootSectorGuard 的基线巡检兜住,但 VBR 写入拦不住。"
                                       "请用同源编译的驱动替换后重新加载。"));
        }
    }

    {
        static const char* const kDeprecatedCmdHard[] = {
            "VSSADMIN+RESIZE+SHADOWSTORAGE",
            "WBADMIN+DELETE+SYSTEMSTATEBACKUP",
            "BCDEDIT+RECOVERYENABLED",
            "BCDEDIT+BOOTSTATUSPOLICY",
            "VSSADMIN+DELETE+SHADOWS",
            "FSUTIL+DELETEJOURNAL",
        };
        for (const char* p : kDeprecatedCmdHard)
            sendConfig(BLW_CMD_DEL_CMDBLOCK, QString::fromLatin1(p));

        // 能力判据来自握手位图;这里只是清空后重新下发名单(下发失败由 sendConfig 自己记日志)
        sendConfig(BLW_CMD_CLEAR_CMDBLOCK);

        // 只收正常运维几乎不会执行的形态:清理单个旧卷影(/oldest /quiet)、按保留份数删备份都不在此列。
        QStringList patterns;
        if (cmdHardBaseline) {
            patterns = QStringList{
                QStringLiteral("VSSADMIN+DELETE+SHADOWS+/ALL"),
                QStringLiteral("WMIC+SHADOWCOPY+DELETE"),
                QStringLiteral("WIN32_SHADOWCOPY+DELETE"),
                QStringLiteral("WBADMIN+DELETE+CATALOG"),
                QStringLiteral("WBADMIN+DELETE+SYSTEMSTATEBACKUP+KEEPVERSIONS:0"),
                QStringLiteral("BCDEDIT+RECOVERYENABLED+NO"),
                QStringLiteral("BCDEDIT+BOOTSTATUSPOLICY+IGNOREALLFAILURES"),
                QStringLiteral("FSUTIL+USN+DELETEJOURNAL"),
                QStringLiteral("COMSVCS+MINIDUMP"),

                QStringLiteral("SAVE+HKLM\\SAM"),
                QStringLiteral("SAVE+HKLM\\SECURITY"),
                QStringLiteral("SAVE+HKEY_LOCAL_MACHINE\\SAM"),
                QStringLiteral("SAVE+HKEY_LOCAL_MACHINE\\SECURITY"),
            };
        }
        for (const QString& s : cmdHardBlocks) {
            const QString t = s.trimmed();
            if (!t.isEmpty() && !patterns.contains(t, Qt::CaseInsensitive))
                patterns.append(t);
        }

        for (const QString& p : patterns)
            sendConfig(BLW_CMD_ADD_CMDBLOCK, p);

        if (patterns.isEmpty()) {
            log.info(QStringLiteral("命令行硬拦:名单为空(基线已关闭且无自定义模式),该维度未启用。"));
        } else {
            log.info(QStringLiteral("命令行硬拦(执行前拦截):已下发 %1 条模式(内置基线%2,自定义 %3 条)"
                                    " —— 命中即内核拒绝创建进程,危险命令一次都不会执行,且跨重启/杀服务持续生效。")
                         .arg(patterns.size())
                         .arg(cmdHardBaseline ? QStringLiteral("已启用") : QStringLiteral("已关闭"))
                         .arg(cmdHardBlocks.size()));
        }
    }

    sendConfig(BLW_CMD_CLEAR_BLOCKIP);
    for (const QString& s : blockedEndpoints) {
        quint32 bip = 0; quint16 bport = 0;
        if (parseIpEndpoint(s, bip, bport))
            sendConfig(BLW_CMD_ADD_BLOCKIP, QString(), 0, bip, bport);
        else if (!s.trimmed().isEmpty())
            log.warning(QStringLiteral("忽略无法解析的网络黑名单条目:%1").arg(s));
    }

    {
        protectedPids.insert(static_cast<int>(::GetCurrentProcessId()));
        for (int pid : pendingPids)
            protectedPids.insert(pid);
        pendingPids.clear();
        sendConfig(BLW_CMD_CLEAR_PIDS);
        for (int pid : protectedPids)
            if (pid > 0) sendConfig(BLW_CMD_ADD_PID, QString(), static_cast<ULONG>(pid));
    }

    {
        sendConfig(BLW_CMD_CLEAR_SELFGUARD);
        int guarded = 0;
        wchar_t selfBuf[BLW_MAX_PATH] = {};
        const DWORD selfN = ::GetModuleFileNameW(nullptr, selfBuf, BLW_MAX_PATH);
        if (selfN > 0) {
            const QString selfExe = QString::fromWCharArray(selfBuf, static_cast<int>(selfN));
            QString dir = driveAgnostic(QFileInfo(selfExe).absolutePath());
            if (!dir.endsWith(QLatin1Char('\\'))) dir += QLatin1Char('\\');
            if (dir.size() >= 4) { sendConfig(BLW_CMD_ADD_SELFGUARD, dir); ++guarded; }
        }
        {
            const QString pd = qEnvironmentVariable("ProgramData", QStringLiteral("C:\\ProgramData"));
            QString dataDir = driveAgnostic(pd);
            if (!dataDir.endsWith(QLatin1Char('\\'))) dataDir += QLatin1Char('\\');
            dataDir += QStringLiteral("Bulwark\\");
            if (dataDir.size() >= 4) { sendConfig(BLW_CMD_ADD_SELFGUARD, dataDir); ++guarded; }
        }
        sendConfig(BLW_CMD_ADD_SELFGUARD, QStringLiteral("\\System32\\drivers\\Bulwark.sys"));
        ++guarded;
        log.info(QStringLiteral("自我保护(反勒索)· 完整内容:已把本产品足迹纳入内核 SelfGuard(%1 项;"
                                "仅放行本产品自身进程写入,其余进程写/删/改名一律拒绝)。").arg(guarded));
    }

    initMemoryProtection();

    sendConfig(BLW_CMD_SET_FILETELEMETRY, QString(), 1u);

    // 受保护目录必须在受保护 PID 下发之后对账,否则本产品自己的写入会被短暂拦下。
    reconcileRansomGuard();
    reconcileReadGuard();

    log.info(QStringLiteral("已向内核下发初始配置(受保护项 / 硬拦名单 / 命令行硬拦 / 黑名单 / 自保 PID / 文件遥测)。"));
    logCapabilitySummary();
}

void DriverEventSource::Impl::addMemProtPidToKernel(int pid) {
    if (pid <= 4) return;
    sendConfig(BLW_CMD_ADD_MEMPROT, QString(), static_cast<ULONG>(pid));
}

void DriverEventSource::Impl::addCredProtPidToKernel(int pid) {
    if (pid <= 4) return;
    sendConfig(BLW_CMD_ADD_CREDPROT, QString(), static_cast<ULONG>(pid));
}

void DriverEventSource::Impl::initMemoryProtection() {
    sendConfig(BLW_CMD_CLEAR_MEMPROT);
    sendConfig(BLW_CMD_CLEAR_CREDPROT);
    memProtNames.clear();
    credProtNames.clear();

    if (!memProtEnabled) {
        log.warning(QStringLiteral("内存防护已按设置关闭:已清空内核反注入与凭据反转储目标集"
                                   "(lsass 反转储随之停止)。在设置页重新开启即恢复。"));
        return;
    }

    for (const QString& t : memProtTargets) {
        const QString name = QFileInfo(t.trimmed()).fileName().toLower();
        if (!name.isEmpty()) memProtNames.insert(name);
    }
    credProtNames.insert(QStringLiteral("lsass.exe"));

    // 登记现存的目标进程,新进程由 readLoop 增量登记。memProtNames 为空也要枚举,lsass 必须登记。
    int memCount = 0, credCount = 0;
    HANDLE snap = ::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32W pe;
        ZeroMemory(&pe, sizeof(pe));
        pe.dwSize = sizeof(pe);
        if (::Process32FirstW(snap, &pe)) {
            do {
                const QString exe = QString::fromWCharArray(pe.szExeFile).toLower();
                if (pe.th32ProcessID > 4) {
                    if (memProtNames.contains(exe)) {
                        addMemProtPidToKernel(static_cast<int>(pe.th32ProcessID));
                        ++memCount;
                    }
                    if (credProtNames.contains(exe)) {
                        addCredProtPidToKernel(static_cast<int>(pe.th32ProcessID));
                        ++credCount;
                    }
                }
            } while (::Process32NextW(snap, &pe));
        }
        ::CloseHandle(snap);
    }
    log.info(QStringLiteral("内存防护:反注入目标名 %1 个(现存 %2)、凭据反转储目标名 %3 个(现存 %4,含 lsass,额外剥 VM_READ)。")
                 .arg(memProtNames.size()).arg(memCount).arg(credProtNames.size()).arg(credCount));
}

void DriverEventSource::Impl::closePort() {
    QMutexLocker lock(&portMutex);
    if (port != nullptr) {
        ::CloseHandle(port);
        port = nullptr;
    }
    connected.store(false);
}

}

namespace bulwark::service {

void DriverEventSource::Impl::buildAndQueue(const BLW_EVENT_MESSAGE& ev, ULONG64 messageId) {
    Q_UNUSED(messageId);
    bulwark::SecurityEvent e;

    e.type = mapType(ev.Type);
    e.actorPid = static_cast<int>(ev.ActorPid);

    // 长度来自内核消息,夹到数组容量内,防止越界读。
    const int imageChars = qMin<int>(ev.ImagePathLength, BLW_MAX_PATH);
    const int targetChars = qMin<int>(ev.TargetPathLength, BLW_MAX_PATH);
    const QString imagePath = imageChars > 0
        ? normalizeNtPath(QString::fromWCharArray(ev.ImagePath, imageChars))
        : QString();
    const QString targetRaw = targetChars > 0
        ? QString::fromWCharArray(ev.TargetPath, targetChars)
        : QString();
    const QString targetPath = targetRaw.isEmpty() ? QString() : normalizeNtPath(targetRaw);
    const QString actorPlaceholder = QStringLiteral("PID %1").arg(e.actorPid);

    switch (ev.Type) {
        case BlwEventProcessCreate:
            e.actorPath = imagePath;
            e.target = imagePath;
            e.commandLine = targetRaw;
            e.parentPid = static_cast<int>(ev.ParentPid);
            // 进程事件不占网络字段:驱动在 RemoteIpV4 里带上回调上下文里的创建者 PID(旧驱动恒为 0)。
            if (ev.RemoteIpV4 > 4 && ev.RemoteIpV4 != ev.ParentPid && ev.RemoteIpV4 != ev.ActorPid)
                e.creatorPid = static_cast<int>(ev.RemoteIpV4);
            e.actorImageFlags = ev.RemotePort & (BLW_IMAGE_DELETE_PENDING | BLW_IMAGE_TRANSACTED
                                                 | BLW_IMAGE_WRITABLE);
            if (const auto instance = monitoring::ProcessInspector::tryGetProcessInstance(e.actorPid))
                e.actorCreationFileTime = instance->creationFileTime;
            e.detail = QStringLiteral("内核遥测 · 进程创建(父PID %1)").arg(ev.ParentPid);
            e.userModeObserved = true;
            if (memProtEnabled && !imagePath.isEmpty()) {
                const QString name = QFileInfo(imagePath).fileName().toLower();
                if (!memProtNames.isEmpty() && memProtNames.contains(name))
                    addMemProtPidToKernel(e.actorPid);
                if (credProtNames.contains(name))
                    addCredProtPidToKernel(e.actorPid);
            }
            break;

        case BlwEventFileDelete:
        case BlwEventFileRename:
            e.actorPath = actorPlaceholder;
            e.target = targetPath;
            e.kernelBlocked = true;
            e.detail = (ev.Type == BlwEventFileDelete)
                ? QStringLiteral("内核拦截 · 删除受保护文件")
                : QStringLiteral("内核拦截 · 重命名/移动受保护文件");
            break;

        case BlwEventGuardDirBlocked: {
            e.type = (ev.ParentPid == BlwEventFileDelete) ? bulwark::EventType::FileDelete
                                                          : bulwark::EventType::FileWrite;
            e.actorPath = imagePath.isEmpty() ? actorPlaceholder : imagePath;
            e.target = targetPath;
            e.kernelBlocked = true;
            e.detail = QStringLiteral("内核拦截 · 受保护目录(反勒索)· %1")
                           .arg(ev.ParentPid == BlwEventFileDelete ? QStringLiteral("删除")
                              : ev.ParentPid == BlwEventFileRename ? QStringLiteral("重命名/移动")
                                                                   : QStringLiteral("写入/新建"));
            break;
        }

        case BlwEventFileModify:
            e.type = (ev.ParentPid == BlwEventFileDelete)
                ? bulwark::EventType::FileDelete
                : bulwark::EventType::FileWrite;
            e.actorPath = actorPlaceholder;
            e.target = targetPath;
            e.detail = QStringLiteral("文件行为遥测 · %1")
                           .arg(ev.ParentPid == BlwEventFileDelete ? QStringLiteral("删除")
                              : ev.ParentPid == BlwEventFileRename ? QStringLiteral("重命名/移动")
                                                                   : QStringLiteral("写入/新建"));
            e.userModeObserved = true;
            break;

        case BlwEventRegistrySetValue:
        case BlwEventRegistryDeleteValue:
        case BlwEventRegistryDeleteKey:
        case BlwEventRegistrySetValueBlocked:
        case BlwEventRegistryDeleteValueBlocked:
        case BlwEventRegistryDeleteKeyBlocked: {
            e.actorPath = actorPlaceholder;
            e.target = targetPath;
            const bool blocked = ev.Type == BlwEventRegistrySetValueBlocked
                || ev.Type == BlwEventRegistryDeleteValueBlocked
                || ev.Type == BlwEventRegistryDeleteKeyBlocked;
            const bool setValue = ev.Type == BlwEventRegistrySetValue
                || ev.Type == BlwEventRegistrySetValueBlocked;
            const bool deleteValue = ev.Type == BlwEventRegistryDeleteValue
                || ev.Type == BlwEventRegistryDeleteValueBlocked;
            e.registryOp = setValue
                ? bulwark::RegistryOperation::SetValue
                : deleteValue ? bulwark::RegistryOperation::DeleteValue
                              : bulwark::RegistryOperation::DeleteKey;
            if (ev.RemotePort == 4 && setValue) {
                e.hasRegistryDword = true;
                e.registryDwordValue = ev.RemoteIpV4;
            }
            e.kernelBlocked = blocked;
            e.userModeObserved = !blocked;
            const QString operation = setValue
                ? QStringLiteral("写入受保护注册表键")
                : deleteValue ? QStringLiteral("删除受保护注册表值")
                              : QStringLiteral("删除受保护注册表键");
            e.detail = blocked
                ? QStringLiteral("内核拦截 · 已阻止%1").arg(operation)
                : QStringLiteral("内核监控 · %1(观测,事后处置)").arg(operation);
            break;
        }

        case BlwEventRegistryRestore:
        case BlwEventRegistryRestoreBlocked: {
            const bool blocked = ev.Type == BlwEventRegistryRestoreBlocked;
            e.actorPath = actorPlaceholder;
            e.target = targetPath;
            e.registryOp = bulwark::RegistryOperation::RestoreKey;
            e.kernelBlocked = blocked;
            e.userModeObserved = !blocked;
            e.detail = blocked
                ? QStringLiteral("内核拦截 · 已阻止整棵恢复 / 替换注册表键(子树含受保护项)")
                : QStringLiteral("内核监控 · 整棵恢复 / 替换注册表键(绕过逐值监控,观测,事后处置)");
            break;
        }

        case BlwEventCredDumpBlocked: {
            const QString victimPath = resolvePidImagePath(ev.ParentPid);
            e.actorPath = imagePath.isEmpty() ? actorPlaceholder : imagePath;
            e.target = victimPath.isEmpty() ? QStringLiteral("PID %1").arg(ev.ParentPid) : victimPath;
            e.kernelBlocked = true;
            e.techniques << QStringLiteral("T1003.001");
            e.detail = QStringLiteral("内核凭据防护 · 已剥离对 %1 的内存读写权限(访问掩码 0x%2)")
                           .arg(QFileInfo(e.target).fileName())
                           .arg(ev.RemoteIpV4, 0, 16);
            break;
        }

        case BlwEventSelfProtect:
            e.actorPath = actorPlaceholder;
            e.target = QStringLiteral("受保护进程 PID %1").arg(ev.ParentPid);
            e.kernelBlocked = true;
            e.kernelRightsStripped = true;
            e.detail = QStringLiteral("内核自保 · 已剥离对本软件的危险访问权限");
            break;

        case BlwEventDriverUnloadBlocked:
            e.actorPath = actorPlaceholder;
            e.target = QStringLiteral("Bulwark.sys(本软件内核驱动)");
            e.kernelBlocked = true;
            e.detail = QStringLiteral("内核自保 · 防护生效中,已拒绝卸载内核驱动");
            break;

        case BlwEventUiLaunchBlocked:
            e.actorPath = actorPlaceholder;
            e.target = imagePath;
            e.kernelBlocked = true;
            e.detail = QStringLiteral("内核自保 · 已阻止非系统程序启动本软件界面(防抢先注入;"
                                      "请从开始菜单或桌面快捷方式启动)");
            break;

        case BlwEventSensitiveReadBlocked:
            e.actorPath = imagePath.isEmpty() ? actorPlaceholder : imagePath;
            e.target = targetPath;
            e.kernelBlocked = true;
            e.techniques << QStringLiteral("T1555.003") << QStringLiteral("T1005");
            e.detail = QStringLiteral("内核窃密防护 · 已阻止非指定程序读取浏览器 / 通讯 / 钱包敏感数据"
                                      "(同一程序 60 秒内只记一次;确属正常可加入信任名单)");
            break;

        case BlwEventMemoryProtect: {
            const int victim = static_cast<int>(ev.ParentPid);
            const QString victimPath = resolvePidImagePath(ev.ParentPid);
            e.actorPath = actorPlaceholder;
            e.target = victimPath.isEmpty() ? QStringLiteral("PID %1").arg(victim) : victimPath;
            e.memoryInjection = true;
            e.kernelBlocked = true;
            e.kernelRightsStripped = true;
            e.detail = QStringLiteral("内核内存防护 · 已阻止跨进程注入 -> %1(PID %2)")
                           .arg(QFileInfo(e.target).fileName()).arg(victim);
            break;
        }

        case BlwEventNetworkConnect: {
            e.actorPath = actorPlaceholder;
            e.target = QStringLiteral("%1:%2").arg(formatIpv4Host(ev.RemoteIpV4)).arg(ev.RemotePort);
            e.kernelBlocked = true;
            e.detail = QStringLiteral("内核拦截 · 已阻断对黑名单地址的外联");
            break;
        }

        case BlwEventImageLoad: {
            const bool kernelModule = (e.actorPid == 0);
            e.actorPath = kernelModule ? QStringLiteral("内核(驱动加载)") : actorPlaceholder;
            e.target = targetPath;
            e.detail = kernelModule
                ? QStringLiteral("内核监控 · 加载驱动模块 %1").arg(QFileInfo(targetPath).fileName())
                : QStringLiteral("内核监控 · 加载模块 %1").arg(QFileInfo(targetPath).fileName());
            break;
        }

        case BlwEventImageBlocked:
            e.actorPath = e.actorPid > 0 ? actorPlaceholder : QStringLiteral("(加载方未知)");
            e.target = targetPath;
            e.kernelBlocked = true;
            e.detail = QStringLiteral("内核拦截 · 已阻止加载禁用模块 %1(白加黑防护)")
                           .arg(QFileInfo(targetPath).fileName());
            break;

        case BlwEventCommandBlocked: {
            const int initiator = static_cast<int>(ev.ParentPid);
            e.actorPid = initiator;
            e.parentPid = initiator;
            e.actorPath = initiator > 0 ? QStringLiteral("PID %1").arg(initiator)
                                        : QStringLiteral("(发起方未知)");
            e.target = imagePath;
            e.commandLine = targetPath;
            e.kernelBlocked = true;
            e.detail = QStringLiteral("内核拦截 · 已在执行前阻断危险命令:%1")
                           .arg(targetPath.isEmpty() ? QFileInfo(imagePath).fileName() : targetPath);
            break;
        }

        case BlwEventRegistryHiveDump:
            e.actorPath = actorPlaceholder;
            e.target = targetPath;
            e.kernelBlocked = true;
            e.detail = QStringLiteral("内核拦截 · 已阻止导出注册表 hive %1(凭据窃取防护)")
                           .arg(targetPath);
            break;

        case BlwEventRemoteThread: {
            const int victim = static_cast<int>(ev.ParentPid);
            const QString victimPath = resolvePidImagePath(ev.ParentPid);
            e.actorPath = actorPlaceholder;
            e.target = victimPath.isEmpty() ? QStringLiteral("PID %1").arg(victim) : victimPath;
            e.detail = QStringLiteral("内核监控 · 跨进程线程注入 -> %1(PID %2)")
                           .arg(QFileInfo(e.target).fileName()).arg(victim);
            break;
        }

        case BlwEventProcessTerminate: {
            e.actorPath = actorPlaceholder;
            QString victimPath = targetPath;
            if (victimPath.isEmpty())
                victimPath = resolvePidImagePath(ev.ParentPid);
            e.target = victimPath;
            e.detail = QStringLiteral("内核拦截 · 结束进程 %1").arg(QFileInfo(e.target).fileName());
            break;
        }

        case BlwEventBootSectorBlocked: {
            e.actorPath = actorPlaceholder;

            QString volume = targetPath;
            if (volume.isEmpty() || volume.compare(QLatin1String("RawVolume"), Qt::CaseInsensitive) == 0)
                volume = QStringLiteral("(裸卷句柄,未能解析卷名)");
            e.target = QStringLiteral("%1 %2").arg(volume, bulwark::targetTag::volumeBootSector());

            e.kernelBlocked = true;
            e.detail = (ev.ParentPid == 0)
                ? QStringLiteral("内核拦截 · 申请裸卷写权限(打开阶段即拒)")
                : QStringLiteral("内核拦截 · 写入卷引导区(被拒偏移 %1KB)").arg(ev.ParentPid);
            break;
        }

        default:
            e.actorPath = imagePath.isEmpty() ? actorPlaceholder : imagePath;
            e.target = e.actorPath;
            break;
    }

    enqueue(std::move(e));
}

void DriverEventSource::Impl::readLoop() {
    HANDLE p;
    {
        QMutexLocker lock(&portMutex);
        p = port;
    }
    if (p == nullptr) {
        connected.store(false);
        running.store(false);
        return;
    }

    HANDLE iocp = ::CreateIoCompletionPort(p, nullptr, 0, 1);
    if (iocp == nullptr) {
        log.warning(QStringLiteral("驱动端口关联完成端口失败(错误 %1),收不到内核事件(将由主线程重连)。")
                        .arg(::GetLastError()));
        connected.store(false);
        running.store(false);
        return;
    }

    // 槽位在本线程上分配,且只在所有挂起请求都已完成后才随线程退出释放;停机等不到本线程
    // 时宁可连线程带内存一起放弃,也不能让内核写入已释放的缓冲。
    std::vector<ReadSlot> readSlots(kReadSlots);
    int outstanding = 0;
    HRESULT failure = S_OK;
    bool closing = false;
    bool cancelled = false;

    const auto post = [&](ReadSlot& s) -> bool {
        ZeroMemory(&s.ov, sizeof(s.ov));
        const HRESULT hr = ::FilterGetMessage(p, &s.msg.Header,
                                              static_cast<DWORD>(sizeof(s.msg)), &s.ov);
        // 同步完成也会投递完成包(未设置 FILE_SKIP_COMPLETION_PORT_ON_SUCCESS),一样计入在途。
        if (hr == HRESULT_FROM_WIN32(ERROR_IO_PENDING) || hr == S_OK) {
            ++outstanding;
            return true;
        }
        if (failure == S_OK)
            failure = hr;
        return false;
    };

    for (ReadSlot& s : readSlots) {
        if (!post(s)) {
            closing = true;
            break;
        }
    }

    while (outstanding > 0) {
        if ((closing || !running.load()) && !cancelled) {
            ::CancelIoEx(p, nullptr);
            cancelled = true;
        }

        DWORD bytes = 0;
        ULONG_PTR key = 0;
        LPOVERLAPPED ov = nullptr;
        const BOOL ok = ::GetQueuedCompletionStatus(iocp, &bytes, &key, &ov,
                                                    cancelled ? 1000 : INFINITE);
        if (ov == nullptr) {
            // 没拿到完成包(取消后超时,或完成端口本身出错):在途请求清零前不能离开,
            // 再取消一次后继续等。
            const DWORD err = ::GetLastError();
            if (!closing) {
                closing = true;
                if (failure == S_OK)
                    failure = HRESULT_FROM_WIN32(err);
            }
            if (cancelled)
                ::CancelIoEx(p, nullptr);
            if (err != WAIT_TIMEOUT)
                ::Sleep(50);
            continue;
        }

        --outstanding;
        ReadSlot& s = *CONTAINING_RECORD(ov, ReadSlot, ov);
        if (!ok) {
            if (!closing) {
                closing = true;
                failure = HRESULT_FROM_WIN32(::GetLastError());
            }
            continue;
        }
        if (closing || !running.load())
            continue;

        try {
            buildAndQueue(s.msg.Event, s.msg.Header.MessageId);
        } catch (...) {
        }
        if (!post(s))
            closing = true;
    }
    ::CloseHandle(iocp);

    if (running.load() && failure != S_OK) {
        if (isBenignDisconnect(failure))
            log.info(QStringLiteral("FilterGetMessage 返回 0x%1(连接已断开),退出读取循环。")
                         .arg(static_cast<quint32>(failure), 8, 16, QLatin1Char('0')));
        else
            log.warning(QStringLiteral("FilterGetMessage 返回 0x%1,退出读取循环(将由主线程重连)。")
                            .arg(static_cast<quint32>(failure), 8, 16, QLatin1Char('0')));
    }
    connected.store(false);
    running.store(false);
}

}

namespace bulwark::service {

DriverEventSource::DriverEventSource(const BulwarkOptions& options, QObject* parent)
    : EventSource(parent), d_(std::make_unique<Impl>()) {
    d_->protectedPaths    = options.ProtectedPaths;
    d_->fileHardBlocks    = options.FileHardBlocks;
    d_->protectedRegKeys  = options.ProtectedRegistryKeys;
    d_->regHardBlocks     = options.RegistryHardBlocks;
    d_->cmdHardBlocks     = options.CommandHardBlocks;
    d_->cmdHardBaseline   = options.CommandHardBlockBaseline;
    d_->blockedEndpoints  = options.BlockedRemoteEndpoints;
    d_->memProtTargets    = options.MemoryProtectionTargets;
    d_->selfPid           = static_cast<quint32>(::GetCurrentProcessId());

    const int drainMs = qBound(1, options.EventDrainIntervalMs, 1000);
    drainTimer_ = new QTimer(this);
    drainTimer_->setInterval(drainMs);
    connect(drainTimer_, &QTimer::timeout, this, &DriverEventSource::drain);

    statsTimer_ = new QTimer(this);
    statsTimer_->setInterval(kDeliveryStatsIntervalMs);
    connect(statsTimer_, &QTimer::timeout, this, [this] { reportDeliveryStats(false); });
}

DriverEventSource::~DriverEventSource() { stop(); }

void DriverEventSource::start() {
    if (d_->running.load())
        return;

    // 断线后的读取线程已经结束，但 std::thread 仍须 join 后才能创建下一条连接。
    if (d_->readThread.joinable()) {
        d_->readThread.join();
        d_->readThreadNative = nullptr;
        d_->closePort();
    }

    if (!d_->connectPort())
        return;
    if (!d_->handshake()) {
        d_->protocolMismatch.store(true);
        d_->closePort();
        return;
    }

    d_->pushInitialConfig();

    // 驱动的计数从加载起累计,以连接时的值为基线,之后只报本次连接期间新增的丢失。
    d_->statsUnsupported = !d_->queryEventStats(d_->lastStats);
    d_->lastUserDropped = d_->userQueueDropped.load(std::memory_order_relaxed);
    if (d_->statsUnsupported)
        d_->log.info(QStringLiteral("内核驱动不支持事件投递统计查询(驱动比服务旧),内核侧丢失无法计数。"));

    d_->running.store(true);
    Impl* impl = d_.get();
    d_->readThread = std::thread([impl] {
        try { impl->readLoop(); }
        catch (...) { impl->log.warning(QStringLiteral("驱动读取线程异常退出。")); }
        impl->connected.store(false);
        impl->running.store(false);
    });
    d_->readThreadNative = static_cast<HANDLE>(d_->readThread.native_handle());
    drainTimer_->start();
    statsTimer_->start();
    d_->log.info(QStringLiteral("内核驱动事件源已就绪(行为前拦截 + 用户态补偿)。"));
}

void DriverEventSource::stop() {
    if (drainTimer_)
        drainTimer_->stop();
    if (statsTimer_ && statsTimer_->isActive()) {
        statsTimer_->stop();
        reportDeliveryStats(true);
    }
    d_->running.store(false);

    if (!d_->readThread.joinable()) {
        d_->closePort();
        QMutexLocker lock(&d_->queueMutex);
        d_->clearQueueLocked();
        return;
    }

    const HANDLE th = d_->readThreadNative;
    bool exited = false;
    if (th != nullptr) {
        for (int i = 0; i < 60 && !exited; ++i) {
            {
                QMutexLocker lock(&d_->portMutex);
                if (d_->port != nullptr)
                    ::CancelIoEx(d_->port, nullptr);
            }
            ::CancelSynchronousIo(th);
            exited = (::WaitForSingleObject(th, 100) == WAIT_OBJECT_0);
        }
    }

    if (!exited) {
        // 取消失败也不能让停机卡住:放弃该线程,有意泄漏旧 Impl 且不关端口句柄(线程还在用),
        // 换一个新 Impl 让后续调用安全。
        d_->log.warning(QStringLiteral("驱动读取线程未能在 6s 内退出:放弃等待以保证服务可正常停止"
                                       "(该线程及其状态被有意保留,随进程退出由系统回收)。"
                                       "它占着的那条端口连接也随之保留,驱动只允许一条连接,"
                                       "所以重启服务之前内核驱动接不回来。"));
        d_->readThread.detach();
        (void)d_.release();
        d_ = std::make_unique<Impl>();
        return;
    }

    d_->readThread.join();
    d_->readThreadNative = nullptr;
    d_->closePort();
    QMutexLocker lock(&d_->queueMutex);
    d_->clearQueueLocked();
}

bool DriverEventSource::isAvailable() const { return d_->connected.load(); }
bool DriverEventSource::isConnected() const { return d_->connected.load(); }
bool DriverEventSource::protocolMismatch() const { return d_->protocolMismatch.load(); }

void DriverEventSource::applyRansomGuard(bool enabled, const QStringList& dirs,
                                         const QStringList& writers) {
    // 三者必须一起设:它们有一致性约束,拆成独立 setter 会出现内核按半新半旧配置拦截的中间状态。
    d_->guardEnabled = enabled;
    d_->guardDirs = dirs;
    d_->guardWriters = writers;

    if (!d_->connected.load())
        return;
    d_->reconcileRansomGuard();
}

void DriverEventSource::applyReadGuard(bool enabled, const QStringList& entries,
                                       const QStringList& readers) {
    d_->readGuardEnabled = enabled;
    d_->readGuardEntries = entries;
    d_->readGuardReaders = readers;

    if (!d_->connected.load())
        return;
    d_->reconcileReadGuard();
}

void DriverEventSource::setMemoryProtectionEnabled(bool on) {
    if (d_->memProtEnabled == on)
        return;
    d_->memProtEnabled = on;
    if (!d_->connected.load())
        return;
    d_->initMemoryProtection();
}

QStringList DriverEventSource::missingCapabilities() const {
    if (!d_->connected.load())
        return {};
    return d_->missingCapabilities();
}

void DriverEventSource::submitVerdict(const bulwark::SecurityEvent& e,
                                      bulwark::VerdictAction action) {
    Q_UNUSED(e);
    Q_UNUSED(action);
    // 驱动事件队列是单向异步遥测，内核不等待用户态裁决。
}

void DriverEventSource::addProtectedPid(int pid) {
    if (pid <= 0)
        return;
    if (d_->connected.load()) {
        bool added = false;
        {
            QMutexLocker lock(&d_->queueMutex);
            added = !d_->protectedPids.contains(pid);
            if (added) d_->protectedPids.insert(pid);
        }
        if (added) {
            d_->sendConfig(BLW_CMD_ADD_PID, QString(), static_cast<ULONG>(pid));
            d_->log.info(QStringLiteral("已将进程 PID %1 加入内核自我保护。").arg(pid));
        }
    } else {
        QMutexLocker lock(&d_->queueMutex);
        d_->pendingPids.insert(pid);
    }
}

void DriverEventSource::addBlockedIp(const QString& ip, quint16 port) {
    quint32 ipHost = 0; quint16 p = 0;
    const QString entry = port > 0 ? QStringLiteral("%1:%2").arg(ip).arg(port) : ip;
    if (parseIpEndpoint(entry, ipHost, p))
        d_->sendConfig(BLW_CMD_ADD_BLOCKIP, QString(), 0, ipHost, p);
}

bool DriverEventSource::Impl::kernelReadFile(const QString& path, QByteArray& out) {
    out.clear();
    const QString p0 = path.trimmed();
    if (p0.isEmpty()) return false;

    constexpr int kChunk = 64 * 1024;
    constexpr qint64 kMaxTotal = 512LL * 1024 * 1024;
    QByteArray chunk(kChunk, Qt::Uninitialized);
    quint64 offset = 0;

    for (;;) {
        BLW_CONFIG_MESSAGE cfg;
        ZeroMemory(&cfg, sizeof(cfg));
        cfg.Command = BLW_CMD_QUARANTINE_READ;
        cfg.Pid = static_cast<ULONG>(offset & 0xFFFFFFFFull);
        cfg.BlockIpV4 = static_cast<ULONG>((offset >> 32) & 0xFFFFFFFFull);
        QString p = p0;
        const int maxChars = BLW_MAX_PATH - 1;
        if (p.size() > maxChars) p = p.left(maxChars);
        cfg.PathLength = static_cast<USHORT>(p.size());
        const int copied = p.isEmpty() ? 0 : p.toWCharArray(cfg.Path);
        cfg.Path[copied] = L'\0';

        DWORD returned = 0;
        HRESULT hr;
        {
            QMutexLocker lock(&portMutex);
            if (port == nullptr) return false;
            hr = ::FilterSendMessage(port, &cfg, sizeof(cfg), chunk.data(), kChunk, &returned);
        }
        if (FAILED(hr)) return false;
        if (returned == 0) break;
        out.append(chunk.constData(), static_cast<int>(returned));
        offset += returned;
        if (static_cast<qint64>(out.size()) > kMaxTotal) return false;
    }
    return true;
}

bool DriverEventSource::Impl::kernelForceDelete(const QString& path) {
    const QString p0 = path.trimmed();
    if (p0.isEmpty()) return false;

    BLW_CONFIG_MESSAGE cfg;
    ZeroMemory(&cfg, sizeof(cfg));
    cfg.Command = BLW_CMD_FORCE_DELETE;
    QString p = p0;
    const int maxChars = BLW_MAX_PATH - 1;
    if (p.size() > maxChars) p = p.left(maxChars);
    cfg.PathLength = static_cast<USHORT>(p.size());
    const int copied = p.isEmpty() ? 0 : p.toWCharArray(cfg.Path);
    cfg.Path[copied] = L'\0';

    BLW_FILEOP_REPLY reply;
    ZeroMemory(&reply, sizeof(reply));
    DWORD returned = 0;
    HRESULT hr;
    {
        QMutexLocker lock(&portMutex);
        if (port == nullptr) return false;
        hr = ::FilterSendMessage(port, &cfg, sizeof(cfg), &reply, sizeof(reply), &returned);
    }
    if (FAILED(hr) || returned < sizeof(reply)) return false;
    const bool ok = (reply.Status == 0);
    if (ok)
        log.warning(QStringLiteral("内核级强制删除成功(忽略共享/映像占用):%1").arg(p0));
    else
        log.info(QStringLiteral("内核级强制删除未成功(0x%1),将回退用户态处置:%2")
                     .arg(static_cast<quint32>(reply.Status), 8, 16, QLatin1Char('0')).arg(p0));
    return ok;
}

bool DriverEventSource::blockModuleLoad(const QString& modulePath) {
    const QString p = modulePath.trimmed();
    if (p.isEmpty() || !d_->connected.load())
        return false;
    const bool ok = d_->sendConfig(BLW_CMD_ADD_NOLOAD, p);
    if (ok)
        d_->log.warning(QStringLiteral("已下发内核「禁止加载」名单:%1").arg(p));
    return ok;
}

bool DriverEventSource::blockExecPath(const QString& imagePath) {
    const QString p = imagePath.trimmed();
    if (p.isEmpty() || !d_->connected.load())
        return false;
    const bool ok = d_->sendConfig(BLW_CMD_ADD_EXECBLOCK, p);
    if (ok)
        d_->log.warning(QStringLiteral("已下发内核「禁止执行」名单(执行前拦截):%1").arg(p));
    return ok;
}

namespace {

// 服务名必须与 DriverControl.cpp 的 kServiceName("Bulwark")一致。
constexpr wchar_t kPolicyKeyPath[] =
    L"SYSTEM\\CurrentControlSet\\Services\\Bulwark\\Policy";

QStringList readMultiSz(const wchar_t* valueName) {
    DWORD type = 0, bytes = 0;
    LSTATUS st = ::RegGetValueW(HKEY_LOCAL_MACHINE, kPolicyKeyPath, valueName,
                                RRF_RT_REG_MULTI_SZ, &type, nullptr, &bytes);
    if (st != ERROR_SUCCESS || bytes < sizeof(wchar_t) || bytes > 0x100000)
        return {};
    QVector<wchar_t> buf(static_cast<int>(bytes / sizeof(wchar_t)) + 2, L'\0');
    st = ::RegGetValueW(HKEY_LOCAL_MACHINE, kPolicyKeyPath, valueName,
                        RRF_RT_REG_MULTI_SZ, &type, buf.data(), &bytes);
    if (st != ERROR_SUCCESS)
        return {};
    QStringList out;
    const wchar_t* p = buf.constData();
    const wchar_t* end = buf.constData() + buf.size();
    while (p < end && *p != L'\0') {
        const QString s = QString::fromWCharArray(p);
        if (!s.trimmed().isEmpty())
            out << s.trimmed();
        p += s.size() + 1;
    }
    return out;
}

}

void DriverEventSource::Impl::reconcileRansomGuard() {
    if (!connected.load())
        return;

    // 判据来自握手位图。
    if (!caps.guardDir) {
        log.warning(QStringLiteral("受保护目录(反勒索):当前驱动未声明该能力(驱动比服务旧),"
                                   "这一维【未生效】。其余防护不受影响;更新 Bulwark.sys 后自动恢复。"));
        return;
    }

    QStringList wantDirs;
    QStringList wantWriters;
    if (guardEnabled) {
        for (const QString& s : guardDirs)
            if (!s.trimmed().isEmpty() && !wantDirs.contains(s.trimmed(), Qt::CaseInsensitive))
                wantDirs << s.trimmed();
        for (const QString& s : guardWriters)
            if (!s.trimmed().isEmpty() && !wantWriters.contains(s.trimmed(), Qt::CaseInsensitive))
                wantWriters << s.trimmed();
    }

    const QStringList haveWriters = readMultiSz(L"GuardWriters");
    const QStringList haveDirs = readMultiSz(L"GuardDirs");

    int added = 0, removed = 0;
    for (const QString& w : wantWriters)
        if (sendConfig(BLW_CMD_ADD_GUARDWRITER, w)) ++added;
    for (const QString& w : haveWriters)
        if (!wantWriters.contains(w, Qt::CaseInsensitive) &&
            sendConfig(BLW_CMD_DEL_GUARDWRITER, w)) ++removed;

    int dirAdded = 0, dirRemoved = 0;
    for (const QString& d : haveDirs)
        if (!wantDirs.contains(d, Qt::CaseInsensitive) &&
            sendConfig(BLW_CMD_DEL_GUARDDIR, d)) ++dirRemoved;
    for (const QString& d : wantDirs)
        if (sendConfig(BLW_CMD_ADD_GUARDDIR, d)) ++dirAdded;

    if (!guardEnabled) {
        log.warning(QStringLiteral("受保护目录(反勒索)已【关闭】:已从内核与磁盘基线移除 %1 个目录、"
                                   "%2 条可信写入者例外。此后勒索对这些目录的加密/删除不再被内核前拦。")
                        .arg(dirRemoved).arg(removed));
        return;
    }

    // 名单各 64 槽(BLW_MAX_PROTECTED),超出部分被内核丢弃且用户看不到内核日志,所以在这里警告。
    constexpr int kKernelSlots = 64;
    if (wantDirs.size() > kKernelSlots)
        log.warning(QStringLiteral("受保护目录共 %1 个,超过内核名单容量(%2)—— 超出的部分【不会生效】。"
                                   "请减少目录数量,或用更靠上的父目录合并。")
                        .arg(wantDirs.size()).arg(kKernelSlots));
    if (wantWriters.size() > kKernelSlots)
        log.warning(QStringLiteral("可信写入者共 %1 条,超过内核名单容量(%2)—— 超出的部分【不会生效】,"
                                   "表现为对那些程序的误拦。请精简信任名单中的条目。")
                        .arg(wantWriters.size()).arg(kKernelSlots));

    log.info(QStringLiteral("受保护目录(反勒索)已就绪:%1 个目录(本次新增/重推 %2、移除 %3)、"
                            "%4 条可信写入者(新增/重推 %5、移除 %6)。"
                            "此后非可信写入者对这些目录的写/新建/删除/改名一律由内核在打开阶段拒绝。")
                 .arg(wantDirs.size()).arg(dirAdded).arg(dirRemoved)
                 .arg(wantWriters.size()).arg(added).arg(removed));
}

void DriverEventSource::Impl::reconcileReadGuard() {
    if (!connected.load())
        return;
    if (!caps.readGuard) {
        log.warning(QStringLiteral("窃密防护:当前驱动未声明该能力(驱动比服务旧),这一维【未生效】。"
                                   "更新 Bulwark.sys 后自动恢复。"));
        return;
    }

    // 驱动把条目和读者都存成大写,所以这里一律不区分大小写比较。
    constexpr int kKernelSlots = 64;
    QStringList wantEntries;
    QStringList wantReaders;
    int tooLong = 0;
    if (readGuardEnabled) {
        for (const QString& s : readGuardEntries) {
            const QString t = s.trimmed();
            if (t.isEmpty() || wantEntries.contains(t, Qt::CaseInsensitive))
                continue;
            if (t.size() >= BLW_MAX_PATH) { ++tooLong; continue; }
            wantEntries << t;
        }
        for (const QString& s : readGuardReaders) {
            const QString t = s.trimmed();
            if (t.isEmpty() || wantReaders.contains(t, Qt::CaseInsensitive))
                continue;
            if (t.size() >= BLW_MAX_PATH) { ++tooLong; continue; }
            wantReaders << t;
        }
    }

    const QStringList haveEntries = readMultiSz(L"ReadGuard");
    const QStringList haveReaders = readMultiSz(L"ReadGuardReaders");

    // 先加读者、后加条目;先删条目、后删读者 —— 中间态只会多放行,不会把正常程序拦下。
    int readerAdded = 0, readerRemoved = 0, entryAdded = 0, entryRemoved = 0;
    for (const QString& r : wantReaders)
        if (sendConfig(BLW_CMD_ADD_READGUARD_READER, r)) ++readerAdded;
    for (const QString& e : haveEntries)
        if (!wantEntries.contains(e, Qt::CaseInsensitive) &&
            sendConfig(BLW_CMD_DEL_READGUARD, e)) ++entryRemoved;
    for (const QString& e : wantEntries)
        if (sendConfig(BLW_CMD_ADD_READGUARD, e)) ++entryAdded;
    for (const QString& r : haveReaders)
        if (!wantReaders.contains(r, Qt::CaseInsensitive) &&
            sendConfig(BLW_CMD_DEL_READGUARD_READER, r)) ++readerRemoved;

    if (!readGuardEnabled) {
        log.warning(QStringLiteral("窃密防护已【关闭】:已从内核与磁盘基线移除 %1 条敏感数据条目、%2 个全局读者。"
                                   "此后任何程序都能读取浏览器登录库、通讯会话与钱包文件。")
                        .arg(entryRemoved).arg(readerRemoved));
        return;
    }

    if (tooLong > 0)
        log.warning(QStringLiteral("窃密防护:%1 条条目 / 读者超过内核单条长度上限(%2 字符),已跳过。")
                        .arg(tooLong).arg(BLW_MAX_PATH - 1));
    if (wantEntries.size() > kKernelSlots)
        log.warning(QStringLiteral("窃密防护条目共 %1 条,超过内核名单容量(%2)—— 超出的部分【不会生效】。")
                        .arg(wantEntries.size()).arg(kKernelSlots));
    if (wantReaders.size() > kKernelSlots)
        log.warning(QStringLiteral("窃密防护全局读者共 %1 个,超过内核名单容量(%2)—— 超出的部分【不会生效】,"
                                   "表现为对那些程序的误拦。请精简信任名单。")
                        .arg(wantReaders.size()).arg(kKernelSlots));

    log.info(QStringLiteral("窃密防护已就绪:%1 条敏感数据条目(新增/重推 %2、移除 %3)、%4 个全局读者"
                            "(新增/重推 %5、移除 %6)。此后非指定程序打开这些数据一律由内核拒绝。")
                 .arg(wantEntries.size()).arg(entryAdded).arg(entryRemoved)
                 .arg(wantReaders.size()).arg(readerAdded).arg(readerRemoved));
}

bool DriverEventSource::clearExecBlock() {
    if (!d_->connected.load())
        return false;
    const bool ok = d_->sendConfig(BLW_CMD_CLEAR_EXECBLOCK, QString());
    if (ok)
        d_->log.warning(QStringLiteral("已请求内核清空「禁止执行」名单(加白对账,随后重下发未加白条目)。"));
    return ok;
}

bool DriverEventSource::clearModuleNoLoad() {
    if (!d_->connected.load())
        return false;
    const bool ok = d_->sendConfig(BLW_CMD_CLEAR_NOLOAD, QString());
    if (ok)
        d_->log.warning(QStringLiteral("已请求内核清空「禁止加载」名单(加白对账,随后重下发未加白条目)。"));
    return ok;
}

bool DriverEventSource::clearBannedProcesses() {
    if (!d_->connected.load())
        return false;
    const bool ok = d_->sendConfig(BLW_CMD_CLEAR_BANNED, QString());
    if (ok)
        d_->log.warning(QStringLiteral("已请求内核清空「已封禁主体」PID 集(加白对账:解除对已加白进程的全维拒绝)。"));
    return ok;
}

QStringList DriverEventSource::persistedExecBlockList() const {
    return readMultiSz(L"FileExecBlock");
}

QStringList DriverEventSource::persistedModuleNoLoadList() const {
    return readMultiSz(L"FileNoLoad");
}

bool DriverEventSource::hardenRegistryKey(const QString& keyOrValue) {
    const QString k = keyOrValue.trimmed();
    if (k.isEmpty() || !d_->connected.load())
        return false;
    const bool ok = d_->sendConfig(BLW_CMD_ADD_REGHARD, k);
    if (ok)
        d_->log.warning(QStringLiteral("已下发内核注册表硬拦(持久化反重建):%1").arg(k));
    return ok;
}

bool DriverEventSource::readLockedFile(const QString& path, QByteArray& out) {
    if (!d_->connected.load())
        return false;
    return d_->kernelReadFile(path, out);
}

bool DriverEventSource::forceDeleteFile(const QString& path) {
    if (!d_->connected.load())
        return false;
    return d_->kernelForceDelete(path);
}

bool DriverEventSource::killProcess(int pid) {
    if (pid <= 4 || !d_->connected.load())
        return false;
    BLW_CONFIG_MESSAGE cfg;
    ZeroMemory(&cfg, sizeof(cfg));
    cfg.Command = BLW_CMD_KILL_PID;
    cfg.Pid = static_cast<ULONG>(pid);
    DWORD returned = 0;
    HRESULT hr;
    {
        QMutexLocker lock(&d_->portMutex);
        if (d_->port == nullptr) return false;
        hr = ::FilterSendMessage(d_->port, &cfg, sizeof(cfg), nullptr, 0, &returned);
    }
    if (SUCCEEDED(hr)) {
        d_->log.info(QStringLiteral("已请求内核级结束进程 PID=%1(驱动级 ZwTerminateProcess)。").arg(pid));
        return true;
    }
    return false;
}

bool DriverEventSource::banProcess(int pid) {
    if (pid <= 4 || !d_->connected.load())
        return false;
    const bool ok = d_->sendConfig(BLW_CMD_ADD_BANNED, QString(), static_cast<ULONG>(pid));
    if (ok)
        d_->log.warning(QStringLiteral("已下发内核封禁主体(情报确认恶意,全维拒绝其行为):PID=%1").arg(pid));
    return ok;
}

bool DriverEventSource::Impl::queryWfpStats(BLW_WFP_STATS_REPLY& out) {
    BLW_CONFIG_MESSAGE cfg;
    ZeroMemory(&cfg, sizeof(cfg));
    cfg.Command = BLW_CMD_QUERY_WFP_STATS;

    BLW_WFP_STATS_REPLY reply;
    ZeroMemory(&reply, sizeof(reply));
    DWORD returned = 0;
    HRESULT hr;
    {
        QMutexLocker lock(&portMutex);
        if (port == nullptr) return false;
        hr = ::FilterSendMessage(port, &cfg, sizeof(cfg), &reply, sizeof(reply), &returned);
    }
    if (FAILED(hr) || returned < sizeof(reply)) return false;
    out = reply;
    return true;
}

bool DriverEventSource::Impl::queryEventStats(BLW_EVENT_STATS_REPLY& out) {
    BLW_CONFIG_MESSAGE cfg;
    ZeroMemory(&cfg, sizeof(cfg));
    cfg.Command = BLW_CMD_QUERY_EVENT_STATS;

    BLW_EVENT_STATS_REPLY reply;
    ZeroMemory(&reply, sizeof(reply));
    DWORD returned = 0;
    HRESULT hr;
    {
        QMutexLocker lock(&portMutex);
        if (port == nullptr) return false;
        hr = ::FilterSendMessage(port, &cfg, sizeof(cfg), &reply, sizeof(reply), &returned);
    }
    if (FAILED(hr) || returned < sizeof(reply)) return false;
    out = reply;
    return true;
}

void DriverEventSource::reportDeliveryStats(bool final) {
    if (!d_->connected.load() || d_->statsUnsupported)
        return;
    BLW_EVENT_STATS_REPLY s;
    if (!d_->queryEventStats(s))
        return;

    const BLW_EVENT_STATS_REPLY& prev = d_->lastStats;
    const quint64 userDropped = d_->userQueueDropped.load(std::memory_order_relaxed);
    const quint64 droppedNow = (s.DroppedQueueFull - prev.DroppedQueueFull)
                             + (s.DroppedNoClient - prev.DroppedNoClient)
                             + (s.DroppedSendFailed - prev.DroppedSendFailed)
                             + (userDropped - d_->lastUserDropped);
    if (final || droppedNow > 0) {
        const QString line =
            QStringLiteral("内核事件投递%1:入队 %2,送达 %3;丢弃 —— 内核队列满 %4,服务未连接 %5,"
                           "发送出错 %6,服务端队列满 %7;发送等待重试 %8 次(均为驱动加载以来的累计)。")
                .arg(final ? QStringLiteral("汇总") : QStringLiteral("出现丢失(最近一分钟新增 %1 条)").arg(droppedNow))
                .arg(s.Queued).arg(s.Delivered)
                .arg(s.DroppedQueueFull).arg(s.DroppedNoClient).arg(s.DroppedSendFailed)
                .arg(userDropped).arg(s.SendWaits);
        if (!final)
            d_->log.warning(line);
        else
            d_->log.info(line);
    }
    d_->lastStats = s;
    d_->lastUserDropped = userDropped;
}

DriverEventSource::WfpStats DriverEventSource::queryWfpStats() const {
    WfpStats s;
    if (!d_->connected.load())
        return s;
    BLW_WFP_STATS_REPLY r;
    if (!d_->queryWfpStats(r))
        return s;
    s.available     = true;
    s.registered    = (r.Registered != 0);
    s.layerCount    = r.LayerCount;
    s.classifyCalls = r.ClassifyCalls;
    s.rightsCleared = r.RightsCleared;
    s.bannedBlocks  = r.BannedBlocks;
    s.ipBlocks      = r.IpBlocks;
    s.bringUpAttempts = r.BringUpAttempts;
    s.lastStage       = r.LastStage;
    s.lastStatus      = r.LastStatus;
    s.bfeSubscribed   = (r.BfeSubscribed != 0);
    s.lastLayer       = static_cast<qint32>(r.LastLayer);
    return s;
}

QString DriverEventSource::wfpStageName(quint32 stage) {
    switch (stage) {
        case BLW_WFP_STAGE_NONE:         return QStringLiteral("无失败记录");
        case BLW_WFP_STAGE_NO_DEVICE:    return QStringLiteral("设备对象缺失(注册 callout 的前提)");
        case BLW_WFP_STAGE_CALLOUT_REG:  return QStringLiteral("FwpsCalloutRegister(内核 callout)");
        case BLW_WFP_STAGE_ENGINE_OPEN:  return QStringLiteral("FwpmEngineOpen(BFE 未就绪时最常见)");
        case BLW_WFP_STAGE_TXN_BEGIN:    return QStringLiteral("FwpmTransactionBegin");
        case BLW_WFP_STAGE_SUBLAYER_ADD: return QStringLiteral("FwpmSubLayerAdd(子层)");
        case BLW_WFP_STAGE_CALLOUT_ADD:  return QStringLiteral("FwpmCalloutAdd(管理层 callout)");
        case BLW_WFP_STAGE_FILTER_ADD:   return QStringLiteral("FwpmFilterAdd(过滤器)");
        case BLW_WFP_STAGE_TXN_COMMIT:   return QStringLiteral("FwpmTransactionCommit");
        default:                         return QStringLiteral("未知阶段(%1)").arg(stage);
    }
}

// 把计数折成一句结论;判读规则只在这里实现,调用方不要另写阈值。
QString DriverEventSource::describeWfpHealth(const WfpStats& s) {
    if (!s.available) {
        return QStringLiteral("内核出站拦截的【实际】工作状态未知:驱动未连接,或 Bulwark.sys "
                              "比服务旧(不认 WFP 统计查询)。此时不应声称「出站连接阻断」已生效 —— "
                              "命令被受理只说明名单下发成功,不等于连接真的会被拦下。");
    }
    if (!s.registered) {
        QString why;
        if (s.bringUpAttempts == 0) {
            why = QStringLiteral("拉起【一次都没被尝试过】—— 说明 BlwWfpStart 没被调用到"
                                 "(设备对象创建失败,或网络防护在更早的分支就被跳过)");
        } else {
            const QString layerNote =
                (s.lastLayer >= 0)
                    ? QStringLiteral(",层索引=%1(0=IPv4,1=IPv6)").arg(s.lastLayer)
                    : QString();
            why = QStringLiteral("拉起已尝试 %1 次,最近一次失败在:%2%3,NTSTATUS=0x%4")
                      .arg(s.bringUpAttempts)
                      .arg(wfpStageName(s.lastStage))
                      .arg(layerNote)
                      .arg(static_cast<quint32>(s.lastStatus), 8, 16, QLatin1Char('0'));
            if (s.lastStage == BLW_WFP_STAGE_CALLOUT_REG &&
                static_cast<quint32>(s.lastStatus) == 0xC00000BBu) {
                why += QStringLiteral("。【这个组合有已查清的根因】STATUS_NOT_SUPPORTED 落在 "
                                      "FwpsCalloutRegister 上,几乎总是「调用时 IRQL 不是 "
                                      "PASSIVE_LEVEL」。本产品曾因 WFP 拉起跑在 FAST_MUTEX 内"
                                      "(IRQL=APC_LEVEL)导致整条出站拦截失效,现已改用 "
                                      "ERESOURCE。若再次出现,请先查锁与 IRQL,【不要】从 BFE "
                                      "启动时序查起 —— 那个方向已经被排除过一次");
            }
        }
        return QStringLiteral("内核出站拦截【未就绪】:WFP callout / filter 没有挂上。%1。"
                              "BFE 状态订阅%2 —— %3。"
                              "期间出站封禁、已封禁主体断网【全部不生效】。")
            .arg(why)
            .arg(s.bfeSubscribed ? QStringLiteral("在") : QStringLiteral("【不在】"))
            .arg(s.bfeSubscribed
                     ? QStringLiteral("若失败原因是 BFE 未就绪,它就绪后会自动补挂,稍后复查")
                     : QStringLiteral("没有订阅就【不会自动重试】,必须重启服务或重新加载驱动"));
    }
    if (s.classifyCalls == 0) {
        return QStringLiteral("内核出站拦截【疑似未生效】:WFP 已注册,但 classify 回调一次都没被"
                              "调用过(机器有出站流量却计数为 0)。说明 filter 实际没有把连接引到"
                              "本驱动的回调上,问题在注册侧而不在各拦截分支。");
    }
    if (s.rightsCleared * 2 >= s.classifyCalls) {
        return QStringLiteral("内核出站拦截【大概率被压制】:classify 被调用 %1 次,其中 %2 次进来时 "
                              "FWPS_RIGHT_ACTION_WRITE 已被上游清除 —— 即更高权重的 WFP 子层下了"
                              "硬性允许,本驱动无权再改写该连接的裁决。后果是"
                              "已封禁主体断网、IP 黑名单【两条一起静默失效】。"
                              "常见于机器上并存其它安全产品(各自的子层权重更高)。")
            .arg(s.classifyCalls).arg(s.rightsCleared);
    }
    return QString();
}

void DriverEventSource::drain() {
    constexpr int kMaxPerDrain = 32;
    QVector<bulwark::SecurityEvent> batch;
    bool more = false;
    {
        QMutexLocker lock(&d_->queueMutex);
        if (d_->queue.isEmpty())
            return;
        const int n = qMin(d_->queue.size(), kMaxPerDrain);
        // 逐个 move 出来，避免 mid()+remove() 在积压时反复 detach 和拷贝剩余事件。
        batch.reserve(n);
        for (int i = 0; i < n; ++i)
            batch.push_back(std::move(d_->queue[i]));
        d_->queue.remove(0, n);
        more = !d_->queue.isEmpty();
    }

    for (const auto& e : batch)
        emit eventProduced(e);
    if (more)
        QTimer::singleShot(0, this, &DriverEventSource::drain);
}

}
