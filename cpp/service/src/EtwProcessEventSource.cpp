#include "bulwark/service/EtwProcessEventSource.h"
#include "bulwark/service/Logger.h"
#include "bulwark/engine/DgaDomainAnalyzer.h"
#include "bulwark/service/monitoring/ProcessInspector.h"
#include "bulwark/service/VolumePathMap.h"

#include <QTimer>
#include <QMutex>
#include <QMutexLocker>
#include <QFileInfo>
#include <QMap>
#include <QHash>
#include <QSet>
#include <QString>
#include <QStringList>

#include <algorithm>
#include <atomic>
#include <cstdint>
#include <thread>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <krabs.hpp>

namespace bulwark::service {

namespace {

const wchar_t* const kKernelProcessGuid = L"{22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}";
constexpr USHORT    kProcessStartEventId = 1;
constexpr USHORT    kThreadStartEventId  = 3;
constexpr USHORT    kImageLoadEventId    = 5;
constexpr ULONGLONG kKeywordProcess      = 0x10;
constexpr ULONGLONG kKeywordThread       = 0x20;
constexpr ULONGLONG kKeywordImage        = 0x40;
constexpr int       kQueueMax            = 4096;
constexpr int       kProcBirthSoftMax    = 512;

const wchar_t* const kKernelNetworkGuid  = L"{7DD42A49-5329-4832-8DFD-43D979153A88}";
constexpr USHORT     kNetConnectEventId  = 12;

const wchar_t* const kDnsClientGuid      = L"{1C95126E-7EEA-49A9-A3FE-A378B03DDB4D}";
constexpr USHORT     kDnsQueryEventId    = 3006;

// 只要 TerminateProcess(事件 2)。同一提供程序的 OpenProcess / OpenThread 量极大,
// 用启用时的事件 ID 过滤挡在内核侧。事件头 PID 是调用方,载荷里是被结束的进程。
const wchar_t* const kAuditApiGuid            = L"{E02A841C-75A3-4FA7-AFC8-AE09CF9B7F23}";
constexpr USHORT     kAuditTerminateProcessId = 2;
constexpr int        kProcParentMax           = 8192;

const wchar_t* const kKernelRegistryGuid = L"{70EB4F03-C1DE-4F73-A051-33D13D5413BD}";
constexpr ULONGLONG  kKeywordRegistry    = 0x7720;
constexpr USHORT     kRegCreateKey       = 1;
constexpr USHORT     kRegOpenKey         = 2;
constexpr USHORT     kRegDeleteKey       = 3;
constexpr USHORT     kRegSetValueKey     = 5;
constexpr USHORT     kRegDeleteValueKey  = 6;
constexpr int        kRegNameCacheMax    = 8192;

const wchar_t* const kKernelFileGuid     = L"{EDD08927-9CC4-4E65-B970-C2560FB5C289}";
constexpr ULONGLONG  kKeywordFile        = 0x1400;
constexpr USHORT     kFileDeletePath     = 26;
constexpr USHORT     kFileCreateNew      = 30;
constexpr USHORT     kFileCreate         = 12;
constexpr USHORT     kFileWrite          = 16;
constexpr ULONGLONG  kKeywordFileCreate  = 0x80;
constexpr ULONGLONG  kKeywordFileWrite   = 0x200;
constexpr int        kFileObjMapMax      = 4096;

inline bool matchesWatch(const QString& target, const QStringList& watch) {
    for (const QString& w : watch)
        if (!w.isEmpty() && target.contains(w, Qt::CaseInsensitive))
            return true;
    return false;
}

inline bool isDroppedExecutable(const QString& path) {
    static const QStringList kExt = {
        QStringLiteral(".exe"), QStringLiteral(".dll"), QStringLiteral(".sys"),
        QStringLiteral(".scr"), QStringLiteral(".cpl"), QStringLiteral(".ocx"),
        QStringLiteral(".msi"), QStringLiteral(".msp"), QStringLiteral(".jar"),
        QStringLiteral(".bat"), QStringLiteral(".cmd"), QStringLiteral(".ps1"),
        QStringLiteral(".vbs"), QStringLiteral(".vbe"), QStringLiteral(".js"),
        QStringLiteral(".jse"), QStringLiteral(".wsf"), QStringLiteral(".wsh"),
        QStringLiteral(".hta"), QStringLiteral(".lnk"), QStringLiteral(".pif"),
        QStringLiteral(".com"),
    };
    static const QStringList kDirs = {
        QStringLiteral("\\Users\\"), QStringLiteral("\\ProgramData\\"),
        QStringLiteral("\\Windows\\Temp\\"), QStringLiteral("\\Temp\\"),
        QStringLiteral("\\PerfLogs\\"),
    };
    bool extOk = false;
    for (const QString& x : kExt) {
        if (path.endsWith(x, Qt::CaseInsensitive)) { extOk = true; break; }
    }
    if (!extOk)
        return false;
    for (const QString& d : kDirs) {
        if (path.contains(d, Qt::CaseInsensitive))
            return true;
    }
    return false;
}

inline bool isSuspectModulePath(const QString& path) {
    static const QStringList kModExt = {
        QStringLiteral(".dll"), QStringLiteral(".sys"), QStringLiteral(".ocx"),
        QStringLiteral(".cpl"), QStringLiteral(".drv"), QStringLiteral(".acm"),
        QStringLiteral(".ax"),  QStringLiteral(".efi"), QStringLiteral(".scr"),
    };
    bool extOk = false;
    for (const QString& x : kModExt) {
        if (path.endsWith(x, Qt::CaseInsensitive)) { extOk = true; break; }
    }
    if (!extOk)
        return false;

    static const QStringList kDropDirs = {
        QStringLiteral("\\Users\\"), QStringLiteral("\\ProgramData\\"),
        QStringLiteral("\\Windows\\Temp\\"), QStringLiteral("\\Temp\\"),
        QStringLiteral("\\PerfLogs\\"),
    };
    for (const QString& d : kDropDirs) {
        if (path.contains(d, Qt::CaseInsensitive))
            return true;
    }
    static const QStringList kSystemDirs = {
        QStringLiteral("\\Windows\\"), QStringLiteral("\\Program Files\\"),
        QStringLiteral("\\Program Files (x86)\\"),
    };
    for (const QString& d : kSystemDirs) {
        if (path.contains(d, Qt::CaseInsensitive))
            return false;
    }
    return true;
}

inline QString system32Dir() {
    static const QString dir = [] {
        wchar_t buf[MAX_PATH] = {};
        const UINT n = ::GetSystemDirectoryW(buf, MAX_PATH);
        return (n > 0 && n < MAX_PATH)
            ? QString::fromWCharArray(buf, static_cast<int>(n))
            : QStringLiteral("C:\\Windows\\System32");
    }();
    return dir;
}

inline bool isOsThreadInjector(const QString& creatorPath) {
    if (creatorPath.isEmpty())
        return false;
    static const QString kCsrss = system32Dir() + QStringLiteral("\\csrss.exe");
    return creatorPath.compare(kCsrss, Qt::CaseInsensitive) == 0;
}

inline QString ipv4ToString(quint32 addr) {
    return QStringLiteral("%1.%2.%3.%4")
        .arg(addr & 0xFF).arg((addr >> 8) & 0xFF)
        .arg((addr >> 16) & 0xFF).arg((addr >> 24) & 0xFF);
}

inline quint16 netToHostPort(quint16 p) {
    return static_cast<quint16>((p << 8) | (p >> 8));
}

struct EmitGate {
    int    perMinCap     = 0;
    qint64 dedupWindowMs = 0;
    qint64 minStart      = 0;
    qint64 dedupStart    = 0;
    QHash<quint32, int> perPid;
    QSet<QString>       dedup;

    bool allow(quint32 pid, const QString& target, qint64 nowMs) {
        if (nowMs - minStart >= 60000) { minStart = nowMs; perPid.clear(); }
        if (dedupWindowMs > 0 && nowMs - dedupStart >= dedupWindowMs) {
            dedupStart = nowMs;
            dedup.clear();
        }
        QString key;
        if (dedupWindowMs > 0) {
            key = QString::number(pid) + QLatin1Char('|') + target;
            if (dedup.contains(key)) return false;
        }
        if (perMinCap > 0 && perPid.value(pid, 0) >= perMinCap) return false;
        if (perMinCap > 0) ++perPid[pid];
        if (dedupWindowMs > 0) dedup.insert(key);
        return true;
    }
};

QString deviceToDrive(const QString& p) {
    if (p.isEmpty() || p.at(0) != QLatin1Char('\\'))
        return p;
    const QString mapped = volumepath::deviceToWin32Path(p);
    return mapped.isEmpty() ? p : mapped;
}

}

struct EtwProcessEventSource::Impl {
    // provider 必须比 trace 活得久:trace 按引用持有 provider。
    std::unique_ptr<krabs::user_trace> trace;
    std::unique_ptr<krabs::provider<>> provider;
    std::unique_ptr<krabs::provider<>> netProvider;
    std::unique_ptr<krabs::provider<>> dnsProvider;
    std::unique_ptr<krabs::provider<>> regProvider;
    std::unique_ptr<krabs::provider<>> fileProvider;
    std::unique_ptr<krabs::provider<>> auditProvider;
    std::thread                        worker;
    std::atomic<bool>                  running{false};
    QMutex                             mutex;
    QVector<bulwark::SecurityEvent>    queue;
    std::atomic<quint64>               queueDropped{0};
    Logger                             log{QStringLiteral("bulwark.service.Etw")};

    EtwOptions etw;
    quint32    selfPid = 0;

    QHash<quint32, bool> netTrustCache;
    QMutex               netTrustMx;

    bool actorIsTrustedSigned(quint32 pid) {
        {
            QMutexLocker lk(&netTrustMx);
            const auto it = netTrustCache.constFind(pid);
            if (it != netTrustCache.constEnd())
                return it.value();
        }
        const QString path = monitoring::ProcessInspector::tryGetProcessImagePath(static_cast<int>(pid));
        const bool trusted = !path.isEmpty() && monitoring::ProcessInspector::isSigned(path);
        {
            QMutexLocker lk(&netTrustMx);
            if (netTrustCache.size() > 4096)
                netTrustCache.clear();
            netTrustCache.insert(pid, trusted);
        }
        return trusted;
    }
    EmitGate   netGate;
    EmitGate   dnsGate;
    EmitGate   regGate;
    EmitGate   fileGate;
    EmitGate   imageGate;
    EmitGate   threadGate;
    EmitGate   killGate;
    // 新进程 -> 真正的创建者,用来认出「父进程收尾自己的子进程」。
    QHash<quint32, quint32> procParent;
    bool        killSchemaWarned = false;
    QStringList regWatch_;
    QStringList fileWatch_;
    QHash<quint64, QString> regKeyNames_;

    QHash<quint32, qint64> procBirthMs;
    qint64 sessionStartMs = 0;
    int    minTargetAgeMs = 500;

    QHash<quint32, QString> pidPathCache;

    bool        attribEnabled = false;
    int         attribPathMax = 256;
    QSet<QString> attribPaths_;
    QHash<QString, QString> attribCorrelationIds_;
    QMutex        attribMx_;
    QHash<quint64, QString> fileObjPath_;

    void addAttributionPath(const QString& path, const QString& correlationId) {
        const QString normalized = path.trimmed().toLower();
        if (normalized.isEmpty())
            return;
        QMutexLocker lk(&attribMx_);
        if (!attribPaths_.contains(normalized) && attribPaths_.size() >= attribPathMax)
            return;
        attribPaths_.insert(normalized);
        if (!correlationId.trimmed().isEmpty())
            attribCorrelationIds_.insert(normalized, correlationId.trimmed());
        else
            attribCorrelationIds_.remove(normalized);
    }

    bool isAttributionPath(const QString& lowerPath) {
        QMutexLocker lk(&attribMx_);
        return attribPaths_.contains(lowerPath);
    }

    QString attributionCorrelationId(const QString& lowerPath) {
        QMutexLocker lk(&attribMx_);
        return attribCorrelationIds_.value(lowerPath);
    }

    bool hasAttributionPaths() {
        QMutexLocker lk(&attribMx_);
        return !attribPaths_.isEmpty();
    }

    QHash<QString, qint64> attribLastHitMs_;

    void noteAttributionHit(const QString& lowerPath) {
        QMutexLocker lk(&attribMx_);
        attribLastHitMs_.insert(lowerPath, static_cast<qint64>(::GetTickCount64()));
    }

    bool attributedRecently(const QString& lowerPath, qint64 windowMs) {
        QMutexLocker lk(&attribMx_);
        const auto it = attribLastHitMs_.constFind(lowerPath);
        return it != attribLastHitMs_.constEnd()
            && static_cast<qint64>(::GetTickCount64()) - it.value() <= windowMs;
    }

    qint64  statsLastLogMs = 0;
    quint32 statsLastLost = 0;
    quint32 statsLastBuffersLost = 0;
    static constexpr qint64 kStatsIntervalMs = 5LL * 60 * 1000;

    void logSessionStats(bool finalLine) {
        if (!trace)
            return;
        try {
            const krabs::trace_stats st = trace->query_stats();
            const quint32 lost = st.eventsLost;
            const quint32 bufLost = st.buffersLost;
            const bool grew = lost > statsLastLost || bufLost > statsLastBuffersLost;
            const QString line =
                QStringLiteral("ETW 会话统计%1:已处理 %2 条,丢失 %3 条(较上次 +%4),"
                               "实时缓冲区丢失 %5 个(较上次 +%6)")
                    .arg(finalLine ? QStringLiteral("(停止前最后一次)") : QString())
                    .arg(static_cast<qulonglong>(st.eventsHandled))
                    .arg(lost).arg(lost - qMin(lost, statsLastLost))
                    .arg(bufLost).arg(bufLost - qMin(bufLost, statsLastBuffersLost));
            if (grew)
                log.warning(line + QStringLiteral(
                    " —— 会话层面在丢事件,丢的可能包括 Kernel-Process 的进程创建事件(五个提供程序共用"
                    "一个会话)。写入归因(Etw.KernelFileWriteAttribution)是回调量最大的来源,"
                    "确认是它造成的话可置 false 回退。"));
            else
                log.info(line);
            statsLastLost = lost;
            statsLastBuffersLost = bufLost;
        } catch (...) {}
    }

    QString imagePathOf(quint32 pid) {
        const auto it = pidPathCache.constFind(pid);
        if (it != pidPathCache.constEnd())
            return it.value();
        const QString p =
            monitoring::ProcessInspector::tryGetProcessImagePath(static_cast<int>(pid));
        if (pidPathCache.size() > 2048)
            pidPathCache.clear();
        pidPathCache.insert(pid, p);
        return p;
    }

    void notePidBirth(quint32 pid, qint64 nowMs) {
        procBirthMs.insert(pid, nowMs);
        if (procBirthMs.size() <= kProcBirthSoftMax)
            return;
        const qint64 keepMs = std::max<qint64>(minTargetAgeMs * 4, 5000);
        for (auto it = procBirthMs.begin(); it != procBirthMs.end();)
            it = (nowMs - it.value() > keepMs) ? procBirthMs.erase(it) : ++it;
    }

    bool isLikelyInitialThread(quint32 targetPid, qint64 nowMs) const {
        const auto it = procBirthMs.constFind(targetPid);
        if (it != procBirthMs.constEnd())
            return (nowMs - it.value()) < minTargetAgeMs;
        return (nowMs - sessionStartMs) < minTargetAgeMs;
    }

    void onProcessStart(const EVENT_RECORD& record, const krabs::trace_context& ctx) {
        krabs::schema schema(record, ctx.schema_locator);
        krabs::parser parser(schema);
        uint32_t pid = 0, ppid = 0;
        std::wstring image;
        parser.try_parse(L"ProcessID", pid);
        parser.try_parse(L"ParentProcessID", ppid);
        parser.try_parse(L"ImageName", image);
        if (pid > 0) {
            notePidBirth(pid, static_cast<qint64>(::GetTickCount64()));
            pidPathCache.remove(pid);
            QMutexLocker trustLock(&netTrustMx);
            netTrustCache.remove(pid);
        }
        bulwark::SecurityEvent e;
        e.type      = bulwark::EventType::ProcessCreate;
        e.actorPid  = static_cast<int>(pid);
        e.parentPid = static_cast<int>(ppid);
        // 进程启动事件由创建者的线程发出,事件头里的 PID 就是真正调用 CreateProcess 的进程;
        // 载荷里的 ParentProcessID 可以被调用方随意指定。
        const uint32_t creator = record.EventHeader.ProcessId;
        if (creator > 4 && creator != ppid && creator != pid)
            e.creatorPid = static_cast<int>(creator);
        if (pid > 0) {
            if (procParent.size() >= kProcParentMax)
                procParent.clear();
            procParent.insert(pid, creator > 4 ? creator : ppid);
        }
        e.actorPath = deviceToDrive(QString::fromWCharArray(image.c_str()));
        if (pid > 0 && !e.actorPath.isEmpty())
            pidPathCache.insert(pid, e.actorPath);
        e.target    = e.actorPath;
        if (const auto instance = monitoring::ProcessInspector::tryGetProcessInstance(e.actorPid))
            e.actorCreationFileTime = instance->creationFileTime;
        e.userModeObserved = true;
        enqueue(std::move(e));
    }

    void onImageLoad(const EVENT_RECORD& record, const krabs::trace_context& ctx) {
        krabs::schema schema(record, ctx.schema_locator);
        krabs::parser parser(schema);
        uint32_t host = 0;
        std::wstring image;
        if (!parser.try_parse(L"ProcessID", host) || host == 0)
            host = record.EventHeader.ProcessId;
        if (host == 0 || host == selfPid)
            return;
        if (!parser.try_parse(L"ImageName", image) || image.empty())
            return;
        const QString path = deviceToDrive(QString::fromWCharArray(image.c_str()));
        if (!isSuspectModulePath(path))
            return;
        if (!imageGate.allow(host, path, static_cast<qint64>(::GetTickCount64())))
            return;
        bulwark::SecurityEvent e;
        e.type     = bulwark::EventType::ImageLoad;
        e.actorPid = static_cast<int>(host);
        e.actorPath = QStringLiteral("PID %1").arg(e.actorPid);
        e.target    = path;
        e.userModeObserved = true;
        e.detail = QStringLiteral("用户态观测 · 加载模块 %1").arg(QFileInfo(path).fileName());
        enqueue(std::move(e));
    }

    void onThreadStart(const EVENT_RECORD& record, const krabs::trace_context& ctx) {
        const quint32 creator = record.EventHeader.ProcessId;
        // System(4)与 Idle(0)建的线程是内核线程,不是用户态注入,而且数量很多,必须排除。
        if (creator <= 4 || creator == selfPid)
            return;
        krabs::schema schema(record, ctx.schema_locator);
        krabs::parser parser(schema);
        uint32_t owner = 0, tid = 0;
        if (!parser.try_parse(L"ProcessID", owner) || owner <= 4)
            return;
        if (owner == creator)
            return;
        const qint64 nowMs = static_cast<qint64>(::GetTickCount64());
        if (isLikelyInitialThread(owner, nowMs))
            return;
        const QString creatorPath = imagePathOf(creator);
        if (isOsThreadInjector(creatorPath))
            return;
        parser.try_parse(L"ThreadID", tid);
        const QString victimPath =
            monitoring::ProcessInspector::tryGetProcessImagePath(static_cast<int>(owner));
        const QString target = victimPath.isEmpty()
            ? QStringLiteral("PID %1").arg(owner)
            : victimPath;
        if (!threadGate.allow(creator, target, nowMs))
            return;
        bulwark::SecurityEvent e;
        e.type     = bulwark::EventType::RemoteThread;
        e.actorPid = static_cast<int>(creator);
        e.actorPath = creatorPath.isEmpty() ? QStringLiteral("PID %1").arg(e.actorPid)
                                           : creatorPath;
        e.target    = target;
        e.parentPid  = static_cast<int>(owner);
        e.parentPath = victimPath;
        e.userModeObserved = true;
        e.detail = QStringLiteral("用户态观测 · 跨进程线程注入 -> %1(PID %2,TID %3)")
                       .arg(QFileInfo(target).fileName()).arg(owner).arg(tid);
        enqueue(std::move(e));
    }

    void onTerminateProcess(const EVENT_RECORD& record, const krabs::trace_context& ctx) {
        const quint32 caller = record.EventHeader.ProcessId;
        if (caller <= 4 || caller == selfPid)
            return;
        krabs::schema schema(record, ctx.schema_locator);
        krabs::parser parser(schema);
        // 载荷(实机核对):TargetProcessId / ReturnCode 都是 UInt32,另有 TargetProcessStartKey(UInt64)。
        // krabs 的 try_parse 类型对不上(含有无符号)会直接抛异常而不是返回 false,类型不能写错。
        uint32_t victim = 0;
        if (!parser.try_parse(L"TargetProcessId", victim)) {
            if (!killSchemaWarned) {
                killSchemaWarned = true;
                log.warning(QStringLiteral("ETW 审计 API:TerminateProcess 事件里没有 TargetProcessId 字段,"
                                           "「结束进程」类规则将收不到事件。"));
            }
            return;
        }
        if (victim <= 4 || victim == caller)
            return;
        uint32_t rc = 0;
        if (parser.try_parse(L"ReturnCode", rc) && rc != 0)
            return;
        // 父进程收尾自己拉起的子进程(浏览器回收渲染进程、构建工具回收编译进程)是最常见的正常情形。
        const auto parentIt = procParent.constFind(victim);
        const quint32 parent = parentIt != procParent.constEnd()
            ? parentIt.value()
            : static_cast<quint32>(
                  monitoring::ProcessInspector::tryGetParentPid(static_cast<int>(victim)));
        if (parent == caller)
            return;
        const QString victimPath =
            monitoring::ProcessInspector::tryGetProcessImagePath(static_cast<int>(victim));
        const QString target = victimPath.isEmpty() ? QStringLiteral("PID %1").arg(victim) : victimPath;
        if (!killGate.allow(caller, target, static_cast<qint64>(::GetTickCount64())))
            return;
        bulwark::SecurityEvent e;
        e.type     = bulwark::EventType::ProcessTerminate;
        e.actorPid = static_cast<int>(caller);
        e.actorPath = imagePathOf(caller);
        e.target    = target;
        e.parentPid  = static_cast<int>(victim);
        e.parentPath = victimPath;
        e.userModeObserved = true;
        e.detail = QStringLiteral("用户态观测 · 结束进程 %1(PID %2)")
                       .arg(QFileInfo(target).fileName()).arg(victim);
        enqueue(std::move(e));
    }

    int queueCap = kQueueMax;

    void enqueue(bulwark::SecurityEvent&& e) {
        if (e.actorPid > 4 && !e.actorCreationFileTime.has_value()) {
            if (const auto instance = monitoring::ProcessInspector::tryGetProcessInstance(e.actorPid)) {
                e.actorCreationFileTime = instance->creationFileTime;
                if (e.actorPath.isEmpty()
                    || e.actorPath.startsWith(QLatin1String("PID "), Qt::CaseInsensitive))
                    e.actorPath = instance->imagePath;
            }
        }
        {
            QMutexLocker lock(&mutex);
            if (queue.size() < queueCap) {
                queue.push_back(std::move(e));
                return;
            }
        }
        const quint64 dropped = queueDropped.fetch_add(1, std::memory_order_relaxed) + 1;
        if (dropped == 1 || (dropped % 1024) == 0) {
            log.warning(QStringLiteral("ETW 应用队列已满(%1),累计丢弃 %2 条事件")
                            .arg(queueCap).arg(dropped));
        }
    }
};

EtwProcessEventSource::EtwProcessEventSource(const EtwOptions& etw, QObject* parent)
    : EventSource(parent), d_(std::make_unique<Impl>()) {
    d_->etw = etw;
    d_->selfPid = static_cast<quint32>(::GetCurrentProcessId());
    const qint64 dedupMs = static_cast<qint64>(std::max(0, etw.DedupWindowSeconds)) * 1000;
    d_->netGate.perMinCap     = etw.PerProcessNetPerMinute;
    d_->netGate.dedupWindowMs = dedupMs;
    d_->queueCap = (etw.RawChannelCapacity > 0)
                       ? std::clamp(etw.RawChannelCapacity, 256, 65536)
                       : kQueueMax;
    d_->dnsGate.perMinCap     = etw.PerProcessDnsPerMinute;
    d_->dnsGate.dedupWindowMs = dedupMs;
    d_->regGate.perMinCap     = etw.PerProcessRegPerMinute;
    d_->regGate.dedupWindowMs = dedupMs;
    d_->fileGate.perMinCap     = etw.PerProcessFilePerMinute;
    d_->fileGate.dedupWindowMs = dedupMs;
    d_->imageGate.perMinCap     = etw.PerProcessImagePerMinute;
    d_->imageGate.dedupWindowMs = dedupMs;
    d_->threadGate.perMinCap     = etw.PerProcessThreadPerMinute;
    d_->threadGate.dedupWindowMs = 0;
    d_->minTargetAgeMs = std::clamp(etw.RemoteThreadMinTargetAgeMs, 50, 10000);
    d_->attribEnabled = etw.Enabled && etw.KernelFile && etw.KernelFileWriteAttribution;
    d_->attribPathMax = std::clamp(etw.AttributionPathMax, 1, 4096);

    drainTimer_ = new QTimer(this);
    drainTimer_->setInterval(kDefaultDrainMs);
    connect(drainTimer_, &QTimer::timeout, this, &EtwProcessEventSource::drain);
}

EtwProcessEventSource::~EtwProcessEventSource() { stop(); }

void EtwProcessEventSource::setDrainIntervalMs(int ms) {
    if (drainTimer_)
        drainTimer_->setInterval(qBound(1, ms, 1000));
}

void EtwProcessEventSource::setWatchLists(const QStringList& registryKeys, const QStringList& filePaths) {
    d_->regWatch_ = registryKeys;
    d_->fileWatch_ = filePaths;
}

void EtwProcessEventSource::addAttributionPath(const QString& path, const QString& correlationId) {
    d_->addAttributionPath(path, correlationId);
}

bool EtwProcessEventSource::writeAttributionEnabled() const {
    return d_->attribEnabled;
}

void EtwProcessEventSource::start() {
    if (d_->running.load()) return;

    if (d_->worker.joinable())
        d_->worker.join();
    d_->provider.reset();
    d_->netProvider.reset();
    d_->dnsProvider.reset();
    d_->regProvider.reset();
    d_->fileProvider.reset();
    d_->auditProvider.reset();
    d_->trace.reset();

    Impl* impl = d_.get();
    bool netOn = false, dnsOn = false, regOn = false, fileOn = false;
    bool imageOn = false, threadOn = false, auditOn = false;
    try {
        const std::wstring sessionName = impl->etw.SessionName.isEmpty()
            ? std::wstring(L"Bulwark-ETW")
            : impl->etw.SessionName.toStdWString();
        impl->trace = std::make_unique<krabs::user_trace>(sessionName);

        impl->sessionStartMs = static_cast<qint64>(::GetTickCount64());
        ULONGLONG kpMask = kKeywordProcess;
        if (impl->etw.Enabled && impl->etw.KernelImageLoad)    kpMask |= kKeywordImage;
        if (impl->etw.Enabled && impl->etw.KernelRemoteThread) kpMask |= kKeywordThread;
        imageOn  = (kpMask & kKeywordImage)  != 0;
        threadOn = (kpMask & kKeywordThread) != 0;
        impl->provider = std::make_unique<krabs::provider<>>(krabs::guid(kKernelProcessGuid));
        impl->provider->any(kpMask);
        impl->provider->add_on_event_callback(
            [impl](const EVENT_RECORD& record, const krabs::trace_context& ctx) {
                try {
                    switch (record.EventHeader.EventDescriptor.Id) {
                        case kProcessStartEventId: impl->onProcessStart(record, ctx); break;
                        case kImageLoadEventId:    impl->onImageLoad(record, ctx);    break;
                        case kThreadStartEventId:  impl->onThreadStart(record, ctx);  break;
                        default: break;
                    }
                } catch (...) {
                }
            });
        impl->trace->enable(*impl->provider);

        if (impl->etw.Enabled && impl->etw.KernelNetwork) {
            impl->netProvider = std::make_unique<krabs::provider<>>(krabs::guid(kKernelNetworkGuid));
            impl->netProvider->add_on_event_callback(
                [impl](const EVENT_RECORD& record, const krabs::trace_context& ctx) {
                    try {
                        if (record.EventHeader.EventDescriptor.Id != kNetConnectEventId)
                            return;
                        krabs::schema schema(record, ctx.schema_locator);
                        krabs::parser parser(schema);
                        uint32_t pid = 0, daddr = 0;
                        uint16_t dport = 0;
                        parser.try_parse(L"PID", pid);
                        if (!parser.try_parse(L"daddr", daddr) || daddr == 0)
                            return;
                        parser.try_parse(L"dport", dport);
                        if (pid == 0 || pid == impl->selfPid)
                            return;
                        const QString target = ipv4ToString(daddr) + QLatin1Char(':')
                            + QString::number(netToHostPort(dport));
                        if (!impl->netGate.allow(pid, target, static_cast<qint64>(::GetTickCount64())))
                            return;
                        if (impl->etw.NetworkUntrustedOnly && impl->actorIsTrustedSigned(pid))
                            return;
                        bulwark::SecurityEvent e;
                        e.type     = bulwark::EventType::NetworkConnect;
                        e.actorPid = static_cast<int>(pid);
                        e.target   = target;
                        e.userModeObserved = true;
                        impl->enqueue(std::move(e));
                    } catch (...) {}
                });
            impl->trace->enable(*impl->netProvider);
            netOn = true;
        }

        if (impl->etw.Enabled && impl->etw.DnsClient) {
            impl->dnsProvider = std::make_unique<krabs::provider<>>(krabs::guid(kDnsClientGuid));
            impl->dnsProvider->add_on_event_callback(
                [impl](const EVENT_RECORD& record, const krabs::trace_context& ctx) {
                    try {
                        if (record.EventHeader.EventDescriptor.Id != kDnsQueryEventId)
                            return;
                        krabs::schema schema(record, ctx.schema_locator);
                        krabs::parser parser(schema);
                        std::wstring qname;
                        parser.try_parse(L"QueryName", qname);
                        const uint32_t pid = record.EventHeader.ProcessId;
                        if (pid == 0 || pid == impl->selfPid)
                            return;
                        QString domain = QString::fromWCharArray(qname.c_str()).trimmed();
                        while (domain.endsWith(QLatin1Char('.'))) domain.chop(1);
                        if (domain.isEmpty())
                            return;
                        if (impl->etw.SuspiciousOnly
                            && bulwark::engine::DgaDomainAnalyzer::analyze(domain).score <= 0)
                            return;
                        if (!impl->dnsGate.allow(pid, domain, static_cast<qint64>(::GetTickCount64())))
                            return;
                        bulwark::SecurityEvent e;
                        e.type     = bulwark::EventType::DnsQuery;
                        e.actorPid = static_cast<int>(pid);
                        e.target   = domain;
                        e.userModeObserved = true;
                        impl->enqueue(std::move(e));
                    } catch (...) {}
                });
            impl->trace->enable(*impl->dnsProvider);
            dnsOn = true;
        }

        if (impl->etw.Enabled && impl->etw.KernelRegistry && !impl->regWatch_.isEmpty()) {
            impl->regProvider = std::make_unique<krabs::provider<>>(krabs::guid(kKernelRegistryGuid));
            impl->regProvider->any(kKeywordRegistry);
            impl->regProvider->add_on_event_callback(
                [impl](const EVENT_RECORD& record, const krabs::trace_context& ctx) {
                    try {
                        const USHORT id = record.EventHeader.EventDescriptor.Id;
                        const bool isName = (id == kRegCreateKey || id == kRegOpenKey);
                        const bool isWrite = (id == kRegDeleteKey || id == kRegSetValueKey
                                              || id == kRegDeleteValueKey);
                        if (!isName && !isWrite)
                            return;

                        krabs::schema schema(record, ctx.schema_locator);
                        krabs::parser parser(schema);
                        uint64_t keyObject = 0;
                        parser.try_parse(L"KeyObject", keyObject);

                        if (isName) {
                            std::wstring rel;
                            if (keyObject != 0 && parser.try_parse(L"RelativeName", rel) && !rel.empty()) {
                                if (impl->regKeyNames_.size() >= kRegNameCacheMax)
                                    impl->regKeyNames_.clear();
                                impl->regKeyNames_.insert(keyObject, QString::fromWCharArray(rel.c_str()));
                            }
                            return;
                        }

                        QString keyName = impl->regKeyNames_.value(keyObject);
                        if (keyName.isEmpty()) {
                            std::wstring kn;
                            if (parser.try_parse(L"KeyName", kn))
                                keyName = QString::fromWCharArray(kn.c_str());
                        }
                        if (keyName.isEmpty())
                            return;

                        std::wstring valName;
                        if (id == kRegSetValueKey || id == kRegDeleteValueKey)
                            parser.try_parse(L"ValueName", valName);
                        QString target = keyName;
                        if (!valName.empty())
                            target += QLatin1Char('\\') + QString::fromWCharArray(valName.c_str());

                        if (!matchesWatch(target, impl->regWatch_))
                            return;

                        const uint32_t pid = record.EventHeader.ProcessId;
                        if (pid == 0 || pid == impl->selfPid)
                            return;
                        if (!impl->regGate.allow(pid, target, static_cast<qint64>(::GetTickCount64())))
                            return;
                        bulwark::SecurityEvent e;
                        e.type     = bulwark::EventType::RegistryWrite;
                        e.actorPid = static_cast<int>(pid);
                        e.target   = target;
                        e.registryOp = id == kRegSetValueKey
                            ? bulwark::RegistryOperation::SetValue
                            : id == kRegDeleteValueKey
                                  ? bulwark::RegistryOperation::DeleteValue
                                  : bulwark::RegistryOperation::DeleteKey;
                        e.userModeObserved = true;
                        impl->enqueue(std::move(e));
                    } catch (...) {}
                });
            impl->trace->enable(*impl->regProvider);
            regOn = true;
        }

        if (impl->etw.Enabled && impl->etw.KernelFile) {
            impl->fileProvider = std::make_unique<krabs::provider<>>(krabs::guid(kKernelFileGuid));
            ULONGLONG kfMask = kKeywordFile;
            if (impl->attribEnabled)
                kfMask |= kKeywordFileCreate | kKeywordFileWrite;
            impl->fileProvider->any(kfMask);
            impl->fileProvider->add_on_event_callback(
                [impl](const EVENT_RECORD& record, const krabs::trace_context& ctx) {
                    try {
                        const USHORT id = record.EventHeader.EventDescriptor.Id;
                        if (impl->attribEnabled && (id == kFileCreate || id == kFileWrite
                                                    || id == kFileCreateNew)) {
                            krabs::schema sch(record, ctx.schema_locator);
                            krabs::parser par(sch);
                            uint64_t fobj = 0;
                            if (par.try_parse(L"FileObject", fobj) && fobj != 0) {
                                if (id == kFileWrite) {
                                    const auto it = impl->fileObjPath_.constFind(fobj);
                                    if (it != impl->fileObjPath_.constEnd()) {
                                        const uint32_t wpid = record.EventHeader.ProcessId;
                                        // 写入者必须是真实用户态进程:缓存管理器由 System(pid 4)惰性写回时,
                                        // header pid 是 4。这种事件既不可处置,还会误标「已归因」而压掉
                                        // UserModeBehaviorSource 的兜底合成告警,所以 pid<=4 既不归因也不产出事件。
                                        const bool realWriter = wpid > 4 && wpid != impl->selfPid;
                                        if (realWriter)
                                            impl->noteAttributionHit(it.value().toLower());
                                        if (realWriter
                                            && impl->fileGate.allow(
                                                   wpid, it.value(),
                                                   static_cast<qint64>(::GetTickCount64()))) {
                                            bulwark::SecurityEvent e;
                                            e.type     = bulwark::EventType::FileWrite;
                                            e.actorPid = static_cast<int>(wpid);
                                            e.target   = it.value();
                                            e.correlationId = impl->attributionCorrelationId(
                                                it.value().toLower());
                                            e.userModeObserved = true;
                                            e.detail = QStringLiteral("用户态观测 · 改写受监视文件 %1")
                                                           .arg(QFileInfo(it.value()).fileName());
                                            impl->enqueue(std::move(e));
                                        }
                                    }
                                    return;
                                }
                                impl->fileObjPath_.remove(fobj);
                                std::wstring cname;
                                if (par.try_parse(L"FileName", cname) && !cname.empty()) {
                                    const QString cpath =
                                        deviceToDrive(QString::fromWCharArray(cname.c_str()));
                                    if (impl->isAttributionPath(cpath.toLower())) {
                                        if (impl->fileObjPath_.size() >= kFileObjMapMax)
                                            impl->fileObjPath_.clear();
                                        impl->fileObjPath_.insert(fobj, cpath);
                                    }
                                }
                            }
                            if (id == kFileCreate)
                                return;
                        }

                        if (id != kFileCreateNew && id != kFileDeletePath)
                            return;
                        krabs::schema schema(record, ctx.schema_locator);
                        krabs::parser parser(schema);

                        QString path;
                        bulwark::EventType type;
                        if (id == kFileCreateNew) {
                            std::wstring fname;
                            if (!parser.try_parse(L"FileName", fname) || fname.empty())
                                return;
                            path = deviceToDrive(QString::fromWCharArray(fname.c_str()));
                            type = bulwark::EventType::FileWrite;
                        } else {
                            std::wstring fpath;
                            if (!parser.try_parse(L"FilePath", fpath) || fpath.empty())
                                return;
                            path = deviceToDrive(QString::fromWCharArray(fpath.c_str()));
                            type = bulwark::EventType::FileDelete;
                        }
                        const bool canaryDelete = impl->attribEnabled && id == kFileDeletePath
                                                  && impl->isAttributionPath(path.toLower());
                        if (!matchesWatch(path, impl->fileWatch_)
                            && !(id == kFileCreateNew && isDroppedExecutable(path))
                            && !canaryDelete)
                            return;

                        const uint32_t pid = record.EventHeader.ProcessId;
                        if (pid == 0 || pid == impl->selfPid)
                            return;
                        if (canaryDelete)
                            impl->noteAttributionHit(path.toLower());
                        if (!impl->fileGate.allow(pid, path, static_cast<qint64>(::GetTickCount64())))
                            return;
                        bulwark::SecurityEvent e;
                        e.type     = type;
                        e.actorPid = static_cast<int>(pid);
                        e.target   = path;
                        if (canaryDelete)
                            e.correlationId = impl->attributionCorrelationId(path.toLower());
                        e.fileCreatedNew = (id == kFileCreateNew);
                        e.userModeObserved = true;
                        impl->enqueue(std::move(e));
                    } catch (...) {}
                });
            impl->trace->enable(*impl->fileProvider);
            fileOn = true;
        }

        if (impl->etw.Enabled && impl->etw.KernelAuditApi) {
            impl->auditProvider = std::make_unique<krabs::provider<>>(krabs::guid(kAuditApiGuid));
            impl->auditProvider->any(0xFFFFFFFFFFFFFFFFULL);
            krabs::event_filter killFilter(kAuditTerminateProcessId);
            killFilter.add_on_event_callback(
                [impl](const EVENT_RECORD& record, const krabs::trace_context& ctx) {
                    try {
                        if (record.EventHeader.EventDescriptor.Id == kAuditTerminateProcessId)
                            impl->onTerminateProcess(record, ctx);
                    } catch (...) {}
                });
            impl->auditProvider->add_filter(killFilter);
            impl->trace->enable(*impl->auditProvider);
            auditOn = true;
        }

        impl->trace->open();
    } catch (const std::exception& ex) {
        available_ = false;
        impl->trace.reset();
        impl->provider.reset();
        impl->netProvider.reset();
        impl->dnsProvider.reset();
        impl->regProvider.reset();
        impl->fileProvider.reset();
        impl->auditProvider.reset();
        impl->log.warning(
            QStringLiteral("ETW 会话启动失败(需要以管理员身份运行?):%1")
                .arg(QString::fromUtf8(ex.what())));
        return;
    }

    available_ = true;
    impl->running.store(true);
    impl->worker = std::thread([impl] {
        try {
            impl->trace->process();
        } catch (const std::exception& ex) {
            impl->log.warning(
                QStringLiteral("ETW 处理线程结束:%1").arg(QString::fromUtf8(ex.what())));
        }
        impl->running.store(false);
    });
    drainTimer_->start();
    QStringList active{ QStringLiteral("Kernel-Process") };
    if (imageOn) active << QStringLiteral("ImageLoad(模块加载)");
    if (threadOn) active << QStringLiteral("ThreadStart(跨进程注入)");
    if (netOn) active << QStringLiteral("Kernel-Network");
    if (dnsOn) active << QStringLiteral("DNS-Client");
    if (regOn) active << QStringLiteral("Kernel-Registry");
    if (fileOn) active << QStringLiteral("Kernel-File");
    if (fileOn && impl->attribEnabled)
        active << QStringLiteral("FileWrite归因(诱饵可定位写入者)");
    if (auditOn) active << QStringLiteral("Kernel-Audit-API(结束进程)");
    impl->log.info(QStringLiteral("ETW 实时会话已启动(%1)。").arg(active.join(QStringLiteral(", "))));
}

void EtwProcessEventSource::stop() {
    if (drainTimer_) drainTimer_->stop();
    if (d_->running.load() && d_->attribEnabled)
        d_->logSessionStats(true);
    d_->running.store(false);
    if (d_->trace) {
        try { d_->trace->stop(); } catch (...) {}
    }
    if (d_->worker.joinable())
        d_->worker.join();
    d_->provider.reset();
    d_->netProvider.reset();
    d_->dnsProvider.reset();
    d_->regProvider.reset();
    d_->fileProvider.reset();
    d_->auditProvider.reset();
    d_->trace.reset();
    available_ = false;
}

bool EtwProcessEventSource::isAvailable() const {
    return available_ && d_->running.load(std::memory_order_relaxed);
}

bool EtwProcessEventSource::wasAttributedRecently(const QString& pathLower, qint64 windowMs) const {
    return d_->attributedRecently(pathLower, windowMs);
}

void EtwProcessEventSource::drain() {
    if (available_ && !d_->running.load(std::memory_order_relaxed)) {
        available_ = false;
        d_->log.warning(QStringLiteral("ETW 处理线程已意外结束,状态已降级;1 秒后尝试重建会话。"));
        if (d_->worker.joinable())
            d_->worker.join();
        d_->provider.reset();
        d_->netProvider.reset();
        d_->dnsProvider.reset();
        d_->regProvider.reset();
        d_->fileProvider.reset();
        d_->auditProvider.reset();
        d_->trace.reset();
        QTimer::singleShot(1000, this, [this] {
            if (drainTimer_ && drainTimer_->isActive() && !d_->running.load())
                start();
        });
    }

    if (d_->attribEnabled && d_->running.load(std::memory_order_relaxed)) {
        const qint64 nowMs = static_cast<qint64>(::GetTickCount64());
        if (d_->statsLastLogMs == 0) {
            d_->statsLastLogMs = nowMs;
        } else if (nowMs - d_->statsLastLogMs >= Impl::kStatsIntervalMs) {
            d_->statsLastLogMs = nowMs;
            d_->logSessionStats(false);
        }
    }

    QVector<bulwark::SecurityEvent> batch;
    {
        QMutexLocker lock(&d_->mutex);
        if (d_->queue.isEmpty()) return;
        batch.swap(d_->queue);
    }
    for (const auto& e : batch)
        emit eventProduced(e);
}

}
