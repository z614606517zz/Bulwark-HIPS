#include "bulwark/service/monitoring/ProcessOriginResolver.h"
#include "bulwark/service/monitoring/ProcessInspector.h"

#include <QDateTime>
#include <QDir>
#include <QDirIterator>
#include <QFile>
#include <QFileInfo>
#include <QHash>
#include <QMutex>
#include <QMutexLocker>
#include <QRegularExpression>
#include <QSet>

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <winsvc.h>
#include <oleauto.h>
#include <taskschd.h>

#include <algorithm>
#include <vector>

using namespace bulwark::service::monitoring;

namespace {

QString u(const char* s) { return QString::fromUtf8(s); }

const wchar_t* wcstr(const QString& s)
{
    return reinterpret_cast<const wchar_t*>(s.utf16());
}

QString fromWide(const wchar_t* w)
{
    return w ? QString::fromWCharArray(w) : QString();
}

qint64 nowMs() { return QDateTime::currentMSecsSinceEpoch(); }

QString lowerFileName(const QString& path)
{
    return QFileInfo(path).fileName().toLower();
}

QString expandEnv(const QString& raw)
{
    if (raw.isEmpty() || !raw.contains(QLatin1Char('%')))
        return raw;
    wchar_t buf[1024];
    const DWORD n = ExpandEnvironmentStringsW(wcstr(raw), buf, 1024);
    if (n == 0 || n > 1024)
        return raw;
    return QString::fromWCharArray(buf);
}

QString extractImagePath(const QString& commandLine)
{
    QString s = commandLine.trimmed();
    if (s.isEmpty())
        return QString();
    if (s.startsWith(QLatin1Char('"'))) {
        const int end = s.indexOf(QLatin1Char('"'), 1);
        if (end > 1)
            return expandEnv(s.mid(1, end - 1));
    }
    if (s.startsWith(QLatin1String("\\??\\")))
        s = s.mid(4);
    const int exeAt = s.indexOf(QLatin1String(".exe"), 0, Qt::CaseInsensitive);
    if (exeAt > 0)
        return expandEnv(s.left(exeAt + 4));
    const int sp = s.indexOf(QLatin1Char(' '));
    return expandEnv(sp > 0 ? s.left(sp) : s);
}

QString svchostGroup(const QString& commandLine)
{
    if (commandLine.isEmpty())
        return QString();
    static const QRegularExpression re(QStringLiteral("-k\\s+([A-Za-z0-9_.-]+)"),
                                       QRegularExpression::CaseInsensitiveOption);
    const auto m = re.match(commandLine);
    return m.hasMatch() ? m.captured(1) : QString();
}

struct ServiceRec {
    QString name;
    QString displayName;
};

struct ScmSnapshot {
    QHash<int, QList<ServiceRec>> byPid;
    qint64 builtAtMs = 0;
};

QMutex g_scmMx;
ScmSnapshot g_scm;
qint64 g_scmLastForcedMs = 0;
constexpr qint64 kScmTtlMs = 3000;
constexpr qint64 kScmForceThrottleMs = 250;

ScmSnapshot buildScmSnapshot()
{
    ScmSnapshot snap;
    snap.builtAtMs = nowMs();

    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ENUMERATE_SERVICE);
    if (!scm)
        return snap;

    DWORD needed = 0, returned = 0, resume = 0;
    EnumServicesStatusExW(scm, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_ACTIVE,
                          nullptr, 0, &needed, &returned, &resume, nullptr);
    if (needed == 0) {
        CloseServiceHandle(scm);
        return snap;
    }
    std::vector<BYTE> buf(needed + 64, 0);
    resume = 0;
    if (EnumServicesStatusExW(scm, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_ACTIVE,
                              buf.data(), static_cast<DWORD>(buf.size()), &needed, &returned,
                              &resume, nullptr)) {
        auto* arr = reinterpret_cast<ENUM_SERVICE_STATUS_PROCESSW*>(buf.data());
        for (DWORD i = 0; i < returned; ++i) {
            const DWORD pid = arr[i].ServiceStatusProcess.dwProcessId;
            if (pid == 0)
                continue;
            ServiceRec rec;
            rec.name = fromWide(arr[i].lpServiceName);
            rec.displayName = fromWide(arr[i].lpDisplayName);
            if (rec.name.isEmpty())
                continue;
            snap.byPid[static_cast<int>(pid)].append(rec);
        }
    }
    CloseServiceHandle(scm);
    return snap;
}

QList<ServiceRec> scmServicesFor(int pid, bool force)
{
    QMutexLocker lk(&g_scmMx);
    const qint64 t = nowMs();
    bool rebuild = (g_scm.builtAtMs == 0) || (t - g_scm.builtAtMs > kScmTtlMs);
    if (!rebuild && force && !g_scm.byPid.contains(pid)
        && (t - g_scmLastForcedMs > kScmForceThrottleMs)) {
        rebuild = true;
        g_scmLastForcedMs = t;
    }
    if (rebuild) {
        lk.unlock();
        ScmSnapshot fresh = buildScmSnapshot();
        lk.relock();
        if (!fresh.byPid.isEmpty() || g_scm.builtAtMs == 0)
            g_scm = std::move(fresh);
        else
            g_scm.builtAtMs = t;
    }
    return g_scm.byPid.value(pid);
}

struct ServiceRegIndex {
    QHash<QString, QList<ServiceRec>> byImageName;
    QHash<QString, QList<ServiceRec>> byGroup;
    qint64 builtAtMs = 0;
};

QMutex g_regMx;
ServiceRegIndex g_reg;
constexpr qint64 kRegTtlMs = 5 * 60 * 1000;

ServiceRegIndex buildServiceRegIndex()
{
    ServiceRegIndex idx;
    idx.builtAtMs = nowMs();

    HKEY root = nullptr;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services", 0,
                      KEY_READ | KEY_WOW64_64KEY, &root) != ERROR_SUCCESS)
        return idx;

    for (DWORD i = 0;; ++i) {
        wchar_t nameBuf[256];
        DWORD nameLen = 256;
        if (RegEnumKeyExW(root, i, nameBuf, &nameLen, nullptr, nullptr, nullptr, nullptr)
            != ERROR_SUCCESS)
            break;
        const QString svcName = QString::fromWCharArray(nameBuf, static_cast<int>(nameLen));

        HKEY sub = nullptr;
        if (RegOpenKeyExW(root, nameBuf, 0, KEY_READ | KEY_WOW64_64KEY, &sub) != ERROR_SUCCESS)
            continue;

        auto readStr = [&sub](const wchar_t* value) -> QString {
            DWORD type = 0, cb = 0;
            if (RegQueryValueExW(sub, value, nullptr, &type, nullptr, &cb) != ERROR_SUCCESS || cb == 0)
                return QString();
            if (type != REG_SZ && type != REG_EXPAND_SZ)
                return QString();
            std::vector<BYTE> data(cb + sizeof(wchar_t), 0);
            if (RegQueryValueExW(sub, value, nullptr, &type, data.data(), &cb) != ERROR_SUCCESS)
                return QString();
            return QString::fromWCharArray(reinterpret_cast<const wchar_t*>(data.data()));
        };

        const QString imagePath = readStr(L"ImagePath");
        if (!imagePath.trimmed().isEmpty()) {
            ServiceRec rec;
            rec.name = svcName;
            rec.displayName = readStr(L"DisplayName");
            const QString exe = extractImagePath(imagePath);
            const QString key = lowerFileName(exe);
            if (!key.isEmpty())
                idx.byImageName[key].append(rec);
            const QString group = svchostGroup(imagePath);
            if (!group.isEmpty())
                idx.byGroup[group.toLower()].append(rec);
        }
        RegCloseKey(sub);
    }
    RegCloseKey(root);
    return idx;
}

ServiceRegIndex regIndex()
{
    QMutexLocker lk(&g_regMx);
    const qint64 t = nowMs();
    if (g_reg.builtAtMs == 0 || t - g_reg.builtAtMs > kRegTtlMs) {
        lk.unlock();
        ServiceRegIndex fresh = buildServiceRegIndex();
        lk.relock();
        if (!fresh.byImageName.isEmpty() || g_reg.builtAtMs == 0)
            g_reg = fresh;
        else
            g_reg.builtAtMs = t;
    }
    return g_reg;
}

struct RunningTaskSnapshot {
    QHash<int, QString> pathByPid;
    qint64 builtAtMs = 0;
    bool comUsable = true;
};

QMutex g_taskMx;
RunningTaskSnapshot g_runningTasks;
constexpr qint64 kRunningTaskTtlMs = 1500;

bool ensureCom()
{
    thread_local int state = 0;
    if (state != 0)
        return state == 1;
    const HRESULT hr = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    state = (SUCCEEDED(hr) || hr == RPC_E_CHANGED_MODE) ? 1 : 2;
    return state == 1;
}

RunningTaskSnapshot buildRunningTaskSnapshot()
{
    RunningTaskSnapshot snap;
    snap.builtAtMs = nowMs();
    if (!ProcessOriginResolver::taskComEnabled || !ensureCom()) {
        snap.comUsable = false;
        return snap;
    }

    ITaskService* svc = nullptr;
    HRESULT hr = CoCreateInstance(__uuidof(TaskScheduler), nullptr, CLSCTX_INPROC_SERVER,
                                  __uuidof(ITaskService), reinterpret_cast<void**>(&svc));
    if (FAILED(hr) || !svc) {
        snap.comUsable = false;
        return snap;
    }

    VARIANT empty;
    VariantInit(&empty);
    hr = svc->Connect(empty, empty, empty, empty);
    if (FAILED(hr)) {
        svc->Release();
        snap.comUsable = false;
        return snap;
    }

    IRunningTaskCollection* tasks = nullptr;
    hr = svc->GetRunningTasks(TASK_ENUM_HIDDEN, &tasks);
    if (SUCCEEDED(hr) && tasks) {
        LONG count = 0;
        tasks->get_Count(&count);
        for (LONG i = 1; i <= count; ++i) {
            IRunningTask* rt = nullptr;
            VARIANT idx;
            VariantInit(&idx);
            idx.vt = VT_I4;
            idx.lVal = i;
            if (FAILED(tasks->get_Item(idx, &rt)) || !rt)
                continue;
            DWORD enginePid = 0;
            BSTR path = nullptr;
            if (SUCCEEDED(rt->get_EnginePID(&enginePid)) && enginePid != 0
                && SUCCEEDED(rt->get_Path(&path)) && path) {
                snap.pathByPid.insert(static_cast<int>(enginePid), QString::fromWCharArray(path));
            }
            if (path)
                SysFreeString(path);
            rt->Release();
        }
        tasks->Release();
    }
    svc->Release();
    return snap;
}

QString runningTaskPathFor(int pid)
{
    QMutexLocker lk(&g_taskMx);
    const qint64 t = nowMs();
    if (g_runningTasks.builtAtMs == 0 || t - g_runningTasks.builtAtMs > kRunningTaskTtlMs) {
        lk.unlock();
        RunningTaskSnapshot fresh = buildRunningTaskSnapshot();
        lk.relock();
        g_runningTasks = fresh;
    }
    return g_runningTasks.pathByPid.value(pid);
}

struct TaskFileIndex {
    QHash<QString, QStringList> byImageName;
    qint64 builtAtMs = 0;
};

QMutex g_taskFileMx;
TaskFileIndex g_taskFiles;
constexpr qint64 kTaskFileTtlMs = 5 * 60 * 1000;
constexpr int kMaxTaskFiles = 4000;

QString between(const QString& s, const QString& a, const QString& b)
{
    const int i = s.indexOf(a, 0, Qt::CaseInsensitive);
    if (i < 0)
        return QString();
    const int from = i + a.size();
    const int j = s.indexOf(b, from, Qt::CaseInsensitive);
    return j < 0 ? QString() : s.mid(from, j - from).trimmed();
}

TaskFileIndex buildTaskFileIndex()
{
    TaskFileIndex idx;
    idx.builtAtMs = nowMs();
    const QString windir = qEnvironmentVariable("SystemRoot", QStringLiteral("C:\\Windows"));
    const QString tasksRoot = windir + QStringLiteral("\\System32\\Tasks");
    if (!QDir(tasksRoot).exists())
        return idx;

    int seen = 0;
    QDirIterator it(tasksRoot, QDir::Files, QDirIterator::Subdirectories);
    while (it.hasNext() && seen < kMaxTaskFiles) {
        const QString file = it.next();
        ++seen;
        QFile f(file);
        if (!f.open(QIODevice::ReadOnly))
            continue;
        const QString xml = QString::fromUtf8(f.read(64 * 1024));
        f.close();
        if (xml.isEmpty() || !xml.contains(QStringLiteral("<Exec")))
            continue;
        const QString cmd = between(xml, QStringLiteral("<Command>"), QStringLiteral("</Command>"));
        if (cmd.trimmed().isEmpty())
            continue;
        QString exe = expandEnv(QString(cmd).trimmed().remove(QLatin1Char('"')));
        const QString key = lowerFileName(exe);
        if (key.isEmpty())
            continue;
        const QString taskPath = QStringLiteral("\\") + QDir(tasksRoot).relativeFilePath(file);
        QStringList& list = idx.byImageName[key];
        if (!list.contains(taskPath))
            list.append(taskPath);
    }
    return idx;
}

QStringList taskCandidatesFor(const QString& imagePath)
{
    const QString key = lowerFileName(imagePath);
    if (key.isEmpty())
        return {};
    QMutexLocker lk(&g_taskFileMx);
    const qint64 t = nowMs();
    if (g_taskFiles.builtAtMs == 0 || t - g_taskFiles.builtAtMs > kTaskFileTtlMs) {
        lk.unlock();
        TaskFileIndex fresh = buildTaskFileIndex();
        lk.relock();
        if (!fresh.byImageName.isEmpty() || g_taskFiles.builtAtMs == 0)
            g_taskFiles = fresh;
        else
            g_taskFiles.builtAtMs = t;
    }
    return g_taskFiles.byImageName.value(key);
}

enum class HostRole {
    Other = 0,
    Scm,
    TaskEngine,
    TaskHost,
    ServiceHost,
    WmiProvider,
    Userinit,
    SystemBoot,
};

HostRole classifyParent(int parentPid, const QString& parentImage)
{
    const QString name = lowerFileName(parentImage);
    if (name == QLatin1String("services.exe"))
        return HostRole::Scm;
    if (name == QLatin1String("taskeng.exe"))
        return HostRole::TaskEngine;
    if (name == QLatin1String("wmiprvse.exe"))
        return HostRole::WmiProvider;
    if (name == QLatin1String("userinit.exe"))
        return HostRole::Userinit;
    if (name == QLatin1String("smss.exe") || name == QLatin1String("wininit.exe")
        || name == QLatin1String("csrss.exe") || name == QLatin1String("winlogon.exe"))
        return HostRole::SystemBoot;
    if (name == QLatin1String("svchost.exe")) {
        for (const ServiceRec& r : scmServicesFor(parentPid, false))
            if (r.name.compare(QLatin1String("Schedule"), Qt::CaseInsensitive) == 0)
                return HostRole::TaskHost;
        return HostRole::ServiceHost;
    }
    return HostRole::Other;
}

QString joinServiceNames(const QList<ServiceRec>& recs)
{
    QStringList names;
    for (const ServiceRec& r : recs)
        names << r.name;
    return names.join(QStringLiteral(", "));
}

struct OriginMemo {
    ProcessOrigin origin;
    qint64 atMs = 0;
};

QMutex g_memoMx;
QHash<QString, OriginMemo> g_memo;
constexpr qint64 kMemoTtlMs = 60 * 1000;
constexpr int kMemoCapacity = 4096;

QString memoKey(int pid, const QString& imagePath)
{
    quint64 creationFileTime = 0;
    if (const auto instance = ProcessInspector::tryGetProcessInstance(pid))
        creationFileTime = instance->creationFileTime;
    return QString::number(pid) + QLatin1Char('|') + QString::number(creationFileTime)
        + QLatin1Char('|') + lowerFileName(imagePath);
}

}

QStringList ProcessOriginResolver::servicesHostedBy(int pid)
{
    QStringList out;
    if (pid <= 4)
        return out;
    for (const ServiceRec& r : scmServicesFor(pid, false))
        out << r.name;
    return out;
}

void ProcessOriginResolver::invalidateCaches()
{
    { QMutexLocker lk(&g_scmMx);      g_scm = ScmSnapshot{}; }
    { QMutexLocker lk(&g_regMx);      g_reg = ServiceRegIndex{}; }
    { QMutexLocker lk(&g_taskMx);     g_runningTasks = RunningTaskSnapshot{}; }
    { QMutexLocker lk(&g_taskFileMx); g_taskFiles = TaskFileIndex{}; }
    { QMutexLocker lk(&g_memoMx);     g_memo.clear(); }
}

void ProcessOriginResolver::invalidateMemo() { QMutexLocker lk(&g_memoMx); g_memo.clear(); }

ProcessOrigin ProcessOriginResolver::resolve(int pid, const QString& imagePathIn, int parentPidIn,
                                            const QString& commandLineIn)
{
    ProcessOrigin origin;
    if (pid <= 4)
        return origin;

    try {
        QString imagePath = imagePathIn;
        if (imagePath.isEmpty() || imagePath.startsWith(QLatin1String("PID "), Qt::CaseInsensitive))
            imagePath = ProcessInspector::tryGetProcessImagePath(pid);

        const QString key = memoKey(pid, imagePath);
        {
            QMutexLocker lk(&g_memoMx);
            auto it = g_memo.constFind(key);
            if (it != g_memo.constEnd() && nowMs() - it.value().atMs < kMemoTtlMs)
                return it.value().origin;
        }
        struct MemoGuard {
            QString key;
            const ProcessOrigin* origin;
            ~MemoGuard() {
                QMutexLocker lk(&g_memoMx);
                if (g_memo.size() >= kMemoCapacity)
                    g_memo.clear();
                g_memo.insert(key, OriginMemo{ *origin, nowMs() });
            }
        } memoGuard{ key, &origin };

        int parentPid = parentPidIn;
        if (parentPid < 0)
            parentPid = ProcessInspector::tryGetParentPid(pid);
        const QString parentImage = parentPid > 0
                                        ? ProcessInspector::tryGetProcessImagePath(parentPid)
                                        : QString();

        const bool freshServiceLikely =
            lowerFileName(parentImage) == QLatin1String("services.exe");
        const QList<ServiceRec> own = scmServicesFor(pid, freshServiceLikely);
        if (!own.isEmpty()) {
            origin.kind = bulwark::ProcessOriginKind::Service;
            origin.serviceName = joinServiceNames(own);
            origin.serviceDisplayName = own.first().displayName;
            origin.highConfidence = true;
            origin.detail = own.size() > 1
                ? u("SCM 权威映射:该进程为共享服务宿主,承载 %1 个服务").arg(own.size())
                : u("SCM 权威映射:该进程即服务 %1 的宿主").arg(own.first().name);
            return origin;
        }

        const HostRole role = classifyParent(parentPid, parentImage);

        switch (role) {
        case HostRole::TaskEngine:
        case HostRole::TaskHost: {
            origin.kind = bulwark::ProcessOriginKind::ScheduledTask;
            const QString exact = runningTaskPathFor(pid);
            if (!exact.isEmpty()) {
                origin.taskPath = exact;
                origin.highConfidence = true;
                origin.detail = u("任务计划程序运行中任务按 EnginePID 精确匹配");
                return origin;
            }
            const QStringList cands = taskCandidatesFor(imagePath);
            if (cands.size() == 1) {
                origin.taskPath = cands.first();
                origin.detail = u("按任务定义中的映像路径反查,唯一命中(中置信)");
            } else if (cands.size() > 1) {
                origin.taskPath = cands.first();
                origin.detail = u("由计划任务启动;按映像路径反查到 %1 个候选任务:%2")
                                    .arg(cands.size())
                                    .arg(cands.mid(0, 4).join(QStringLiteral(" | ")));
            } else {
                origin.detail = (role == HostRole::TaskEngine)
                    ? u("父进程为 taskeng.exe,确定由计划任务启动,但未能确定具体任务")
                    : u("父进程为承载 Schedule 服务的 svchost.exe,确定由计划任务启动,"
                        "但未能确定具体任务");
            }
            return origin;
        }
        case HostRole::Scm: {
            origin.kind = bulwark::ProcessOriginKind::Service;
            const ServiceRegIndex idx = regIndex();
            QList<ServiceRec> cands = idx.byImageName.value(lowerFileName(imagePath));
            const QString group = svchostGroup(commandLineIn);
            if (cands.isEmpty() && !group.isEmpty())
                cands = idx.byGroup.value(group.toLower());
            if (cands.size() == 1) {
                origin.serviceName = cands.first().name;
                origin.serviceDisplayName = cands.first().displayName;
                origin.detail = u("父进程为 services.exe;按服务注册表 ImagePath 反查,唯一命中(中置信)");
            } else if (cands.size() > 1) {
                origin.serviceName = joinServiceNames(cands.mid(0, 6));
                origin.serviceDisplayName = cands.first().displayName;
                origin.detail = u("父进程为 services.exe;按 ImagePath%1 反查到 %2 个候选服务")
                                    .arg(group.isEmpty() ? QString()
                                                         : u(" / 分组 %1").arg(group))
                                    .arg(cands.size());
            } else {
                origin.detail = u("父进程为 services.exe,确定由 SCM 启动,但未能确定具体服务");
            }
            return origin;
        }
        case HostRole::WmiProvider:
            origin.kind = bulwark::ProcessOriginKind::WmiProvider;
            origin.detail = u("父进程为 WMI 提供者宿主 wmiprvse.exe(WMI 远程/本地调用派生)");
            return origin;
        case HostRole::Userinit:
            origin.kind = bulwark::ProcessOriginKind::LogonAutostart;
            origin.detail = u("父进程为 userinit.exe(用户登录初始化链)");
            return origin;
        case HostRole::SystemBoot:
            origin.kind = bulwark::ProcessOriginKind::SystemBoot;
            origin.detail = u("父进程为系统启动组件 %1").arg(lowerFileName(parentImage));
            return origin;
        case HostRole::ServiceHost: {
            const QList<ServiceRec> hosted = scmServicesFor(parentPid, false);
            origin.kind = bulwark::ProcessOriginKind::Service;
            if (!hosted.isEmpty()) {
                origin.serviceName = joinServiceNames(hosted.mid(0, 6));
                origin.serviceDisplayName = hosted.first().displayName;
                origin.highConfidence = hosted.size() == 1;
                origin.detail = u("由服务宿主 svchost.exe(PID %1,承载 %2)派生")
                                    .arg(parentPid)
                                    .arg(joinServiceNames(hosted.mid(0, 6)));
            } else {
                origin.detail = u("由 svchost.exe(PID %1)派生,未能确定具体服务").arg(parentPid);
            }
            return origin;
        }
        case HostRole::Other:
        default:
            break;
        }

        if (!parentImage.isEmpty()) {
            origin.kind = bulwark::ProcessOriginKind::Interactive;
            origin.detail = u("由 %1(PID %2)启动").arg(lowerFileName(parentImage)).arg(parentPid);
        }
        return origin;
    } catch (...) {
        return ProcessOrigin{}; // 溯源不得影响裁决
    }
}
