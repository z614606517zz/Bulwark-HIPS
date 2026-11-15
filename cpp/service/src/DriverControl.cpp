#include "bulwark/service/DriverControl.h"
#include "bulwark/service/Logger.h"

#include <QCoreApplication>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QMap>
#include <QProcess>
#include <QStringList>
#include <QThread>

#include <windows.h>

namespace bulwark::service {

namespace {

Logger& log() {
    static Logger l(QStringLiteral("bulwark.service.Driver"));
    return l;
}

const QString kServiceName = QStringLiteral("Bulwark");
const QString kAltitude    = QStringLiteral("385201");
const QString kInstance    = QStringLiteral("Bulwark Instance");

struct ExecResult { int code = -1; QString output; };

ExecResult exec(const QString& program, const QStringList& args, int timeoutMs = 15000) {
    QProcess p;
    p.setProcessChannelMode(QProcess::MergedChannels);
    p.start(program, args);
    if (!p.waitForStarted(5000))
        return {};
    if (!p.waitForFinished(timeoutMs)) {
        p.kill();
        p.waitForFinished(2000);
    }
    ExecResult r;
    r.code = (p.exitStatus() == QProcess::NormalExit) ? p.exitCode() : -1;
    r.output = QString::fromLocal8Bit(p.readAll());
    return r;
}

const QString kServiceKey =
    QStringLiteral("HKLM\\SYSTEM\\CurrentControlSet\\Services\\Bulwark");

bool regHasValue(const QString& key, const QString& value) {
    const ExecResult r = exec(QStringLiteral("reg.exe"), {
        QStringLiteral("query"), key, QStringLiteral("/v"), value });
    return r.code == 0;
}

bool isRegistered() {
    return regHasValue(kServiceKey, QStringLiteral("Type"))
        && regHasValue(kServiceKey, QStringLiteral("ImagePath"));
}

bool writeServiceKeysDirect() {
    HKEY h = nullptr;
    const LSTATUS open = ::RegCreateKeyExW(
        HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Services\\Bulwark",
        0, nullptr, REG_OPTION_NON_VOLATILE, KEY_SET_VALUE, nullptr, &h, nullptr);
    if (open != ERROR_SUCCESS) {
        log().warning(QStringLiteral("打开/创建驱动服务键失败(错误 %1)。").arg(open));
        return false;
    }

    struct Fail { const wchar_t* name; LSTATUS code; };
    QStringList failed;

    const auto setDword = [&](const wchar_t* name, DWORD v) {
        const LSTATUS s = ::RegSetValueExW(h, name, 0, REG_DWORD,
                                           reinterpret_cast<const BYTE*>(&v), sizeof(v));
        if (s != ERROR_SUCCESS)
            failed << QStringLiteral("%1(%2)").arg(QString::fromWCharArray(name)).arg(s);
    };
    const auto setStr = [&](const wchar_t* name, DWORD type, const wchar_t* v) {
        const DWORD bytes = static_cast<DWORD>((::wcslen(v) + 1) * sizeof(wchar_t));
        const LSTATUS s = ::RegSetValueExW(h, name, 0, type,
                                           reinterpret_cast<const BYTE*>(v), bytes);
        if (s != ERROR_SUCCESS)
            failed << QStringLiteral("%1(%2)").arg(QString::fromWCharArray(name)).arg(s);
    };

    setDword(L"Type", 2);
    setDword(L"Start", 3);
    setDword(L"ErrorControl", 1);
    // ImagePath 用相对 %SystemRoot% 的形式,与 install.ps1 的 sc create 保持一致。
    setStr(L"ImagePath", REG_EXPAND_SZ, L"System32\\drivers\\Bulwark.sys");
    setStr(L"DisplayName", REG_SZ, L"Bulwark");
    setStr(L"Group", REG_SZ, L"FSFilter Activity Monitor");
    // REG_MULTI_SZ 必须双 null 结尾;L"FltMgr\0" 连同隐式终止符正好是 8 个 wchar。
    {
        static const wchar_t kDepend[] = L"FltMgr\0";
        const LSTATUS s = ::RegSetValueExW(h, L"DependOnService", 0, REG_MULTI_SZ,
                                           reinterpret_cast<const BYTE*>(kDepend),
                                           sizeof(kDepend));
        if (s != ERROR_SUCCESS)
            failed << QStringLiteral("DependOnService(%1)").arg(s);
    }
    ::RegCloseKey(h);

    if (!failed.isEmpty()) {
        log().warning(QStringLiteral("驱动服务键有 %1 个值写入失败:%2")
                          .arg(failed.size()).arg(failed.join(QStringLiteral(", "))));
        return false;
    }
    log().info(QStringLiteral("已直接写入驱动服务定义(绕开被拒的 CreateService)。"));
    return true;
}

const QString kInstancesKey =
    QStringLiteral("HKLM\\SYSTEM\\CurrentControlSet\\Services\\Bulwark\\Instances");

// minifilter 实例配置(DefaultInstance + Altitude)是否齐备。它与服务条目是否存在相互独立,必须分开查。
bool hasInstanceConfig() {
    const ExecResult def = exec(QStringLiteral("reg.exe"), {
        QStringLiteral("query"), kInstancesKey,
        QStringLiteral("/v"), QStringLiteral("DefaultInstance") });
    if (def.code != 0)
        return false;
    const ExecResult alt = exec(QStringLiteral("reg.exe"), {
        QStringLiteral("query"), kInstancesKey + QStringLiteral("\\") + kInstance,
        QStringLiteral("/v"), QStringLiteral("Altitude") });
    return alt.code == 0;
}

void writeInstanceConfig() {
    exec(QStringLiteral("reg.exe"), { QStringLiteral("add"), kInstancesKey,
        QStringLiteral("/v"), QStringLiteral("DefaultInstance"),
        QStringLiteral("/t"), QStringLiteral("REG_SZ"),
        QStringLiteral("/d"), kInstance, QStringLiteral("/f") });
    const QString instKey = kInstancesKey + QStringLiteral("\\") + kInstance;
    exec(QStringLiteral("reg.exe"), { QStringLiteral("add"), instKey,
        QStringLiteral("/v"), QStringLiteral("Altitude"),
        QStringLiteral("/t"), QStringLiteral("REG_SZ"),
        QStringLiteral("/d"), kAltitude, QStringLiteral("/f") });
    exec(QStringLiteral("reg.exe"), { QStringLiteral("add"), instKey,
        QStringLiteral("/v"), QStringLiteral("Flags"),
        QStringLiteral("/t"), QStringLiteral("REG_DWORD"),
        QStringLiteral("/d"), QStringLiteral("0"), QStringLiteral("/f") });
}

QString ensureRegistered() {
    const QString sys = DriverControl::locateSys();

    if (!isRegistered()) {
        if (sys.isEmpty()) {
            log().warning(QStringLiteral("未找到 Bulwark.sys,无法注册内核驱动(将降级为用户态观测)。"));
            return QString::fromUtf8("找不到驱动文件 Bulwark.sys,无法注册内核驱动服务。");
        }
        const ExecResult create = exec(QStringLiteral("sc.exe"), {
            QStringLiteral("create"), kServiceName,
            QStringLiteral("type="),   QStringLiteral("filesys"),
            QStringLiteral("binPath="), QDir::toNativeSeparators(sys),
            QStringLiteral("start="),  QStringLiteral("demand"),
            QStringLiteral("depend="), QStringLiteral("FltMgr"),
            QStringLiteral("group="),  QStringLiteral("FSFilter Activity Monitor"),
        });
        if (create.code != 0)
            log().info(QStringLiteral("sc create 返回 code=%1(将改用直接写注册表):%2")
                           .arg(create.code).arg(create.output.trimmed()));

        if (!isRegistered()) {
            log().info(QStringLiteral("改用直接写注册表注册内核驱动服务。"));
            writeServiceKeysDirect();
        }
    }

    if (!hasInstanceConfig()) {
        log().info(QStringLiteral("内核驱动缺少 minifilter 实例配置(Instances),正在补写。"));
        writeInstanceConfig();
    }

    const bool svcOk  = isRegistered();
    const bool instOk = hasInstanceConfig();
    if (svcOk && instOk) {
        log().info(QStringLiteral("内核驱动注册就绪(minifilter,Altitude=%1)。").arg(kAltitude));
        return QString();
    }
    if (!svcOk) {
        log().warning(QStringLiteral("内核驱动服务条目仍不存在,无法加载。"));
        return QString::fromUtf8(
            "内核驱动的服务条目创建失败(SCM 里没有 Bulwark 这个服务)。"
            "请以管理员身份重新运行一次安装程序;若仍失败,"
            "可能是本机的安全软件拦下了「安装内核驱动服务」这个动作。");
    }
    log().warning(QStringLiteral("内核驱动实例配置(Instances)写入失败,驱动即使加载也不会附加到任何卷。"));
    return QString::fromUtf8(
        "内核驱动的 minifilter 实例配置写入失败(Instances\\Altitude)。"
        "少了它,驱动即使加载成功也不会附加到任何卷 —— 看着正常,实际什么都拦不到。");
}

bool runFltmc(const QString& verb) {
    const ExecResult r = exec(QStringLiteral("fltmc.exe"), { verb, kServiceName });
    if (r.code == 0) {
        log().info(QStringLiteral("内核驱动 fltmc %1 成功。").arg(verb));
        return true;
    }
    log().info(QStringLiteral("fltmc %1 返回 code=%2(将尝试 sc 回退):%3")
                   .arg(verb).arg(r.code).arg(r.output.trimmed()));
    return false;
}

bool runSc(const QString& verb) {
    const ExecResult r = exec(QStringLiteral("sc.exe"), { verb, kServiceName });
    const bool ok = r.code == 0
        || r.output.contains(QStringLiteral("1056"))
        || (verb == QStringLiteral("stop") && r.output.contains(QStringLiteral("1062")));
    if (ok)
        log().info(QStringLiteral("内核驱动 sc %1 成功。").arg(verb));
    else
        log().warning(QStringLiteral("内核驱动 sc %1 失败(code=%2):%3")
                          .arg(verb).arg(r.code).arg(r.output.trimmed()));
    return ok;
}

}

QString DriverControl::locateSys() {
    const QString sysRoot = qEnvironmentVariable("SystemRoot", QStringLiteral("C:\\Windows"));
    const QString deployed = QDir(sysRoot).filePath(QStringLiteral("System32/drivers/Bulwark.sys"));
    return QFileInfo::exists(deployed) ? QDir::cleanPath(deployed) : QString();
}

bool DriverControl::isRunning() {
    const ExecResult f = exec(QStringLiteral("fltmc.exe"), { QStringLiteral("filters") });
    if (f.code == 0 && f.output.contains(kServiceName, Qt::CaseInsensitive))
        return true;
    const ExecResult r = exec(QStringLiteral("sc.exe"), { QStringLiteral("query"), kServiceName });
    return r.code >= 0 && r.output.contains(QStringLiteral("RUNNING"), Qt::CaseInsensitive);
}

bool DriverControl::ensureLoaded() {
    if (isRunning())
        return true;
    (void)ensureRegistered();

    if (runFltmc(QStringLiteral("load")) && isRunning())
        return true;

    log().info(QStringLiteral("内核筛选器未挂载,但服务状态可能残留为已启动 —— 先停止再重新加载。"));
    runFltmc(QStringLiteral("unload"));
    runSc(QStringLiteral("stop"));
    QThread::msleep(1500);
    if (runFltmc(QStringLiteral("load")) && isRunning())
        return true;

    runSc(QStringLiteral("start"));
    return isRunning();
}

bool DriverControl::tryStop() {
    return runFltmc(QStringLiteral("unload")) || runSc(QStringLiteral("stop"));
}

}
