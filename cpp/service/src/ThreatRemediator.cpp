#include "bulwark/service/ThreatRemediator.h"
#include "bulwark/service/RegSurgery.h"
#include "bulwark/service/monitoring/ProcessInspector.h"

#include <QDir>
#include <QDirIterator>
#include <QFile>
#include <QFileInfo>
#include <QProcess>
#include <QSet>

#include <atomic>
#include <iterator>

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <oleauto.h>
#include <taskschd.h>

namespace bulwark::service {
namespace {

using bulwark::EventType;
namespace mon = bulwark::service::monitoring;

std::atomic<bool> g_loggedAutostartScope{false};
std::atomic<bool> g_loggedTaskScope{false};

inline QString u(const char* s) { return QString::fromUtf8(s); }

const wchar_t* wstr(const QString& s) {
    return reinterpret_cast<const wchar_t*>(s.utf16());
}

HKEY hiveToHkey(RegHive h) {
    switch (h) {
        case RegHive::LocalMachine:  return HKEY_LOCAL_MACHINE;
        case RegHive::CurrentUser:   return HKEY_CURRENT_USER;
        case RegHive::ClassesRoot:   return HKEY_CLASSES_ROOT;
        case RegHive::Users:         return HKEY_USERS;
        case RegHive::CurrentConfig: return HKEY_CURRENT_CONFIG;
    }
    return HKEY_LOCAL_MACHINE;
}

REGSAM viewToSam(RegView v) {
    switch (v) {
        case RegView::Registry32: return KEY_WOW64_32KEY;
        case RegView::Registry64: return KEY_WOW64_64KEY;
        default:                  return 0;
    }
}

RegView viewForSubKey(const QString& subKey) {
    return subKey.contains(QLatin1String("WOW6432Node"), Qt::CaseInsensitive)
               ? RegView::Registry64 : RegView::Default;
}

HKEY openKey(RegHive hive, const QString& subKey, RegView view, REGSAM access) {
    HKEY hk = nullptr;
    if (RegOpenKeyExW(hiveToHkey(hive), wstr(subKey), 0, access | viewToSam(view), &hk) == ERROR_SUCCESS)
        return hk;
    return nullptr;
}

HKEY openKeyRaw(HKEY root, const QString& subKey, RegView view, REGSAM access) {
    HKEY hk = nullptr;
    if (RegOpenKeyExW(root, subKey.isEmpty() ? nullptr : wstr(subKey), 0,
                      access | viewToSam(view), &hk) == ERROR_SUCCESS)
        return hk;
    return nullptr;
}

QString readString(HKEY hk, const QString& name) {
    DWORD type = 0, cb = 0;
    if (RegQueryValueExW(hk, wstr(name), nullptr, &type, nullptr, &cb) != ERROR_SUCCESS) return QString();
    if ((type != REG_SZ && type != REG_EXPAND_SZ) || cb == 0) return QString();
    QByteArray buf(static_cast<int>(cb), '\0');
    if (RegQueryValueExW(hk, wstr(name), nullptr, &type,
                         reinterpret_cast<BYTE*>(buf.data()), &cb) != ERROR_SUCCESS)
        return QString();
    const wchar_t* w = reinterpret_cast<const wchar_t*>(buf.constData());
    int wlen = static_cast<int>(cb / sizeof(wchar_t));
    while (wlen > 0 && w[wlen - 1] == L'\0') --wlen;
    return QString::fromWCharArray(w, wlen);
}

QStringList enumValueNames(HKEY hk) {
    QStringList out;
    wchar_t name[16384];
    for (DWORD idx = 0;; ++idx) {
        DWORD cch = 16384;
        const LSTATUS s = RegEnumValueW(hk, idx, name, &cch, nullptr, nullptr, nullptr, nullptr);
        if (s == ERROR_SUCCESS) out << QString::fromWCharArray(name, static_cast<int>(cch));
        else break;
    }
    return out;
}

QStringList enumSubKeyNames(HKEY hk) {
    QStringList out;
    wchar_t name[256];
    for (DWORD idx = 0;; ++idx) {
        DWORD cch = 256;
        const LSTATUS s = RegEnumKeyExW(hk, idx, name, &cch, nullptr, nullptr, nullptr, nullptr);
        if (s == ERROR_SUCCESS) out << QString::fromWCharArray(name, static_cast<int>(cch));
        else break;
    }
    return out;
}

const char* const kDropZones[] = {
    "\\appdata\\local\\temp\\", "\\windows\\temp\\", "\\appdata\\roaming\\",
    "\\appdata\\local\\", "\\downloads\\", "\\desktop\\", "\\documents\\",
    "\\users\\public\\", "\\programdata\\", "\\$recycle.bin\\", "\\perflogs\\",
    "c:\\temp\\",
    "c:\\tmp\\",
    "\\music\\",
    "\\videos\\",
    "\\pictures\\",
};

// Protected (never cleaned) zones - system and legit install dirs.
const char* const kProtectedZones[] = {
    "\\windows\\system32\\", "\\windows\\syswow64\\", "\\windows\\winsxs\\",
    "\\program files\\", "\\program files (x86)\\",
};

// System executables that must never be cleaned, even if reported as dropped files.
const char* const kSystemExecutables[] = {
    "cmd.exe", "powershell.exe", "pwsh.exe",
    "conhost.exe", "taskmgr.exe", "regedit.exe",
    "notepad.exe", "explorer.exe", "rundll32.exe",
    "mshta.exe", "wscript.exe", "cscript.exe",
    "reg.exe", "sc.exe", "net.exe", "netsh.exe",
    "svchost.exe", "services.exe", "lsass.exe",
    "winlogon.exe", "csrss.exe", "smss.exe",
    "wininit.exe", "dwm.exe", "taskhostw.exe",
    "msiexec.exe", "dllhost.exe", "runtimebroker.exe",
};

struct RegLoc { RegHive hive; const char* subKey; };

QString hiveName(RegHive h) {
    switch (h) {
        case RegHive::LocalMachine: return QStringLiteral("HKLM");
        case RegHive::CurrentUser:  return QStringLiteral("HKCU");
        case RegHive::Users:        return QStringLiteral("HKU");
        default:                    return QStringLiteral("HKLM");
    }
}

const RegLoc kAutostartKeys[] = {
    { RegHive::LocalMachine, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" },
    { RegHive::LocalMachine, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce" },
    { RegHive::LocalMachine, "SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run" },
    { RegHive::LocalMachine, "SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce" },
    { RegHive::LocalMachine, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run" },
    { RegHive::LocalMachine, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" },
};

const char* const kPerUserAutostartSubKeys[] = {
    "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
    "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
    "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run",
};

// root 必须是原始 HKEY:HKEY_USERS 下按 SID 展开的路径没有对应的 RegHive 枚举值。
struct AutostartTarget {
    HKEY root = HKEY_LOCAL_MACHINE;
    QString subKey;
    QString display;
};

QList<AutostartTarget> autostartTargets() {
    QList<AutostartTarget> out;
    for (const RegLoc& loc : kAutostartKeys) {
        AutostartTarget t;
        t.root = hiveToHkey(loc.hive);
        t.subKey = QString::fromLatin1(loc.subKey);
        t.display = hiveName(loc.hive) + QLatin1Char('\\') + t.subKey;
        out.append(t);
    }

    HKEY usersRoot = openKeyRaw(HKEY_USERS, QString(), RegView::Default, KEY_READ);
    if (!usersRoot)
        return out;
    for (const QString& sid : enumSubKeyNames(usersRoot)) {
        if (sid.endsWith(QStringLiteral("_Classes"), Qt::CaseInsensitive))
            continue;
        for (const char* sub : kPerUserAutostartSubKeys) {
            AutostartTarget t;
            t.root = HKEY_USERS;
            t.subKey = sid + QLatin1Char('\\') + QString::fromLatin1(sub);
            t.display = QStringLiteral("HKU\\") + t.subKey;
            out.append(t);
        }
    }
    RegCloseKey(usersRoot);
    return out;
}

const RegLoc kIfeoRoots[] = {
    { RegHive::LocalMachine, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options" },
    { RegHive::LocalMachine, "SOFTWARE\\WOW6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options" },
};

}
}

namespace bulwark::service {
namespace {

QString forceProtectedReasonImpl(const QString& path);

bulwark::ipc::RemediationSkippedItem mkSkip(const QString& target, const QString& reason, bool isFile) {
    bulwark::ipc::RemediationSkippedItem s;
    s.target = target;
    s.reason = reason;
    s.isFile = isFile;
    if (isFile) {
        s.kind = QStringLiteral("file");
        s.location = target;
        s.forceable = QFileInfo::exists(target) && forceProtectedReasonImpl(target).isEmpty();
    }
    return s;
}

bulwark::ipc::RemediationSkippedItem mkPersistSkip(const QString& target, const QString& reason,
                                                   const QString& kind, const QString& location,
                                                   const QString& name = QString()) {
    bulwark::ipc::RemediationSkippedItem s = mkSkip(target, reason, false);
    s.kind = kind;
    s.location = location;
    s.name = name;
    s.forceable = true;
    return s;
}

bool looksLikeFilePath(const QString& s) {
    if (s.size() < 4) return false;
    const bool hasRoot =
        (s.size() > 2 && s[1] == QLatin1Char(':') &&
         (s[2] == QLatin1Char('\\') || s[2] == QLatin1Char('/'))) ||
        s.startsWith(QLatin1String("\\\\"));
    if (!hasRoot) return false;
    if (s.startsWith(QLatin1String("\\REGISTRY"), Qt::CaseInsensitive)) return false;
    return true;
}

bool referencesMalware(const QString& data, const QStringList& maliciousFiles) {
    if (data.isEmpty()) return false;
    const auto isSep = [](QChar c) {
        return c.isSpace() || c == QLatin1Char('"') || c == QLatin1Char('\'') || c == QLatin1Char(',')
            || c == QLatin1Char('=');
    };
    for (const QString& mf : maliciousFiles) {
        if (mf.isEmpty()) continue;
        qsizetype from = 0;
        for (;;) {
            const qsizetype i = data.indexOf(mf, from, Qt::CaseInsensitive);
            if (i < 0) break;
            const qsizetype end = i + mf.size();
            const bool leftOk = (i == 0) || isSep(data.at(i - 1)) || data.at(i - 1) == QLatin1Char('\\');
            const bool rightOk = (end >= data.size()) || isSep(data.at(end));
            if (leftOk && rightOk) return true;
            from = i + 1;
        }
    }
    return false;
}

bool underDriveRoot(const QString& lower, const char* zone) {
    QStringView v(lower);
    if (v.startsWith(QLatin1String("\\\\?\\")) || v.startsWith(QLatin1String("\\??\\")))
        v = v.mid(4);
    return v.size() > 2 && v.at(1) == QLatin1Char(':')
        && v.mid(2).startsWith(QLatin1String(zone));
}

bool isInProtectedZone(const QString& path) {
    const QString lower = path.toLower().replace(QLatin1Char('/'), QLatin1Char('\\'));
    for (const char* z : kProtectedZones)
        if (underDriveRoot(lower, z)) return true;
    return false;
}

bool isUserProfileRootFile(const QString& lower) {
    if (!underDriveRoot(lower, "\\users\\")) return false;
    const QStringView rest = QStringView(lower).mid(lower.indexOf(QLatin1String(":\\users\\")) + 8);
    return rest.count(QLatin1Char('\\')) == 1 && !rest.endsWith(QLatin1Char('\\'));
}

bool isSystemExecutable(const QString& path) {
    const QFileInfo fi(path);
    const QString fname = fi.fileName().toLower();
    bool nameHit = false;
    for (const char* sysExe : kSystemExecutables)
        if (fname == QLatin1String(sysExe)) { nameHit = true; break; }
    if (!nameHit) return false;

    QString lower = QDir::cleanPath(path.trimmed());
    lower.replace(QLatin1Char('/'), QLatin1Char('\\'));
    lower = lower.toLower();
    wchar_t windowsPath[MAX_PATH] = {};
    const UINT chars = ::GetWindowsDirectoryW(windowsPath, MAX_PATH);
    if (chars == 0 || chars >= MAX_PATH)
        return false;
    QString windows = QDir::cleanPath(QString::fromWCharArray(windowsPath, static_cast<int>(chars)));
    windows.replace(QLatin1Char('/'), QLatin1Char('\\'));
    windows = windows.toLower();
    return lower.startsWith(windows + QStringLiteral("\\system32\\"))
        || lower.startsWith(windows + QStringLiteral("\\syswow64\\"))
        || lower.startsWith(windows + QStringLiteral("\\winsxs\\"));
}

QStringList g_canaryFiles;
QMutex g_canaryMx;

bool isOwnCanaryFile(const QString& path) {
    const QString p = path.trimmed().toLower().replace(QLatin1Char('/'), QLatin1Char('\\'));
    if (p.isEmpty())
        return false;
    QMutexLocker lk(&g_canaryMx);
    for (const QString& c : g_canaryFiles) {
        if (c == p)
            return true;
    }
    return false;
}

bool passesLocationGuard(const QString& path, QString& reason) {
    reason.clear();

    // 0) 本产品自己的勒索诱饵 —— 绝不清理。放在最前面:它比下面任何一条都更不该被误判,
    //    而且诱饵路径天生满足「用户可写落地区」。
    if (isOwnCanaryFile(path)) {
        reason = u("这是本产品自己投放的勒索诱饵文件,不是释放物(清掉它等于自毁蜜罐)");
        return false;
    }

    if (isSystemExecutable(path)) {
        reason = u("系统关键工具,绝对保护");
        return false;
    }

    const QString lower = path.toLower().replace(QLatin1Char('/'), QLatin1Char('\\'));
    if (isInProtectedZone(lower)) { reason = u("位于系统/安装目录,保护不动"); return false; }
    bool inDrop = isUserProfileRootFile(lower);
    for (const char* z : kDropZones)
        if (!inDrop && lower.contains(QLatin1String(z))) { inDrop = true; break; }
    if (!inDrop) { reason = u("不在用户可写落地区,谨慎起见不清理"); return false; }
    return true;
}

QString forceProtectedReasonImpl(const QString& path) {
    if (isOwnCanaryFile(path))
        return u("这是本产品自己投放的勒索诱饵文件,强制处理也不会动它");
    if (isSystemExecutable(path))
        return u("系统关键工具,强制处理也不会动它");
    const QString lower = path.toLower().replace(QLatin1Char('/'), QLatin1Char('\\'));
    if (lower.size() >= 3 && lower.at(1) == QLatin1Char(':')) {
        const QStringView rel = QStringView(lower).mid(2);
        if (rel.startsWith(QStringLiteral("\\windows\\")) && !rel.startsWith(QStringLiteral("\\windows\\temp\\")))
            return u("位于 Windows 系统目录,强制处理也不会动它(删错会导致系统无法启动)");
    }
    return QString();
}

bool isSafeToRemove(const QString& path, bool bypassSignatureGuard, QString& reason) {
    if (!passesLocationGuard(path, reason))
        return false;
    if (!bypassSignatureGuard) {
        if (mon::ProcessInspector::isSigned(path)) { reason = u("带可信数字签名,保护不动"); return false; }
    }
    return true;
}

bool tryParseHive(const QString& location, RegHive& hive, QString& subKey) {
    hive = RegHive::LocalMachine;
    subKey.clear();
    const QString loc = location.trimmed();
    if (loc.isEmpty()) return false;
    const int slash = loc.indexOf(QLatin1Char('\\'));
    const QString prefix = slash < 0 ? loc : loc.left(slash);
    subKey = slash < 0 ? QString() : loc.mid(slash + 1);
    const QString up = prefix.toUpper();
    if (up == QLatin1String("HKLM") || up == QLatin1String("HKEY_LOCAL_MACHINE")) { hive = RegHive::LocalMachine; return true; }
    if (up == QLatin1String("HKCU") || up == QLatin1String("HKEY_CURRENT_USER")) { hive = RegHive::CurrentUser; return true; }
    if (up == QLatin1String("HKU")  || up == QLatin1String("HKEY_USERS"))        { hive = RegHive::Users; return true; }
    return false;
}

QString xmlBetween(const QString& s, const QString& a, const QString& b) {
    const int i = s.indexOf(a, 0, Qt::CaseInsensitive);
    if (i < 0) return QString();
    const int from = i + a.size();
    const int j = s.indexOf(b, from, Qt::CaseInsensitive);
    return j < 0 ? QString() : s.mid(from, j - from).trimmed();
}

QString expandEnvVars(const QString& s) {
    if (!s.contains(QLatin1Char('%')))
        return s;
    wchar_t buf[2048] = {};
    const DWORD n = ExpandEnvironmentStringsW(reinterpret_cast<const wchar_t*>(s.utf16()), buf,
                                              static_cast<DWORD>(std::size(buf)));
    if (n == 0 || n > std::size(buf))
        return s;   // 展开失败 / 缓冲不够 -> 保持原样,绝不返回半截串
    return QString::fromWCharArray(buf, static_cast<int>(n - 1));
}

bool ensureComForTasks() {
    thread_local int state = 0;
    if (state != 0)
        return state == 1;
    const HRESULT hr = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    state = (SUCCEEDED(hr) || hr == RPC_E_CHANGED_MODE) ? 1 : 2;
    return state == 1;
}

bool deleteScheduledTaskByPath(const QString& fullPath, QString& err) {
    err.clear();
    QString p = fullPath;
    p.replace(QLatin1Char('/'), QLatin1Char('\\'));
    while (p.startsWith(QLatin1Char('\\'))) p = p.mid(1);
    if (p.isEmpty()) { err = u("任务路径为空"); return false; }

    const int cut = p.lastIndexOf(QLatin1Char('\\'));
    const QString folder = cut < 0 ? QStringLiteral("\\") : (QStringLiteral("\\") + p.left(cut));
    const QString name = cut < 0 ? p : p.mid(cut + 1);

    if (!ensureComForTasks()) { err = u("COM 初始化失败"); return false; }

    ITaskService* svc = nullptr;
    HRESULT hr = CoCreateInstance(__uuidof(TaskScheduler), nullptr, CLSCTX_INPROC_SERVER,
                                  __uuidof(ITaskService), reinterpret_cast<void**>(&svc));
    if (FAILED(hr) || !svc) {
        err = u("无法创建 TaskScheduler(0x") + QString::number(static_cast<quint32>(hr), 16) + u(")");
        return false;
    }
    VARIANT empty;
    VariantInit(&empty);
    hr = svc->Connect(empty, empty, empty, empty);
    if (FAILED(hr)) {
        svc->Release();
        err = u("连接任务计划服务失败(0x") + QString::number(static_cast<quint32>(hr), 16) + u(")");
        return false;
    }
    BSTR bFolder = SysAllocString(reinterpret_cast<const wchar_t*>(folder.utf16()));
    ITaskFolder* tf = nullptr;
    hr = svc->GetFolder(bFolder, &tf);
    if (bFolder) SysFreeString(bFolder);
    if (FAILED(hr) || !tf) {
        svc->Release();
        err = u("找不到任务文件夹 ") + folder + u("(0x") + QString::number(static_cast<quint32>(hr), 16) + u(")");
        return false;
    }
    BSTR bName = SysAllocString(reinterpret_cast<const wchar_t*>(name.utf16()));
    hr = tf->DeleteTask(bName, 0);
    if (bName) SysFreeString(bName);
    tf->Release();
    svc->Release();
    if (FAILED(hr)) {
        err = u("DeleteTask 失败(0x") + QString::number(static_cast<quint32>(hr), 16) + u(")");
        return false;
    }
    return true;
}

std::pair<int, QString> runProcess(const QString& fileName, const QStringList& args) {
    QProcess p;
    p.start(fileName, args);
    if (!p.waitForStarted(5000)) return { -1, u("无法启动进程") };
    if (!p.waitForFinished(15000)) { p.kill(); p.waitForFinished(1000); return { -2, u("执行超时") }; }
    const QString err = QString::fromLocal8Bit(p.readAllStandardError());
    return { p.exitCode(), err };
}

}
}

namespace bulwark::service {

ThreatRemediator::ThreatRemediator(QuarantineManager& quarantine, Logger logger)
    : quarantine_(quarantine), log_(std::move(logger)) {}

void ThreatRemediator::setOwnCanaryFiles(const QStringList& paths) {
    QStringList norm;
    norm.reserve(paths.size());
    for (const QString& p : paths) {
        const QString t = p.trimmed().toLower().replace(QLatin1Char('/'), QLatin1Char('\\'));
        if (!t.isEmpty() && !norm.contains(t))
            norm << t;
    }
    QMutexLocker lk(&g_canaryMx);
    g_canaryFiles = norm;
}

bool ThreatRemediator::isInUserDropZone(const QString& path, QString* reason) {
    QString why;
    const bool ok = looksLikeFilePath(path.trimmed()) && passesLocationGuard(path.trimmed(), why);
    if (reason)
        *reason = why;
    return ok;
}

bool ThreatRemediator::isPersistenceRemovalTarget(const QString& path) {
    const QString p = path.trimmed();
    if (!looksLikeFilePath(p) || isOwnCanaryFile(p) || isSystemExecutable(p))
        return false;
    const QString lower = p.toLower().replace(QLatin1Char('/'), QLatin1Char('\\'));
    const bool installedLocation = isInProtectedZone(lower)
        || (underDriveRoot(lower, "\\windows\\") && !underDriveRoot(lower, "\\windows\\temp\\"));
    return !(installedLocation && mon::ProcessInspector::isSigned(p));
}

RemediationReport ThreatRemediator::remediate(const bulwark::SecurityEvent& malicious,
                                              const QList<bulwark::ChainEventInfo>& footprint) {
    RemediationReport report;

    QStringList maliciousFiles;
    QSet<QString> seenLower;
    auto consider = [&](const QString& path) {
        if (path.trimmed().isEmpty()) return;
        if (path.startsWith(QLatin1String("PID "))) return;
        if (!looksLikeFilePath(path)) return;
        const QString t = path.trimmed();
        const QString low = t.toLower();
        if (!seenLower.contains(low)) { seenLower.insert(low); maliciousFiles << t; }
    };

    consider(malicious.actorPath);

    const bool actorSignatureUntrusted =
        malicious.certRevoked || malicious.signatureMismatch || malicious.signedAfterCertExpiry;
    const QString actorPath = malicious.actorPath.trimmed();

    for (const bulwark::ChainEventInfo& ev : footprint)
        if (ev.type == EventType::FileWrite || ev.type == EventType::FileDelete)
            consider(ev.target);

    auto dirLowerOf = [](const QString& p) {
        return QFileInfo(p.trimmed()).absolutePath().toLower().replace(QLatin1Char('/'), QLatin1Char('\\'));
    };
    QSet<QString> sideloadDirsLower;
    if (!malicious.sideloadedUnsignedModulePath.trimmed().isEmpty())
        sideloadDirsLower.insert(dirLowerOf(malicious.sideloadedUnsignedModulePath));
    for (const QString& p : maliciousFiles) {
        if (!p.endsWith(QLatin1String(".dll"), Qt::CaseInsensitive) || !QFileInfo::exists(p))
            continue;
        QString why;
        if (passesLocationGuard(p, why) && !mon::ProcessInspector::isSigned(p))
            sideloadDirsLower.insert(dirLowerOf(p));
    }

    int alreadyVaulted = 0;
    for (const QString& path : maliciousFiles) {
        if (!QFileInfo::exists(path)) continue;
        if (quarantine_.isAlreadyQuarantined(path)) {
            ++alreadyVaulted;
            continue;
        }
        const bool bypass = (actorSignatureUntrusted && path.compare(actorPath, Qt::CaseInsensitive) == 0)
                            || (path.endsWith(QLatin1String(".exe"), Qt::CaseInsensitive)
                                && sideloadDirsLower.contains(dirLowerOf(path)));
        QString why;
        if (!isSafeToRemove(path, bypass, why)) {
            report.skipped.append(mkSkip(path, why, true));
            continue;
        }
        const QString hash = QuarantineManager::tryComputeSha256(path);
        const auto entry = quarantine_.quarantine(
            path,
            u("恶意进程释放/关联文件的足迹清理(主体 PID ") + QString::number(malicious.actorPid) + u(")"),
            malicious.actorPid, hash, false);
        if (entry.has_value() && entry->originalRemoved) {
            report.quarantinedFiles.append(path);
            log_.warning(u("足迹清理:已隔离恶意释放文件 ") + path);
        } else if (entry.has_value()) {
            report.skipped.append(mkSkip(
                path,
                entry->deleteOnRebootScheduled
                    ? u("已保存可还原副本,但原文件仍在;已计划重启删除")
                    : u("已保存可还原副本,但原文件删除及重启调度均失败"),
                true));
        } else {
            report.skipped.append(mkSkip(path, u("隔离失败,可能被占用"), true));
        }
    }

    if (alreadyVaulted > 0) {
        log_.debug(u("足迹清理:") + QString::number(alreadyVaulted)
                   + u(" 个候选文件此前已隔离(金库副本仍在),本轮跳过 —— 未重复计算签名/哈希。"));
    }

    // 主体本身常是隔离阶段放过的系统程序(承载方 svchost、被借用的 explorer),它仍在候选里;
    // 拿它去比服务的 ImagePath,会把所有按用户实例化的 svchost 服务当成恶意服务删掉。
    QStringList persistenceTargets;
    for (const QString& path : maliciousFiles)
        if (isPersistenceRemovalTarget(path))
            persistenceTargets << path;

    removeAutostartPersistence(persistenceTargets, report);
    removeIfeoPersistence(persistenceTargets, report);
    removeServicePersistence(persistenceTargets, report);
    removeScheduledTaskPersistence(persistenceTargets, report);

    if (report.totalActions() > 0)
        log_.warning(u("足迹清理完成:隔离文件 ") + QString::number(report.quarantinedFiles.size())
                     + u(" 个,移除持久化 ") + QString::number(report.removedRegistryValues.size()) + u(" 项。"));
    return report;
}

std::pair<bool, QString> ThreatRemediator::forceQuarantine(const QString& path) {
    if (path.trimmed().isEmpty()) return { false, u("路径为空") };
    if (!QFileInfo::exists(path)) return { false, u("文件不存在(可能已被移动或删除)") };
    const QString hash = QuarantineManager::tryComputeSha256(path);
    const auto entry = quarantine_.quarantine(path, u("用户手动强制隔离(清理报告重试)"), 0, hash);
    if (entry.has_value() && entry->originalRemoved) {
        log_.warning(u("手动强制隔离成功:") + path);
        return { true, u("已移入隔离区") };
    }
    if (entry.has_value()) {
        const QString msg = entry->deleteOnRebootScheduled
            ? u("已保存可还原副本,但原文件仍在;已计划重启删除")
            : u("已保存可还原副本,但原文件删除及重启调度均失败");
        log_.warning(u("手动强制隔离仅部分完成:") + path + u(" · ") + msg);
        return { false, msg };
    }
    return { false, u("隔离失败(文件可能被占用或权限不足)") };
}

}

namespace bulwark::service {

void ThreatRemediator::removeAutostartPersistence(const QStringList& maliciousFiles, RemediationReport& report) {
    const QList<AutostartTarget> targets = autostartTargets();
    for (const AutostartTarget& loc : targets) {
        const RegView view = viewForSubKey(loc.subKey);
        HKEY hk = openKeyRaw(loc.root, loc.subKey, view, KEY_READ | KEY_SET_VALUE);
        if (!hk) continue;

        for (const QString& valueName : enumValueNames(hk)) {
            const QString data = readString(hk, valueName);
            if (data.isEmpty() || !referencesMalware(data, maliciousFiles)) continue;

            const QString full = loc.display + QLatin1Char('\\') + valueName;
            const LSTATUS st = RegDeleteValueW(hk, wstr(valueName));
            if (st == ERROR_SUCCESS) {
                report.removedRegistryValues.append(full);
                report.hardenedRegTargets.append(loc.subKey + QLatin1Char('\\') + valueName);
                log_.warning(u("足迹清理:已删除自启动持久化项 ") + full);
            } else if (st == ERROR_ACCESS_DENIED) {
                const RegHive surgeryHive =
                    loc.root == HKEY_USERS ? RegHive::Users : RegHive::LocalMachine;
                if (RegSurgery::forceDeleteValue(surgeryHive, loc.subKey, valueName, view)) {
                    report.removedRegistryValues.append(full + u("(夺取所有权后删除)"));
                    report.hardenedRegTargets.append(loc.subKey + QLatin1Char('\\') + valueName);
                    log_.warning(u("足迹清理:夺取所有权后删除自启动项 ") + full);
                } else {
                    report.skipped.append(mkPersistSkip(full, u("受 ACL 保护,夺取所有权仍失败(建议手动删除)"),
                                                        QStringLiteral("regValue"), loc.display, valueName));
                }
            } else {
                report.skipped.append(mkPersistSkip(full, u("删除失败"), QStringLiteral("regValue"),
                                                    loc.display, valueName));
            }
        }
        RegCloseKey(hk);
    }
    const QString scope = u("足迹清理:自启动位置共 ") + QString::number(targets.size())
                          + u(" 处(机器范围 ")
                          + QString::number(static_cast<int>(std::size(kAutostartKeys)))
                          + u(" + HKEY_USERS 已加载 hive 展开 ")
                          + QString::number(targets.size() - static_cast<int>(std::size(kAutostartKeys)))
                          + u(")。");
    if (!g_loggedAutostartScope.exchange(true))
        log_.info(scope);
    else
        log_.debug(scope);
}

void ThreatRemediator::removeIfeoPersistence(const QStringList& maliciousFiles, RemediationReport& report) {
    for (const RegLoc& loc : kIfeoRoots) {
        const QString root = QString::fromLatin1(loc.subKey);
        const RegView view = viewForSubKey(root);
        HKEY rootKey = openKey(loc.hive, root, view, KEY_READ);
        if (!rootKey) continue;

        for (const QString& sub : enumSubKeyNames(rootKey)) {
            const QString childPath = root + QLatin1Char('\\') + sub;
            HKEY child = openKey(loc.hive, childPath, view, KEY_READ);
            if (!child) continue;
            const QString dbg = readString(child, QStringLiteral("Debugger"));
            RegCloseKey(child);
            if (!referencesMalware(dbg, maliciousFiles)) continue;

            const QString full = hiveName(loc.hive) + QLatin1Char('\\') + childPath + u("\\Debugger");
            bool done = false;
            HKEY wk = openKey(loc.hive, childPath, view, KEY_SET_VALUE);
            if (wk) {
                if (RegDeleteValueW(wk, L"Debugger") == ERROR_SUCCESS) {
                    report.removedRegistryValues.append(full);
                    report.hardenedRegTargets.append(childPath + u("\\Debugger"));
                    log_.warning(u("足迹清理:已删除映像劫持(IFEO)项 ") + full);
                    done = true;
                }
                RegCloseKey(wk);
            }
            if (done) continue;

            if (RegSurgery::forceDeleteValue(loc.hive, childPath, QStringLiteral("Debugger"), view)) {
                report.removedRegistryValues.append(full + u("(夺取所有权后删除)"));
                report.hardenedRegTargets.append(childPath + u("\\Debugger"));
                log_.warning(u("足迹清理:夺取所有权后删除映像劫持项 ") + full);
            } else {
                report.skipped.append(mkPersistSkip(
                    full, u("受 ACL 保护,夺取所有权仍失败(建议关闭 Defender 篡改保护后手动删除)"),
                    QStringLiteral("regValue"), hiveName(loc.hive) + QLatin1Char('\\') + childPath,
                    QStringLiteral("Debugger")));
            }
        }
        RegCloseKey(rootKey);
    }
}

void ThreatRemediator::removeServicePersistence(const QStringList& maliciousFiles, RemediationReport& report) {
    const QString servicesPath = QStringLiteral("SYSTEM\\CurrentControlSet\\Services");
    HKEY servicesKey = openKey(RegHive::LocalMachine, servicesPath, RegView::Default, KEY_READ | DELETE);
    if (!servicesKey) return;

    for (const QString& svc : enumSubKeyNames(servicesKey)) {
        HKEY sk = openKey(RegHive::LocalMachine, servicesPath + QLatin1Char('\\') + svc, RegView::Default, KEY_READ);
        if (!sk) continue;
        const QString imagePath = readString(sk, QStringLiteral("ImagePath"));
        QString serviceDll;
        HKEY param = openKey(RegHive::LocalMachine,
                             servicesPath + QLatin1Char('\\') + svc + u("\\Parameters"), RegView::Default, KEY_READ);
        if (param) { serviceDll = readString(param, QStringLiteral("ServiceDll")); RegCloseKey(param); }
        RegCloseKey(sk);

        if (!referencesMalware(imagePath, maliciousFiles) && !referencesMalware(serviceDll, maliciousFiles))
            continue;

        const QString full = u("HKLM\\SYSTEM\\CurrentControlSet\\Services\\") + svc;
        const LSTATUS st = RegDeleteTreeW(servicesKey, wstr(svc));
        if (st == ERROR_SUCCESS) {
            report.removedRegistryValues.append(full);
            report.hardenedRegTargets.append(u("\\Services\\") + svc + QLatin1Char('\\'));
            log_.warning(u("足迹清理:已删除指向恶意文件的服务 ") + full);
        } else if (st == ERROR_ACCESS_DENIED) {
            if (RegSurgery::forceDeleteSubKeyTree(RegHive::LocalMachine, servicesPath, svc, RegView::Default)) {
                report.removedRegistryValues.append(full + u("(夺取所有权后删除)"));
                report.hardenedRegTargets.append(u("\\Services\\") + svc + QLatin1Char('\\'));
                log_.warning(u("足迹清理:夺取所有权后删除恶意服务 ") + full);
            } else {
                report.skipped.append(mkPersistSkip(full, u("受 ACL 保护,夺取所有权仍失败(建议手动删除该服务)"),
                                                    QStringLiteral("regKey"), u("HKLM\\") + servicesPath, svc));
            }
        } else {
            report.skipped.append(mkPersistSkip(u("Services\\") + svc, u("删除失败"), QStringLiteral("regKey"),
                                                u("HKLM\\") + servicesPath, svc));
        }
    }
    RegCloseKey(servicesKey);
}

void ThreatRemediator::removeScheduledTaskPersistence(const QStringList& maliciousFiles,
                                                     RemediationReport& report) {
    if (maliciousFiles.isEmpty())
        return;
    const QString windir = qEnvironmentVariable("SystemRoot", QStringLiteral("C:\\Windows"));
    const QString tasksRoot = windir + QStringLiteral("\\System32\\Tasks");
    QDir rootDir(tasksRoot);
    if (!rootDir.exists())
        return;

    constexpr int kMaxTaskFiles = 4000;
    int seen = 0, hit = 0;
    QDirIterator it(tasksRoot, QDir::Files, QDirIterator::Subdirectories);
    while (it.hasNext() && seen < kMaxTaskFiles) {
        const QString file = it.next();
        ++seen;
        QFile f(file);
        if (!f.open(QIODevice::ReadOnly))
            continue;
        const QString xml = QString::fromUtf8(f.read(64 * 1024));
        f.close();
        if (xml.isEmpty() || !xml.contains(QStringLiteral("<Exec"), Qt::CaseInsensitive))
            continue;

        const QString cmd = xmlBetween(xml, QStringLiteral("<Command>"), QStringLiteral("</Command>"));
        const QString args = xmlBetween(xml, QStringLiteral("<Arguments>"), QStringLiteral("</Arguments>"));
        const QString expanded = expandEnvVars(QString(cmd).remove(QLatin1Char('"')));
        if (!referencesMalware(cmd, maliciousFiles) && !referencesMalware(args, maliciousFiles)
            && !referencesMalware(expanded, maliciousFiles))
            continue;

        ++hit;
        const QString taskPath = QStringLiteral("\\") + rootDir.relativeFilePath(file);
        const QString display = u("计划任务 ") + taskPath;
        QString err;
        if (deleteScheduledTaskByPath(taskPath, err)) {
            report.removedRegistryValues.append(display + u("(已删除)"));
            QString leaf = taskPath;
            while (leaf.startsWith(QLatin1Char('\\'))) leaf = leaf.mid(1);
            if (!leaf.isEmpty())
                report.hardenedRegTargets.append(u("\\TaskCache\\Tree\\") + leaf);
            log_.warning(u("足迹清理:已删除指向恶意文件的计划任务 ") + taskPath);
        } else {
            report.skipped.append(mkPersistSkip(display, err, QStringLiteral("task"), taskPath));
            log_.warning(u("足迹清理:计划任务删除失败 ") + taskPath + u(" —— ") + err);
        }
    }
    if (seen >= kMaxTaskFiles) {
        log_.warning(u("足迹清理:计划任务目录文件数已达上限 ") + QString::number(kMaxTaskFiles)
                     + u(" 个,本轮未看完 —— 可能有指向恶意文件的任务被漏过。"));
    }
    const QString scope = u("足迹清理:已检查计划任务 ") + QString::number(seen) + u(" 个,命中 ")
                          + QString::number(hit) + u(" 个。");
    if (!g_loggedTaskScope.exchange(true))
        log_.info(scope);
    else
        log_.debug(scope);
}

}

namespace bulwark::service {

RemediationReport ThreatRemediator::cleanupPersistenceEntry(const bulwark::PersistenceEntry& entry) {
    RemediationReport report;
    using PC = bulwark::PersistenceCategory;

    if (entry.category != PC::StartupFolder)
        tryQuarantinePayload(entry, report);

    switch (entry.category) {
        case PC::RegistryRun:
        case PC::RegistryRunOnce: removeRunValue(entry, report); break;
        case PC::IfeoDebugger:    removeIfeoDebugger(entry, report); break;
        case PC::Winlogon:        resetWinlogonValue(entry, report); break;
        case PC::AppInitDll:      clearAppInitDlls(entry, report); break;
        case PC::StartupFolder:   quarantineStartupFile(entry, report); break;
        case PC::ScheduledTask:   deleteScheduledTask(entry, report); break;
        case PC::Service:         disableService(entry, report); break;
        default:
            report.skipped.append(mkSkip(entry.location + QLatin1Char('\\') + entry.name,
                                         u("暂不支持自动清理该类别,请手动处理"), false));
            break;
    }

    if (report.totalActions() > 0)
        log_.warning(u("用户清理自启动项:隔离文件 ") + QString::number(report.quarantinedFiles.size())
                     + u(" 个,处理持久化 ") + QString::number(report.removedRegistryValues.size()) + u(" 项。"));
    return report;
}

void ThreatRemediator::tryQuarantinePayload(const bulwark::PersistenceEntry& entry, RemediationReport& report) {
    const QString path = entry.imagePath;
    if (path.trimmed().isEmpty() || !QFileInfo::exists(path)) return;
    if (isInProtectedZone(path)) {
        report.skipped.append(mkSkip(path, u("位于系统/安装目录,保护不动(仅移除自启动挂钩)"), true));
        return;
    }
    const QString hash = QuarantineManager::tryComputeSha256(path);
    const auto q = quarantine_.quarantine(path, u("用户手动清理自启动项载荷"), 0, hash);
    if (q.has_value() && q->originalRemoved) {
        report.quarantinedFiles.append(path);
    } else if (q.has_value()) {
        report.skipped.append(mkSkip(
            path,
            q->deleteOnRebootScheduled
                ? u("已保存隔离副本,但原文件仍在;已计划重启删除")
                : u("已保存隔离副本,但原文件删除及重启调度均失败"),
            true));
    } else {
        report.skipped.append(mkSkip(path, u("隔离失败(可能被占用)"), true));
    }
}

void ThreatRemediator::removeRunValue(const bulwark::PersistenceEntry& entry, RemediationReport& report) {
    RegHive hive; QString subKey;
    if (!tryParseHive(entry.location, hive, subKey)) {
        report.skipped.append(mkSkip(entry.location + QLatin1Char('\\') + entry.name, u("无法解析注册表位置"), false));
        return;
    }
    const QString valueName = entry.name;
    bool removed = false, sawValue = false;
    for (RegView view : { RegView::Registry64, RegView::Registry32 }) {
        HKEY hk = openKey(hive, subKey, view, KEY_READ | KEY_SET_VALUE);
        if (hk) {
            bool exists = false;
            for (const QString& n : enumValueNames(hk))
                if (n.compare(valueName, Qt::CaseInsensitive) == 0) { exists = true; break; }
            if (exists) {
                sawValue = true;
                const LSTATUS st = RegDeleteValueW(hk, wstr(valueName));
                if (st == ERROR_SUCCESS) removed = true;
                else if (st == ERROR_ACCESS_DENIED && RegSurgery::forceDeleteValue(hive, subKey, valueName, view)) removed = true;
            }
            RegCloseKey(hk);
        } else if (RegSurgery::forceDeleteValue(hive, subKey, valueName, view)) {
            sawValue = true; removed = true;
        }
    }
    if (removed) report.removedRegistryValues.append(entry.location + QLatin1Char('\\') + valueName);
    else if (sawValue) report.skipped.append(mkPersistSkip(entry.location + QLatin1Char('\\') + entry.name,
             u("受 ACL 保护,删除失败(建议手动删除)"), QStringLiteral("regValue"), entry.location, valueName));
    else report.skipped.append(mkSkip(entry.location + QLatin1Char('\\') + entry.name,
             u("值不存在(可能已被移除)"), false));
}

void ThreatRemediator::removeIfeoDebugger(const bulwark::PersistenceEntry& entry, RemediationReport& report) {
    RegHive hive; QString subKey;
    if (!tryParseHive(entry.location, hive, subKey)) {
        report.skipped.append(mkSkip(entry.location + QLatin1Char('\\') + entry.name, u("无法解析注册表位置"), false));
        return;
    }
    bool removed = false, sawValue = false;
    HKEY hk = openKey(hive, subKey, RegView::Registry64, KEY_READ | KEY_SET_VALUE);
    if (hk) {
        if (RegQueryValueExW(hk, L"Debugger", nullptr, nullptr, nullptr, nullptr) == ERROR_SUCCESS) {
            sawValue = true;
            const LSTATUS st = RegDeleteValueW(hk, L"Debugger");
            if (st == ERROR_SUCCESS) removed = true;
            else if (st == ERROR_ACCESS_DENIED &&
                     RegSurgery::forceDeleteValue(hive, subKey, QStringLiteral("Debugger"), RegView::Registry64))
                removed = true;
        }
        RegCloseKey(hk);
    } else if (RegSurgery::forceDeleteValue(hive, subKey, QStringLiteral("Debugger"), RegView::Registry64)) {
        sawValue = true; removed = true;
    }
    if (removed) report.removedRegistryValues.append(entry.location + u("\\Debugger"));
    else report.skipped.append(mkSkip(entry.location + QLatin1Char('\\') + entry.name,
             sawValue ? u("受 ACL 保护,删除失败(建议手动删除)") : u("Debugger 值不存在(可能已被移除)"), false));
}

}

namespace bulwark::service {

void ThreatRemediator::resetWinlogonValue(const bulwark::PersistenceEntry& entry, RemediationReport& report) {
    RegHive hive; QString subKey;
    if (!tryParseHive(entry.location, hive, subKey)) {
        report.skipped.append(mkSkip(entry.location + QLatin1Char('\\') + entry.name, u("无法解析注册表位置"), false));
        return;
    }
    const QString valueName = entry.name;
    QString def;
    if (valueName.compare(QLatin1String("Userinit"), Qt::CaseInsensitive) == 0) {
        wchar_t sysdir[MAX_PATH] = {};
        GetSystemDirectoryW(sysdir, MAX_PATH);
        def = QString::fromWCharArray(sysdir) + u("\\userinit.exe,");
    } else if (valueName.compare(QLatin1String("Shell"), Qt::CaseInsensitive) == 0) {
        def = QStringLiteral("explorer.exe");
    } else {
        report.skipped.append(mkSkip(entry.location + QLatin1Char('\\') + entry.name,
                                     u("未知 Winlogon 值,未改动(避免破坏登录)"), false));
        return;
    }
    HKEY hk = openKey(hive, subKey, RegView::Registry64, KEY_SET_VALUE);
    if (!hk) { report.skipped.append(mkSkip(entry.location + QLatin1Char('\\') + entry.name, u("Winlogon 键不可写"), false)); return; }
    const QByteArray data(reinterpret_cast<const char*>(def.utf16()),
                          static_cast<int>((def.size() + 1) * sizeof(ushort)));
    const LSTATUS st = RegSetValueExW(hk, wstr(valueName), 0, REG_SZ,
                                      reinterpret_cast<const BYTE*>(data.constData()),
                                      static_cast<DWORD>(data.size()));
    RegCloseKey(hk);
    if (st == ERROR_SUCCESS)
        report.removedRegistryValues.append(entry.location + QLatin1Char('\\') + valueName + u("(已重置为默认:") + def + u(")"));
    else
        report.skipped.append(mkSkip(entry.location + QLatin1Char('\\') + entry.name, u("重置失败"), false));
}

void ThreatRemediator::clearAppInitDlls(const bulwark::PersistenceEntry& entry, RemediationReport& report) {
    RegHive hive; QString subKey;
    if (!tryParseHive(entry.location, hive, subKey)) {
        report.skipped.append(mkSkip(entry.location + QLatin1Char('\\') + entry.name, u("无法解析注册表位置"), false));
        return;
    }
    bool cleared = false;
    for (RegView view : { RegView::Registry64, RegView::Registry32 }) {
        HKEY hk = openKey(hive, subKey, view, KEY_READ | KEY_SET_VALUE);
        if (!hk) continue;
        const QString cur = readString(hk, QStringLiteral("AppInit_DLLs"));
        if (!cur.isEmpty()) {
            const wchar_t empty[1] = { L'\0' };
            if (RegSetValueExW(hk, L"AppInit_DLLs", 0, REG_SZ,
                               reinterpret_cast<const BYTE*>(empty), sizeof(empty)) == ERROR_SUCCESS)
                cleared = true;
            DWORD zero = 0;
            RegSetValueExW(hk, L"LoadAppInit_DLLs", 0, REG_DWORD,
                           reinterpret_cast<const BYTE*>(&zero), sizeof(zero));
        }
        RegCloseKey(hk);
    }
    if (cleared) report.removedRegistryValues.append(entry.location + u("\\AppInit_DLLs(已清空)"));
    else report.skipped.append(mkSkip(entry.location + QLatin1Char('\\') + entry.name, u("清空失败或已为空"), false));
}

void ThreatRemediator::quarantineStartupFile(const bulwark::PersistenceEntry& entry, RemediationReport& report) {
    QString path = !entry.imagePath.trimmed().isEmpty() ? entry.imagePath : entry.command;
    if (path.trimmed().isEmpty() || !QFileInfo::exists(path)) {
        report.skipped.append(mkSkip(
            path.trimmed().isEmpty() ? (entry.location + QLatin1Char('\\') + entry.name) : path,
            u("启动项文件不存在(可能已被移除)"), true));
        return;
    }
    const QString hash = QuarantineManager::tryComputeSha256(path);
    const auto q = quarantine_.quarantine(path, u("用户手动清理启动文件夹项"), 0, hash);
    if (q.has_value() && q->originalRemoved) {
        report.quarantinedFiles.append(path);
    } else if (q.has_value()) {
        report.skipped.append(mkSkip(
            path,
            q->deleteOnRebootScheduled
                ? u("已保存隔离副本,但启动项文件仍在;已计划重启删除")
                : u("已保存隔离副本,但启动项文件删除及重启调度均失败"),
            true));
    } else {
        report.skipped.append(mkSkip(path, u("隔离失败(可能被占用)"), true));
    }
}

bool parseAutostartRegValue(const QString& rawTarget, QString& location, QString& valueName) {
    QString t = rawTarget.trimmed();
    if (t.isEmpty()) return false;
    t.replace(QLatin1Char('/'), QLatin1Char('\\'));
    while (t.contains(QLatin1String("\\\\")))
        t.replace(QLatin1String("\\\\"), QLatin1String("\\"));

    if (t.startsWith(QLatin1String("\\REGISTRY\\USER\\"), Qt::CaseInsensitive)) {
        const QString body = t.mid(QStringLiteral("\\REGISTRY\\USER\\").size());
        const int sl = body.indexOf(QLatin1Char('\\'));
        if (sl <= 0 || sl + 1 >= body.size()) return false;
        location = QStringLiteral("HKU\\") + body.left(sl) + QLatin1Char('\\') + body.mid(sl + 1);
    } else if (t.startsWith(QLatin1String("\\REGISTRY\\MACHINE\\"), Qt::CaseInsensitive)) {
        location = QStringLiteral("HKLM\\")
            + t.mid(QStringLiteral("\\REGISTRY\\MACHINE\\").size());
    } else if (t.startsWith(QLatin1String("HKEY_CURRENT_USER\\"), Qt::CaseInsensitive)) {
        location = QStringLiteral("HKCU\\")
            + t.mid(QStringLiteral("HKEY_CURRENT_USER\\").size());
    } else if (t.startsWith(QLatin1String("HKEY_LOCAL_MACHINE\\"), Qt::CaseInsensitive)) {
        location = QStringLiteral("HKLM\\")
            + t.mid(QStringLiteral("HKEY_LOCAL_MACHINE\\").size());
    } else if (t.startsWith(QLatin1String("HKEY_USERS\\"), Qt::CaseInsensitive)) {
        location = QStringLiteral("HKU\\") + t.mid(QStringLiteral("HKEY_USERS\\").size());
    } else if (t.startsWith(QLatin1String("HKCU\\"), Qt::CaseInsensitive)
               || t.startsWith(QLatin1String("HKLM\\"), Qt::CaseInsensitive)
               || t.startsWith(QLatin1String("HKU\\"), Qt::CaseInsensitive)) {
        location = t;
    } else if (t.contains(QLatin1String("\\Run\\"), Qt::CaseInsensitive)
               || t.contains(QLatin1String("\\RunOnce\\"), Qt::CaseInsensitive)
               || t.contains(QLatin1String("\\Policies\\Explorer\\Run\\"), Qt::CaseInsensitive)) {
        location = QStringLiteral("HKCU\\") + t;
    } else {
        return false;
    }

    const char* needles[] = {
        "\\Policies\\Explorer\\Run\\",
        "\\RunOnce\\",
        "\\Run\\",
    };
    for (const char* needle : needles) {
        const QString n = QString::fromLatin1(needle);
        const int idx = location.lastIndexOf(n, -1, Qt::CaseInsensitive);
        if (idx < 0) continue;
        const int valAt = idx + n.size();
        if (valAt >= location.size()) return false;
        valueName = location.mid(valAt);
        location = location.left(idx + n.size() - 1);
        return !valueName.isEmpty();
    }
    return false;
}

bool ThreatRemediator::undoBlockedWrite(const bulwark::SecurityEvent& e, RemediationReport& report) {
    using bulwark::EventType;
    if (e.type == EventType::RegistryWrite) {
        QString location, valueName;
        if (!parseAutostartRegValue(e.target, location, valueName))
            return false;
        bulwark::PersistenceEntry pe;
        pe.location = location;
        pe.name = valueName;
        pe.category = location.contains(QLatin1String("RunOnce"), Qt::CaseInsensitive)
            ? bulwark::PersistenceCategory::RegistryRunOnce
            : bulwark::PersistenceCategory::RegistryRun;
        removeRunValue(pe, report);
        return report.removedRegistryValues.size() > 0;
    }
    if (e.type == EventType::FileWrite) {
        QString path = e.target.trimmed();
        if (path.isEmpty()) return false;
        path.replace(QLatin1Char('/'), QLatin1Char('\\'));
        const QString low = path.toLower();
        const bool startup = low.contains(QLatin1String("\\start menu\\programs\\startup\\"));
        const bool taskDef = low.contains(QLatin1String("\\system32\\tasks\\"));
        if (!startup && !taskDef)
            return false;
        if (!QFileInfo::exists(path)) {
            report.skipped.append(mkSkip(path, u("目标侧撤销:文件已不存在"), true));
            return false;
        }
        const QString hash = QuarantineManager::tryComputeSha256(path);
        const auto q = quarantine_.quarantine(
            path, startup ? u("拦截后撤销:启动文件夹投放")
                          : u("拦截后撤销:计划任务定义"),
            0, hash);
        if (q.has_value() && q->originalRemoved) {
            report.quarantinedFiles.append(path);
            return true;
        }
        if (q.has_value()) {
            report.skipped.append(mkSkip(
                path,
                q->deleteOnRebootScheduled
                    ? u("目标侧撤销仅部分完成:已保存副本,但文件仍在;已计划重启删除")
                    : u("目标侧撤销仅部分完成:已保存副本,但文件删除及重启调度均失败"),
                true));
            return false;
        }
        report.skipped.append(mkSkip(path, u("目标侧撤销:隔离失败(可能被占用或受保护路径拒删)"), true));
        return false;
    }
    return false;
}

void ThreatRemediator::deleteScheduledTask(const bulwark::PersistenceEntry& entry, RemediationReport& report) {
    QString name = QString(entry.name).replace(QLatin1Char('/'), QLatin1Char('\\'));
    while (name.startsWith(QLatin1Char('\\'))) name = name.mid(1);
    const QString tn = QStringLiteral("\\") + name;
    const auto r = runProcess(QStringLiteral("schtasks.exe"),
                              { QStringLiteral("/delete"), QStringLiteral("/tn"), tn, QStringLiteral("/f") });
    if (r.first == 0) {
        report.removedRegistryValues.append(u("计划任务 ") + tn + u("(已删除)"));
    } else {
        const QString extra = r.second.trimmed().isEmpty() ? QString() : (u(":") + r.second.trimmed());
        report.skipped.append(mkSkip(u("计划任务 ") + tn,
            u("schtasks 失败(退出码 ") + QString::number(r.first) + u(")") + extra, false));
    }
}

void ThreatRemediator::disableService(const bulwark::PersistenceEntry& entry, RemediationReport& report) {
    const QString name = entry.name;
    runProcess(QStringLiteral("sc.exe"), { QStringLiteral("stop"), name });
    HKEY hk = openKey(RegHive::LocalMachine,
                      u("SYSTEM\\CurrentControlSet\\Services\\") + name, RegView::Default, KEY_SET_VALUE);
    if (!hk) {
        report.skipped.append(mkSkip(u("服务 ") + name, u("服务键不存在或不可写"), false));
        return;
    }
    DWORD four = 4;
    const LSTATUS st = RegSetValueExW(hk, L"Start", 0, REG_DWORD,
                                      reinterpret_cast<const BYTE*>(&four), sizeof(four));
    RegCloseKey(hk);
    if (st == ERROR_SUCCESS)
        report.removedRegistryValues.append(u("服务 ") + name + u("(已停止并禁用,可在服务管理器恢复)"));
    else
        report.skipped.append(mkSkip(u("服务 ") + name, u("禁用失败"), false));
}

QString ThreatRemediator::forceProtectedReason(const QString& path) {
    return forceProtectedReasonImpl(path);
}

std::pair<bool, QString> ThreatRemediator::forceRemoveFile(const QString& path) {
    if (!QFileInfo::exists(path))
        return { false, u("文件不存在(可能已被移动或删除)") };

    const QString hash = QuarantineManager::tryComputeSha256(path);
    const auto entry = quarantine_.quarantine(path, u("用户强制处理(清理报告)"), 0, hash, true);
    if (entry.has_value()) {
        if (entry->originalRemoved) {
            log_.warning(u("强制处理:已隔离 ") + path);
            return { true, u("已移入隔离区(可在隔离区还原)") };
        }
        const QString msg = entry->deleteOnRebootScheduled
            ? u("已制作可还原副本;原文件仍被占用,已计划在下次重启时删除")
            : u("已制作可还原副本;但原文件删除及重启删除调度均失败");
        log_.warning(u("强制处理仅部分完成:") + path + u(" · ") + msg);
        return { false, msg };
    }

    // 整条读取阶梯都失败(内核读也不行):做不出金库副本。用户已确认「不可还原也要清掉」,直接删。
    const auto [deleted, note] = quarantine_.forceDelete(path);
    if (deleted) {
        log_.warning(u("强制处理:无法制作可还原副本,已直接删除 ") + path);
        return { true, u("无法制作可还原副本,已直接删除(不可还原)") };
    }
    log_.warning(u("强制处理:未能立即删除 ") + path + u(" —— ") + note);
    return { false, note.isEmpty() ? u("删除失败(文件可能被内核级占用或受保护)") : note };
}

std::pair<bool, QString> ThreatRemediator::forceRemovePersistence(const QString& kind, const QString& location,
                                                                  const QString& name,
                                                                  RemediationReport& report) {
    if (kind == QLatin1String("task")) {
        QString taskPath = location.trimmed();
        taskPath.replace(QLatin1Char('/'), QLatin1Char('\\'));
        while (taskPath.startsWith(QLatin1Char('\\'))) taskPath = taskPath.mid(1);
        if (taskPath.isEmpty())
            return { false, u("任务路径为空") };
        if (taskPath.startsWith(QLatin1String("Microsoft\\"), Qt::CaseInsensitive))
            return { false, u("拒绝删除:\\Microsoft\\ 下是 Windows 自带任务") };
        const QString full = QStringLiteral("\\") + taskPath;
        QString err;
        bool ok = deleteScheduledTaskByPath(full, err);
        if (!ok) {
            const auto r = runProcess(QStringLiteral("schtasks.exe"),
                                      { QStringLiteral("/delete"), QStringLiteral("/tn"), full, QStringLiteral("/f") });
            ok = (r.first == 0);
            if (!ok)
                err += u(";schtasks 退出码 ") + QString::number(r.first)
                       + (r.second.trimmed().isEmpty() ? QString() : (u(":") + r.second.trimmed()));
        }
        if (!ok)
            return { false, u("删除计划任务失败:") + err };
        report.removedRegistryValues.append(u("计划任务 ") + full + u("(强制删除)"));
        report.hardenedRegTargets.append(u("\\TaskCache\\Tree\\") + taskPath);
        log_.warning(u("强制处理:已删除计划任务 ") + full);
        return { true, u("已删除计划任务 ") + full };
    }

    RegHive hive;
    QString subKey;
    if (!tryParseHive(location, hive, subKey) || subKey.isEmpty() || name.trimmed().isEmpty())
        return { false, u("无法解析注册表位置") };
    const QString lowKey = subKey.toLower();
    const RegView view = viewForSubKey(subKey);
    const QString display = location + QLatin1Char('\\') + name;

    if (kind == QLatin1String("regValue")) {
        const bool runKey = lowKey.endsWith(QLatin1String("\\currentversion\\run"))
                         || lowKey.endsWith(QLatin1String("\\currentversion\\runonce"))
                         || lowKey.endsWith(QLatin1String("\\policies\\explorer\\run"));
        const bool ifeo = lowKey.contains(QLatin1String("\\image file execution options\\"))
                       && name.compare(QLatin1String("Debugger"), Qt::CaseInsensitive) == 0;
        if (!runKey && !ifeo)
            return { false, u("拒绝:只能强制删除 Run / RunOnce / IFEO Debugger 位置的值") };

        bool removed = false;
        if (HKEY hk = openKey(hive, subKey, view, KEY_SET_VALUE)) {
            const LSTATUS st = RegDeleteValueW(hk, wstr(name));
            removed = (st == ERROR_SUCCESS || st == ERROR_FILE_NOT_FOUND);
            RegCloseKey(hk);
        }
        if (!removed)
            removed = RegSurgery::forceDeleteValue(hive, subKey, name, view);
        if (!removed)
            return { false, u("夺取所有权后仍删除失败(可能被内核驱动或篡改保护锁定)") };
        report.removedRegistryValues.append(display + u("(强制删除)"));
        report.hardenedRegTargets.append(subKey + QLatin1Char('\\') + name);
        log_.warning(u("强制处理:已删除注册表值 ") + display);
        return { true, u("已删除 ") + display };
    }

    if (kind == QLatin1String("regKey")) {
        if (hive != RegHive::LocalMachine
            || lowKey != QLatin1String("system\\currentcontrolset\\services")
            || name.contains(QLatin1Char('\\')))
            return { false, u("拒绝:只能强制删除 Services 下的服务键") };
        {
            QString imagePath, serviceDll;
            if (HKEY sk = openKey(hive, subKey + QLatin1Char('\\') + name, RegView::Default, KEY_READ)) {
                imagePath = readString(sk, QStringLiteral("ImagePath"));
                RegCloseKey(sk);
            }
            if (HKEY pk = openKey(hive, subKey + QLatin1Char('\\') + name + u("\\Parameters"), RegView::Default, KEY_READ)) {
                serviceDll = readString(pk, QStringLiteral("ServiceDll"));
                RegCloseKey(pk);
            }
            auto isWindowsImage = [](QString p) {
                p = expandEnvVars(p.remove(QLatin1Char('"'))).trimmed().toLower();
                p.replace(QLatin1Char('/'), QLatin1Char('\\'));
                if (p.startsWith(QLatin1String("\\systemroot\\")) || p.startsWith(QLatin1String("system32\\")))
                    return true;
                const QString root = qEnvironmentVariable("SystemRoot", QStringLiteral("C:\\Windows")).toLower() + u("\\");
                return p.startsWith(root) && !p.startsWith(root + u("temp\\"));
            };
            const bool dllIsWindows = !serviceDll.isEmpty() && isWindowsImage(serviceDll);
            const bool imgIsWindows = !imagePath.isEmpty() && isWindowsImage(imagePath);
            if (serviceDll.isEmpty() ? imgIsWindows : dllIsWindows)
                return { false, u("拒绝:该服务的映像位于 Windows 系统目录,是系统服务或驱动") };
        }
        runProcess(QStringLiteral("sc.exe"), { QStringLiteral("stop"), name });
        bool removed = false;
        if (HKEY parent = openKey(hive, subKey, RegView::Default, KEY_READ | DELETE)) {
            const LSTATUS st = RegDeleteTreeW(parent, wstr(name));
            removed = (st == ERROR_SUCCESS || st == ERROR_FILE_NOT_FOUND);
            RegCloseKey(parent);
        }
        if (!removed)
            removed = RegSurgery::forceDeleteSubKeyTree(hive, subKey, name, RegView::Default);
        if (!removed)
            return { false, u("夺取所有权后仍删除失败(可能被内核驱动或篡改保护锁定)") };
        report.removedRegistryValues.append(display + u("(强制删除)"));
        report.hardenedRegTargets.append(u("\\Services\\") + name + QLatin1Char('\\'));
        log_.warning(u("强制处理:已删除服务 ") + display);
        return { true, u("已删除服务 ") + name + u("(重启后彻底失效)") };
    }

    return { false, u("不支持的残留项类型:") + kind };
}

}
