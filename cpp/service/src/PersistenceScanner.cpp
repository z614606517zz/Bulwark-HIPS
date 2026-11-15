#include "bulwark/service/PersistenceScanner.h"
#include "bulwark/service/RegistryUtil.h"
#include "bulwark/service/monitoring/ProcessInspector.h"
#include "bulwark/engine/PersistenceAnalyzer.h"

#include <QCryptographicHash>
#include <QDateTime>
#include <QDir>
#include <QDirIterator>
#include <QFile>
#include <QFileInfo>
#include <QRegularExpression>
#include <QSet>
#include <QString>
#include <QStringList>

#include <algorithm>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

namespace bulwark::service {
using bulwark::PersistenceCategory;
using bulwark::PersistenceEntry;
using bulwark::ipc::PersistenceListResponsePayload;
using bulwark::service::monitoring::ProcessInspector;

namespace {

QString expandEnv(const QString& p) {
    if (p.isEmpty()) return p;
    wchar_t buf[1024] = {};
    const DWORD n = ::ExpandEnvironmentStringsW(reinterpret_cast<LPCWSTR>(p.utf16()), buf, 1024);
    if (n == 0 || n > 1024) return p;
    return QString::fromWCharArray(buf);
}

QString extractImagePath(const QString& command) {
    QString c = command.trimmed();
    if (c.isEmpty()) return QString();
    QString path;
    if (c.startsWith(QLatin1Char('"'))) {
        const int end = c.indexOf(QLatin1Char('"'), 1);
        path = end > 1 ? c.mid(1, end - 1) : QString(c).remove(QLatin1Char('"'));
    } else {
        static const QRegularExpression re(
            QStringLiteral("^(.*?\\.(?:exe|dll|sys|com|bat|cmd|scr))(?:\\s|$)"),
            QRegularExpression::CaseInsensitiveOption);
        const QRegularExpressionMatch m = re.match(c);
        path = m.hasMatch() ? m.captured(1) : c.section(QLatin1Char(' '), 0, 0);
    }
    path = path.replace(QStringLiteral("\\??\\"), QString()).trimmed();
    return expandEnv(path);
}

QString regReadString(HKEY key, const wchar_t* valueName) {
    DWORD type = 0, cb = 0;
    if (::RegQueryValueExW(key, valueName, nullptr, &type, nullptr, &cb) != ERROR_SUCCESS)
        return QString();
    if ((type != REG_SZ && type != REG_EXPAND_SZ) || cb == 0)
        return QString();
    QByteArray buf(static_cast<int>(cb) + 2, '\0');
    if (::RegQueryValueExW(key, valueName, nullptr, &type,
                           reinterpret_cast<LPBYTE>(buf.data()), &cb) != ERROR_SUCCESS)
        return QString();
    QString s = QString::fromWCharArray(reinterpret_cast<const wchar_t*>(buf.constData()));
    return (type == REG_EXPAND_SZ) ? expandEnv(s) : s;
}

HKEY openKey(HKEY hive, const wchar_t* sub, REGSAM extra = 0) {
    HKEY h = nullptr;
    if (::RegOpenKeyExW(hive, sub, 0, KEY_READ | extra, &h) != ERROR_SUCCESS)
        return nullptr;
    return h;
}

void scanRunKey(HKEY hive, const wchar_t* sub, REGSAM view, PersistenceCategory cat,
                const QString& hiveDisplay, const QString& subDisplay,
                QList<PersistenceEntry>& out) {
    HKEY key = openKey(hive, sub, view);
    if (!key) return;
    DWORD idx = 0;
    wchar_t nameBuf[16384];
    for (;;) {
        DWORD nameLen = 16384, type = 0, cb = 0;
        LONG r = ::RegEnumValueW(key, idx++, nameBuf, &nameLen, nullptr, &type, nullptr, &cb);
        if (r == ERROR_NO_MORE_ITEMS) break;
        if (r != ERROR_SUCCESS && r != ERROR_MORE_DATA) break;
        const QString name = QString::fromWCharArray(nameBuf, static_cast<int>(nameLen));
        const QString cmd = regReadString(key, name.isEmpty() ? nullptr
                                                              : reinterpret_cast<LPCWSTR>(name.utf16()));
        if (cmd.trimmed().isEmpty()) continue;
        PersistenceEntry e;
        e.category = cat;
        e.name = name;
        e.location = hiveDisplay + QStringLiteral("\\") + subDisplay;
        e.command = cmd;
        e.imagePath = extractImagePath(cmd);
        out.append(e);
    }
    ::RegCloseKey(key);
}

}

}

namespace bulwark::service {
namespace {

QString profilePathForSid(const QString& sid) {
    const regutil::Value v = regutil::readValue(
        regutil::Hive::Machine,
        QStringLiteral("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList\\") + sid,
        QStringLiteral("ProfileImagePath"));
    return v.present && v.supported ? expandEnv(v.text).trimmed() : QString();
}

void scanStartupFolders(QList<PersistenceEntry>& out) {
    QStringList folders;
    const QString progData = qEnvironmentVariable("ProgramData");
    if (!progData.isEmpty())
        folders << QDir(progData).filePath(QStringLiteral("Microsoft/Windows/Start Menu/Programs/Startup"));
    for (const QString& sid : regutil::interactiveUserSids()) {
        const QString profile = profilePathForSid(sid);
        if (!profile.isEmpty())
            folders << QDir(profile).filePath(QStringLiteral("AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup"));
    }
    folders.removeDuplicates();
    for (const QString& folder : folders) {
        QDir dir(folder);
        if (!dir.exists()) continue;
        const QFileInfoList files = dir.entryInfoList(QDir::Files | QDir::NoDotAndDotDot);
        for (const QFileInfo& fi : files) {
            PersistenceEntry e;
            e.category = PersistenceCategory::StartupFolder;
            e.name = fi.fileName();
            e.location = folder;
            e.command = fi.absoluteFilePath();
            e.imagePath = fi.suffix().compare(QStringLiteral("lnk"), Qt::CaseInsensitive) == 0
                              ? QString() : fi.absoluteFilePath();
            out.append(e);
        }
    }
}

void scanServices(QList<PersistenceEntry>& out) {
    HKEY root = openKey(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services", KEY_WOW64_64KEY);
    if (!root) return;
    DWORD idx = 0;
    wchar_t nameBuf[512];
    for (;;) {
        DWORD nameLen = 512;
        LONG r = ::RegEnumKeyExW(root, idx++, nameBuf, &nameLen, nullptr, nullptr, nullptr, nullptr);
        if (r == ERROR_NO_MORE_ITEMS) break;
        if (r != ERROR_SUCCESS) break;
        const QString svc = QString::fromWCharArray(nameBuf, static_cast<int>(nameLen));
        HKEY k = nullptr;
        if (::RegOpenKeyExW(root, nameBuf, 0, KEY_READ | KEY_WOW64_64KEY, &k) != ERROR_SUCCESS)
            continue;
        const QString imagePath = regReadString(k, L"ImagePath");
        DWORD start = 3, type = 0, cb = sizeof(DWORD);
        ::RegQueryValueExW(k, L"Start", nullptr, &type, reinterpret_cast<LPBYTE>(&start), &cb);
        ::RegCloseKey(k);
        if (imagePath.trimmed().isEmpty() || start == 4) continue;
        PersistenceEntry e;
        e.category = PersistenceCategory::Service;
        e.name = svc;
        e.location = QStringLiteral("HKLM\\SYSTEM\\CurrentControlSet\\Services\\") + svc;
        e.command = imagePath;
        e.imagePath = extractImagePath(imagePath);
        out.append(e);
    }
    ::RegCloseKey(root);
}

void scanIfeo(QList<PersistenceEntry>& out) {
    const wchar_t* ifeo = L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options";
    HKEY root = openKey(HKEY_LOCAL_MACHINE, ifeo, KEY_WOW64_64KEY);
    if (!root) return;
    DWORD idx = 0;
    wchar_t nameBuf[512];
    for (;;) {
        DWORD nameLen = 512;
        LONG r = ::RegEnumKeyExW(root, idx++, nameBuf, &nameLen, nullptr, nullptr, nullptr, nullptr);
        if (r == ERROR_NO_MORE_ITEMS) break;
        if (r != ERROR_SUCCESS) break;
        const QString img = QString::fromWCharArray(nameBuf, static_cast<int>(nameLen));
        HKEY k = nullptr;
        if (::RegOpenKeyExW(root, nameBuf, 0, KEY_READ | KEY_WOW64_64KEY, &k) != ERROR_SUCCESS)
            continue;
        const QString debugger = regReadString(k, L"Debugger");
        ::RegCloseKey(k);
        if (debugger.trimmed().isEmpty()) continue;
        PersistenceEntry e;
        e.category = PersistenceCategory::IfeoDebugger;
        e.name = img;
        e.location = QStringLiteral("HKLM\\") + QString::fromWCharArray(ifeo) + QStringLiteral("\\") + img;
        e.command = debugger;
        e.imagePath = extractImagePath(debugger);
        out.append(e);
    }
    ::RegCloseKey(root);
}

void scanWinlogon(QList<PersistenceEntry>& out) {
    const wchar_t* sub = L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon";
    HKEY k = openKey(HKEY_LOCAL_MACHINE, sub, KEY_WOW64_64KEY);
    if (!k) return;
    for (const wchar_t* val : { L"Userinit", L"Shell" }) {
        const QString cmd = regReadString(k, val);
        if (cmd.trimmed().isEmpty()) continue;
        PersistenceEntry e;
        e.category = PersistenceCategory::Winlogon;
        e.name = QString::fromWCharArray(val);
        e.location = QStringLiteral("HKLM\\") + QString::fromWCharArray(sub);
        e.command = cmd;
        e.imagePath = extractImagePath(cmd);
        out.append(e);
    }
    ::RegCloseKey(k);
}

void scanAppInit(QList<PersistenceEntry>& out) {
    const wchar_t* sub = L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows";
    for (REGSAM view : { KEY_WOW64_64KEY, KEY_WOW64_32KEY }) {
        HKEY k = openKey(HKEY_LOCAL_MACHINE, sub, view);
        if (!k) continue;
        const QString dlls = regReadString(k, L"AppInit_DLLs");
        ::RegCloseKey(k);
        if (dlls.trimmed().isEmpty()) continue;
        PersistenceEntry e;
        e.category = PersistenceCategory::AppInitDll;
        e.name = QStringLiteral("AppInit_DLLs");
        e.location = QStringLiteral("HKLM\\") + QString::fromWCharArray(sub);
        e.command = dlls;
        e.imagePath = extractImagePath(dlls);
        out.append(e);
    }
}

QString between(const QString& s, const QString& a, const QString& b) {
    const int i = s.indexOf(a, 0, Qt::CaseInsensitive);
    if (i < 0) return QString();
    const int from = i + a.size();
    const int j = s.indexOf(b, from, Qt::CaseInsensitive);
    return j < 0 ? QString() : s.mid(from, j - from).trimmed();
}

void scanScheduledTasks(QList<PersistenceEntry>& out) {
    const QString windir = qEnvironmentVariable("SystemRoot", QStringLiteral("C:\\Windows"));
    const QString tasksRoot = windir + QStringLiteral("\\System32\\Tasks");
    QDir root(tasksRoot);
    if (!root.exists()) return;
    QDirIterator it(tasksRoot, QDir::Files, QDirIterator::Subdirectories);
    while (it.hasNext()) {
        const QString file = it.next();
        QFile f(file);
        if (!f.open(QIODevice::ReadOnly)) continue;
        const QString xml = QString::fromUtf8(f.readAll());
        f.close();
        if (xml.isEmpty() || !xml.contains(QStringLiteral("<Exec"))) continue;
        const QString cmd = between(xml, QStringLiteral("<Command>"), QStringLiteral("</Command>"));
        if (cmd.trimmed().isEmpty()) continue;
        const QString args = between(xml, QStringLiteral("<Arguments>"), QStringLiteral("</Arguments>"));
        const QString full = args.isEmpty() ? cmd : (cmd + QLatin1Char(' ') + args);
        QString image = expandEnv(QString(cmd).trimmed().remove(QLatin1Char('"')));
        QString taskName = QDir(tasksRoot).relativeFilePath(file);
        PersistenceEntry e;
        e.category = PersistenceCategory::ScheduledTask;
        e.name = taskName;
        e.location = QStringLiteral("\\") + taskName;
        e.command = full;
        e.imagePath = QFileInfo::exists(image) ? image : extractImagePath(full);
        out.append(e);
    }
}

QString makeId(const PersistenceEntry& e) {
    const QString raw = QStringLiteral("%1|%2|%3|%4")
        .arg(static_cast<int>(e.category)).arg(e.location, e.name, e.command);
    const QByteArray h = QCryptographicHash::hash(raw.toUtf8(), QCryptographicHash::Sha256);
    return QString::fromLatin1(h.left(8).toHex()).toUpper();
}

}

PersistenceListResponsePayload PersistenceScanner::scan() {
    QList<PersistenceEntry> entries;
    QStringList notes;

    struct RunKey { const wchar_t* sub; QString disp; PersistenceCategory cat; };
    const RunKey machineRunKeys[] = {
        { L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
          QStringLiteral("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"), PersistenceCategory::RegistryRun },
        { L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
          QStringLiteral("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce"), PersistenceCategory::RegistryRunOnce },
    };
    for (const RunKey& rk : machineRunKeys) {
        for (REGSAM view : { KEY_WOW64_64KEY, KEY_WOW64_32KEY })
            scanRunKey(HKEY_LOCAL_MACHINE, rk.sub, view, rk.cat,
                       QStringLiteral("HKLM"), rk.disp, entries);
    }

    const QStringList userSids = regutil::interactiveUserSids();
    for (const QString& sid : userSids) {
        for (const RunKey& rk : machineRunKeys) {
            const QString userSub = sid + QLatin1Char('\\') + rk.disp;
            for (REGSAM view : { KEY_WOW64_64KEY, KEY_WOW64_32KEY }) {
                scanRunKey(HKEY_USERS, reinterpret_cast<const wchar_t*>(userSub.utf16()),
                           view, rk.cat, QStringLiteral("HKU\\") + sid, rk.disp, entries);
            }
        }
    }

    scanStartupFolders(entries);
    scanServices(entries);
    scanIfeo(entries);
    scanWinlogon(entries);
    scanAppInit(entries);
    scanScheduledTasks(entries);

    QList<PersistenceEntry> unique;
    QSet<QString> seen;
    for (PersistenceEntry& e : entries) {
        try {
            if (!e.imagePath.isEmpty() && QFileInfo::exists(e.imagePath)) {
                e.isSigned = ProcessInspector::isSigned(e.imagePath);
                e.publisher = ProcessInspector::tryGetPublisher(e.imagePath);
            }
            bulwark::engine::PersistenceAnalyzer::analyze(e);
        } catch (...) {}
        e.id = makeId(e);
        if (seen.contains(e.id)) continue;
        seen.insert(e.id);
        unique.append(e);
    }

    std::sort(unique.begin(), unique.end(), [](const PersistenceEntry& a, const PersistenceEntry& b) {
        if (a.riskScore != b.riskScore) return a.riskScore > b.riskScore;
        return static_cast<int>(a.category) < static_cast<int>(b.category);
    });

    PersistenceListResponsePayload payload;
    payload.scannedUtc = QDateTime::currentDateTimeUtc();
    payload.entries = unique;
    payload.message = QStringLiteral("共 %1 项").arg(unique.size());
    return payload;
}

}
