#include "bulwark/service/InstallerDetect.h"
#include "bulwark/models/SecurityEvent.h"

#include <QDir>
#include <QFileInfo>
#include <QStringList>

#include <vector>

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

namespace bulwark::service {

namespace {

QString normLower(const QString& s) {
    QString t = QDir::cleanPath(s.trimmed());
    t.replace(QLatin1Char('/'), QLatin1Char('\\'));
    return t.toLower();
}

QString firstMsiArg(const QString& cmdLine) {
    QStringList tokens;
    QString cur;
    bool inQuote = false;
    for (const QChar ch : cmdLine) {
        if (ch == QLatin1Char('"')) { inQuote = !inQuote; continue; }
        if (ch.isSpace() && !inQuote) {
            if (!cur.isEmpty()) { tokens << cur; cur.clear(); }
            continue;
        }
        cur += ch;
    }
    if (!cur.isEmpty())
        tokens << cur;
    for (const QString& t : tokens) {
        const QString low = t.toLower();
        if (low.endsWith(QLatin1String(".msi")) || low.endsWith(QLatin1String(".msp")))
            return t;
    }
    return QString();
}

bool isSystemOrInstalledLocation(const QString& pathLow) {
    const auto under = [&pathLow](QString root) {
        root = normLower(root);
        return !root.isEmpty() && pathLow.startsWith(root + QLatin1Char('\\'));
    };
    const QString windows = qEnvironmentVariable("SystemRoot", QStringLiteral("C:/Windows"));
    const QString programFiles = qEnvironmentVariable("ProgramFiles");
    const QString programFilesX86 = qEnvironmentVariable("ProgramFiles(x86)");
    if (under(programFiles) || under(programFilesX86))
        return true;
    const QString windowsLow = normLower(windows);
    if (!windowsLow.isEmpty() && pathLow.startsWith(windowsLow + QLatin1Char('\\'))
        && !pathLow.startsWith(windowsLow + QStringLiteral("\\temp\\")))
        return true;
    return false;
}

bool isStagingLocation(const QString& pathLow) {
    return pathLow.contains(QLatin1String("\\downloads\\"))
        || pathLow.contains(QLatin1String("\\desktop\\"))
        || pathLow.contains(QLatin1String("\\appdata\\local\\temp\\"))
        || pathLow.contains(QLatin1String("\\appdata\\roaming\\"))
        || pathLow.contains(QLatin1String("\\windows\\temp\\"))
        || pathLow.contains(QLatin1String("\\programdata\\"))
        || pathLow.contains(QLatin1String("\\users\\public\\"));
}

bool textLooksLikeInstaller(const QString& low) {
    if (low.isEmpty())
        return false;
    const bool hasInstall = low.contains(QLatin1String("install"))
                            && !low.contains(QLatin1String("uninstall"));
    if (hasInstall)
        return true;
    static const char* kNeedles[] = {
        "setup", "inno setup", "nullsoft", "nsis", "installshield", "install shield",
        "wixtoolset", "wix toolset", "windows installer", "advanced installer",
        "installaware", "setup factory", "installanywhere", "squirrel",
        "\xe5\xae\x89\xe8\xa3\x85",
    };
    for (const char* n : kNeedles)
        if (low.contains(QLatin1String(n)))
            return true;
    return false;
}

struct VerStrings {
    QString productName;
    QString fileDescription;
    QString originalFilename;
};

VerStrings readVersionStrings(const QString& path) {
    VerStrings out;
    if (path.isEmpty())
        return out;

    using GetSizeFn = DWORD(WINAPI*)(LPCWSTR, LPDWORD);
    using GetFn = BOOL(WINAPI*)(LPCWSTR, DWORD, DWORD, LPVOID);
    using QueryFn = BOOL(WINAPI*)(LPCVOID, LPCWSTR, LPVOID*, PUINT);
    struct Api { GetSizeFn size = nullptr; GetFn get = nullptr; QueryFn query = nullptr; };
    static const Api api = [] {
        Api a;
        if (HMODULE m = ::LoadLibraryExW(L"version.dll", nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32)) {
            a.size  = reinterpret_cast<GetSizeFn>(::GetProcAddress(m, "GetFileVersionInfoSizeW"));
            a.get   = reinterpret_cast<GetFn>(::GetProcAddress(m, "GetFileVersionInfoW"));
            a.query = reinterpret_cast<QueryFn>(::GetProcAddress(m, "VerQueryValueW"));
        }
        return a;
    }();
    if (!api.size || !api.get || !api.query)
        return out;

    const wchar_t* wpath = reinterpret_cast<const wchar_t*>(path.utf16());
    DWORD dummy = 0;
    const DWORD sz = api.size(wpath, &dummy);
    if (sz == 0 || sz > 4u * 1024 * 1024)
        return out;
    std::vector<BYTE> buf(sz, 0);
    if (!api.get(wpath, 0, sz, buf.data()))
        return out;

    struct LangCp { WORD lang; WORD cp; };
    LangCp* trans = nullptr;
    UINT transBytes = 0;
    QString block = QStringLiteral("040904b0");
    if (api.query(buf.data(), L"\\VarFileInfo\\Translation",
                  reinterpret_cast<void**>(&trans), &transBytes)
        && trans && transBytes >= sizeof(LangCp)) {
        block = QStringLiteral("%1%2")
                    .arg(static_cast<uint>(trans->lang), 4, 16, QLatin1Char('0'))
                    .arg(static_cast<uint>(trans->cp), 4, 16, QLatin1Char('0'));
    }

    const auto field = [&](const QString& name) -> QString {
        const QString sub = QStringLiteral("\\StringFileInfo\\%1\\%2").arg(block, name);
        wchar_t* val = nullptr;
        UINT len = 0;
        if (api.query(buf.data(), reinterpret_cast<const wchar_t*>(sub.utf16()),
                      reinterpret_cast<void**>(&val), &len)
            && val && len > 0)
            return QString::fromWCharArray(val, static_cast<int>(len)).trimmed();
        return QString();
    };
    out.productName      = field(QStringLiteral("ProductName"));
    out.fileDescription  = field(QStringLiteral("FileDescription"));
    out.originalFilename = field(QStringLiteral("OriginalFilename"));
    return out;
}

QString displayNameFromFile(const QString& baseName) {
    QString n = QFileInfo(baseName).completeBaseName();
    n.replace(QLatin1Char('_'), QLatin1Char(' '));
    n.replace(QLatin1Char('-'), QLatin1Char(' '));
    return n.trimmed();
}

}

QString originalFileNameOutsideInstallDirs(const QString& path) {
    if (path.isEmpty() || path.startsWith(QLatin1String("PID "), Qt::CaseInsensitive))
        return QString();
    if (isSystemOrInstalledLocation(normLower(path)))
        return QString();
    QString name = readVersionStrings(path).originalFilename.toLower();
    if (name.endsWith(QLatin1String(".mui")))
        name.chop(4);
    return name;
}

bool looksLikeInstaller(const bulwark::SecurityEvent& e, QString* displayName) {
    const auto setName = [displayName](const QString& n) {
        if (displayName && !n.trimmed().isEmpty())
            *displayName = n.trimmed();
    };

    if (e.type != bulwark::EventType::ProcessCreate)
        return false;

    const QString path = e.actorPath;
    if (path.isEmpty() || path.startsWith(QLatin1String("PID "), Qt::CaseInsensitive))
        return false;

    const QString pathLow = normLower(path);
    const QString base = QFileInfo(path).fileName();
    const QString baseLow = base.toLower();

    if (baseLow == QLatin1String("msiexec.exe")) {
        const QString msi = firstMsiArg(e.commandLine);
        if (!msi.isEmpty()) {
            setName(displayNameFromFile(QFileInfo(msi).fileName()));
            return true;
        }
        return false;
    }

    if (isSystemOrInstalledLocation(pathLow))
        return false;

    if (textLooksLikeInstaller(baseLow)) {
        setName(displayNameFromFile(base));
        return true;
    }

    if (isStagingLocation(pathLow)) {
        const VerStrings v = readVersionStrings(path);
        const QString hay = (v.productName + QLatin1Char(' ') + v.fileDescription
                             + QLatin1Char(' ') + v.originalFilename).toLower();
        if (textLooksLikeInstaller(hay)) {
            if (!v.productName.isEmpty())
                setName(v.productName);
            else if (!v.fileDescription.isEmpty())
                setName(v.fileDescription);
            else
                setName(displayNameFromFile(base));
            return true;
        }
    }

    return false;
}

}
