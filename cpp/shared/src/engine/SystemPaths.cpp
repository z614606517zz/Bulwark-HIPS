#include "bulwark/engine/SystemPaths.h"

#include <QtGlobal>

#ifdef Q_OS_WIN
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#endif

namespace bulwark::engine {

namespace {

QString& driveOverride() {
    static QString s;
    return s;
}

QString detectSystemDrive() {
#ifdef Q_OS_WIN
    wchar_t buf[MAX_PATH] = {};
    const UINT n = ::GetSystemWindowsDirectoryW(buf, MAX_PATH);
    if (n >= 2 && n < MAX_PATH && buf[1] == L':')
        return QString::fromWCharArray(buf, 2).toLower();
#endif
    const QString root = qEnvironmentVariable("SystemRoot");
    if (root.size() >= 2 && root.at(1) == QLatin1Char(':'))
        return root.left(2).toLower();
    return QStringLiteral("c:");
}

}

QString SystemPaths::volumeRelative(const QString& path) {
    if (path.isEmpty()) return path;
    QString p = path;
    p.replace(QLatin1Char('/'), QLatin1Char('\\'));
    if (p.startsWith(QLatin1String("\\\\?\\"))) p = p.mid(4);
    else if (p.startsWith(QLatin1String("\\\\.\\"))) p = p.mid(4);
    if (p.size() >= 2 && p.at(1) == QLatin1Char(':')) return p.mid(2);
    return p;
}

QString SystemPaths::systemDrive() {
    if (!driveOverride().isEmpty())
        return driveOverride();
    static const QString drive = detectSystemDrive();
    return drive;
}

QString SystemPaths::systemVolumeRelative(const QString& path) {
    if (path.isEmpty()) return QString();
    QString p = path;
    p.replace(QLatin1Char('/'), QLatin1Char('\\'));
    if (p.startsWith(QLatin1String("\\\\?\\")) || p.startsWith(QLatin1String("\\\\.\\"))
        || p.startsWith(QLatin1String("\\??\\")))
        p = p.mid(4);
    if (p.size() < 3 || p.at(1) != QLatin1Char(':') || p.at(2) != QLatin1Char('\\'))
        return QString();
    const QString drive = systemDrive();
    if (drive.isEmpty() || p.at(0).toLower() != drive.at(0))
        return QString();
    return p.mid(2);
}

void SystemPaths::setSystemDriveForTest(const QString& drive) {
    driveOverride() = drive.trimmed().left(2).toLower();
}

}
