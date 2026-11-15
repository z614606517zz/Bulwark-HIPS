#pragma once
#include <QMap>
#include <QMutex>
#include <QMutexLocker>
#include <QString>

#include <vector>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

namespace bulwark::service::volumepath {

// miss 后最快多久重建一次:调用方包括内核事件读线程,必须快进快出,不能每个事件做一次卷枚举。
inline constexpr quint64 kVolumeMapRefreshMs = 10000;

inline QMap<QString, QString> buildVolumeDeviceMap() {
    QMap<QString, QString> map;

    wchar_t volName[MAX_PATH] = {};
    const HANDLE find = ::FindFirstVolumeW(volName, MAX_PATH);
    if (find == INVALID_HANDLE_VALUE)
        return map;

    do {
        const QString guidPath = QString::fromWCharArray(volName);
        if (!guidPath.startsWith(QLatin1String("\\\\?\\")))
            continue;
        QString guidName = guidPath.mid(4);
        while (guidName.endsWith(QLatin1Char('\\')))
            guidName.chop(1);
        if (guidName.isEmpty())
            continue;

        wchar_t device[1024] = {};
        if (::QueryDosDeviceW(reinterpret_cast<const wchar_t*>(guidName.utf16()), device, 1024) == 0)
            continue;
        const QString devicePath = QString::fromWCharArray(device);
        if (devicePath.isEmpty())
            continue;

        QString win32;
        std::vector<wchar_t> names(1024);
        DWORD used = 0;
        if (::GetVolumePathNamesForVolumeNameW(volName, names.data(),
                                               static_cast<DWORD>(names.size()), &used) != 0) {
            for (const wchar_t* p = names.data(); *p != L'\0'; p += wcslen(p) + 1) {
                const QString mount = QString::fromWCharArray(p);
                if (mount.size() >= 2 && mount.at(1) == QLatin1Char(':')) {
                    win32 = mount.left(2);
                    break;
                }
            }
        }
        if (win32.isEmpty())
            win32 = guidPath.chopped(1);

        map.insert(devicePath, win32);
    } while (::FindNextVolumeW(find, volName, MAX_PATH) != 0);

    ::FindVolumeClose(find);
    return map;
}

inline QString resolveInVolumeMap(const QMap<QString, QString>& map, const QString& raw) {
    for (auto it = map.constBegin(); it != map.constEnd(); ++it) {
        const qsizetype n = it.key().size();
        if (raw.size() < n || !raw.startsWith(it.key(), Qt::CaseInsensitive))
            continue;
        // 卷名后面必须是路径分隔符,或者整条路径就是卷名本身(裸卷)。
        if (raw.size() == n || raw.at(n) == QLatin1Char('\\'))
            return it.value() + raw.mid(n);
    }
    return QString();
}

inline QString deviceToWin32Path(const QString& raw) {
    static QMutex mutex;
    static QMap<QString, QString> map;
    static quint64 builtTick = 0;
    static bool built = false;

    QMutexLocker lock(&mutex);

    if (!built) {
        map = buildVolumeDeviceMap();
        builtTick = ::GetTickCount64();
        built = true;
    }

    const QString hit = resolveInVolumeMap(map, raw);
    if (!hit.isEmpty())
        return hit;

    const quint64 now = ::GetTickCount64();
    if (now - builtTick < kVolumeMapRefreshMs)
        return QString();

    map = buildVolumeDeviceMap();
    builtTick = now;
    return resolveInVolumeMap(map, raw);
}

}
