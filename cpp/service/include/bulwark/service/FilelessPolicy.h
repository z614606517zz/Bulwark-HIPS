#pragma once

#include <QByteArray>
#include <QString>
#include <QStringList>

#include <algorithm>

#include "bulwark/engine/SystemPaths.h"

namespace bulwark::service::fileless_policy {

inline QString imageNameLower(const QString& imagePath)
{
    const QString trimmed = imagePath.trimmed();
    const int slash = std::max(trimmed.lastIndexOf(QLatin1Char('\\')),
                               trimmed.lastIndexOf(QLatin1Char('/')));
    return trimmed.mid(slash + 1).toLower();
}

inline bool isHighRiskMemoryScanHost(const QString& imagePath)
{
    static const QStringList kHosts = {
        QStringLiteral("powershell.exe"),
        QStringLiteral("powershell_ise.exe"),
        QStringLiteral("pwsh.exe"),
        QStringLiteral("wscript.exe"),
        QStringLiteral("cscript.exe"),
        QStringLiteral("mshta.exe"),
        QStringLiteral("rundll32.exe"),
        QStringLiteral("regsvr32.exe"),
    };
    return kHosts.contains(imageNameLower(imagePath));
}

inline bool isUserWritableLaunchPath(const QString& imagePath)
{
    QString path = imagePath.trimmed().toLower();
    path.replace(QLatin1Char('/'), QLatin1Char('\\'));
    if (!path.contains(QLatin1String("\\users\\")))
        return false;
    return path.contains(QLatin1String("\\users\\public\\")) ||
           path.contains(QLatin1String("\\appdata\\local\\temp\\")) ||
           path.contains(QLatin1String("\\downloads\\"));
}

inline bool shouldTargetNewProcess(const QString& imagePath)
{
    return isHighRiskMemoryScanHost(imagePath) || isUserWritableLaunchPath(imagePath);
}

// 扫描器出事件、处置层认出这一项发现,用的是同一句文案。
inline QString unbackedPeFinding()
{
    return QStringLiteral("内存中存在未落地的 PE 映像(反射式 DLL / 手工映射)");
}

// 未落地 PE 只说明载荷在承载方的地址空间里,不说明是谁放进去的:同机安全软件、输入法、录屏与
// 游戏覆盖层都会把自己的模块手工映射进别的进程。承载方签名健康,或装在系统盘的 Windows /
// Program Files 下时只告警。脚本宿主例外:PowerShell 里冒出反射加载的 PE 就是攻击本身。
inline bool mayTerminateUnbackedPeCarrier(const QString& imagePath, bool healthySigned)
{
    if (isHighRiskMemoryScanHost(imagePath))
        return true;
    if (healthySigned)
        return false;
    const QString rel = bulwark::engine::SystemPaths::systemVolumeRelative(imagePath.trimmed()).toLower();
    if (rel.isEmpty() || rel.startsWith(QLatin1String("\\windows\\temp\\")))
        return true;
    return !(rel.startsWith(QLatin1String("\\windows\\"))
             || rel.startsWith(QLatin1String("\\program files\\"))
             || rel.startsWith(QLatin1String("\\program files (x86)\\")));
}

inline bool scanIsCoolingDown(bool urgent,
                              qint64 nowMs,
                              qint64 lastNormalMs,
                              qint64 lastUrgentMs,
                              qint64 normalWindowMs,
                              qint64 urgentWindowMs)
{
    const qint64 lastMs = urgent ? lastUrgentMs : lastNormalMs;
    const qint64 windowMs = urgent ? urgentWindowMs : normalWindowMs;
    return lastMs >= 0 && nowMs >= lastMs && nowMs - lastMs < windowMs;
}

inline bool isKnownBypassStub(const QByteArray& b)
{
    if (b.isEmpty())
        return false;
    const auto u = [&b](int i) -> quint8 {
        return i < b.size() ? static_cast<quint8>(b.at(i)) : 0u;
    };
    if (u(0) == 0xC3)
        return true;
    if (u(0) == 0xB8 && u(1) == 0x57 && u(2) == 0x00 && u(3) == 0x07 && u(4) == 0x80 &&
        (u(5) == 0xC3 || u(5) == 0xC2))
        return true;
    if ((u(0) == 0x31 || u(0) == 0x33) && u(1) == 0xC0 && u(2) == 0xC3)
        return true;
    if (u(0) == 0x48 && (u(1) == 0x31 || u(1) == 0x33) && u(2) == 0xC0 && u(3) == 0xC3)
        return true;
    if (u(0) == 0xB8 && u(1) == 0x00 && u(2) == 0x00 && u(3) == 0x00 && u(4) == 0x00 &&
        u(5) == 0xC3)
        return true;
    return false;
}

}
