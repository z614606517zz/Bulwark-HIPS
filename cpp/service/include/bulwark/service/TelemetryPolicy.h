#pragma once
#include <QString>
#include <QSet>

namespace bulwark::service::telemetry_policy {

// High-value hosts need module telemetry even for modules in installation/system
// directories. This is a collection decision, never an automatic threat verdict.
inline bool needsCompleteModuleTelemetry(QString path) {
    path.replace(QLatin1Char('/'), QLatin1Char('\\'));
    const QString name = path.mid(path.lastIndexOf(QLatin1Char('\\')) + 1).toLower();
    static const QSet<QString> hosts = {
        QStringLiteral("lsass.exe"), QStringLiteral("lsaiso.exe"),
        QStringLiteral("winlogon.exe"), QStringLiteral("csrss.exe"),
        QStringLiteral("services.exe"), QStringLiteral("smss.exe"), QStringLiteral("wininit.exe"),
        QStringLiteral("bulwark_service.exe"), QStringLiteral("bulwark_ui.exe"),
        QStringLiteral("wechat.exe"), QStringLiteral("weixin.exe"), QStringLiteral("wxwork.exe"),
        QStringLiteral("qq.exe"), QStringLiteral("tim.exe")
    };
    return hosts.contains(name);
}

} // namespace bulwark::service::telemetry_policy
