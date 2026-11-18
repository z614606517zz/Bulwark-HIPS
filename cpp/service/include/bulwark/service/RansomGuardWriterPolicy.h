#pragma once
#include "bulwark/engine/SystemPaths.h"
#include "bulwark/engine/TrustPolicy.h"
#include "bulwark/models/SecurityEvent.h"
#include <QSet>

namespace bulwark::service::ransom_writer_policy {

// Only a small set of installed document editors may be enrolled automatically.
// Other applications use explicit user/deployment authorizations.
inline bool canEnrollDocumentWriter(const bulwark::SecurityEvent& e) {
    if (!e.actorSigned || e.signatureMismatch || e.certRevoked || e.signedAfterCertExpiry
        || bulwark::engine::TrustPolicy::isAbusedSigner(e).ok)
        return false;
    QString path = e.actorPath.toLower();
    path.replace(QLatin1Char('/'), QLatin1Char('\\'));
    const QString relative = bulwark::engine::SystemPaths::systemVolumeRelative(path);
    if (!relative.startsWith(QLatin1String("\\program files\\"))
        && !relative.startsWith(QLatin1String("\\program files (x86)\\")))
        return false;
    const QString name = path.mid(path.lastIndexOf(QLatin1Char('\\')) + 1);
    const QString publisher = e.actorPublisher.trimmed();
    static const QSet<QString> office = {
        QStringLiteral("winword.exe"), QStringLiteral("excel.exe"),
        QStringLiteral("powerpnt.exe"), QStringLiteral("msaccess.exe"), QStringLiteral("outlook.exe")
    };
    static const QSet<QString> wps = {
        QStringLiteral("wps.exe"), QStringLiteral("et.exe"), QStringLiteral("wpp.exe")
    };
    static const QSet<QString> adobe = {
        QStringLiteral("acrobat.exe"), QStringLiteral("acrord32.exe"), QStringLiteral("photoshop.exe")
    };
    if (office.contains(name))
        return publisher.compare(QStringLiteral("Microsoft Corporation"), Qt::CaseInsensitive) == 0;
    if (wps.contains(name))
        return publisher.startsWith(QLatin1String("Kingsoft"), Qt::CaseInsensitive)
            || publisher.startsWith(QStringLiteral("珠海金山"));
    if (adobe.contains(name))
        return publisher.compare(QStringLiteral("Adobe Inc."), Qt::CaseInsensitive) == 0
            || publisher.compare(QStringLiteral("Adobe Inc"), Qt::CaseInsensitive) == 0
            || publisher.startsWith(QLatin1String("Adobe Systems Incorporated"), Qt::CaseInsensitive);
    return false;
}

} // namespace bulwark::service::ransom_writer_policy
