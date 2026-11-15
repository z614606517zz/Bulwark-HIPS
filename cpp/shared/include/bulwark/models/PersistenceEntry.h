#pragma once
#include <QString>
#include <QStringList>
#include <QJsonObject>
#include <optional>

namespace bulwark {

enum class PersistenceCategory {
    RegistryRun = 0,
    RegistryRunOnce,
    StartupFolder,
    ScheduledTask,
    Service,
    WmiSubscription,
    IfeoDebugger,
    Winlogon,
    AppInitDll,
    Other,
};

struct PersistenceEntry {
    QString id;
    PersistenceCategory category = PersistenceCategory::Other;
    QString name;
    QString location;
    QString command;
    QString imagePath;
    std::optional<bool> isSigned;
    QString publisher;
    int riskScore = 0;
    QStringList riskReasons;
    QStringList techniques;

    QJsonObject toJson() const;
    static PersistenceEntry fromJson(const QJsonObject& o);
};

}
