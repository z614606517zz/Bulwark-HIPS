#pragma once
#include <QString>
#include <QDateTime>
#include <QJsonObject>
#include "bulwark/models/Enums.h"

namespace bulwark {

struct SecurityEvent;

struct ChainEventInfo {
    QDateTime timestampUtc;
    EventType type = EventType::ProcessCreate;
    int actorPid = 0;
    int parentPid = 0;
    QString actorPath;
    QString commandLine;
    QString target;
    int riskScore = 0;
    ProcessOriginKind originKind = ProcessOriginKind::Unknown;
    QString originLabel;

    static ChainEventInfo from(const SecurityEvent& e);

    QJsonObject toJson() const;
    static ChainEventInfo fromJson(const QJsonObject& o);
};

}
