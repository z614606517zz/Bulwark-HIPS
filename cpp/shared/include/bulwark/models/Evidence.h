#pragma once
#include <QString>
#include <QDateTime>
#include <QJsonObject>
#include "bulwark/models/Enums.h"
#include "bulwark/Clock.h"

namespace bulwark {

enum class EvidenceSubject {
    Actor,
    Target,
};

struct Evidence {
    QDateTime timestampUtc = nowUtc();
    QString source;
    EvidenceKind kind = EvidenceKind::Info;
    QString description;
    int scoreDelta = 0;
    QString technique;
    QString techniqueName;
    EvidenceSubject subject = EvidenceSubject::Actor;

    QJsonObject toJson() const;
    static Evidence fromJson(const QJsonObject& o);
};

}
