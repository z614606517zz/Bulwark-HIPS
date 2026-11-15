#pragma once
#include <QUuid>
#include <QJsonObject>
#include "bulwark/models/Enums.h"

namespace bulwark {

struct SecurityEvent;

struct Verdict {
    QUuid eventId;
    VerdictAction action = VerdictAction::Allow;
    VerdictSource source = VerdictSource::DefaultPolicy;
    bool remember = false;

    static Verdict forEvent(const SecurityEvent& e, VerdictAction action,
                            VerdictSource source, bool remember = false);

    QJsonObject toJson() const;
    static Verdict fromJson(const QJsonObject& o);
};

}
