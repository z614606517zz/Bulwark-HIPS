#pragma once
#include <QList>
#include <QUuid>
#include "bulwark/models/AttackGraph.h"
#include "bulwark/models/SecurityEvent.h"

namespace bulwark::engine {

class AttackGraphBuilder {
public:
    struct Input {
        bulwark::SecurityEvent event;
        bulwark::VerdictAction action = bulwark::VerdictAction::Allow;
        bulwark::EnforcementOutcome enforcement = bulwark::EnforcementOutcome::NotApplicable;
    };

    struct Options {
        int maxAncestorDepth = 4;
        int maxNodes = 160;
        int maxEdges = 320;
    };

    static bulwark::AttackGraph build(const QList<Input>& events, const QUuid& seedEventId,
                                      int rootPid, const Options& opt = Options{});
};

}
