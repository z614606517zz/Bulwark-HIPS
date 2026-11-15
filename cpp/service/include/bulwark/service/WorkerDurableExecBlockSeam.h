#pragma once

#include "bulwark/service/DurableExecBlockPolicy.h"

namespace bulwark::service {

class WorkerDurableExecBlockSeam {
public:
    static DurableExecBlockExecution fromEnforceBlock(
        const bulwark::SecurityEvent& event,
        const std::optional<monitoring::ProcessInspector::ProcessInstance>& current,
        int containmentPid,
        const DurableExecBlockPolicy::PersistFn& persist,
        const DurableExecBlockPolicy::ContainFn& contain);

    static DurableExecBlockExecution fromLaunchingParent(
        const bulwark::SecurityEvent& event,
        const std::optional<monitoring::ProcessInspector::ProcessInstance>& current,
        const DurableExecBlockPolicy::PersistFn& persist,
        const DurableExecBlockPolicy::ContainFn& contain);

    static DurableExecBlockExecution fromSweptMalicious(
        const bulwark::SecurityEvent& event,
        const std::optional<monitoring::ProcessInspector::ProcessInstance>& current,
        const DurableExecBlockPolicy::PersistFn& persist,
        const DurableExecBlockPolicy::ContainFn& contain);
};

}
