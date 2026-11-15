#include "bulwark/service/WorkerDurableExecBlockSeam.h"

namespace bulwark::service {

DurableExecBlockExecution WorkerDurableExecBlockSeam::fromEnforceBlock(
    const bulwark::SecurityEvent& event,
    const std::optional<monitoring::ProcessInspector::ProcessInstance>& current,
    int containmentPid,
    const DurableExecBlockPolicy::PersistFn& persist,
    const DurableExecBlockPolicy::ContainFn& contain)
{
    return DurableExecBlockPolicy::execute(
        true, event, current, DurableExecBlockOrigin::Enforcement,
        containmentPid, DurableExecBlockEffectOrder::PersistThenContain,
        persist, contain);
}

DurableExecBlockExecution WorkerDurableExecBlockSeam::fromLaunchingParent(
    const bulwark::SecurityEvent& event,
    const std::optional<monitoring::ProcessInspector::ProcessInstance>& current,
    const DurableExecBlockPolicy::PersistFn& persist,
    const DurableExecBlockPolicy::ContainFn& contain)
{
    return DurableExecBlockPolicy::execute(
        true, event, current, DurableExecBlockOrigin::LaunchingParent,
        event.actorPid, DurableExecBlockEffectOrder::ContainThenPersist,
        persist, contain);
}

DurableExecBlockExecution WorkerDurableExecBlockSeam::fromSweptMalicious(
    const bulwark::SecurityEvent& event,
    const std::optional<monitoring::ProcessInspector::ProcessInstance>& current,
    const DurableExecBlockPolicy::PersistFn& persist,
    const DurableExecBlockPolicy::ContainFn& contain)
{
    return DurableExecBlockPolicy::execute(
        true, event, current, DurableExecBlockOrigin::MaliciousSweep,
        event.actorPid, DurableExecBlockEffectOrder::ContainThenPersist,
        persist, contain);
}

}
