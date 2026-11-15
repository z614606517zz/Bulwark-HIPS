#pragma once
#include "bulwark/ipc/Payloads.h"

namespace bulwark::service {

class EventHistoryStore;

namespace ForensicsService {

bulwark::ipc::TimelineResponsePayload queryTimeline(EventHistoryStore& history,
                                                    const bulwark::ipc::TimelineRequestPayload& req);

bulwark::ipc::AttackGraphResponsePayload buildAttackGraph(
    EventHistoryStore& history, const bulwark::ipc::AttackGraphRequestPayload& req);

}

}
