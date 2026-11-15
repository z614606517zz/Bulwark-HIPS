#pragma once

#include "bulwark/models/Enums.h"

namespace bulwark::service::event_routing_policy {

[[nodiscard]] constexpr bool suppressBaseWhenKernelConnected(bulwark::EventType type) noexcept
{
    switch (type) {
    case bulwark::EventType::ProcessCreate:
        return true;
    case bulwark::EventType::ProcessTerminate:
        return false; // 驱动不产出结束进程事件,只能来自 ETW 审计 API,压掉就一条都没有了。
    case bulwark::EventType::ImageLoad:
        return false; // 驱动只覆盖高风险路径，保留 ETW 全量并在协调器跨源去重。
    default:
        return false;
    }
}

}
