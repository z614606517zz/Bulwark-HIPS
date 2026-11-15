#pragma once

namespace bulwark::ipc {

enum class IpcMessageType {
    PromptRequest = 0,
    PromptResponse,
    LogEntry,
    BlockNotification,
    Hello,
    RulesRequest,
    RulesResponse,
    DeleteRule,
    AddRule,
    SettingsRequest,
    SettingsResponse,
    SettingsUpdate,
    TrustListRequest,
    TrustListResponse,
    AddTrust,
    RemoveTrust,
    ReservedVtQueryRequest,
    ReservedVtQueryResponse,
    QuarantineListRequest,
    QuarantineListResponse,
    QuarantineRestore,
    QuarantineDelete,
    QuarantineActionResult,

    ReservedBehaviorSessionStart,
    ReservedBehaviorSessionResult,
    ReservedBehaviorSessionEnd,
    ReservedSlot26,
    ReservedSlot27,

    ReservedAiScanRequest,
    ReservedAiScanResponse,
    RemediationReport,
    ManualQuarantineRequest,
    ManualQuarantineResponse,
    PersistenceListRequest,
    PersistenceListResponse,
    EventLogEntry,
    ReservedVtScanUpdate,
    ReservedVtHistoryRequest,
    ReservedVtHistoryResponse,
    IntelRefreshRequest,
    IntelRefreshResponse,
    IntelApplyRequest,
    IntelApplyResponse,
    PersistenceCleanupRequest,
    PersistenceCleanupResponse,
    EventHistoryRequest,
    EventHistoryResponse,
    EventHistoryClearRequest,
    ReservedVtDetailRequest,
    ReservedVtDetailResponse,

    EventTimelineRequest,
    EventTimelineResponse,
    AttackGraphRequest,
    AttackGraphResponse,

    ProcessListRequest,
    ProcessListResponse,
    ProcessActionRequest,
    ProcessActionResponse,

    ReservedAttackChainRequest,
    ReservedAttackChainResponse,
    ReservedAttackChainClearRequest,
    ReservedAttackChainHitNotification,

    ReservedUpdateCheckRequest,
    ReservedUpdateCheckResponse,
    ReservedUpdateDownloadRequest,
    ReservedUpdateProgressNotification,
    ReservedUpdateDownloadResponse,

    ReservedJunkScanRequest,
    ReservedJunkScanResponse,
    ReservedJunkCleanRequest,
    ReservedJunkCleanResponse,
    ReservedJunkProgressNotification,

    ReservedUpdateApplyRequest,
    ReservedUpdateApplyResponse,

    ReservedLargeFileScanRequest,
    ReservedLargeFileScanResponse,

    ReservedDriverSignRequest,
    ReservedDriverSignResponse,

    ReservedAiShareUploadNotification,

    // 保留、不再使用:旧版服务的「AI 全权裁决」代答后用它收回弹窗。序号由下面的 static_assert 固定,不能删。
    PromptWithdrawNotification,

    HardeningStatusRequest,
    HardeningStatusResponse,
    HardeningActionRequest,
    HardeningActionResponse,
    HijackAlertNotification,

    NetTrafficSubscribe,
    NetTrafficSnapshot,

    ReservedSlot87,

    SystemBoostRequest,
    SystemBoostResponse,

    ReservedSlot90,
    ReservedSlot91,
    ReservedSlot92,
    ReservedSlot93,

    YaraRulesStatusRequest,
    YaraRulesStatusResponse,
    YaraRulesActionRequest,
    YaraRulesActionResponse,
};

static_assert(static_cast<int>(IpcMessageType::ReservedBehaviorSessionStart) == 23);
static_assert(static_cast<int>(IpcMessageType::ReservedAiScanRequest) == 28);
static_assert(static_cast<int>(IpcMessageType::RemediationReport) == 30);
static_assert(static_cast<int>(IpcMessageType::ReservedVtQueryRequest) == 16);
static_assert(static_cast<int>(IpcMessageType::ReservedVtScanUpdate) == 36);
static_assert(static_cast<int>(IpcMessageType::IntelRefreshRequest) == 39);
static_assert(static_cast<int>(IpcMessageType::ReservedVtDetailRequest) == 48);
static_assert(static_cast<int>(IpcMessageType::EventTimelineRequest) == 50);
static_assert(static_cast<int>(IpcMessageType::ProcessActionResponse) == 57);
static_assert(static_cast<int>(IpcMessageType::ReservedAttackChainRequest) == 58);
static_assert(static_cast<int>(IpcMessageType::ReservedAttackChainHitNotification) == 61);
static_assert(static_cast<int>(IpcMessageType::ReservedUpdateCheckRequest) == 62);
static_assert(static_cast<int>(IpcMessageType::ReservedUpdateDownloadResponse) == 66);
static_assert(static_cast<int>(IpcMessageType::ReservedUpdateApplyRequest) == 72);
static_assert(static_cast<int>(IpcMessageType::ReservedUpdateApplyResponse) == 73);
static_assert(static_cast<int>(IpcMessageType::ReservedLargeFileScanResponse) == 75);
static_assert(static_cast<int>(IpcMessageType::ReservedDriverSignRequest) == 76);
static_assert(static_cast<int>(IpcMessageType::ReservedDriverSignResponse) == 77);
static_assert(static_cast<int>(IpcMessageType::ReservedAiShareUploadNotification) == 78);
static_assert(static_cast<int>(IpcMessageType::PromptWithdrawNotification) == 79);
static_assert(static_cast<int>(IpcMessageType::HardeningStatusRequest) == 80);
static_assert(static_cast<int>(IpcMessageType::HijackAlertNotification) == 84);
static_assert(static_cast<int>(IpcMessageType::NetTrafficSubscribe) == 85);
static_assert(static_cast<int>(IpcMessageType::NetTrafficSnapshot) == 86);
static_assert(static_cast<int>(IpcMessageType::ReservedSlot87) == 87);
static_assert(static_cast<int>(IpcMessageType::SystemBoostRequest) == 88);
static_assert(static_cast<int>(IpcMessageType::SystemBoostResponse) == 89);
static_assert(static_cast<int>(IpcMessageType::ReservedSlot90) == 90);
static_assert(static_cast<int>(IpcMessageType::ReservedSlot91) == 91);
static_assert(static_cast<int>(IpcMessageType::ReservedSlot92) == 92);
static_assert(static_cast<int>(IpcMessageType::ReservedSlot93) == 93);
static_assert(static_cast<int>(IpcMessageType::YaraRulesStatusRequest) == 94);
static_assert(static_cast<int>(IpcMessageType::YaraRulesActionResponse) == 97);
static_assert(static_cast<int>(IpcMessageType::ReservedSlot26) == 26);
static_assert(static_cast<int>(IpcMessageType::ReservedSlot27) == 27);

}
