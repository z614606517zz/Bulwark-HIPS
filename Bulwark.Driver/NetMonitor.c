#include "Driver.h"
#include <ntstrsafe.h>

// fwpsk.h 依赖 NDIS6 类型,必须在包含它之前定义。
#ifndef NDIS_SUPPORT_NDIS6
#define NDIS_SUPPORT_NDIS6 1
#endif

#pragma warning(push)
#pragma warning(disable: 4201)
#include <fwpsk.h>
#include <fwpmk.h>
#pragma warning(pop)

#include <initguid.h>

DEFINE_GUID(BLW_CALLOUT_V4_GUID,
    0xc9a1f7d2, 0x3b6e, 0x4a21, 0x9f, 0x8c, 0x1e, 0x2d, 0x3c, 0x4b, 0x5a, 0x60);
DEFINE_GUID(BLW_SUBLAYER_GUID,
    0xc9a1f7d2, 0x3b6e, 0x4a21, 0x9f, 0x8c, 0x1e, 0x2d, 0x3c, 0x4b, 0x5a, 0x61);
DEFINE_GUID(BLW_CALLOUT_V6_GUID,
    0xc9a1f7d2, 0x3b6e, 0x4a21, 0x9f, 0x8c, 0x1e, 0x2d, 0x3c, 0x4b, 0x5a, 0x62);

void
BlwClearBlockList(void)
{
    KIRQL oldIrql;
    KeAcquireSpinLock(&g_Blw.NetLock, &oldIrql);
    RtlZeroMemory(g_Blw.BlockList, sizeof(g_Blw.BlockList));
    InterlockedExchange(&g_Blw.BlockIpCount, 0);
    InterlockedExchange64(&g_Blw.BlockIpMask, 0);
    KeReleaseSpinLock(&g_Blw.NetLock, oldIrql);
}

void
BlwAddBlockIp(_In_ ULONG IpV4, _In_ USHORT Port)
{
    ULONG i;
    KIRQL oldIrql;
    if (IpV4 == 0) {
        return;
    }
    KeAcquireSpinLock(&g_Blw.NetLock, &oldIrql);
    InterlockedOr64(&g_Blw.BlockIpMask, (LONG64)BLW_IP_BIT(IpV4));
    for (i = 0; i < BLW_MAX_PROTECTED; i++) {
        if (!g_Blw.BlockList[i].InUse) {
            g_Blw.BlockList[i].IsV6 = FALSE;
            g_Blw.BlockList[i].IpV4 = IpV4;
            g_Blw.BlockList[i].Port = Port;
            g_Blw.BlockList[i].InUse = TRUE;
            InterlockedIncrement(&g_Blw.BlockIpCount);
            break;
        }
    }
    KeReleaseSpinLock(&g_Blw.NetLock, oldIrql);
}

BOOLEAN
BlwAddBlockIp6(_In_reads_(32) PCWSTR Hex, _In_ USHORT Port)
{
    UCHAR address[16]; ULONG i; KIRQL irql; BOOLEAN added = FALSE;
    if (!BlwParseIpv6Hex(Hex, 32, address)) return FALSE;
    KeAcquireSpinLock(&g_Blw.NetLock, &irql);
    for (i = 0; i < BLW_MAX_PROTECTED; ++i) {
        if (!g_Blw.BlockList[i].InUse) {
            RtlCopyMemory(g_Blw.BlockList[i].IpV6, address, 16);
            g_Blw.BlockList[i].IsV6 = TRUE;
            g_Blw.BlockList[i].Port = Port;
            g_Blw.BlockList[i].InUse = TRUE;
            InterlockedIncrement(&g_Blw.BlockIpCount); added = TRUE; break;
        }
    }
    KeReleaseSpinLock(&g_Blw.NetLock, irql);
    return added;
}
static BOOLEAN
BlwIp6IsBlocked(_In_reads_(16) const UCHAR* Address, _In_ USHORT Port)
{
    ULONG i; KIRQL irql; BOOLEAN blocked = FALSE;
    if (!g_Blw.BlockIpCount) return FALSE;
    KeAcquireSpinLock(&g_Blw.NetLock, &irql);
    for (i = 0; i < BLW_MAX_PROTECTED; ++i) {
        const BLW_BLOCK_IP* item = &g_Blw.BlockList[i];
        if (item->InUse && item->IsV6 && (item->Port == 0 || item->Port == Port)
            && RtlEqualMemory(item->IpV6, Address, 16)) { blocked = TRUE; break; }
    }
    KeReleaseSpinLock(&g_Blw.NetLock, irql); return blocked;
}

// 每条外发连接的 classify 都会调用(可能在 DISPATCH_LEVEL)。先做无锁位测试,位命中才取锁精确判定。
static BOOLEAN
BlwIpIsBlocked(_In_ ULONG IpV4, _In_ USHORT Port)
{
    ULONG i;
    LONG  count;
    LONG  seen = 0;
    BOOLEAN blocked = FALSE;
    KIRQL oldIrql;

    if (((ULONG64)g_Blw.BlockIpMask & BLW_IP_BIT(IpV4)) == 0) {
        return FALSE;
    }

    KeAcquireSpinLock(&g_Blw.NetLock, &oldIrql);
    count = g_Blw.BlockIpCount;
    for (i = 0; i < BLW_MAX_PROTECTED && seen < count; i++) {
        if (!g_Blw.BlockList[i].InUse) {
            continue;
        }
        seen++;
        if (!g_Blw.BlockList[i].IsV6 && g_Blw.BlockList[i].IpV4 == IpV4 &&
            (g_Blw.BlockList[i].Port == 0 || g_Blw.BlockList[i].Port == Port)) {
            blocked = TRUE;
            break;
        }
    }
    KeReleaseSpinLock(&g_Blw.NetLock, oldIrql);
    return blocked;
}

static void
BlwReportNetEvent(_In_ ULONG actorPid, _In_ ULONG remoteIp, _In_ USHORT remotePort)
{
    if (!g_Blw.Active || KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return;  // 高 IRQL 不上报
    }

    BlwReportEvent(BlwEventNetworkConnect, actorPid, 0u,
                   NULL, NULL, remoteIp, remotePort);
}

static void NTAPI
BlwClassifyFn(
    _In_ const FWPS_INCOMING_VALUES0* inFixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUES0* inMetaValues,
    _Inout_opt_ void* layerData,
    _In_opt_ const void* classifyContext,
    _In_ const FWPS_FILTER2* filter,
    _In_ UINT64 flowContext,
    _Inout_ FWPS_CLASSIFY_OUT0* classifyOut)
{
    ULONG  remoteIp;
    USHORT remotePort;
    ULONG  actorPid = 0;

    UNREFERENCED_PARAMETER(layerData);
    UNREFERENCED_PARAMETER(classifyContext);
    UNREFERENCED_PARAMETER(filter);
    UNREFERENCED_PARAMETER(flowContext);

    InterlockedIncrement64(&g_Blw.WfpClassifyCalls);

    // 没有 FWPS_RIGHT_ACTION_WRITE 时必须保留前一过滤器的 actionType，不能先改成 Permit。
    if ((classifyOut->rights & FWPS_RIGHT_ACTION_WRITE) == 0) {
        InterlockedIncrement64(&g_Blw.WfpRightsCleared);
        return;
    }

    classifyOut->actionType = FWP_ACTION_PERMIT;

    // 已封禁 PID 的任何外联都拒绝,不看目标 IP 和地址族。BlwPidIsBanned 无锁,DISPATCH_LEVEL 可用。
    if (g_Blw.BannedPidCount > 0 && inMetaValues != NULL &&
        FWPS_IS_METADATA_FIELD_PRESENT(inMetaValues, FWPS_METADATA_FIELD_PROCESS_ID)) {
        ULONG connPid = (ULONG)inMetaValues->processId;
        if (connPid != 0 && BlwPidIsBanned(connPid)) {
            classifyOut->actionType = FWP_ACTION_BLOCK;
            classifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE;
            InterlockedIncrement64(&g_Blw.WfpBannedBlocks);
            return;
        }
    }

    if (inFixedValues->layerId == FWPS_LAYER_ALE_AUTH_CONNECT_V6) {
        const FWP_BYTE_ARRAY16* address = inFixedValues->incomingValue[
            FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_REMOTE_ADDRESS].value.byteArray16;
        remotePort = inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_REMOTE_PORT].value.uint16;
        if (address && BlwIp6IsBlocked(address->byteArray16, remotePort)) {
            classifyOut->actionType = FWP_ACTION_BLOCK;
            classifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE;
            InterlockedIncrement64(&g_Blw.WfpIpBlocks);
            if (g_Blw.Active && KeGetCurrentIrql() == PASSIVE_LEVEL) {
                WCHAR text[80]; UNICODE_STRING target;
                const UCHAR* b = address->byteArray16;
                if (inMetaValues && FWPS_IS_METADATA_FIELD_PRESENT(inMetaValues, FWPS_METADATA_FIELD_PROCESS_ID))
                    actorPid = (ULONG)inMetaValues->processId;
                if (NT_SUCCESS(RtlStringCchPrintfW(text, RTL_NUMBER_OF(text),
                    L"[%x:%x:%x:%x:%x:%x:%x:%x]:%u",
                    (b[0]<<8)|b[1], (b[2]<<8)|b[3], (b[4]<<8)|b[5], (b[6]<<8)|b[7],
                    (b[8]<<8)|b[9], (b[10]<<8)|b[11], (b[12]<<8)|b[13], (b[14]<<8)|b[15], remotePort))) {
                    RtlInitUnicodeString(&target, text);
                    BlwReportEvent(BlwEventNetworkConnect6, actorPid, 0, &target, NULL, 0, remotePort);
                }
            }
        }
        return;
    }
    if (inFixedValues->layerId != FWPS_LAYER_ALE_AUTH_CONNECT_V4) {
        return;
    }

    remoteIp = inFixedValues->incomingValue[
        FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_ADDRESS].value.uint32;
    remotePort = inFixedValues->incomingValue[
        FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_PORT].value.uint16;

    if (BlwIpIsBlocked(remoteIp, remotePort)) {
        if (inMetaValues != NULL &&
            FWPS_IS_METADATA_FIELD_PRESENT(inMetaValues, FWPS_METADATA_FIELD_PROCESS_ID)) {
            actorPid = (ULONG)inMetaValues->processId;
        }

        classifyOut->actionType = FWP_ACTION_BLOCK;
        classifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE;
        InterlockedIncrement64(&g_Blw.WfpIpBlocks);

        BlwReportNetEvent(actorPid, remoteIp, remotePort);
        KdPrint(("[Bulwark] Net BLOCK pid=%u ip=0x%08x port=%u\n",
            actorPid, remoteIp, remotePort));
    }
}

static NTSTATUS NTAPI
BlwNotifyFn(
    _In_ FWPS_CALLOUT_NOTIFY_TYPE notifyType,
    _In_ const GUID* filterKey,
    _In_ const FWPS_FILTER2* filter)
{
    UNREFERENCED_PARAMETER(notifyType);
    UNREFERENCED_PARAMETER(filterKey);
    UNREFERENCED_PARAMETER(filter);
    return STATUS_SUCCESS;
}

typedef struct _BLW_WFP_LAYER {
    const GUID* CalloutKey;
    const GUID* LayerKey;
    PCWSTR      CalloutName;
    PCWSTR      FilterName;
} BLW_WFP_LAYER;

static const BLW_WFP_LAYER kBlwWfpLayers[] = {
    { &BLW_CALLOUT_V4_GUID, &FWPM_LAYER_ALE_AUTH_CONNECT_V4,
      L"Bulwark Connect Callout (IPv4)", L"Bulwark Connect Filter (IPv4)" },
    { &BLW_CALLOUT_V6_GUID, &FWPM_LAYER_ALE_AUTH_CONNECT_V6,
      L"Bulwark Connect Callout (IPv6)", L"Bulwark Connect Filter (IPv6)" },
};
C_ASSERT(RTL_NUMBER_OF(kBlwWfpLayers) == BLW_WFP_LAYER_COUNT);

// 不能用 ExAcquireFastMutex:它把 IRQL 提到 APC_LEVEL,而锁内的 Fwp* DDI 和 KeDelayExecutionThread 要求
// PASSIVE_LEVEL(FwpsCalloutRegister 会返回 STATUS_NOT_SUPPORTED)。ERESOURCE 配 KeEnterCriticalRegion
// 不提升 IRQL,独占语义相同。调用前必须先确认 g_Blw.WfpLockReady。
static void
BlwWfpLockAcquire(void)
{
    KeEnterCriticalRegion();
    (void)ExAcquireResourceExclusiveLite(&g_Blw.WfpLock, TRUE);
}

static void
BlwWfpLockRelease(void)
{
    ExReleaseResourceLite(&g_Blw.WfpLock);
    KeLeaveCriticalRegion();
}

// 卸载路径据此决定能否删设备对象:callout 依附于设备对象,残留一个就不能删。
BOOLEAN
BlwWfpHasCallouts(void)
{
    ULONG i;

    for (i = 0; i < BLW_WFP_LAYER_COUNT; i++) {
        if (g_Blw.WfpCalloutIds[i] != 0) {
            return TRUE;
        }
    }
    return FALSE;
}

static NTSTATUS
BlwWfpBringUpLocked(void)
{
    NTSTATUS status;
    FWPM_SUBLAYER subLayer = { 0 };
    BOOLEAN inTxn = FALSE;
    BOOLEAN calloutAddedHere[BLW_WFP_LAYER_COUNT] = { 0 };
    FWPM_SESSION session = { 0 };
    ULONG i;

    if (g_Blw.WfpRegistered) {
        return STATUS_SUCCESS;
    }
    InterlockedIncrement(&g_Blw.WfpBringUpAttempts);
    InterlockedExchange(&g_Blw.WfpLastStage, BLW_WFP_STAGE_NONE);
    InterlockedExchange(&g_Blw.WfpLastStatus, 0);
    InterlockedExchange(&g_Blw.WfpLastLayer, -1);

    if (g_Blw.WfpDeviceObject == NULL) {
        InterlockedExchange(&g_Blw.WfpLastStage, BLW_WFP_STAGE_NO_DEVICE);
        InterlockedExchange(&g_Blw.WfpLastStatus, (LONG)STATUS_DEVICE_NOT_READY);
        return STATUS_DEVICE_NOT_READY;
    }

    for (i = 0; i < BLW_WFP_LAYER_COUNT; i++) {
        FWPS_CALLOUT2 sCallout = { 0 };

        if (g_Blw.WfpCalloutIds[i] != 0) {
            continue;
        }

        sCallout.calloutKey = *kBlwWfpLayers[i].CalloutKey;
        sCallout.classifyFn = BlwClassifyFn;
        sCallout.notifyFn = BlwNotifyFn;
        sCallout.flowDeleteFn = NULL;

        status = FwpsCalloutRegister2(g_Blw.WfpDeviceObject, &sCallout, &g_Blw.WfpCalloutIds[i]);

        if (status == STATUS_FWP_ALREADY_EXISTS) {
            KdPrint(("[Bulwark] Callout GUID (layer %lu) already registered; "
                     "re-registering to recover its id.\n", i));
            (void)FwpsCalloutUnregisterByKey(kBlwWfpLayers[i].CalloutKey);
            g_Blw.WfpCalloutIds[i] = 0;
            status = FwpsCalloutRegister2(g_Blw.WfpDeviceObject, &sCallout,
                                          &g_Blw.WfpCalloutIds[i]);
        }

        if (!NT_SUCCESS(status)) {
            KdPrint(("[Bulwark] FwpsCalloutRegister(layer %lu) failed 0x%x\n", i, status));
            InterlockedExchange(&g_Blw.WfpLastStage, BLW_WFP_STAGE_CALLOUT_REG);
            InterlockedExchange(&g_Blw.WfpLastStatus, (LONG)status);
            InterlockedExchange(&g_Blw.WfpLastLayer, (LONG)i);
            g_Blw.WfpCalloutIds[i] = 0;
            goto cleanup;
        }
        calloutAddedHere[i] = TRUE;
    }

    session.flags = FWPM_SESSION_FLAG_DYNAMIC;

    status = FwpmEngineOpen(NULL, RPC_C_AUTHN_WINNT, NULL, &session, &g_Blw.WfpEngine);
    if (!NT_SUCCESS(status)) {
        KdPrint(("[Bulwark] FwpmEngineOpen failed 0x%x (BFE not ready?)\n", status));
        InterlockedExchange(&g_Blw.WfpLastStage, BLW_WFP_STAGE_ENGINE_OPEN);
        InterlockedExchange(&g_Blw.WfpLastStatus, (LONG)status);
        g_Blw.WfpEngine = NULL;
        goto cleanup;
    }

    status = FwpmTransactionBegin(g_Blw.WfpEngine, 0);
    if (!NT_SUCCESS(status)) {
        InterlockedExchange(&g_Blw.WfpLastStage, BLW_WFP_STAGE_TXN_BEGIN);
        InterlockedExchange(&g_Blw.WfpLastStatus, (LONG)status);
        goto cleanup;
    }
    inTxn = TRUE;

    subLayer.subLayerKey = BLW_SUBLAYER_GUID;
    subLayer.displayData.name = L"Bulwark SubLayer";
    subLayer.flags = 0;
    subLayer.weight = 0xF000;
    status = FwpmSubLayerAdd(g_Blw.WfpEngine, &subLayer, NULL);
    if (!NT_SUCCESS(status)) {
        KdPrint(("[Bulwark] FwpmSubLayerAdd failed 0x%x\n", status));
        InterlockedExchange(&g_Blw.WfpLastStage, BLW_WFP_STAGE_SUBLAYER_ADD);
        InterlockedExchange(&g_Blw.WfpLastStatus, (LONG)status);
        goto cleanup;
    }

    for (i = 0; i < BLW_WFP_LAYER_COUNT; i++) {
        FWPM_CALLOUT mCallout = { 0 };
        FWPM_FILTER  mFilter = { 0 };

        mCallout.calloutKey = *kBlwWfpLayers[i].CalloutKey;
        mCallout.displayData.name = (PWSTR)kBlwWfpLayers[i].CalloutName;
        mCallout.applicableLayer = *kBlwWfpLayers[i].LayerKey;
        status = FwpmCalloutAdd(g_Blw.WfpEngine, &mCallout, NULL, NULL);
        if (!NT_SUCCESS(status)) {
            KdPrint(("[Bulwark] FwpmCalloutAdd(layer %lu) failed 0x%x\n", i, status));
            InterlockedExchange(&g_Blw.WfpLastStage, BLW_WFP_STAGE_CALLOUT_ADD);
            InterlockedExchange(&g_Blw.WfpLastStatus, (LONG)status);
            goto cleanup;
        }

        mFilter.displayData.name = (PWSTR)kBlwWfpLayers[i].FilterName;
        mFilter.layerKey = *kBlwWfpLayers[i].LayerKey;
        mFilter.subLayerKey = BLW_SUBLAYER_GUID;
        mFilter.weight.type = FWP_EMPTY;
        mFilter.action.type = FWP_ACTION_CALLOUT_TERMINATING;
        mFilter.action.calloutKey = *kBlwWfpLayers[i].CalloutKey;
        mFilter.numFilterConditions = 0;

        status = FwpmFilterAdd(g_Blw.WfpEngine, &mFilter, NULL, &g_Blw.WfpFilterIds[i]);
        if (!NT_SUCCESS(status)) {
            KdPrint(("[Bulwark] FwpmFilterAdd(layer %lu) failed 0x%x\n", i, status));
            InterlockedExchange(&g_Blw.WfpLastStage, BLW_WFP_STAGE_FILTER_ADD);
            InterlockedExchange(&g_Blw.WfpLastStatus, (LONG)status);
            goto cleanup;
        }
    }

    status = FwpmTransactionCommit(g_Blw.WfpEngine);
    if (!NT_SUCCESS(status)) {
        InterlockedExchange(&g_Blw.WfpLastStage, BLW_WFP_STAGE_TXN_COMMIT);
        InterlockedExchange(&g_Blw.WfpLastStatus, (LONG)status);
        goto cleanup;
    }
    inTxn = FALSE;

    g_Blw.WfpRegistered = TRUE;
    KdPrint(("[Bulwark] WFP registered on %u layer(s).\n", (ULONG)BLW_WFP_LAYER_COUNT));
    return STATUS_SUCCESS;

cleanup:
    if (inTxn) {
        FwpmTransactionAbort(g_Blw.WfpEngine);
    }
    if (g_Blw.WfpEngine != NULL) {
        FwpmEngineClose(g_Blw.WfpEngine);
        g_Blw.WfpEngine = NULL;
    }

    for (i = 0; i < BLW_WFP_LAYER_COUNT; i++) {
        if (!calloutAddedHere[i] || g_Blw.WfpCalloutIds[i] == 0) {
            continue;
        }
        if (NT_SUCCESS(FwpsCalloutUnregisterById(g_Blw.WfpCalloutIds[i]))) {
            g_Blw.WfpCalloutIds[i] = 0;
        } else {
            KdPrint(("[Bulwark] WFP rollback: callout(layer %lu) still registered, keeping it pinned.\n", i));
        }
    }
    return status;
}

NTSTATUS
BlwWfpRetryBringUp(void)
{
    NTSTATUS status;

    if (g_Blw.WfpRegistered) {
        return STATUS_SUCCESS;
    }
    // 锁内的 Fwp* DDI 要求 PASSIVE_LEVEL。
    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return STATUS_INVALID_DEVICE_STATE;
    }
    if (!g_Blw.WfpLockReady) {
        return STATUS_DEVICE_NOT_READY;   // 锁没建起来,WFP 路径已放弃
    }

    BlwWfpLockAcquire();
    if (g_Blw.WfpUnloading) {
        status = STATUS_DELETE_PENDING;   // 卸载中,不能重注册 callout
    } else {
        status = g_Blw.WfpRegistered ? STATUS_SUCCESS : BlwWfpBringUpLocked();
    }
    BlwWfpLockRelease();
    return status;
}

static void CALLBACK
BlwBfeStateChangeFn(_Inout_ void* context, _In_ FWPM_SERVICE_STATE newState)
{
    UNREFERENCED_PARAMETER(context);

    // 回调在 PASSIVE_LEVEL 触发,所以能在这里取锁并调用 Fwpm*。
    if (!g_Blw.WfpLockReady) {
        return;   // 锁没建起来,WFP 路径已放弃
    }
    BlwWfpLockAcquire();

    if (newState == FWPM_SERVICE_RUNNING) {
        if (!g_Blw.WfpRegistered) {
            NTSTATUS status = BlwWfpBringUpLocked();
            KdPrint(("[Bulwark] BFE running -> WFP bring-up 0x%x\n", status));
            UNREFERENCED_PARAMETER(status);
        }
    } else if (newState == FWPM_SERVICE_STOPPED) {
        g_Blw.WfpEngine = NULL;
        RtlZeroMemory(g_Blw.WfpFilterIds, sizeof(g_Blw.WfpFilterIds));
        g_Blw.WfpRegistered = FALSE;
        KdPrint(("[Bulwark] BFE stopped -> WFP objects gone; will rebuild when it returns.\n"));
    }

    BlwWfpLockRelease();
}

NTSTATUS
BlwWfpStart(_In_ PDEVICE_OBJECT DeviceObject)
{
    NTSTATUS subStatus;
    NTSTATUS upStatus;

    g_Blw.WfpDeviceObject = DeviceObject;

    subStatus = FwpmBfeStateSubscribeChanges(DeviceObject, BlwBfeStateChangeFn,
                                            NULL, &g_Blw.WfpBfeSubscription);
    if (!NT_SUCCESS(subStatus)) {
        KdPrint(("[Bulwark] FwpmBfeStateSubscribeChanges failed 0x%x "
                 "(no deferred bring-up; one-shot attempt only)\n", subStatus));
        g_Blw.WfpBfeSubscription = NULL;
    }

    BlwWfpLockAcquire();
    if (FwpmBfeStateGet() == FWPM_SERVICE_RUNNING) {
        upStatus = BlwWfpBringUpLocked();
    } else {
        upStatus = STATUS_DEVICE_NOT_READY;
        KdPrint(("[Bulwark] BFE not running yet; WFP bring-up deferred to state-change callback.\n"));
    }
    BlwWfpLockRelease();

    if (NT_SUCCESS(subStatus) || NT_SUCCESS(upStatus)) {
        return STATUS_SUCCESS;
    }
    return upStatus;
}

NTSTATUS
BlwUnregisterWfp(void)
{
    NTSTATUS status = STATUS_SUCCESS;
    ULONG    attempt;
    ULONG    layer;

    if (g_Blw.WfpBfeSubscription != NULL) {
        FwpmBfeStateUnsubscribeChanges(g_Blw.WfpBfeSubscription);
        g_Blw.WfpBfeSubscription = NULL;
        KdPrint(("[Bulwark] BFE state subscription removed.\n"));
    }

    // 锁没建起来说明 WFP 从未启动,没有东西要拆;必须返回成功,否则卸载会被拒绝。
    if (!g_Blw.WfpLockReady) {
        g_Blw.WfpRegistered = FALSE;
        return STATUS_SUCCESS;
    }

    BlwWfpLockAcquire();
    g_Blw.WfpUnloading = TRUE;

    // 不能只看 WfpRegistered:BFE 未就绪时它为 FALSE,但内核 callout 可能已经注册。
    if (g_Blw.WfpEngine == NULL && !BlwWfpHasCallouts()) {
        g_Blw.WfpRegistered = FALSE;
        BlwWfpLockRelease();
        return STATUS_SUCCESS;
    }

    if (g_Blw.WfpEngine != NULL) {
        FwpmEngineClose(g_Blw.WfpEngine);
        g_Blw.WfpEngine = NULL;
    }

    for (layer = 0; layer < BLW_WFP_LAYER_COUNT; layer++) {
        NTSTATUS one = STATUS_SUCCESS;

        if (g_Blw.WfpCalloutIds[layer] == 0) {
            continue;
        }

        for (attempt = 0; ; attempt++) {
            one = FwpsCalloutUnregisterById(g_Blw.WfpCalloutIds[layer]);
            if (one != STATUS_DEVICE_BUSY || attempt >= BLW_WFP_UNREG_RETRIES) {
                break;
            }
            {
                LARGE_INTEGER delay;
                delay.QuadPart = -(LONGLONG)BLW_WFP_UNREG_DELAY_MS * 10 * 1000;
                KeDelayExecutionThread(KernelMode, FALSE, &delay);
            }
        }

        if (NT_SUCCESS(one)) {
            g_Blw.WfpCalloutIds[layer] = 0;
        } else {
            KdPrint(("[Bulwark] FwpsCalloutUnregisterById(layer %lu) failed 0x%x after %u retries; "
                     "unload must be refused.\n", layer, one, attempt));
            status = one;
        }
    }

    if (!NT_SUCCESS(status)) {
        BlwWfpLockRelease();
        return status;
    }

    g_Blw.WfpRegistered = FALSE;
    BlwWfpLockRelease();
    KdPrint(("[Bulwark] WFP unregistered.\n"));
    return STATUS_SUCCESS;
}
