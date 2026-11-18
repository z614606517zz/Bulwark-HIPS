#include "Driver.h"

BLW_GLOBALS g_Blw = { 0 };

DRIVER_INITIALIZE DriverEntry;

void
BlwInitPools(void)
{
    NTSTATUS a, b, c;

    a = ExInitializeLookasideListEx(&g_Blw.MatchCtxPool, NULL, NULL, NonPagedPoolNx, 0,
                                    sizeof(BLW_MATCH_CTX), BLW_TAG, 0);
    b = ExInitializeLookasideListEx(&g_Blw.RegScratchPool, NULL, NULL, NonPagedPoolNx, 0,
                                    sizeof(BLW_REG_SCRATCH), BLW_TAG, 0);
    c = ExInitializeLookasideListEx(&g_Blw.EventPathPool, NULL, NULL, NonPagedPoolNx, 0,
                                    BLW_EVENT_PATHS_BYTES, BLW_TAG, 0);
    if (NT_SUCCESS(a) && NT_SUCCESS(b) && NT_SUCCESS(c)) {
        g_Blw.PoolsReady = TRUE;
        return;
    }
    KdPrint(("[Bulwark] Lookaside init failed (0x%x 0x%x 0x%x); name matching will be skipped.\n", a, b, c));
    if (NT_SUCCESS(a)) ExDeleteLookasideListEx(&g_Blw.MatchCtxPool);
    if (NT_SUCCESS(b)) ExDeleteLookasideListEx(&g_Blw.RegScratchPool);
    if (NT_SUCCESS(c)) ExDeleteLookasideListEx(&g_Blw.EventPathPool);
}

// 只能在所有回调都已摘除、过滤器已注销之后调用。
void
BlwFreePools(void)
{
    if (!g_Blw.PoolsReady) {
        return;
    }
    g_Blw.PoolsReady = FALSE;
    ExDeleteLookasideListEx(&g_Blw.MatchCtxPool);
    ExDeleteLookasideListEx(&g_Blw.RegScratchPool);
    ExDeleteLookasideListEx(&g_Blw.EventPathPool);
}

PBLW_MATCH_CTX
BlwAllocMatchCtx(void)
{
    return g_Blw.PoolsReady ? (PBLW_MATCH_CTX)ExAllocateFromLookasideListEx(&g_Blw.MatchCtxPool) : NULL;
}

void
BlwFreeMatchCtx(_In_opt_ PBLW_MATCH_CTX Ctx)
{
    if (Ctx != NULL) {
        ExFreeToLookasideListEx(&g_Blw.MatchCtxPool, Ctx);
    }
}

void
BlwResolveSystemVolume(void)
{
    static const WCHAR kLinkPrefix[] = L"\\GLOBAL??\\";
    WCHAR linkBuf[RTL_NUMBER_OF(kLinkPrefix) + 2];
    WCHAR targetBuf[BLW_SYSVOL_DEVICE_MAX];
    UNICODE_STRING linkName;
    UNICODE_STRING target;
    OBJECT_ATTRIBUTES oa;
    HANDLE link = NULL;
    NTSTATUS status;
    WCHAR letter;

    PAGED_CODE();

    if (BlwSystemVolumeKnown()) {
        return;
    }

    letter = SharedUserData->NtSystemRoot[0];
    if (SharedUserData->NtSystemRoot[1] != L':') {
        KdPrint(("[Bulwark] System volume: NtSystemRoot has no drive letter; trusted-path checks fall back to any volume.\n"));
        return;
    }

    RtlCopyMemory(linkBuf, kLinkPrefix, sizeof(kLinkPrefix) - sizeof(WCHAR));
    linkBuf[RTL_NUMBER_OF(kLinkPrefix) - 1] = letter;
    linkBuf[RTL_NUMBER_OF(kLinkPrefix)] = L':';
    linkBuf[RTL_NUMBER_OF(kLinkPrefix) + 1] = L'\0';
    RtlInitUnicodeString(&linkName, linkBuf);
    InitializeObjectAttributes(&oa, &linkName, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);

    status = ZwOpenSymbolicLinkObject(&link, GENERIC_READ, &oa);
    if (!NT_SUCCESS(status)) {
        KdPrint(("[Bulwark] System volume: cannot open %wZ (0x%x); will retry when the service connects.\n",
                 &linkName, status));
        return;
    }

    target.Buffer = targetBuf;
    target.Length = 0;
    target.MaximumLength = sizeof(targetBuf);
    status = ZwQuerySymbolicLinkObject(link, &target, NULL);
    ZwClose(link);
    if (!NT_SUCCESS(status) || target.Length == 0) {
        KdPrint(("[Bulwark] System volume: cannot resolve %wZ (0x%x).\n", &linkName, status));
        return;
    }

    BlwSetSystemVolume(letter, target.Buffer, (USHORT)(target.Length / sizeof(WCHAR)));
    KdPrint(("[Bulwark] System volume: %wZ -> %wZ (known=%d).\n",
             &linkName, &target, BlwSystemVolumeKnown()));
}

static void
BlwpRollbackWfp(void)
{
    NTSTATUS st = BlwUnregisterWfp();
    if (!NT_SUCCESS(st)) {
        // 拆不掉时 WFP 仍在引用设备对象与锁,只能保留(泄漏)它们。
        KdPrint(("[Bulwark] DriverEntry rollback: WFP unregister failed 0x%x\n", st));
        return;
    }
    if (g_Blw.WfpDeviceObject != NULL && !BlwWfpHasCallouts()) {
        IoDeleteDevice(g_Blw.WfpDeviceObject);
        g_Blw.WfpDeviceObject = NULL;
    }
    if (g_Blw.WfpLockReady) {
        ExDeleteResourceLite(&g_Blw.WfpLock);
        g_Blw.WfpLockReady = FALSE;
    }
}

static NTSTATUS
BlwFilterUnload(_In_ FLT_FILTER_UNLOAD_FLAGS Flags)
{
    NTSTATUS wfpStatus;

    PAGED_CODE();
    UNREFERENCED_PARAMETER(Flags); // Release 下 KdPrint 会被编译掉。

    // 防护生效(可信服务在线)时不许从外面卸驱动:fltmc unload / FilterUnload 是脚本致盲安全软件的
    // 常用一步。服务自己卸载前会先断开连接,不受影响;系统发起的强制卸载拒绝不了,也不拒绝。
    if (!FlagOn(Flags, FLTFL_FILTER_UNLOAD_MANDATORY) && g_Blw.Active && g_Blw.ClientTrusted) {
        BlwReportEvent(BlwEventDriverUnloadBlocked, HandleToULong(PsGetCurrentProcessId()), 0,
                       NULL, NULL, 0, 0);
        KdPrint(("[Bulwark] Unload REFUSED: protection is active (trusted service connected).\n"));
        return STATUS_FLT_DO_NOT_DETACH;
    }

    wfpStatus = BlwUnregisterWfp();
    if (!NT_SUCCESS(wfpStatus)) {
        // g_FilterRegistration 禁用了 service-stop mandatory unload，因此所有受支持的运行时
        // 卸载都必须可拒绝。callout 尚在时绝不能继续拆回调或让映像离开内存。
        KdPrint(("[Bulwark] Unload REFUSED: WFP callout still busy (0x%x, flags=0x%x). "
                 "Nothing torn down; retry later.\n", wfpStatus, Flags));
        g_Blw.WfpUnloading = FALSE;
        return STATUS_FLT_DO_NOT_DETACH;
    }

    BlwUnregisterProcessCallback();
    BlwUnregisterImageCallback();
    BlwUnregisterThreadCallback();
    BlwUnregisterRegistryCallback();
    BlwUnregisterObCallbacks();

    if (g_Blw.WfpDeviceObject != NULL && !BlwWfpHasCallouts()) {
        IoDeleteDevice(g_Blw.WfpDeviceObject);
        g_Blw.WfpDeviceObject = NULL;
    }
    BlwStopHashWorker();

    // 停止策略写回线程:会把仍未落地的脏名单全部刷进注册表后再退出,
    // 保证「已学习裁决」(执行前拦截 / 禁止加载 / 注册表硬拦)不因去抖延迟而丢失。
    // 必须在此(仍可安全调用 Zw* 的 PASSIVE_LEVEL 阶段)完成。
    BlwStopPolicyPersist();

    // 所有回调已摘除,不会再有新事件入队;停止并排空后台发送线程,
    // 必须在关闭通信端口之前(发送线程仍可能在用 ClientPort)。
    BlwStopEventQueue();
    BlwTearDownCommunication();

    // 排空并注销 Minifilter(摘除 I/O 预操作回调)。必须在返回前完成。
    if (g_Blw.Filter != NULL) {
        FltUnregisterFilter(g_Blw.Filter);
        g_Blw.Filter = NULL;
    }

    if (g_Blw.WfpLockReady) {
        ExDeleteResourceLite(&g_Blw.WfpLock);
        g_Blw.WfpLockReady = FALSE;
    }

    BlwFreePools();
    return STATUS_SUCCESS;
}

CONST FLT_OPERATION_REGISTRATION g_Callbacks[] = {
    { IRP_MJ_CREATE,          0, BlwPreCreate,         BlwPostCreate },
    { IRP_MJ_SET_INFORMATION, 0, BlwPreSetInformation, NULL },
    { IRP_MJ_WRITE,           0, BlwPreWrite,          NULL },
    { IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION, 0, BlwPreAcquireSection, NULL },
    { IRP_MJ_OPERATION_END }
};

static NTSTATUS
BlwInstanceSetup(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
    _In_ DEVICE_TYPE VolumeDeviceType,
    _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);
    UNREFERENCED_PARAMETER(VolumeDeviceType);
    UNREFERENCED_PARAMETER(VolumeFilesystemType);
    PAGED_CODE();

    // 每个卷都挂载，文件硬拦、受保护目录与自保护在所有卷上继续生效。
    return STATUS_SUCCESS;
}

static NTSTATUS
BlwInstanceQueryTeardown(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);
    PAGED_CODE();
    return STATUS_SUCCESS;
}

CONST FLT_REGISTRATION g_FilterRegistration = {
    sizeof(FLT_REGISTRATION),
    FLT_REGISTRATION_VERSION,
    // 禁止 SCM 触发不可拒绝的 mandatory unload。WFP callout 注销失败时，只有可拒绝的
    // FilterUnload 路径才能保证驱动映像不会在回调仍注册时被卸载。
    FLTFL_REGISTRATION_DO_NOT_SUPPORT_SERVICE_STOP,
    NULL,
    g_Callbacks,
    BlwFilterUnload,
    BlwInstanceSetup,
    BlwInstanceQueryTeardown,
    NULL,
    NULL,
    NULL, NULL, NULL, NULL
};

NTSTATUS
DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath)
{
    NTSTATUS status;

    ExInitializeDriverRuntime(DrvRtPoolNxOptIn);

    KdPrint(("[Bulwark] DriverEntry\n"));

    // 放在回调注册之前,可信路径判定从第一个回调起就按系统卷生效。
    BlwResolveSystemVolume();

    InterlockedExchange(&g_Blw.BootGuardEnabled, 1);

    BlwInitPools();

    FltInitializePushLock(&g_Blw.PathLock);
    FltInitializePushLock(&g_Blw.FileHardLock);
    FltInitializePushLock(&g_Blw.SelfGuardLock);  // 自保护足迹锁(owner-aware 反勒索)
    FltInitializePushLock(&g_Blw.GuardDirLock);   // 受保护目录锁(反勒索:只许可信写入者改)
    FltInitializePushLock(&g_Blw.GuardWriterLock);// 可信写入者名单锁(受保护目录的唯一误拦出口)
    FltInitializePushLock(&g_Blw.ReadGuardLock);  // 窃密防护条目锁(敏感数据只许指定程序读)
    FltInitializePushLock(&g_Blw.ReadGuardReaderLock); // 窃密防护全局读者名单锁
    FltInitializePushLock(&g_Blw.FileNoLoadLock);
    FltInitializePushLock(&g_Blw.FileExecBlockLock);
    FltInitializePushLock(&g_Blw.CmdHardLock);    // 命令行硬拦名单锁(执行前拦截危险命令用法)
    FltInitializePushLock(&g_Blw.RegLock);
    FltInitializePushLock(&g_Blw.RegHardLock);
    FltInitializePushLock(&g_Blw.KnownBadLock);   // 已知恶意 SHA-256 集合锁(事后哈希研判)
    {
        NTSTATUS lockStatus = ExInitializeResourceLite(&g_Blw.WfpLock);
        g_Blw.WfpLockReady = NT_SUCCESS(lockStatus);
        if (!g_Blw.WfpLockReady) {
            KdPrint(("[Bulwark] ExInitializeResourceLite(WfpLock) failed 0x%x; "
                     "network protection will stay off.\n", lockStatus));
        }
    }
    // NetLock 用自旋锁:WFP classifyFn 可能在 DISPATCH_LEVEL 运行,
    // FAST_MUTEX 在 > APC_LEVEL 获取会蓝屏。
    KeInitializeSpinLock(&g_Blw.NetLock);
    KeInitializeSpinLock(&g_Blw.BannedLock);
    // 「受保护 / 反注入 / 凭据保护」三个 PID 集的写侧锁。必须在注册任何回调之前初始化 ——
    // 进程退出回调一注册就可能立刻走 BlwRemoveTrackedPid 取这把锁。
    KeInitializeSpinLock(&g_Blw.PidSetLock);
    ExInitializeRundownProtection(&g_Blw.ClientPortRundown);
    ExWaitForRundownProtectionRelease(&g_Blw.ClientPortRundown);

    // WFP 在所有可能导致 DriverEntry 失败的初始化完成后再启动。这样后续失败回滚时
    // 不会出现 callout 注销失败、但 DriverEntry 仍返回失败并卸载映像的生命周期冲突。

    status = FltRegisterFilter(DriverObject, &g_FilterRegistration, &g_Blw.Filter);
    if (!NT_SUCCESS(status)) {
        KdPrint(("[Bulwark] FltRegisterFilter failed 0x%x\n", status));
        BlwpRollbackWfp();
        BlwFreePools();
        return status;
    }

    status = BlwInitCommunication(DriverObject);
    if (!NT_SUCCESS(status)) {
        KdPrint(("[Bulwark] BlwInitCommunication failed 0x%x\n", status));
        FltUnregisterFilter(g_Blw.Filter);
        g_Blw.Filter = NULL;
        BlwpRollbackWfp();
        BlwFreePools();
        return status;
    }

    // 2.5) 启动异步事件队列 + 后台发送线程。必须在任何回调注册之前就绪,
    //      因为所有回调都通过 BlwReportEvent 入队。失败则回滚。
    status = BlwStartEventQueue();
    if (!NT_SUCCESS(status)) {
        KdPrint(("[Bulwark] BlwStartEventQueue failed 0x%x\n", status));
        BlwTearDownCommunication();
        FltUnregisterFilter(g_Blw.Filter);
        g_Blw.Filter = NULL;
        BlwpRollbackWfp();
        BlwFreePools();
        return status;
    }

    status = FltStartFiltering(g_Blw.Filter);
    if (!NT_SUCCESS(status)) {
        KdPrint(("[Bulwark] FltStartFiltering failed 0x%x\n", status));
        BlwStopEventQueue();
        BlwTearDownCommunication();
        FltUnregisterFilter(g_Blw.Filter);
        g_Blw.Filter = NULL;
        BlwpRollbackWfp();
        BlwFreePools();
        return status;
    }

    status = BlwRegisterProcessCallback();
    if (!NT_SUCCESS(status)) {
        KdPrint(("[Bulwark] BlwRegisterProcessCallback failed 0x%x\n", status));
        BlwStopEventQueue();
        BlwTearDownCommunication();
        FltUnregisterFilter(g_Blw.Filter);
        g_Blw.Filter = NULL;
        BlwpRollbackWfp();
        BlwFreePools();
        return status;
    }

    status = BlwRegisterRegistryCallback(DriverObject);
    if (!NT_SUCCESS(status)) {
        KdPrint(("[Bulwark] BlwRegisterRegistryCallback failed 0x%x\n", status));
        BlwUnregisterProcessCallback();
        BlwStopEventQueue();
        BlwTearDownCommunication();
        FltUnregisterFilter(g_Blw.Filter);
        g_Blw.Filter = NULL;
        BlwpRollbackWfp();
        BlwFreePools();
        return status;
    }

    status = BlwRegisterImageCallback();
    if (!NT_SUCCESS(status)) {
        KdPrint(("[Bulwark] BlwRegisterImageCallback failed 0x%x (映像监控不可用,其余防护继续)\n", status));
    }

    status = BlwRegisterThreadCallback();
    if (!NT_SUCCESS(status)) {
        KdPrint(("[Bulwark] BlwRegisterThreadCallback failed 0x%x (线程监控不可用,其余防护继续)\n", status));
    }

    status = BlwRegisterObCallbacks();
    if (!NT_SUCCESS(status)) {
        KdPrint(("[Bulwark] BlwRegisterObCallbacks failed 0x%x (自保不可用,其余防护继续)\n", status));
    }

    status = BlwStartHashWorker();
    if (!NT_SUCCESS(status)) {
        KdPrint(("[Bulwark] BlwStartHashWorker failed 0x%x (哈希研判不可用,其余防护继续)\n", status));
    }

    BlwSaveRegistryPath(RegistryPath);
    BlwLoadPolicyFromRegistry();

    status = BlwStartPolicyPersist();
    if (!NT_SUCCESS(status)) {
        KdPrint(("[Bulwark] BlwStartPolicyPersist failed 0x%x (改为同步写回,功能不受影响)\n", status));
    }

    BlwPersistDeadEntryDrops();

    // WFP 最后启动。它是可选能力，失败只降级网络保护；此后 DriverEntry 不再有失败返回，
    // 因而不会在残留 callout 仍引用本镜像时进入系统的失败卸载路径。
    if (!g_Blw.WfpLockReady) {
        KdPrint(("[Bulwark] WfpLock unavailable; WFP bring-up skipped "
                 "(net protection unavailable).\n"));
    } else {
        UNICODE_STRING devName;
        PDEVICE_OBJECT devObj = NULL;
        NTSTATUS netStatus;

        RtlInitUnicodeString(&devName, L"\\Device\\BulwarkNet");
        netStatus = IoCreateDevice(DriverObject, 0, &devName,
            FILE_DEVICE_NETWORK, FILE_DEVICE_SECURE_OPEN, FALSE, &devObj);
        if (NT_SUCCESS(netStatus)) {
            devObj->Flags &= ~DO_DEVICE_INITIALIZING;

            g_Blw.WfpDeviceObject = devObj;
            netStatus = BlwWfpStart(devObj);
            if (!NT_SUCCESS(netStatus)) {
                KdPrint(("[Bulwark] BlwWfpStart failed 0x%x (net protection unavailable)\n", netStatus));
                if (!BlwWfpHasCallouts() && g_Blw.WfpBfeSubscription == NULL) {
                    IoDeleteDevice(devObj);
                    g_Blw.WfpDeviceObject = NULL;
                }
            }
        } else {
            KdPrint(("[Bulwark] IoCreateDevice failed 0x%x (net protection unavailable)\n", netStatus));
        }
    }

    KdPrint(("[Bulwark] Loaded successfully\n"));
    return STATUS_SUCCESS;
}
