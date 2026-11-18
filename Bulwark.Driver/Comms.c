#include "Driver.h"

static BOOLEAN
BlwClientIsLocalSystem(void)
{
    PACCESS_TOKEN token;
    PTOKEN_USER user = NULL;
    BOOLEAN isSystem = FALSE;

    token = PsReferencePrimaryToken(PsGetCurrentProcess());
    if (token == NULL) {
        return FALSE;
    }
    if (NT_SUCCESS(SeQueryInformationToken(token, TokenUser, (PVOID*)&user)) && user != NULL) {
        isSystem = RtlEqualSid(user->User.Sid, SeExports->SeLocalSystemSid);
        ExFreePool(user);
    }
    PsDereferencePrimaryToken(token);
    return isSystem;
}

static BOOLEAN
BlwClientIsTrusted(void)
{
    PUNICODE_STRING imageName = NULL;
    NTSTATUS status;
    BOOLEAN trusted = FALSE;

    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return FALSE;
    }

    if (!BlwClientIsLocalSystem()) {
        KdPrint(("[Bulwark] Client auth: connecting process is not LocalSystem -> untrusted.\n"));
        return FALSE;
    }

    status = SeLocateProcessImageName(PsGetCurrentProcess(), &imageName);
    if (!NT_SUCCESS(status) || imageName == NULL ||
        imageName->Buffer == NULL || imageName->Length == 0) {
        if (imageName != NULL) {
            ExFreePool(imageName);
        }
        KdPrint(("[Bulwark] Client auth: cannot resolve connecting image (0x%x) -> untrusted.\n",
                 status));
        return FALSE;
    }

    {
        const USHORT chars = (USHORT)(imageName->Length / sizeof(WCHAR));
        static const BLW_NAME_ENTRY kService[] = { BLW_NAME(L"bulwark_service.exe") };

        if (!BlwImageNameIn(kService, RTL_NUMBER_OF(kService), imageName->Buffer, chars)) {
            KdPrint(("[Bulwark] Client auth: unexpected image name %wZ -> untrusted.\n", imageName));
        } else {
            const LONG known = g_Blw.ServiceImageChars;
            if (known == 0) {
                if (chars > 0 && chars < BLW_MAX_PATH) {
                    RtlCopyMemory(g_Blw.ServiceImageBuffer, imageName->Buffer,
                                  (SIZE_T)chars * sizeof(WCHAR));
                    g_Blw.ServiceImageBuffer[chars] = L'\0';
                    InterlockedExchange(&g_Blw.ServiceImageChars, (LONG)chars);
                    BlwPersistServiceImagePath();
                    trusted = TRUE;
                    KdPrint(("[Bulwark] Client auth: recorded service image %wZ (TOFU).\n", imageName));
                }
            } else if ((USHORT)known == chars) {
                UNICODE_STRING recorded;
                recorded.Buffer = g_Blw.ServiceImageBuffer;
                recorded.Length = (USHORT)(chars * sizeof(WCHAR));
                recorded.MaximumLength = recorded.Length;
                if (RtlEqualUnicodeString(&recorded, imageName, TRUE)) {
                    trusted = TRUE;
                } else {
                    KdPrint(("[Bulwark] Client auth: image path mismatch (%wZ) -> untrusted; "
                             "destructive commands will be refused.\n", imageName));
                }
            } else {
                KdPrint(("[Bulwark] Client auth: image path mismatch (%wZ) -> untrusted; "
                         "destructive commands will be refused.\n", imageName));
            }
        }
    }

    ExFreePool(imageName);
    return trusted;
}

static BOOLEAN
BlwCommandIsDestructive(_In_ ULONG Command)
{
    switch (Command) {
    case BLW_CMD_CLEAR_PATHS:
    case BLW_CMD_CLEAR_REGKEYS:
    case BLW_CMD_CLEAR_PIDS:
    case BLW_CMD_CLEAR_BLOCKIP:
    case BLW_CMD_CLEAR_REGHARD:
    case BLW_CMD_CLEAR_FILEHARD:
    case BLW_CMD_CLEAR_MEMPROT:
    case BLW_CMD_CLEAR_NOLOAD:
    case BLW_CMD_CLEAR_EXECBLOCK:
    case BLW_CMD_CLEAR_CREDPROT:
    case BLW_CMD_CLEAR_BANNED:
    case BLW_CMD_CLEAR_SELFGUARD:
    case BLW_CMD_CLEAR_CMDBLOCK:
    case BLW_CMD_CLEAR_KNOWNBAD:
    case BLW_CMD_DEL_PATH:
    case BLW_CMD_DEL_FILEHARD:
    case BLW_CMD_DEL_NOLOAD:
    case BLW_CMD_DEL_EXECBLOCK:
    case BLW_CMD_DEL_REGHARD:
    case BLW_CMD_DEL_CMDBLOCK:
    case BLW_CMD_CLEAR_GUARDDIR:
    case BLW_CMD_DEL_GUARDDIR:
    case BLW_CMD_CLEAR_GUARDWRITER:
    case BLW_CMD_DEL_GUARDWRITER:
    case BLW_CMD_ADD_GUARDWRITER:   // 加一个可信写入者等于给受保护目录开一扇门
    case BLW_CMD_CLEAR_READGUARD:
    case BLW_CMD_DEL_READGUARD:
    case BLW_CMD_CLEAR_READGUARD_READER:
    case BLW_CMD_DEL_READGUARD_READER:
    case BLW_CMD_ADD_READGUARD_READER: // 加一个全局读者等于把所有敏感数据向它敞开
    case BLW_CMD_FORCE_DELETE:
    case BLW_CMD_KILL_PID:
    case BLW_CMD_SET_BOOTGUARD:
    case BLW_CMD_QUARANTINE_READ:
    case BLW_CMD_ADD_PID:
    case BLW_CMD_ADD_MEMPROT:
    case BLW_CMD_ADD_CREDPROT:
    case BLW_CMD_SET_FILETELEMETRY:
    case BLW_CMD_ADD_SELFGUARD:
        return TRUE;
    default:
        return FALSE;
    }
}

static NTSTATUS
BlwConnectNotify(
    _In_ PFLT_PORT ClientPort,
    _In_opt_ PVOID ServerPortCookie,
    _In_reads_bytes_opt_(SizeOfContext) PVOID ConnectionContext,
    _In_ ULONG SizeOfContext,
    _Outptr_result_maybenull_ PVOID* ConnectionPortCookie)
{
    UNREFERENCED_PARAMETER(ServerPortCookie);
    UNREFERENCED_PARAMETER(ConnectionContext);
    UNREFERENCED_PARAMETER(SizeOfContext);

    // 驱动加载过早时 \GLOBAL??\X: 可能还不存在,在此补一次;已解析则立即返回。
    BlwResolveSystemVolume();

    // 必须在置 Active 之前定下可信性:MessageNotify 一旦开始收命令就会读这个标志。
    g_Blw.ClientTrusted = BlwClientIsTrusted();

    g_Blw.ClientPort = ClientPort;
    ExReInitializeRundownProtection(&g_Blw.ClientPortRundown);
    g_Blw.Active = TRUE;
    *ConnectionPortCookie = NULL;

    KdPrint(("[Bulwark] User-mode service connected (trusted=%d).\n", g_Blw.ClientTrusted));

    (void)BlwWfpRetryBringUp();

    return STATUS_SUCCESS;
}

static VOID
BlwDisconnectNotify(_In_opt_ PVOID ConnectionCookie)
{
    UNREFERENCED_PARAMETER(ConnectionCookie);

    KdPrint(("[Bulwark] User-mode service disconnecting...\n"));

    g_Blw.Active = FALSE;
    // 可信标记随连接生命周期作废 —— 下一个连接必须重新过一遍身份校验。
    g_Blw.ClientTrusted = FALSE;

    BlwClearSelfGuard();

    ExWaitForRundownProtectionRelease(&g_Blw.ClientPortRundown);

    {
        PFLT_PORT port = (PFLT_PORT)InterlockedExchangePointer((PVOID volatile*)&g_Blw.ClientPort, NULL);
        if (port != NULL) {
            FltCloseClientPort(g_Blw.Filter, &port);
        }
    }

    KdPrint(("[Bulwark] User-mode service disconnected.\n"));
}

static NTSTATUS
BlwMessageNotify(
    _In_opt_ PVOID PortCookie,
    _In_reads_bytes_opt_(InputBufferLength) PVOID InputBuffer,
    _In_ ULONG InputBufferLength,
    _Out_writes_bytes_to_opt_(OutputBufferLength, *ReturnOutputBufferLength) PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength,
    _Out_ PULONG ReturnOutputBufferLength)
{
    UNREFERENCED_PARAMETER(PortCookie);

    *ReturnOutputBufferLength = 0;

    if (InputBuffer == NULL || InputBufferLength < sizeof(BLW_CONFIG_MESSAGE)) {
        return STATUS_INVALID_PARAMETER;
    }

    BLW_CONFIG_MESSAGE cfg;
    __try {
        if (ExGetPreviousMode() == UserMode) {
            ProbeForRead(InputBuffer, sizeof(cfg), TYPE_ALIGNMENT(BLW_CONFIG_MESSAGE));
        }
        RtlCopyMemory(&cfg, InputBuffer, sizeof(cfg));
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return STATUS_INVALID_USER_BUFFER;
    }

    // 协议握手:把内核结构体布局回给用户态校验,必须在其它命令之前处理(要写 OutputBuffer)。
    // 布局不一致时用户态一律降级、不拦截,避免结构体错位引起误判或蓝屏。
    if (cfg.Command == BLW_CMD_HANDSHAKE) {
        if (OutputBuffer == NULL || OutputBufferLength < sizeof(BLW_HANDSHAKE_REPLY)) {
            return STATUS_BUFFER_TOO_SMALL;
        }
        __try {
            if (ExGetPreviousMode() == UserMode) {
                ProbeForWrite(OutputBuffer, sizeof(BLW_HANDSHAKE_REPLY),
                              TYPE_ALIGNMENT(BLW_HANDSHAKE_REPLY));
            }
            PBLW_HANDSHAKE_REPLY reply = (PBLW_HANDSHAKE_REPLY)OutputBuffer;
            reply->ProtocolVersion = BLW_PROTOCOL_VERSION;
            reply->EventMessageSize = (ULONG)sizeof(BLW_EVENT_MESSAGE);
            reply->ConfigMessageSize = (ULONG)sizeof(BLW_CONFIG_MESSAGE);
            reply->VerdictReplySize = (ULONG)sizeof(BLW_VERDICT_REPLY);
            // 直接声明本驱动编译进了哪些能力,用户态不必靠下发非法参数去反推。
            reply->Capabilities = BLW_CAP_CURRENT;
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            return STATUS_INVALID_USER_BUFFER;
        }
        *ReturnOutputBufferLength = sizeof(BLW_HANDSHAKE_REPLY);
        return STATUS_SUCCESS;
    }

    if (cfg.Command == BLW_CMD_QUERY_WFP_STATS) {
        if (OutputBuffer == NULL || OutputBufferLength < sizeof(BLW_WFP_STATS_REPLY)) {
            return STATUS_BUFFER_TOO_SMALL;
        }
        __try {
            if (ExGetPreviousMode() == UserMode) {
                ProbeForWrite(OutputBuffer, sizeof(BLW_WFP_STATS_REPLY),
                              TYPE_ALIGNMENT(BLW_WFP_STATS_REPLY));
            }
            PBLW_WFP_STATS_REPLY reply = (PBLW_WFP_STATS_REPLY)OutputBuffer;
            reply->Registered = g_Blw.WfpRegistered ? 1u : 0u;
            reply->LayerCount = (ULONG)BLW_WFP_LAYER_COUNT;
            reply->ClassifyCalls =
                (ULONG64)InterlockedCompareExchange64(&g_Blw.WfpClassifyCalls, 0, 0);
            reply->RightsCleared =
                (ULONG64)InterlockedCompareExchange64(&g_Blw.WfpRightsCleared, 0, 0);
            reply->ContainBlocks = 0;
            reply->BannedBlocks =
                (ULONG64)InterlockedCompareExchange64(&g_Blw.WfpBannedBlocks, 0, 0);
            reply->IpBlocks =
                (ULONG64)InterlockedCompareExchange64(&g_Blw.WfpIpBlocks, 0, 0);
            reply->BringUpAttempts =
                (ULONG)InterlockedCompareExchange(&g_Blw.WfpBringUpAttempts, 0, 0);
            reply->LastStage =
                (ULONG)InterlockedCompareExchange(&g_Blw.WfpLastStage, 0, 0);
            reply->LastStatus =
                InterlockedCompareExchange(&g_Blw.WfpLastStatus, 0, 0);
            reply->BfeSubscribed = (g_Blw.WfpBfeSubscription != NULL) ? 1u : 0u;
            reply->LastLayer =
                (ULONG)InterlockedCompareExchange(&g_Blw.WfpLastLayer, 0, 0);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            return STATUS_INVALID_USER_BUFFER;
        }
        *ReturnOutputBufferLength = sizeof(BLW_WFP_STATS_REPLY);
        return STATUS_SUCCESS;
    }

    if (cfg.Command == BLW_CMD_QUERY_EVENT_STATS) {
        if (OutputBuffer == NULL || OutputBufferLength < sizeof(BLW_EVENT_STATS_REPLY)) {
            return STATUS_BUFFER_TOO_SMALL;
        }
        __try {
            if (ExGetPreviousMode() == UserMode) {
                ProbeForWrite(OutputBuffer, sizeof(BLW_EVENT_STATS_REPLY),
                              TYPE_ALIGNMENT(BLW_EVENT_STATS_REPLY));
            }
            PBLW_EVENT_STATS_REPLY reply = (PBLW_EVENT_STATS_REPLY)OutputBuffer;
            reply->Queued =
                (ULONG64)InterlockedCompareExchange64(&g_Blw.NextEventId, 0, 0);
            reply->Delivered =
                (ULONG64)InterlockedCompareExchange64(&g_Blw.EventsDelivered, 0, 0);
            reply->DroppedQueueFull =
                (ULONG64)InterlockedCompareExchange64(&g_Blw.DroppedEvents, 0, 0);
            reply->DroppedNoClient =
                (ULONG64)InterlockedCompareExchange64(&g_Blw.EventsDroppedNoClient, 0, 0);
            reply->DroppedSendFailed =
                (ULONG64)InterlockedCompareExchange64(&g_Blw.EventsDroppedSendFailed, 0, 0);
            reply->SendWaits =
                (ULONG64)InterlockedCompareExchange64(&g_Blw.EventSendWaits, 0, 0);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            return STATUS_INVALID_USER_BUFFER;
        }
        *ReturnOutputBufferLength = sizeof(BLW_EVENT_STATS_REPLY);
        return STATUS_SUCCESS;
    }

    if (BlwCommandIsDestructive(cfg.Command) && !g_Blw.ClientTrusted) {
        KdPrint(("[Bulwark] REFUSED destructive command %u from untrusted client.\n", cfg.Command));
        return STATUS_ACCESS_DENIED;
    }

    if (cfg.Command == BLW_CMD_QUARANTINE_READ) {
        ULONG64 offset;
        PVOID kbuf;
        ULONG want;
        ULONG got = 0;
        NTSTATUS st;

        if (OutputBuffer == NULL || OutputBufferLength == 0) {
            return STATUS_BUFFER_TOO_SMALL;
        }
        cfg.Path[BLW_MAX_PATH - 1] = L'\0';
        if (cfg.PathLength == 0) {
            return STATUS_INVALID_PARAMETER;
        }

        want = OutputBufferLength;
        if (want > BLW_CLEANUP_READ_MAX) {
            want = BLW_CLEANUP_READ_MAX;
        }

        kbuf = BlwAllocPool(PagedPool, want, BLW_TAG);
        if (kbuf == NULL) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        offset = ((ULONG64)cfg.BlockIpV4 << 32) | (ULONG64)cfg.Pid;
        st = BlwCleanupReadFile(cfg.Path, offset, kbuf, want, &got);
        if (NT_SUCCESS(st) && got > 0) {
            __try {
                if (ExGetPreviousMode() == UserMode) {
                    ProbeForWrite(OutputBuffer, got, sizeof(UCHAR));
                }
                RtlCopyMemory(OutputBuffer, kbuf, got);
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {
                ExFreePoolWithTag(kbuf, BLW_TAG);
                return STATUS_INVALID_USER_BUFFER;
            }
        }
        ExFreePoolWithTag(kbuf, BLW_TAG);

        if (!NT_SUCCESS(st)) {
            return st;
        }
        *ReturnOutputBufferLength = got;   // 0 = 到达文件尾 / 空文件
        return STATUS_SUCCESS;
    }

    if (cfg.Command == BLW_CMD_FORCE_DELETE) {
        NTSTATUS st;

        if (OutputBuffer == NULL || OutputBufferLength < sizeof(BLW_FILEOP_REPLY)) {
            return STATUS_BUFFER_TOO_SMALL;
        }
        cfg.Path[BLW_MAX_PATH - 1] = L'\0';
        if (cfg.PathLength == 0) {
            return STATUS_INVALID_PARAMETER;
        }

        st = BlwCleanupForceDelete(cfg.Path);
        __try {
            if (ExGetPreviousMode() == UserMode) {
                ProbeForWrite(OutputBuffer, sizeof(BLW_FILEOP_REPLY),
                              TYPE_ALIGNMENT(BLW_FILEOP_REPLY));
            }
            ((PBLW_FILEOP_REPLY)OutputBuffer)->Status = (LONG)st;
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            return STATUS_INVALID_USER_BUFFER;
        }
        *ReturnOutputBufferLength = sizeof(BLW_FILEOP_REPLY);
        KdPrint(("[Bulwark] Kernel force-delete %ws -> 0x%x\n", cfg.Path, st));
        return STATUS_SUCCESS;
    }

    switch (cfg.Command) {
    case BLW_CMD_CLEAR_PATHS:
        BlwClearProtectedPaths();
        BlwMarkPolicyDirty(BLW_POLICY_DIRTY_PATHS);
        KdPrint(("[Bulwark] Protected paths cleared and persistence scheduled.\n"));
        break;
    case BLW_CMD_ADD_PATH:
        if (cfg.PathLength > 0 && cfg.PathLength < BLW_MAX_PATH) {
            cfg.Path[BLW_MAX_PATH - 1] = L'\0';
            BlwAddProtectedPath(cfg.Path, cfg.PathLength);
            BlwMarkPolicyDirty(BLW_POLICY_DIRTY_PATHS);
            KdPrint(("[Bulwark] Protected path added: %ws\n", cfg.Path));
        }
        break;
    case BLW_CMD_CLEAR_REGKEYS:
        BlwClearProtectedRegKeys();
        BlwMarkPolicyDirty(BLW_POLICY_DIRTY_REGKEYS);
        KdPrint(("[Bulwark] Protected reg keys cleared and persistence scheduled.\n"));
        break;
    case BLW_CMD_ADD_REGKEY:
        if (cfg.PathLength > 0 && cfg.PathLength < BLW_MAX_PATH) {
            cfg.Path[BLW_MAX_PATH - 1] = L'\0';
            BlwAddProtectedRegKey(cfg.Path, cfg.PathLength);
            BlwMarkPolicyDirty(BLW_POLICY_DIRTY_REGKEYS);
            KdPrint(("[Bulwark] Protected reg key added: %ws\n", cfg.Path));
        }
        break;
    case BLW_CMD_CLEAR_PIDS:
        BlwClearProtectedPids();
        KdPrint(("[Bulwark] Protected pids cleared.\n"));
        break;
    case BLW_CMD_ADD_PID:
        BlwAddProtectedPid(cfg.Pid);
        KdPrint(("[Bulwark] Protected pid added: %u\n", cfg.Pid));
        break;
    case BLW_CMD_CLEAR_BLOCKIP:
        BlwClearBlockList();
        KdPrint(("[Bulwark] Net block list cleared.\n"));
        break;
    case BLW_CMD_ADD_BLOCKIP6:
        if (cfg.PathLength != 32) return STATUS_INVALID_PARAMETER;
        if (!BlwAddBlockIp6(cfg.Path, cfg.BlockPort)) return STATUS_INSUFFICIENT_RESOURCES;
        break;
    case BLW_CMD_ADD_BLOCKIP:
        BlwAddBlockIp(cfg.BlockIpV4, cfg.BlockPort);
        KdPrint(("[Bulwark] Net block added: 0x%08x:%u\n", cfg.BlockIpV4, cfg.BlockPort));
        break;
    case BLW_CMD_CLEAR_REGHARD:
        BlwClearRegHardBlock();
        BlwMarkPolicyDirty(BLW_POLICY_DIRTY_REGHARD);
        KdPrint(("[Bulwark] Reg hard-block list cleared and persistence scheduled.\n"));
        break;
    case BLW_CMD_ADD_REGHARD:
        if (cfg.PathLength == 0 || cfg.PathLength >= BLW_MAX_PATH)
            return STATUS_INVALID_PARAMETER;
        cfg.Path[BLW_MAX_PATH - 1] = L'\0';
        if (!BlwAddRegHardBlock(cfg.Path, cfg.PathLength))
            return STATUS_INSUFFICIENT_RESOURCES;
        BlwMarkPolicyDirty(BLW_POLICY_DIRTY_REGHARD);
        KdPrint(("[Bulwark] Reg hard-block added: %ws\n", cfg.Path));
        break;
    case BLW_CMD_CLEAR_FILEHARD:
        BlwClearFileHardBlock();
        BlwMarkPolicyDirty(BLW_POLICY_DIRTY_FILEHARD);
        KdPrint(("[Bulwark] File hard-block list cleared and persistence scheduled.\n"));
        break;
    case BLW_CMD_ADD_FILEHARD:
        if (cfg.PathLength > 0 && cfg.PathLength < BLW_MAX_PATH) {
            cfg.Path[BLW_MAX_PATH - 1] = L'\0';
            BlwAddFileHardBlock(cfg.Path, cfg.PathLength);
            BlwMarkPolicyDirty(BLW_POLICY_DIRTY_FILEHARD);
            KdPrint(("[Bulwark] File hard-block added: %ws\n", cfg.Path));
        }
        break;
    case BLW_CMD_CLEAR_MEMPROT:
        BlwClearMemProtPids();
        KdPrint(("[Bulwark] MemProtect target list cleared.\n"));
        break;
    case BLW_CMD_ADD_MEMPROT:
        BlwAddMemProtPid(cfg.Pid);
        KdPrint(("[Bulwark] MemProtect target pid added: %u\n", cfg.Pid));
        break;
    case BLW_CMD_CLEAR_CREDPROT:
        BlwClearCredProtPids();
        KdPrint(("[Bulwark] CredProtect target list cleared.\n"));
        break;
    case BLW_CMD_ADD_CREDPROT:
        BlwAddCredProtPid(cfg.Pid);
        KdPrint(("[Bulwark] CredProtect(LSASS) target pid added: %u\n", cfg.Pid));
        break;
    case BLW_CMD_CLEAR_BANNED:
        BlwClearBannedPids();
        KdPrint(("[Bulwark] Banned actor list cleared.\n"));
        break;
    case BLW_CMD_ADD_BANNED:
        if (!BlwAddBannedPid(cfg.Pid)) {
            return STATUS_ACCESS_DENIED;
        }
        KdPrint(("[Bulwark] Banned actor pid added: %u (deny ALL its behaviors).\n", cfg.Pid));
        break;

    case BLW_CMD_CLEAR_SELFGUARD:
        BlwClearSelfGuard();
        KdPrint(("[Bulwark] SelfGuard footprint cleared.\n"));
        break;
    case BLW_CMD_ADD_SELFGUARD:
        if (cfg.PathLength > 0 && cfg.PathLength < BLW_MAX_PATH) {
            cfg.Path[BLW_MAX_PATH - 1] = L'\0';
            BlwAddSelfGuard(cfg.Path, cfg.PathLength);
            KdPrint(("[Bulwark] SelfGuard footprint added: %ws\n", cfg.Path));
        }
        break;
    case BLW_CMD_CLEAR_NOLOAD:
        BlwClearFileNoLoad();
        BlwMarkPolicyDirty(BLW_POLICY_DIRTY_NOLOAD);
        KdPrint(("[Bulwark] No-load module list cleared and persistence scheduled.\n"));
        break;
    case BLW_CMD_ADD_NOLOAD:
        if (cfg.PathLength == 0 || cfg.PathLength >= BLW_MAX_PATH)
            return STATUS_INVALID_PARAMETER;
        cfg.Path[BLW_MAX_PATH - 1] = L'\0';
        if (!BlwAddFileNoLoad(cfg.Path, cfg.PathLength))
            return STATUS_INSUFFICIENT_RESOURCES;
        BlwMarkPolicyDirty(BLW_POLICY_DIRTY_NOLOAD);
        KdPrint(("[Bulwark] No-load module added: %ws\n", cfg.Path));
        break;
    case BLW_CMD_CLEAR_GUARDDIR:
        BlwClearGuardDirs();
        BlwMarkPolicyDirty(BLW_POLICY_DIRTY_GUARDDIR);
        KdPrint(("[Bulwark] Guard dirs cleared and persistence scheduled.\n"));
        break;
    case BLW_CMD_ADD_GUARDDIR:
        if (cfg.PathLength > 0 && cfg.PathLength < BLW_MAX_PATH) {
            cfg.Path[BLW_MAX_PATH - 1] = L'\0';
            BlwAddGuardDir(cfg.Path, cfg.PathLength);
            BlwMarkPolicyDirty(BLW_POLICY_DIRTY_GUARDDIR);
            KdPrint(("[Bulwark] Guard dir added: %ws\n", cfg.Path));
        }
        break;
    case BLW_CMD_CLEAR_GUARDWRITER:
        BlwClearGuardWriters();
        BlwMarkPolicyDirty(BLW_POLICY_DIRTY_GUARDWRITER);
        KdPrint(("[Bulwark] Guard writers cleared and persistence scheduled.\n"));
        break;
    case BLW_CMD_ADD_GUARDWRITER:
        if (cfg.PathLength > 0 && cfg.PathLength < BLW_MAX_PATH) {
            cfg.Path[BLW_MAX_PATH - 1] = L'\0';
            BlwAddGuardWriter(cfg.Path, cfg.PathLength);
            // 例外必须和目录一起跨重启,否则重启后目录还在拦、例外却没了,会表现为重启后突然误拦。
            BlwMarkPolicyDirty(BLW_POLICY_DIRTY_GUARDWRITER);
            KdPrint(("[Bulwark] Guard writer added: %ws\n", cfg.Path));
        }
        break;
    case BLW_CMD_CLEAR_READGUARD:
        BlwClearReadGuard();
        BlwMarkPolicyDirty(BLW_POLICY_DIRTY_READGUARD);
        KdPrint(("[Bulwark] Read-guard entries cleared and persistence scheduled.\n"));
        break;
    case BLW_CMD_ADD_READGUARD:
        if (cfg.PathLength > 0 && cfg.PathLength < BLW_MAX_PATH) {
            cfg.Path[BLW_MAX_PATH - 1] = L'\0';
            BlwAddReadGuard(cfg.Path, cfg.PathLength);
            // 条目与全局读者必须一起跨重启,理由同受保护目录与可信写入者。
            BlwMarkPolicyDirty(BLW_POLICY_DIRTY_READGUARD);
            KdPrint(("[Bulwark] Read-guard entry added: %ws\n", cfg.Path));
        }
        break;
    case BLW_CMD_CLEAR_READGUARD_READER:
        BlwClearReadGuardReaders();
        BlwMarkPolicyDirty(BLW_POLICY_DIRTY_READGUARD_READER);
        KdPrint(("[Bulwark] Read-guard readers cleared and persistence scheduled.\n"));
        break;
    case BLW_CMD_ADD_READGUARD_READER:
        if (cfg.PathLength > 0 && cfg.PathLength < BLW_MAX_PATH) {
            cfg.Path[BLW_MAX_PATH - 1] = L'\0';
            BlwAddReadGuardReader(cfg.Path, cfg.PathLength);
            BlwMarkPolicyDirty(BLW_POLICY_DIRTY_READGUARD_READER);
            KdPrint(("[Bulwark] Read-guard reader added: %ws\n", cfg.Path));
        }
        break;

    case BLW_CMD_CLEAR_CMDBLOCK:
        BlwClearCmdHardBlock();
        BlwMarkPolicyDirty(BLW_POLICY_DIRTY_CMDHARD);
        KdPrint(("[Bulwark] Command hard-block list cleared and persistence scheduled.\n"));
        break;
    case BLW_CMD_ADD_CMDBLOCK:
        if (cfg.PathLength > 0 && cfg.PathLength < BLW_MAX_PATH) {
            cfg.Path[BLW_MAX_PATH - 1] = L'\0';
            BlwAddCmdHardBlock(cfg.Path, cfg.PathLength);
            BlwMarkPolicyDirty(BLW_POLICY_DIRTY_CMDHARD);
            KdPrint(("[Bulwark] Command hard-block pattern added: %ws\n", cfg.Path));
        }
        break;
    case BLW_CMD_SET_FILETELEMETRY:
        InterlockedExchange(&g_Blw.FileTelemetryEnabled, cfg.Pid != 0 ? 1 : 0);
        KdPrint(("[Bulwark] File behavior telemetry %ws.\n",
            cfg.Pid != 0 ? L"enabled" : L"disabled"));
        break;
    case BLW_CMD_SET_BOOTGUARD:
        InterlockedExchange(&g_Blw.BootGuardEnabled, cfg.Pid != 0 ? 1 : 0);
        KdPrint(("[Bulwark] Boot sector (MBR/VBR) guard %ws.\n",
            cfg.Pid != 0 ? L"enabled" : L"DISABLED (runtime only; re-enabled on reboot)"));
        break;
    case BLW_CMD_KILL_PID:
        {
            const NTSTATUS killStatus = BlwKillProcessById(cfg.Pid);
            KdPrint(("[Bulwark] KILL_PID command for PID %u -> 0x%x.\n",
                     cfg.Pid, killStatus));
            return killStatus;
        }

    case BLW_CMD_CLEAR_EXECBLOCK:
        BlwClearFileExecBlock();
        BlwMarkPolicyDirty(BLW_POLICY_DIRTY_EXECBLOCK);
        KdPrint(("[Bulwark] Exec-block list cleared and persistence scheduled.\n"));
        break;
    case BLW_CMD_ADD_EXECBLOCK:
        if (cfg.PathLength == 0 || cfg.PathLength >= BLW_MAX_PATH)
            return STATUS_INVALID_PARAMETER;
        cfg.Path[BLW_MAX_PATH - 1] = L'\0';
        if (!BlwAddFileExecBlock(cfg.Path, cfg.PathLength))
            return STATUS_INSUFFICIENT_RESOURCES;
        BlwMarkPolicyDirty(BLW_POLICY_DIRTY_EXECBLOCK);
        KdPrint(("[Bulwark] Exec-block image added: %ws\n", cfg.Path));
        break;

    case BLW_CMD_CLEAR_KNOWNBAD:
        BlwClearKnownBad();
        KdPrint(("[Bulwark] Known-bad hash set cleared (runtime only; registry baseline untouched).\n"));
        break;
    case BLW_CMD_ADD_KNOWNBAD:
        // BlwAddKnownBadHex 自带校验(长度必须 64、必须全为十六进制字符)与去重,非法即整条丢弃。
        if (cfg.PathLength > 0 && cfg.PathLength < BLW_MAX_PATH) {
            cfg.Path[BLW_MAX_PATH - 1] = L'\0';
            BlwAddKnownBadHex(cfg.Path, cfg.PathLength);
            KdPrint(("[Bulwark] Known-bad hash submitted (set size now %d).\n",
                     g_Blw.KnownBadCount));
        }
        break;

    case BLW_CMD_DEL_PATH:
    case BLW_CMD_DEL_FILEHARD:
    case BLW_CMD_DEL_NOLOAD:
    case BLW_CMD_DEL_EXECBLOCK:
    case BLW_CMD_DEL_REGHARD:
    case BLW_CMD_DEL_CMDBLOCK:
    case BLW_CMD_DEL_GUARDDIR:
    case BLW_CMD_DEL_GUARDWRITER:
    case BLW_CMD_DEL_READGUARD:
    case BLW_CMD_DEL_READGUARD_READER:
        if (cfg.PathLength == 0 || cfg.PathLength >= BLW_MAX_PATH) {
            return STATUS_INVALID_PARAMETER;
        }
        cfg.Path[BLW_MAX_PATH - 1] = L'\0';
        {
            BOOLEAN removed = FALSE;
            LONG    dirty = 0;
            PCSTR   which = "?";

            switch (cfg.Command) {
            case BLW_CMD_DEL_PATH:
                removed = BlwDelProtectedPath(cfg.Path, cfg.PathLength);
                dirty = BLW_POLICY_DIRTY_PATHS;
                which = "protected path";
                break;
            case BLW_CMD_DEL_FILEHARD:
                removed = BlwDelFileHardBlock(cfg.Path, cfg.PathLength);
                dirty = BLW_POLICY_DIRTY_FILEHARD;
                which = "file hard-block";
                break;
            case BLW_CMD_DEL_NOLOAD:
                removed = BlwDelFileNoLoad(cfg.Path, cfg.PathLength);
                dirty = BLW_POLICY_DIRTY_NOLOAD;
                which = "no-load module";
                break;
            case BLW_CMD_DEL_EXECBLOCK:
                removed = BlwDelFileExecBlock(cfg.Path, cfg.PathLength);
                dirty = BLW_POLICY_DIRTY_EXECBLOCK;
                which = "exec-block image";
                break;
            case BLW_CMD_DEL_REGHARD:
                removed = BlwDelRegHardBlock(cfg.Path, cfg.PathLength);
                dirty = BLW_POLICY_DIRTY_REGHARD;
                which = "reg hard-block";
                break;
            case BLW_CMD_DEL_GUARDDIR:
                removed = BlwDelGuardDir(cfg.Path, cfg.PathLength);
                dirty = BLW_POLICY_DIRTY_GUARDDIR;
                which = "guard dir";
                break;
            case BLW_CMD_DEL_GUARDWRITER:
                removed = BlwDelGuardWriter(cfg.Path, cfg.PathLength);
                dirty = BLW_POLICY_DIRTY_GUARDWRITER;
                which = "guard writer";
                break;
            case BLW_CMD_DEL_READGUARD:
                removed = BlwDelReadGuard(cfg.Path, cfg.PathLength);
                dirty = BLW_POLICY_DIRTY_READGUARD;
                which = "read-guard entry";
                break;
            case BLW_CMD_DEL_READGUARD_READER:
                removed = BlwDelReadGuardReader(cfg.Path, cfg.PathLength);
                dirty = BLW_POLICY_DIRTY_READGUARD_READER;
                which = "read-guard reader";
                break;
            default:
                removed = BlwDelCmdHardBlock(cfg.Path, cfg.PathLength);
                dirty = BLW_POLICY_DIRTY_CMDHARD;
                which = "command hard-block";
                break;
            }

            if (removed) {
                BlwMarkPolicyDirty(dirty);
                KdPrint(("[Bulwark] Removed %s entry (persisting): %ws\n", which, cfg.Path));
            } else {
                KdPrint(("[Bulwark] Remove %s: no such entry (no-op): %ws\n", which, cfg.Path));
            }
            UNREFERENCED_PARAMETER(which);
        }
        break;

    default:
        return STATUS_INVALID_PARAMETER;
    }

    return STATUS_SUCCESS;
}

NTSTATUS
BlwInitCommunication(_In_ PDRIVER_OBJECT DriverObject)
{
    NTSTATUS status;
    PSECURITY_DESCRIPTOR sd = NULL;
    OBJECT_ATTRIBUTES oa;
    UNICODE_STRING portName;

    UNREFERENCED_PARAMETER(DriverObject);

    status = FltBuildDefaultSecurityDescriptor(&sd, FLT_PORT_ALL_ACCESS);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    RtlInitUnicodeString(&portName, BLW_PORT_NAME);
    InitializeObjectAttributes(&oa, &portName,
        OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, sd);

    status = FltCreateCommunicationPort(
        g_Blw.Filter,
        &g_Blw.ServerPort,
        &oa,
        NULL,
        BlwConnectNotify,
        BlwDisconnectNotify,
        BlwMessageNotify,
        1);

    FltFreeSecurityDescriptor(sd);

    if (!NT_SUCCESS(status)) {
        KdPrint(("[Bulwark] FltCreateCommunicationPort failed 0x%x\n", status));
        g_Blw.ServerPort = NULL;
    }
    return status;
}

void
BlwTearDownCommunication(void)
{
    // 停用并等待在途发送结束,再关闭端口(与断开回调一致的安全顺序)
    g_Blw.Active = FALSE;
    ExWaitForRundownProtectionRelease(&g_Blw.ClientPortRundown);
    {
        PFLT_PORT port = (PFLT_PORT)InterlockedExchangePointer((PVOID volatile*)&g_Blw.ClientPort, NULL);
        if (port != NULL) {
            FltCloseClientPort(g_Blw.Filter, &port);
        }
    }
    if (g_Blw.ServerPort != NULL) {
        FltCloseCommunicationPort(g_Blw.ServerPort);
        g_Blw.ServerPort = NULL;
    }
    g_Blw.Active = FALSE;
}

// 返回 TRUE 表示这条事件已有结果(送达或确定丢弃),可以出队;FALSE 表示服务此刻没有
// 挂起的读取,事件应留在队头稍后重试。
static BOOLEAN
BlwDeliverEvent(_In_ PBLW_EVENT_MESSAGE Event)
{
    NTSTATUS status = STATUS_PORT_DISCONNECTED;
    BOOLEAN attempted = FALSE;

    if (g_Blw.Active && g_Blw.ClientPort != NULL &&
        ExAcquireRundownProtection(&g_Blw.ClientPortRundown)) {
        if (g_Blw.Active && g_Blw.ClientPort != NULL) {
            LARGE_INTEGER timeout;
            timeout.QuadPart = -(LONGLONG)BLW_EVENT_SEND_TIMEOUT_MS * 10 * 1000;
            status = FltSendMessage(g_Blw.Filter, &g_Blw.ClientPort,
                                    Event, sizeof(*Event), NULL, NULL, &timeout);
            attempted = TRUE;
        }
        ExReleaseRundownProtection(&g_Blw.ClientPortRundown);
    }

    if (!attempted) {
        InterlockedIncrement64(&g_Blw.EventsDroppedNoClient);
        return TRUE;
    }
    if (status == STATUS_SUCCESS) {
        InterlockedIncrement64(&g_Blw.EventsDelivered);
        return TRUE;
    }
    // STATUS_TIMEOUT 属于成功类状态码,不能用 NT_SUCCESS 判断送达。
    if (status == STATUS_TIMEOUT) {
        InterlockedIncrement64(&g_Blw.EventSendWaits);
        return FALSE;
    }
    InterlockedIncrement64(&g_Blw.EventsDroppedSendFailed);
    return TRUE;
}

static VOID
BlwSenderThread(_In_ PVOID Context)
{
    UNREFERENCED_PARAMETER(Context);

    for (;;) {
        KIRQL emptyIrql;
        BOOLEAN empty;

        InterlockedExchange(&g_Blw.SenderIdle, 1);

        KeAcquireSpinLock(&g_Blw.RingLock, &emptyIrql);
        empty = (g_Blw.RingHead == g_Blw.RingTail);
        KeReleaseSpinLock(&g_Blw.RingLock, emptyIrql);

        if (empty && InterlockedCompareExchange(&g_Blw.SenderStop, 0, 0) == 0) {
            KeWaitForSingleObject(&g_Blw.RingEvent, Executive, KernelMode, FALSE, NULL);
        }

        InterlockedExchange(&g_Blw.SenderIdle, 0);

        // 停机时不再排空:服务若不读,逐条等待会让卸载拖上百秒;剩余事件随环形缓冲一起释放。
        while (InterlockedCompareExchange(&g_Blw.SenderStop, 0, 0) == 0) {
            BLW_EVENT_MESSAGE local;
            KIRQL oldIrql;
            BOOLEAN haveItem = FALSE;

            // 先复制队头、确定送达(或确定丢弃)之后才出队。服务端在两次读取之间处理事件时
            // 没有挂起的读取,先出队再发送会把这段时间里的事件全部丢掉。
            KeAcquireSpinLock(&g_Blw.RingLock, &oldIrql);
            if (g_Blw.RingTail != g_Blw.RingHead) {
                local = g_Blw.EventRing[g_Blw.RingTail];
                haveItem = TRUE;
            }
            KeReleaseSpinLock(&g_Blw.RingLock, oldIrql);

            if (!haveItem) {
                break;
            }

            if (!BlwDeliverEvent(&local)) {
                continue;
            }

            KeAcquireSpinLock(&g_Blw.RingLock, &oldIrql);
            g_Blw.RingTail = (g_Blw.RingTail + 1) & BLW_EVENT_QUEUE_MASK;
            KeReleaseSpinLock(&g_Blw.RingLock, oldIrql);
        }

        if (InterlockedCompareExchange(&g_Blw.SenderStop, 0, 0) != 0) {
            break;
        }
    }

    PsTerminateSystemThread(STATUS_SUCCESS);
}

NTSTATUS
BlwStartEventQueue(void)
{
    HANDLE threadHandle = NULL;
    NTSTATUS status;

    // 预分配环形缓冲(非分页内存,供 DISPATCH_LEVEL 入队访问)
    g_Blw.EventRing = (PBLW_EVENT_MESSAGE)BlwAllocPool(
        NonPagedPoolNx,
        (SIZE_T)BLW_EVENT_QUEUE_CAP * sizeof(BLW_EVENT_MESSAGE),
        BLW_TAG);
    if (g_Blw.EventRing == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    g_Blw.RingHead = 0;
    g_Blw.RingTail = 0;
    g_Blw.SenderStop = 0;
    g_Blw.SenderIdle = 0;
    KeInitializeSpinLock(&g_Blw.RingLock);
    KeInitializeEvent(&g_Blw.RingEvent, SynchronizationEvent, FALSE);

    status = PsCreateSystemThread(&threadHandle, THREAD_ALL_ACCESS,
        NULL, NULL, NULL, BlwSenderThread, NULL);
    if (!NT_SUCCESS(status)) {
        ExFreePoolWithTag(g_Blw.EventRing, BLW_TAG);
        g_Blw.EventRing = NULL;
        return status;
    }

    status = ObReferenceObjectByHandle(threadHandle, THREAD_ALL_ACCESS, *PsThreadType,
        KernelMode, (PVOID*)&g_Blw.SenderThread, NULL);
    if (!NT_SUCCESS(status)) {
        KdPrint(("[Bulwark] ObReferenceObjectByHandle(sender) failed 0x%08X; stopping thread.\n",
                 status));
        g_Blw.SenderThread = NULL;
        InterlockedExchange(&g_Blw.SenderStop, 1);
        KeSetEvent(&g_Blw.RingEvent, IO_NO_INCREMENT, FALSE);
        (void)ZwWaitForSingleObject(threadHandle, FALSE, NULL);
        ZwClose(threadHandle);
        ExFreePoolWithTag(g_Blw.EventRing, BLW_TAG);
        g_Blw.EventRing = NULL;
        return status;
    }
    ZwClose(threadHandle);

    KdPrint(("[Bulwark] Event queue started.\n"));
    return STATUS_SUCCESS;
}

void
BlwStopEventQueue(void)
{
    InterlockedExchange(&g_Blw.SenderStop, 1);
    KeSetEvent(&g_Blw.RingEvent, IO_NO_INCREMENT, FALSE);

    if (g_Blw.SenderThread != NULL) {
        KeWaitForSingleObject(g_Blw.SenderThread, Executive, KernelMode, FALSE, NULL);
        ObDereferenceObject(g_Blw.SenderThread);
        g_Blw.SenderThread = NULL;
    }

    {
        KIRQL oldIrql;
        PBLW_EVENT_MESSAGE ring;

        KeAcquireSpinLock(&g_Blw.RingLock, &oldIrql);
        ring = g_Blw.EventRing;
        g_Blw.EventRing = NULL;
        KeReleaseSpinLock(&g_Blw.RingLock, oldIrql);

        if (ring != NULL) {
            ExFreePoolWithTag(ring, BLW_TAG);
        }
    }
    KdPrint(("[Bulwark] Event queue stopped. queued=%lld delivered=%lld dropped(full=%lld noclient=%lld sendfail=%lld) waits=%lld\n",
        InterlockedCompareExchange64(&g_Blw.NextEventId, 0, 0),
        InterlockedCompareExchange64(&g_Blw.EventsDelivered, 0, 0),
        InterlockedCompareExchange64(&g_Blw.DroppedEvents, 0, 0),
        InterlockedCompareExchange64(&g_Blw.EventsDroppedNoClient, 0, 0),
        InterlockedCompareExchange64(&g_Blw.EventsDroppedSendFailed, 0, 0),
        InterlockedCompareExchange64(&g_Blw.EventSendWaits, 0, 0)));
}

static void
BlwFillPathField(
    _Out_writes_(BLW_MAX_PATH) PWCHAR Dest,
    _Out_ PUSHORT DestChars,
    _In_opt_ PCUNICODE_STRING Src)
{
    USHORT chars = 0;

    if (Src != NULL && Src->Buffer != NULL && Src->Length > 0) {
        chars = (USHORT)(Src->Length / sizeof(WCHAR));
        if (chars > (BLW_MAX_PATH - 1)) {
            chars = BLW_MAX_PATH - 1;
        }
        RtlCopyMemory(Dest, Src->Buffer, (SIZE_T)chars * sizeof(WCHAR));
    }
    RtlZeroMemory(&Dest[chars], (SIZE_T)(BLW_MAX_PATH - chars) * sizeof(WCHAR));
    *DestChars = chars;
}

// 入队一条事件,所有内核回调都经此对外上报。
// 只在自旋锁下就地填槽、必要时唤醒发送线程,可在 <= DISPATCH_LEVEL 调用。
// 队列满则丢弃并计数,不阻塞调用方。
void
BlwReportEvent(
    _In_ ULONG Type,
    _In_ ULONG ActorPid,
    _In_ ULONG ParentPid,
    _In_opt_ PCUNICODE_STRING TargetPath,
    _In_opt_ PCUNICODE_STRING ImagePath,
    _In_ ULONG RemoteIpV4,
    _In_ USHORT RemotePort)
{
    KIRQL oldIrql;
    LONG nextHead;
    BOOLEAN queued = FALSE;
    const BOOLEAN fromPool = g_Blw.PoolsReady;
    PWCHAR paths = NULL;
    USHORT imageChars = 0;
    USHORT targetChars = 0;

    if (!g_Blw.Active || g_Blw.EventRing == NULL) {
        return;
    }

    // 源路径可能在分页内存里,只能在自旋锁外先拷进非分页缓冲。
    paths = fromPool ? (PWCHAR)ExAllocateFromLookasideListEx(&g_Blw.EventPathPool)
                     : (PWCHAR)BlwAllocPool(NonPagedPoolNx, BLW_EVENT_PATHS_BYTES, BLW_TAG);
    if (paths == NULL) {
        InterlockedIncrement64(&g_Blw.DroppedEvents);
        return;
    }
    BlwFillPathField(paths, &imageChars, ImagePath);
    BlwFillPathField(paths + BLW_MAX_PATH, &targetChars, TargetPath);

    KeAcquireSpinLock(&g_Blw.RingLock, &oldIrql);
    nextHead = (g_Blw.RingHead + 1) & BLW_EVENT_QUEUE_MASK;
    if (g_Blw.EventRing != NULL && nextHead != g_Blw.RingTail) {
        PBLW_EVENT_MESSAGE slot = &g_Blw.EventRing[g_Blw.RingHead];

        slot->EventId = (ULONG64)InterlockedIncrement64(&g_Blw.NextEventId);
        slot->Type = Type;
        slot->ActorPid = ActorPid;
        slot->ParentPid = ParentPid;
        slot->RemoteIpV4 = RemoteIpV4;
        slot->RemotePort = RemotePort;
        RtlCopyMemory(slot->ImagePath, paths, BLW_MAX_PATH * sizeof(WCHAR));
        slot->ImagePathLength = imageChars;
        RtlCopyMemory(slot->TargetPath, paths + BLW_MAX_PATH, BLW_MAX_PATH * sizeof(WCHAR));
        slot->TargetPathLength = targetChars;

        g_Blw.RingHead = nextHead;
        queued = TRUE;
    }
    KeReleaseSpinLock(&g_Blw.RingLock, oldIrql);

    if (fromPool) {
        ExFreeToLookasideListEx(&g_Blw.EventPathPool, paths);
    } else {
        ExFreePoolWithTag(paths, BLW_TAG);
    }

    if (g_Blw.EventRing == NULL) {
        return;
    }

    if (!queued) {
        InterlockedIncrement64(&g_Blw.DroppedEvents);
        return;
    }

    if (InterlockedCompareExchange(&g_Blw.SenderIdle, 0, 1) == 1) {
        KeSetEvent(&g_Blw.RingEvent, IO_NO_INCREMENT, FALSE);
    }
}
