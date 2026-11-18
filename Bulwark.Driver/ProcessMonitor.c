#include "Driver.h"

void
BlwClearCmdHardBlock(void)
{
    BlwLockExclusive(&g_Blw.CmdHardLock);
    RtlZeroMemory(g_Blw.CmdHardBlock, sizeof(g_Blw.CmdHardBlock));
    InterlockedExchange(&g_Blw.CmdHardCount, 0);
    BlwUnlock(&g_Blw.CmdHardLock);
}

void
BlwAddCmdHardBlock(_In_ PCWSTR Pattern, _In_ USHORT Length)
{
    BlwLockExclusive(&g_Blw.CmdHardLock);
    BlwAddToList(g_Blw.CmdHardBlock, Pattern, Length);
    {
        LONG cnt = 0;
        ULONG i;
        for (i = 0; i < BLW_MAX_PROTECTED; i++) {
            if (g_Blw.CmdHardBlock[i].InUse) cnt++;
        }
        InterlockedExchange(&g_Blw.CmdHardCount, cnt);
    }
    BlwUnlock(&g_Blw.CmdHardLock);
}

BOOLEAN
BlwDelCmdHardBlock(_In_ PCWSTR Pattern, _In_ USHORT Length)
{
    return BlwRemoveFromGuardedList(g_Blw.CmdHardBlock, &g_Blw.CmdHardLock,
                                    &g_Blw.CmdHardCount, Pattern, Length);
}

BOOLEAN
BlwCmdLineIsBlocked(_In_opt_ PCUNICODE_STRING CommandLine)
{
    ULONG   chars;
    LONG    count;
    LONG    seen = 0;
    ULONG   i;
    BOOLEAN matched = FALSE;

    if (CommandLine == NULL || CommandLine->Buffer == NULL || CommandLine->Length == 0) {
        return FALSE;
    }

    chars = CommandLine->Length / sizeof(WCHAR);
    if (chars == 0) {
        return FALSE;
    }

    BlwLockShared(&g_Blw.CmdHardLock);
    count = g_Blw.CmdHardCount;
    for (i = 0; i < BLW_MAX_PROTECTED && seen < count; i++) {
        if (!g_Blw.CmdHardBlock[i].InUse) {
            continue;
        }
        seen++;
        if (BlwCmdPatternMatches(&g_Blw.CmdHardBlock[i], CommandLine->Buffer, chars)) {
            matched = TRUE;
            break;
        }
    }
    BlwUnlock(&g_Blw.CmdHardLock);

    return matched;
}

BOOLEAN
BlwImageIsLolBin(_In_ PCWSTR Path, _In_ USHORT Chars)
{
    static const BLW_NAME_ENTRY kLolBins[] = {
        BLW_NAME(L"powershell.exe"), BLW_NAME(L"pwsh.exe"),     BLW_NAME(L"cmd.exe"),
        BLW_NAME(L"wscript.exe"),    BLW_NAME(L"cscript.exe"),  BLW_NAME(L"mshta.exe"),
        BLW_NAME(L"rundll32.exe"),   BLW_NAME(L"regsvr32.exe"), BLW_NAME(L"certutil.exe"),
        BLW_NAME(L"bitsadmin.exe"),  BLW_NAME(L"wmic.exe"),     BLW_NAME(L"vssadmin.exe"),
        BLW_NAME(L"bcdedit.exe"),    BLW_NAME(L"wbadmin.exe"),  BLW_NAME(L"schtasks.exe"),
        BLW_NAME(L"at.exe"),         BLW_NAME(L"msbuild.exe"),  BLW_NAME(L"installutil.exe"),
        BLW_NAME(L"regsvcs.exe"),    BLW_NAME(L"regasm.exe"),   BLW_NAME(L"mavinject.exe"),
        BLW_NAME(L"cmstp.exe"),      BLW_NAME(L"msdt.exe"),     BLW_NAME(L"hh.exe"),
        BLW_NAME(L"forfiles.exe"),   BLW_NAME(L"pcalua.exe"),   BLW_NAME(L"scriptrunner.exe"),
        BLW_NAME(L"netsh.exe"),
    };

    return BlwImageNameIn(kLolBins, RTL_NUMBER_OF(kLolBins), Path, Chars);
}

BOOLEAN
BlwImageIsTrustedSystemPath(_In_ PCWSTR Path, _In_ USHORT Chars)
{
    // Installation directories do not grant write authority. Keep a narrow OS
    // component policy; verified document editors and user grants use GuardWriters.
    return BlwIsRansomGuardSystemWriter(Path, Chars);
}

static BOOLEAN
BlwPathIsSystemImageDir(_In_opt_ PCWSTR Path, _In_ USHORT Chars)
{
    if (Path == NULL || Chars == 0) {
        return FALSE;
    }
    return BLW_SYSVOL_PATH_STARTS(Path, Chars, L"\\Windows\\System32\\")
        || BLW_SYSVOL_PATH_STARTS(Path, Chars, L"\\Windows\\SysWOW64\\")
        || BLW_SYSVOL_PATH_STARTS(Path, Chars, L"\\Windows\\WinSxS\\");
}

BOOLEAN
BlwImageIsOsComponent(_In_ PCWSTR Path, _In_ USHORT Chars)
{
    static const WCHAR kExplorer[] = L"\\Windows\\explorer.exe";
    const USHORT explorerChars = (USHORT)(RTL_NUMBER_OF(kExplorer) - 1);
    USHORT off;

    if (Path == NULL || Chars == 0 || BlwImageIsLolBin(Path, Chars)) {
        return FALSE;
    }
    if (BLW_SYSVOL_PATH_STARTS(Path, Chars, L"\\Windows\\System32\\") ||
        BLW_SYSVOL_PATH_STARTS(Path, Chars, L"\\Windows\\SysWOW64\\")) {
        return TRUE;
    }
    off = BlwSystemVolumeRelativeOffset(Path, Chars);
    return off != 0 && (USHORT)(Chars - off) == explorerChars &&
           BlwStartsWithCI(Path + off, explorerChars, kExplorer, explorerChars);
}

static BOOLEAN
BlwIsCriticalSystemProcess(_In_opt_ PCWSTR Path, _In_ USHORT Chars)
{
    static const BLW_NAME_ENTRY kCritical[] = {
        BLW_NAME(L"smss.exe"),
        BLW_NAME(L"csrss.exe"),
        BLW_NAME(L"wininit.exe"),
        BLW_NAME(L"winlogon.exe"),
        BLW_NAME(L"services.exe"),
        BLW_NAME(L"lsass.exe"),
        BLW_NAME(L"svchost.exe"),
        BLW_NAME(L"lsaiso.exe"),
        BLW_NAME(L"fontdrvhost.exe"),
        BLW_NAME(L"dwm.exe"),
        BLW_NAME(L"spoolsv.exe"),
        BLW_NAME(L"WerFault.exe"),
        BLW_NAME(L"WerFaultSecure.exe"),
        BLW_NAME(L"wermgr.exe"),
    };

    if (!BlwImageNameIn(kCritical, RTL_NUMBER_OF(kCritical), Path, Chars)) {
        return FALSE;
    }
    return BlwPathIsSystemImageDir(Path, Chars);
}

// 正常 CreateProcess 由系统自己以只读 / 执行打开映像。下面三种状态只会出现在「先拿文件造映像节、
// 再从节创建进程」的手法里:幽灵化(删除挂起)、替身(未提交事务)、Herpaderping(写打开后改写)。
static USHORT
BlwImageAnomalyFlags(_In_ PPS_CREATE_NOTIFY_INFO CreateInfo)
{
    PFILE_OBJECT fo = CreateInfo->FileObject;
    USHORT flags = 0;

    if (fo == NULL) {
        return 0;
    }
    if (fo->DeletePending) {
        flags |= BLW_IMAGE_DELETE_PENDING;
    }
    if (IoGetTransactionParameterBlock(fo) != NULL) {
        flags |= BLW_IMAGE_TRANSACTED;
    }
    if (fo->WriteAccess) {
        flags |= BLW_IMAGE_WRITABLE;
    }
    return flags;
}

static void
BlwCreateProcessNotifyEx(
    _Inout_ PEPROCESS Process,
    _In_ HANDLE ProcessId,
    _Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo)
{
    PCUNICODE_STRING image;
    PCWSTR  imgBuf = NULL;
    USHORT  imgChars = 0;
    ULONG   newPid;
    ULONG   parentPid;
    BOOLEAN critical;

    if (CreateInfo == NULL) {
        BlwRemoveBannedPid(HandleToULong(ProcessId));
        BlwRemoveTrackedPid(HandleToULong(ProcessId));
        BlwReadGuardOnProcessExit(HandleToULong(ProcessId));
        return;
    }

    newPid = HandleToULong(ProcessId);
    parentPid = HandleToULong(CreateInfo->ParentProcessId);

    image = CreateInfo->ImageFileName;
    if (image != NULL && image->Buffer != NULL && image->Length > 0) {
        imgBuf = image->Buffer;
        imgChars = (USHORT)(image->Length / sizeof(WCHAR));
    }
    critical = BlwIsCriticalSystemProcess(imgBuf, imgChars);

    // 已封禁的进程不得创建子进程。
    if (g_Blw.BannedPidCount > 0 &&
        BlwPidIsBanned(HandleToULong(PsGetCurrentProcessId()))) {
        CreateInfo->CreationStatus = STATUS_ACCESS_DENIED;
        KdPrint(("[Bulwark] Banned actor pid %u denied spawning a child.\n",
            HandleToULong(PsGetCurrentProcessId())));
        return;
    }

    // 本产品界面只许系统组件或本产品自己拉起:创建者握着新进程的完整句柄,能抢在界面连上服务前注入它,
    // 而界面带清单,创建时系统要往新进程里写激活上下文,不能靠剥创建者句柄的权限来挡。
    if (BlwProcessIsProductUi(Process) && !BlwActorMayTouchUi(HandleToULong(PsGetCurrentProcessId()))) {
        CreateInfo->CreationStatus = STATUS_ACCESS_DENIED;
        BlwReportEvent(BlwEventUiLaunchBlocked, HandleToULong(PsGetCurrentProcessId()), newPid,
                       NULL, image, 0, 0);
        KdPrint(("[Bulwark] UiGuard: untrusted creator pid %u denied launching the product UI.\n",
            HandleToULong(PsGetCurrentProcessId())));
        return;
    }

    if (imgChars > 0 && g_Blw.FileExecBlockCount > 0 && !critical) {
        PBLW_MATCH_CTX ctx = BlwAllocMatchCtx();
        BOOLEAN blocked = FALSE;

        if (ctx != NULL) {
            BlwPrepareMatch(ctx, image);
            blocked = BlwFileIsExecBlocked(ctx);
            BlwFreeMatchCtx(ctx);
        }
        if (blocked) {
            CreateInfo->CreationStatus = STATUS_ACCESS_DENIED;
            BlwReportEvent(BlwEventImageBlocked, newPid, parentPid, image, image, 0, 0);
            KdPrint(("[Bulwark] Exec blocked (pre-create denied): %wZ\n", image));
            return;
        }
    }

    if (g_Blw.CmdHardCount > 0 && !critical &&
        BlwCmdLineIsBlocked(CreateInfo->CommandLine)) {
        CreateInfo->CreationStatus = STATUS_ACCESS_DENIED;
        BlwReportEvent(BlwEventCommandBlocked, newPid, parentPid,
                       CreateInfo->CommandLine, image, 0, 0);
        KdPrint(("[Bulwark] Command blocked (pre-create denied): %wZ\n",
            CreateInfo->CommandLine));
        return;
    }

    BlwNoteProcessCreated(newPid, HandleToULong(PsGetCurrentProcessId()));

    if (!g_Blw.Active && g_Blw.FileExecBlockCount == 0 && g_Blw.KnownBadCount == 0 &&
        g_Blw.CmdHardCount == 0) {
        return;
    }

    if (critical) {
        return;
    }

    if (g_Blw.KnownBadCount > 0) {
        BlwEnqueueHashScan(newPid);
    }

    // 回调运行在创建者的线程上下文里:当前进程才是真正的创建者,ParentProcessId 可被
    // PROC_THREAD_ATTRIBUTE_PARENT_PROCESS 任意指定。进程事件不占网络字段,借 RemoteIpV4
    // 带创建者、RemotePort 带映像异常位。
    BlwReportEvent(BlwEventProcessCreate, newPid, parentPid,
                   CreateInfo->CommandLine, image, HandleToULong(PsGetCurrentProcessId()),
                   BlwImageAnomalyFlags(CreateInfo));
}

NTSTATUS
BlwRegisterProcessCallback(void)
{
    NTSTATUS status;

    if (g_Blw.ProcessCallbackRegistered) {
        return STATUS_SUCCESS;
    }

    status = PsSetCreateProcessNotifyRoutineEx(BlwCreateProcessNotifyEx, FALSE);
    if (NT_SUCCESS(status)) {
        g_Blw.ProcessCallbackRegistered = TRUE;
        KdPrint(("[Bulwark] Process callback registered.\n"));
    }
    return status;
}

void
BlwUnregisterProcessCallback(void)
{
    if (g_Blw.ProcessCallbackRegistered) {
        PsSetCreateProcessNotifyRoutineEx(BlwCreateProcessNotifyEx, TRUE);
        g_Blw.ProcessCallbackRegistered = FALSE;
        KdPrint(("[Bulwark] Process callback unregistered.\n"));
    }
}

#ifndef PROCESS_TERMINATE
#define PROCESS_TERMINATE 0x0001
#endif

typedef BOOLEAN (*BLW_PS_IS_PROCESS_CRITICAL)(_In_ PEPROCESS Process);

static BOOLEAN
BlwProcessIsKernelCritical(_In_ PEPROCESS Process)
{
    static BLW_PS_IS_PROCESS_CRITICAL s_fn = NULL;
    static BOOLEAN s_resolved = FALSE;

    if (!s_resolved) {
        union { PVOID p; BLW_PS_IS_PROCESS_CRITICAL fn; } cast;
        UNICODE_STRING name;

        RtlInitUnicodeString(&name, L"PsIsProcessCritical");
        cast.p = MmGetSystemRoutineAddress(&name);
        s_fn = cast.fn;
        s_resolved = TRUE;
        if (s_fn == NULL) {
            KdPrint(("[Bulwark] PsIsProcessCritical unavailable; name+path guard only.\n"));
        }
    }

    return (s_fn != NULL) ? s_fn(Process) : FALSE;
}

NTSTATUS
BlwKillProcessById(_In_ ULONG Pid)
{
    PEPROCESS proc = NULL;
    HANDLE hProc = NULL;
    PUNICODE_STRING imageName = NULL;
    NTSTATUS status;

    if (Pid <= 4) {
        return STATUS_INVALID_PARAMETER;
    }
    if (BlwPidIsProtected(Pid)) {
        KdPrint(("[Bulwark] KILL refused: PID %u is self-protected.\n", Pid));
        return STATUS_ACCESS_DENIED;
    }

    status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)Pid, &proc);
    if (!NT_SUCCESS(status) || proc == NULL) {
        return status;
    }

    if (BlwProcessIsKernelCritical(proc)) {
        KdPrint(("[Bulwark] KILL refused: PID %u is kernel-critical (BreakOnTermination).\n", Pid));
        ObDereferenceObject(proc);
        return STATUS_ACCESS_DENIED;
    }

    status = SeLocateProcessImageName(proc, &imageName);
    if (NT_SUCCESS(status) && imageName != NULL && imageName->Buffer != NULL && imageName->Length > 0) {
        USHORT chars = (USHORT)(imageName->Length / sizeof(WCHAR));
        BOOLEAN critical = BlwIsCriticalSystemProcess(imageName->Buffer, chars);
        ExFreePool(imageName);
        if (critical) {
            KdPrint(("[Bulwark] KILL refused: PID %u is a system process in System32.\n", Pid));
            ObDereferenceObject(proc);
            return STATUS_ACCESS_DENIED;
        }
    }

    status = ObOpenObjectByPointer(proc, OBJ_KERNEL_HANDLE, NULL,
                                   PROCESS_TERMINATE, *PsProcessType, KernelMode, &hProc);
    if (NT_SUCCESS(status) && hProc != NULL) {
        status = ZwTerminateProcess(hProc, STATUS_ACCESS_DENIED);
        ZwClose(hProc);
        KdPrint(("[Bulwark] Kernel-terminated PID %u (status 0x%x).\n", Pid, status));
    }

    ObDereferenceObject(proc);
    return status;
}
