#include "Driver.h"

#ifndef PROCESS_TERMINATE
#define PROCESS_TERMINATE                  (0x0001)
#define PROCESS_CREATE_THREAD              (0x0002)
#define PROCESS_SET_SESSIONID              (0x0004)
#define PROCESS_VM_OPERATION               (0x0008)
#define PROCESS_VM_READ                    (0x0010)
#define PROCESS_VM_WRITE                   (0x0020)
#define PROCESS_DUP_HANDLE                 (0x0040)
#define PROCESS_CREATE_PROCESS             (0x0080)
#define PROCESS_SET_QUOTA                  (0x0100)
#define PROCESS_SET_INFORMATION            (0x0200)
#define PROCESS_QUERY_INFORMATION          (0x0400)
#define PROCESS_SUSPEND_RESUME             (0x0800)
#endif

#ifndef THREAD_TERMINATE
#define THREAD_TERMINATE                   (0x0001)
#define THREAD_SUSPEND_RESUME              (0x0002)
#define THREAD_GET_CONTEXT                 (0x0008)
#define THREAD_SET_CONTEXT                 (0x0010)
#define THREAD_SET_INFORMATION             (0x0020)
#define THREAD_QUERY_INFORMATION           (0x0040)
#endif

#define BLW_PROC_DENY_KILL (PROCESS_TERMINATE | PROCESS_VM_WRITE | \
                            PROCESS_VM_OPERATION | PROCESS_CREATE_THREAD | \
                            PROCESS_SUSPEND_RESUME | PROCESS_SET_INFORMATION)

// 只读句柄不剥权:PROCESS_QUERY_INFORMATION 是任务管理器等枚举进程信息的正常权限,剥掉会大量误告警。
// DUP_HANDLE / SET_QUOTA / SET_SESSIONID 仍拦:它们可被用来提权或改写进程配额。
#define BLW_PROC_DENY_DEGRADE (PROCESS_DUP_HANDLE | \
                               PROCESS_SET_QUOTA | PROCESS_SET_SESSIONID)

#define BLW_PROC_DENY (BLW_PROC_DENY_KILL | BLW_PROC_DENY_DEGRADE)

#ifndef THREAD_SET_THREAD_TOKEN
#define THREAD_SET_THREAD_TOKEN            (0x0080)
#define THREAD_IMPERSONATE                 (0x0100)
#define THREAD_DIRECT_IMPERSONATION        (0x0200)
#endif

#define BLW_THREAD_DENY_KILL (THREAD_TERMINATE | THREAD_SUSPEND_RESUME | \
                              THREAD_SET_CONTEXT | THREAD_SET_INFORMATION)

#define BLW_THREAD_DENY_DEGRADE (THREAD_SET_THREAD_TOKEN | THREAD_IMPERSONATE | \
                                 THREAD_DIRECT_IMPERSONATION)

#define BLW_THREAD_DENY (BLW_THREAD_DENY_KILL | BLW_THREAD_DENY_DEGRADE)

#define BLW_MEMPROT_PROC_DENY (PROCESS_VM_WRITE | PROCESS_VM_OPERATION | \
                               PROCESS_CREATE_THREAD | PROCESS_SUSPEND_RESUME)

#define BLW_MEMPROT_THREAD_DENY (THREAD_SET_CONTEXT | THREAD_SET_INFORMATION)

#define BLW_CRED_PROC_DENY (PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | \
                            PROCESS_CREATE_THREAD | PROCESS_SUSPEND_RESUME)

#define BLW_LSA_PROC_ALLOW (PROCESS_QUERY_INFORMATION | PROCESS_DUP_HANDLE)

// 已确认的真 lsass PID,0 = 尚未识别。在 ObCallbacks 热路径上读,只能是一次原子读加比较。
static volatile LONG g_BlwLsaPid = 0;

typedef PCHAR (*BLW_PS_GET_PROCESS_IMAGE_FILE_NAME)(_In_ PEPROCESS Process);

static BLW_PS_GET_PROCESS_IMAGE_FILE_NAME
BlwImageFileNameRoutine(void)
{
    static BLW_PS_GET_PROCESS_IMAGE_FILE_NAME s_fn = NULL;
    static BOOLEAN s_resolved = FALSE;

    if (!s_resolved) {
        union { PVOID p; BLW_PS_GET_PROCESS_IMAGE_FILE_NAME fn; } cast;
        UNICODE_STRING rtn;

        RtlInitUnicodeString(&rtn, L"PsGetProcessImageFileName");
        cast.p = MmGetSystemRoutineAddress(&rtn);
        s_fn = cast.fn;
        s_resolved = TRUE;
    }
    return s_fn;
}

// EPROCESS 里的短映像名是否等于 Name(小写,NameLen 个字符)。1 = 是,0 = 不是,-1 = 取不到短名。
// 短名最长 15 字节、不保证以 NUL 结尾:名字之后必须紧跟 NUL,否则是 "lsass.exeX" 之类的名字。
static int
BlwShortNameMatches(_In_ PEPROCESS Process, _In_reads_(NameLen) const char* Name, _In_ ULONG NameLen)
{
    const BLW_PS_GET_PROCESS_IMAGE_FILE_NAME fn = BlwImageFileNameRoutine();
    PCHAR name;
    ULONG i;

    if (fn == NULL) {
        return -1;
    }
    name = fn(Process);
    if (name == NULL) {
        return -1;
    }
    for (i = 0; i < NameLen; i++) {
        CHAR c = name[i];
        if (c >= 'A' && c <= 'Z') {
            c = (CHAR)(c - 'A' + 'a');
        }
        if (c != Name[i]) {
            return 0;
        }
    }
    return (NameLen >= 15 || name[NameLen] == '\0') ? 1 : 0;
}

static BOOLEAN
BlwShortNameIsLsass(_In_ PEPROCESS Process)
{
    static const char kName[] = "lsass.exe";

    return BlwShortNameMatches(Process, kName, sizeof(kName) - 1) != 0;
}

static BOOLEAN
BlwActorIsGenuineLsa(_In_ ULONG ActorPid)
{
    static const BLW_NAME_ENTRY kLsass[] = { BLW_NAME(L"lsass.exe") };
    ULONG cached;
    PEPROCESS self;
    PUNICODE_STRING imageName = NULL;
    NTSTATUS status;
    BOOLEAN genuine = FALSE;

    if (ActorPid == 0) {
        return FALSE;
    }

    cached = (ULONG)g_BlwLsaPid;
    if (cached != 0) {
        return (cached == ActorPid);
    }

    // SeLocateProcessImageName 要求 PASSIVE_LEVEL。
    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return FALSE;
    }

    self = PsGetCurrentProcess();
    if (self == NULL) {
        return FALSE;
    }

    if (!BlwShortNameIsLsass(self)) {
        return FALSE;
    }

    status = SeLocateProcessImageName(self, &imageName);
    if (NT_SUCCESS(status) && imageName != NULL &&
        imageName->Buffer != NULL && imageName->Length > 0) {
        USHORT chars = (USHORT)(imageName->Length / sizeof(WCHAR));
        genuine = BlwImageNameIn(kLsass, RTL_NUMBER_OF(kLsass), imageName->Buffer, chars)
               && BLW_SYSVOL_PATH_STARTS(imageName->Buffer, chars, L"\\Windows\\System32\\");
    }
    if (imageName != NULL) {
        ExFreePool(imageName);
    }

    if (genuine) {
        InterlockedCompareExchange(&g_BlwLsaPid, (LONG)ActorPid, 0);
        KdPrint(("[Bulwark] SelfProtect: genuine LSA identified as pid %u; "
                 "QUERY_INFORMATION|DUP_HANDLE will be allowed on protected processes.\n",
                 ActorPid));
    }
    return genuine;
}

static BOOLEAN
BlwPidSetContains(_In_ volatile LONG* Set, _In_ volatile LONG64* Mask, _In_ ULONG Pid)
{
    ULONG i;

    if (Pid == 0) {
        return FALSE;
    }

    if (((ULONG64)*Mask & BLW_PID_BIT(Pid)) == 0) {
        return FALSE;
    }

    for (i = 0; i < BLW_MAX_PROTECTED; i++) {
        if ((ULONG)Set[i] == Pid) {
            return TRUE;
        }
    }
    return FALSE;
}

// 按当前槽位重算掩码。调用方必须持有 PidSetLock。
static void
BlwRebuildPidMaskLocked(_In_ volatile LONG* Set, _Inout_ volatile LONG64* Mask)
{
    ULONG64 m = 0;
    ULONG i;

    for (i = 0; i < BLW_MAX_PROTECTED; i++) {
        ULONG p = (ULONG)Set[i];
        if (p != 0) {
            m |= BLW_PID_BIT(p);
        }
    }
    InterlockedExchange64(Mask, (LONG64)m);
}

static void
BlwPidSetAdd(_Inout_ volatile LONG* Set, _Inout_ volatile LONG64* Mask, _In_ ULONG Pid)
{
    KIRQL oldIrql;
    ULONG i;

    if (Pid == 0) {
        return;
    }

    KeAcquireSpinLock(&g_Blw.PidSetLock, &oldIrql);

    for (i = 0; i < BLW_MAX_PROTECTED; i++) {
        if ((ULONG)Set[i] == Pid) {
            KeReleaseSpinLock(&g_Blw.PidSetLock, oldIrql);
            return;
        }
    }

    InterlockedOr64(Mask, (LONG64)BLW_PID_BIT(Pid));

    for (i = 0; i < BLW_MAX_PROTECTED; i++) {
        if (InterlockedCompareExchange(&Set[i], (LONG)Pid, 0) == 0) {
            break;
        }
    }

    KeReleaseSpinLock(&g_Blw.PidSetLock, oldIrql);
}

static void
BlwPidSetRemove(_Inout_ volatile LONG* Set, _Inout_ volatile LONG64* Mask, _In_ ULONG Pid)
{
    KIRQL oldIrql;
    ULONG i;

    if (Pid == 0) {
        return;
    }
    if (((ULONG64)*Mask & BLW_PID_BIT(Pid)) == 0) {
        return;
    }

    KeAcquireSpinLock(&g_Blw.PidSetLock, &oldIrql);
    for (i = 0; i < BLW_MAX_PROTECTED; i++) {
        if ((ULONG)Set[i] == Pid) {
            InterlockedExchange(&Set[i], 0);
            BlwRebuildPidMaskLocked(Set, Mask);
            break;
        }
    }
    KeReleaseSpinLock(&g_Blw.PidSetLock, oldIrql);
}

static void
BlwPidSetClear(_Inout_ volatile LONG* Set, _Inout_ volatile LONG64* Mask)
{
    KIRQL oldIrql;
    ULONG i;

    KeAcquireSpinLock(&g_Blw.PidSetLock, &oldIrql);
    for (i = 0; i < BLW_MAX_PROTECTED; i++) {
        InterlockedExchange(&Set[i], 0);
    }
    InterlockedExchange64(Mask, 0);
    KeReleaseSpinLock(&g_Blw.PidSetLock, oldIrql);
}

void
BlwClearProtectedPids(void)
{
    BlwPidSetClear(g_Blw.ProtectedPids, &g_Blw.ProtectedPidMask);
}

void
BlwAddProtectedPid(_In_ ULONG Pid)
{
    BlwPidSetAdd(g_Blw.ProtectedPids, &g_Blw.ProtectedPidMask, Pid);
}

BOOLEAN
BlwPidIsProtected(_In_ ULONG Pid)
{
    return BlwPidSetContains(g_Blw.ProtectedPids, &g_Blw.ProtectedPidMask, Pid);
}

void
BlwClearMemProtPids(void)
{
    BlwPidSetClear(g_Blw.MemProtPids, &g_Blw.MemProtPidMask);
}

void
BlwAddMemProtPid(_In_ ULONG Pid)
{
    BlwPidSetAdd(g_Blw.MemProtPids, &g_Blw.MemProtPidMask, Pid);
}

BOOLEAN
BlwPidIsMemProtected(_In_ ULONG Pid)
{
    return BlwPidSetContains(g_Blw.MemProtPids, &g_Blw.MemProtPidMask, Pid);
}

void
BlwClearCredProtPids(void)
{
    BlwPidSetClear(g_Blw.CredProtPids, &g_Blw.CredProtPidMask);
}

void
BlwAddCredProtPid(_In_ ULONG Pid)
{
    BlwPidSetAdd(g_Blw.CredProtPids, &g_Blw.CredProtPidMask, Pid);
}

BOOLEAN
BlwPidIsCredProtected(_In_ ULONG Pid)
{
    return BlwPidSetContains(g_Blw.CredProtPids, &g_Blw.CredProtPidMask, Pid);
}

void
BlwRemoveTrackedPid(_In_ ULONG Pid)
{
    if (Pid == 0) {
        return;
    }
    BlwPidSetRemove(g_Blw.ProtectedPids, &g_Blw.ProtectedPidMask, Pid);
    BlwPidSetRemove(g_Blw.MemProtPids, &g_Blw.MemProtPidMask, Pid);
    BlwPidSetRemove(g_Blw.CredProtPids, &g_Blw.CredProtPidMask, Pid);
    InterlockedCompareExchange(&g_BlwLsaPid, 0, (LONG)Pid);
}

// 按当前槽位内容重算封禁集掩码。调用方必须持有 BannedLock。
static void
BlwRebuildBannedMask(void)
{
    ULONG64 mask = 0;
    ULONG i;

    for (i = 0; i < BLW_MAX_PROTECTED; i++) {
        ULONG p = (ULONG)g_Blw.BannedPids[i];
        if (p != 0) {
            mask |= BLW_PID_BIT(p);
        }
    }
    InterlockedExchange64(&g_Blw.BannedPidMask, (LONG64)mask);
}

void
BlwClearBannedPids(void)
{
    KIRQL oldIrql;
    ULONG i;

    KeAcquireSpinLock(&g_Blw.BannedLock, &oldIrql);
    for (i = 0; i < BLW_MAX_PROTECTED; i++) {
        InterlockedExchange(&g_Blw.BannedPids[i], 0);
    }
    InterlockedExchange(&g_Blw.BannedPidCount, 0);
    InterlockedExchange64(&g_Blw.BannedPidMask, 0);
    KeReleaseSpinLock(&g_Blw.BannedLock, oldIrql);
}

BOOLEAN
BlwAddBannedPid(_In_ ULONG Pid)
{
    KIRQL oldIrql;
    ULONG i;
    BOOLEAN added = FALSE;

    if (Pid <= 4) {
        return FALSE;
    }
    if (BlwPidIsProtected(Pid) || BlwPidIsCredProtected(Pid)) {
        return FALSE;
    }

    KeAcquireSpinLock(&g_Blw.BannedLock, &oldIrql);
    for (i = 0; i < BLW_MAX_PROTECTED; i++) {
        if ((ULONG)g_Blw.BannedPids[i] == Pid) {
            KeReleaseSpinLock(&g_Blw.BannedLock, oldIrql);
            return TRUE;
        }
    }
    InterlockedOr64(&g_Blw.BannedPidMask, (LONG64)BLW_PID_BIT(Pid));
    for (i = 0; i < BLW_MAX_PROTECTED; i++) {
        if (InterlockedCompareExchange(&g_Blw.BannedPids[i], (LONG)Pid, 0) == 0) {
            InterlockedIncrement(&g_Blw.BannedPidCount);
            added = TRUE;
            break;
        }
    }
    KeReleaseSpinLock(&g_Blw.BannedLock, oldIrql);

    if (added) {
        KdPrint(("[Bulwark] Banned actor PID %u (deny ALL its behaviors).\n", Pid));
    }
    return added;
}

void
BlwRemoveBannedPid(_In_ ULONG Pid)
{
    KIRQL oldIrql;
    ULONG i;

    if (Pid == 0) {
        return;
    }

    if (g_Blw.BannedPidCount <= 0 ||
        ((ULONG64)g_Blw.BannedPidMask & BLW_PID_BIT(Pid)) == 0) {
        return;
    }

    KeAcquireSpinLock(&g_Blw.BannedLock, &oldIrql);
    for (i = 0; i < BLW_MAX_PROTECTED; i++) {
        if ((ULONG)g_Blw.BannedPids[i] == Pid) {
            InterlockedExchange(&g_Blw.BannedPids[i], 0);
            InterlockedDecrement(&g_Blw.BannedPidCount);
            BlwRebuildBannedMask();
            break;
        }
    }
    KeReleaseSpinLock(&g_Blw.BannedLock, oldIrql);
}

BOOLEAN
BlwPidIsBanned(_In_ ULONG Pid)
{
    return BlwPidSetContains(g_Blw.BannedPids, &g_Blw.BannedPidMask, Pid);
}

static void
BlwReportSelfProtect(_In_ ULONG actorPid, _In_ ULONG targetPid)
{
    if (!g_Blw.Active || KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return;
    }

    BlwReportEvent(BlwEventSelfProtect, actorPid, targetPid, NULL, NULL, 0, 0);
}

static void
BlwReportTokenAttack(_In_ ULONG actorPid, _In_ ULONG targetPid)
{
    if (!g_Blw.Active || KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return;
    }

    BlwReportEvent(BlwEventTokenAttack, actorPid, targetPid, NULL, NULL, 0, 0);
}

static void
BlwReportMemProtect(_In_ ULONG actorPid, _In_ ULONG targetPid)
{
    if (!g_Blw.Active || KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return;
    }

    BlwReportEvent(BlwEventMemoryProtect, actorPid, targetPid, NULL, NULL, 0, 0);
}

C_ASSERT((BLW_REPORT_SLOTS & (BLW_REPORT_SLOTS - 1)) == 0);
static volatile LONG64 g_CredDumpSeen[BLW_REPORT_SLOTS];
static volatile LONG64 g_UiGuardSeen[BLW_REPORT_SLOTS];
static volatile LONG64 g_ThreadContextSeen[BLW_REPORT_SLOTS];

// 同一格被别的 PID 占走只会多报一条。
BOOLEAN
BlwReportOncePerWindow(_Inout_updates_(BLW_REPORT_SLOTS) volatile LONG64* Table, _In_ ULONG ActorPid)
{
    volatile LONG64* slot = &Table[(ActorPid >> 2) & (BLW_REPORT_SLOTS - 1)];
    const ULONG now = (ULONG)(KeQueryInterruptTime() / 10000000ULL);
    const ULONG64 seen = (ULONG64)*slot;

    if ((ULONG)(seen >> 32) == ActorPid && (ULONG)(now - (ULONG)seen) < BLW_REPORT_WINDOW_S) {
        return FALSE;
    }
    InterlockedExchange64(slot, (LONG64)(((ULONG64)ActorPid << 32) | now));
    return TRUE;
}

// 权限照剥不误,这里只决定报不报。系统目录与标准安装目录下的非 LOLBin(Defender 扫内存、
// 任务管理器取命令行)不报;映像路径随事件带上,转储工具往往一闪即退,服务端未必还查得到。
static void
BlwReportCredDump(_In_ ULONG ActorPid, _In_ ULONG TargetPid, _In_ ACCESS_MASK Stripped)
{
    PUNICODE_STRING image = NULL;
    BOOLEAN quiet = FALSE;

    if (!g_Blw.Active || KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return;
    }
    if (!BlwReportOncePerWindow(g_CredDumpSeen, ActorPid)) {
        return;
    }

    if (NT_SUCCESS(SeLocateProcessImageName(PsGetCurrentProcess(), &image)) && image != NULL &&
        image->Buffer != NULL && image->Length > 0) {
        const USHORT chars = (USHORT)(image->Length / sizeof(WCHAR));
        quiet = BlwImageIsTrustedSystemPath(image->Buffer, chars) &&
                !BlwImageIsLolBin(image->Buffer, chars);
    }
    if (!quiet) {
        BlwReportEvent(BlwEventCredDumpBlocked, ActorPid, TargetPid, NULL, image, Stripped, 0);
    }
    if (image != NULL) {
        ExFreePool(image);
    }
}

// 界面进程:能拿来注入代码或偷走它已认证的管道句柄的权限一律剥掉;结束、挂起、查询照常放行
// (创建者要靠挂起 / 恢复把首线程跑起来)。
#define BLW_UI_PROC_DENY   (PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_CREATE_THREAD | \
                            PROCESS_DUP_HANDLE | PROCESS_SET_INFORMATION)
#define BLW_UI_THREAD_DENY (THREAD_SET_CONTEXT | THREAD_SET_INFORMATION | THREAD_SET_THREAD_TOKEN | \
                            THREAD_IMPERSONATE | THREAD_DIRECT_IMPERSONATION)

// 服务从没连上过时一律 FALSE。
BOOLEAN
BlwPathInProductDir(_In_reads_(Chars) PCWSTR Path, _In_ USHORT Chars)
{
    const LONG svcChars = g_Blw.ServiceImageChars;
    USHORT dirChars;
    USHORT i;

    if (Path == NULL || svcChars <= 0 || svcChars >= BLW_MAX_PATH) {
        return FALSE;
    }
    dirChars = (USHORT)svcChars;
    while (dirChars > 0 && g_Blw.ServiceImageBuffer[dirChars - 1] != L'\\') {
        dirChars--;
    }
    if (dirChars == 0 || Chars <= dirChars) {
        return FALSE;
    }
    for (i = 0; i < dirChars; i++) {
        if (BlwUpcaseChar(Path[i]) != BlwUpcaseChar(g_Blw.ServiceImageBuffer[i])) {
            return FALSE;
        }
    }
    for (i = dirChars; i < Chars; i++) {
        if (Path[i] == L'\\') {
            return FALSE;
        }
    }
    return TRUE;
}

// 按映像身份认本产品界面,不等它连上服务登记成受保护 PID —— 那之前正是抢先注入的窗口。
// 短名先筛,对得上才查完整路径。
BOOLEAN
BlwProcessIsProductUi(_In_ PEPROCESS Process)
{
    static const char kShort[] = "bulwark_ui.exe";
    static const BLW_NAME_ENTRY kUi[] = { BLW_NAME(L"bulwark_ui.exe") };
    PUNICODE_STRING image = NULL;
    BOOLEAN match = FALSE;

    if (BlwShortNameMatches(Process, kShort, sizeof(kShort) - 1) != 1) {
        return FALSE;
    }
    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return TRUE;
    }
    if (NT_SUCCESS(SeLocateProcessImageName(Process, &image)) && image != NULL) {
        if (image->Buffer != NULL && image->Length > 0) {
            const USHORT chars = (USHORT)(image->Length / sizeof(WCHAR));
            match = BlwPathInProductDir(image->Buffer, chars) &&
                    BlwImageNameIn(kUi, RTL_NUMBER_OF(kUi), image->Buffer, chars);
        }
        ExFreePool(image);
    }
    return match;
}

// 可以对界面拿这些权限、也可以启动界面的:本产品自己的进程,以及系统目录里的非 LOLBin
// (csrss 复制句柄、AppInfo 以管理员身份启动界面、资源管理器、任务计划)。ActorPid 须是当前进程。
BOOLEAN
BlwActorMayTouchUi(_In_ ULONG ActorPid)
{
    PUNICODE_STRING image = NULL;
    BOOLEAN ok = FALSE;

    if (BlwPidIsProtected(ActorPid)) {
        return TRUE;
    }
    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return FALSE;
    }
    if (NT_SUCCESS(SeLocateProcessImageName(PsGetCurrentProcess(), &image)) && image != NULL) {
        if (image->Buffer != NULL && image->Length > 0) {
            const USHORT chars = (USHORT)(image->Length / sizeof(WCHAR));
            ok = BlwPathInProductDir(image->Buffer, chars) || BlwImageIsOsComponent(image->Buffer, chars);
        }
        ExFreePool(image);
    }
    return ok;
}

static void
BlwGuardProductUi(_In_ POB_PRE_OPERATION_INFORMATION Info, _Inout_ PACCESS_MASK Desired, _In_ ULONG ActorPid)
{
    const BOOLEAN isProcess = (Info->ObjectType == *PsProcessType);
    const ACCESS_MASK mask = isProcess ? BLW_UI_PROC_DENY : BLW_UI_THREAD_DENY;
    PEPROCESS target;

    if ((*Desired & mask) == 0 || ActorPid == 4) {
        return;
    }
    target = isProcess ? (PEPROCESS)Info->Object : PsGetThreadProcess((PETHREAD)Info->Object);
    if (target == NULL || target == PsGetCurrentProcess()) {
        return;
    }
    if (!BlwProcessIsProductUi(target) || BlwActorMayTouchUi(ActorPid)) {
        return;
    }

    *Desired &= ~mask;
    if (g_Blw.Active && KeGetCurrentIrql() == PASSIVE_LEVEL && BlwReportOncePerWindow(g_UiGuardSeen, ActorPid)) {
        BlwReportEvent(BlwEventSelfProtect, ActorPid, HandleToULong(PsGetProcessId(target)), NULL, NULL, 0, 0);
    }
    KdPrint(("[Bulwark] UiGuard: stripped 0x%x from pid %u -> product UI pid %u\n",
             mask, ActorPid, HandleToULong(PsGetProcessId(target))));
}

static OB_PREOP_CALLBACK_STATUS
BlwPreOperationCallback(
    _In_ PVOID RegistrationContext,
    _In_ POB_PRE_OPERATION_INFORMATION OperationInformation)
{
    ULONG targetPid = 0;
    ULONG actorPid;
    ACCESS_MASK denyMask;
    PACCESS_MASK pDesired;
    ULONG64 anyTargetMask;

    UNREFERENCED_PARAMETER(RegistrationContext);

    if (!g_Blw.ObCallbackRegistered) {
        return OB_PREOP_SUCCESS;
    }

    if (OperationInformation->KernelHandle) {
        return OB_PREOP_SUCCESS;
    }

    actorPid = HandleToULong(PsGetCurrentProcessId());
    if (OperationInformation->Operation == OB_OPERATION_HANDLE_CREATE) {
        pDesired = &OperationInformation->Parameters->CreateHandleInformation.DesiredAccess;
    } else {
        pDesired = &OperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess;
    }

    BlwGuardProductUi(OperationInformation, pDesired, actorPid);

    // This is a requested access right, not evidence that an APC ran or a context changed.
    // Kernel handles/self-access are excluded. Existing target protections below still strip rights.
    if (g_Blw.Active && KeGetCurrentIrql() == PASSIVE_LEVEL && actorPid > 4 &&
        OperationInformation->ObjectType == *PsThreadType && (*pDesired & THREAD_SET_CONTEXT) != 0) {
        const ULONG victim = HandleToULong(PsGetThreadProcessId((PETHREAD)OperationInformation->Object));
        // DuplicateHandle may deposit the handle into a different process. Its actor is ambiguous here.
        if (OperationInformation->Operation == OB_OPERATION_HANDLE_CREATE && victim > 4 && victim != actorPid &&
            !BlwPidIsProtected(actorPid) && BlwReportOncePerWindow(g_ThreadContextSeen, actorPid))
            BlwReportEvent(BlwEventThreadContextAccess, actorPid, victim, NULL, NULL, *pDesired, 0);
    }

    anyTargetMask = (ULONG64)g_Blw.ProtectedPidMask |
                    (ULONG64)g_Blw.CredProtPidMask |
                    (ULONG64)g_Blw.MemProtPidMask;
    if (anyTargetMask == 0) {
        return OB_PREOP_SUCCESS;
    }

    if (OperationInformation->ObjectType == *PsProcessType) {
        PEPROCESS targetProc = (PEPROCESS)OperationInformation->Object;
        targetPid = HandleToULong(PsGetProcessId(targetProc));
        denyMask = BLW_PROC_DENY;
    } else if (OperationInformation->ObjectType == *PsThreadType) {
        PETHREAD targetThread = (PETHREAD)OperationInformation->Object;
        targetPid = HandleToULong(PsGetThreadProcessId(targetThread));
        denyMask = BLW_THREAD_DENY;
    } else {
        return OB_PREOP_SUCCESS;
    }

    if ((anyTargetMask & BLW_PID_BIT(targetPid)) == 0) {
        return OB_PREOP_SUCCESS;
    }

    {
        BOOLEAN targetIsSelf = BlwPidIsProtected(targetPid);
        BOOLEAN targetIsCred = (!targetIsSelf) && BlwPidIsCredProtected(targetPid);
        BOOLEAN targetIsMemProt = (!targetIsSelf && !targetIsCred) && BlwPidIsMemProtected(targetPid);

        if (!targetIsSelf && !targetIsCred && !targetIsMemProt) {
            return OB_PREOP_SUCCESS;
        }

        if (actorPid == targetPid || actorPid == 4 || BlwPidIsProtected(actorPid)) {
            return OB_PREOP_SUCCESS;
        }

        if (targetIsSelf) {
            ACCESS_MASK effDeny = denyMask;
            ACCESS_MASK stripped;

            if (BlwActorIsGenuineLsa(actorPid)) {
                effDeny = 0;
            }



            stripped = *pDesired & effDeny;

            if (stripped != 0) {
                const ACCESS_MASK killBits = (OperationInformation->ObjectType == *PsThreadType)
                    ? BLW_THREAD_DENY_KILL : BLW_PROC_DENY_KILL;

                *pDesired &= ~effDeny;
                if ((stripped & killBits) != 0) {
                    BlwReportSelfProtect(actorPid, targetPid);
                } else {
                    BlwReportTokenAttack(actorPid, targetPid);
                }
                KdPrint(("[Bulwark] SelfProtect: stripped 0x%x (of 0x%x) from pid %u -> pid %u\n",
                    stripped, effDeny, actorPid, targetPid));
            }
        } else if (targetIsCred) {
            ACCESS_MASK credMask = (OperationInformation->ObjectType == *PsThreadType)
                ? BLW_MEMPROT_THREAD_DENY : BLW_CRED_PROC_DENY;
            const ACCESS_MASK stripped = *pDesired & credMask;
            if (stripped != 0) {
                *pDesired &= ~credMask;
                BlwReportCredDump(actorPid, targetPid, stripped);
                KdPrint(("[Bulwark] CredProtect(LSASS): stripped 0x%x from pid %u -> pid %u (anti-dump)\n",
                    stripped, actorPid, targetPid));
            }
        } else {
            ACCESS_MASK memMask = (OperationInformation->ObjectType == *PsThreadType)
                ? BLW_MEMPROT_THREAD_DENY : BLW_MEMPROT_PROC_DENY;
            if ((*pDesired & memMask) != 0) {
                *pDesired &= ~memMask;
                BlwReportMemProtect(actorPid, targetPid);
                KdPrint(("[Bulwark] MemProtect: stripped 0x%x from pid %u -> pid %u (anti-inject)\n",
                    memMask, actorPid, targetPid));
            }
        }
    }

    return OB_PREOP_SUCCESS;
}

NTSTATUS
BlwRegisterObCallbacks(void)
{
    NTSTATUS status;
    OB_OPERATION_REGISTRATION ops[2];
    OB_CALLBACK_REGISTRATION reg;
    UNICODE_STRING altitude;

    if (g_Blw.ObCallbackRegistered) {
        return STATUS_SUCCESS;
    }

    RtlZeroMemory(ops, sizeof(ops));

    ops[0].ObjectType = PsProcessType;
    ops[0].Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    ops[0].PreOperation = BlwPreOperationCallback;
    ops[0].PostOperation = NULL;

    ops[1].ObjectType = PsThreadType;
    ops[1].Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    ops[1].PreOperation = BlwPreOperationCallback;
    ops[1].PostOperation = NULL;

    RtlInitUnicodeString(&altitude, L"385199");

    RtlZeroMemory(&reg, sizeof(reg));
    reg.Version = OB_FLT_REGISTRATION_VERSION;
    reg.OperationRegistrationCount = 2;
    reg.Altitude = altitude;
    reg.RegistrationContext = NULL;
    reg.OperationRegistration = ops;

    status = ObRegisterCallbacks(&reg, &g_Blw.ObRegHandle);
    if (NT_SUCCESS(status)) {
        g_Blw.ObCallbackRegistered = TRUE;
        KdPrint(("[Bulwark] Ob callbacks registered.\n"));
    } else {
        KdPrint(("[Bulwark] ObRegisterCallbacks failed 0x%x\n", status));
    }
    return status;
}

void
BlwUnregisterObCallbacks(void)
{
    if (g_Blw.ObCallbackRegistered) {
        g_Blw.ObCallbackRegistered = FALSE;
        if (g_Blw.ObRegHandle != NULL) {
            ObUnRegisterCallbacks(g_Blw.ObRegHandle);
            g_Blw.ObRegHandle = NULL;
        }
        KdPrint(("[Bulwark] Ob callbacks unregistered.\n"));
    }
}
