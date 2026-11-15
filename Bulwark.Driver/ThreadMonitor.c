#include "Driver.h"

static BOOLEAN g_ThreadCallbackRegistered = FALSE;

// 新进程的第一个线程由创建者建立,在线程回调里和远程注入长得一样(创建者 != 目标)。
// 进程创建回调先于首线程的线程回调运行:那里登记 (新 PID << 32 | 创建者 PID),这里取走
// 匹配的一格即认作首线程。两个新进程撞同一格只会多报一条,不会漏掉真正的注入。
#define BLW_FRESH_SLOTS 256
C_ASSERT((BLW_FRESH_SLOTS & (BLW_FRESH_SLOTS - 1)) == 0);
static volatile LONG64 g_FreshProcess[BLW_FRESH_SLOTS];

static LONG64
BlwFreshKey(_In_ ULONG Pid, _In_ ULONG CreatorPid)
{
    return (LONG64)(((ULONG64)Pid << 32) | (ULONG64)CreatorPid);
}

void
BlwNoteProcessCreated(_In_ ULONG Pid, _In_ ULONG CreatorPid)
{
    InterlockedExchange64(&g_FreshProcess[(Pid >> 2) & (BLW_FRESH_SLOTS - 1)],
                          BlwFreshKey(Pid, CreatorPid));
}

static BOOLEAN
BlwConsumeInitialThread(_In_ ULONG TargetPid, _In_ ULONG ActorPid)
{
    const LONG64 key = BlwFreshKey(TargetPid, ActorPid);

    return InterlockedCompareExchange64(&g_FreshProcess[(TargetPid >> 2) & (BLW_FRESH_SLOTS - 1)],
                                        0, key) == key;
}

static BOOLEAN
BlwTargetIsInjectionWatched(_In_ HANDLE Pid)
{
    PEPROCESS proc = NULL;
    PUNICODE_STRING name = NULL;
    BOOLEAN hit = FALSE;

    if (!NT_SUCCESS(PsLookupProcessByProcessId(Pid, &proc)) || proc == NULL) {
        return FALSE;
    }
    if (NT_SUCCESS(SeLocateProcessImageName(proc, &name)) && name != NULL) {
        if (name->Buffer != NULL && name->Length > 0) {
            hit = BlwIsInjectionTelemetryTarget(name->Buffer, (USHORT)(name->Length / sizeof(WCHAR)));
        }
        ExFreePool(name);
    }
    ObDereferenceObject(proc);
    return hit;
}

static VOID
BlwCreateThreadNotify(
    _In_ HANDLE ProcessId,
    _In_ HANDLE ThreadId,
    _In_ BOOLEAN Create)
{
    ULONG actorPid;
    ULONG targetPid;

    UNREFERENCED_PARAMETER(ThreadId);

    if (!Create) {
        return;
    }

    actorPid = HandleToULong(PsGetCurrentProcessId());
    targetPid = HandleToULong(ProcessId);

    if (actorPid == targetPid) {
        return;
    }

    // 服务未连接时也要取走登记,否则留下的旧登记会在之后吞掉一条真正的注入。
    if (BlwConsumeInitialThread(targetPid, actorPid)) {
        return;
    }

    if (!g_Blw.Active) {
        return;
    }
    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return;
    }

    if (actorPid == 4 || actorPid == 0) {
        return;
    }

    if (BlwPidIsProtected(actorPid)) {
        return;
    }

    if (!BlwTargetIsInjectionWatched(ProcessId)) {
        return;
    }

    BlwReportEvent(BlwEventRemoteThread, actorPid, targetPid, NULL, NULL, 0, 0);
}

NTSTATUS
BlwRegisterThreadCallback(void)
{
    NTSTATUS status;

    if (g_ThreadCallbackRegistered) {
        return STATUS_SUCCESS;
    }

    status = PsSetCreateThreadNotifyRoutine(BlwCreateThreadNotify);
    if (NT_SUCCESS(status)) {
        g_ThreadCallbackRegistered = TRUE;
        KdPrint(("[Bulwark] Thread-create callback registered.\n"));
    } else {
        KdPrint(("[Bulwark] PsSetCreateThreadNotifyRoutine failed 0x%x\n", status));
    }
    return status;
}

void
BlwUnregisterThreadCallback(void)
{
    if (g_ThreadCallbackRegistered) {
        PsRemoveCreateThreadNotifyRoutine(BlwCreateThreadNotify);
        g_ThreadCallbackRegistered = FALSE;
        KdPrint(("[Bulwark] Thread-create callback unregistered.\n"));
    }
}
