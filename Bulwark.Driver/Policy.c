#include "Driver.h"

#define BLW_POLICY_SUBKEY  L"\\Policy"

#define BLW_POLICY_VALUE_MAX  0x10000   // 64 KB

typedef void (*BLW_ADD_STRING_FN)(_In_ PCWSTR Path, _In_ USHORT Length);

void
BlwSaveRegistryPath(_In_opt_ PUNICODE_STRING RegistryPath)
{
    g_Blw.RegistryPath.Buffer = g_Blw.RegistryPathBuffer;
    g_Blw.RegistryPath.Length = 0;
    g_Blw.RegistryPath.MaximumLength = sizeof(g_Blw.RegistryPathBuffer);

    if (RegistryPath != NULL && RegistryPath->Buffer != NULL &&
        RegistryPath->Length > 0 &&
        RegistryPath->Length < sizeof(g_Blw.RegistryPathBuffer)) {
        RtlCopyMemory(g_Blw.RegistryPathBuffer, RegistryPath->Buffer, RegistryPath->Length);
        g_Blw.RegistryPath.Length = RegistryPath->Length;
    }
}

// PASSIVE_LEVEL。Create=TRUE 用于写回(不存在则创建),FALSE 用于加载(不存在即失败)。
static NTSTATUS
BlwOpenOrCreatePolicyKey(_In_ BOOLEAN Create, _Out_ PHANDLE OutKey)
{
    UNICODE_STRING subKey;
    UNICODE_STRING policyPath;
    OBJECT_ATTRIBUTES oa;
    PWCH buf;
    USHORT totalLen;
    NTSTATUS status;

    *OutKey = NULL;

    if (g_Blw.RegistryPath.Length == 0 || g_Blw.RegistryPath.Buffer == NULL) {
        return STATUS_UNSUCCESSFUL;
    }

    RtlInitUnicodeString(&subKey, BLW_POLICY_SUBKEY);
    if ((ULONG)g_Blw.RegistryPath.Length + subKey.Length + sizeof(WCHAR) > 0xFFFF) {
        return STATUS_UNSUCCESSFUL;
    }
    totalLen = g_Blw.RegistryPath.Length + subKey.Length;

    buf = (PWCH)BlwAllocPool(PagedPool, (SIZE_T)totalLen + sizeof(WCHAR), BLW_TAG);
    if (buf == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlCopyMemory(buf, g_Blw.RegistryPath.Buffer, g_Blw.RegistryPath.Length);
    RtlCopyMemory((PUCHAR)buf + g_Blw.RegistryPath.Length, subKey.Buffer, subKey.Length);
    buf[totalLen / sizeof(WCHAR)] = L'\0';

    policyPath.Buffer = buf;
    policyPath.Length = totalLen;
    policyPath.MaximumLength = totalLen + sizeof(WCHAR);

    InitializeObjectAttributes(&oa, &policyPath,
        OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);

    if (Create) {
        ULONG disposition = 0;
        status = ZwCreateKey(OutKey, KEY_SET_VALUE, &oa, 0, NULL,
            REG_OPTION_NON_VOLATILE, &disposition);
    } else {
        status = ZwOpenKey(OutKey, KEY_READ, &oa);
    }

    ExFreePoolWithTag(buf, BLW_TAG);
    return status;
}

static PWCH
BlwQueryMultiSz(_In_ HANDLE KeyHandle, _In_ PCWSTR ValueName, _Out_ PULONG OutChars)
{
    UNICODE_STRING valName;
    NTSTATUS status;
    ULONG needed = 0;
    PKEY_VALUE_PARTIAL_INFORMATION info;
    PWCH out = NULL;

    *OutChars = 0;
    RtlInitUnicodeString(&valName, ValueName);

    status = ZwQueryValueKey(KeyHandle, &valName, KeyValuePartialInformation, NULL, 0, &needed);
    if (needed == 0 || needed > BLW_POLICY_VALUE_MAX) {
        return NULL;
    }

    info = (PKEY_VALUE_PARTIAL_INFORMATION)BlwAllocPool(PagedPool, needed, BLW_TAG);
    if (info == NULL) {
        return NULL;
    }

    status = ZwQueryValueKey(KeyHandle, &valName, KeyValuePartialInformation, info, needed, &needed);
    if (NT_SUCCESS(status) &&
        info->Type == REG_MULTI_SZ &&
        info->DataLength >= sizeof(WCHAR)) {

        ULONG chars = info->DataLength / sizeof(WCHAR);
        out = (PWCH)BlwAllocPool(PagedPool, (SIZE_T)(chars + 1) * sizeof(WCHAR), BLW_TAG);
        if (out != NULL) {
            RtlCopyMemory(out, info->Data, (SIZE_T)chars * sizeof(WCHAR));
            out[chars] = L'\0';   // 保护 NUL,枚举不越界
            *OutChars = chars;
        }
    }

    ExFreePoolWithTag(info, BLW_TAG);
    return out;
}

static void
BlwApplyStringList(_In_ HANDLE KeyHandle, _In_ PCWSTR ValueName, _In_ BLW_ADD_STRING_FN Add)
{
    ULONG chars = 0;
    PWCH buf = BlwQueryMultiSz(KeyHandle, ValueName, &chars);
    ULONG i = 0;
    ULONG loaded = 0;

    if (buf == NULL) {
        return;
    }

    while (i < chars && buf[i] != L'\0') {
        ULONG start = i;
        USHORT len;

        while (i < chars && buf[i] != L'\0') {
            i++;
        }
        len = (USHORT)(i - start);
        if (len > 0 && len < BLW_MAX_PATH) {
            Add(&buf[start], len);
            loaded++;
        }
        i++;
    }

    if (loaded > 0) {
        KdPrint(("[Bulwark] Policy: loaded %lu entries for %ws.\n", loaded, ValueName));
    }
    ExFreePoolWithTag(buf, BLW_TAG);
}

static BOOLEAN
BlwParseIpv4(_In_ PCWSTR s, _In_ ULONG len, _Out_ PULONG OutIpHost, _Out_ PUSHORT OutPort)
{
    ULONG octets[4] = { 0, 0, 0, 0 };
    ULONG oi = 0;
    ULONG cur = 0;
    ULONG port = 0;
    BOOLEAN haveDigit = FALSE;
    BOOLEAN inPort = FALSE;
    ULONG i;

    *OutIpHost = 0;
    *OutPort = 0;

    for (i = 0; i < len; i++) {
        WCHAR c = s[i];
        if (c >= L'0' && c <= L'9') {
            if (inPort) {
                port = port * 10 + (ULONG)(c - L'0');
                if (port > 65535) return FALSE;
            } else {
                cur = cur * 10 + (ULONG)(c - L'0');
                if (cur > 255) return FALSE;
                haveDigit = TRUE;
            }
        } else if (c == L'.' && !inPort) {
            if (!haveDigit || oi >= 3) return FALSE;
            octets[oi++] = cur;
            cur = 0;
            haveDigit = FALSE;
        } else if (c == L':' && !inPort) {
            if (!haveDigit || oi != 3) return FALSE;
            octets[oi++] = cur;
            cur = 0;
            haveDigit = FALSE;
            inPort = TRUE;
        } else {
            return FALSE;
        }
    }

    if (inPort) {
        if (oi != 4) return FALSE;
        *OutPort = (USHORT)port;
    } else {
        if (!haveDigit || oi != 3) return FALSE;
        octets[oi++] = cur;
        *OutPort = 0;
    }

    *OutIpHost = (octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3];
    return TRUE;
}

static void
BlwLoadBlockIps(_In_ HANDLE KeyHandle)
{
    ULONG chars = 0;
    PWCH buf = BlwQueryMultiSz(KeyHandle, L"BlockIps", &chars);
    ULONG i = 0;
    ULONG loaded = 0;

    if (buf == NULL) {
        return;
    }

    while (i < chars && buf[i] != L'\0') {
        ULONG start = i;
        ULONG len;
        ULONG ip = 0;
        USHORT port = 0;

        while (i < chars && buf[i] != L'\0') {
            i++;
        }
        len = i - start;
        if (len > 0 && BlwParseIpv4(&buf[start], len, &ip, &port)) {
            BlwAddBlockIp(ip, port);
            loaded++;
        }
        i++;
    }

    if (loaded > 0) {
        KdPrint(("[Bulwark] Policy: loaded %lu network blocklist entries.\n", loaded));
    }
    ExFreePoolWithTag(buf, BLW_TAG);
}

// PASSIVE_LEVEL,失败非致命。须在 BlwSaveRegistryPath 之后调用。
void
BlwLoadPolicyFromRegistry(void)
{
    HANDLE hKey = NULL;
    NTSTATUS status = BlwOpenOrCreatePolicyKey(FALSE, &hKey);

    if (!NT_SUCCESS(status) || hKey == NULL) {
        KdPrint(("[Bulwark] Policy: no \\Policy key (0x%x), baseline empty.\n", status));
        return;
    }

    BlwApplyStringList(hKey, L"ProtectedPaths",   BlwAddProtectedPath);
    BlwApplyStringList(hKey, L"FileHardBlock",    BlwAddFileHardBlock);
    BlwApplyStringList(hKey, L"FileNoLoad",       BlwAddFileNoLoad);
    BlwApplyStringList(hKey, L"FileExecBlock",    BlwAddFileExecBlock);
    BlwApplyStringList(hKey, L"ProtectedRegKeys", BlwAddProtectedRegKey);
    BlwApplyStringList(hKey, L"RegHardBlock",     BlwAddRegHardBlock);
    BlwApplyStringList(hKey, L"CmdHardBlock",     BlwAddCmdHardBlock);
    // GuardDirs 与 GuardWriters 必须一起载入:只有目录会在服务连上前持续误拦,只有例外则这一维不生效。
    BlwApplyStringList(hKey, L"GuardDirs",        BlwAddGuardDir);
    BlwApplyStringList(hKey, L"GuardWriters",     BlwAddGuardWriter);
    // 窃密防护条目与全局读者同理:服务连上之前就要生效,且两者必须成对载入。
    BlwApplyStringList(hKey, L"ReadGuard",        BlwAddReadGuard);
    BlwApplyStringList(hKey, L"ReadGuardReaders", BlwAddReadGuardReader);
    BlwLoadBlockIps(hKey);
    BlwApplyStringList(hKey, L"KnownBadSha256",   BlwAddKnownBadHex);

    BlwApplyStringList(hKey, L"ServiceImagePath", BlwSetServiceImagePath);

    ZwClose(hKey);
    KdPrint(("[Bulwark] Policy baseline loaded from registry.\n"));
}

void
BlwSetServiceImagePath(_In_ PCWSTR Path, _In_ USHORT Length)
{
    if (Path == NULL || Length == 0 || Length >= BLW_MAX_PATH) {
        return;
    }
    if (g_Blw.ServiceImageChars != 0) {
        return;
    }
    RtlCopyMemory(g_Blw.ServiceImageBuffer, Path, (SIZE_T)Length * sizeof(WCHAR));
    g_Blw.ServiceImageBuffer[Length] = L'\0';
    InterlockedExchange(&g_Blw.ServiceImageChars, (LONG)Length);
    KdPrint(("[Bulwark] Policy: expected service image loaded (%u chars).\n", Length));
}

void
BlwPersistServiceImagePath(void)
{
    HANDLE hKey = NULL;
    const LONG chars = g_Blw.ServiceImageChars;

    if (chars <= 0 || chars >= BLW_MAX_PATH) {
        return;
    }
    if (!NT_SUCCESS(BlwOpenOrCreatePolicyKey(TRUE, &hKey)) || hKey == NULL) {
        return;
    }
    {
        UNICODE_STRING valName;
        const ULONG cb = (ULONG)((chars + 2) * sizeof(WCHAR));
        PWCH data = (PWCH)BlwAllocPool(PagedPool, cb, BLW_TAG);
        if (data != NULL) {
            RtlCopyMemory(data, g_Blw.ServiceImageBuffer, (SIZE_T)chars * sizeof(WCHAR));
            data[chars] = L'\0';
            data[chars + 1] = L'\0';
            RtlInitUnicodeString(&valName, L"ServiceImagePath");
            ZwSetValueKey(hKey, &valName, 0, REG_MULTI_SZ, data, cb);
            ExFreePoolWithTag(data, BLW_TAG);
            KdPrint(("[Bulwark] Policy: persisted expected service image path.\n"));
        }
    }
    ZwClose(hKey);
}

// 把名单序列化为 REG_MULTI_SZ 写回 \Policy\<ValueName>。持锁期间普通 APC 被关,不能拿着名单锁
// 去做注册表 I/O,所以持锁只做内存拷贝,放锁后再写注册表。
static void
BlwPersistListToRegistry(_In_ PCWSTR ValueName, _In_ BLW_PROTECTED_PATH* List, _Inout_ PEX_PUSH_LOCK Lock)
{
    SIZE_T maxChars;
    PWCH data;
    SIZE_T pos = 0;
    ULONG i;
    HANDLE hKey = NULL;

    if (g_Blw.RegistryPath.Length == 0) {
        return;
    }

    maxChars = (SIZE_T)BLW_MAX_PROTECTED * BLW_MAX_PATH + 1;
    data = (PWCH)BlwAllocPool(PagedPool, maxChars * sizeof(WCHAR), BLW_TAG);
    if (data == NULL) {
        return;
    }

    BlwLockShared(Lock);
    for (i = 0; i < BLW_MAX_PROTECTED; i++) {
        USHORT len;
        if (!List[i].InUse) {
            continue;
        }
        len = List[i].Length;
        if (len == 0 || len >= BLW_MAX_PATH) {
            continue;
        }
        if (pos + (SIZE_T)len + 1 > maxChars) {
            break;   // 越界保护
        }
        RtlCopyMemory(&data[pos], List[i].Path, (SIZE_T)len * sizeof(WCHAR));
        pos += len;
        data[pos++] = L'\0';
    }
    BlwUnlock(Lock);

    if (pos >= maxChars) {
        pos = maxChars - 1;
    }
    data[pos++] = L'\0';

    if (NT_SUCCESS(BlwOpenOrCreatePolicyKey(TRUE, &hKey)) && hKey != NULL) {
        UNICODE_STRING valName;
        RtlInitUnicodeString(&valName, ValueName);
        ZwSetValueKey(hKey, &valName, 0, REG_MULTI_SZ, data, (ULONG)(pos * sizeof(WCHAR)));
        ZwClose(hKey);
        KdPrint(("[Bulwark] Policy: persisted %ws (%Iu chars).\n", ValueName, pos));
    }

    ExFreePoolWithTag(data, BLW_TAG);
}

#define BLW_POLICY_DEBOUNCE_100NS  (300LL * 10 * 1000)

// 须在 PASSIVE_LEVEL 调用(写回用 Zw*)。
static void
BlwFlushDirtyPolicy(_In_ LONG Dirty)
{
    if (Dirty == 0) {
        return;
    }
    if (Dirty & BLW_POLICY_DIRTY_PATHS) {
        BlwPersistListToRegistry(L"ProtectedPaths", g_Blw.ProtectedPaths, &g_Blw.PathLock);
    }
    if (Dirty & BLW_POLICY_DIRTY_FILEHARD) {
        BlwPersistListToRegistry(L"FileHardBlock", g_Blw.FileHardBlock, &g_Blw.FileHardLock);
    }
    if (Dirty & BLW_POLICY_DIRTY_NOLOAD) {
        BlwPersistListToRegistry(L"FileNoLoad", g_Blw.FileNoLoad, &g_Blw.FileNoLoadLock);
    }
    if (Dirty & BLW_POLICY_DIRTY_EXECBLOCK) {
        BlwPersistListToRegistry(L"FileExecBlock", g_Blw.FileExecBlock, &g_Blw.FileExecBlockLock);
    }
    if (Dirty & BLW_POLICY_DIRTY_REGKEYS) {
        BlwPersistListToRegistry(L"ProtectedRegKeys", g_Blw.ProtectedRegKeys, &g_Blw.RegLock);
    }
    if (Dirty & BLW_POLICY_DIRTY_REGHARD) {
        BlwPersistListToRegistry(L"RegHardBlock", g_Blw.RegHardBlock, &g_Blw.RegHardLock);
    }
    if (Dirty & BLW_POLICY_DIRTY_CMDHARD) {
        BlwPersistListToRegistry(L"CmdHardBlock", g_Blw.CmdHardBlock, &g_Blw.CmdHardLock);
    }
    if (Dirty & BLW_POLICY_DIRTY_GUARDDIR) {
        BlwPersistListToRegistry(L"GuardDirs", g_Blw.GuardDirs, &g_Blw.GuardDirLock);
    }
    if (Dirty & BLW_POLICY_DIRTY_GUARDWRITER) {
        BlwPersistListToRegistry(L"GuardWriters", g_Blw.GuardWriters, &g_Blw.GuardWriterLock);
    }
    if (Dirty & BLW_POLICY_DIRTY_READGUARD) {
        BlwPersistListToRegistry(L"ReadGuard", g_Blw.ReadGuard, &g_Blw.ReadGuardLock);
    }
    if (Dirty & BLW_POLICY_DIRTY_READGUARD_READER) {
        BlwPersistListToRegistry(L"ReadGuardReaders", g_Blw.ReadGuardReaders, &g_Blw.ReadGuardReaderLock);
    }
}

static VOID
BlwPolicyPersistThread(_In_ PVOID Context)
{
    UNREFERENCED_PARAMETER(Context);

    for (;;) {
        LONG dirty;
        BOOLEAN stopping;

        KeWaitForSingleObject(&g_Blw.PolicyEvent, Executive, KernelMode, FALSE, NULL);

        stopping = (InterlockedCompareExchange(&g_Blw.PolicyStop, 0, 0) != 0);

        if (!stopping) {
            LARGE_INTEGER delay;
            delay.QuadPart = -BLW_POLICY_DEBOUNCE_100NS;
            KeDelayExecutionThread(KernelMode, FALSE, &delay);
            stopping = (InterlockedCompareExchange(&g_Blw.PolicyStop, 0, 0) != 0);
        }

        dirty = InterlockedExchange(&g_Blw.PolicyDirtyMask, 0);
        BlwFlushDirtyPolicy(dirty);

        if (stopping) {
            dirty = InterlockedExchange(&g_Blw.PolicyDirtyMask, 0);
            BlwFlushDirtyPolicy(dirty);
            break;
        }
    }

    PsTerminateSystemThread(STATUS_SUCCESS);
}

void
BlwMarkDeadEntryDrop(_In_ LONG DirtyBit)
{
    if (DirtyBit != 0) {
        InterlockedOr(&g_Blw.PolicyDeadDropMask, DirtyBit);
    }
}

void
BlwPersistDeadEntryDrops(void)
{
    const LONG mask = InterlockedExchange(&g_Blw.PolicyDeadDropMask, 0);

    if (mask == 0) {
        return;
    }
    KdPrint(("[Bulwark] Policy: rewriting lists 0x%x to purge dead (drive-letter) entries.\n", mask));
    BlwMarkPolicyDirty(mask);
}

void
BlwMarkPolicyDirty(_In_ LONG DirtyBits)
{
    if (DirtyBits == 0) {
        return;
    }

    if (g_Blw.PolicyThread == NULL) {
        BlwFlushDirtyPolicy(DirtyBits);
        return;
    }

    InterlockedOr(&g_Blw.PolicyDirtyMask, DirtyBits);
    KeSetEvent(&g_Blw.PolicyEvent, IO_NO_INCREMENT, FALSE);
}

NTSTATUS
BlwStartPolicyPersist(void)
{
    HANDLE threadHandle = NULL;
    NTSTATUS status;

    g_Blw.PolicyDirtyMask = 0;
    g_Blw.PolicyStop = 0;
    KeInitializeEvent(&g_Blw.PolicyEvent, SynchronizationEvent, FALSE);

    status = PsCreateSystemThread(&threadHandle, THREAD_ALL_ACCESS,
        NULL, NULL, NULL, BlwPolicyPersistThread, NULL);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = ObReferenceObjectByHandle(threadHandle, THREAD_ALL_ACCESS, *PsThreadType,
        KernelMode, (PVOID*)&g_Blw.PolicyThread, NULL);
    if (!NT_SUCCESS(status)) {
        KdPrint(("[Bulwark] ObReferenceObjectByHandle(policy) failed 0x%08X; stopping worker.\n",
                 status));
        g_Blw.PolicyThread = NULL;
        InterlockedExchange(&g_Blw.PolicyStop, 1);
        KeSetEvent(&g_Blw.PolicyEvent, IO_NO_INCREMENT, FALSE);
        (void)ZwWaitForSingleObject(threadHandle, FALSE, NULL);
        ZwClose(threadHandle);
        return status;
    }
    ZwClose(threadHandle);

    KdPrint(("[Bulwark] Policy persist worker started.\n"));
    return STATUS_SUCCESS;
}

void
BlwStopPolicyPersist(void)
{
    InterlockedExchange(&g_Blw.PolicyStop, 1);
    KeSetEvent(&g_Blw.PolicyEvent, IO_NO_INCREMENT, FALSE);

    if (g_Blw.PolicyThread != NULL) {
        KeWaitForSingleObject(g_Blw.PolicyThread, Executive, KernelMode, FALSE, NULL);
        ObDereferenceObject(g_Blw.PolicyThread);
        g_Blw.PolicyThread = NULL;
    }

    {
        LONG dirty = InterlockedExchange(&g_Blw.PolicyDirtyMask, 0);
        BlwFlushDirtyPolicy(dirty);
    }
    KdPrint(("[Bulwark] Policy persist worker stopped.\n"));
}
