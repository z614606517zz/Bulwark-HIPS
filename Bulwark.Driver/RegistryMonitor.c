#include "Driver.h"

void
BlwClearProtectedRegKeys(void)
{
    BlwLockExclusive(&g_Blw.RegLock);
    RtlZeroMemory(g_Blw.ProtectedRegKeys, sizeof(g_Blw.ProtectedRegKeys));
    InterlockedExchange(&g_Blw.ProtectedRegCount, 0);
    BlwUnlock(&g_Blw.RegLock);
}

void
BlwAddProtectedRegKey(_In_ PCWSTR Key, _In_ USHORT Length)
{
    BlwLockExclusive(&g_Blw.RegLock);
    BlwAddToList(g_Blw.ProtectedRegKeys, Key, Length);
    {
        LONG cnt = 0;
        ULONG i;
        for (i = 0; i < BLW_MAX_PROTECTED; i++) {
            if (g_Blw.ProtectedRegKeys[i].InUse) cnt++;
        }
        InterlockedExchange(&g_Blw.ProtectedRegCount, cnt);
    }
    BlwUnlock(&g_Blw.RegLock);
}

static BOOLEAN
BlwRegKeyIsProtected(_In_ PBLW_MATCH_CTX Ctx, _In_ USHORT KeyChars)
{
    BOOLEAN matched;
    BlwLockShared(&g_Blw.RegLock);
    matched = BlwMatchInListCtx(g_Blw.ProtectedRegKeys, g_Blw.ProtectedRegCount, Ctx, KeyChars);
    BlwUnlock(&g_Blw.RegLock);
    return matched;
}

void
BlwClearRegHardBlock(void)
{
    BlwLockExclusive(&g_Blw.RegHardLock);
    RtlZeroMemory(g_Blw.RegHardBlock, sizeof(g_Blw.RegHardBlock));
    InterlockedExchange(&g_Blw.RegHardCount, 0);
    BlwUnlock(&g_Blw.RegHardLock);
}

BOOLEAN
BlwAddRegHardBlock(_In_ PCWSTR Key, _In_ USHORT Length)
{
    BOOLEAN accepted;
    BlwLockExclusive(&g_Blw.RegHardLock);
    accepted = BlwAddToList(g_Blw.RegHardBlock, Key, Length);
    {
        LONG cnt = 0;
        ULONG i;
        for (i = 0; i < BLW_MAX_PROTECTED; i++) {
            if (g_Blw.RegHardBlock[i].InUse) cnt++;
        }
        InterlockedExchange(&g_Blw.RegHardCount, cnt);
    }
    BlwUnlock(&g_Blw.RegHardLock);
    return accepted;
}

BOOLEAN
BlwDelRegHardBlock(_In_ PCWSTR Key, _In_ USHORT Length)
{
    return BlwRemoveFromGuardedList(g_Blw.RegHardBlock, &g_Blw.RegHardLock,
                                    &g_Blw.RegHardCount, Key, Length);
}

// 预通知里 Data / ValueName / NewName 对用户态调用方可能仍指向调用方的地址空间,另一个线程
// 随时能释放或改写它们。用户态地址先探测再在 __try 内拷出;内核地址是系统已捕获的副本,直接读
// (对内核地址做 ProbeForRead 会抛异常,而 __try 兜不住无效的内核地址)。
static BOOLEAN
BlwRegCaptureUlong(_In_opt_ const VOID* Src, _Out_ PULONG Out)
{
    BOOLEAN ok = TRUE;

    *Out = 0;
    if (Src == NULL) {
        return FALSE;
    }
    if ((ULONG_PTR)Src >= (ULONG_PTR)MM_USER_PROBE_ADDRESS) {
        *Out = *(const ULONG UNALIGNED*)Src;
        return TRUE;
    }
    __try {
        ProbeForRead((PVOID)Src, sizeof(ULONG), 1);
        *Out = *(const ULONG UNALIGNED*)Src;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        *Out = 0;
        ok = FALSE;
    }
    return ok;
}

static BOOLEAN
BlwRegCaptureName(_In_opt_ PCUNICODE_STRING Src,
                  _Out_writes_(CapChars) PWCH Buf, _In_ USHORT CapChars,
                  _Out_ PUNICODE_STRING Dst)
{
    UNICODE_STRING s;
    USHORT bytes = 0;

    Dst->Buffer = Buf;
    Dst->Length = 0;
    Dst->MaximumLength = (USHORT)(CapChars * sizeof(WCHAR));
    if (Src == NULL) {
        return FALSE;
    }

    __try {
        if ((ULONG_PTR)Src < (ULONG_PTR)MM_USER_PROBE_ADDRESS) {
            ProbeForRead((PVOID)Src, sizeof(*Src), 1);
        }
        s = *Src;
        if (s.Buffer != NULL && s.Length >= sizeof(WCHAR)) {
            bytes = (USHORT)(s.Length & ~(USHORT)1);
            if (bytes > Dst->MaximumLength) {
                bytes = Dst->MaximumLength;
            }
            if ((ULONG_PTR)s.Buffer < (ULONG_PTR)MM_USER_PROBE_ADDRESS) {
                ProbeForRead(s.Buffer, bytes, 1);
            }
            RtlCopyMemory(Buf, s.Buffer, bytes);
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        bytes = 0;
    }

    Dst->Length = bytes;
    return bytes > 0;
}

static void
BlwPrepareRegMatch(
    _Out_ PBLW_MATCH_CTX Ctx,
    _In_ PCUNICODE_STRING KeyPath,
    _In_opt_ PCUNICODE_STRING ValueName,
    _Out_ PUSHORT OutKeyChars)
{
    USHORT keyChars;
    USHORT valChars;
    USHORT i;

    *OutKeyChars = 0;

    BlwPrepareMatch(Ctx, KeyPath);
    if (Ctx->Chars == 0) {
        return;
    }

    keyChars = Ctx->Chars;
    *OutKeyChars = keyChars;

    if (ValueName == NULL || ValueName->Buffer == NULL || ValueName->Length == 0) {
        return;
    }

    valChars = (USHORT)(ValueName->Length / sizeof(WCHAR));
    if ((ULONG)keyChars + 1 + (ULONG)valChars > BLW_MAX_PATH) {
        return;
    }

    Ctx->Up[keyChars] = L'\\';
    for (i = 0; i < valChars; i++) {
        Ctx->Up[keyChars + 1 + i] = BlwUpcaseChar(ValueName->Buffer[i]);
    }
    Ctx->Chars = (USHORT)(keyChars + 1 + valChars);
}

static BOOLEAN
BlwRegIsHardBlocked(_In_ PBLW_MATCH_CTX Ctx)
{
    BOOLEAN matched;
    BlwLockShared(&g_Blw.RegHardLock);
    matched = BlwMatchInListCtx(g_Blw.RegHardBlock, g_Blw.RegHardCount, Ctx, 0);
    BlwUnlock(&g_Blw.RegHardLock);
    return matched;
}

// 目标是否位于 Root 之下。Root 必须是大写字面量;Root 之后须是串尾或 '\',
// 避免 ...\SAMPLE 这类同前缀键误命中。
static BOOLEAN
BlwRegPathUnder(
    _In_reads_(Chars) PCWSTR Buf,
    _In_ USHORT Chars,
    _In_ BOOLEAN Prepared,
    _In_reads_(RootChars) PCWSTR Root,
    _In_ USHORT RootChars)
{
    USHORT i;

    if (Buf == NULL || Chars < RootChars || RootChars == 0) {
        return FALSE;
    }
    for (i = 0; i < RootChars; i++) {
        WCHAR c = Prepared ? Buf[i] : BlwUpcaseChar(Buf[i]);
        if (c != Root[i]) {
            return FALSE;
        }
    }
    return (Chars == RootChars) || (Buf[RootChars] == L'\\');
}

static BOOLEAN
BlwRegIsCredentialHive(_In_ PBLW_MATCH_CTX Ctx, _In_ USHORT KeyChars)
{
    static const BLW_NAME_ENTRY kHives[] = {
        BLW_NAME(L"\\REGISTRY\\MACHINE\\SAM"),
        BLW_NAME(L"\\REGISTRY\\MACHINE\\SECURITY"),
    };

    PCWSTR  buf;
    USHORT  chars;
    BOOLEAN prepared;
    ULONG   i;

    if (Ctx == NULL) {
        return FALSE;
    }

    if (Ctx->Chars != 0) {
        buf = Ctx->Up;
        chars = (KeyChars != 0 && KeyChars <= Ctx->Chars) ? KeyChars : Ctx->Chars;
        prepared = TRUE;
    } else if (Ctx->Original != NULL && Ctx->Original->Buffer != NULL &&
               Ctx->Original->Length > 0) {
        buf = Ctx->Original->Buffer;
        chars = (USHORT)(Ctx->Original->Length / sizeof(WCHAR));
        prepared = FALSE;
    } else {
        return FALSE;
    }

    for (i = 0; i < RTL_NUMBER_OF(kHives); i++) {
        if (BlwRegPathUnder(buf, chars, prepared, kHives[i].Name, kHives[i].Chars)) {
            return TRUE;
        }
    }
    return FALSE;
}

// 值名是否等于 Literal(大小写不敏感)。Literal 必须是大写字面量。
static BOOLEAN
BlwRegValueNameIs(_In_opt_ PCUNICODE_STRING ValueName,
                  _In_ PCWSTR Literal, _In_ USHORT LiteralChars)
{
    USHORT i;

    if (ValueName == NULL || ValueName->Buffer == NULL) {
        return FALSE;
    }
    if ((USHORT)(ValueName->Length / sizeof(WCHAR)) != LiteralChars) {
        return FALSE;
    }
    for (i = 0; i < LiteralChars; i++) {
        if (BlwUpcaseChar(ValueName->Buffer[i]) != Literal[i]) {
            return FALSE;
        }
    }
    return TRUE;
}

static BOOLEAN
BlwRegIsServiceKey(_In_ PBLW_MATCH_CTX Ctx, _In_ USHORT KeyChars)
{
    static const WCHAR kSysRoot[] = L"\\REGISTRY\\MACHINE\\SYSTEM";
    const USHORT rootChars = (USHORT)(RTL_NUMBER_OF(kSysRoot) - 1);

    PCWSTR  buf;
    USHORT  chars;
    BOOLEAN prepared;

    if (Ctx == NULL) {
        return FALSE;
    }

    if (Ctx->Chars != 0) {
        buf = Ctx->Up;
        chars = (KeyChars != 0 && KeyChars <= Ctx->Chars) ? KeyChars : Ctx->Chars;
        prepared = TRUE;
    } else if (Ctx->Original != NULL && Ctx->Original->Buffer != NULL &&
               Ctx->Original->Length > 0) {
        buf = Ctx->Original->Buffer;
        chars = (USHORT)(Ctx->Original->Length / sizeof(WCHAR));
        prepared = FALSE;
    } else {
        return FALSE;
    }

    if (!BlwRegPathUnder(buf, chars, prepared, kSysRoot, rootChars)) {
        return FALSE;
    }
    return BlwWideContainsCI(buf, chars, L"\\Services\\");
}

static BOOLEAN
BlwRegNameIsAbsolute(_In_opt_ PCUNICODE_STRING Name)
{
    static const WCHAR kPrefix[] = L"\\REGISTRY";
    const USHORT prefixChars = (USHORT)(RTL_NUMBER_OF(kPrefix) - 1);

    if (Name == NULL || Name->Buffer == NULL || Name->Length == 0) {
        return FALSE;
    }
    return BlwRegPathUnder(Name->Buffer, (USHORT)(Name->Length / sizeof(WCHAR)),
                           FALSE, kPrefix, prefixChars);
}

static void
BlwReportRegOp(_Inout_ PBLW_REG_SCRATCH S, _In_ ULONG eventType, _In_ PCUNICODE_STRING keyPath,
    _In_opt_ PCUNICODE_STRING valueName,
    _In_ ULONG valueDword, _In_ USHORT valueType)
{
    PWCH target = S->Report;
    UNICODE_STRING usTarget;
    USHORT keyChars = 0;

    if (!g_Blw.Active) {
        return;
    }
    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return;  // 高 IRQL 无法发送,直接放弃记录
    }

    if (keyPath != NULL && keyPath->Buffer != NULL && keyPath->Length > 0) {
        keyChars = (USHORT)(keyPath->Length / sizeof(WCHAR));
        if (keyChars > (BLW_MAX_PATH - 1)) {
            keyChars = BLW_MAX_PATH - 1;
        }
        RtlCopyMemory(target, keyPath->Buffer, (SIZE_T)keyChars * sizeof(WCHAR));
    }

    if (valueName != NULL && valueName->Buffer != NULL && valueName->Length > 0 &&
        keyChars < (BLW_MAX_PATH - 2)) {
        USHORT pos = keyChars;
        USHORT valChars = (USHORT)(valueName->Length / sizeof(WCHAR));

        target[pos++] = L'\\';
        if (valChars > (BLW_MAX_PATH - 1 - pos)) {
            valChars = (USHORT)(BLW_MAX_PATH - 1 - pos);
        }
        RtlCopyMemory(&target[pos], valueName->Buffer, (SIZE_T)valChars * sizeof(WCHAR));
        keyChars = (USHORT)(pos + valChars);
    }

    usTarget.Buffer = target;
    usTarget.Length = (USHORT)(keyChars * sizeof(WCHAR));
    usTarget.MaximumLength = usTarget.Length;

    // 注册表事件不占网络字段,借 RemoteIpV4 / RemotePort 携带 REG_DWORD 值与注册表类型码,不改 BLW_EVENT_MESSAGE 布局。
    // 旧驱动这两项恒为 0,服务侧按「值未知」处理。
    BlwReportEvent(eventType, HandleToULong(PsGetCurrentProcessId()), 0,
                   &usTarget, NULL, valueDword, valueType);
}

static ULONG
BlwBlockedRegEventType(_In_ ULONG eventType)
{
    switch (eventType) {
    case BlwEventRegistrySetValue:
        return BlwEventRegistrySetValueBlocked;
    case BlwEventRegistryDeleteValue:
        return BlwEventRegistryDeleteValueBlocked;
    case BlwEventRegistryDeleteKey:
        return BlwEventRegistryDeleteKeyBlocked;
    case BlwEventRegistryRestore:
        return BlwEventRegistryRestoreBlocked;
    default:
        return eventType;
    }
}

static BOOLEAN
BlwGetKeyPath(_In_opt_ PVOID RegObject, _Out_ PCUNICODE_STRING* OutName)
{
    PCUNICODE_STRING name = NULL;
    NTSTATUS status;

    *OutName = NULL;
    if (RegObject == NULL) {
        return FALSE;
    }

    status = CmCallbackGetKeyObjectIDEx(&g_Blw.RegCookie, RegObject, NULL, &name, 0);
    if (!NT_SUCCESS(status) || name == NULL) {
        return FALSE;
    }
    *OutName = name;
    return TRUE;
}

static NTSTATUS
BlwRegDecide(
    _Inout_ PBLW_REG_SCRATCH S,
    _In_ USHORT KeyChars,
    _In_ ULONG EventType,
    _In_ PCUNICODE_STRING ReportKey,
    _In_opt_ PCUNICODE_STRING ReportValue,
    _In_ ULONG ValueDword,
    _In_ USHORT ValueType,
    _In_ BOOLEAN HardOnly,
    _In_ BOOLEAN BuiltinHive,
    _In_ BOOLEAN SvcRegWatch)
{
    PBLW_MATCH_CTX ctx = &S->Ctx;

    if (BuiltinHive && BlwRegIsCredentialHive(ctx, KeyChars)) {
        BlwReportRegOp(S, BlwBlockedRegEventType(EventType), ReportKey, ReportValue,
                       ValueDword, ValueType);
        return STATUS_ACCESS_DENIED;
    }

    if (g_Blw.RegHardCount > 0 && BlwRegIsHardBlocked(ctx)) {
        BlwReportRegOp(S, BlwBlockedRegEventType(EventType), ReportKey, ReportValue,
                       ValueDword, ValueType);
        return STATUS_ACCESS_DENIED;
    }

    if (SvcRegWatch && BlwRegIsServiceKey(ctx, KeyChars)) {
        BlwReportRegOp(S, EventType, ReportKey, ReportValue, ValueDword, ValueType);
        return STATUS_SUCCESS;
    }

    if (!HardOnly && g_Blw.ProtectedRegCount > 0 && BlwRegKeyIsProtected(ctx, KeyChars)) {
        BlwReportRegOp(S, EventType, ReportKey, ReportValue, ValueDword, ValueType);
    }

    return STATUS_SUCCESS;
}

// 本产品服务键自身及其下,或它的各级上级(SYSTEM、控制集、控制集\SERVICES)。
// 键对象名里的 CurrentControlSet 已解析成 ControlSet00x。
static BOOLEAN
BlwRegCoversOwnServiceKey(_In_ PBLW_MATCH_CTX Ctx)
{
    static const WCHAR kSys[] = L"\\REGISTRY\\MACHINE\\SYSTEM";
    static const WCHAR kOwn[] = L"\\SERVICES\\BULWARK";
    static const WCHAR kSvc[] = L"SERVICES";
    static const WCHAR kCs[] = L"CONTROLSET";
    const USHORT sysChars = (USHORT)(RTL_NUMBER_OF(kSys) - 1);
    const USHORT ownChars = (USHORT)(RTL_NUMBER_OF(kOwn) - 1);
    const USHORT svcChars = (USHORT)(RTL_NUMBER_OF(kSvc) - 1);
    PCWSTR up = Ctx->Up;
    const USHORT chars = Ctx->Chars;
    USHORT s;
    USHORT c1;
    USHORT c1End;
    USHORT c2;

    if (chars == 0 || !BlwRegPathUnder(up, chars, TRUE, kSys, sysChars)) {
        return FALSE;
    }

    for (s = sysChars; (USHORT)(s + ownChars) <= chars; s++) {
        if (RtlEqualMemory(&up[s], kOwn, (SIZE_T)ownChars * sizeof(WCHAR)) &&
            ((USHORT)(s + ownChars) == chars || up[s + ownChars] == L'\\')) {
            return TRUE;
        }
    }

    if (chars == sysChars) {
        return TRUE;
    }
    c1 = (USHORT)(sysChars + 1);
    c1End = c1;
    while (c1End < chars && up[c1End] != L'\\') {
        c1End++;
    }
    // 第一段必须是控制集(ControlSet00x / CurrentControlSet)。
    if (!BlwWideContainsCI(&up[c1], (USHORT)(c1End - c1), kCs)) {
        return FALSE;
    }
    if (c1End == chars) {
        return TRUE;
    }
    c2 = (USHORT)(c1End + 1);
    return (USHORT)(chars - c2) == svcChars &&
           RtlEqualMemory(&up[c2], kSvc, (SIZE_T)svcChars * sizeof(WCHAR));
}

// 整棵恢复 / 替换一次改写整个子树,不经逐值回调,只能看子树里有没有受保护项。
// 凭据配置单元、本产品服务键(含各级上级)、子树可能含硬拦条目的键一律拒绝;其余放行并上报。
static NTSTATUS
BlwRegDecideSubtree(_Inout_ PBLW_REG_SCRATCH S, _In_ PCUNICODE_STRING KeyPath)
{
    USHORT keyChars = 0;
    BOOLEAN deny = FALSE;

    BlwPrepareRegMatch(&S->Ctx, KeyPath, NULL, &keyChars);

    if (BlwRegIsCredentialHive(&S->Ctx, keyChars) || BlwRegCoversOwnServiceKey(&S->Ctx)) {
        deny = TRUE;
    } else if (g_Blw.RegHardCount > 0 && S->Ctx.Chars != 0) {
        BlwLockShared(&g_Blw.RegHardLock);
        deny = BlwListHitsSubtree(S->Ctx.Up, S->Ctx.Chars, 0, g_Blw.RegHardBlock, g_Blw.RegHardCount,
                                  NULL, NULL);
        BlwUnlock(&g_Blw.RegHardLock);
    }

    BlwReportRegOp(S, deny ? BlwEventRegistryRestoreBlocked : BlwEventRegistryRestore,
                   KeyPath, NULL, 0, 0);
    return deny ? STATUS_ACCESS_DENIED : STATUS_SUCCESS;
}

static NTSTATUS
BlwRegistryCallback(
    _In_ PVOID CallbackContext,
    _In_opt_ PVOID Argument1,
    _In_opt_ PVOID Argument2)
{
    REG_NOTIFY_CLASS notifyClass;
    PCUNICODE_STRING keyPath = NULL;
    PCUNICODE_STRING rawName = NULL;
    PCUNICODE_STRING valueName = NULL;
    PUNICODE_STRING completeName = NULL;
    PVOID regObject = NULL;
    PBLW_REG_SCRATCH scratch;
    UNICODE_STRING capturedName;
    NTSTATUS decision = STATUS_SUCCESS;
    ULONG eventType;
    BOOLEAN hardOnly = FALSE;
    BOOLEAN builtinHive = FALSE;
    BOOLEAN imagePathCandidate = FALSE;
    BOOLEAN subtreeOp = FALSE;
    BOOLEAN svcReg;
    ULONG valueDword = 0;
    USHORT valueType = 0;

    UNREFERENCED_PARAMETER(CallbackContext);

    if (Argument2 == NULL) {
        return STATUS_SUCCESS;
    }

    // 内核态操作豁免:本驱动用 Zw* 把策略写回 \Policy 时,不能被自我保护的硬拦("\Services\Bulwark")挡住。
    if (ExGetPreviousMode() == KernelMode) {
        return STATUS_SUCCESS;
    }

    notifyClass = (REG_NOTIFY_CLASS)(ULONG_PTR)Argument1;

    switch (notifyClass) {
    case RegNtPreSetValueKey:
    {
        PREG_SET_VALUE_KEY_INFORMATION info = (PREG_SET_VALUE_KEY_INFORMATION)Argument2;
        regObject = info->Object;
        rawName = info->ValueName;
        eventType = BlwEventRegistrySetValue;
        imagePathCandidate = TRUE;
        /* 只取 REG_DWORD 定长值:这是区分「设 0 加固 / 设 1 削弱」的唯一形态。
           字符串/多串值长度无界,不采集,避免热路径放大。 */
        if (info->Type == REG_DWORD && info->DataSize >= sizeof(ULONG) &&
            BlwRegCaptureUlong(info->Data, &valueDword)) {
            valueType = REG_DWORD;
        }
        break;
    }
    case RegNtPreDeleteValueKey:
    {
        PREG_DELETE_VALUE_KEY_INFORMATION info = (PREG_DELETE_VALUE_KEY_INFORMATION)Argument2;
        regObject = info->Object;
        rawName = info->ValueName;
        eventType = BlwEventRegistryDeleteValue;
        break;
    }
    case RegNtPreDeleteKey:
    {
        PREG_DELETE_KEY_INFORMATION info = (PREG_DELETE_KEY_INFORMATION)Argument2;
        regObject = info->Object;
        eventType = BlwEventRegistryDeleteKey;
        break;
    }

    case RegNtPreRenameKey:
    {
        PREG_RENAME_KEY_INFORMATION info = (PREG_RENAME_KEY_INFORMATION)Argument2;
        regObject = info->Object;
        rawName = info->NewName;
        eventType = BlwEventRegistryDeleteKey;
        break;
    }

    case RegNtPreSaveKey:
    {
        PREG_SAVE_KEY_INFORMATION info = (PREG_SAVE_KEY_INFORMATION)Argument2;
        regObject = info->Object;
        eventType = BlwEventRegistryHiveDump;
        builtinHive = TRUE;
        hardOnly = TRUE;
        break;
    }

    case RegNtPreRestoreKey:
    {
        PREG_RESTORE_KEY_INFORMATION info = (PREG_RESTORE_KEY_INFORMATION)Argument2;
        regObject = info->Object;
        eventType = BlwEventRegistryRestore;
        subtreeOp = TRUE;
        break;
    }
    case RegNtPreReplaceKey:
    {
        PREG_REPLACE_KEY_INFORMATION info = (PREG_REPLACE_KEY_INFORMATION)Argument2;
        regObject = info->Object;
        eventType = BlwEventRegistryRestore;
        subtreeOp = TRUE;
        break;
    }

    case RegNtPreLoadKey:
    {
        // hive 挂载。不要合并处理 RegNtPreLoadKeyEx:REG_LOAD_KEY_INFORMATION_V2 首成员是 Size
        // 而不是 Object,按本结构解释会把 ULONG 当指针传给 CmCallbackGetKeyObjectIDEx。
        PREG_LOAD_KEY_INFORMATION info = (PREG_LOAD_KEY_INFORMATION)Argument2;
        regObject = info->Object;
        eventType = BlwEventRegistrySetValue;
        break;
    }

    case RegNtPreSetKeySecurity:
    {
        PREG_SET_KEY_SECURITY_INFORMATION info = (PREG_SET_KEY_SECURITY_INFORMATION)Argument2;
        regObject = info->Object;
        eventType = BlwEventRegistrySetValue;
        break;
    }

    case RegNtPreCreateKeyEx:
    {
        PREG_CREATE_KEY_INFORMATION info = (PREG_CREATE_KEY_INFORMATION)Argument2;
        regObject = info->RootObject;
        completeName = info->CompleteName;
        if (completeName == NULL || completeName->Buffer == NULL || completeName->Length == 0) {
            return STATUS_SUCCESS;
        }
        eventType = BlwEventRegistrySetValue;
        hardOnly = TRUE;
        break;
    }

    default:
        return STATUS_SUCCESS;
    }

    if (g_Blw.BannedPidCount > 0
        && BlwPidIsBanned(HandleToULong(PsGetCurrentProcessId()))) {
        return STATUS_ACCESS_DENIED;
    }

    if (!subtreeOp && !builtinHive && !imagePathCandidate
        && g_Blw.ProtectedRegCount == 0 && g_Blw.RegHardCount == 0) {
        return STATUS_SUCCESS;
    }
    if (hardOnly && !builtinHive && g_Blw.RegHardCount == 0) {
        return STATUS_SUCCESS;
    }

    scratch = g_Blw.PoolsReady
        ? (PBLW_REG_SCRATCH)ExAllocateFromLookasideListEx(&g_Blw.RegScratchPool) : NULL;
    if (scratch == NULL) {
        return STATUS_SUCCESS;
    }

    // 键名上限 255 字符;更长的值名只截取前段参与匹配与上报。
    if (rawName != NULL &&
        BlwRegCaptureName(rawName, scratch->Name, (USHORT)RTL_NUMBER_OF(scratch->Name),
                          &capturedName)) {
        valueName = &capturedName;
    }
    svcReg = imagePathCandidate && BlwRegValueNameIs(valueName, L"IMAGEPATH", 9);

    if (!subtreeOp && !builtinHive && !svcReg
        && g_Blw.ProtectedRegCount == 0 && g_Blw.RegHardCount == 0) {
        // 只是普通写值、而名单都空:没有可判定的。
    } else if (completeName != NULL && BlwRegNameIsAbsolute(completeName)) {
        USHORT keyChars = 0;

        BlwPrepareRegMatch(&scratch->Ctx, completeName, NULL, &keyChars);
        decision = BlwRegDecide(scratch, keyChars, eventType, completeName, NULL,
                                0, 0, hardOnly, builtinHive, svcReg);
    } else if (BlwGetKeyPath(regObject, &keyPath)) {
        if (subtreeOp) {
            decision = BlwRegDecideSubtree(scratch, keyPath);
        } else {
            PCUNICODE_STRING extra = (completeName != NULL) ? completeName : valueName;
            USHORT keyChars = 0;

            BlwPrepareRegMatch(&scratch->Ctx, keyPath, extra, &keyChars);
            decision = BlwRegDecide(scratch, keyChars, eventType, keyPath, extra,
                                    valueDword, valueType, hardOnly, builtinHive, svcReg);
        }
        CmCallbackReleaseKeyObjectIDEx(keyPath);
    }

    ExFreeToLookasideListEx(&g_Blw.RegScratchPool, scratch);
    return decision;
}

NTSTATUS
BlwRegisterRegistryCallback(_In_ PDRIVER_OBJECT DriverObject)
{
    NTSTATUS status;
    UNICODE_STRING altitude;

    if (g_Blw.RegCallbackRegistered) {
        return STATUS_SUCCESS;
    }

    RtlInitUnicodeString(&altitude, L"385200");

    status = CmRegisterCallbackEx(
        BlwRegistryCallback,
        &altitude,
        DriverObject,
        NULL,
        &g_Blw.RegCookie,
        NULL);

    if (NT_SUCCESS(status)) {
        g_Blw.RegCallbackRegistered = TRUE;
        KdPrint(("[Bulwark] Registry callback registered.\n"));
    } else {
        KdPrint(("[Bulwark] CmRegisterCallbackEx failed 0x%x\n", status));
    }
    return status;
}

void
BlwUnregisterRegistryCallback(void)
{
    if (g_Blw.RegCallbackRegistered) {
        CmUnRegisterCallback(g_Blw.RegCookie);
        g_Blw.RegCallbackRegistered = FALSE;
        KdPrint(("[Bulwark] Registry callback unregistered.\n"));
    }
}
