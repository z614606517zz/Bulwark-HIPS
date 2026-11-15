#include "Driver.h"

// 窃密防护(ReadGuard):只许指定程序打开命中「数据片段」的文件。防的是信息窃取木马把浏览器
// 登录库、通讯软件会话、钱包文件整个拷走。与受保护目录(反勒索,防写)互补 —— 这一维防读。
//
// 条目格式见 Protocol.h:"数据片段|读者;读者",整条由 BlwAddToList 存成大写。判定分两步:
//   1) 目标文件路径里出现某条目的「数据片段」(子串,大小写不敏感) —— 该文件是这条保护的敏感数据;
//   2) 发起打开的进程是不是这条的「指定读者」(从安装根之后比)或全局读者 —— 不是就拒绝。
//
// 热路径优化:某 PID 对各条目能不能读只取决于它的映像路径,与具体文件无关,所以按 PID 缓存一张
// 位掩码(ReadGuardCache,seqlock)。取映像名的 SeLocateProcessImageName 很贵,一个 PID 只算一次。

static volatile LONG64 g_ReadGuardSeen[BLW_REPORT_SLOTS];

static void
BlwReadGuardBumpGen(void)
{
    InterlockedIncrement(&g_Blw.ReadGuardGen);
}

void
BlwClearReadGuard(void)
{
    BlwLockExclusive(&g_Blw.ReadGuardLock);
    RtlZeroMemory(g_Blw.ReadGuard, sizeof(g_Blw.ReadGuard));
    InterlockedExchange(&g_Blw.ReadGuardCount, 0);
    BlwUnlock(&g_Blw.ReadGuardLock);
    BlwReadGuardBumpGen();
}

void
BlwAddReadGuard(_In_ PCWSTR Entry, _In_ USHORT Length)
{
    // 条目含 '|' 与去盘符的片段,正常绝不该带盘符;带了就是脏数据,拒收并标脏清理。
    if (BlwPatternHasDriveLetter(Entry, Length)) {
        BlwLogPattern("ReadGuard entry REJECTED (drive-letter pattern never matches)", Entry, Length);
        BlwMarkDeadEntryDrop(BLW_POLICY_DIRTY_READGUARD);
        return;
    }
    {
        USHORT dataChars = 0;
        while (dataChars < Length && Entry[dataChars] != BLW_READGUARD_SEP) {
            dataChars++;
        }
        // 数据片段太短会让几乎所有路径都算敏感数据,受限进程从此读不了任何文件。
        if (dataChars < 4) {
            BlwLogPattern("ReadGuard entry REJECTED (data fragment too short)", Entry, Length);
            BlwMarkDeadEntryDrop(BLW_POLICY_DIRTY_READGUARD);
            return;
        }
    }

    BlwLockExclusive(&g_Blw.ReadGuardLock);
    BlwAddToList(g_Blw.ReadGuard, Entry, Length);
    {
        LONG cnt = 0;
        ULONG i;
        for (i = 0; i < BLW_MAX_PROTECTED; i++) {
            if (g_Blw.ReadGuard[i].InUse) cnt++;
        }
        InterlockedExchange(&g_Blw.ReadGuardCount, cnt);
    }
    BlwUnlock(&g_Blw.ReadGuardLock);
    BlwReadGuardBumpGen();
}

BOOLEAN
BlwDelReadGuard(_In_ PCWSTR Entry, _In_ USHORT Length)
{
    const BOOLEAN removed = BlwRemoveFromGuardedList(g_Blw.ReadGuard, &g_Blw.ReadGuardLock,
                                                     &g_Blw.ReadGuardCount, Entry, Length);
    if (removed) {
        BlwReadGuardBumpGen();
    }
    return removed;
}

void
BlwClearReadGuardReaders(void)
{
    BlwLockExclusive(&g_Blw.ReadGuardReaderLock);
    RtlZeroMemory(g_Blw.ReadGuardReaders, sizeof(g_Blw.ReadGuardReaders));
    InterlockedExchange(&g_Blw.ReadGuardReaderCount, 0);
    BlwUnlock(&g_Blw.ReadGuardReaderLock);
    BlwReadGuardBumpGen();
}

void
BlwAddReadGuardReader(_In_ PCWSTR Path, _In_ USHORT Length)
{
    if (BlwPatternHasDriveLetter(Path, Length)) {
        BlwLogPattern("ReadGuardReader entry REJECTED (drive-letter pattern never matches)", Path, Length);
        BlwMarkDeadEntryDrop(BLW_POLICY_DIRTY_READGUARD_READER);
        return;
    }

    BlwLockExclusive(&g_Blw.ReadGuardReaderLock);
    BlwAddToList(g_Blw.ReadGuardReaders, Path, Length);
    {
        LONG cnt = 0;
        ULONG i;
        for (i = 0; i < BLW_MAX_PROTECTED; i++) {
            if (g_Blw.ReadGuardReaders[i].InUse) cnt++;
        }
        InterlockedExchange(&g_Blw.ReadGuardReaderCount, cnt);
    }
    BlwUnlock(&g_Blw.ReadGuardReaderLock);
    BlwReadGuardBumpGen();
}

BOOLEAN
BlwDelReadGuardReader(_In_ PCWSTR Path, _In_ USHORT Length)
{
    const BOOLEAN removed = BlwRemoveFromGuardedList(g_Blw.ReadGuardReaders, &g_Blw.ReadGuardReaderLock,
                                                     &g_Blw.ReadGuardReaderCount, Path, Length);
    if (removed) {
        BlwReadGuardBumpGen();
    }
    return removed;
}

// 对全部敏感数据放行的内置系统读者:资源管理器、索引 / 备份 / 卷影等系统服务、商店应用、Defender。
// 刻意不认整个 System32 —— curl.exe、esentutl.exe 这类住在 System32 里的程序本身就是窃密工具。
static BOOLEAN
BlwReadGuardActorAllowedAll(_In_reads_(Chars) PCWSTR Path, _In_ USHORT Chars)
{
    static const BLW_NAME_ENTRY kSysReaders[] = {
        BLW_NAME(L"svchost.exe"),            BLW_NAME(L"RuntimeBroker.exe"),
        BLW_NAME(L"backgroundTaskHost.exe"), BLW_NAME(L"SearchProtocolHost.exe"),
        BLW_NAME(L"SearchIndexer.exe"),      BLW_NAME(L"SearchFilterHost.exe"),
        BLW_NAME(L"wbengine.exe"),           BLW_NAME(L"VSSVC.exe"),
    };
    static const WCHAR kExplorer[] = L"\\Windows\\explorer.exe";
    const USHORT explorerChars = (USHORT)(RTL_NUMBER_OF(kExplorer) - 1);
    USHORT off;

    if (Path == NULL || Chars == 0) {
        return FALSE;
    }
    if (BlwPathInProductDir(Path, Chars)) {
        return TRUE;
    }
    if (BLW_SYSVOL_PATH_STARTS(Path, Chars, L"\\Windows\\SystemApps\\") ||
        BLW_SYSVOL_PATH_STARTS(Path, Chars, L"\\ProgramData\\Microsoft\\Windows Defender\\Platform\\")) {
        return TRUE;
    }

    off = BlwSystemVolumeRelativeOffset(Path, Chars);
    if (off == 0) {
        return FALSE;
    }
    if ((USHORT)(Chars - off) == explorerChars &&
        BlwStartsWithCI(Path + off, explorerChars, kExplorer, explorerChars)) {
        return TRUE;
    }
    if (BLW_SYSVOL_PATH_STARTS(Path, Chars, L"\\Windows\\System32\\") ||
        BLW_SYSVOL_PATH_STARTS(Path, Chars, L"\\Windows\\SysWOW64\\")) {
        return BlwImageNameIn(kSysReaders, RTL_NUMBER_OF(kSysReaders), Path, Chars);
    }
    return FALSE;
}

// 返回某 PID 对各 ReadGuard 条目的可读位掩码。~0 = 对全部放行。仅在 PASSIVE_LEVEL 调用。
static LONG64
BlwReadGuardComputeMask(_In_ ULONG ActorPid)
{
    PUNICODE_STRING image = NULL;
    PBLW_MATCH_CTX  ictx;
    USHORT          chars;
    LONG64          mask = 0;
    BOOLEAN         allowAll = FALSE;

    if (BlwPidIsProtected(ActorPid)) {
        return ~0ll;
    }
    if (!NT_SUCCESS(SeLocateProcessImageName(PsGetCurrentProcess(), &image)) ||
        image == NULL || image->Buffer == NULL || image->Length == 0) {
        if (image != NULL) {
            ExFreePool(image);
        }
        return ~0ll;   // 取不到身份就放行,宁松不误拦
    }

    chars = (USHORT)(image->Length / sizeof(WCHAR));
    if (BlwReadGuardActorAllowedAll(image->Buffer, chars)) {
        ExFreePool(image);
        return ~0ll;
    }

    ictx = BlwAllocMatchCtx();
    if (ictx == NULL) {
        ExFreePool(image);
        return ~0ll;
    }
    BlwPrepareMatch(ictx, image);
    if (ictx->Chars == 0) {
        // 映像路径超长,无法预归一化。按受限主体处理(mask 保持 0),极罕见。
        BlwFreeMatchCtx(ictx);
        ExFreePool(image);
        return 0;
    }

    BlwLockShared(&g_Blw.ReadGuardReaderLock);
    {
        ULONG i;
        LONG  seen = 0;
        for (i = 0; i < BLW_MAX_PROTECTED && seen < g_Blw.ReadGuardReaderCount; i++) {
            if (!g_Blw.ReadGuardReaders[i].InUse) {
                continue;
            }
            seen++;
            if (BlwReadGuardGlobalReaderHit(&g_Blw.ReadGuardReaders[i], ictx->Up, ictx->Chars)) {
                allowAll = TRUE;
                break;
            }
        }
    }
    BlwUnlock(&g_Blw.ReadGuardReaderLock);

    if (allowAll) {
        BlwFreeMatchCtx(ictx);
        ExFreePool(image);
        return ~0ll;
    }

    BlwLockShared(&g_Blw.ReadGuardLock);
    {
        ULONG i;
        LONG  seen = 0;
        for (i = 0; i < BLW_MAX_PROTECTED && seen < g_Blw.ReadGuardCount; i++) {
            if (!g_Blw.ReadGuard[i].InUse) {
                continue;
            }
            seen++;
            if (BlwReadGuardReaderHit(&g_Blw.ReadGuard[i], ictx->Up, ictx->Chars)) {
                mask |= (1ll << i);
            }
        }
    }
    BlwUnlock(&g_Blw.ReadGuardLock);

    BlwFreeMatchCtx(ictx);
    ExFreePool(image);
    return mask;
}

LONG64
BlwReadGuardMaskForPid(_In_ ULONG ActorPid)
{
    const LONG gen = g_Blw.ReadGuardGen;
    const LONG64 wantTag = ((LONG64)(ULONG)gen << 32) | (LONG64)ActorPid;
    PBLW_RG_CACHE_SLOT slot = &g_Blw.ReadGuardCache[(ActorPid >> 2) & (BLW_RG_CACHE_SLOTS - 1)];
    LONG64 seq;
    LONG64 mask;

    // 非 PASSIVE 取不到映像名:放行,且绝不写缓存(否则会把「放行」缓存给该 PID 导致后续绕过)。
    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return ~0ll;
    }

    seq = slot->Seq;
    if ((seq & 1) == 0 && slot->Tag == wantTag) {
        mask = slot->Mask;
        KeMemoryBarrier();
        if (slot->Seq == seq) {
            return mask;
        }
    }

    mask = BlwReadGuardComputeMask(ActorPid);

    // 抢不到写权(别的写者正在改这一格)就不缓存,结果照样正确。
    seq = slot->Seq;
    if ((seq & 1) == 0 && InterlockedCompareExchange64(&slot->Seq, seq + 1, seq) == seq) {
        slot->Tag = wantTag;
        slot->Mask = mask;
        InterlockedExchange64(&slot->Seq, seq + 2);
    }
    return mask;
}

void
BlwReadGuardOnProcessExit(_In_ ULONG Pid)
{
    PBLW_RG_CACHE_SLOT slot = &g_Blw.ReadGuardCache[(Pid >> 2) & (BLW_RG_CACHE_SLOTS - 1)];
    const LONG64 seq = slot->Seq;

    // 抢不到写权说明有别的 PID 正在占这一格,旧标签反正会被换掉。
    if ((seq & 1) == 0 && slot->Tag != 0 && (ULONG)(slot->Tag & 0xFFFFFFFFll) == Pid &&
        InterlockedCompareExchange64(&slot->Seq, seq + 1, seq) == seq) {
        slot->Tag = 0;
        InterlockedExchange64(&slot->Seq, seq + 2);
    }
}

void
BlwReportSensitiveRead(_In_ ULONG ActorPid, _In_opt_ PCUNICODE_STRING Target)
{
    PUNICODE_STRING image = NULL;

    if (!g_Blw.Active || KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return;
    }
    if (!BlwReportOncePerWindow(g_ReadGuardSeen, ActorPid)) {
        return;
    }

    if (NT_SUCCESS(SeLocateProcessImageName(PsGetCurrentProcess(), &image)) && image != NULL &&
        image->Buffer != NULL && image->Length > 0) {
        BlwReportEvent(BlwEventSensitiveReadBlocked, ActorPid, 0, Target, image, 0, 0);
    } else {
        BlwReportEvent(BlwEventSensitiveReadBlocked, ActorPid, 0, Target, NULL, 0, 0);
    }
    if (image != NULL) {
        ExFreePool(image);
    }
}

BOOLEAN
BlwReadGuardRawNameMightHit(_In_ PCUNICODE_STRING RawName)
{
    PBLW_MATCH_CTX ctx;
    BOOLEAN hit = FALSE;

    if (g_Blw.ReadGuardCount == 0) {
        return FALSE;
    }
    ctx = BlwAllocMatchCtx();
    if (ctx == NULL) {
        return TRUE;   // 分配不到 => 保守走规范化精判
    }
    BlwPrepareMatch(ctx, RawName);
    if (ctx->Chars == 0) {
        BlwFreeMatchCtx(ctx);
        return TRUE;   // 原始名超长无法预归一化 => 保守精判
    }

    BlwLockShared(&g_Blw.ReadGuardLock);
    {
        ULONG i;
        LONG  seen = 0;
        for (i = 0; i < BLW_MAX_PROTECTED && seen < g_Blw.ReadGuardCount; i++) {
            if (!g_Blw.ReadGuard[i].InUse) {
                continue;
            }
            seen++;
            if (BlwReadGuardDataHit(&g_Blw.ReadGuard[i], ctx->Up, ctx->Chars)) {
                hit = TRUE;
                break;
            }
        }
    }
    BlwUnlock(&g_Blw.ReadGuardLock);

    BlwFreeMatchCtx(ctx);
    return hit;
}

BOOLEAN
BlwReadGuardDenies(_In_ PBLW_MATCH_CTX Ctx, _In_ ULONG ActorPid, _In_opt_ PCUNICODE_STRING ReportName)
{
    LONG64  mask;
    BOOLEAN denied = FALSE;
    ULONG   i;
    LONG    seen = 0;

    if (g_Blw.ReadGuardCount == 0 || Ctx == NULL || Ctx->Chars == 0) {
        return FALSE;
    }
    mask = BlwReadGuardMaskForPid(ActorPid);
    if (mask == ~0ll) {
        return FALSE;
    }

    BlwLockShared(&g_Blw.ReadGuardLock);
    for (i = 0; i < BLW_MAX_PROTECTED && seen < g_Blw.ReadGuardCount; i++) {
        if (!g_Blw.ReadGuard[i].InUse) {
            continue;
        }
        seen++;
        if ((mask & (1ll << i)) != 0) {
            continue;   // 本主体是这条的指定读者
        }
        if (BlwReadGuardDataHit(&g_Blw.ReadGuard[i], Ctx->Up, Ctx->Chars)) {
            denied = TRUE;
            break;
        }
    }
    BlwUnlock(&g_Blw.ReadGuardLock);

    if (denied) {
        BlwReportSensitiveRead(ActorPid, ReportName);
    }
    return denied;
}
