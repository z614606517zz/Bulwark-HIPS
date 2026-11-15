#ifdef BLW_MATCHCORE_HOST
#include "MatchCore.h"
#else
#include "Driver.h"
#endif

typedef struct _BLW_SYSTEM_VOLUME {
    volatile LONG Known;
    WCHAR         DriveLetter;                         // 大写
    USHORT        DeviceChars;
    WCHAR         DeviceName[BLW_SYSVOL_DEVICE_MAX];   // 大写,如 \DEVICE\HARDDISKVOLUME3
} BLW_SYSTEM_VOLUME;

static BLW_SYSTEM_VOLUME g_BlwSystemVolume;

void
BlwSetSystemVolume(_In_ WCHAR DriveLetter,
                   _In_reads_opt_(DeviceChars) PCWSTR DeviceName, _In_ USHORT DeviceChars)
{
    const WCHAR letter = BlwUpcaseChar(DriveLetter);
    USHORT i;

    g_BlwSystemVolume.Known = 0;
    if (letter < L'A' || letter > L'Z' || DeviceName == NULL ||
        DeviceChars == 0 || DeviceChars >= BLW_SYSVOL_DEVICE_MAX) {
        return;
    }

    for (i = 0; i < DeviceChars; i++) {
        g_BlwSystemVolume.DeviceName[i] = BlwUpcaseChar(DeviceName[i]);
    }
    g_BlwSystemVolume.DeviceName[DeviceChars] = L'\0';
    g_BlwSystemVolume.DeviceChars = DeviceChars;
    g_BlwSystemVolume.DriveLetter = letter;

    // 读侧不加锁:先看到 Known 再读其余字段,所以 Known 必须最后、且在屏障之后置位。
    KeMemoryBarrier();
    g_BlwSystemVolume.Known = 1;
}

BOOLEAN
BlwSystemVolumeKnown(void)
{
    return g_BlwSystemVolume.Known != 0;
}

USHORT
BlwSystemVolumeRelativeOffset(_In_reads_(Chars) PCWSTR Path, _In_ USHORT Chars)
{
    USHORT dev;

    if (Path == NULL || Chars < 3) {
        return 0;
    }
    if (g_BlwSystemVolume.Known == 0) {
        return BlwVolumeRelativeOffset(Path, Chars);
    }

    dev = g_BlwSystemVolume.DeviceChars;
    if (Chars > dev && Path[dev] == L'\\' &&
        BlwStartsWithCI(Path, Chars, g_BlwSystemVolume.DeviceName, dev)) {
        return dev;
    }

    if (BlwStartsWithCI(Path, Chars, L"\\??\\", 4)) {
        if (Chars >= 7 && Path[5] == L':' && Path[6] == L'\\' &&
            BlwUpcaseChar(Path[4]) == g_BlwSystemVolume.DriveLetter) {
            return 6;
        }
        return 0;
    }

    if (Path[1] == L':' && Path[2] == L'\\' &&
        BlwUpcaseChar(Path[0]) == g_BlwSystemVolume.DriveLetter) {
        return 2;
    }
    return 0;
}

BOOLEAN
BlwSystemVolumePathStartsWith(_In_opt_ PCWSTR Path, _In_ USHORT Chars,
                              _In_ PCWSTR Literal, _In_ USHORT LiteralChars)
{
    USHORT off;

    if (Path == NULL || Chars == 0) {
        return FALSE;
    }
    off = BlwSystemVolumeRelativeOffset(Path, Chars);
    if (off == 0) {
        return FALSE;
    }
    return BlwStartsWithCI(Path + off, (USHORT)(Chars - off), Literal, LiteralChars);
}

void
BlwPrepareMatch(_Out_ PBLW_MATCH_CTX Ctx, _In_opt_ PCUNICODE_STRING Target)
{
    USHORT chars;
    USHORT i;

    Ctx->Original = Target;
    Ctx->Chars = 0;

    if (Target == NULL || Target->Buffer == NULL || Target->Length == 0) {
        return;
    }

    chars = (USHORT)(Target->Length / sizeof(WCHAR));
    if (chars > BLW_MAX_PATH) {
        return;
    }

    for (i = 0; i < chars; i++) {
        Ctx->Up[i] = BlwUpcaseChar(Target->Buffer[i]);
    }
    Ctx->Chars = chars;
}

typedef enum _BLW_MATCH_MODE {
    BlwMatchSubstring = 0,
    BlwMatchAnchored = 1
} BLW_MATCH_MODE;

static BOOLEAN
BlwAnchorsOk(
    _In_reads_(TargetChars) PCWSTR Target,
    _In_ USHORT TargetChars,
    _In_ PCWSTR Pattern,
    _In_ USHORT PatChars,
    _In_ USHORT Start)
{
    USHORT end = (USHORT)(Start + PatChars);

    if (Pattern[0] != L'\\' && Start != 0 && Target[Start - 1] != L'\\') {
        return FALSE;
    }

    if (Pattern[PatChars - 1] == L'\\') {
        return TRUE;
    }
    if (end == TargetChars) {
        return TRUE;
    }
    if (Target[end] == L':') {
        return TRUE;
    }
    return FALSE;
}

static BOOLEAN
BlwMatchScan(
    _In_ BLW_PROTECTED_PATH* List,
    _In_ LONG Count,
    _In_reads_(TargetChars) PCWSTR Target,
    _In_ USHORT TargetChars,
    _In_ BOOLEAN Prepared,
    _In_ BLW_MATCH_MODE Mode)
{
    ULONG i;
    LONG  seen = 0;

    if (Target == NULL || TargetChars == 0 || Count <= 0) {
        return FALSE;
    }

    for (i = 0; i < BLW_MAX_PROTECTED && seen < Count; i++) {
        USHORT patChars;
        USHORT limit;
        USHORT s;
        PCWSTR p;
        WCHAR  first;
        WCHAR  last;

        if (!List[i].InUse) {
            continue;
        }
        seen++;

        patChars = List[i].Length;
        if (patChars == 0 || patChars > TargetChars) {
            continue;
        }

        p = List[i].Path;
        first = p[0];
        last = p[patChars - 1];
        limit = (USHORT)(TargetChars - patChars);

        if (Prepared) {
            for (s = 0; s <= limit; s++) {
                if (Target[s] != first) {
                    continue;
                }
                if (Target[s + patChars - 1] != last) {
                    continue;
                }
                if (Mode == BlwMatchAnchored &&
                    !BlwAnchorsOk(Target, TargetChars, p, patChars, s)) {
                    continue;
                }
                if (patChars <= 2 ||
                    RtlEqualMemory(&Target[s + 1], &p[1],
                                   (SIZE_T)(patChars - 2) * sizeof(WCHAR))) {
                    return TRUE;
                }
            }
        } else {
            for (s = 0; s <= limit; s++) {
                USHORT k;

                if (BlwUpcaseChar(Target[s]) != first) {
                    continue;
                }
                if (BlwUpcaseChar(Target[s + patChars - 1]) != last) {
                    continue;
                }
                if (Mode == BlwMatchAnchored &&
                    !BlwAnchorsOk(Target, TargetChars, p, patChars, s)) {
                    continue;
                }
                for (k = 1; (USHORT)(k + 1) < patChars; k++) {
                    if (BlwUpcaseChar(Target[s + k]) != p[k]) {
                        break;
                    }
                }
                if ((USHORT)(k + 1) >= patChars) {
                    return TRUE;
                }
            }
        }
    }
    return FALSE;
}

static BOOLEAN
BlwMatchDispatch(
    _In_ BLW_PROTECTED_PATH* List,
    _In_ LONG Count,
    _In_ PBLW_MATCH_CTX Ctx,
    _In_ USHORT UseChars,
    _In_ BLW_MATCH_MODE Mode)
{
    if (Ctx == NULL) {
        return FALSE;
    }

    if (Ctx->Chars != 0) {
        USHORT n = (UseChars == 0 || UseChars > Ctx->Chars) ? Ctx->Chars : UseChars;
        return BlwMatchScan(List, Count, Ctx->Up, n, TRUE, Mode);
    }

    if (Ctx->Original != NULL && Ctx->Original->Buffer != NULL && Ctx->Original->Length > 0) {
        USHORT total = (USHORT)(Ctx->Original->Length / sizeof(WCHAR));
        USHORT n = (UseChars == 0 || UseChars > total) ? total : UseChars;
        return BlwMatchScan(List, Count, Ctx->Original->Buffer, n, FALSE, Mode);
    }
    return FALSE;
}

BOOLEAN
BlwMatchInListCtx(
    _In_ BLW_PROTECTED_PATH* List,
    _In_ LONG Count,
    _In_ PBLW_MATCH_CTX Ctx,
    _In_ USHORT UseChars)
{
    return BlwMatchDispatch(List, Count, Ctx, UseChars, BlwMatchSubstring);
}

BOOLEAN
BlwMatchInListAnchoredCtx(
    _In_ BLW_PROTECTED_PATH* List,
    _In_ LONG Count,
    _In_ PBLW_MATCH_CTX Ctx)
{
    return BlwMatchDispatch(List, Count, Ctx, 0, BlwMatchAnchored);
}

BOOLEAN
BlwPatternHitsSubtree(
    _In_reads_(DirChars) PCWSTR Dir,
    _In_ USHORT DirChars,
    _In_ USHORT LastStart,
    _In_reads_(PatChars) PCWSTR Pat,
    _In_ USHORT PatChars,
    _In_opt_ BLW_SUBTREE_PROBE Probe,
    _In_opt_ PVOID Context)
{
    const USHORT tChars = (USHORT)(DirChars + 1);
    USHORT s;

    if (Dir == NULL || DirChars == 0 || DirChars >= BLW_MAX_PATH || Pat == NULL || PatChars == 0) {
        return FALSE;
    }

    // s == DirChars 是补上的那个 '\':从这里开始的出现完全落在子树内,改名不影响它。
    for (s = 0; s < DirChars; s++) {
        const USHORT avail = (USHORT)(tChars - s);
        const USHORT n = (PatChars < avail) ? PatChars : avail;
        USHORT k;

        for (k = 0; k < n; k++) {
            const WCHAR c = ((USHORT)(s + k) < DirChars) ? Dir[s + k] : L'\\';
            if (c != Pat[k]) {
                break;
            }
        }
        if (k < n) {
            continue;
        }
        if (n == PatChars) {
            if ((USHORT)(s + PatChars) > LastStart) {
                return TRUE;
            }
            continue;
        }
        if (Probe == NULL || Probe(Context, &Pat[n], (USHORT)(PatChars - n))) {
            return TRUE;
        }
    }
    return FALSE;
}

BOOLEAN
BlwListHitsSubtree(
    _In_reads_(DirChars) PCWSTR Dir,
    _In_ USHORT DirChars,
    _In_ USHORT LastStart,
    _In_ BLW_PROTECTED_PATH* List,
    _In_ LONG Count,
    _In_opt_ BLW_SUBTREE_PROBE Probe,
    _In_opt_ PVOID Context)
{
    ULONG i;
    LONG  seen = 0;

    if (Dir == NULL || DirChars == 0 || DirChars >= BLW_MAX_PATH || Count <= 0) {
        return FALSE;
    }

    for (i = 0; i < BLW_MAX_PROTECTED && seen < Count; i++) {
        if (!List[i].InUse) {
            continue;
        }
        seen++;
        if (BlwPatternHitsSubtree(Dir, DirChars, LastStart, List[i].Path, List[i].Length,
                                  Probe, Context)) {
            return TRUE;
        }
    }
    return FALSE;
}

USHORT
BlwReadGuardDataChars(_In_ const BLW_PROTECTED_PATH* Entry)
{
    USHORT i;

    for (i = 0; i < Entry->Length; i++) {
        if (Entry->Path[i] == BLW_READGUARD_SEP) {
            return i;
        }
    }
    return Entry->Length;
}

BOOLEAN
BlwReadGuardDataHit(_In_ const BLW_PROTECTED_PATH* Entry,
                    _In_reads_(Chars) PCWSTR Up, _In_ USHORT Chars)
{
    const USHORT n = BlwReadGuardDataChars(Entry);
    const PCWSTR p = Entry->Path;
    USHORT s;

    if (Up == NULL || n == 0 || n > Chars) {
        return FALSE;
    }
    for (s = 0; (USHORT)(s + n) <= Chars; s++) {
        if (Up[s] != p[0] || Up[s + n - 1] != p[n - 1]) {
            continue;
        }
        if (n <= 2 || RtlEqualMemory(&Up[s + 1], &p[1], (SIZE_T)(n - 2) * sizeof(WCHAR))) {
            return TRUE;
        }
    }
    return FALSE;
}

USHORT
BlwImageInstallRelative(_In_reads_(Chars) PCWSTR Image, _In_ USHORT Chars)
{
    static const BLW_NAME_ENTRY kRoots[] = {
        BLW_NAME(L"\\Program Files"),
        BLW_NAME(L"\\Program Files (x86)"),
    };
    static const BLW_NAME_ENTRY kUserRoots[] = {
        BLW_NAME(L"\\AppData\\Local"),
        BLW_NAME(L"\\AppData\\Roaming"),
    };
    static const WCHAR kPublic[] = L"PUBLIC";
    const USHORT publicChars = (USHORT)(RTL_NUMBER_OF(kPublic) - 1);
    const USHORT off = BlwSystemVolumeRelativeOffset(Image, Chars);
    USHORT user;
    USHORT p;
    ULONG  i;

    if (off == 0) {
        return 0;
    }
    for (i = 0; i < RTL_NUMBER_OF(kRoots); i++) {
        const USHORT end = (USHORT)(off + kRoots[i].Chars);
        if (end < Chars && Image[end] == L'\\' &&
            BlwStartsWithCI(Image + off, (USHORT)(Chars - off), kRoots[i].Name, kRoots[i].Chars)) {
            return end;
        }
    }

    if (!BlwStartsWithCI(Image + off, (USHORT)(Chars - off), L"\\Users\\", 7)) {
        return 0;
    }
    user = (USHORT)(off + 7);
    p = user;
    while (p < Chars && Image[p] != L'\\') {
        p++;
    }
    if (p == user || p >= Chars) {
        return 0;
    }
    if ((USHORT)(p - user) == publicChars &&
        BlwStartsWithCI(Image + user, (USHORT)(p - user), kPublic, publicChars)) {
        return 0;
    }
    for (i = 0; i < RTL_NUMBER_OF(kUserRoots); i++) {
        const USHORT end = (USHORT)(p + kUserRoots[i].Chars);
        if (end < Chars && Image[end] == L'\\' &&
            BlwStartsWithCI(Image + p, (USHORT)(Chars - p), kUserRoots[i].Name, kUserRoots[i].Chars)) {
            return end;
        }
    }
    return 0;
}

// Frag 以 '\' 结尾时 Rest 以它开头即可,否则须与它整段相等。
static BOOLEAN
BlwFragmentFits(_In_reads_(RestChars) PCWSTR Rest, _In_ USHORT RestChars,
                _In_reads_(FragChars) PCWSTR Frag, _In_ USHORT FragChars)
{
    if (FragChars == 0 || RestChars < FragChars) {
        return FALSE;
    }
    if (Frag[FragChars - 1] != L'\\' && RestChars != FragChars) {
        return FALSE;
    }
    return BlwStartsWithCI(Rest, RestChars, Frag, FragChars);
}

BOOLEAN
BlwReadGuardReaderHit(_In_ const BLW_PROTECTED_PATH* Entry,
                      _In_reads_(Chars) PCWSTR Image, _In_ USHORT Chars)
{
    const USHORT root = BlwImageInstallRelative(Image, Chars);
    USHORT start;
    USHORT i;

    if (root == 0) {
        return FALSE;
    }
    start = (USHORT)(BlwReadGuardDataChars(Entry) + 1);
    for (i = start; i <= Entry->Length; i++) {
        if (i == Entry->Length || Entry->Path[i] == BLW_READGUARD_READER_SEP) {
            if (i > start &&
                BlwFragmentFits(Image + root, (USHORT)(Chars - root), &Entry->Path[start],
                                (USHORT)(i - start))) {
                return TRUE;
            }
            start = (USHORT)(i + 1);
        }
    }
    return FALSE;
}

BOOLEAN
BlwReadGuardGlobalReaderHit(_In_ const BLW_PROTECTED_PATH* Entry,
                            _In_reads_(Chars) PCWSTR Image, _In_ USHORT Chars)
{
    BOOLEAN sysOnly;
    USHORT off;

    if (Entry->Length == 0 || Image == NULL || Chars == 0) {
        return FALSE;
    }
    sysOnly = BlwStartsWithCI(Entry->Path, Entry->Length, L"\\PROGRAM FILES", 14) ||
              BlwStartsWithCI(Entry->Path, Entry->Length, L"\\WINDOWS\\", 9);
    off = sysOnly ? BlwSystemVolumeRelativeOffset(Image, Chars) : BlwVolumeRelativeOffset(Image, Chars);
    if (off == 0) {
        return FALSE;
    }
    return BlwFragmentFits(Image + off, (USHORT)(Chars - off), Entry->Path, Entry->Length);
}

void
BlwLogPattern(_In_ PCSTR Reason, _In_opt_ PCWSTR Path, _In_ USHORT Chars)
{
    UNICODE_STRING s;

    if (Path == NULL || Chars == 0 || Chars >= BLW_MAX_PATH) {
        RtlInitUnicodeString(&s, L"<invalid>");
    } else {
        s.Buffer = (PWCH)Path;
        s.Length = (USHORT)(Chars * sizeof(WCHAR));
        s.MaximumLength = s.Length;
    }

    KdPrint(("[Bulwark] %s: %wZ\n", Reason, &s));

    UNREFERENCED_PARAMETER(Reason);
    UNREFERENCED_PARAMETER(s);
}

BOOLEAN
BlwAddToList(_In_ BLW_PROTECTED_PATH* List, _In_ PCWSTR Path, _In_ USHORT Length)
{
    ULONG  i;
    ULONG  freeSlot = BLW_MAX_PROTECTED;
    USHORT k;

    if (Length == 0 || Length > (BLW_MAX_PATH - 1)) {
        return FALSE;
    }

    for (i = 0; i < BLW_MAX_PROTECTED; i++) {
        if (!List[i].InUse) {
            if (freeSlot == BLW_MAX_PROTECTED) {
                freeSlot = i;
            }
            continue;
        }
        if (List[i].Length != Length) {
            continue;
        }
        for (k = 0; k < Length; k++) {
            if (List[i].Path[k] != BlwUpcaseChar(Path[k])) {
                break;
            }
        }
        if (k == Length) {
            return TRUE; // 已存在也算成功，调用方请求的最终状态已经满足。
        }
    }

    if (freeSlot == BLW_MAX_PROTECTED) {
        BlwLogPattern("List full, entry DROPPED", Path, Length);
        return FALSE;
    }

    for (k = 0; k < Length; k++) {
        List[freeSlot].Path[k] = BlwUpcaseChar(Path[k]);
    }
    List[freeSlot].Path[Length] = L'\0';
    List[freeSlot].Length = Length;
    List[freeSlot].InUse = TRUE;
    return TRUE;
}

BOOLEAN
BlwRemoveFromList(_In_ BLW_PROTECTED_PATH* List, _In_ PCWSTR Path, _In_ USHORT Length)
{
    ULONG  i;
    USHORT k;

    if (Path == NULL || Length == 0 || Length > (BLW_MAX_PATH - 1)) {
        return FALSE;
    }

    for (i = 0; i < BLW_MAX_PROTECTED; i++) {
        if (!List[i].InUse || List[i].Length != Length) {
            continue;
        }
        for (k = 0; k < Length; k++) {
            if (List[i].Path[k] != BlwUpcaseChar(Path[k])) {
                break;
            }
        }
        if (k == Length) {
            RtlZeroMemory(&List[i], sizeof(List[i]));
            return TRUE;
        }
    }
    return FALSE;
}

BOOLEAN
BlwPatternHasDriveLetter(_In_opt_ PCWSTR Pattern, _In_ USHORT Chars)
{
    USHORT i;

    if (Pattern == NULL || Chars < 3) {
        return FALSE;
    }

    for (i = 0; (USHORT)(i + 3) <= Chars; i++) {
        const WCHAR c = BlwUpcaseChar(Pattern[i]);

        if (c >= L'A' && c <= L'Z' && Pattern[i + 1] == L':' && Pattern[i + 2] == L'\\') {
            return TRUE;
        }
    }
    return FALSE;
}

BOOLEAN
BlwWideContainsCI(_In_ PCWSTR Str, _In_ USHORT StrChars, _In_ PCWSTR Sub)
{
    USHORT subChars = 0;
    USHORT limit;
    USHORT s;
    WCHAR  first;
    WCHAR  last;

    if (Str == NULL || Sub == NULL || StrChars == 0) {
        return FALSE;
    }

    while (subChars < BLW_MAX_PATH && Sub[subChars] != L'\0') {
        subChars++;
    }
    if (subChars == 0 || subChars > StrChars) {
        return FALSE;
    }

    first = BlwUpcaseChar(Sub[0]);
    last = BlwUpcaseChar(Sub[subChars - 1]);
    limit = (USHORT)(StrChars - subChars);

    for (s = 0; s <= limit; s++) {
        USHORT k;

        if (BlwUpcaseChar(Str[s]) != first) {
            continue;
        }
        if (BlwUpcaseChar(Str[s + subChars - 1]) != last) {
            continue;
        }
        for (k = 1; (USHORT)(k + 1) < subChars; k++) {
            if (BlwUpcaseChar(Str[s + k]) != BlwUpcaseChar(Sub[k])) {
                break;
            }
        }
        if ((USHORT)(k + 1) >= subChars) {
            return TRUE;
        }
    }
    return FALSE;
}

BOOLEAN
BlwImageNameIn(
    _In_reads_(TableCount) const BLW_NAME_ENTRY* Table,
    _In_ ULONG TableCount,
    _In_opt_ PCWSTR Path,
    _In_ USHORT Chars)
{
    USHORT nameStart;
    USHORT nameChars;
    ULONG  i;
    WCHAR  firstUp;

    if (Path == NULL || Chars == 0) {
        return FALSE;
    }

    nameStart = Chars;
    while (nameStart > 0 && Path[nameStart - 1] != L'\\') {
        nameStart--;
    }
    if (nameStart == 0) {
        return FALSE;
    }

    nameChars = (USHORT)(Chars - nameStart);
    if (nameChars == 0) {
        return FALSE;
    }

    firstUp = BlwUpcaseChar(Path[nameStart]);

    for (i = 0; i < TableCount; i++) {
        USHORT k;

        if (Table[i].Chars != nameChars) {
            continue;
        }
        if (BlwUpcaseChar(Table[i].Name[0]) != firstUp) {
            continue;
        }
        for (k = 1; k < nameChars; k++) {
            if (BlwUpcaseChar(Path[nameStart + k]) != BlwUpcaseChar(Table[i].Name[k])) {
                break;
            }
        }
        if (k == nameChars) {
            return TRUE;
        }
    }
    return FALSE;
}

BOOLEAN
BlwIsInjectionTelemetryTarget(_In_opt_ PCWSTR Path, _In_ USHORT Chars)
{
    static const BLW_NAME_ENTRY kTargets[] = {
        BLW_NAME(L"lsass.exe"),
        BLW_NAME(L"winlogon.exe"),
        BLW_NAME(L"csrss.exe"),
        BLW_NAME(L"services.exe"),
        BLW_NAME(L"smss.exe"),
        BLW_NAME(L"WeChat.exe"),
        BLW_NAME(L"Weixin.exe"),
        BLW_NAME(L"WXWork.exe"),
        BLW_NAME(L"QQ.exe"),
        BLW_NAME(L"TIM.exe"),
    };

    return BlwImageNameIn(kTargets, RTL_NUMBER_OF(kTargets), Path, Chars);
}

static BOOLEAN
BlwTokenInCmdLine(
    _In_reads_(TargetChars) PCWSTR Target,
    _In_ ULONG TargetChars,
    _In_reads_(TokChars) PCWSTR Tok,
    _In_ USHORT TokChars)
{
    ULONG limit;
    ULONG s;
    WCHAR first;
    WCHAR last;

    if (TokChars == 0 || (ULONG)TokChars > TargetChars) {
        return FALSE;
    }

    first = Tok[0];
    last = Tok[TokChars - 1];
    limit = TargetChars - TokChars;

    for (s = 0; s <= limit; s++) {
        USHORT k;

        if (BlwUpcaseChar(Target[s]) != first) {
            continue;
        }
        if (BlwUpcaseChar(Target[s + TokChars - 1]) != last) {
            continue;
        }
        for (k = 1; (USHORT)(k + 1) < TokChars; k++) {
            if (BlwUpcaseChar(Target[s + k]) != Tok[k]) {
                break;
            }
        }
        if ((USHORT)(k + 1) >= TokChars) {
            return TRUE;
        }
    }
    return FALSE;
}

BOOLEAN
BlwCmdPatternMatches(
    _In_ const BLW_PROTECTED_PATH* Entry,
    _In_reads_(TargetChars) PCWSTR Target,
    _In_ ULONG TargetChars)
{
    USHORT start = 0;
    USHORT i;
    BOOLEAN haveToken = FALSE;

    for (i = 0; i <= Entry->Length; i++) {
        if (i == Entry->Length || Entry->Path[i] == BLW_CMD_TOKEN_SEP) {
            USHORT tokChars = (USHORT)(i - start);

            if (tokChars > 0) {
                haveToken = TRUE;
                if (!BlwTokenInCmdLine(Target, TargetChars, &Entry->Path[start], tokChars)) {
                    return FALSE;
                }
            }
            start = (USHORT)(i + 1);
        }
    }

    return haveToken;
}

static USHORT
BlwFileNameStart(_In_reads_(Chars) PCWSTR Up, _In_ USHORT Chars, _Out_ USHORT* Start)
{
    USHORT i;
    USHORT s = 0;
    for (i = 0; i < Chars; i++) {
        if (Up[i] == L'\\' || Up[i] == L'/') {
            s = (USHORT)(i + 1);
        }
    }
    *Start = s;
    return (USHORT)(Chars - s);
}

BOOLEAN
BlwFileIsUninstallerData(_In_ PBLW_MATCH_CTX Ctx)
{
    WCHAR name[64];
    USHORT n = 0;
    USHORT i;
    USHORT start;
    USHORT nameLen;
    USHORT digits;
    BOOLEAN isDat;
    BOOLEAN isMsg;

    if (Ctx->Chars > 0) {
        nameLen = BlwFileNameStart(Ctx->Up, Ctx->Chars, &start);
        if (nameLen == 0 || nameLen >= 64) {
            return FALSE;
        }
        for (i = 0; i < nameLen; i++) {
            name[n++] = Ctx->Up[start + i];
        }
    } else if (Ctx->Original != NULL && Ctx->Original->Buffer != NULL && Ctx->Original->Length > 0) {
        USHORT chars = (USHORT)(Ctx->Original->Length / sizeof(WCHAR));
        if (chars == 0) {
            return FALSE;
        }
        nameLen = BlwFileNameStart(Ctx->Original->Buffer, chars, &start);
        if (nameLen == 0 || nameLen >= 64) {
            return FALSE;
        }
        for (i = 0; i < nameLen; i++) {
            name[n++] = BlwUpcaseChar(Ctx->Original->Buffer[start + i]);
        }
    } else {
        return FALSE;
    }
    name[n] = L'\0';

    if (n < 10) {
        return FALSE;
    }
    if (name[0] != L'U' || name[1] != L'N' || name[2] != L'I' || name[3] != L'N' || name[4] != L'S') {
        return FALSE;
    }
    isDat = (name[n - 4] == L'.' && name[n - 3] == L'D' && name[n - 2] == L'A' && name[n - 1] == L'T');
    isMsg = (name[n - 4] == L'.' && name[n - 3] == L'M' && name[n - 2] == L'S' && name[n - 1] == L'G');
    if (!isDat && !isMsg) {
        return FALSE;
    }
    // UNINS 与 .EXT 之间必须是 1..4 位数字
    digits = (USHORT)(n - 4 - 5);
    if (digits < 1 || digits > 4) {
        return FALSE;
    }
    for (i = 5; i < (USHORT)(5 + digits); i++) {
        if (name[i] < L'0' || name[i] > L'9') {
            return FALSE;
        }
    }
    return TRUE;
}
