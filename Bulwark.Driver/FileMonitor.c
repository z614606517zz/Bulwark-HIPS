#include "Driver.h"

#ifndef FILE_RENAME_REPLACE_IF_EXISTS
#define FILE_RENAME_REPLACE_IF_EXISTS 0x00000001
#endif

static BOOLEAN
BlwRejectDeadPathPattern(
    _In_ PCSTR ListName,
    _In_opt_ PCWSTR Path,
    _In_ USHORT Length,
    _In_ LONG DirtyBit)
{
    if (!BlwPatternHasDriveLetter(Path, Length)) {
        return FALSE;
    }

    BlwLogPattern(ListName, Path, Length);
    BlwMarkDeadEntryDrop(DirtyBit);
    return TRUE;
}

BOOLEAN
BlwRemoveFromGuardedList(
    _In_ BLW_PROTECTED_PATH* List,
    _Inout_ PEX_PUSH_LOCK Lock,
    _Inout_ volatile LONG* Count,
    _In_ PCWSTR Path,
    _In_ USHORT Length)
{
    BOOLEAN removed;

    BlwLockExclusive(Lock);
    removed = BlwRemoveFromList(List, Path, Length);
    if (removed) {
        LONG cnt = 0;
        ULONG i;
        for (i = 0; i < BLW_MAX_PROTECTED; i++) {
            if (List[i].InUse) cnt++;
        }
        InterlockedExchange(Count, cnt);
    }
    BlwUnlock(Lock);
    return removed;
}

void
BlwClearProtectedPaths(void)
{
    BlwLockExclusive(&g_Blw.PathLock);
    RtlZeroMemory(g_Blw.ProtectedPaths, sizeof(g_Blw.ProtectedPaths));
    InterlockedExchange(&g_Blw.ProtectedPathCount, 0);
    BlwUnlock(&g_Blw.PathLock);
}

void
BlwAddProtectedPath(_In_ PCWSTR Path, _In_ USHORT Length)
{
    if (BlwRejectDeadPathPattern("ProtectedPath entry REJECTED (drive-letter pattern never matches)",
                                 Path, Length, BLW_POLICY_DIRTY_PATHS)) {
        return;
    }

    BlwLockExclusive(&g_Blw.PathLock);
    BlwAddToList(g_Blw.ProtectedPaths, Path, Length);
    {
        LONG cnt = 0;
        ULONG i;
        for (i = 0; i < BLW_MAX_PROTECTED; i++) {
            if (g_Blw.ProtectedPaths[i].InUse) cnt++;
        }
        InterlockedExchange(&g_Blw.ProtectedPathCount, cnt);
    }
    BlwUnlock(&g_Blw.PathLock);
}

BOOLEAN
BlwDelProtectedPath(_In_ PCWSTR Path, _In_ USHORT Length)
{
    return BlwRemoveFromGuardedList(g_Blw.ProtectedPaths, &g_Blw.PathLock,
                                    &g_Blw.ProtectedPathCount, Path, Length);
}

BOOLEAN
BlwPathIsProtected(_In_ PBLW_MATCH_CTX Ctx)
{
    BOOLEAN matched;
    BlwLockShared(&g_Blw.PathLock);
    matched = BlwMatchInListCtx(g_Blw.ProtectedPaths, g_Blw.ProtectedPathCount, Ctx, 0);
    BlwUnlock(&g_Blw.PathLock);
    return matched;
}

void
BlwClearFileHardBlock(void)
{
    BlwLockExclusive(&g_Blw.FileHardLock);
    RtlZeroMemory(g_Blw.FileHardBlock, sizeof(g_Blw.FileHardBlock));
    InterlockedExchange(&g_Blw.FileHardCount, 0);
    BlwUnlock(&g_Blw.FileHardLock);
}

void
BlwAddFileHardBlock(_In_ PCWSTR Path, _In_ USHORT Length)
{
    if (BlwRejectDeadPathPattern("FileHardBlock entry REJECTED (drive-letter pattern never matches)",
                                 Path, Length, BLW_POLICY_DIRTY_FILEHARD)) {
        return;
    }

    BlwLockExclusive(&g_Blw.FileHardLock);
    BlwAddToList(g_Blw.FileHardBlock, Path, Length);
    {
        LONG cnt = 0;
        ULONG i;
        for (i = 0; i < BLW_MAX_PROTECTED; i++) {
            if (g_Blw.FileHardBlock[i].InUse) cnt++;
        }
        InterlockedExchange(&g_Blw.FileHardCount, cnt);
    }
    BlwUnlock(&g_Blw.FileHardLock);
}

BOOLEAN
BlwDelFileHardBlock(_In_ PCWSTR Path, _In_ USHORT Length)
{
    return BlwRemoveFromGuardedList(g_Blw.FileHardBlock, &g_Blw.FileHardLock,
                                    &g_Blw.FileHardCount, Path, Length);
}

BOOLEAN
BlwFileIsHardBlocked(_In_ PBLW_MATCH_CTX Ctx)
{
    BOOLEAN matched;
    BlwLockShared(&g_Blw.FileHardLock);
    matched = BlwMatchInListCtx(g_Blw.FileHardBlock, g_Blw.FileHardCount, Ctx, 0);
    BlwUnlock(&g_Blw.FileHardLock);
    return matched;
}

void
BlwClearSelfGuard(void)
{
    BlwLockExclusive(&g_Blw.SelfGuardLock);
    RtlZeroMemory(g_Blw.SelfGuard, sizeof(g_Blw.SelfGuard));
    InterlockedExchange(&g_Blw.SelfGuardCount, 0);
    BlwUnlock(&g_Blw.SelfGuardLock);
}

void
BlwAddSelfGuard(_In_ PCWSTR Path, _In_ USHORT Length)
{
    if (BlwRejectDeadPathPattern("SelfGuard entry REJECTED (drive-letter pattern never matches)",
                                 Path, Length, 0)) {
        return;
    }

    BlwLockExclusive(&g_Blw.SelfGuardLock);
    BlwAddToList(g_Blw.SelfGuard, Path, Length);
    {
        LONG cnt = 0;
        ULONG i;
        for (i = 0; i < BLW_MAX_PROTECTED; i++) {
            if (g_Blw.SelfGuard[i].InUse) cnt++;
        }
        InterlockedExchange(&g_Blw.SelfGuardCount, cnt);
    }
    BlwUnlock(&g_Blw.SelfGuardLock);
}

BOOLEAN
BlwFileIsSelfGuarded(_In_ PBLW_MATCH_CTX Ctx)
{
    BOOLEAN matched;
    BlwLockShared(&g_Blw.SelfGuardLock);
    matched = BlwMatchInListCtx(g_Blw.SelfGuard, g_Blw.SelfGuardCount, Ctx, 0);
    BlwUnlock(&g_Blw.SelfGuardLock);
    return matched;
}

void
BlwClearGuardDirs(void)
{
    BlwLockExclusive(&g_Blw.GuardDirLock);
    RtlZeroMemory(g_Blw.GuardDirs, sizeof(g_Blw.GuardDirs));
    InterlockedExchange(&g_Blw.GuardDirCount, 0);
    BlwUnlock(&g_Blw.GuardDirLock);
}

void
BlwAddGuardDir(_In_ PCWSTR Path, _In_ USHORT Length)
{
    if (BlwRejectDeadPathPattern("GuardDir entry REJECTED (drive-letter pattern never matches)",
                                 Path, Length, BLW_POLICY_DIRTY_GUARDDIR)) {
        return;
    }

    BlwLockExclusive(&g_Blw.GuardDirLock);
    BlwAddToList(g_Blw.GuardDirs, Path, Length);
    {
        LONG cnt = 0;
        ULONG i;
        for (i = 0; i < BLW_MAX_PROTECTED; i++) {
            if (g_Blw.GuardDirs[i].InUse) cnt++;
        }
        InterlockedExchange(&g_Blw.GuardDirCount, cnt);
    }
    BlwUnlock(&g_Blw.GuardDirLock);
}

BOOLEAN
BlwDelGuardDir(_In_ PCWSTR Path, _In_ USHORT Length)
{
    return BlwRemoveFromGuardedList(g_Blw.GuardDirs, &g_Blw.GuardDirLock,
                                    &g_Blw.GuardDirCount, Path, Length);
}

void
BlwClearGuardWriters(void)
{
    BlwLockExclusive(&g_Blw.GuardWriterLock);
    RtlZeroMemory(g_Blw.GuardWriters, sizeof(g_Blw.GuardWriters));
    InterlockedExchange(&g_Blw.GuardWriterCount, 0);
    BlwUnlock(&g_Blw.GuardWriterLock);
}

void
BlwAddGuardWriter(_In_ PCWSTR Path, _In_ USHORT Length)
{
    if (BlwRejectDeadPathPattern("GuardWriter entry REJECTED (drive-letter pattern never matches)",
                                 Path, Length, BLW_POLICY_DIRTY_GUARDWRITER)) {
        return;
    }

    BlwLockExclusive(&g_Blw.GuardWriterLock);
    BlwAddToList(g_Blw.GuardWriters, Path, Length);
    {
        LONG cnt = 0;
        ULONG i;
        for (i = 0; i < BLW_MAX_PROTECTED; i++) {
            if (g_Blw.GuardWriters[i].InUse) cnt++;
        }
        InterlockedExchange(&g_Blw.GuardWriterCount, cnt);
    }
    BlwUnlock(&g_Blw.GuardWriterLock);
}

BOOLEAN
BlwDelGuardWriter(_In_ PCWSTR Path, _In_ USHORT Length)
{
    return BlwRemoveFromGuardedList(g_Blw.GuardWriters, &g_Blw.GuardWriterLock,
                                    &g_Blw.GuardWriterCount, Path, Length);
}

static BOOLEAN
BlwFileIsInGuardDir(_In_ PBLW_MATCH_CTX Ctx)
{
    BOOLEAN matched;
    BlwLockShared(&g_Blw.GuardDirLock);
    matched = BlwMatchInListAnchoredCtx(g_Blw.GuardDirs, g_Blw.GuardDirCount, Ctx);
    BlwUnlock(&g_Blw.GuardDirLock);
    return matched;
}

static BOOLEAN
BlwImageIsGuardWriter(_In_ PBLW_MATCH_CTX Ctx)
{
    BOOLEAN matched;
    BlwLockShared(&g_Blw.GuardWriterLock);
    matched = BlwMatchInListAnchoredCtx(g_Blw.GuardWriters, g_Blw.GuardWriterCount, Ctx);
    BlwUnlock(&g_Blw.GuardWriterLock);
    return matched;
}

static BOOLEAN
BlwProtectedPathActorAllowed(_In_ ULONG ActorPid)
{
    PUNICODE_STRING imageName = NULL;
    PBLW_MATCH_CTX imgCtx;
    USHORT chars;
    BOOLEAN allowed = FALSE;

    if (BlwPidIsProtected(ActorPid)) {
        return TRUE;
    }
    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return FALSE;
    }
    if (!NT_SUCCESS(SeLocateProcessImageName(PsGetCurrentProcess(), &imageName)) ||
        imageName == NULL || imageName->Buffer == NULL || imageName->Length == 0) {
        if (imageName != NULL) {
            ExFreePool(imageName);
        }
        return FALSE;
    }

    chars = (USHORT)(imageName->Length / sizeof(WCHAR));
    imgCtx = BlwAllocMatchCtx();
    if (imgCtx != NULL) {
        BlwPrepareMatch(imgCtx, imageName);
        allowed = BlwImageIsGuardWriter(imgCtx) ||
                  (BlwImageIsTrustedSystemPath(imageName->Buffer, chars) &&
                   !BlwImageIsLolBin(imageName->Buffer, chars));
        BlwFreeMatchCtx(imgCtx);
    }

    ExFreePool(imageName);
    return allowed;
}

static void BlwReportGuardDirBlock(_In_opt_ PCUNICODE_STRING fileName,
                                   _In_reads_opt_z_(ImageChars) PCWSTR Image,
                                   _In_ USHORT ImageChars,
                                   _In_ ULONG OriginalOp);

BOOLEAN
BlwGuardDirDenies(_In_ PBLW_MATCH_CTX Ctx, _In_ ULONG ActorPid,
                  _In_opt_ PCUNICODE_STRING ReportName, _In_ ULONG OriginalOp)
{
    PUNICODE_STRING imageName = NULL;
    PBLW_MATCH_CTX  imgCtx;
    USHORT          chars;
    BOOLEAN         denied;

    if (g_Blw.GuardDirCount == 0) {
        return FALSE;
    }

    if (BlwPidIsProtected(ActorPid)) {
        return FALSE;
    }

    if (!BlwFileIsInGuardDir(Ctx)) {
        return FALSE;
    }

    // SeLocateProcessImageName 要分配分页池,只能在 PASSIVE_LEVEL 调用;拿不到映像路径就放行。
    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return FALSE;
    }
    if (!NT_SUCCESS(SeLocateProcessImageName(PsGetCurrentProcess(), &imageName)) ||
        imageName == NULL || imageName->Buffer == NULL || imageName->Length == 0) {
        if (imageName != NULL) {
            ExFreePool(imageName);
        }
        return FALSE;
    }

    chars = (USHORT)(imageName->Length / sizeof(WCHAR));

    imgCtx = BlwAllocMatchCtx();
    if (imgCtx == NULL) {
        ExFreePool(imageName);
        return FALSE;
    }
    BlwPrepareMatch(imgCtx, imageName);

    denied = TRUE;
    if (BlwImageIsGuardWriter(imgCtx)) {
        denied = FALSE;
    } else if (BlwImageIsTrustedSystemPath(imageName->Buffer, chars) &&
               !BlwImageIsLolBin(imageName->Buffer, chars)) {
        denied = FALSE;
    }

    BlwFreeMatchCtx(imgCtx);

    if (denied) {
        BlwReportGuardDirBlock(ReportName, imageName->Buffer, chars, OriginalOp);
    }

    ExFreePool(imageName);
    return denied;
}

#define BLW_SYS_BOTH(n)  L"\\WINDOWS\\SYSTEM32\\" n, L"\\WINDOWS\\SYSWOW64\\" n

static const PCWSTR kBlwSystemImages[] = {
    BLW_SYS_BOTH(L"CMD.EXE"),
    BLW_SYS_BOTH(L"WSCRIPT.EXE"),
    BLW_SYS_BOTH(L"CSCRIPT.EXE"),
    BLW_SYS_BOTH(L"MSHTA.EXE"),
    L"\\WINDOWS\\SYSTEM32\\WINDOWSPOWERSHELL\\V1.0\\POWERSHELL.EXE",
    L"\\WINDOWS\\SYSWOW64\\WINDOWSPOWERSHELL\\V1.0\\POWERSHELL.EXE",

    BLW_SYS_BOTH(L"RUNDLL32.EXE"),
    BLW_SYS_BOTH(L"REGSVR32.EXE"),
    BLW_SYS_BOTH(L"NETSH.EXE"),
    BLW_SYS_BOTH(L"CERTUTIL.EXE"),
    BLW_SYS_BOTH(L"BITSADMIN.EXE"),
    BLW_SYS_BOTH(L"SCHTASKS.EXE"),
    BLW_SYS_BOTH(L"MSIEXEC.EXE"),
    BLW_SYS_BOTH(L"REG.EXE"),
    BLW_SYS_BOTH(L"SC.EXE"),
    BLW_SYS_BOTH(L"WMIC.EXE"),
    BLW_SYS_BOTH(L"VSSADMIN.EXE"),
    BLW_SYS_BOTH(L"BCDEDIT.EXE"),
    BLW_SYS_BOTH(L"WBADMIN.EXE"),
    BLW_SYS_BOTH(L"FORFILES.EXE"),

    BLW_SYS_BOTH(L"SVCHOST.EXE"),
    L"\\WINDOWS\\SYSTEM32\\SMSS.EXE",
    L"\\WINDOWS\\SYSTEM32\\CSRSS.EXE",
    L"\\WINDOWS\\SYSTEM32\\WININIT.EXE",
    L"\\WINDOWS\\SYSTEM32\\WINLOGON.EXE",
    L"\\WINDOWS\\SYSTEM32\\SERVICES.EXE",
    L"\\WINDOWS\\SYSTEM32\\LSASS.EXE",
    L"\\WINDOWS\\SYSTEM32\\LSAISO.EXE",
    L"\\WINDOWS\\SYSTEM32\\FONTDRVHOST.EXE",
    L"\\WINDOWS\\SYSTEM32\\DWM.EXE",
    L"\\WINDOWS\\SYSTEM32\\CONHOST.EXE",
    L"\\WINDOWS\\SYSTEM32\\DLLHOST.EXE",
    L"\\WINDOWS\\SYSTEM32\\TASKHOSTW.EXE",
    L"\\WINDOWS\\SYSTEM32\\SPOOLSV.EXE",
    L"\\WINDOWS\\SYSTEM32\\WERFAULT.EXE",
    L"\\WINDOWS\\EXPLORER.EXE",

    BLW_SYS_BOTH(L"NTDLL.DLL"),
    BLW_SYS_BOTH(L"KERNEL32.DLL"),
    BLW_SYS_BOTH(L"KERNELBASE.DLL"),
    BLW_SYS_BOTH(L"USER32.DLL"),
    BLW_SYS_BOTH(L"ADVAPI32.DLL"),
    BLW_SYS_BOTH(L"MSVCRT.DLL"),
    BLW_SYS_BOTH(L"UCRTBASE.DLL"),
    BLW_SYS_BOTH(L"COMBASE.DLL"),
    BLW_SYS_BOTH(L"OLE32.DLL"),
    BLW_SYS_BOTH(L"RPCRT4.DLL"),
    BLW_SYS_BOTH(L"SECHOST.DLL"),
    BLW_SYS_BOTH(L"GDI32.DLL"),
    BLW_SYS_BOTH(L"SHELL32.DLL"),
    BLW_SYS_BOTH(L"WS2_32.DLL"),
    BLW_SYS_BOTH(L"CRYPT32.DLL"),
    BLW_SYS_BOTH(L"BCRYPT.DLL"),
    BLW_SYS_BOTH(L"BCRYPTPRIMITIVES.DLL"),
};

// 只在配置下发和基线载入时调用,朴素滑窗扫描即可。Pattern 不要求以 NUL 结尾。
static BOOLEAN
BlwPatternHitsSystemImage(_In_opt_ PCWSTR Pattern, _In_ USHORT Chars)
{
    ULONG i;

    if (Pattern == NULL || Chars == 0) {
        return FALSE;
    }

    for (i = 0; i < RTL_NUMBER_OF(kBlwSystemImages); i++) {
        PCWSTR sys = kBlwSystemImages[i];
        USHORT sysChars = 0;
        USHORT s;

        while (sys[sysChars] != L'\0') {
            sysChars++;
        }
        if (Chars > sysChars) {
            continue;
        }

        for (s = 0; (USHORT)(s + Chars) <= sysChars; s++) {
            USHORT k;
            for (k = 0; k < Chars; k++) {
                if (sys[s + k] != BlwUpcaseChar(Pattern[k])) {
                    break;
                }
            }
            if (k == Chars) {
                return TRUE;
            }
        }
    }
    return FALSE;
}

void
BlwClearFileNoLoad(void)
{
    BlwLockExclusive(&g_Blw.FileNoLoadLock);
    RtlZeroMemory(g_Blw.FileNoLoad, sizeof(g_Blw.FileNoLoad));
    InterlockedExchange(&g_Blw.FileNoLoadCount, 0);
    BlwUnlock(&g_Blw.FileNoLoadLock);
}

BOOLEAN
BlwAddFileNoLoad(_In_ PCWSTR Path, _In_ USHORT Length)
{
    BOOLEAN accepted;
    if (BlwRejectDeadPathPattern("NoLoad entry REJECTED (drive-letter pattern never matches)",
                                 Path, Length, BLW_POLICY_DIRTY_NOLOAD)) {
        return FALSE;
    }
    if (BlwPatternHitsSystemImage(Path, Length)) {
        BlwLogPattern("NoLoad entry REJECTED (would block a system image)", Path, Length);
        BlwMarkDeadEntryDrop(BLW_POLICY_DIRTY_NOLOAD);
        return FALSE;
    }

    BlwLockExclusive(&g_Blw.FileNoLoadLock);
    accepted = BlwAddToList(g_Blw.FileNoLoad, Path, Length);
    {
        LONG cnt = 0;
        ULONG i;
        for (i = 0; i < BLW_MAX_PROTECTED; i++) {
            if (g_Blw.FileNoLoad[i].InUse) cnt++;
        }
        InterlockedExchange(&g_Blw.FileNoLoadCount, cnt);
    }
    BlwUnlock(&g_Blw.FileNoLoadLock);
    return accepted;
}

BOOLEAN
BlwDelFileNoLoad(_In_ PCWSTR Path, _In_ USHORT Length)
{
    return BlwRemoveFromGuardedList(g_Blw.FileNoLoad, &g_Blw.FileNoLoadLock,
                                    &g_Blw.FileNoLoadCount, Path, Length);
}

BOOLEAN
BlwFileIsNoLoad(_In_ PBLW_MATCH_CTX Ctx)
{
    BOOLEAN matched;
    BlwLockShared(&g_Blw.FileNoLoadLock);
    matched = BlwMatchInListAnchoredCtx(g_Blw.FileNoLoad, g_Blw.FileNoLoadCount, Ctx);
    BlwUnlock(&g_Blw.FileNoLoadLock);
    return matched;
}

void
BlwClearFileExecBlock(void)
{
    BlwLockExclusive(&g_Blw.FileExecBlockLock);
    RtlZeroMemory(g_Blw.FileExecBlock, sizeof(g_Blw.FileExecBlock));
    InterlockedExchange(&g_Blw.FileExecBlockCount, 0);
    BlwUnlock(&g_Blw.FileExecBlockLock);
}

BOOLEAN
BlwAddFileExecBlock(_In_ PCWSTR Path, _In_ USHORT Length)
{
    BOOLEAN accepted;
    if (BlwRejectDeadPathPattern("ExecBlock entry REJECTED (drive-letter pattern never matches)",
                                 Path, Length, BLW_POLICY_DIRTY_EXECBLOCK)) {
        return FALSE;
    }
    if (BlwPatternHitsSystemImage(Path, Length)) {
        BlwLogPattern("ExecBlock entry REJECTED (would block a system image)", Path, Length);
        BlwMarkDeadEntryDrop(BLW_POLICY_DIRTY_EXECBLOCK);
        return FALSE;
    }

    BlwLockExclusive(&g_Blw.FileExecBlockLock);
    accepted = BlwAddToList(g_Blw.FileExecBlock, Path, Length);
    {
        LONG cnt = 0;
        ULONG i;
        for (i = 0; i < BLW_MAX_PROTECTED; i++) {
            if (g_Blw.FileExecBlock[i].InUse) cnt++;
        }
        InterlockedExchange(&g_Blw.FileExecBlockCount, cnt);
    }
    BlwUnlock(&g_Blw.FileExecBlockLock);
    return accepted;
}

BOOLEAN
BlwDelFileExecBlock(_In_ PCWSTR Path, _In_ USHORT Length)
{
    return BlwRemoveFromGuardedList(g_Blw.FileExecBlock, &g_Blw.FileExecBlockLock,
                                    &g_Blw.FileExecBlockCount, Path, Length);
}

BOOLEAN
BlwFileIsExecBlocked(_In_ PBLW_MATCH_CTX Ctx)
{
    BOOLEAN matched;
    BlwLockShared(&g_Blw.FileExecBlockLock);
    matched = BlwMatchInListAnchoredCtx(g_Blw.FileExecBlock, g_Blw.FileExecBlockCount, Ctx);
    BlwUnlock(&g_Blw.FileExecBlockLock);
    return matched;
}

static void
BlwReportFileBlock(_In_ ULONG eventType, _In_ PCUNICODE_STRING fileName)
{
    if (!g_Blw.Active) {
        return;
    }
    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return;
    }

    BlwReportEvent(eventType, HandleToULong(PsGetCurrentProcessId()), 0,
                   fileName, NULL, 0, 0);
}

static void
BlwReportGuardDirBlock(_In_opt_ PCUNICODE_STRING fileName,
                       _In_reads_opt_z_(ImageChars) PCWSTR Image,
                       _In_ USHORT ImageChars,
                       _In_ ULONG OriginalOp)
{
    UNICODE_STRING img;
    PCUNICODE_STRING imgPtr = NULL;

    if (!g_Blw.Active) {
        return;
    }
    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return;
    }

    if (Image != NULL && ImageChars > 0) {
        img.Buffer = (PWCH)Image;
        img.Length = (USHORT)(ImageChars * sizeof(WCHAR));
        img.MaximumLength = img.Length;
        imgPtr = &img;
    }

    BlwReportEvent(BlwEventGuardDirBlocked, HandleToULong(PsGetCurrentProcessId()), OriginalOp,
                   fileName, imgPtr, 0, 0);
}

static void
BlwReportFileTelemetry(_In_ ULONG eventType, _In_ PCUNICODE_STRING fileName)
{
    if (!g_Blw.Active) {
        return;
    }
    if (g_Blw.FileTelemetryEnabled == 0) {
        return;
    }
    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return;
    }

    BlwReportEvent(BlwEventFileModify, HandleToULong(PsGetCurrentProcessId()), eventType,
                   fileName, NULL, 0, 0);
}

#ifndef FO_VOLUME_OPEN
#define FO_VOLUME_OPEN 0x00400000
#endif

static void
BlwReportBootBlock(_In_opt_ PFLT_VOLUME Volume, _In_ ULONG SectorKb)
{
    WCHAR nameBuf[64];
    UNICODE_STRING volName;
    UNICODE_STRING fallback;

    if (!g_Blw.Active || KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return;
    }

    volName.Buffer = nameBuf;
    volName.Length = 0;
    volName.MaximumLength = sizeof(nameBuf);

    if (Volume != NULL && NT_SUCCESS(FltGetVolumeName(Volume, &volName, NULL)) &&
        volName.Length > 0) {
        BlwReportEvent(BlwEventBootSectorBlocked, HandleToULong(PsGetCurrentProcessId()),
                       SectorKb, &volName, NULL, 0, 0);
        return;
    }

    RtlInitUnicodeString(&fallback, L"\\??\\RawVolume");
    BlwReportEvent(BlwEventBootSectorBlocked, HandleToULong(PsGetCurrentProcessId()),
                   SectorKb, &fallback, NULL, 0, 0);
}

BOOLEAN
BlwCreateIsRawVolumeOpen(_In_ PFLT_CALLBACK_DATA Data)
{
    return (Data->Iopb->TargetFileObject != NULL &&
            Data->Iopb->TargetFileObject->FileName.Length == 0 &&
            Data->Iopb->TargetFileObject->RelatedFileObject == NULL) ? TRUE : FALSE;
}

FLT_PREOP_CALLBACK_STATUS
BlwBootGuardPreCreate(_Inout_ PFLT_CALLBACK_DATA Data)
{
    ACCESS_MASK desiredAccess = 0;
    ULONG actorPid;

    if (Data->Iopb->Parameters.Create.SecurityContext != NULL) {
        desiredAccess = Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess;
    }
    if ((desiredAccess & (FILE_WRITE_DATA | FILE_APPEND_DATA)) == 0) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    actorPid = HandleToULong(PsGetCurrentProcessId());

    if (g_Blw.BannedPidCount > 0) {
        if (BlwPidIsBanned(actorPid)) {
            Data->IoStatus.Status = STATUS_ACCESS_DENIED;
            Data->IoStatus.Information = 0;
            BlwReportBootBlock(NULL, 0);
            return FLT_PREOP_COMPLETE;
        }
    }

    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

static BOOLEAN
BlwIsDroppedPayload(_In_opt_ PCWSTR Path, _In_ USHORT Chars)
{
    static const BLW_NAME_ENTRY kDropZones[] = {
        BLW_NAME(L"\\Users\\"),
        BLW_NAME(L"\\ProgramData\\"),
        BLW_NAME(L"\\Windows\\Temp\\"),
        BLW_NAME(L"\\PerfLogs\\"),
        BLW_NAME(L"\\$Recycle.Bin\\"),
    };

    // 与用户态 isDroppedExecutable 的扩展名列表保持一致。
    static const BLW_NAME_ENTRY kPayloadExt[] = {
        BLW_NAME(L".exe"),  BLW_NAME(L".dll"),  BLW_NAME(L".sys"),  BLW_NAME(L".scr"),
        BLW_NAME(L".com"),  BLW_NAME(L".pif"),  BLW_NAME(L".cpl"),  BLW_NAME(L".ocx"),
        BLW_NAME(L".drv"),  BLW_NAME(L".bat"),  BLW_NAME(L".cmd"),  BLW_NAME(L".ps1"),
        BLW_NAME(L".psm1"), BLW_NAME(L".vbs"),  BLW_NAME(L".vbe"),  BLW_NAME(L".js"),
        BLW_NAME(L".jse"),  BLW_NAME(L".wsf"),  BLW_NAME(L".wsh"),  BLW_NAME(L".hta"),
        BLW_NAME(L".jar"),  BLW_NAME(L".msi"),  BLW_NAME(L".msp"),  BLW_NAME(L".lnk"),
    };

    USHORT off;
    ULONG  i;
    BOOLEAN inZone = FALSE;

    if (Path == NULL || Chars == 0) {
        return FALSE;
    }

    off = BlwVolumeRelativeOffset(Path, Chars);
    if (off == 0) {
        return FALSE;
    }

    for (i = 0; i < RTL_NUMBER_OF(kDropZones); i++) {
        if (BlwStartsWithCI(Path + off, (USHORT)(Chars - off),
                            kDropZones[i].Name, kDropZones[i].Chars)) {
            inZone = TRUE;
            break;
        }
    }
    if (!inZone) {
        return FALSE;
    }

    for (i = 0; i < RTL_NUMBER_OF(kPayloadExt); i++) {
        const USHORT extChars = kPayloadExt[i].Chars;

        if (Chars < extChars) {
            continue;
        }
        if (BlwStartsWithCI(Path + (Chars - extChars), extChars,
                            kPayloadExt[i].Name, extChars)) {
            return TRUE;
        }
    }
    return FALSE;
}

static BOOLEAN
BlwCreateDispositionWrites(_In_ ULONG CreateOptions)
{
    const ULONG disposition = (CreateOptions >> 24) & 0xFF;

    return (disposition == FILE_SUPERSEDE ||
            disposition == FILE_CREATE ||
            disposition == FILE_OPEN_IF ||
            disposition == FILE_OVERWRITE ||
            disposition == FILE_OVERWRITE_IF);
}

// 打开阶段的名单判定位。预创建取不到名字时原样交给 BlwPostCreate。
#define BLW_CHK_HARD      0x01
#define BLW_CHK_SELFGUARD 0x02
#define BLW_CHK_NOLOAD    0x04
#define BLW_CHK_PROT      0x08
#define BLW_CHK_GUARDDIR  0x10
#define BLW_CHK_READGUARD 0x20
// 不是名单,是标记:HARD / SELFGUARD / GUARDDIR 只因 MAXIMUM_ALLOWED 才设上,真拿到写 / 删权才算数。
#define BLW_CHK_MAXALLOWED 0x40

// 命中返回 TRUE。受保护目录由 BlwGuardDirDenies 自己上报,其余在这里上报。
static BOOLEAN
BlwCreateDenied(_In_ ULONG Checks, _In_ PBLW_MATCH_CTX Ctx, _In_ PCUNICODE_STRING Name,
                _In_ ULONG ActorPid)
{
    if ((Checks & BLW_CHK_HARD) && BlwFileIsHardBlocked(Ctx)) {
        BlwReportFileBlock(BlwEventFileDelete, Name);
        return TRUE;
    }
    if ((Checks & BLW_CHK_SELFGUARD) && !BlwPidIsProtected(ActorPid) &&
        BlwFileIsSelfGuarded(Ctx) && !BlwFileIsUninstallerData(Ctx)) {
        BlwReportFileBlock(BlwEventFileDelete, Name);
        return TRUE;
    }
    if ((Checks & BLW_CHK_NOLOAD) && BlwFileIsNoLoad(Ctx)) {
        BlwReportFileBlock(BlwEventImageBlocked, Name);
        return TRUE;
    }
    if ((Checks & BLW_CHK_PROT) && BlwPathIsProtected(Ctx) &&
        !BlwProtectedPathActorAllowed(ActorPid)) {
        BlwReportFileBlock(BlwEventFileDelete, Name);
        return TRUE;
    }
    if ((Checks & BLW_CHK_GUARDDIR) && BlwGuardDirDenies(Ctx, ActorPid, Name, 0)) {
        return TRUE;
    }
    // 窃密防护自己上报 SensitiveRead,内部取 PID 掩码(带缓存)判定主体是否指定读者。
    if ((Checks & BLW_CHK_READGUARD) && BlwReadGuardDenies(Ctx, ActorPid, Name)) {
        return TRUE;
    }
    return FALSE;
}

// 原始名里是否含某字符(快筛用,避免对 8.3 短名误信)。
static BOOLEAN
BlwUnicodeHasChar(_In_ PCUNICODE_STRING Name, _In_ WCHAR Ch)
{
    USHORT chars = (USHORT)(Name->Length / sizeof(WCHAR));
    USHORT i;

    if (Name->Buffer == NULL) {
        return FALSE;
    }
    for (i = 0; i < chars; i++) {
        if (Name->Buffer[i] == Ch) {
            return TRUE;
        }
    }
    return FALSE;
}

typedef struct _BLW_RENAME_PROBE {
    PFLT_INSTANCE    Instance;
    PCUNICODE_STRING Dir;      // 被改名目录的规范化全路径
} BLW_RENAME_PROBE;

// 「Dir\Rest」在卷上是否存在。经本实例之下打开,不会回到本过滤器;查不了时按存在处理(拦)。
static BOOLEAN
BlwRenameProbeExists(_In_opt_ PVOID Context, _In_reads_(RestChars) PCWSTR Rest, _In_ USHORT RestChars)
{
    const BLW_RENAME_PROBE* probe = (const BLW_RENAME_PROBE*)Context;
    UNICODE_STRING path;
    OBJECT_ATTRIBUTES oa;
    IO_STATUS_BLOCK iosb;
    HANDLE h = NULL;
    NTSTATUS st;
    USHORT dirChars;
    ULONG total;
    PWCH buf;

    while (RestChars > 0 && Rest[RestChars - 1] == L'\\') {
        RestChars--;
    }
    if (probe == NULL || probe->Dir == NULL || probe->Dir->Buffer == NULL || RestChars == 0 ||
        KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return TRUE;
    }
    dirChars = (USHORT)(probe->Dir->Length / sizeof(WCHAR));
    total = (ULONG)dirChars + 1 + RestChars;
    if (total * sizeof(WCHAR) > MAXUSHORT) {
        return TRUE;
    }
    buf = (PWCH)BlwAllocPool(PagedPool, total * sizeof(WCHAR), BLW_TAG);
    if (buf == NULL) {
        return TRUE;
    }
    RtlCopyMemory(buf, probe->Dir->Buffer, (SIZE_T)dirChars * sizeof(WCHAR));
    buf[dirChars] = L'\\';
    RtlCopyMemory(&buf[dirChars + 1], Rest, (SIZE_T)RestChars * sizeof(WCHAR));
    path.Buffer = buf;
    path.Length = (USHORT)(total * sizeof(WCHAR));
    path.MaximumLength = path.Length;

    InitializeObjectAttributes(&oa, &path, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);
    st = FltCreateFile(g_Blw.Filter, probe->Instance, &h, FILE_READ_ATTRIBUTES | SYNCHRONIZE, &oa, &iosb,
                       NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                       FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT | FILE_OPEN_REPARSE_POINT, NULL, 0,
                       IO_IGNORE_SHARE_ACCESS_CHECK);
    ExFreePoolWithTag(buf, BLW_TAG);
    if (NT_SUCCESS(st)) {
        FltClose(h);
        return TRUE;
    }
    return st != STATUS_OBJECT_NAME_NOT_FOUND && st != STATUS_OBJECT_PATH_NOT_FOUND &&
           st != STATUS_OBJECT_NAME_INVALID && st != STATUS_NOT_A_DIRECTORY;
}

static BOOLEAN
BlwDirRenameHits(_In_ PBLW_MATCH_CTX Ctx, _In_ USHORT LastStart, _In_ BLW_PROTECTED_PATH* List,
                 _Inout_ PEX_PUSH_LOCK Lock, _In_ volatile LONG* Count, _In_ BLW_RENAME_PROBE* Probe)
{
    BOOLEAN hit;

    if (*Count <= 0) {
        return FALSE;
    }
    BlwLockShared(Lock);
    hit = BlwListHitsSubtree(Ctx->Up, Ctx->Chars, LastStart, List, *Count, BlwRenameProbeExists, Probe);
    BlwUnlock(Lock);
    return hit;
}

// 目录改名会把整棵子树一起换路径,子树里的文件一次都不经过逐文件拦截,
// 所以受保护条目本身所在的目录及其各级上级,都按条目自身的规则把关。
static BOOLEAN
BlwDirRenameDenied(_In_ PBLW_MATCH_CTX Ctx, _In_ ULONG ActorPid, _In_ PFLT_INSTANCE Instance,
                   _In_ PCUNICODE_STRING DirName)
{
    BLW_RENAME_PROBE probe;
    USHORT last;
    BOOLEAN needTrust;

    if (Ctx->Chars < 2 || Ctx->Up[Ctx->Chars - 1] == L'\\') {
        return FALSE;
    }
    last = Ctx->Chars;
    while (last > 0 && Ctx->Up[last - 1] != L'\\') {
        last--;
    }
    probe.Instance = Instance;
    probe.Dir = DirName;

    if (BlwDirRenameHits(Ctx, last, g_Blw.FileHardBlock, &g_Blw.FileHardLock, &g_Blw.FileHardCount, &probe)) {
        return TRUE;
    }
    if (BlwPidIsProtected(ActorPid)) {
        return FALSE;
    }
    if (BlwDirRenameHits(Ctx, last, g_Blw.SelfGuard, &g_Blw.SelfGuardLock, &g_Blw.SelfGuardCount, &probe)) {
        return TRUE;
    }
    needTrust =
        BlwDirRenameHits(Ctx, last, g_Blw.ProtectedPaths, &g_Blw.PathLock, &g_Blw.ProtectedPathCount, &probe) ||
        BlwDirRenameHits(Ctx, last, g_Blw.GuardDirs, &g_Blw.GuardDirLock, &g_Blw.GuardDirCount, &probe);
    return needTrust && !BlwProtectedPathActorAllowed(ActorPid);
}

// 改名敏感数据所在目录或它的上级,能把整棵子树移出数据片段的命中范围,之后再读就不再命中。
// 只看主体不是指定读者的那些条目(浏览器改自己的配置目录照常放行)。
BOOLEAN
BlwReadGuardDirRenameDenies(_In_ PBLW_MATCH_CTX Ctx, _In_ ULONG ActorPid,
                            _In_ PFLT_INSTANCE Instance, _In_ PCUNICODE_STRING DirName)
{
    BLW_RENAME_PROBE probe;
    USHORT  last;
    LONG64  mask;
    BOOLEAN hit = FALSE;
    ULONG   i;
    LONG    seen = 0;

    if (g_Blw.ReadGuardCount == 0 || Ctx->Chars < 2 || Ctx->Up[Ctx->Chars - 1] == L'\\') {
        return FALSE;
    }
    mask = BlwReadGuardMaskForPid(ActorPid);
    if (mask == ~0ll) {
        return FALSE;
    }
    last = Ctx->Chars;
    while (last > 0 && Ctx->Up[last - 1] != L'\\') {
        last--;
    }
    probe.Instance = Instance;
    probe.Dir = DirName;

    BlwLockShared(&g_Blw.ReadGuardLock);
    for (i = 0; i < BLW_MAX_PROTECTED && seen < g_Blw.ReadGuardCount; i++) {
        USHORT dataChars;

        if (!g_Blw.ReadGuard[i].InUse) {
            continue;
        }
        seen++;
        if ((mask & (1ll << i)) != 0) {
            continue;
        }
        dataChars = BlwReadGuardDataChars(&g_Blw.ReadGuard[i]);
        if (dataChars != 0 &&
            BlwPatternHitsSubtree(Ctx->Up, Ctx->Chars, last, g_Blw.ReadGuard[i].Path, dataChars,
                                  BlwRenameProbeExists, &probe)) {
            hit = TRUE;
            break;
        }
    }
    BlwUnlock(&g_Blw.ReadGuardLock);

    if (hit) {
        BlwReportSensitiveRead(ActorPid, DirName);
    }
    return hit;
}

FLT_PREOP_CALLBACK_STATUS
BlwPreCreate(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext)
{
    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    PBLW_MATCH_CTX ctx;
    NTSTATUS status;
    ULONG createOptions;
    ULONG disposition;
    ACCESS_MASK desiredAccess;
    BOOLEAN deleteOnClose;
    BOOLEAN truncates;
    BOOLEAN writeOrDeleteIntent;
    BOOLEAN executeIntent;
    BOOLEAN contentIntent;
    BOOLEAN maxAllowedDefer;
    BOOLEAN needTelemetry;
    BOOLEAN needDropWatch;
    BOOLEAN denied;
    ULONG   checks = 0;
    ULONG   actorPid;

    UNREFERENCED_PARAMETER(FltObjects);
    *CompletionContext = NULL;

    // 无客户端连接时名单照样生效,不要在这里判 Active;上报函数内部自己判空。

    if (Data->RequestorMode == KernelMode) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    actorPid = HandleToULong(PsGetCurrentProcessId());

    // 不干预页面文件打开(拒绝或拖慢会死锁或 BugCheck)。上面的 RequestorMode 判断已覆盖,这里显式再挡一道。
    if (FlagOn(Data->Iopb->OperationFlags, SL_OPEN_PAGING_FILE)) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    if (BlwCreateIsRawVolumeOpen(Data)) {
        if (g_Blw.BootGuardEnabled != 0) {
            return BlwBootGuardPreCreate(Data);
        }
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    createOptions = Data->Iopb->Parameters.Create.Options;
    disposition = (createOptions >> 24) & 0xFF;
    deleteOnClose = (createOptions & FILE_DELETE_ON_CLOSE) ? TRUE : FALSE;
    // 覆盖 / 取代在打开的那一刻就清空了原内容,哪怕只申请了读权限。
    truncates = (disposition == FILE_SUPERSEDE || disposition == FILE_OVERWRITE ||
                 disposition == FILE_OVERWRITE_IF) ? TRUE : FALSE;

    desiredAccess = 0;
    if (Data->Iopb->Parameters.Create.SecurityContext != NULL) {
        desiredAccess = Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess;
    }
    writeOrDeleteIntent = (deleteOnClose || truncates ||
        (desiredAccess & (FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_WRITE_ATTRIBUTES |
                          FILE_WRITE_EA | DELETE | WRITE_DAC | WRITE_OWNER))) ? TRUE : FALSE;

    // GENERIC_WRITE / GENERIC_ALL 到这里时已被 I/O 管理器展开成具体写位,上面的判定已覆盖它们。
    // MAXIMUM_ALLOWED 不展开,预创建看不到写位:先按写意图设判定位纳入名单检查,拦不拦留到创建后
    // 看 FILE_OBJECT 的 WriteAccess / DeleteAccess,这样只读打开不会被误拦。
    maxAllowedDefer = FALSE;
    if ((desiredAccess & MAXIMUM_ALLOWED) && !writeOrDeleteIntent) {
        writeOrDeleteIntent = TRUE;
        maxAllowedDefer = TRUE;
    }

    executeIntent = (desiredAccess & FILE_EXECUTE) ? TRUE : FALSE;

    // 碰到文件内容的打开(读 / 列目录 / 执行映射 / 写 / 删 / 改权限)。只查属性的不算,
    // 资源管理器显示图标、杀软看大小都靠它,拦了只会误伤。
    contentIntent = (writeOrDeleteIntent || executeIntent ||
        (desiredAccess & (FILE_READ_DATA | MAXIMUM_ALLOWED | GENERIC_READ | GENERIC_ALL))) ? TRUE : FALSE;

    if ((writeOrDeleteIntent || executeIntent) && g_Blw.BannedPidCount > 0) {
        if (BlwPidIsBanned(actorPid)) {
            Data->IoStatus.Status = STATUS_ACCESS_DENIED;
            Data->IoStatus.Information = 0;
            return FLT_PREOP_COMPLETE;
        }
    }

    if (g_Blw.FileHardCount > 0 && writeOrDeleteIntent) {
        checks |= BLW_CHK_HARD;
    }
    if (g_Blw.SelfGuardCount > 0 && writeOrDeleteIntent) {
        checks |= BLW_CHK_SELFGUARD;
    }
    if (g_Blw.FileNoLoadCount > 0 && executeIntent) {
        checks |= BLW_CHK_NOLOAD;
    }
    if (g_Blw.ProtectedPathCount > 0 && deleteOnClose) {
        checks |= BLW_CHK_PROT;
    }
    // 受保护目录必须在打开阶段拦:就地加密型勒索既不删也不改名,拒绝写意图打开后内容一个字节都改不了。
    if (g_Blw.GuardDirCount > 0 && writeOrDeleteIntent) {
        checks |= BLW_CHK_GUARDDIR;
    }
    // 窃密防护:系统读者 / 全局读者 / 本产品进程的掩码是全 1,直接跳过,不为它们的每次读打开查名字。
    if (g_Blw.ReadGuardCount > 0 && contentIntent && BlwReadGuardMaskForPid(actorPid) != ~0ll) {
        checks |= BLW_CHK_READGUARD;

        // 原始绝对名里一个数据片段都没有 => 这次打开不涉及敏感数据,省掉规范化查询(读是热路径)。
        // 相对打开、含 '~' 的(可能是 8.3 短名)原始名不能代表真实路径,仍走规范化精判。
        if (!FlagOn(createOptions, FILE_OPEN_BY_FILE_ID)) {
            const PFILE_OBJECT fo = Data->Iopb->TargetFileObject;
            if (fo != NULL && fo->RelatedFileObject == NULL && fo->FileName.Buffer != NULL &&
                fo->FileName.Length > 0 && !BlwUnicodeHasChar(&fo->FileName, L'~') &&
                !BlwReadGuardRawNameMightHit(&fo->FileName)) {
                checks &= ~BLW_CHK_READGUARD;
            }
        }
    }

    // 写向名单命中、且本次是 MAXIMUM_ALLOWED 撑起来的写意图:整体推迟到 BlwPostCreate,
    // 按实际授予的写 / 删权限定夺。读向(ReadGuard)可读即判,不受影响。
    if (maxAllowedDefer && (checks & (BLW_CHK_HARD | BLW_CHK_SELFGUARD | BLW_CHK_GUARDDIR)) != 0) {
        checks |= BLW_CHK_MAXALLOWED;
    }

    needTelemetry = (g_Blw.FileTelemetryEnabled != 0) && deleteOnClose;
    needDropWatch = (g_Blw.FileTelemetryEnabled != 0) && writeOrDeleteIntent && !maxAllowedDefer &&
                    !deleteOnClose && BlwCreateDispositionWrites(createOptions);

    if (checks == 0 && !needTelemetry && !needDropWatch) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    // MAXIMUM_ALLOWED 的写向判定要等创建后看实际授予的权限,整次打开挪到 BlwPostCreate。
    // 撤销打开发生在句柄返回调用方之前,所以推迟并不会放过写入。
    if (checks & BLW_CHK_MAXALLOWED) {
        *CompletionContext = (PVOID)(ULONG_PTR)checks;
        return FLT_PREOP_SUCCESS_WITH_CALLBACK;
    }

    // 按文件 ID 打开时这里查不到名字,名单判定挪到 BlwPostCreate。撤销打开撤不回已经发生的
    // 截断,也拦不住关闭时删除,所以这两种对不可信进程只能在这里直接拒绝。
    if (FlagOn(createOptions, FILE_OPEN_BY_FILE_ID)) {
        if (checks == 0) {
            return FLT_PREOP_SUCCESS_NO_CALLBACK;
        }
        // 窃密防护防的是读,截断不归它管,照常挪到 BlwPostCreate 按名字判定。
        if ((truncates || deleteOnClose) && (checks & ~(BLW_CHK_NOLOAD | BLW_CHK_READGUARD)) != 0 &&
            !BlwProtectedPathActorAllowed(actorPid)) {
            UNICODE_STRING byId;
            RtlInitUnicodeString(&byId, L"<open-by-file-id>");
            BlwReportFileBlock(BlwEventFileDelete, &byId);
            Data->IoStatus.Status = STATUS_ACCESS_DENIED;
            Data->IoStatus.Information = 0;
            return FLT_PREOP_COMPLETE;
        }
        *CompletionContext = (PVOID)(ULONG_PTR)checks;
        return FLT_PREOP_SUCCESS_WITH_CALLBACK;
    }

    // 不要把 NORMALIZED 改成 OPENED:OPENED 可能是 8.3 短名或挂载点 / 符号链接路径,换个写法打开就能
    // 绕过所有长名匹配。要降成本应继续收窄上面的判定位。网络卷的规范化查询较慢,这是接受的代价。
    status = FltGetFileNameInformation(
        Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &nameInfo);
    if (!NT_SUCCESS(status)) {
        if (checks == 0) {
            return FLT_PREOP_SUCCESS_NO_CALLBACK;
        }
        *CompletionContext = (PVOID)(ULONG_PTR)checks;
        return FLT_PREOP_SUCCESS_WITH_CALLBACK;
    }
    FltParseFileNameInformation(nameInfo);

    if (checks != 0) {
        ctx = BlwAllocMatchCtx();
        if (ctx == NULL) {
            FltReleaseFileNameInformation(nameInfo);
            return FLT_PREOP_SUCCESS_NO_CALLBACK;
        }
        BlwPrepareMatch(ctx, &nameInfo->Name);
        denied = BlwCreateDenied(checks, ctx, &nameInfo->Name, actorPid);
        BlwFreeMatchCtx(ctx);
        if (denied) {
            Data->IoStatus.Status = STATUS_ACCESS_DENIED;
            Data->IoStatus.Information = 0;
            FltReleaseFileNameInformation(nameInfo);
            return FLT_PREOP_COMPLETE;
        }
    }

    if (needTelemetry) {
        BlwReportFileTelemetry(BlwEventFileDelete, &nameInfo->Name);
    }

    if (needDropWatch && !BlwPidIsProtected(actorPid) &&
        BlwIsDroppedPayload(nameInfo->Name.Buffer,
                            (USHORT)(nameInfo->Name.Length / sizeof(WCHAR)))) {
        BlwReportFileTelemetry(BlwEventFileRename, &nameInfo->Name);
    }

    FltReleaseFileNameInformation(nameInfo);
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

FLT_POSTOP_CALLBACK_STATUS
BlwPostCreate(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags)
{
    ULONG checks = (ULONG)(ULONG_PTR)CompletionContext;
    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    PBLW_MATCH_CTX ctx;
    BOOLEAN denied;

    if (checks == 0 || FlagOn(Flags, FLTFL_POST_OPERATION_DRAINING)) {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }
    // STATUS_REPARSE 也是成功码,但此时文件并没有打开。
    if (!NT_SUCCESS(Data->IoStatus.Status) || Data->IoStatus.Status == STATUS_REPARSE ||
        FltObjects->FileObject == NULL) {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    // MAXIMUM_ALLOWED:写向名单当初只是「按写意图」设上的,这里看实际授予的权限 ——
    // 没真拿到写 / 删权就把这些写向位摘掉,避免把只读打开误拦;读向(ReadGuard)不受影响。
    if (checks & BLW_CHK_MAXALLOWED) {
        if (!FltObjects->FileObject->WriteAccess && !FltObjects->FileObject->DeleteAccess) {
            checks &= ~(BLW_CHK_HARD | BLW_CHK_SELFGUARD | BLW_CHK_PROT | BLW_CHK_GUARDDIR);
        }
        checks &= ~BLW_CHK_MAXALLOWED;
        if (checks == 0) {
            return FLT_POSTOP_FINISHED_PROCESSING;
        }
    }

    if (!NT_SUCCESS(FltGetFileNameInformation(
            Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &nameInfo))) {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    ctx = BlwAllocMatchCtx();
    if (ctx == NULL) {
        FltReleaseFileNameInformation(nameInfo);
        return FLT_POSTOP_FINISHED_PROCESSING;
    }
    BlwPrepareMatch(ctx, &nameInfo->Name);
    denied = BlwCreateDenied(checks, ctx, &nameInfo->Name, HandleToULong(PsGetCurrentProcessId()));
    BlwFreeMatchCtx(ctx);
    FltReleaseFileNameInformation(nameInfo);

    if (denied) {
        FltCancelFileOpen(FltObjects->Instance, FltObjects->FileObject);
        Data->IoStatus.Status = STATUS_ACCESS_DENIED;
        Data->IoStatus.Information = 0;
    }
    return FLT_POSTOP_FINISHED_PROCESSING;
}

FLT_PREOP_CALLBACK_STATUS
BlwPreSetInformation(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext)
{
    FILE_INFORMATION_CLASS infoClass;
    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    PBLW_MATCH_CTX ctx;
    NTSTATUS status;
    ULONG eventType;
    BOOLEAN isLink = FALSE;
    BOOLEAN deny = FALSE;
    BOOLEAN reported = FALSE;
    ULONG   actorPid;

    *CompletionContext = NULL;

    if (Data->RequestorMode == KernelMode) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    infoClass = Data->Iopb->Parameters.SetFileInformation.FileInformationClass;

    switch (infoClass) {
    case FileDispositionInformation:
    case FileDispositionInformationEx:
        eventType = BlwEventFileDelete;
        break;
    case FileRenameInformation:
    case FileRenameInformationEx:
        eventType = BlwEventFileRename;
        break;
    // 硬链接给受保护文件在名单外另起一个名字,之后经新名字打开写入就不再命中名单。
    // 源和目标按改名同样把关,但不当作改名上报遥测。
    case FileLinkInformation:
    case FileLinkInformationEx:
        eventType = BlwEventFileRename;
        isLink = TRUE;
        break;
    default:
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    actorPid = HandleToULong(PsGetCurrentProcessId());

    if (g_Blw.BannedPidCount > 0 && BlwPidIsBanned(actorPid)) {
        Data->IoStatus.Status = STATUS_ACCESS_DENIED;
        Data->IoStatus.Information = 0;
        return FLT_PREOP_COMPLETE;
    }

    if (g_Blw.ProtectedPathCount == 0 && g_Blw.FileHardCount == 0 &&
        g_Blw.SelfGuardCount == 0 && g_Blw.GuardDirCount == 0 && g_Blw.ReadGuardCount == 0 &&
        (isLink || g_Blw.FileTelemetryEnabled == 0)) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    status = FltGetFileNameInformation(
        Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &nameInfo);
    if (!NT_SUCCESS(status)) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }
    FltParseFileNameInformation(nameInfo);

    ctx = BlwAllocMatchCtx();
    if (ctx == NULL) {
        FltReleaseFileNameInformation(nameInfo);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }
    BlwPrepareMatch(ctx, &nameInfo->Name);

    if (g_Blw.SelfGuardCount > 0 && !BlwPidIsProtected(actorPid) &&
        BlwFileIsSelfGuarded(ctx) && !BlwFileIsUninstallerData(ctx)) {
        deny = TRUE;
    } else if (g_Blw.FileHardCount > 0 && BlwFileIsHardBlocked(ctx)) {
        deny = TRUE;
    } else if (!isLink && g_Blw.ProtectedPathCount > 0 && BlwPathIsProtected(ctx) &&
               !BlwProtectedPathActorAllowed(actorPid)) {
        // 受保护路径只防删除与改名,不防写入,经链接写入谈不上绕过,链接源不必在此把关。
        deny = TRUE;
    } else if (g_Blw.GuardDirCount > 0 &&
               BlwGuardDirDenies(ctx, actorPid, &nameInfo->Name, eventType)) {
        deny = TRUE;
        reported = TRUE;
    } else if (g_Blw.ReadGuardCount > 0 && BlwReadGuardDenies(ctx, actorPid, &nameInfo->Name)) {
        // 把敏感数据硬链接 / 改名 / 移动出受保护命名空间也是窃密的一步,源名命中即拦(链接同理)。
        deny = TRUE;
        reported = TRUE;
    }

    if (!deny && eventType == BlwEventFileRename && !isLink) {
        BOOLEAN isDir = FALSE;
        if (NT_SUCCESS(FltIsDirectory(FltObjects->FileObject, FltObjects->Instance, &isDir)) && isDir) {
            if (BlwDirRenameDenied(ctx, actorPid, FltObjects->Instance, &nameInfo->Name)) {
                deny = TRUE;
            } else if (BlwReadGuardDirRenameDenies(ctx, actorPid, FltObjects->Instance, &nameInfo->Name)) {
                deny = TRUE;
                reported = TRUE;
            }
        }
    }

    if (deny) {
        if (!reported) {
            BlwReportFileBlock(eventType, &nameInfo->Name);
        }
        BlwFreeMatchCtx(ctx);
        FltReleaseFileNameInformation(nameInfo);
        Data->IoStatus.Status = STATUS_ACCESS_DENIED;
        Data->IoStatus.Information = 0;
        return FLT_PREOP_COMPLETE;
    }

    if (eventType == BlwEventFileRename &&
        (g_Blw.SelfGuardCount > 0 || g_Blw.FileHardCount > 0 || g_Blw.ProtectedPathCount > 0 ||
         g_Blw.GuardDirCount > 0) &&
        KeGetCurrentIrql() == PASSIVE_LEVEL) {

        // FILE_LINK_INFORMATION 与 FILE_RENAME_INFORMATION 布局相同。
        PFILE_RENAME_INFORMATION ren =
            (PFILE_RENAME_INFORMATION)Data->Iopb->Parameters.SetFileInformation.InfoBuffer;

        if (ren != NULL && ren->FileNameLength > 0) {
            PFLT_FILE_NAME_INFORMATION destInfo = NULL;

            status = FltGetDestinationFileNameInformation(
                FltObjects->Instance,
                FltObjects->FileObject,
                ren->RootDirectory,
                ren->FileName,
                ren->FileNameLength,
                FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,
                &destInfo);

            if (NT_SUCCESS(status) && destInfo != NULL) {
                BOOLEAN guardDeny = FALSE;
                BOOLEAN replaceIfExists;

                FltParseFileNameInformation(destInfo);

                BlwPrepareMatch(ctx, &destInfo->Name);

                if (infoClass == FileRenameInformationEx || infoClass == FileLinkInformationEx) {
                    ULONG flags = 0;
                    RtlCopyMemory(&flags, ren, sizeof(flags));
                    replaceIfExists = (flags & FILE_RENAME_REPLACE_IF_EXISTS) != 0;
                } else {
                    replaceIfExists = (ren->ReplaceIfExists != FALSE);
                }

                if (g_Blw.SelfGuardCount > 0 && !BlwPidIsProtected(actorPid) &&
                    BlwFileIsSelfGuarded(ctx) && !BlwFileIsUninstallerData(ctx)) {
                    deny = TRUE;
                }
                if (!deny && g_Blw.FileHardCount > 0 && BlwFileIsHardBlocked(ctx)) {
                    deny = TRUE;
                }
                // 受保护路径对本产品进程豁免,与源名判定一致。
                if (!deny && replaceIfExists && g_Blw.ProtectedPathCount > 0 &&
                    BlwPathIsProtected(ctx) && !BlwProtectedPathActorAllowed(actorPid)) {
                    deny = TRUE;
                }
                if (!deny && g_Blw.GuardDirCount > 0 &&
                    BlwGuardDirDenies(ctx, actorPid, &destInfo->Name, BlwEventFileRename)) {
                    deny = TRUE;
                    guardDeny = TRUE;
                }

                if (deny) {
                    if (!guardDeny) {
                        BlwReportFileBlock(BlwEventFileRename, &destInfo->Name);
                    }
                    FltReleaseFileNameInformation(destInfo);
                    BlwFreeMatchCtx(ctx);
                    FltReleaseFileNameInformation(nameInfo);
                    Data->IoStatus.Status = STATUS_ACCESS_DENIED;
                    Data->IoStatus.Information = 0;
                    return FLT_PREOP_COMPLETE;
                }

                FltReleaseFileNameInformation(destInfo);
            }
        }
    }

    BlwFreeMatchCtx(ctx);

    if (isLink) {
        FltReleaseFileNameInformation(nameInfo);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    BlwReportFileTelemetry(eventType, &nameInfo->Name);

    if (eventType == BlwEventFileRename && g_Blw.Active && g_Blw.FileTelemetryEnabled != 0 &&
        KeGetCurrentIrql() == PASSIVE_LEVEL) {

        PFILE_RENAME_INFORMATION ren =
            (PFILE_RENAME_INFORMATION)Data->Iopb->Parameters.SetFileInformation.InfoBuffer;

        if (ren != NULL && ren->FileNameLength > 0) {
            PFLT_FILE_NAME_INFORMATION destInfo = NULL;

            status = FltGetDestinationFileNameInformation(
                FltObjects->Instance,
                FltObjects->FileObject,
                ren->RootDirectory,
                ren->FileName,
                ren->FileNameLength,
                FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,
                &destInfo);

            if (NT_SUCCESS(status) && destInfo != NULL) {
                BlwReportFileTelemetry(BlwEventFileRename, &destInfo->Name);
                FltReleaseFileNameInformation(destInfo);
            }
        }
    }

    FltReleaseFileNameInformation(nameInfo);
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

// 无锁,任意 IRQL 可调用。FileObjectKey 只做相等比较,不能解引用(可能已释放),比错只影响一条遥测。
static BOOLEAN
BlwWriteSampleShouldReport(_In_ ULONG Pid, _In_opt_ PVOID FileObjectKey)
{
    const ULONG slot = (Pid >> 2) & BLW_WRITE_SLOT_MASK;
    const LONG64 key = (LONG64)(ULONG_PTR)FileObjectKey;
    LONG n;

    if (key != 0) {
        if (InterlockedExchange64(&g_Blw.WriteSeenFile[slot], key) == key) {
            return FALSE;
        }
    }

    // 计数从 1 开始,每个槽的第一次首块写必定上报。用无符号位与取模:LONG 计数溢出成负数后,
    // 有符号 % 永远不等于 1,该槽会永久停报。采样率必须是 2 的幂(见下方 C_ASSERT)。
    n = InterlockedIncrement(&g_Blw.WriteSampleSlots[slot]);
    return ((((ULONG)n) & (BLW_WRITE_SAMPLE_RATE - 1)) == 1);
}
C_ASSERT((BLW_WRITE_SAMPLE_RATE & (BLW_WRITE_SAMPLE_RATE - 1)) == 0);

// U 盘、SD 卡的卷头由格式化 / 制作启动盘工具正当改写,引导区防护只管固定磁盘。
// 取不到磁盘设备对象时按固定磁盘处理(保持拦截)。
static BOOLEAN
BlwVolumeIsRemovable(_In_opt_ PFLT_VOLUME Volume)
{
    PDEVICE_OBJECT disk = NULL;
    BOOLEAN removable;

    if (Volume == NULL || KeGetCurrentIrql() > APC_LEVEL) {
        return FALSE;
    }
    if (!NT_SUCCESS(FltGetDiskDeviceObject(Volume, &disk)) || disk == NULL) {
        return FALSE;
    }
    removable = FlagOn(disk->Characteristics, FILE_REMOVABLE_MEDIA) ? TRUE : FALSE;
    ObDereferenceObject(disk);
    return removable;
}

FLT_PREOP_CALLBACK_STATUS
BlwPreWrite(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext)
{
    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    NTSTATUS status;
    LARGE_INTEGER byteOffset;
    ULONG actorPid;

    *CompletionContext = NULL;

    actorPid = HandleToULong(PsGetCurrentProcessId());

    if (g_Blw.BannedPidCount > 0 && Data->RequestorMode != KernelMode &&
        BlwPidIsBanned(actorPid)) {
        Data->IoStatus.Status = STATUS_ACCESS_DENIED;
        Data->IoStatus.Information = 0;
        return FLT_PREOP_COMPLETE;
    }

    // 0) 引导区硬拦:用户态、非分页 I/O、FO_VOLUME_OPEN 的写落在卷头 BLW_BOOT_GUARD_BYTES 内则拒绝。
    //    必须排在遥测开关和 Active 判断之前,服务未连接时也要生效。内核态和分页写放行,否则会死锁或蓝屏。
    //    负偏移是 FILE_WRITE_TO_END_OF_FILE 之类的特殊标记,按不在引导区处理。
    //    可移动介质放行,见 BlwVolumeIsRemovable。
    if (g_Blw.BootGuardEnabled != 0 &&
        Data->RequestorMode != KernelMode &&
        !FlagOn(Data->Iopb->IrpFlags, IRP_PAGING_IO) &&
        FltObjects->FileObject != NULL &&
        FlagOn(FltObjects->FileObject->Flags, FO_VOLUME_OPEN)) {

        const LARGE_INTEGER bootOff = Data->Iopb->Parameters.Write.ByteOffset;

        if (bootOff.QuadPart >= 0 && (ULONG64)bootOff.QuadPart < BLW_BOOT_GUARD_BYTES &&
            !BlwPidIsProtected(HandleToULong(PsGetCurrentProcessId())) &&
            !BlwVolumeIsRemovable(FltObjects->Volume)) {
            Data->IoStatus.Status = STATUS_ACCESS_DENIED;
            Data->IoStatus.Information = 0;
            BlwReportBootBlock(FltObjects->Volume,
                               (ULONG)((ULONG64)bootOff.QuadPart / 1024ULL) + 1);
            KdPrint(("[Bulwark] BootGuard: denied raw volume write at offset %lld by pid %u\n",
                     bootOff.QuadPart, HandleToULong(PsGetCurrentProcessId())));
            return FLT_PREOP_COMPLETE;
        }
    }

    // 1) 遥测未开启立即放行。volatile LONG 直接读,不要用 Interlocked 读(每个写 IRP 都会多一次带锁 cmpxchg)。
    if (g_Blw.FileTelemetryEnabled == 0) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }
    if (!g_Blw.Active) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }
    // 2) 内核态发起的写不关注(分页写/系统缓存回写等),避免噪声与重入。
    if (Data->RequestorMode == KernelMode) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }
    if (FlagOn(Data->Iopb->IrpFlags, IRP_PAGING_IO)) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }
    byteOffset = Data->Iopb->Parameters.Write.ByteOffset;
    if (byteOffset.QuadPart != 0) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    if (!BlwWriteSampleShouldReport(HandleToULong(PsGetCurrentProcessId()),
                                    Data->Iopb->TargetFileObject)) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    status = FltGetFileNameInformation(
        Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &nameInfo);
    if (!NT_SUCCESS(status)) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }
    FltParseFileNameInformation(nameInfo);

    BlwReportFileTelemetry(BlwEventFileRename, &nameInfo->Name);

    FltReleaseFileNameInformation(nameInfo);
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}
