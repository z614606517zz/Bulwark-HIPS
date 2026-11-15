#include "Driver.h"

#ifndef IO_IGNORE_SHARE_ACCESS_CHECK
#define IO_IGNORE_SHARE_ACCESS_CHECK 0x0800
#endif
#ifndef FILE_DISPOSITION_DELETE
#define FILE_DISPOSITION_DELETE 0x00000001
#endif
#ifndef FILE_DISPOSITION_POSIX_SEMANTICS
#define FILE_DISPOSITION_POSIX_SEMANTICS 0x00000002
#endif
#ifndef FILE_DISPOSITION_IGNORE_READONLY_ATTRIBUTE
#define FILE_DISPOSITION_IGNORE_READONLY_ATTRIBUTE 0x00000010
#endif

static NTSTATUS
BlwBuildNtPath(_In_ PCWSTR InPath, _Out_writes_(OutChars) PWCHAR OutBuf, _In_ USHORT OutChars)
{
    UNICODE_STRING in;

    RtlInitUnicodeString(&in, InPath);
    if (in.Length == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    if (InPath[0] == L'\\') {
        USHORT chars = (USHORT)(in.Length / sizeof(WCHAR));
        if ((ULONG)chars + 1 > OutChars) {
            return STATUS_BUFFER_TOO_SMALL;
        }
        RtlCopyMemory(OutBuf, InPath, in.Length);
        OutBuf[chars] = L'\0';
        return STATUS_SUCCESS;
    }

    {
        static const WCHAR pfx[] = { L'\\', L'?', L'?', L'\\' };
        USHORT chars = (USHORT)(in.Length / sizeof(WCHAR));
        USHORT need = (USHORT)(4 + chars);
        if ((ULONG)need + 1 > OutChars) {
            return STATUS_BUFFER_TOO_SMALL;
        }
        RtlCopyMemory(OutBuf, pfx, sizeof(pfx));
        RtlCopyMemory(OutBuf + 4, InPath, in.Length);
        OutBuf[need] = L'\0';
        return STATUS_SUCCESS;
    }
}

static BOOLEAN
BlwCleanupMatchesSelfLists(_In_ PCUNICODE_STRING Target)
{
    PBLW_MATCH_CTX ctx;
    BOOLEAN hit;

    if (Target == NULL || Target->Length == 0) {
        return TRUE;
    }

    ctx = BlwAllocMatchCtx();
    if (ctx == NULL) {
        return TRUE;
    }
    BlwPrepareMatch(ctx, Target);

    hit = (g_Blw.SelfGuardCount > 0 && BlwFileIsSelfGuarded(ctx)) ||
          (g_Blw.FileHardCount > 0 && BlwFileIsHardBlocked(ctx));
    BlwFreeMatchCtx(ctx);
    return hit;
}

static BOOLEAN
BlwCleanupTargetIsProtected(_In_ PCWSTR Path)
{
    UNICODE_STRING us;

    RtlInitUnicodeString(&us, Path);
    if (us.Length == 0) {
        return TRUE;
    }
    return BlwCleanupMatchesSelfLists(&us);
}

static BOOLEAN
BlwCleanupHandleIsProtected(_In_ HANDLE FileHandle)
{
    const ULONG cbInfo = (ULONG)(sizeof(FILE_NAME_INFORMATION) + BLW_MAX_PATH * sizeof(WCHAR));
    PFILE_NAME_INFORMATION info;
    IO_STATUS_BLOCK iosb;
    UNICODE_STRING name;
    NTSTATUS status;
    BOOLEAN protectedTarget = TRUE;
    ULONG chars;

    info = (PFILE_NAME_INFORMATION)BlwAllocPool(PagedPool, cbInfo, BLW_TAG);
    if (info == NULL) {
        return TRUE;
    }

    RtlZeroMemory(&iosb, sizeof(iosb));
    status = ZwQueryInformationFile(FileHandle, &iosb, info, cbInfo, FileNameInformation);

    // STATUS_BUFFER_OVERFLOW:名字被截断,但前缀有效,足以判定目录部分。
    if (NT_SUCCESS(status) || status == STATUS_BUFFER_OVERFLOW) {
        chars = info->FileNameLength / sizeof(WCHAR);
        if (chars > BLW_MAX_PATH) {
            chars = BLW_MAX_PATH;
        }
        if (chars > 0) {
            name.Buffer = info->FileName;
            name.Length = (USHORT)(chars * sizeof(WCHAR));
            name.MaximumLength = name.Length;
            protectedTarget = BlwCleanupMatchesSelfLists(&name);
        }
    } else {
        KdPrint(("[Bulwark] Cleanup: FileNameInformation query failed 0x%x, refusing delete.\n",
                 status));
    }

    ExFreePoolWithTag(info, BLW_TAG);
    return protectedTarget;
}

static NTSTATUS
BlwCleanupOpen(_In_ PCWSTR Path, _In_ ACCESS_MASK Access, _In_ ULONG CreateOptions, _Out_ PHANDLE Handle)
{
    WCHAR ntBuf[BLW_MAX_PATH + 8];
    UNICODE_STRING ntPath;
    OBJECT_ATTRIBUTES oa;
    IO_STATUS_BLOCK iosb;
    NTSTATUS status;

    *Handle = NULL;
    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return STATUS_INVALID_DEVICE_STATE;
    }

    status = BlwBuildNtPath(Path, ntBuf, (USHORT)RTL_NUMBER_OF(ntBuf));
    if (!NT_SUCCESS(status)) {
        return status;
    }
    RtlInitUnicodeString(&ntPath, ntBuf);
    InitializeObjectAttributes(&oa, &ntPath, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);
    RtlZeroMemory(&iosb, sizeof(iosb));

    status = IoCreateFileEx(
        Handle,
        Access,
        &oa,
        &iosb,
        NULL,
        FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        FILE_OPEN,                                                  // 只打开既有文件,绝不创建
        CreateOptions,
        NULL, 0,
        CreateFileTypeNone,
        NULL,
        IO_IGNORE_SHARE_ACCESS_CHECK | IO_NO_PARAMETER_CHECKING | IO_FORCE_ACCESS_CHECK,
        NULL);
    return status;
}

NTSTATUS
BlwCleanupReadFile(_In_ PCWSTR Path, _In_ ULONG64 Offset,
                   _Out_writes_bytes_(BufLen) PVOID Buffer, _In_ ULONG BufLen, _Out_ PULONG BytesRead)
{
    HANDLE h = NULL;
    IO_STATUS_BLOCK iosb;
    LARGE_INTEGER off;
    NTSTATUS status;

    *BytesRead = 0;
    if (Buffer == NULL || BufLen == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    status = BlwCleanupOpen(Path, FILE_READ_DATA | SYNCHRONIZE,
        FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT | FILE_OPEN_REPARSE_POINT, &h);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    RtlZeroMemory(&iosb, sizeof(iosb));
    off.QuadPart = (LONGLONG)Offset;
    status = ZwReadFile(h, NULL, NULL, NULL, &iosb, Buffer, BufLen, &off, NULL);
    if (status == STATUS_END_OF_FILE) {
        status = STATUS_SUCCESS;
        iosb.Information = 0;
    }
    if (NT_SUCCESS(status)) {
        *BytesRead = (ULONG)iosb.Information;
    }
    ZwClose(h);
    return status;
}

NTSTATUS
BlwCleanupForceDelete(_In_ PCWSTR Path)
{
    HANDLE h = NULL;
    IO_STATUS_BLOCK iosb;
    NTSTATUS status;
    FILE_DISPOSITION_INFORMATION_EX dispEx;
    FILE_DISPOSITION_INFORMATION disp;

    if (BlwCleanupTargetIsProtected(Path)) {
        KdPrint(("[Bulwark] Force-delete refused by path pre-check (self/hard-block): %ws\n", Path));
        return STATUS_ACCESS_DENIED;
    }

    status = BlwCleanupOpen(Path, DELETE | SYNCHRONIZE,
        FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT | FILE_OPEN_REPARSE_POINT, &h);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    if (BlwCleanupHandleIsProtected(h)) {
        KdPrint(("[Bulwark] Force-delete refused by normalized-name check (self/hard-block): %ws\n", Path));
        ZwClose(h);
        return STATUS_ACCESS_DENIED;
    }

    RtlZeroMemory(&iosb, sizeof(iosb));
    RtlZeroMemory(&dispEx, sizeof(dispEx));
    dispEx.Flags = FILE_DISPOSITION_DELETE | FILE_DISPOSITION_POSIX_SEMANTICS
                 | FILE_DISPOSITION_IGNORE_READONLY_ATTRIBUTE;
    status = ZwSetInformationFile(h, &iosb, &dispEx, sizeof(dispEx), FileDispositionInformationEx);
    if (!NT_SUCCESS(status)) {
        RtlZeroMemory(&iosb, sizeof(iosb));
        disp.DeleteFile = TRUE;
        status = ZwSetInformationFile(h, &iosb, &disp, sizeof(disp), FileDispositionInformation);
    }

    ZwClose(h);
    return status;
}
