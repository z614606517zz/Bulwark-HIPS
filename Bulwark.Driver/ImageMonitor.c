#include "Driver.h"

static BOOLEAN g_ImageCallbackRegistered = FALSE;

static BOOLEAN
BlwWideContains(_In_ PCWSTR Str, _In_ USHORT StrChars, _In_ PCWSTR Sub)
{
    UNICODE_STRING usStr, usSub;

    if (Str == NULL || Sub == NULL || StrChars == 0) {
        return FALSE;
    }

    usStr.Buffer = (PWSTR)Str;
    usStr.Length = StrChars * sizeof(WCHAR);
    usStr.MaximumLength = usStr.Length;

    RtlInitUnicodeString(&usSub, Sub);
    if (usSub.Length == 0 || usSub.Length > usStr.Length) {
        return FALSE;
    }

    {
        USHORT strChars = usStr.Length / sizeof(WCHAR);
        USHORT subChars = usSub.Length / sizeof(WCHAR);
        USHORT limit = strChars - subChars;
        USHORT s;

        for (s = 0; s <= limit; s++) {
            UNICODE_STRING window;
            window.Buffer = &usStr.Buffer[s];
            window.Length = usSub.Length;
            window.MaximumLength = usSub.Length;
            if (RtlCompareUnicodeString(&window, &usSub, TRUE) == 0) {
                return TRUE;
            }
        }
    }
    return FALSE;
}

static BOOLEAN
BlwPathIsUserWritable(_In_ PCWSTR Path, _In_ USHORT Chars)
{
    return BlwWideContains(Path, Chars, L"\\Temp\\")
        || BlwWideContains(Path, Chars, L"\\Users\\Public\\")
        || BlwWideContains(Path, Chars, L"\\ProgramData\\")
        || BlwWideContains(Path, Chars, L"\\AppData\\")
        || BlwWideContains(Path, Chars, L"\\Downloads\\")
        || BlwWideContains(Path, Chars, L"\\Desktop\\");
}

static VOID
BlwLoadImageNotify(
    _In_opt_ PUNICODE_STRING FullImageName,
    _In_ HANDLE ProcessId,
    _In_ PIMAGE_INFO ImageInfo)
{
    USHORT chars;
    BOOLEAN isKernelModule;
    BOOLEAN report = FALSE;

    if (!g_Blw.Active) {
        return;
    }
    if (FullImageName == NULL || FullImageName->Buffer == NULL || FullImageName->Length == 0) {
        return;
    }
    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return;
    }

    chars = (USHORT)(FullImageName->Length / sizeof(WCHAR));

    isKernelModule = (ProcessId == NULL) || (ImageInfo != NULL && ImageInfo->SystemModeImage);

    if (isKernelModule) {
        // 开机后的驱动加载本来就少,全部上报:BYOVD 常把易受攻击驱动先放进 System32\drivers
        // 再建服务加载,只看可写目录会漏掉。
        report = TRUE;
    } else if (BlwPathIsUserWritable(FullImageName->Buffer, chars)) {
        report = TRUE;
    } else {
        PEPROCESS host = NULL;
        PUNICODE_STRING hostName = NULL;
        // The target PID need not be the process currently executing this callback.
        if (NT_SUCCESS(PsLookupProcessByProcessId(ProcessId, &host)) && host != NULL) {
            if (NT_SUCCESS(SeLocateProcessImageName(host, &hostName)) && hostName != NULL) {
                report = BlwIsInjectionTelemetryTarget(hostName->Buffer,
                    (USHORT)(hostName->Length / sizeof(WCHAR)));
                ExFreePool(hostName);
            }
            ObDereferenceObject(host);
        }
    }

    if (!report) {
        return;
    }

    BlwReportEvent(BlwEventImageLoad,
                   isKernelModule ? 0 : HandleToULong(ProcessId), 0,
                   FullImageName, NULL, 0, 0);
}

NTSTATUS
BlwRegisterImageCallback(void)
{
    NTSTATUS status;

    if (g_ImageCallbackRegistered) {
        return STATUS_SUCCESS;
    }

    status = PsSetLoadImageNotifyRoutine(BlwLoadImageNotify);
    if (NT_SUCCESS(status)) {
        g_ImageCallbackRegistered = TRUE;
        KdPrint(("[Bulwark] Image-load callback registered.\n"));
    } else {
        KdPrint(("[Bulwark] PsSetLoadImageNotifyRoutine failed 0x%x\n", status));
    }
    return status;
}

void
BlwUnregisterImageCallback(void)
{
    if (g_ImageCallbackRegistered) {
        PsRemoveLoadImageNotifyRoutine(BlwLoadImageNotify);
        g_ImageCallbackRegistered = FALSE;
        KdPrint(("[Bulwark] Image-load callback unregistered.\n"));
    }
}
