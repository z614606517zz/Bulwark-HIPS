#include "PipeClient.h"

namespace blw {
namespace {

constexpr DWORD     kTotalBudgetMs = 1200;
constexpr DWORD     kWaitPipeMs    = 200;

constexpr LONG      kFailuresToOpen = 3;
constexpr ULONGLONG kOpenForMs      = 60 * 1000;

volatile LONG   g_failures    = 0;
volatile LONG64 g_breakerTill = 0;

bool breakerIsOpen() {
    const LONG64 till = InterlockedCompareExchange64(&g_breakerTill, 0, 0);
    if (till == 0)
        return false;
    if (static_cast<LONG64>(::GetTickCount64()) >= till) {
        ::InterlockedCompareExchange64(&g_breakerTill, 0, till);
        ::InterlockedExchange(&g_failures, 0);
        return false;
    }
    return true;
}

void noteFailure() {
    if (::InterlockedIncrement(&g_failures) >= kFailuresToOpen) {
        const LONG64 prev = ::InterlockedExchange64(
            &g_breakerTill, static_cast<LONG64>(::GetTickCount64() + kOpenForMs));
        if (prev == 0)
            ::OutputDebugStringW(L"[BulwarkAmsi] 服务连续不可达,AMSI 熔断 60 秒,期间脚本不经扫描放行\n");
    }
}

void noteSuccess() {
    ::InterlockedExchange(&g_failures, 0);
    ::InterlockedExchange64(&g_breakerTill, 0);
}

bool awaitIo(HANDLE pipe, OVERLAPPED& ov, BOOL started,
             DWORD* transferred, ULONGLONG deadline) {
    if (!started && ::GetLastError() != ERROR_IO_PENDING)
        return false;

    const ULONGLONG now = ::GetTickCount64();
    const DWORD waitMs = (now >= deadline) ? 0 : static_cast<DWORD>(deadline - now);

    if (::WaitForSingleObject(ov.hEvent, waitMs) != WAIT_OBJECT_0) {
        ::CancelIoEx(pipe, &ov);
        DWORD discarded = 0;
        ::GetOverlappedResult(pipe, &ov, &discarded, TRUE);
        return false;
    }
    return ::GetOverlappedResult(pipe, &ov, transferred, FALSE) != FALSE;
}

bool writeAll(HANDLE pipe, HANDLE evt, const void* buf, DWORD len, ULONGLONG deadline) {
    const unsigned char* p = static_cast<const unsigned char*>(buf);
    DWORD done = 0;
    while (done < len) {
        ::ResetEvent(evt);
        OVERLAPPED ov = {};
        ov.hEvent = evt;
        DWORD n = 0;
        const BOOL started = ::WriteFile(pipe, p + done, len - done, &n, &ov);
        if (!awaitIo(pipe, ov, started, &n, deadline) || n == 0)
            return false;
        done += n;
    }
    return true;
}

bool readAll(HANDLE pipe, HANDLE evt, void* buf, DWORD len, ULONGLONG deadline) {
    unsigned char* p = static_cast<unsigned char*>(buf);
    DWORD done = 0;
    while (done < len) {
        ::ResetEvent(evt);
        OVERLAPPED ov = {};
        ov.hEvent = evt;
        DWORD n = 0;
        const BOOL started = ::ReadFile(pipe, p + done, len - done, &n, &ov);
        if (!awaitIo(pipe, ov, started, &n, deadline) || n == 0)
            return false;
        done += n;
    }
    return true;
}

// *unavailable 只在服务确实不在(管道不存在、打不开、对端不是会话 0 的服务)时置真。管道忙不算:
// 管道是所有人都能连的,别的进程占满实例就能让这里连不上,不能因此熔断。
HANDLE connectPipe(ULONGLONG deadline, bool* unavailable) {
    *unavailable = false;
    const DWORD access = FILE_READ_DATA | FILE_WRITE_DATA | FILE_READ_ATTRIBUTES | SYNCHRONIZE;
    for (int attempt = 0; attempt < 2; ++attempt) {
        HANDLE h = ::CreateFileW(BLW_AMSI_PIPE_NAME, access,
                                 0, nullptr, OPEN_EXISTING,
                                 FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION,
                                 nullptr);
        if (h != INVALID_HANDLE_VALUE) {
            ULONG serverPid = 0;
            DWORD serverSession = 1;
            if (!::GetNamedPipeServerProcessId(h, &serverPid) || serverPid == 0 ||
                !::ProcessIdToSessionId(serverPid, &serverSession) || serverSession != 0) {
                ::CloseHandle(h);
                *unavailable = true;
                return INVALID_HANDLE_VALUE;
            }
            return h;
        }
        if (::GetLastError() != ERROR_PIPE_BUSY) {
            *unavailable = true;
            return INVALID_HANDLE_VALUE;
        }
        if (::GetTickCount64() >= deadline)
            return INVALID_HANDLE_VALUE;
        if (!::WaitNamedPipeW(BLW_AMSI_PIPE_NAME, kWaitPipeMs)) {
            if (::GetLastError() == ERROR_FILE_NOT_FOUND)
                *unavailable = true;
            return INVALID_HANDLE_VALUE;
        }
    }
    return INVALID_HANDLE_VALUE;
}

DWORD wcharBytes(const wchar_t* s, DWORD cap) {
    if (s == nullptr)
        return 0;
    DWORD n = 0;
    while (s[n] != L'\0' && (n + 1) * sizeof(wchar_t) <= cap)
        ++n;
    return n * static_cast<DWORD>(sizeof(wchar_t));
}

}

bool breakerOpen() { return breakerIsOpen(); }

AskResult askService(BLW_AMSI_REQUEST& head,
                     const wchar_t* appName,
                     const wchar_t* contentName,
                     const unsigned char* content,
                     wchar_t* reasonOut,
                     DWORD reasonChars) {
    if (reasonOut != nullptr && reasonChars > 0)
        reasonOut[0] = L'\0';

    if (breakerIsOpen())
        return AskResult::Allow;

    const ULONGLONG deadline = ::GetTickCount64() + kTotalBudgetMs;

    head.magic      = BLW_AMSI_MAGIC;
    head.version    = BLW_AMSI_VERSION;
    head.structSize = static_cast<uint32_t>(sizeof(BLW_AMSI_REQUEST));
    head.appNameBytes     = wcharBytes(appName, BLW_AMSI_MAX_NAME);
    head.contentNameBytes = wcharBytes(contentName, BLW_AMSI_MAX_NAME);
    if (content == nullptr)
        head.contentBytes = 0;
    if (head.contentBytes > BLW_AMSI_MAX_CONTENT)
        head.contentBytes = BLW_AMSI_MAX_CONTENT;

    bool unavailable = false;
    HANDLE pipe = connectPipe(deadline, &unavailable);
    if (pipe == INVALID_HANDLE_VALUE) {
        if (unavailable)
            noteFailure();
        return AskResult::Allow;
    }

    HANDLE evt = ::CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (evt == nullptr) {
        ::CloseHandle(pipe);
        return AskResult::Allow;
    }

    AskResult result = AskResult::Allow;
    bool ok = writeAll(pipe, evt, &head, static_cast<DWORD>(sizeof(head)), deadline);
    if (ok && head.appNameBytes > 0)
        ok = writeAll(pipe, evt, appName, head.appNameBytes, deadline);
    if (ok && head.contentNameBytes > 0)
        ok = writeAll(pipe, evt, contentName, head.contentNameBytes, deadline);
    if (ok && head.contentBytes > 0)
        ok = writeAll(pipe, evt, content, head.contentBytes, deadline);

    if (ok) {
        BLW_AMSI_REPLY reply = {};
        ok = readAll(pipe, evt, &reply, static_cast<DWORD>(sizeof(reply)), deadline);
        if (ok && reply.magic == BLW_AMSI_MAGIC
                && reply.version == BLW_AMSI_VERSION
                && reply.structSize == sizeof(BLW_AMSI_REPLY)) {
            if (reply.verdict == BLW_AMSI_VERDICT_BLOCK)
                result = AskResult::Blocked;

            if (reply.reasonBytes > 0 && reply.reasonBytes <= BLW_AMSI_MAX_REASON) {
                wchar_t buf[BLW_AMSI_MAX_REASON / sizeof(wchar_t)] = {};
                if (readAll(pipe, evt, buf, reply.reasonBytes, deadline)
                    && reasonOut != nullptr && reasonChars > 0) {
                    const DWORD chars = reply.reasonBytes / sizeof(wchar_t);
                    const DWORD copy = (chars < reasonChars - 1) ? chars : reasonChars - 1;
                    for (DWORD i = 0; i < copy; ++i)
                        reasonOut[i] = buf[i];
                    reasonOut[copy] = L'\0';
                }
            }
            noteSuccess();
        }
    }

    // 连上之后的失败(超时、断开、畸形回复)只放行这一次,不计入熔断:服务端对每个连上的请求都会
    // 回复,这类失败要么是服务端故障,要么是有人在挤占管道,都不该换来整个进程 60 秒免检。
    ::CloseHandle(evt);
    ::CloseHandle(pipe);
    return result;
}

}
