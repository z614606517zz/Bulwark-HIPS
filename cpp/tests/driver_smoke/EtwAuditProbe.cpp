// 核对 Microsoft-Windows-Kernel-Audit-API-Calls 的 TerminateProcess(事件 2)能否按服务里的方式启用
// (只订阅事件 2,启用时按事件 ID 过滤),以及载荷字段名与类型。服务的「结束进程」事件全靠它。
// 开一个临时会话,自己拉起再结束一个子进程,观察几秒后退出;看到那次结束即返回 0。需要管理员权限。
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <krabs.hpp>

#include <atomic>
#include <cstdio>
#include <thread>

int wmain()
{
    krabs::user_trace trace(L"Bulwark-ETW-AuditProbe");
    krabs::provider<> prov(krabs::guid(L"{E02A841C-75A3-4FA7-AFC8-AE09CF9B7F23}"));
    prov.any(0xFFFFFFFFFFFFFFFFULL);
    krabs::event_filter filter(static_cast<unsigned short>(2));
    std::atomic<int> count{ 0 };
    std::atomic<DWORD> childPid{ 0 };
    std::atomic<bool> sawChild{ false };
    filter.add_on_event_callback([&](const EVENT_RECORD& r, const krabs::trace_context& ctx) {
        try {
            krabs::schema s(r, ctx.schema_locator);
            krabs::parser p(s);
            if (count++ == 0) {
                wprintf(L"schema:");
                for (krabs::property& prop : p.properties())
                    wprintf(L" [%s intype=%u]", prop.name().c_str(), static_cast<unsigned>(prop.type()));
                wprintf(L"\n");
            }
            // 与服务的解析一致:两个字段都是 UInt32,krabs 的 try_parse 类型对不上会直接抛异常。
            uint32_t target = 0;
            uint32_t rc = 0;
            const bool gotTarget = p.try_parse(L"TargetProcessId", target);
            const bool gotRc = p.try_parse(L"ReturnCode", rc);
            if (gotTarget && target == childPid.load()) {
                sawChild = true;
                wprintf(L"caller=%lu target=%u rc=0x%X%s\n", r.EventHeader.ProcessId, target, rc,
                        gotRc ? L"" : L"(none)");
            }
        } catch (const std::exception& ex) {
            std::printf("callback exception: %s\n", ex.what());
        }
    });
    prov.add_filter(filter);
    trace.enable(prov);

    std::thread worker([&] {
        try {
            trace.start();
        } catch (const std::exception& ex) {
            std::printf("trace.start failed: %s\n", ex.what());
        }
    });
    Sleep(2000);

    STARTUPINFOW si{};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};
    wchar_t cmd[] = L"ping.exe -n 30 127.0.0.1";
    if (CreateProcessW(nullptr, cmd, nullptr, nullptr, FALSE, CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi)) {
        childPid = pi.dwProcessId;
        Sleep(500);
        TerminateProcess(pi.hProcess, 1);
        WaitForSingleObject(pi.hProcess, 5000);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
    }
    Sleep(4000);
    try {
        trace.stop();
    } catch (...) {
    }
    worker.join();
    std::printf("events: %d, child termination observed: %s\n", count.load(), sawChild ? "yes" : "no");
    return sawChild ? 0 : 1;
}
