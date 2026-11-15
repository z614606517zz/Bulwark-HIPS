#include "bulwark/service/SystemBoost.h"
#include "bulwark/service/monitoring/ProcessInspector.h"

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>

#include <algorithm>
#include <chrono>
#include <thread>

namespace bulwark::service {

namespace {

void readMemory(qint64& totalPhys, qint64& inUse, int& loadPercent)
{
    MEMORYSTATUSEX ms{};
    ms.dwLength = sizeof(ms);
    if (GlobalMemoryStatusEx(&ms)) {
        totalPhys = static_cast<qint64>(ms.ullTotalPhys);
        inUse = static_cast<qint64>(ms.ullTotalPhys - ms.ullAvailPhys);
        loadPercent = static_cast<int>(ms.dwMemoryLoad);
    }
}

}

SystemBoostReport SystemBoost::run(const std::function<bool(int)>& shouldSkip)
{
    monitoring::ProcessInspector::ensureDebugPrivilege();

    SystemBoostReport r;
    readMemory(r.totalPhysical, r.inUseBefore, r.loadBefore);

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32W pe{};
        pe.dwSize = sizeof(pe);
        if (Process32FirstW(snap, &pe)) {
            do {
                const int pid = static_cast<int>(pe.th32ProcessID);
                if (pid <= 4)
                    continue;
                ++r.processesTotal;
                if (shouldSkip && shouldSkip(pid))
                    continue;
                HANDLE h = OpenProcess(PROCESS_SET_QUOTA | PROCESS_QUERY_INFORMATION, FALSE,
                                       static_cast<DWORD>(pid));
                if (!h)
                    continue;
                if (EmptyWorkingSet(h))
                    ++r.processesTrimmed;
                CloseHandle(h);
            } while (Process32NextW(snap, &pe));
        }
        CloseHandle(snap);
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(600));

    readMemory(r.totalPhysical, r.inUseAfter, r.loadAfter);
    r.freedBytes = std::max<qint64>(0, r.inUseBefore - r.inUseAfter);
    return r;
}

}
