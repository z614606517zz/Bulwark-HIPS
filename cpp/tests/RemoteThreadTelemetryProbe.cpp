#include <windows.h>

#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <string>

namespace {

void writeLine(const wchar_t* path, const std::string& line, bool append = false)
{
    std::ofstream out(path, std::ios::binary | (append ? std::ios::app : std::ios::trunc));
    out << line << '\n';
}

bool auditContainsRemoteThreadFor(DWORD actorPid)
{
    char* programData = nullptr;
    size_t programDataLength = 0;
    if (_dupenv_s(&programData, &programDataLength, "ProgramData") != 0 || programData == nullptr)
        return false;
    const std::filesystem::path auditDir = std::filesystem::path(programData) / "Bulwark" / "audit";
    std::free(programData);
    std::error_code ec;
    if (!std::filesystem::is_directory(auditDir, ec))
        return false;

    const std::string actor = "\"actorPid\":" + std::to_string(actorPid);
    for (const auto& entry : std::filesystem::directory_iterator(auditDir, ec)) {
        if (ec || !entry.is_regular_file(ec))
            continue;
        const std::string name = entry.path().filename().string();
        if (name.rfind("audit-", 0) != 0 || entry.path().extension() != ".jsonl")
            continue;
        std::ifstream in(entry.path(), std::ios::binary);
        std::string line;
        while (std::getline(in, line)) {
            if (line.find("\"type\":\"RemoteThread\"") != std::string::npos &&
                line.find(actor) != std::string::npos)
                return true;
        }
    }
    return false;
}

}

int wmain(int argc, wchar_t* argv[])
{
    if (argc == 2 && std::wstring(argv[1]) == L"--target") {
        ::Sleep(10000);
        return 0;
    }
    if (argc != 2)
        return 2;

    const wchar_t* resultPath = argv[1];
    wchar_t selfPath[MAX_PATH]{};
    if (::GetModuleFileNameW(nullptr, selfPath, MAX_PATH) == 0)
        return 3;

    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    startup.dwFlags = STARTF_USESHOWWINDOW;
    startup.wShowWindow = SW_HIDE;
    PROCESS_INFORMATION target{};
    std::wstring command = L"\"" + std::wstring(selfPath) + L"\" --target";
    if (!::CreateProcessW(nullptr, command.data(), nullptr, nullptr, FALSE,
                          CREATE_NEW_PROCESS_GROUP, nullptr, nullptr, &startup, &target)) {
        writeLine(resultPath, "CREATE|False|" + std::to_string(::GetLastError()));
        return 4;
    }
    ::CloseHandle(target.hThread);

    ::Sleep(1200);
    writeLine(resultPath, "READY|" + std::to_string(target.dwProcessId));

    const DWORD access = PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
                         PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ;
    HANDLE process = ::OpenProcess(access, FALSE, target.dwProcessId);
    if (process == nullptr) {
        writeLine(resultPath, "THREAD|False|" + std::to_string(::GetLastError()) + "|0", true);
        ::TerminateProcess(target.hProcess, 0);
        ::CloseHandle(target.hProcess);
        return 5;
    }

    const HMODULE kernel32 = ::GetModuleHandleW(L"kernel32.dll");
    const FARPROC sleepProc = kernel32 ? ::GetProcAddress(kernel32, "Sleep") : nullptr;
    if (sleepProc == nullptr) {
        writeLine(resultPath, "THREAD|False|" + std::to_string(::GetLastError()) + "|0", true);
        ::CloseHandle(process);
        ::TerminateProcess(target.hProcess, 0);
        ::CloseHandle(target.hProcess);
        return 6;
    }

    DWORD threadId = 0;
    HANDLE thread = ::CreateRemoteThread(process, nullptr, 0,
                                         reinterpret_cast<LPTHREAD_START_ROUTINE>(sleepProc),
                                         nullptr, 0, &threadId);
    const DWORD error = ::GetLastError();
    writeLine(resultPath, std::string("THREAD|") + (thread ? "True|" : "False|") +
                              std::to_string(error) + "|" + std::to_string(threadId), true);
    if (thread)
        ::CloseHandle(thread);
    ::CloseHandle(process);

    bool auditObserved = false;
    for (int i = 0; i < 16 && !auditObserved; ++i) {
        ::Sleep(500);
        auditObserved = auditContainsRemoteThreadFor(::GetCurrentProcessId());
    }
    writeLine(resultPath, std::string("EVENT|") + (auditObserved ? "True" : "False"), true);

    ::TerminateProcess(target.hProcess, 0);
    ::CloseHandle(target.hProcess);
    return (thread && auditObserved) ? 0 : 7;
}
