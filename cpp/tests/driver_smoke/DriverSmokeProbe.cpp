// 驱动冒烟探针。需要管理员权限与真实加载的驱动,不进 CTest,由 scripts/driver-smoke.ps1 编排:
//   driver_smoke_probe setup             准备测试目录与注册表测试键(驱动加载前)
//   driver_smoke_probe baseline [ui] [pid]   无驱动时的对照,确认各条绕过本来确实存在(会真改文件,改完复原)
//   driver_smoke_probe guard [ui] [pid]      驱动已加载、测试目录在受保护名单里:各条绕过都应被拒
//   driver_smoke_probe reader                副本放在全局读者目录里运行:敏感数据应读得到
//   driver_smoke_probe cleanup               删除测试目录与注册表测试键(驱动卸载后)
// [ui] 为本产品界面的完整路径,默认 C:\Program Files\Bulwark\bulwark_ui.exe;
// [pid] 为由系统组件(编排脚本经 WMI)拉起的界面进程,用来核对运行期剥权,省略则跳过这一项。
#include <windows.h>
#include <winternl.h>
#include <tlhelp32.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

namespace {

const wchar_t* kRoot     = L"D:\\BULWARK_KTEST";
const wchar_t* kGuard    = L"D:\\BULWARK_KTEST\\GUARD";
const wchar_t* kFileA    = L"D:\\BULWARK_KTEST\\GUARD\\a.txt";
const wchar_t* kFileB    = L"D:\\BULWARK_KTEST\\GUARD\\b.txt";
// MAXIMUM_ALLOWED 绕过复测:只申请 MAXIMUM_ALLOWED(不带具体写位),实际拿到写权即能改写文件。
const wchar_t* kMaxFile  = L"D:\\BULWARK_KTEST\\GUARD\\m.txt";
// 窃密防护:SECRET 目录由脚本写进 Policy\ReadGuard,读者是本探针绝不匹配的假目录。
const wchar_t* kSecretDir  = L"D:\\BULWARK_KTEST\\SECRET";
const wchar_t* kSecret     = L"D:\\BULWARK_KTEST\\SECRET\\creds.txt";
const wchar_t* kSecretLink = L"D:\\BULWARK_KTEST_OUT\\stolen.txt";
const wchar_t* kOut      = L"D:\\BULWARK_KTEST_OUT";
const wchar_t* kOutSub   = L"D:\\BULWARK_KTEST_OUT\\sub";
const wchar_t* kLink     = L"D:\\BULWARK_KTEST_OUT\\link.txt";
const char*    kContent  = "ORIGINAL-CONTENT-0123456789";
const wchar_t* kRegTest  = L"SOFTWARE\\BulwarkKTest";
const wchar_t* kRegOwn   = L"SYSTEM\\CurrentControlSet\\Services\\Bulwark\\KTestSub";
const wchar_t* kHiveFile = L"D:\\BULWARK_KTEST_OUT\\ktest.hiv";
const wchar_t* kDefaultUi = L"C:\\Program Files\\Bulwark\\bulwark_ui.exe";

int g_fail = 0;

void report(bool ok, const char* name, const std::string& detail)
{
    std::printf("%s  %-56s %s\n", ok ? "PASS" : "FAIL", name, detail.c_str());
    if (!ok) ++g_fail;
}

std::string status(DWORD e)
{
    char buf[64];
    std::snprintf(buf, sizeof(buf), "err=%lu", e);
    return buf;
}

std::string ntstatus(LONG s)
{
    char buf[64];
    std::snprintf(buf, sizeof(buf), "ntstatus=0x%08lX", static_cast<unsigned long>(s));
    return buf;
}

bool writeFile(const wchar_t* path, const char* data)
{
    HANDLE h = CreateFileW(path, GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;
    DWORD n = 0;
    const BOOL ok = WriteFile(h, data, static_cast<DWORD>(strlen(data)), &n, nullptr);
    CloseHandle(h);
    return ok && n == strlen(data);
}

std::string readFile(const wchar_t* path)
{
    HANDLE h = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                           nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return "<open failed>";
    char buf[256] = {};
    DWORD n = 0;
    ReadFile(h, buf, sizeof(buf) - 1, &n, nullptr);
    CloseHandle(h);
    return std::string(buf, n);
}

bool fileId(const wchar_t* path, LARGE_INTEGER* id)
{
    HANDLE h = CreateFileW(path, FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                           nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;
    BY_HANDLE_FILE_INFORMATION fi{};
    const BOOL ok = GetFileInformationByHandle(h, &fi);
    CloseHandle(h);
    if (!ok) return false;
    id->HighPart = static_cast<LONG>(fi.nFileIndexHigh);
    id->LowPart = fi.nFileIndexLow;
    return true;
}

HANDLE volumeHint()
{
    return CreateFileW(kOut, FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                       nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr);
}

// Win32 的 OpenFileById 只能 OPEN,截断类用例走 NtCreateFile。
DWORD openById(const wchar_t* path, DWORD access)
{
    LARGE_INTEGER id{};
    if (!fileId(path, &id)) return 0xFFFFFFFF;
    HANDLE hint = volumeHint();
    if (hint == INVALID_HANDLE_VALUE) return 0xFFFFFFFE;
    FILE_ID_DESCRIPTOR d{};
    d.dwSize = sizeof(d);
    d.Type = FileIdType;
    d.FileId = id;
    HANDLE h = OpenFileById(hint, &d, access, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, 0);
    const DWORD e = (h == INVALID_HANDLE_VALUE) ? GetLastError() : 0;
    if (h != INVALID_HANDLE_VALUE) CloseHandle(h);
    CloseHandle(hint);
    return e;
}

using NtCreateFile_t = LONG(NTAPI*)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK, PLARGE_INTEGER,
                                    ULONG, ULONG, ULONG, ULONG, PVOID, ULONG);
using NtSetInformationFile_t = LONG(NTAPI*)(HANDLE, PIO_STATUS_BLOCK, PVOID, ULONG, ULONG);

NtCreateFile_t ntCreateFile()
{
    return reinterpret_cast<NtCreateFile_t>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtCreateFile"));
}

constexpr ULONG kFileOpen      = 0x00000001;   // FILE_OPEN
constexpr ULONG kFileOverwrite = 0x00000004;   // FILE_OVERWRITE
constexpr ULONG kSyncNonAlert  = 0x00000020;   // FILE_SYNCHRONOUS_IO_NONALERT
constexpr ULONG kNonDirectory  = 0x00000040;   // FILE_NON_DIRECTORY_FILE
constexpr ULONG kOpenById      = 0x00002000;   // FILE_OPEN_BY_FILE_ID

// 只申请读权限 + FILE_OVERWRITE:没有驱动时这样就能把文件截成 0 字节。
LONG overwriteByName(const wchar_t* path)
{
    std::wstring nt = L"\\??\\";
    nt += path;
    UNICODE_STRING us{};
    us.Buffer = nt.data();
    us.Length = static_cast<USHORT>(nt.size() * sizeof(wchar_t));
    us.MaximumLength = us.Length;
    OBJECT_ATTRIBUTES oa{};
    InitializeObjectAttributes(&oa, &us, OBJ_CASE_INSENSITIVE, nullptr, nullptr);
    IO_STATUS_BLOCK io{};
    HANDLE h = nullptr;
    const LONG s = ntCreateFile()(&h, FILE_READ_DATA | SYNCHRONIZE, &oa, &io, nullptr, FILE_ATTRIBUTE_NORMAL,
                                  FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, kFileOverwrite,
                                  kSyncNonAlert | kNonDirectory, nullptr, 0);
    if (s >= 0 && h) CloseHandle(h);
    return s;
}

LONG overwriteById(const wchar_t* path)
{
    LARGE_INTEGER id{};
    if (!fileId(path, &id)) return static_cast<LONG>(0xC0000034);
    HANDLE hint = volumeHint();
    if (hint == INVALID_HANDLE_VALUE) return static_cast<LONG>(0xC0000001);
    UNICODE_STRING us{};
    us.Buffer = reinterpret_cast<PWSTR>(&id);
    us.Length = sizeof(id);
    us.MaximumLength = sizeof(id);
    OBJECT_ATTRIBUTES oa{};
    InitializeObjectAttributes(&oa, &us, OBJ_CASE_INSENSITIVE, hint, nullptr);
    IO_STATUS_BLOCK io{};
    HANDLE h = nullptr;
    const LONG s = ntCreateFile()(&h, FILE_READ_DATA | SYNCHRONIZE, &oa, &io, nullptr, FILE_ATTRIBUTE_NORMAL,
                                  FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, kFileOverwrite,
                                  kSyncNonAlert | kNonDirectory | kOpenById, nullptr, 0);
    if (s >= 0 && h) CloseHandle(h);
    CloseHandle(hint);
    return s;
}

struct LinkInfo {
    BOOLEAN ReplaceIfExists;
    HANDLE  RootDirectory;
    ULONG   FileNameLength;
    WCHAR   FileName[1];
};

// 只拿读属性权限打开源文件,再直接发 FileLinkInformation:绕开 CreateHardLinkW 自己申请的写属性权限,
// 专测驱动对硬链接本身的把关。
LONG linkLowLevel(const wchar_t* src, const wchar_t* dst)
{
    HANDLE h = CreateFileW(src, FILE_READ_ATTRIBUTES | SYNCHRONIZE,
                           FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING, 0,
                           nullptr);
    if (h == INVALID_HANDLE_VALUE) return static_cast<LONG>(0xC0000001);
    std::wstring nt = L"\\??\\";
    nt += dst;
    const ULONG nameBytes = static_cast<ULONG>(nt.size() * sizeof(wchar_t));
    const size_t total = FIELD_OFFSET(LinkInfo, FileName) + nameBytes;
    BYTE* buf = static_cast<BYTE*>(calloc(1, total));
    if (buf == nullptr) {
        CloseHandle(h);
        return static_cast<LONG>(0xC0000017);
    }
    auto* li = reinterpret_cast<LinkInfo*>(buf);
    li->ReplaceIfExists = FALSE;
    li->RootDirectory = nullptr;
    li->FileNameLength = nameBytes;
    memcpy(li->FileName, nt.c_str(), nameBytes);
    IO_STATUS_BLOCK io{};
    auto setInfo = reinterpret_cast<NtSetInformationFile_t>(
        GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtSetInformationFile"));
    const LONG s = setInfo(h, &io, li, static_cast<ULONG>(total), 11 /* FileLinkInformation */);
    free(buf);
    CloseHandle(h);
    return s;
}

DWORD openByName(const wchar_t* path, DWORD access)
{
    HANDLE h = CreateFileW(path, access, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    const DWORD e = (h == INVALID_HANDLE_VALUE) ? GetLastError() : 0;
    if (h != INVALID_HANDLE_VALUE) CloseHandle(h);
    return e;
}

// 以 MAXIMUM_ALLOWED 打开(申请里不带任何具体写位);wroteOut 回报是否真能通过这个句柄写进去。
DWORD openMaxAllowed(const wchar_t* path, bool* wroteOut)
{
    if (wroteOut) *wroteOut = false;
    HANDLE h = CreateFileW(path, MAXIMUM_ALLOWED, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                           nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return GetLastError();
    if (wroteOut) {
        const char b = 'X';
        DWORD n = 0;
        SetFilePointer(h, 0, nullptr, FILE_BEGIN);
        *wroteOut = WriteFile(h, &b, 1, &n, nullptr) && n == 1;
    }
    CloseHandle(h);
    return 0;
}

DWORD renameDir(const wchar_t* from, const wchar_t* to)
{
    return MoveFileExW(from, to, 0) ? 0 : GetLastError();
}

DWORD openDir(const wchar_t* path, DWORD access)
{
    HANDLE h = CreateFileW(path, access, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
                           OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr);
    const DWORD e = (h == INVALID_HANDLE_VALUE) ? GetLastError() : 0;
    if (h != INVALID_HANDLE_VALUE) CloseHandle(h);
    return e;
}

// 先拿不命中数据片段的父目录句柄,再相对它打开 leaf:原始名只有 leaf,驱动必须查规范化全路径才拦得住。
DWORD openRelative(const wchar_t* parentDir, const wchar_t* leaf, ACCESS_MASK access)
{
    HANDLE parent = CreateFileW(parentDir, FILE_LIST_DIRECTORY | SYNCHRONIZE,
                                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
                                FILE_FLAG_BACKUP_SEMANTICS, nullptr);
    if (parent == INVALID_HANDLE_VALUE) return 0xFFFFFFFF;
    std::wstring rel = leaf;
    UNICODE_STRING us{};
    us.Buffer = rel.data();
    us.Length = static_cast<USHORT>(rel.size() * sizeof(wchar_t));
    us.MaximumLength = us.Length;
    OBJECT_ATTRIBUTES oa{};
    InitializeObjectAttributes(&oa, &us, OBJ_CASE_INSENSITIVE, parent, nullptr);
    IO_STATUS_BLOCK io{};
    HANDLE h = nullptr;
    const LONG s = ntCreateFile()(&h, access | SYNCHRONIZE, &oa, &io, nullptr, FILE_ATTRIBUTE_NORMAL,
                                  FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, kFileOpen,
                                  kSyncNonAlert | kNonDirectory, nullptr, 0);
    if (s >= 0 && h) CloseHandle(h);
    CloseHandle(parent);
    if (s >= 0) return 0;
    return s == static_cast<LONG>(0xC0000022) ? ERROR_ACCESS_DENIED : static_cast<DWORD>(s);
}

// 经 8.3 短名打开。卷上没开短名时 GetShortPathNameW 原样返回长名,照样走一遍规范化判定。
DWORD openShortName(const wchar_t* path, DWORD access, std::wstring* used)
{
    wchar_t shortPath[MAX_PATH] = {};
    const DWORD n = GetShortPathNameW(path, shortPath, MAX_PATH);
    if (n == 0 || n >= MAX_PATH) return 0xFFFFFFFD;
    if (used) *used = shortPath;
    return openByName(shortPath, access);
}

bool enablePrivilege(const wchar_t* name)
{
    HANDLE tok = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &tok)) return false;
    TOKEN_PRIVILEGES tp{};
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    const bool ok = LookupPrivilegeValueW(nullptr, name, &tp.Privileges[0].Luid)
                    && AdjustTokenPrivileges(tok, FALSE, &tp, sizeof(tp), nullptr, nullptr)
                    && GetLastError() == ERROR_SUCCESS;
    CloseHandle(tok);
    return ok;
}

LONG saveTestHive()
{
    DeleteFileW(kHiveFile);
    HKEY k = nullptr;
    LONG r = RegOpenKeyExW(HKEY_LOCAL_MACHINE, kRegTest, 0, KEY_READ, &k);
    if (r != ERROR_SUCCESS) return r;
    r = RegSaveKeyW(k, kHiveFile, nullptr);
    RegCloseKey(k);
    return r;
}

LONG restoreOnto(const wchar_t* subKey)
{
    HKEY k = nullptr;
    LONG r = RegOpenKeyExW(HKEY_LOCAL_MACHINE, subKey, 0, KEY_ALL_ACCESS, &k);
    if (r != ERROR_SUCCESS) return r;
    r = RegRestoreKeyW(k, kHiveFile, REG_FORCE_RESTORE);
    RegCloseKey(k);
    return r;
}

DWORD readOwnMarker()
{
    DWORD v = 0, cb = sizeof(v);
    RegGetValueW(HKEY_LOCAL_MACHINE, kRegOwn, L"Untouched", RRF_RT_REG_DWORD, nullptr, &v, &cb);
    return v;
}

// 本探针是不可信进程:驱动在线时它不得启动界面(创建者握着新进程的完整句柄)。
DWORD launchUiSuspended(const std::wstring& uiPath)
{
    STARTUPINFOW si{};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};
    std::wstring cmd = L"\"" + uiPath + L"\"";
    if (!CreateProcessW(uiPath.c_str(), cmd.data(), nullptr, nullptr, FALSE, CREATE_SUSPENDED, nullptr, nullptr,
                        &si, &pi)) {
        return GetLastError();
    }
    TerminateProcess(pi.hProcess, 0);
    WaitForSingleObject(pi.hProcess, 5000);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return 0;
}

using NtQueryObject_t = LONG(NTAPI*)(HANDLE, ULONG, PVOID, ULONG, PULONG);

ACCESS_MASK grantedAccess(HANDLE h)
{
    auto query = reinterpret_cast<NtQueryObject_t>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryObject"));
    PUBLIC_OBJECT_BASIC_INFORMATION info{};
    ULONG len = 0;
    return (query && query(h, 0 /* ObjectBasicInformation */, &info, sizeof(info), &len) >= 0) ? info.GrantedAccess
                                                                                              : 0;
}

// 界面由系统组件拉起后,本探针以全部权限打开它的进程与一个线程,读出实际拿到的权限。只读不写,不碰界面本身。
struct UiRuntime {
    bool        processOpened = false;
    ACCESS_MASK process = 0;
    bool        threadOpened = false;
    ACCESS_MASK thread = 0;
};

constexpr ACCESS_MASK kUiProcDeny = PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_CREATE_THREAD |
                                    PROCESS_DUP_HANDLE | PROCESS_SET_INFORMATION;
constexpr ACCESS_MASK kUiThreadDeny = THREAD_SET_CONTEXT | THREAD_SET_INFORMATION;

UiRuntime probeUiRuntime(DWORD pid)
{
    UiRuntime r;
    HANDLE p = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (p) {
        r.processOpened = true;
        r.process = grantedAccess(p);
        CloseHandle(p);
    }
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap != INVALID_HANDLE_VALUE) {
        THREADENTRY32 te{};
        te.dwSize = sizeof(te);
        for (BOOL more = Thread32First(snap, &te); more; more = Thread32Next(snap, &te)) {
            if (te.th32OwnerProcessID != pid) continue;
            HANDLE t = OpenThread(THREAD_ALL_ACCESS, FALSE, te.th32ThreadID);
            if (t) {
                r.threadOpened = true;
                r.thread = grantedAccess(t);
                CloseHandle(t);
            }
            break;
        }
        CloseHandle(snap);
    }
    return r;
}

std::string hexMask(ACCESS_MASK m)
{
    char buf[32];
    std::snprintf(buf, sizeof(buf), "granted=0x%08lX", static_cast<unsigned long>(m));
    return buf;
}

int setup()
{
    CreateDirectoryW(kRoot, nullptr);
    CreateDirectoryW(kGuard, nullptr);
    CreateDirectoryW(kSecretDir, nullptr);
    CreateDirectoryW(kOut, nullptr);
    CreateDirectoryW(kOutSub, nullptr);
    const bool ok = writeFile(kFileA, kContent) && writeFile(kFileB, kContent) && writeFile(kSecret, kContent) &&
                    writeFile(kMaxFile, kContent);
    HKEY k = nullptr;
    if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, kRegTest, 0, nullptr, 0, KEY_ALL_ACCESS, nullptr, &k, nullptr) ==
        ERROR_SUCCESS) {
        const DWORD v = 1;
        RegSetValueExW(k, L"Marker", 0, REG_DWORD, reinterpret_cast<const BYTE*>(&v), sizeof(v));
        RegCloseKey(k);
    }
    // 驱动加载后本产品服务键受硬拦,这个子键只能在加载前建好。
    if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, kRegOwn, 0, nullptr, 0, KEY_ALL_ACCESS, nullptr, &k, nullptr) ==
        ERROR_SUCCESS) {
        const DWORD v = 7;
        RegSetValueExW(k, L"Untouched", 0, REG_DWORD, reinterpret_cast<const BYTE*>(&v), sizeof(v));
        RegCloseKey(k);
    }
    std::printf("setup %s\n", ok ? "ok" : "FAILED");
    return ok ? 0 : 1;
}

int cleanup()
{
    DeleteFileW(kLink);
    DeleteFileW(kSecretLink);
    DeleteFileW(kHiveFile);
    DeleteFileW(kFileA);
    DeleteFileW(kFileB);
    DeleteFileW(kMaxFile);
    DeleteFileW(kSecret);
    RemoveDirectoryW(kGuard);
    RemoveDirectoryW(kSecretDir);
    RemoveDirectoryW(kRoot);
    RemoveDirectoryW(kOutSub);
    RemoveDirectoryW(kOut);
    RegDeleteKeyW(HKEY_LOCAL_MACHINE, kRegOwn);
    RegDeleteKeyW(HKEY_LOCAL_MACHINE, kRegTest);
    std::printf("cleanup done\n");
    return 0;
}

void commonChecks()
{
    // 受保护目录之外的普通操作必须照常。
    const wchar_t* x = L"D:\\BULWARK_KTEST_OUT\\x.txt";
    const wchar_t* y = L"D:\\BULWARK_KTEST_OUT\\y.txt";
    const bool ok = writeFile(x, "x") && MoveFileExW(x, y, MOVEFILE_REPLACE_EXISTING) && DeleteFileW(y);
    report(ok, "对照:受保护目录外 新建/写/改名/删除", ok ? "" : status(GetLastError()));
    const DWORD d1 = renameDir(kOutSub, L"D:\\BULWARK_KTEST_OUT\\sub2");
    const DWORD d2 = d1 == 0 ? renameDir(L"D:\\BULWARK_KTEST_OUT\\sub2", kOutSub) : 0;
    report(d1 == 0 && d2 == 0, "对照:受保护目录外的目录改名", status(d1 ? d1 : d2));
    report(openByName(kFileA, GENERIC_READ) == 0, "对照:受保护文件只读打开", "");
    report(openById(kFileA, GENERIC_READ) == 0, "对照:受保护文件按 ID 只读打开", "");
    STARTUPINFOW si{};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};
    wchar_t cmd[] = L"cmd.exe /c exit 0";
    const bool spawned = CreateProcessW(nullptr, cmd, nullptr, nullptr, FALSE, CREATE_NO_WINDOW, nullptr, nullptr,
                                        &si, &pi) != 0;
    if (spawned) {
        WaitForSingleObject(pi.hProcess, 10000);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
    }
    report(spawned, "对照:正常创建子进程", "");
}

int baseline(const std::wstring& ui, DWORD uiPid)
{
    std::printf("== baseline(无驱动)==\n");
    commonChecks();
    DWORD e = openByName(kFileA, GENERIC_WRITE);
    report(e == 0, "无驱动:按名写打开成功", status(e));
    e = openById(kFileA, GENERIC_WRITE);
    report(e == 0, "无驱动:按 ID 写打开成功(要堵的绕过)", status(e));
    LONG s = overwriteByName(kFileB);
    std::printf("INFO  无驱动:只读 + FILE_OVERWRITE 按名打开 -> %s,b.txt 现为 \"%s\"\n",
                ntstatus(s).c_str(), readFile(kFileB).c_str());
    writeFile(kFileB, kContent);
    s = overwriteById(kFileB);
    std::printf("INFO  无驱动:只读 + FILE_OVERWRITE 按 ID 打开 -> %s,b.txt 现为 \"%s\"\n",
                ntstatus(s).c_str(), readFile(kFileB).c_str());
    writeFile(kFileB, kContent);
    e = renameDir(kGuard, L"D:\\BULWARK_KTEST\\GUARD_R");
    if (e == 0) renameDir(L"D:\\BULWARK_KTEST\\GUARD_R", kGuard);
    report(e == 0, "无驱动:受保护目录本身可改名", status(e));
    e = CreateHardLinkW(kLink, kFileA, nullptr) ? 0 : GetLastError();
    DeleteFileW(kLink);
    report(e == 0, "无驱动:可给受保护文件建硬链接", status(e));
    s = linkLowLevel(kFileA, kLink);
    DeleteFileW(kLink);
    std::printf("INFO  无驱动:只读属性句柄直接建硬链接 -> %s\n", ntstatus(s).c_str());
    enablePrivilege(SE_BACKUP_NAME);
    enablePrivilege(SE_RESTORE_NAME);
    const LONG r = saveTestHive();
    report(r == ERROR_SUCCESS, "无驱动:导出测试键", status(r));

    e = launchUiSuspended(ui);
    report(e == 0, "无驱动:本探针可以直接启动界面", status(e));
    if (uiPid != 0) {
        const UiRuntime u = probeUiRuntime(uiPid);
        std::printf("INFO  无驱动:界面进程 %s,线程 %s\n", hexMask(u.process).c_str(), hexMask(u.thread).c_str());
    }

    report(readFile(kSecret) == kContent, "无驱动:敏感数据可直接读出(要堵的窃密)", "");
    e = openById(kSecret, GENERIC_READ);
    report(e == 0, "无驱动:敏感数据可按文件 ID 读", status(e));
    e = openRelative(kRoot, L"SECRET\\creds.txt", FILE_READ_DATA);
    report(e == 0, "无驱动:敏感数据可相对父目录句柄读", status(e));
    e = openDir(kSecretDir, FILE_LIST_DIRECTORY);
    report(e == 0, "无驱动:敏感数据目录可列出", status(e));

    bool wrote = false;
    e = openMaxAllowed(kMaxFile, &wrote);
    writeFile(kMaxFile, kContent);
    report(e == 0 && wrote, "无驱动:MAXIMUM_ALLOWED 打开受保护文件即可写入(要堵的绕过)", status(e));
    std::printf("== baseline 完成,失败 %d 项 ==\n", g_fail);
    return g_fail;
}

void readGuardChecks()
{
    DWORD e = openByName(kSecret, GENERIC_READ);
    report(e == ERROR_ACCESS_DENIED, "窃密防护:按名读敏感数据被拒", status(e));
    e = openByName(kSecret, FILE_READ_ATTRIBUTES);
    report(e == 0, "窃密防护:只查属性(大小 / 图标)放行", status(e));
    e = openById(kSecret, GENERIC_READ);
    report(e == ERROR_ACCESS_DENIED, "窃密防护:按文件 ID 读被拒(打开后撤销)", status(e));
    e = openRelative(kRoot, L"SECRET\\creds.txt", FILE_READ_DATA);
    report(e == ERROR_ACCESS_DENIED, "窃密防护:相对父目录句柄读被拒", status(e));
    std::wstring shortName;
    e = openShortName(kSecret, GENERIC_READ, &shortName);
    report(e == ERROR_ACCESS_DENIED, "窃密防护:经 8.3 短名读被拒",
           status(e) + (shortName.find(L'~') == std::wstring::npos ? " (卷上无短名,按长名测)" : ""));
    // 数据片段以 '\' 结尾保护的是目录里的东西,目录本身照常可列(磁盘分析、文件选择框);
    // 拿着这个目录句柄相对打开里面的文件仍要被拒。
    e = openDir(kSecretDir, FILE_LIST_DIRECTORY);
    report(e == 0, "窃密防护:列出敏感数据目录本身放行", status(e));
    e = openRelative(kSecretDir, L"creds.txt", FILE_READ_DATA);
    report(e == ERROR_ACCESS_DENIED, "窃密防护:相对敏感数据目录自身的句柄读被拒", status(e));
    LONG s = linkLowLevel(kSecret, kSecretLink);
    if (s >= 0) DeleteFileW(kSecretLink);
    report(s == static_cast<LONG>(0xC0000022), "窃密防护:给敏感数据建硬链接搬出去被拒", ntstatus(s));
    // 只有窃密防护管这个目录(受保护目录名单里是 GUARD),拒绝只可能来自它的目录改名判定。
    e = renameDir(kSecretDir, L"D:\\BULWARK_KTEST\\SECRET_R");
    if (e == 0) renameDir(L"D:\\BULWARK_KTEST\\SECRET_R", kSecretDir);
    report(e == ERROR_ACCESS_DENIED, "窃密防护:改名敏感数据目录逃出命中被拒", status(e));
    report(readFile(kFileA) == kContent, "窃密防护:不涉及敏感数据的读照常", "");
}

// 本探针的副本放在脚本登记的全局读者目录里运行:同一份敏感数据它应当读得到。
int reader()
{
    std::printf("== reader(本探针副本位于全局读者目录)==\n");
    const std::string c = readFile(kSecret);
    report(c == kContent, "窃密防护:全局读者能读敏感数据", c);
    const DWORD e = openById(kSecret, GENERIC_READ);
    report(e == 0, "窃密防护:全局读者按文件 ID 读放行", status(e));
    std::printf("== reader 完成,失败 %d 项 ==\n", g_fail);
    return g_fail;
}

int guard(const std::wstring& ui, DWORD uiPid)
{
    std::printf("== guard(驱动已加载,测试目录在受保护名单里)==\n");
    commonChecks();
    DWORD e = openByName(kFileA, GENERIC_WRITE);
    report(e == ERROR_ACCESS_DENIED, "按名写打开被拒", status(e));
    e = openById(kFileA, GENERIC_WRITE);
    report(e == ERROR_ACCESS_DENIED, "按文件 ID 写打开被拒", status(e));
    e = openById(kFileA, DELETE);
    report(e == ERROR_ACCESS_DENIED, "按文件 ID 以 DELETE 打开被拒", status(e));
    LONG s = overwriteByName(kFileB);
    report(s == static_cast<LONG>(0xC0000022), "只读 + FILE_OVERWRITE 按名打开被拒", ntstatus(s));
    s = overwriteById(kFileB);
    report(s < 0, "只读 + FILE_OVERWRITE 按 ID 打开失败", ntstatus(s));
    e = renameDir(kGuard, L"D:\\BULWARK_KTEST\\GUARD_R");
    if (e == 0) renameDir(L"D:\\BULWARK_KTEST\\GUARD_R", kGuard);
    report(e == ERROR_ACCESS_DENIED, "改名受保护目录本身被拒", status(e));
    e = renameDir(kRoot, L"D:\\BULWARK_KTEST_R");
    if (e == 0) renameDir(L"D:\\BULWARK_KTEST_R", kRoot);
    report(e == ERROR_ACCESS_DENIED, "改名受保护目录的上级被拒", status(e));
    e = CreateHardLinkW(kLink, kFileA, nullptr) ? 0 : GetLastError();
    if (e == 0) DeleteFileW(kLink);
    report(e == ERROR_ACCESS_DENIED, "给受保护文件建硬链接被拒", status(e));
    s = linkLowLevel(kFileA, kLink);
    if (s >= 0) DeleteFileW(kLink);
    report(s == static_cast<LONG>(0xC0000022), "只读属性句柄直接建硬链接被拒", ntstatus(s));

    bool wrote = false;
    e = openMaxAllowed(kMaxFile, &wrote);
    report(e == ERROR_ACCESS_DENIED && !wrote, "MAXIMUM_ALLOWED 打开受保护文件(实际拿到写权)被拒", status(e));

    const std::string a = readFile(kFileA), b = readFile(kFileB), m = readFile(kMaxFile);
    report(a == kContent && b == kContent && m == kContent, "受保护文件内容完好", a + " | " + b + " | " + m);

    enablePrivilege(SE_BACKUP_NAME);
    enablePrivilege(SE_RESTORE_NAME);
    LONG r = restoreOnto(kRegTest);
    report(r == ERROR_SUCCESS, "整棵恢复普通测试键放行", status(r));
    r = restoreOnto(kRegOwn);
    report(r == ERROR_ACCESS_DENIED, "整棵恢复本产品服务键下的子键被拒", status(r));
    report(readOwnMarker() == 7, "服务键下测试子键内容未被改写", "");

    e = launchUiSuspended(ui);
    report(e == ERROR_ACCESS_DENIED, "界面:本探针(非系统组件)启动界面被拒", status(e));
    if (uiPid == 0) {
        std::printf("SKIP  界面运行期剥权:没有由系统组件拉起的界面进程\n");
    } else {
        const UiRuntime u = probeUiRuntime(uiPid);
        if (!u.processOpened) {
            std::printf("SKIP  界面运行期剥权:界面进程 %lu 已退出\n", uiPid);
        } else {
            report((u.process & kUiProcDeny) == 0 && (u.process & PROCESS_TERMINATE) != 0,
                   "界面:进程句柄剥掉注入类权限、保留结束", hexMask(u.process));
            report(!u.threadOpened || (u.thread & kUiThreadDeny) == 0,
                   "界面:线程句柄剥掉改上下文类权限", hexMask(u.thread));
        }
    }

    readGuardChecks();
    std::printf("== guard 完成,失败 %d 项 ==\n", g_fail);
    return g_fail;
}

}

int wmain(int argc, wchar_t** argv)
{
    if (argc < 2) return 2;
    const std::wstring mode = argv[1];
    const std::wstring ui = argc >= 3 ? argv[2] : kDefaultUi;
    const DWORD uiPid = argc >= 4 ? static_cast<DWORD>(wcstoul(argv[3], nullptr, 10)) : 0;
    if (mode == L"setup") return setup();
    if (mode == L"baseline") return baseline(ui, uiPid);
    if (mode == L"guard") return guard(ui, uiPid);
    if (mode == L"reader") return reader();
    if (mode == L"cleanup") return cleanup();
    return 2;
}
