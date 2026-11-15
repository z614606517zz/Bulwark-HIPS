#include "bulwark/service/ServiceControlTracer.h"

#include <QSet>

#include <vector>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

namespace bulwark::service {

namespace {

constexpr ULONG kWrLpcReply = 17;
constexpr int   kSystemProcessInformation = 5;
constexpr LONG  kStatusInfoLengthMismatch = static_cast<LONG>(0xC0000004);

using NtQuerySystemInformationFn =
    LONG(NTAPI*)(int, PVOID, ULONG, PULONG);

NtQuerySystemInformationFn ntQuery() {
    static NtQuerySystemInformationFn fn = []() -> NtQuerySystemInformationFn {
        HMODULE nt = ::GetModuleHandleW(L"ntdll.dll");
        return nt ? reinterpret_cast<NtQuerySystemInformationFn>(
                        ::GetProcAddress(nt, "NtQuerySystemInformation"))
                  : nullptr;
    }();
    return fn;
}

QString resolvePidPath(DWORD pid) {
    if (pid == 0) return QString();
    HANDLE h = ::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!h) return QStringLiteral("PID %1").arg(pid);
    wchar_t buf[1024] = {};
    DWORD sz = 1024;
    QString out = QStringLiteral("PID %1").arg(pid);
    if (::QueryFullProcessImageNameW(h, 0, buf, &sz))
        out = QString::fromWCharArray(buf, static_cast<int>(sz));
    ::CloseHandle(h);
    return out;
}

QList<int> enumerateLpcReplyWaiters() {
    QList<int> pids;
    auto q = ntQuery();
    if (!q || sizeof(void*) != 8) return pids;

    ULONG len = 0x100000;
    std::vector<unsigned char> buffer;
    long valid = 0;       // 内核实际写入的字节数;越界判定只能按它,不能按 buffer.size()
    bool ok = false;
    for (int attempt = 0; attempt < 6; ++attempt) {
        buffer.assign(len, 0);
        ULONG needed = 0;
        const LONG status = q(kSystemProcessInformation, buffer.data(), len, &needed);
        if (status == kStatusInfoLengthMismatch) {
            len = needed > 0 ? needed + 0x10000 : len * 2;
            continue;
        }
        if (status != 0) return pids;
        valid = needed > 0 && needed <= len ? static_cast<long>(needed) : static_cast<long>(len);
        ok = true;
        break;
    }
    if (!ok) return pids;

    constexpr long kThreadArrayOffset = 0x100;
    constexpr long kThreadEntrySize = 0x50;
    constexpr long kWaitReasonOffset = 0x48;
    constexpr long kProcEntryMinSize = 0x58;

    // 按硬编码偏移解析内核返回的变长链表,每次解引用前都要确认整段落在 valid 范围内;
    // 本函数跑在主线程,越界读会让整个服务崩溃。
    const unsigned char* base = buffer.data();
    long offset = 0;
    while (offset >= 0 && offset + kProcEntryMinSize <= valid) {
        const unsigned char* entry = base + offset;
        const ULONG nextOffset = *reinterpret_cast<const ULONG*>(entry + 0x00);
        const ULONG threadCount = *reinterpret_cast<const ULONG*>(entry + 0x04);
        const quintptr pid = *reinterpret_cast<const quintptr*>(entry + 0x50);

        if (pid > 4 && threadCount > 0 && threadCount < 100000 &&
            offset + kThreadArrayOffset + static_cast<long>(threadCount) * kThreadEntrySize
                <= valid) {
            for (ULONG i = 0; i < threadCount; ++i) {
                const unsigned char* th = base + offset + kThreadArrayOffset + static_cast<long>(i) * kThreadEntrySize;
                const ULONG waitReason = *reinterpret_cast<const ULONG*>(th + kWaitReasonOffset);
                if (waitReason == kWrLpcReply) { pids.append(static_cast<int>(pid)); break; }
            }
        }
        if (nextOffset == 0) break;
        offset += static_cast<long>(nextOffset);
    }
    return pids;
}

}

bool ServiceControlTracer::isServiceDatabaseKey(const QString& targetPath) {
    if (targetPath.isEmpty()) return false;
    return targetPath.contains(QStringLiteral("\\Services\\"), Qt::CaseInsensitive)
        || targetPath.endsWith(QStringLiteral("\\Services"), Qt::CaseInsensitive);
}

ServiceOriginator ServiceControlTracer::trace(int scmPid) {
    ServiceOriginator result;
    const int selfPid = static_cast<int>(::GetCurrentProcessId());
    QSet<int> seen;
    for (int pid : enumerateLpcReplyWaiters()) {
        if (pid <= 4 || pid == scmPid || pid == selfPid) continue;
        if (seen.contains(pid)) continue;
        seen.insert(pid);
        result.candidates.append({ pid, resolvePidPath(static_cast<DWORD>(pid)) });
    }
    if (result.candidates.size() == 1) {
        result.originatorPid = result.candidates.first().first;
        result.originatorPath = result.candidates.first().second;
    }
    return result;
}

}
