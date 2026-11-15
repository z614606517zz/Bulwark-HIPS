#include "bulwark/service/SelfHardening.h"

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <sddl.h>
#endif

#include <QStringList>

namespace bulwark::service {

#ifdef _WIN32

namespace {

QString lastErrorNote() {
    const DWORD e = ::GetLastError();
    switch (e) {
    case ERROR_INVALID_PARAMETER:
        return QStringLiteral("本版本 Windows 不支持该缓解策略");
    case ERROR_ACCESS_DENIED:
        return QStringLiteral("已被更严的策略锁定或权限不足");
    default:
        return QStringLiteral("GetLastError=%1").arg(static_cast<quint32>(e));
    }
}

QByteArray tokenInfo(HANDLE token, TOKEN_INFORMATION_CLASS cls) {
    DWORD need = 0;
    ::GetTokenInformation(token, cls, nullptr, 0, &need);
    if (need == 0)
        return {};
    QByteArray buf(static_cast<int>(need), Qt::Uninitialized);
    if (!::GetTokenInformation(token, cls, buf.data(), need, &need))
        return {};
    buf.resize(static_cast<int>(need));
    return buf;
}

DWORD integrityRid(HANDLE token) {
    const QByteArray buf = tokenInfo(token, TokenIntegrityLevel);
    if (buf.isEmpty())
        return 0;
    const auto* label = reinterpret_cast<const TOKEN_MANDATORY_LABEL*>(buf.constData());
    if (label->Label.Sid == nullptr)
        return 0;
    const UCHAR count = *::GetSidSubAuthorityCount(label->Label.Sid);
    if (count == 0)
        return 0;
    return *::GetSidSubAuthority(label->Label.Sid, count - 1);
}

bool tokenHasPrivilege(HANDLE token, const wchar_t* name) {
    LUID luid{};
    if (!::LookupPrivilegeValueW(nullptr, name, &luid))
        return true;
    const QByteArray buf = tokenInfo(token, TokenPrivileges);
    if (buf.isEmpty())
        return true;
    const auto* privs = reinterpret_cast<const TOKEN_PRIVILEGES*>(buf.constData());
    for (DWORD i = 0; i < privs->PrivilegeCount; ++i) {
        if (privs->Privileges[i].Luid.LowPart == luid.LowPart &&
            privs->Privileges[i].Luid.HighPart == luid.HighPart)
            return true;
    }
    return false;
}

}

SelfHardening::Report SelfHardening::hardenCurrentProcess(bool guiProcess) {
    Report r;
    const HANDLE self = ::GetCurrentProcess();

    {
        PROCESS_MITIGATION_EXTENSION_POINT_DISABLE_POLICY p{};
        p.DisableExtensionPoints = 1;
        if (::SetProcessMitigationPolicy(ProcessExtensionPointDisablePolicy, &p, sizeof(p)))
            r.applied << QStringLiteral("扩展点禁用(AppInit_DLLs / 全局钩子 / IME 注入一律进不来)");
        else
            r.skipped << QStringLiteral("扩展点禁用 —— %1").arg(lastErrorNote());
    }

    {
        PROCESS_MITIGATION_IMAGE_LOAD_POLICY p{};
        p.NoRemoteImages = 1;
        p.NoLowMandatoryLabelImages = 1;
        p.PreferSystem32Images = 1;
        if (::SetProcessMitigationPolicy(ProcessImageLoadPolicy, &p, sizeof(p)))
            r.applied << QStringLiteral("映像加载策略(禁远程映像 / 禁低完整性映像 / 优先 System32)");
        else
            r.skipped << QStringLiteral("映像加载策略 —— %1").arg(lastErrorNote());
    }

    {
        PROCESS_MITIGATION_STRICT_HANDLE_CHECK_POLICY p{};
        p.RaiseExceptionOnInvalidHandleReference = 1;
        p.HandleExceptionsPermanentlyEnabled = 1;
        if (::SetProcessMitigationPolicy(ProcessStrictHandleCheckPolicy, &p, sizeof(p)))
            r.applied << QStringLiteral("严格句柄检查(句柄被恶意关闭即暴露,不静默失效)");
        else
            r.skipped << QStringLiteral("严格句柄检查 —— %1").arg(lastErrorNote());
    }

    {
        PROCESS_MITIGATION_ASLR_POLICY p{};
        p.EnableBottomUpRandomization = 1;
        p.EnableForceRelocateImages = 1;
        p.EnableHighEntropy = 1;
        p.DisallowStrippedImages = 1;
        if (::SetProcessMitigationPolicy(ProcessASLRPolicy, &p, sizeof(p)))
            r.applied << QStringLiteral("强制 ASLR(含高熵 + 拒绝无重定位表映像)");
        else
            r.skipped << QStringLiteral("强制 ASLR —— %1").arg(lastErrorNote());
    }

    if (::SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32 |
                                   LOAD_LIBRARY_SEARCH_USER_DIRS |
                                   LOAD_LIBRARY_SEARCH_APPLICATION_DIR))
        r.applied << QStringLiteral("DLL 搜索目录收紧(不再搜当前目录与 %PATH%,挡搜索顺序劫持)");
    else
        r.skipped << QStringLiteral("DLL 搜索目录收紧 —— %1").arg(lastErrorNote());

    {
        if (::SetProcessWorkingSetSizeEx(self, static_cast<SIZE_T>(-1), static_cast<SIZE_T>(-1),
                                         QUOTA_LIMITS_HARDWS_MIN_DISABLE |
                                         QUOTA_LIMITS_HARDWS_MAX_DISABLE))
            r.applied << QStringLiteral("工作集硬限制禁用(抗「压工作集饿死安全软件」的资源攻击)");
        else
            r.skipped << QStringLiteral("工作集硬限制禁用 —— %1").arg(lastErrorNote());
    }

    if (guiProcess) {
        r.applied << QStringLiteral("(界面进程)以上策略全部适用");
    }

    return r;
}

QStringList SelfHardening::auditOwnToken(bool serviceProcess) {
    QStringList bad;
    HANDLE token = nullptr;

    if (!::OpenProcessToken(::GetCurrentProcess(), TOKEN_QUERY, &token)) {
        bad << QStringLiteral("无法打开本进程令牌(GetLastError=%1)—— 这本身就是异常")
                   .arg(static_cast<quint32>(::GetLastError()));
        return bad;
    }

    const DWORD rid = integrityRid(token);
    const DWORD want = serviceProcess ? SECURITY_MANDATORY_SYSTEM_RID
                                      : SECURITY_MANDATORY_MEDIUM_RID;
    if (rid != 0 && rid < want) {
        bad << QStringLiteral("完整性级别被降低:当前 0x%1,期望不低于 0x%2(疑似降权攻击)")
                   .arg(rid, 0, 16).arg(want, 0, 16);
    }

    if (::IsTokenRestricted(token)) {
        bad << QStringLiteral("本进程令牌已变成【受限令牌】(存在限制 SID)—— 疑似降权攻击");
    }

    if (serviceProcess) {
        static const struct { const wchar_t* name; const char* why; } kNeeded[] = {
            { SE_DEBUG_NAME,            "打开其它进程做内存扫描 / 取证" },
            { SE_BACKUP_NAME,           "绕 DACL 读取取不到的文件(占用文件访问)" },
            { SE_RESTORE_NAME,          "还原隔离区文件 / 修复引导区基线" },
            { SE_LOAD_DRIVER_NAME,      "加载与卸载内核驱动" },
            { SE_SECURITY_NAME,         "读写安全日志与对象 SACL" },
            { SE_TAKE_OWNERSHIP_NAME,   "接管恶意软件锁住的对象" },
        };
        for (const auto& p : kNeeded) {
            if (!tokenHasPrivilege(token, p.name)) {
                bad << QStringLiteral("关键特权 %1 已从令牌中【移除】(用途:%2)—— 疑似降权攻击")
                           .arg(QString::fromWCharArray(p.name))
                           .arg(QString::fromUtf8(p.why));
            }
        }
    }

    ::CloseHandle(token);
    return bad;
}

bool SelfHardening::selfCheck(bool serviceProcess, const DegradedHandler& onDegraded) {
    QStringList reasons = auditOwnToken(serviceProcess);

    SIZE_T minWs = 0, maxWs = 0;
    DWORD flags = 0;
    if (::GetProcessWorkingSetSizeEx(::GetCurrentProcess(), &minWs, &maxWs, &flags)) {
        if (flags & QUOTA_LIMITS_HARDWS_MIN_ENABLE) {
            reasons << QStringLiteral("本进程工作集被施加了【硬下限】(min=%1 字节)—— "
                                      "典型的资源耗尽/饿死攻击,扫描与规则引擎会因持续换页而停摆")
                           .arg(static_cast<qulonglong>(minWs));
        }
    }

    if (!reasons.isEmpty()) {
        if (onDegraded)
            onDegraded(reasons);
        return false;
    }
    return true;
}

#else

SelfHardening::Report SelfHardening::hardenCurrentProcess(bool) {
    Report r;
    r.skipped << QStringLiteral("非 Windows 平台:进程缓解策略不可用");
    return r;
}

QStringList SelfHardening::auditOwnToken(bool) { return {}; }

bool SelfHardening::selfCheck(bool, const DegradedHandler&) { return true; }

#endif

}
