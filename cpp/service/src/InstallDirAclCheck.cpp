#include "bulwark/service/InstallDirAclCheck.h"

#include <QDir>
#include <QFileInfo>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <aclapi.h>
#include <sddl.h>

#include <string>

namespace bulwark::service {

namespace {

constexpr DWORD kWriteMask = FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_DELETE_CHILD | DELETE
                             | WRITE_DAC | WRITE_OWNER | GENERIC_WRITE | GENERIC_ALL;

}

bool InstallDirAclCheck::daclGrantsNonAdminWrite(const void* daclIn, QStringList* who) {
    PACL dacl = const_cast<PACL>(static_cast<const ACL*>(daclIn));
    if (!dacl) {
        if (who) *who << QStringLiteral("NULL DACL(任何人完全控制)");
        return true;
    }

    struct Slot {
        const wchar_t* sddl;
        const wchar_t* label;
        PSID sid;
        bool wrote;
    };
    Slot sidSlots[3] = {
        { L"S-1-1-0", L"Everyone", nullptr, false },
        { L"S-1-5-11", L"Authenticated Users", nullptr, false },
        { L"S-1-5-32-545", L"Users", nullptr, false },
    };
    for (Slot& s : sidSlots)
        ConvertStringSidToSidW(s.sddl, &s.sid);

    DWORD granted = 0;
    DWORD denied = 0;
    for (DWORD i = 0; i < dacl->AceCount; ++i) {
        void* ace = nullptr;
        if (!GetAce(dacl, i, &ace) || !ace)
            continue;
        const ACE_HEADER* h = static_cast<const ACE_HEADER*>(ace);
        if (h->AceFlags & INHERIT_ONLY_ACE)
            continue;
        if (h->AceType != ACCESS_ALLOWED_ACE_TYPE && h->AceType != ACCESS_DENIED_ACE_TYPE)
            continue;
        const ACCESS_ALLOWED_ACE* a = static_cast<const ACCESS_ALLOWED_ACE*>(ace);
        PSID sid = const_cast<DWORD*>(&a->SidStart);
        int idx = -1;
        for (int k = 0; k < 3; ++k) {
            if (sidSlots[k].sid && EqualSid(sid, sidSlots[k].sid)) { idx = k; break; }
        }
        if (idx < 0)
            continue;
        if (h->AceType == ACCESS_ALLOWED_ACE_TYPE) {
            const DWORD add = a->Mask & ~denied;
            granted |= add;
            if (add & kWriteMask)
                sidSlots[idx].wrote = true;
        } else {
            denied |= a->Mask & ~granted;
        }
    }

    for (Slot& s : sidSlots) {
        if (s.sid) { LocalFree(s.sid); s.sid = nullptr; }
    }
    const bool writable = (granted & kWriteMask) != 0;
    if (writable && who) {
        for (const Slot& s : sidSlots)
            if (s.wrote) *who << QString::fromWCharArray(s.label);
    }
    return writable;
}

InstallDirAclCheck::Report InstallDirAclCheck::check(const QString& installDir) {
    Report r;
    QStringList paths;
    paths << installDir;
    for (const QString& name : { QStringLiteral("bulwark_service.exe"), QStringLiteral("bulwark_ui.exe") }) {
        const QString p = QDir(installDir).filePath(name);
        if (QFileInfo::exists(p))
            paths << p;
    }

    for (const QString& p : paths) {
        Target t;
        t.path = QDir::toNativeSeparators(p);
        std::wstring w = t.path.toStdWString();

        PSECURITY_DESCRIPTOR sd = nullptr;
        PACL dacl = nullptr;
        // 只读:仅取 DACL。绝不调用 SetNamedSecurityInfo / SetSecurityInfo。
        const DWORD rc = GetNamedSecurityInfoW(w.data(), SE_FILE_OBJECT, DACL_SECURITY_INFORMATION,
                                               nullptr, nullptr, &dacl, nullptr, &sd);
        if (rc != ERROR_SUCCESS) {
            t.error = QStringLiteral("GetNamedSecurityInfo 失败(错误 %1)").arg(rc);
            r.anyUnreadable = true;
        } else {
            t.readable = true;
            r.checked = true;
            t.writableByNonAdmin = daclGrantsNonAdminWrite(dacl, &t.who);
            if (t.writableByNonAdmin)
                r.anyWritable = true;
        }
        if (sd)
            LocalFree(sd);
        r.targets.push_back(t);
    }
    return r;
}

QString InstallDirAclCheck::Report::detail() const {
    QStringList parts;
    for (const Target& t : targets) {
        if (t.writableByNonAdmin)
            parts << QStringLiteral("%1(%2 可写)").arg(t.path, t.who.join(QStringLiteral("、")));
        else if (!t.readable)
            parts << QStringLiteral("%1(无法读取 ACL:%2)").arg(t.path, t.error);
    }
    return parts.join(QStringLiteral(";"));
}

}
