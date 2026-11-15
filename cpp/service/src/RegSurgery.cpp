#include "bulwark/service/RegSurgery.h"

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <aclapi.h>

namespace bulwark::service {
namespace {

HKEY hiveToHkey(RegHive h) {
    switch (h) {
        case RegHive::LocalMachine:  return HKEY_LOCAL_MACHINE;
        case RegHive::CurrentUser:   return HKEY_CURRENT_USER;
        case RegHive::ClassesRoot:   return HKEY_CLASSES_ROOT;
        case RegHive::Users:         return HKEY_USERS;
        case RegHive::CurrentConfig: return HKEY_CURRENT_CONFIG;
    }
    return HKEY_LOCAL_MACHINE;
}

REGSAM viewToSam(RegView v) {
    switch (v) {
        case RegView::Registry32: return KEY_WOW64_32KEY;
        case RegView::Registry64: return KEY_WOW64_64KEY;
        default:                  return 0;
    }
}

const wchar_t* wstr(const QString& s) {
    return reinterpret_cast<const wchar_t*>(s.utf16());
}

void enablePrivilege(const wchar_t* name) {
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token))
        return;
    LUID luid{};
    if (LookupPrivilegeValueW(nullptr, name, &luid)) {
        TOKEN_PRIVILEGES tp{};
        tp.PrivilegeCount = 1;
        tp.Privileges[0].Luid = luid;
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        AdjustTokenPrivileges(token, FALSE, &tp, 0, nullptr, nullptr);
    }
    CloseHandle(token);
}

PSID buildAdminsSid(BYTE* buf, DWORD bufSize) {
    DWORD sz = bufSize;
    if (!CreateWellKnownSid(WinBuiltinAdministratorsSid, nullptr, buf, &sz)) return nullptr;
    return reinterpret_cast<PSID>(buf);
}

struct SavedKeySecurity {
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    PSID owner = nullptr;
    PACL dacl = nullptr;
    SECURITY_DESCRIPTOR_CONTROL control = 0;

    ~SavedKeySecurity() {
        if (descriptor)
            LocalFree(descriptor);
    }

    SavedKeySecurity(const SavedKeySecurity&) = delete;
    SavedKeySecurity& operator=(const SavedKeySecurity&) = delete;
    SavedKeySecurity() = default;
};

bool captureSecurity(HKEY root, const QString& subKey, REGSAM sam, SavedKeySecurity& saved) {
    HKEY hk = nullptr;
    if (RegOpenKeyExW(root, wstr(subKey), 0, READ_CONTROL | sam, &hk) != ERROR_SUCCESS)
        return false;
    DWORD rc = GetSecurityInfo(hk, SE_REGISTRY_KEY,
                               OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                               &saved.owner, nullptr, &saved.dacl, nullptr, &saved.descriptor);
    RegCloseKey(hk);
    if (rc != ERROR_SUCCESS || !saved.descriptor)
        return false;
    DWORD revision = 0;
    if (!GetSecurityDescriptorControl(saved.descriptor, &saved.control, &revision))
        return false;
    return true;
}

bool restoreSecurity(HKEY root, const QString& subKey, REGSAM sam,
                     const SavedKeySecurity& saved) {
    HKEY hk = nullptr;
    if (RegOpenKeyExW(root, wstr(subKey), 0, WRITE_OWNER | WRITE_DAC | sam, &hk)
        != ERROR_SUCCESS)
        return false;
    SECURITY_INFORMATION info = OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION;
    info |= (saved.control & SE_DACL_PROTECTED)
        ? PROTECTED_DACL_SECURITY_INFORMATION
        : UNPROTECTED_DACL_SECURITY_INFORMATION;
    const DWORD rc = SetSecurityInfo(hk, SE_REGISTRY_KEY, info,
                                     saved.owner, nullptr, saved.dacl, nullptr);
    RegCloseKey(hk);
    return rc == ERROR_SUCCESS;
}

bool takeOwnership(HKEY root, const QString& subKey, REGSAM sam, PSID admins) {
    HKEY hk = nullptr;
    if (RegOpenKeyExW(root, wstr(subKey), 0, WRITE_OWNER | sam, &hk) != ERROR_SUCCESS)
        return false;
    const DWORD rc = SetSecurityInfo(hk, SE_REGISTRY_KEY, OWNER_SECURITY_INFORMATION,
                                     admins, nullptr, nullptr, nullptr);
    RegCloseKey(hk);
    return rc == ERROR_SUCCESS;
}

bool grantAdminsFullControl(HKEY root, const QString& subKey, REGSAM sam,
                            PSID admins, DWORD inheritance) {
    HKEY hk = nullptr;
    if (RegOpenKeyExW(root, wstr(subKey), 0, READ_CONTROL | WRITE_DAC | sam, &hk) != ERROR_SUCCESS)
        return false;
    PACL oldDacl = nullptr;
    PSECURITY_DESCRIPTOR sd = nullptr;
    bool ok = false;
    if (GetSecurityInfo(hk, SE_REGISTRY_KEY, DACL_SECURITY_INFORMATION,
                        nullptr, nullptr, &oldDacl, nullptr, &sd) == ERROR_SUCCESS) {
        EXPLICIT_ACCESSW ea{};
        ea.grfAccessPermissions = KEY_ALL_ACCESS;
        ea.grfAccessMode = SET_ACCESS;
        ea.grfInheritance = inheritance;
        ea.Trustee.TrusteeForm = TRUSTEE_IS_SID;
        ea.Trustee.TrusteeType = TRUSTEE_IS_GROUP;
        ea.Trustee.ptstrName = reinterpret_cast<LPWSTR>(admins);
        PACL newDacl = nullptr;
        if (SetEntriesInAclW(1, &ea, oldDacl, &newDacl) == ERROR_SUCCESS) {
            ok = SetSecurityInfo(hk, SE_REGISTRY_KEY, DACL_SECURITY_INFORMATION,
                                 nullptr, nullptr, newDacl, nullptr) == ERROR_SUCCESS;
            if (newDacl) LocalFree(newDacl);
        }
        if (sd) LocalFree(sd);
    }
    RegCloseKey(hk);
    return ok;
}

}
}

namespace bulwark::service {
namespace RegSurgery {

bool forceDeleteValue(RegHive hive, const QString& subKey, const QString& valueName, RegView view) {
    enablePrivilege(L"SeTakeOwnershipPrivilege");
    enablePrivilege(L"SeRestorePrivilege");

    BYTE sidBuf[SECURITY_MAX_SID_SIZE];
    PSID admins = buildAdminsSid(sidBuf, sizeof(sidBuf));
    const HKEY root = hiveToHkey(hive);
    const REGSAM sam = viewToSam(view);
    SavedKeySecurity saved;
    if (!admins || !captureSecurity(root, subKey, sam, saved))
        return false; // 无法保存原安全描述符时绝不做不可逆接管。

    if (!takeOwnership(root, subKey, sam, admins)
        || !grantAdminsFullControl(root, subKey, sam, admins, NO_INHERITANCE)) {
        (void)restoreSecurity(root, subKey, sam, saved);
        return false;
    }

    HKEY hk = nullptr;
    if (RegOpenKeyExW(root, wstr(subKey), 0, KEY_SET_VALUE | sam, &hk) != ERROR_SUCCESS) {
        (void)restoreSecurity(root, subKey, sam, saved);
        return false;
    }
    const LSTATUS st = RegDeleteValueW(hk, wstr(valueName));
    RegCloseKey(hk);
    const bool restored = restoreSecurity(root, subKey, sam, saved);
    return restored && (st == ERROR_SUCCESS || st == ERROR_FILE_NOT_FOUND);
}

bool forceDeleteSubKeyTree(RegHive hive, const QString& parentSubKey,
                           const QString& childName, RegView view) {
    enablePrivilege(L"SeTakeOwnershipPrivilege");
    enablePrivilege(L"SeRestorePrivilege");

    BYTE sidBuf[SECURITY_MAX_SID_SIZE];
    PSID admins = buildAdminsSid(sidBuf, sizeof(sidBuf));
    const HKEY root = hiveToHkey(hive);
    const REGSAM sam = viewToSam(view);
    const QString childPath = parentSubKey + QStringLiteral("\\") + childName;
    SavedKeySecurity saved;
    if (!admins || !captureSecurity(root, childPath, sam, saved))
        return false;

    if (!takeOwnership(root, childPath, sam, admins)
        || !grantAdminsFullControl(root, childPath, sam, admins, CONTAINER_INHERIT_ACE)) {
        (void)restoreSecurity(root, childPath, sam, saved);
        return false;
    }

    HKEY parent = nullptr;
    if (RegOpenKeyExW(root, wstr(parentSubKey), 0, KEY_ALL_ACCESS | sam, &parent)
        != ERROR_SUCCESS) {
        (void)restoreSecurity(root, childPath, sam, saved);
        return false;
    }
    const LSTATUS st = RegDeleteTreeW(parent, wstr(childName));
    RegCloseKey(parent);
    if (st == ERROR_SUCCESS || st == ERROR_FILE_NOT_FOUND)
        return true;
    (void)restoreSecurity(root, childPath, sam, saved);
    return false;
}

}
}
