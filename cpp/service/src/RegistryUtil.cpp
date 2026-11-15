#include "bulwark/service/RegistryUtil.h"

#include <QByteArray>

#include <cstring>
#include <string>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

namespace bulwark::service::regutil {

namespace {

constexpr DWORD kMaxValueBytes = 256 * 1024;

inline const wchar_t* wstr(const QString& s) {
    return reinterpret_cast<const wchar_t*>(s.utf16());
}

inline HKEY rootOf(Hive h) {
    return h == Hive::Machine ? HKEY_LOCAL_MACHINE : HKEY_USERS;
}

struct KeyCloser {
    HKEY k = nullptr;
    ~KeyCloser() { if (k) ::RegCloseKey(k); }
};

Value readOpen(HKEY k, const QString& name) {
    Value v;
    DWORD type = 0, cb = 0;
    if (::RegQueryValueExW(k, wstr(name), nullptr, &type, nullptr, &cb) != ERROR_SUCCESS)
        return v;
    v.present = true;
    v.type = type;
    const bool wanted = (type == REG_SZ || type == REG_EXPAND_SZ || type == REG_DWORD);
    if (!wanted || cb > kMaxValueBytes) {
        v.supported = false;
        v.text = QStringLiteral("<类型 %1,长度 %2>").arg(type).arg(cb);
        return v;
    }
    QByteArray buf(static_cast<int>(cb) + 4, '\0');
    DWORD got = 0;
    LONG rc = ERROR_MORE_DATA;
    for (int attempt = 0; attempt < 3 && rc == ERROR_MORE_DATA; ++attempt) {
        got = static_cast<DWORD>(buf.size());
        DWORD t2 = 0;
        rc = ::RegQueryValueExW(k, wstr(name), nullptr, &t2,
                                reinterpret_cast<LPBYTE>(buf.data()), &got);
        if (rc == ERROR_MORE_DATA)
            buf.resize(static_cast<int>(qMin<DWORD>(got, kMaxValueBytes)) + 4);
        else
            v.type = t2;
    }
    if (rc != ERROR_SUCCESS) {
        return Value{};
    }
    if (got > static_cast<DWORD>(buf.size()))
        got = static_cast<DWORD>(buf.size());   // 最后一道:宁可截断也不越界
    v.supported = true;
    if (v.type == REG_DWORD) {
        DWORD d = 0;
        if (got >= sizeof(DWORD))
            memcpy(&d, buf.constData(), sizeof(DWORD));
        v.text = QString::number(d);
        return v;
    }
    int chars = static_cast<int>(got / sizeof(wchar_t));
    const wchar_t* w = reinterpret_cast<const wchar_t*>(buf.constData());
    while (chars > 0 && w[chars - 1] == L'\0')
        --chars;
    v.text = QString::fromWCharArray(w, chars);
    return v;
}

}

QString hiveName(Hive h) {
    return h == Hive::Machine ? QStringLiteral("HKLM") : QStringLiteral("HKU");
}

Value readValue(Hive h, const QString& sub, const QString& name) {
    HKEY k = nullptr;
    if (::RegOpenKeyExW(rootOf(h), wstr(sub), 0, KEY_QUERY_VALUE | KEY_WOW64_64KEY, &k)
        != ERROR_SUCCESS)
        return Value{};
    KeyCloser kc{k};
    return readOpen(k, name);
}

bool keyExists(Hive h, const QString& sub) {
    HKEY k = nullptr;
    if (::RegOpenKeyExW(rootOf(h), wstr(sub), 0, KEY_QUERY_VALUE | KEY_WOW64_64KEY, &k)
        != ERROR_SUCCESS)
        return false;
    ::RegCloseKey(k);
    return true;
}

QStringList subKeys(Hive h, const QString& sub) {
    QStringList out;
    HKEY k = nullptr;
    if (::RegOpenKeyExW(rootOf(h), wstr(sub), 0, KEY_ENUMERATE_SUB_KEYS | KEY_WOW64_64KEY, &k)
        != ERROR_SUCCESS)
        return out;
    KeyCloser kc{k};
    for (DWORD i = 0;; ++i) {
        wchar_t name[512] = {};
        DWORD n = 511;
        const LONG rc = ::RegEnumKeyExW(k, i, name, &n, nullptr, nullptr, nullptr, nullptr);
        if (rc == ERROR_NO_MORE_ITEMS)
            break;
        if (rc == ERROR_MORE_DATA)
            continue;
        if (rc != ERROR_SUCCESS)
            break;
        out << QString::fromWCharArray(name, static_cast<int>(n));
    }
    return out;
}

QList<Named> values(Hive h, const QString& sub) {
    QList<Named> out;
    HKEY k = nullptr;
    if (::RegOpenKeyExW(rootOf(h), wstr(sub), 0, KEY_QUERY_VALUE | KEY_WOW64_64KEY, &k)
        != ERROR_SUCCESS)
        return out;
    KeyCloser kc{k};
    constexpr DWORD kNameCap = 16384;
    static thread_local wchar_t nameBuf[kNameCap];
    for (DWORD i = 0;; ++i) {
        DWORD n = kNameCap;
        const LONG rc = ::RegEnumValueW(k, i, nameBuf, &n, nullptr, nullptr, nullptr, nullptr);
        if (rc == ERROR_NO_MORE_ITEMS)
            break;
        if (rc == ERROR_MORE_DATA)
            continue;
        if (rc != ERROR_SUCCESS)
            break;
        if (n > kNameCap - 1)
            n = kNameCap - 1;
        Named item;
        item.name = QString::fromWCharArray(nameBuf, static_cast<int>(n));
        item.value = readOpen(k, item.name);
        out << item;
    }
    return out;
}

bool writeValue(Hive h, const QString& sub, const QString& name, quint32 type, const QString& text,
                quint32* winerr) {
    HKEY k = nullptr;
    LONG rc = ::RegOpenKeyExW(rootOf(h), wstr(sub), 0, KEY_SET_VALUE | KEY_WOW64_64KEY, &k);
    if (rc != ERROR_SUCCESS) {
        if (winerr) *winerr = static_cast<quint32>(rc);
        return false;
    }
    KeyCloser kc{k};
    if (type == kRegDword) {
        bool ok = false;
        const DWORD d = static_cast<DWORD>(text.toUInt(&ok));
        if (!ok) {
            if (winerr) *winerr = ERROR_INVALID_PARAMETER;
            return false;
        }
        rc = ::RegSetValueExW(k, wstr(name), 0, REG_DWORD, reinterpret_cast<const BYTE*>(&d),
                              sizeof(d));
    } else if (type == kRegSz || type == kRegExpandSz) {
        const std::wstring w(wstr(text), static_cast<size_t>(text.size()));
        rc = ::RegSetValueExW(k, wstr(name), 0, type == kRegSz ? REG_SZ : REG_EXPAND_SZ,
                              reinterpret_cast<const BYTE*>(w.c_str()),
                              static_cast<DWORD>((w.size() + 1) * sizeof(wchar_t)));
    } else {
        rc = ERROR_INVALID_PARAMETER;   // 不认识的类型绝不写
    }
    if (winerr) *winerr = static_cast<quint32>(rc);
    return rc == ERROR_SUCCESS;
}

bool deleteValue(Hive h, const QString& sub, const QString& name, quint32* winerr) {
    HKEY k = nullptr;
    LONG rc = ::RegOpenKeyExW(rootOf(h), wstr(sub), 0, KEY_SET_VALUE | KEY_WOW64_64KEY, &k);
    if (rc == ERROR_FILE_NOT_FOUND || rc == ERROR_PATH_NOT_FOUND) {
        if (winerr) *winerr = ERROR_SUCCESS;
        return true;
    }
    if (rc != ERROR_SUCCESS) {
        if (winerr) *winerr = static_cast<quint32>(rc);
        return false;
    }
    KeyCloser kc{k};
    rc = ::RegDeleteValueW(k, wstr(name));
    if (winerr) *winerr = static_cast<quint32>(rc);
    return rc == ERROR_SUCCESS || rc == ERROR_FILE_NOT_FOUND;
}

bool createKeyPath(Hive h, const QString& sub, QStringList* createdOut, quint32* winerr) {
    const QStringList parts = sub.split(QLatin1Char('\\'), Qt::SkipEmptyParts);
    QString prefix;
    for (const QString& p : parts) {
        prefix = prefix.isEmpty() ? p : prefix + QLatin1Char('\\') + p;
        HKEY k = nullptr;
        DWORD disp = 0;
        const LONG rc = ::RegCreateKeyExW(rootOf(h), wstr(prefix), 0, nullptr,
                                          REG_OPTION_NON_VOLATILE,
                                          KEY_WRITE | KEY_WOW64_64KEY, nullptr, &k, &disp);
        if (rc != ERROR_SUCCESS) {
            if (winerr) *winerr = static_cast<quint32>(rc);
            return false;
        }
        ::RegCloseKey(k);
        if (disp == REG_CREATED_NEW_KEY && createdOut)
            *createdOut << prefix;
    }
    if (winerr) *winerr = ERROR_SUCCESS;
    return true;
}

bool deleteKeyIfEmpty(Hive h, const QString& sub) {
    if (!keyExists(h, sub))
        return true;
    if (!values(h, sub).isEmpty() || !subKeys(h, sub).isEmpty())
        return false;
    return ::RegDeleteKeyExW(rootOf(h), wstr(sub), KEY_WOW64_64KEY, 0) == ERROR_SUCCESS;
}

QStringList interactiveUserSids() {
    QStringList out;
    for (const QString& s : subKeys(Hive::Users, QString())) {
        if (s.endsWith(QStringLiteral("_Classes"), Qt::CaseInsensitive))
            continue;
        if (s.startsWith(QStringLiteral("S-1-5-21-")) || s.startsWith(QStringLiteral("S-1-12-1-")))
            out << s;
    }
    return out;
}

}
