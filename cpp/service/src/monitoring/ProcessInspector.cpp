#include "bulwark/service/monitoring/ProcessInspector.h"
#include "bulwark/service/monitoring/RevocationGate.h"
#include "bulwark/service/Logger.h"

#include <QByteArray>
#include <QFile>
#include <QFileInfo>
#include <QCryptographicHash>
#include <QDir>
#include <QHash>
#include <QMutex>
#include <QMutexLocker>
#include <QSet>
#include <QVector>

#include <cstring>
#include <utility>

#define CERT_CHAIN_PARA_HAS_EXTRA_FIELDS
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <sddl.h>
#include <wincrypt.h>
#include <wintrust.h>
#include <softpub.h>
#include <mscat.h>
#include <tlhelp32.h>
#include <appmodel.h>

#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "crypt32.lib")

using namespace bulwark::service::monitoring;

namespace {

QDateTime fileTimeToQDateTime(const FILETIME& ft)
{
    ULARGE_INTEGER u;
    u.LowPart = ft.dwLowDateTime;
    u.HighPart = ft.dwHighDateTime;
    if (u.QuadPart == 0)
        return QDateTime();
    constexpr quint64 kEpochDiffMs = 11644473600000ULL;
    const qint64 ms = static_cast<qint64>(u.QuadPart / 10000ULL) - static_cast<qint64>(kEpochDiffMs);
    return QDateTime::fromMSecsSinceEpoch(ms, QTimeZone::UTC);
}

QString fileIdentity(const QString& path)
{
    if (path.trimmed().isEmpty())
        return QString();
    const HANDLE file = ::CreateFileW(
        reinterpret_cast<const wchar_t*>(path.utf16()), FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE)
        return QString(); // 取不到稳定身份时禁用缓存，宁可重算也不复用陈旧结论。

    BY_HANDLE_FILE_INFORMATION info{};
    const bool ok = ::GetFileInformationByHandle(file, &info) != FALSE;
    ::CloseHandle(file);
    if (!ok || (info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY))
        return QString();

    ULARGE_INTEGER fileIndex{};
    fileIndex.HighPart = info.nFileIndexHigh;
    fileIndex.LowPart = info.nFileIndexLow;
    ULARGE_INTEGER size{};
    size.HighPart = info.nFileSizeHigh;
    size.LowPart = info.nFileSizeLow;
    ULARGE_INTEGER writeTime{};
    writeTime.HighPart = info.ftLastWriteTime.dwHighDateTime;
    writeTime.LowPart = info.ftLastWriteTime.dwLowDateTime;

    return QDir::cleanPath(path).toLower() + QLatin1Char('|')
        + QString::number(info.dwVolumeSerialNumber, 16) + QLatin1Char('|')
        + QString::number(fileIndex.QuadPart, 16) + QLatin1Char('|')
        + QString::number(size.QuadPart) + QLatin1Char('|')
        + QString::number(writeTime.QuadPart);
}

constexpr int kCacheCapacity = 8192;
QMutex g_cacheMx;

template <typename T>
struct FactCache {
    QHash<QString, T> hot;
    QHash<QString, T> cold;
};

template <typename T>
void insertHotLocked(FactCache<T>& store, const QString& id, const T& value)
{
    if (store.hot.size() >= kCacheCapacity) {
        store.cold = std::move(store.hot);
        store.hot.clear();
    }
    store.hot.insert(id, value);
}

template <typename T, typename F>
T cachedFactById(FactCache<T>& store, const QString& id, F compute)
{
    if (id.isEmpty())
        return compute();
    {
        QMutexLocker lk(&g_cacheMx);
        const auto h = store.hot.constFind(id);
        if (h != store.hot.constEnd())
            return h.value();
        const auto c = store.cold.find(id);
        if (c != store.cold.end()) {
            const T v = c.value();
            store.cold.erase(c);
            insertHotLocked(store, id, v);
            return v;
        }
    }
    T value = compute(); // 在锁外计算,避免长 I/O 持锁;竞态下重复计算无害
    {
        QMutexLocker lk(&g_cacheMx);
        insertHotLocked(store, id, value);
    }
    return value;
}

template <typename T, typename F>
T cachedFact(FactCache<T>& store, const QString& path, F compute)
{
    return cachedFactById(store, fileIdentity(path), compute);
}

const wchar_t* wcstr(const QString& s)
{
    return reinterpret_cast<const wchar_t*>(s.utf16());
}

}

namespace {

constexpr DWORD kWinTrustProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL;

long embeddedSignatureStatusRaw(const QString& path)
{
    WINTRUST_FILE_INFO fileInfo;
    ZeroMemory(&fileInfo, sizeof(fileInfo));
    fileInfo.cbStruct = sizeof(fileInfo);
    fileInfo.pcwszFilePath = wcstr(path);

    GUID actionGuid = WINTRUST_ACTION_GENERIC_VERIFY_V2;

    WINTRUST_DATA data;
    ZeroMemory(&data, sizeof(data));
    data.cbStruct = sizeof(data);
    data.dwUIChoice = WTD_UI_NONE;
    data.fdwRevocationChecks = WTD_REVOKE_NONE;
    data.dwUnionChoice = WTD_CHOICE_FILE;
    data.pFile = &fileInfo;
    data.dwStateAction = WTD_STATEACTION_VERIFY;
    data.dwProvFlags = kWinTrustProvFlags;

    const LONG status = WinVerifyTrust(static_cast<HWND>(INVALID_HANDLE_VALUE), &actionGuid, &data);

    data.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(static_cast<HWND>(INVALID_HANDLE_VALUE), &actionGuid, &data);

    return static_cast<long>(status);
}

// 塌缩成可信 / 不可信。必须复用上面同一份验证,否则威胁判定与更新准入可能对同一文件得出不同结论。
bool verifyEmbeddedSignature(const QString& path)
{
    return embeddedSignatureStatusRaw(path) == ERROR_SUCCESS;
}

bool verifyCatalogSignature(const QString& path)
{
    HANDLE hFile = CreateFileW(wcstr(path), GENERIC_READ,
                               FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                               nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE)
        return false;

    bool trusted = false;
    HCATADMIN hCatAdmin = nullptr;
    GUID driverAction = DRIVER_ACTION_VERIFY;

    if (CryptCATAdminAcquireContext2(&hCatAdmin, &driverAction, BCRYPT_SHA256_ALGORITHM, nullptr, 0)) {
        DWORD hashLen = 0;
        CryptCATAdminCalcHashFromFileHandle2(hCatAdmin, hFile, &hashLen, nullptr, 0);
        if (hashLen > 0) {
            QByteArray hash(static_cast<int>(hashLen), '\0');
            if (CryptCATAdminCalcHashFromFileHandle2(
                    hCatAdmin, hFile, &hashLen, reinterpret_cast<BYTE*>(hash.data()), 0)) {
                HCATINFO hCatInfo = CryptCATAdminEnumCatalogFromHash(
                    hCatAdmin, reinterpret_cast<BYTE*>(hash.data()), hashLen, 0, nullptr);
                if (hCatInfo) {
                    CATALOG_INFO catalog{};
                    catalog.cbStruct = sizeof(catalog);
                    if (CryptCATCatalogInfoFromContext(hCatInfo, &catalog, 0)) {
                        const std::wstring memberTag =
                            QString::fromLatin1(hash.toHex().toUpper()).toStdWString();
                        const std::wstring memberPath = path.toStdWString();
                        WINTRUST_CATALOG_INFO catalogTrust{};
                        catalogTrust.cbStruct = sizeof(catalogTrust);
                        catalogTrust.pcwszCatalogFilePath = catalog.wszCatalogFile;
                        catalogTrust.pcwszMemberTag = memberTag.c_str();
                        catalogTrust.pcwszMemberFilePath = memberPath.c_str();
                        catalogTrust.hMemberFile = hFile;
                        catalogTrust.pbCalculatedFileHash =
                            reinterpret_cast<BYTE*>(hash.data());
                        catalogTrust.cbCalculatedFileHash = hashLen;
                        catalogTrust.hCatAdmin = hCatAdmin;

                        WINTRUST_DATA data{};
                        data.cbStruct = sizeof(data);
                        data.dwUIChoice = WTD_UI_NONE;
                        data.fdwRevocationChecks = WTD_REVOKE_NONE;
                        data.dwUnionChoice = WTD_CHOICE_CATALOG;
                        data.pCatalog = &catalogTrust;
                        data.dwStateAction = WTD_STATEACTION_VERIFY;
                        data.dwProvFlags = kWinTrustProvFlags;
                        GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
                        const LONG status = ::WinVerifyTrust(
                            static_cast<HWND>(INVALID_HANDLE_VALUE), &action, &data);
                        trusted = status == ERROR_SUCCESS;
                        data.dwStateAction = WTD_STATEACTION_CLOSE;
                        ::WinVerifyTrust(static_cast<HWND>(INVALID_HANDLE_VALUE), &action, &data);
                    }
                    CryptCATAdminReleaseCatalogContext(hCatAdmin, hCatInfo, 0);
                }
            }
        }
        CryptCATAdminReleaseContext(hCatAdmin, 0);
    }

    CloseHandle(hFile);
    return trusted;
}

struct AppModelApi {
    using FnStagedOrigin   = LONG (WINAPI*)(PCWSTR, PackageOrigin*);
    using FnIdFromFullName = LONG (WINAPI*)(PCWSTR, UINT32, UINT32*, BYTE*);
    using FnPathByFullName = LONG (WINAPI*)(PCWSTR, UINT32*, PWSTR);

    FnStagedOrigin   stagedOrigin   = nullptr;
    FnIdFromFullName idFromFullName = nullptr;
    FnPathByFullName pathByFullName = nullptr;

    AppModelApi()
    {
        static const wchar_t* const kMods[] = {
            L"kernelbase.dll",
            L"api-ms-win-appmodel-runtime-l1-1-1.dll",
            L"kernel32.dll",
        };
        for (const wchar_t* m : kMods) {
            HMODULE h = ::GetModuleHandleW(m);
            if (h == nullptr)
                h = ::LoadLibraryExW(m, nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);
            if (h == nullptr)
                continue;
            if (!stagedOrigin)
                stagedOrigin = reinterpret_cast<FnStagedOrigin>(
                    ::GetProcAddress(h, "GetStagedPackageOrigin"));
            if (!idFromFullName)
                idFromFullName = reinterpret_cast<FnIdFromFullName>(
                    ::GetProcAddress(h, "PackageIdFromFullName"));
            if (!pathByFullName)
                pathByFullName = reinterpret_cast<FnPathByFullName>(
                    ::GetProcAddress(h, "GetPackagePathByFullName"));
            if (ok())
                break;
        }
    }

    bool ok() const { return stagedOrigin && idFromFullName && pathByFullName; }
};

const AppModelApi& appModel()
{
    static const AppModelApi api;
    return api;
}

QString toBackslashLower(const QString& p)
{
    QString s = p;
    s.replace(QLatin1Char('/'), QLatin1Char('\\'));
    return s.toLower();
}

QString msixPackageFullNameFromPath(const QString& path)
{
    static const QString kMarker = QStringLiteral("\\program files\\windowsapps\\");
    const QString lower = toBackslashLower(path);
    if (lower.size() < 2 || lower.at(1) != QLatin1Char(':'))
        return QString();
    if (!QStringView(lower).mid(2).startsWith(kMarker))
        return QString();
    const int start = 2 + kMarker.size();
    const int end = lower.indexOf(QLatin1Char('\\'), start);
    if (end <= start)
        return QString();
    QString norm = path;
    norm.replace(QLatin1Char('/'), QLatin1Char('\\'));
    return norm.mid(start, end - start);
}

QString msixPackagePublisher(const QString& packageFullName)
{
    const AppModelApi& api = appModel();
    if (!api.ok() || packageFullName.isEmpty())
        return QString();

    UINT32 cb = 0;
    if (api.idFromFullName(wcstr(packageFullName), PACKAGE_INFORMATION_FULL, &cb, nullptr)
            != ERROR_INSUFFICIENT_BUFFER || cb == 0)
        return QString();
    QByteArray buf(static_cast<int>(cb), '\0');
    if (api.idFromFullName(wcstr(packageFullName), PACKAGE_INFORMATION_FULL, &cb,
                           reinterpret_cast<BYTE*>(buf.data())) != ERROR_SUCCESS)
        return QString();

    const PACKAGE_ID* id = reinterpret_cast<const PACKAGE_ID*>(buf.constData());
    return id->publisher ? QString::fromWCharArray(id->publisher) : QString();
}

bool verifyMsixPackageSignature(const QString& path, QString* packageFullNameOut = nullptr)
{
    const QString pfn = msixPackageFullNameFromPath(path);
    if (pfn.isEmpty())
        return false;

    const AppModelApi& api = appModel();
    if (!api.ok())
        return false;

    PackageOrigin origin = PackageOrigin_Unknown;
    if (api.stagedOrigin(wcstr(pfn), &origin) != ERROR_SUCCESS)
        return false;
    if (origin != PackageOrigin_Store && origin != PackageOrigin_Inbox)
        return false;

    // 判据 ③:包根必须是该文件真实路径的前缀。
    UINT32 cch = 0;
    if (api.pathByFullName(wcstr(pfn), &cch, nullptr) != ERROR_INSUFFICIENT_BUFFER || cch == 0)
        return false;
    QVector<wchar_t> rootBuf(static_cast<int>(cch));
    if (api.pathByFullName(wcstr(pfn), &cch, rootBuf.data()) != ERROR_SUCCESS)
        return false;

    QString root = toBackslashLower(QString::fromWCharArray(rootBuf.data()));
    while (root.endsWith(QLatin1Char('\\')))
        root.chop(1);
    if (root.isEmpty())
        return false;

    const QString real = toBackslashLower(QFileInfo(path).canonicalFilePath());
    if (real.isEmpty() || !real.startsWith(root + QLatin1Char('\\')))
        return false;

    if (packageFullNameOut)
        *packageFullNameOut = pfn;
    return true;
}

PCCERT_CONTEXT acquireSignerCert(const QString& path)
{
    HCERTSTORE hStore = nullptr;
    HCRYPTMSG  hMsg = nullptr;
    if (!CryptQueryObject(CERT_QUERY_OBJECT_FILE, wcstr(path),
                          CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
                          CERT_QUERY_FORMAT_FLAG_BINARY, 0,
                          nullptr, nullptr, nullptr, &hStore, &hMsg, nullptr)) {
        return nullptr;
    }

    PCCERT_CONTEXT result = nullptr;
    DWORD cb = 0;
    if (CryptMsgGetParam(hMsg, CMSG_SIGNER_CERT_INFO_PARAM, 0, nullptr, &cb) && cb > 0) {
        QByteArray buf(static_cast<int>(cb), '\0');
        if (CryptMsgGetParam(hMsg, CMSG_SIGNER_CERT_INFO_PARAM, 0, buf.data(), &cb)) {
            CERT_INFO* ci = reinterpret_cast<CERT_INFO*>(buf.data());
            PCCERT_CONTEXT found = CertFindCertificateInStore(
                hStore, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 0,
                CERT_FIND_SUBJECT_CERT, ci, nullptr);
            if (found) {
                result = CertDuplicateCertificateContext(found);
                CertFreeCertificateContext(found);
            }
        }
    }

    if (hMsg) CryptMsgClose(hMsg);
    if (hStore) CertCloseStore(hStore, 0);
    return result;
}

bool findSigningTime(const CRYPT_ATTRIBUTES& attrs, QDateTime& out)
{
    for (DWORD i = 0; i < attrs.cAttr; ++i) {
        const CRYPT_ATTRIBUTE& a = attrs.rgAttr[i];
        if (a.pszObjId == nullptr || strcmp(a.pszObjId, szOID_RSA_signingTime) != 0)
            continue;
        if (a.cValue == 0)
            continue;
        FILETIME ft{};
        DWORD cb = sizeof(ft);
        if (CryptDecodeObject(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, szOID_RSA_signingTime,
                              a.rgValue[0].pbData, a.rgValue[0].cbData, 0, &ft, &cb)) {
            const QDateTime dt = fileTimeToQDateTime(ft);
            if (dt.isValid()) {
                out = dt;
                return true;
            }
        }
    }
    return false;
}

#ifndef szOID_RFC3161_counterSign
#define szOID_RFC3161_counterSign "1.3.6.1.4.1.311.3.3.1"
#endif

struct SigningTimeFact {
    QDateTime time;
    bool trusted = false;
};

bool plausibleSigningTime(const QDateTime& dt)
{
    if (!dt.isValid())
        return false;
    if (dt.date().year() < 1990)
        return false;
    return dt <= QDateTime::currentDateTimeUtc().addDays(1);
}

bool rfc3161GenTime(const CRYPT_ATTRIBUTE& attr, QDateTime& out)
{
    if (attr.cValue == 0)
        return false;
    PCRYPT_TIMESTAMP_CONTEXT ctx = nullptr;
    if (!CryptVerifyTimeStampSignature(attr.rgValue[0].pbData, attr.rgValue[0].cbData,
                                       nullptr, 0, nullptr, &ctx, nullptr, nullptr)) {
        return false;
    }
    bool ok = false;
    if (ctx != nullptr) {
        if (ctx->pTimeStamp != nullptr) {
            const QDateTime dt = fileTimeToQDateTime(ctx->pTimeStamp->ftTime);
            if (dt.isValid()) {
                out = dt;
                ok = true;
            }
        }
        CryptMemFree(ctx);
    }
    return ok;
}

bool legacyCounterSignTime(const CRYPT_ATTRIBUTE& attr, QDateTime& out)
{
    if (attr.cValue == 0)
        return false;
    DWORD cb = 0;
    if (!CryptDecodeObject(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, PKCS7_SIGNER_INFO,
                           attr.rgValue[0].pbData, attr.rgValue[0].cbData, 0, nullptr, &cb)
        || cb == 0) {
        return false;
    }
    QByteArray buf(static_cast<int>(cb), '\0');
    if (!CryptDecodeObject(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, PKCS7_SIGNER_INFO,
                           attr.rgValue[0].pbData, attr.rgValue[0].cbData, 0, buf.data(), &cb)) {
        return false;
    }
    CMSG_SIGNER_INFO* cs = reinterpret_cast<CMSG_SIGNER_INFO*>(buf.data());
    return findSigningTime(cs->AuthAttrs, out);
}

SigningTimeFact computeSigningTime(const QString& path)
{
    SigningTimeFact fact;

    HCERTSTORE hStore = nullptr;
    HCRYPTMSG  hMsg = nullptr;
    if (!CryptQueryObject(CERT_QUERY_OBJECT_FILE, wcstr(path),
                          CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
                          CERT_QUERY_FORMAT_FLAG_BINARY, 0,
                          nullptr, nullptr, nullptr, &hStore, &hMsg, nullptr)) {
        return fact;
    }

    DWORD cb = 0;
    if (CryptMsgGetParam(hMsg, CMSG_SIGNER_INFO_PARAM, 0, nullptr, &cb) && cb > 0) {
        QByteArray buf(static_cast<int>(cb), '\0');
        if (CryptMsgGetParam(hMsg, CMSG_SIGNER_INFO_PARAM, 0, buf.data(), &cb)) {
            CMSG_SIGNER_INFO* si = reinterpret_cast<CMSG_SIGNER_INFO*>(buf.data());

            for (DWORD i = 0; i < si->UnauthAttrs.cAttr && !fact.trusted; ++i) {
                const CRYPT_ATTRIBUTE& a = si->UnauthAttrs.rgAttr[i];
                if (a.pszObjId == nullptr)
                    continue;
                QDateTime t;
                if (strcmp(a.pszObjId, szOID_RFC3161_counterSign) == 0) {
                    if (rfc3161GenTime(a, t) && plausibleSigningTime(t)) {
                        fact.time = t;
                        fact.trusted = true;
                    }
                } else if (strcmp(a.pszObjId, szOID_RSA_counterSign) == 0) {
                    if (legacyCounterSignTime(a, t) && plausibleSigningTime(t)) {
                        fact.time = t;
                        fact.trusted = true;
                    }
                }
            }

            if (!fact.trusted) {
                QDateTime t;
                if (findSigningTime(si->AuthAttrs, t) && plausibleSigningTime(t))
                    fact.time = t;
            }
        }
    }

    if (hMsg) CryptMsgClose(hMsg);
    if (hStore) CertCloseStore(hStore, 0);
    return fact;
}

bool localCachedRevoked(PCCERT_CONTEXT cert)
{
    CERT_CHAIN_PARA para;
    ZeroMemory(&para, sizeof(para));
    para.cbSize = sizeof(para);

    const DWORD flags = CERT_CHAIN_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT
                      | CERT_CHAIN_REVOCATION_CHECK_CACHE_ONLY
                      | CERT_CHAIN_CACHE_ONLY_URL_RETRIEVAL;

    PCCERT_CHAIN_CONTEXT chain = nullptr;
    if (!CertGetCertificateChain(nullptr, cert, nullptr, cert->hCertStore, &para, flags, nullptr, &chain))
        return false;

    bool revoked = false;
    if (chain) {
        revoked = (chain->TrustStatus.dwErrorStatus & CERT_TRUST_IS_REVOKED) != 0;
        CertFreeCertificateChain(chain);
    }
    return revoked;
}

constexpr DWORD kOnlineRevocationTimeoutMs = 4000;

RevocationGate::Outcome onlineRevocationLookup(PCCERT_CONTEXT cert)
{
    RevocationGate::Outcome out;
    CERT_CHAIN_PARA para;
    ZeroMemory(&para, sizeof(para));
    para.cbSize = sizeof(para);
    para.dwUrlRetrievalTimeout = kOnlineRevocationTimeoutMs;

    const DWORD flags = CERT_CHAIN_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT
                      | CERT_CHAIN_REVOCATION_ACCUMULATIVE_TIMEOUT;

    PCCERT_CHAIN_CONTEXT chain = nullptr;
    if (!CertGetCertificateChain(nullptr, cert, nullptr, cert->hCertStore, &para, flags, nullptr, &chain) || !chain)
        return out;
    const DWORD st = chain->TrustStatus.dwErrorStatus;
    CertFreeCertificateChain(chain);

    if (st & CERT_TRUST_IS_REVOKED) {
        out.verdict = RevocationGate::Verdict::Revoked;
        out.unreachable = false;
    } else if (st & CERT_TRUST_IS_OFFLINE_REVOCATION) {
    } else {
        out.verdict = RevocationGate::Verdict::Good;
        out.unreachable = false;
    }
    return out;
}

RevocationGate& revocationGate()
{
    static RevocationGate* const gate = [] {
        auto* g = new RevocationGate();
        g->setLateHook([](const QString& thumb) {
            static const bulwark::service::Logger lg(QStringLiteral("ProcessInspector"));
            lg.warning(QStringLiteral("证书吊销校验:调用方已放手之后才返回的结论=已吊销(签名证书 SHA-1 %1)。"
                                      "已写入吊销缓存,此后同一张证书签名的文件会按『证书已吊销』处理。").arg(thumb));
        });
        g->setNoticeHook([](RevocationGate::Notice n) {
            static const bulwark::service::Logger lg(QStringLiteral("ProcessInspector"));
            switch (n) {
            case RevocationGate::Notice::BreakerOpened:
                lg.warning(QStringLiteral("证书吊销在线校验熔断:连续多次没能问到 CA(离线 / 超时)。"
                                          "接下来 10 分钟只读本机缓存 CRL,不再联网;到期后放行一个探测。"));
                break;
            case RevocationGate::Notice::BreakerReopened:
                lg.warning(QStringLiteral("证书吊销在线校验:探测仍然失败,熔断继续 10 分钟。"));
                break;
            case RevocationGate::Notice::BreakerClosed:
                lg.info(QStringLiteral("证书吊销在线校验:探测成功,熔断解除,恢复联网校验。"));
                break;
            }
        });
        return g;
    }();
    return *gate;
}

bool computeCertRevoked(PCCERT_CONTEXT cert, const QString& thumbprint)
{
    if (!cert)
        return false;

    if (localCachedRevoked(cert))
        return true;
    if (!ProcessInspector::onlineRevocationCheck || thumbprint.isEmpty())
        return false;

    PCCERT_CONTEXT dup = CertDuplicateCertificateContext(cert);
    if (!dup)
        return false;
    const std::shared_ptr<const CERT_CONTEXT> held(
        dup, [](const CERT_CONTEXT* c) { CertFreeCertificateContext(c); });
    const auto verdict = revocationGate().query(
        thumbprint,
        [held]() -> RevocationGate::Outcome { return onlineRevocationLookup(held.get()); },
        ProcessInspector::onlineRevocationBudgetMs);
    return verdict == RevocationGate::Verdict::Revoked;
}

void overlayKnownRevoked(ProcessInspector::CertInfo& info)
{
    if (!info.revoked && ProcessInspector::onlineRevocationCheck && !info.thumbprint.isEmpty()
        && revocationGate().isKnownRevoked(info.thumbprint))
        info.revoked = true;
}

}

namespace {

FactCache<bool>    g_signedCache;
FactCache<QString> g_publisherCache;
FactCache<QString> g_sha256Cache;
FactCache<bool>    g_embeddedCache;
FactCache<bool>    g_digestMismatchCache;
FactCache<ProcessInspector::CertInfo> g_certCache;

bool computeIsSigned(const QString& path)
{
    if (path.isEmpty() || path.startsWith(QLatin1String("PID "), Qt::CaseInsensitive))
        return false;
    if (verifyEmbeddedSignature(path))
        return true;
    if (verifyCatalogSignature(path))
        return true;
    return verifyMsixPackageSignature(path);
}

QString computePublisher(const QString& path)
{
    PCCERT_CONTEXT cert = acquireSignerCert(path);
    if (!cert) {
        QString pfn;
        if (verifyMsixPackageSignature(path, &pfn))
            return msixPackagePublisher(pfn);
        return QString();
    }
    QString publisher;
    const DWORD cch = CertGetNameStringW(cert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, nullptr, nullptr, 0);
    if (cch > 1) {
        QVector<wchar_t> buf(static_cast<int>(cch));
        if (CertGetNameStringW(cert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, nullptr, buf.data(), cch) > 1)
            publisher = QString::fromWCharArray(buf.data());
    }
    CertFreeCertificateContext(cert);
    return publisher;
}

QString computeSha256(const QString& path)
{
    if (path.isEmpty())
        return QString();
    QFileInfo fi(path);
    if (!fi.exists() || !fi.isFile())
        return QString();
    constexpr qint64 kMaxBytes = 256LL * 1024 * 1024;
    if (fi.size() > kMaxBytes)
        return QString();
    QFile f(path);
    if (!f.open(QIODevice::ReadOnly))
        return QString();
    QCryptographicHash h(QCryptographicHash::Sha256);
    if (!h.addData(&f))
        return QString();
    // 大写十六进制,与 FirstSeenStore 的归一化保持一致。
    return QString::fromLatin1(h.result().toHex().toUpper());
}

bool computeHasEmbeddedSignature(const QString& path)
{
    if (path.isEmpty())
        return false;
    HCERTSTORE hStore = nullptr;
    HCRYPTMSG  hMsg = nullptr;
    const bool ok = CryptQueryObject(CERT_QUERY_OBJECT_FILE, wcstr(path),
                                     CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
                                     CERT_QUERY_FORMAT_FLAG_BINARY, 0,
                                     nullptr, nullptr, nullptr, &hStore, &hMsg, nullptr);
    if (hMsg) CryptMsgClose(hMsg);
    if (hStore) CertCloseStore(hStore, 0);
    return ok;
}

bool computeSignatureDigestMismatch(const QString& path)
{
    if (path.isEmpty())
        return false;
    return embeddedSignatureStatusRaw(path) == static_cast<long>(TRUST_E_BAD_DIGEST);
}

ProcessInspector::CertInfo computeCertInfo(const QString& path)
{
    ProcessInspector::CertInfo info;
    PCCERT_CONTEXT cert = acquireSignerCert(path);
    if (!cert)
        return info;

    BYTE thumb[20];
    DWORD cb = sizeof(thumb);
    if (CertGetCertificateContextProperty(cert, CERT_SHA1_HASH_PROP_ID, thumb, &cb)) {
        info.thumbprint = QString::fromLatin1(
            QByteArray(reinterpret_cast<char*>(thumb), static_cast<int>(cb)).toHex().toUpper());
    }

    info.notBeforeUtc = fileTimeToQDateTime(cert->pCertInfo->NotBefore);
    info.notAfterUtc  = fileTimeToQDateTime(cert->pCertInfo->NotAfter);

    const SigningTimeFact st = computeSigningTime(path);
    info.signingTimeUtc = st.time;

    if (st.trusted && st.time.isValid() && info.notAfterUtc.isValid() && info.notBeforeUtc.isValid()) {
        if (st.time > info.notAfterUtc.addDays(1) || st.time < info.notBeforeUtc.addDays(-1))
            info.signedAfterCertExpiry = true;
    }

    info.revoked = computeCertRevoked(cert, info.thumbprint);
    CertFreeCertificateContext(cert);
    return info;
}

}

bool ProcessInspector::isSigned(const QString& path)
{
    return cachedFact(g_signedCache, path, [&] { return computeIsSigned(path); });
}

QString ProcessInspector::tryGetPublisher(const QString& path)
{
    return cachedFact(g_publisherCache, path, [&] { return computePublisher(path); });
}

QString ProcessInspector::tryGetSignerThumbprint(const QString& path)
{
    PCCERT_CONTEXT cert = acquireSignerCert(path);
    if (!cert)
        return QString();
    QString thumb;
    BYTE hash[20];
    DWORD cb = sizeof(hash);
    if (CertGetCertificateContextProperty(cert, CERT_SHA1_HASH_PROP_ID, hash, &cb)) {
        thumb = QString::fromLatin1(
            QByteArray(reinterpret_cast<char*>(hash), static_cast<int>(cb)).toHex().toUpper());
    }
    CertFreeCertificateContext(cert);
    return thumb;
}

QString ProcessInspector::tryComputeSha256(const QString& path)
{
    return cachedFact(g_sha256Cache, path, [&] { return computeSha256(path); });
}

bool ProcessInspector::hasEmbeddedSignature(const QString& path)
{
    return cachedFact(g_embeddedCache, path, [&] { return computeHasEmbeddedSignature(path); });
}

ProcessInspector::ForensicFacts
ProcessInspector::collectForensics(const QString& path, bool includeCert)
{
    ForensicFacts f;
    if (path.isEmpty() || path.startsWith(QLatin1String("PID "), Qt::CaseInsensitive))
        return f;

    const QFileInfo fi(path);
    f.isRealFile = fi.exists() && fi.isFile();
    const QString id = f.isRealFile ? fileIdentity(path) : QString();
    if (f.isRealFile)
        f.fileSize = fi.size();

    f.trustedSignature =
        cachedFactById(g_signedCache, id, [&] { return computeIsSigned(path); });
    f.publisher =
        cachedFactById(g_publisherCache, id, [&] { return computePublisher(path); });
    f.sha256 =
        cachedFactById(g_sha256Cache, id, [&] { return computeSha256(path); });
    if (!f.trustedSignature) {
        f.embeddedSignature =
            cachedFactById(g_embeddedCache, id, [&] { return computeHasEmbeddedSignature(path); });
        if (f.embeddedSignature)
            f.signatureDigestMismatch = cachedFactById(
                g_digestMismatchCache, id, [&] { return computeSignatureDigestMismatch(path); });
    }
    if (includeCert) {
        f.cert = cachedFactById(g_certCache, id, [&] { return computeCertInfo(path); });
        overlayKnownRevoked(f.cert);
    }
    return f;
}

bool ProcessInspector::isSignatureMismatch(const QString& path)
{
    return hasEmbeddedSignature(path) && !isSigned(path);
}

ProcessInspector::CertInfo ProcessInspector::getCertInfo(const QString& path)
{
    CertInfo info = cachedFact(g_certCache, path, [&] { return computeCertInfo(path); });
    overlayKnownRevoked(info);
    return info;
}

namespace {

using NtQipFn = LONG(WINAPI*)(HANDLE, ULONG, PVOID, ULONG, PULONG);

NtQipFn resolveNtQip()
{
    static NtQipFn fn = []() -> NtQipFn {
        HMODULE nt = GetModuleHandleW(L"ntdll.dll");
        return nt ? reinterpret_cast<NtQipFn>(GetProcAddress(nt, "NtQueryInformationProcess")) : nullptr;
    }();
    return fn;
}

struct ProcBasicInfo {
    void* ExitStatus;
    void* PebBaseAddress;
    void* AffinityMask;
    void* BasePriority;
    void* UniqueProcessId;
    void* InheritedFromUniqueProcessId;
};
constexpr ULONG kProcessBasicInformation = 0;
constexpr ULONG kProcessWow64Information = 26;

bool readRemote(HANDLE h, const void* addr, void* buf, SIZE_T size)
{
    SIZE_T got = 0;
    return ReadProcessMemory(h, addr, buf, size, &got) && got == size;
}

QString readProcessParameterString(HANDLE process, NtQipFn ntqip,
                                   size_t nativeOffset, size_t wow64Offset)
{
    quint64 bufferAddress = 0;
    unsigned short length = 0;
    ULONG retLen = 0;
    ULONG_PTR wow64Peb = 0;
    if (ntqip(process, kProcessWow64Information, &wow64Peb,
              sizeof(wow64Peb), &retLen) == 0 && wow64Peb != 0) {
        quint32 params32 = 0;
        if (!readRemote(process, reinterpret_cast<const void*>(wow64Peb + 0x10),
                        &params32, sizeof(params32)) || params32 == 0)
            return {};
        struct UnicodeString32 {
            unsigned short length;
            unsigned short maximumLength;
            quint32 buffer;
        } value{};
        if (!readRemote(process,
                        reinterpret_cast<const void*>(static_cast<quintptr>(params32) + wow64Offset),
                        &value, sizeof(value)))
            return {};
        length = value.length;
        bufferAddress = value.buffer;
    } else {
        ProcBasicInfo pbi{};
        if (ntqip(process, kProcessBasicInformation, &pbi, sizeof(pbi), &retLen) != 0
            || !pbi.PebBaseAddress)
            return {};
        void* params = nullptr;
        const char* paramsAddress = reinterpret_cast<const char*>(pbi.PebBaseAddress) + 0x20;
        if (!readRemote(process, paramsAddress, &params, sizeof(params)) || !params)
            return {};
        struct UnicodeString64 {
            unsigned short length;
            unsigned short maximumLength;
            quint32 padding;
            quint64 buffer;
        } value{};
        if (!readRemote(process, reinterpret_cast<const char*>(params) + nativeOffset,
                        &value, sizeof(value)))
            return {};
        length = value.length;
        bufferAddress = value.buffer;
    }

    if (length == 0 || length > 0x8000 || (length & 1u) != 0 || bufferAddress == 0)
        return {};
    QByteArray raw(length, '\0');
    if (!readRemote(process, reinterpret_cast<const void*>(bufferAddress), raw.data(), length))
        return {};
    QString result = QString::fromWCharArray(
        reinterpret_cast<const wchar_t*>(raw.constData()), length / 2);
    while (result.endsWith(QChar(u'\0')))
        result.chop(1);
    return result;
}

}

QString ProcessInspector::tryGetProcessImagePath(int pid)
{
    if (pid <= 0)
        return QString();
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, static_cast<DWORD>(pid));
    if (!h)
        return QString();
    QString result;
    wchar_t buf[MAX_PATH * 2];
    DWORD size = static_cast<DWORD>(std::size(buf));
    if (QueryFullProcessImageNameW(h, 0, buf, &size) && size > 0)
        result = QString::fromWCharArray(buf, static_cast<int>(size));
    CloseHandle(h);
    return result;
}

std::optional<ProcessInspector::ProcessInstance> ProcessInspector::tryGetProcessInstance(int pid)
{
    if (pid <= 4)
        return std::nullopt;

    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, static_cast<DWORD>(pid));
    if (!h)
        return std::nullopt;

    ProcessInstance instance;
    instance.pid = pid;
    wchar_t image[MAX_PATH * 2] = {};
    DWORD imageSize = static_cast<DWORD>(std::size(image));
    FILETIME create{}, exit{}, kernel{}, user{};
    if (QueryFullProcessImageNameW(h, 0, image, &imageSize) && imageSize > 0
        && GetProcessTimes(h, &create, &exit, &kernel, &user)) {
        ULARGE_INTEGER value{};
        value.LowPart = create.dwLowDateTime;
        value.HighPart = create.dwHighDateTime;
        instance.creationFileTime = value.QuadPart;
        instance.imagePath = QString::fromWCharArray(image, static_cast<int>(imageSize));
    }
    CloseHandle(h);

    if (!instance.isUsable())
        return std::nullopt;
    return instance;
}

QList<int> ProcessInspector::enumeratePids()
{
    QList<int> pids;
    HANDLE snap = ::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE)
        return pids;
    PROCESSENTRY32W pe;
    ZeroMemory(&pe, sizeof(pe));
    pe.dwSize = sizeof(pe);
    if (::Process32FirstW(snap, &pe)) {
        do {
            if (pe.th32ProcessID > 4)
                pids.append(static_cast<int>(pe.th32ProcessID));
        } while (::Process32NextW(snap, &pe));
    }
    ::CloseHandle(snap);
    return pids;
}

QString ProcessInspector::tryGetCommandLine(int pid)
{
    if (pid <= 0)
        return QString();
    if constexpr (sizeof(void*) != 8)
        return QString();
    NtQipFn ntqip = resolveNtQip();
    if (!ntqip)
        return QString();

    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, FALSE, static_cast<DWORD>(pid));
    if (!h)
        return QString();

    const QString result = readProcessParameterString(h, ntqip, 0x70, 0x40);
    CloseHandle(h);
    return result;
}

int ProcessInspector::tryGetParentPid(int pid)
{
    if (pid <= 0)
        return 0;
    NtQipFn ntqip = resolveNtQip();
    if (!ntqip)
        return 0;
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, static_cast<DWORD>(pid));
    if (!h)
        return 0;
    int parent = 0;
    ProcBasicInfo pbi{};
    ULONG retLen = 0;
    if (ntqip(h, kProcessBasicInformation, &pbi, sizeof(pbi), &retLen) == 0)
        parent = static_cast<int>(reinterpret_cast<uintptr_t>(pbi.InheritedFromUniqueProcessId));
    CloseHandle(h);
    return parent;
}

namespace {

// 关键系统进程名单(小写),结束它们会触发 0xEF CRITICAL_PROCESS_DIED 蓝屏。
// 必须与 isSystemImageDir 一起用,名字本身不构成豁免理由。
const QSet<QString>& criticalNames()
{
    static const QSet<QString> names = {
        QStringLiteral("system"),       QStringLiteral("smss.exe"),
        QStringLiteral("csrss.exe"),    QStringLiteral("wininit.exe"),
        QStringLiteral("winlogon.exe"), QStringLiteral("services.exe"),
        QStringLiteral("lsass.exe"),    QStringLiteral("lsaiso.exe"),
        QStringLiteral("fontdrvhost.exe")
    };
    return names;
}

bool isSystemImageDir(const QString& path)
{
    QString normalized = QDir::cleanPath(path.trimmed());
    normalized.replace(QLatin1Char('/'), QLatin1Char('\\'));
    normalized = normalized.toLower();

    wchar_t windowsPath[MAX_PATH] = {};
    const UINT chars = ::GetWindowsDirectoryW(windowsPath, MAX_PATH);
    if (chars == 0 || chars >= MAX_PATH)
        return false;
    QString windows = QDir::cleanPath(QString::fromWCharArray(windowsPath, static_cast<int>(chars)));
    windows.replace(QLatin1Char('/'), QLatin1Char('\\'));
    windows = windows.toLower();

    const auto under = [&normalized, &windows](const QString& child) {
        return normalized.startsWith(windows + child + QLatin1Char('\\'));
    };
    return under(QStringLiteral("\\system32"))
        || under(QStringLiteral("\\syswow64"))
        || under(QStringLiteral("\\winsxs"));
}

int queryKernelCritical(int pid)
{
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, static_cast<DWORD>(pid));
    if (!h)
        return -1;
    BOOL critical = FALSE;
    int result = -1;
    if (IsProcessCritical(h, &critical))
        result = critical ? 1 : 0;
    CloseHandle(h);
    return result;
}

quint64 processCreationTime(int pid)
{
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, static_cast<DWORD>(pid));
    if (!h)
        return 0;
    FILETIME create{}, exit{}, kernel{}, user{};
    quint64 result = 0;
    if (GetProcessTimes(h, &create, &exit, &kernel, &user)) {
        ULARGE_INTEGER u;
        u.LowPart = create.dwLowDateTime;
        u.HighPart = create.dwHighDateTime;
        result = u.QuadPart;
    }
    CloseHandle(h);
    return result;
}

QVector<int> collectDescendants(int rootPid)
{
    QVector<int> result;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE)
        return result;

    QHash<int, QVector<int>> childrenByParent;
    PROCESSENTRY32W pe;
    pe.dwSize = sizeof(pe);
    if (Process32FirstW(snap, &pe)) {
        do {
            const int pid = static_cast<int>(pe.th32ProcessID);
            const int ppid = static_cast<int>(pe.th32ParentProcessID);
            if (pid > 4)
                childrenByParent[ppid].push_back(pid);
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);

    const quint64 rootStart = processCreationTime(rootPid);
    QSet<int> visited;
    visited.insert(rootPid);
    QVector<int> queue;
    queue.push_back(rootPid);
    constexpr int kMaxNodes = 4096;

    for (int qi = 0; qi < queue.size() && result.size() < kMaxNodes; ++qi) {
        const int cur = queue[qi];
        auto it = childrenByParent.constFind(cur);
        if (it == childrenByParent.constEnd())
            continue;
        for (int kid : it.value()) {
            if (visited.contains(kid))
                continue;
            visited.insert(kid);
            if (rootStart != 0) {
                const quint64 kidStart = processCreationTime(kid);
                if (kidStart != 0 && kidStart < rootStart)
                    continue;
            }
            result.push_back(kid);
            queue.push_back(kid);
        }
    }
    return result;
}

}

bool ProcessInspector::ensureDebugPrivilege()
{
    static bool s_result = []() -> bool {
        HANDLE token = nullptr;
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token))
            return false;
        LUID luid;
        bool ok = false;
        if (LookupPrivilegeValueW(nullptr, SE_DEBUG_NAME, &luid)) {
            TOKEN_PRIVILEGES tp;
            tp.PrivilegeCount = 1;
            tp.Privileges[0].Luid = luid;
            tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
            AdjustTokenPrivileges(token, FALSE, &tp, sizeof(tp), nullptr, nullptr);
            ok = (GetLastError() == ERROR_SUCCESS);
        }
        CloseHandle(token);
        return ok;
    }();
    return s_result;
}

bool ProcessInspector::isCriticalProcess(int pid)
{
    if (pid <= 4)
        return true;

    const int kernel = queryKernelCritical(pid);
    if (kernel == 1)
        return true;
    if (kernel == -1)
        return true; // fail-safe:无法确认(受保护进程)一律视为关键,绝不冒险结束

    const QString path = tryGetProcessImagePath(pid);
    if (path.isEmpty())
        return true;

    const QString name = QFileInfo(path).fileName().toLower();
    if (criticalNames().contains(name) && isSystemImageDir(path))
        return true;

    return false;
}

bool ProcessInspector::waitForExit(int pid, int msTimeout)
{
    if (pid <= 0)
        return true;
    HANDLE h = OpenProcess(SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION, FALSE,
                           static_cast<DWORD>(pid));
    if (!h) {
        return GetLastError() == ERROR_INVALID_PARAMETER;
    }
    const DWORD w = WaitForSingleObject(h, msTimeout < 0 ? 0 : static_cast<DWORD>(msTimeout));
    CloseHandle(h);
    return w == WAIT_OBJECT_0;
}

bool ProcessInspector::tryTerminateProcess(int pid)
{
    if (pid <= 4)
        return false;
    ensureDebugPrivilege();
    if (isCriticalProcess(pid))
        return false;

    HANDLE h = OpenProcess(PROCESS_TERMINATE, FALSE, static_cast<DWORD>(pid));
    if (!h)
        return false;
    const BOOL ok = TerminateProcess(h, 1);
    CloseHandle(h);
    return ok != FALSE;
}

int ProcessInspector::terminateProcessTree(int rootPid, QList<ProcessInstance>* ended)
{
    if (rootPid <= 4)
        return 0;
    ensureDebugPrivilege();

    // 先结束最深的后代,最后结束根进程。
    const QVector<int> descendants = collectDescendants(rootPid);
    QVector<int> order;
    order.reserve(descendants.size() + 1);
    for (int i = descendants.size() - 1; i >= 0; --i)
        order.push_back(descendants[i]);
    order.push_back(rootPid);

    // 身份要在动手前一次取齐:子进程被结束后,父进程(如 cmd /c)常会立刻自行退出,
    // 轮到它时 TerminateProcess 失败、映像和创建时间也已经查不到。
    QVector<std::optional<ProcessInstance>> identities;
    if (ended) {
        identities.reserve(order.size());
        for (int pid : std::as_const(order))
            identities.push_back(tryGetProcessInstance(pid));
    }

    int killed = 0;
    for (qsizetype i = 0; i < order.size(); ++i) {
        const bool terminated = tryTerminateProcess(order[i]);
        if (terminated)
            ++killed;
        if (!ended || !identities[i])
            continue;
        // 收录「被我们结束掉的那一个实例」:TerminateProcess 成功的,以及因为我们先结束了它的
        // 子进程而随之退出的(如 cmd /c:句柄已不可结束,但原实例已不在 / 内核对象已置信号)。
        const bool goneNow = terminated
            || !isCurrentProcessInstance(*identities[i])
            || waitForExit(order[i], 0);
        if (goneNow)
            ended->append(*identities[i]);
    }
    return killed;
}

namespace {
using NtProcFn = LONG(NTAPI*)(HANDLE);
NtProcFn ntdllProc(const char* name) {
    static HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    return ntdll ? reinterpret_cast<NtProcFn>(GetProcAddress(ntdll, name)) : nullptr;
}

QString normalizedProcessImage(QString path)
{
    path = path.trimmed();
    path.replace(QLatin1Char('/'), QLatin1Char('\\'));
    if (path.startsWith(QLatin1String("\\\\?\\"))
        || path.startsWith(QLatin1String("\\??\\")))
        path.remove(0, 4);
    return path.toCaseFolded();
}

HANDLE openVerifiedProcessInstance(const ProcessInspector::ProcessInstance& expected,
                                   DWORD desiredAccess, bool* differentInstance = nullptr)
{
    if (differentInstance)
        *differentInstance = false;
    if (!expected.isUsable())
        return nullptr;

    HANDLE h = OpenProcess(desiredAccess | PROCESS_QUERY_LIMITED_INFORMATION,
                           FALSE, static_cast<DWORD>(expected.pid));
    if (!h)
        return nullptr;

    wchar_t image[MAX_PATH * 2] = {};
    DWORD imageSize = static_cast<DWORD>(std::size(image));
    FILETIME create{}, exit{}, kernel{}, user{};
    ULARGE_INTEGER created{};
    const bool queried = QueryFullProcessImageNameW(h, 0, image, &imageSize) && imageSize > 0
        && GetProcessTimes(h, &create, &exit, &kernel, &user);
    if (queried) {
        created.LowPart = create.dwLowDateTime;
        created.HighPart = create.dwHighDateTime;
    }
    const QString actualPath = queried
        ? QString::fromWCharArray(image, static_cast<int>(imageSize)) : QString();
    const bool matches = queried && created.QuadPart == expected.creationFileTime
        && normalizedProcessImage(actualPath) == normalizedProcessImage(expected.imagePath);
    if (!matches) {
        if (differentInstance)
            *differentInstance = queried;
        CloseHandle(h);
        return nullptr;
    }
    return h;
}

bool ntControlProcess(int pid, const char* fnName) {
    if (pid <= 0) return false;
    const NtProcFn fn = ntdllProc(fnName);
    if (!fn) return false;
    HANDLE h = OpenProcess(PROCESS_SUSPEND_RESUME, FALSE, static_cast<DWORD>(pid));
    if (!h) return false;
    const LONG st = fn(h);
    CloseHandle(h);
    return st == 0;
}
}

bool ProcessInspector::trySuspend(int pid) { return ntControlProcess(pid, "NtSuspendProcess"); }
bool ProcessInspector::tryResume(int pid)  { return ntControlProcess(pid, "NtResumeProcess"); }

bool ProcessInspector::isCurrentProcessInstance(const ProcessInstance& expected)
{
    HANDLE h = openVerifiedProcessInstance(expected, SYNCHRONIZE);
    if (!h)
        return false;
    CloseHandle(h);
    return true;
}

QString ProcessInspector::tryGetUserSid(int pid) {
    const HANDLE process = ::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, static_cast<DWORD>(pid));
    if (!process) return {};
    HANDLE token = nullptr;
    const BOOL opened = ::OpenProcessToken(process, TOKEN_QUERY, &token);
    ::CloseHandle(process);
    if (!opened) return {};
    DWORD bytes = 0;
    ::GetTokenInformation(token, TokenUser, nullptr, 0, &bytes);
    if (bytes == 0 || bytes > 65536) { ::CloseHandle(token); return {}; }
    QByteArray buffer(static_cast<qsizetype>(bytes), Qt::Uninitialized);
    QString result;
    if (::GetTokenInformation(token, TokenUser, buffer.data(), bytes, &bytes)) {
        LPWSTR sid = nullptr;
        if (::ConvertSidToStringSidW(reinterpret_cast<TOKEN_USER*>(buffer.data())->User.Sid, &sid)) {
            result = QString::fromWCharArray(sid);
            ::LocalFree(sid);
        }
    }
    ::CloseHandle(token);
    return result;
}
