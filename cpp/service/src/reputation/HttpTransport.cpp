#include "bulwark/service/reputation/HttpTransport.h"
#include "bulwark/service/Logger.h"

#include <QByteArray>
#include <QDateTime>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QMutex>
#include <QMutexLocker>
#include <QUrl>

#include <algorithm>
#include <string>

#ifdef Q_OS_WIN
#  define NOMINMAX
#  include <windows.h>
#  include <winhttp.h>
#  pragma comment(lib, "winhttp.lib")
#endif

namespace bulwark::service::reputation {
namespace {

bool isLoopbackHost(const QString& host)
{
    const QString h = host.trimmed().toLower();
    return h == QLatin1String("localhost") || h == QLatin1String("::1")
        || h.startsWith(QLatin1String("127.")) || h.endsWith(QLatin1String(".localhost"));
}

bool transportAllowed(const QUrl& url)
{
    const QString scheme = url.scheme().toLower();
    return scheme == QLatin1String("https")
        || (scheme == QLatin1String("http") && isLoopbackHost(url.host()));
}

#ifdef Q_OS_WIN
std::pair<int, QByteArray> winHttpSend(const wchar_t* verb, const QUrl& url, const QByteArray& body,
                                       const QStringList& headers, int timeoutSeconds,
                                       int maxResponseBytes)
{
    const qint64 started = QDateTime::currentMSecsSinceEpoch();
    const auto elapsed = [started] { return QDateTime::currentMSecsSinceEpoch() - started; };
    const bool https = url.scheme().compare(QLatin1String("https"), Qt::CaseInsensitive) == 0;
    const INTERNET_PORT port = static_cast<INTERNET_PORT>(
        url.port(https ? INTERNET_DEFAULT_HTTPS_PORT : INTERNET_DEFAULT_HTTP_PORT));

    HINTERNET session = WinHttpOpen(L"BulwarkService/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                    WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!session) {
        HttpTransport::diag(QStringLiteral("WinHTTP 打开会话失败(%1ms,error=%2)")
                                .arg(elapsed()).arg(GetLastError()));
        return {0, QByteArray()};
    }

    const int timeoutMs = std::max(5, timeoutSeconds) * 1000;
    WinHttpSetTimeouts(session, timeoutMs, timeoutMs, timeoutMs, timeoutMs);

    const std::wstring host = url.host().toStdWString();
    HINTERNET connection = WinHttpConnect(session, host.c_str(), port, 0);
    if (!connection) {
        HttpTransport::diag(QStringLiteral("WinHTTP 连接失败(%1ms,error=%2)")
                                .arg(elapsed()).arg(GetLastError()));
        WinHttpCloseHandle(session);
        return {0, QByteArray()};
    }

    QString path = url.path(QUrl::FullyEncoded);
    if (path.isEmpty())
        path = QStringLiteral("/");
    if (url.hasQuery())
        path += QLatin1Char('?') + url.query(QUrl::FullyEncoded);

    const DWORD flags = https ? WINHTTP_FLAG_SECURE : 0;
    HINTERNET request = WinHttpOpenRequest(connection, verb,
                                           reinterpret_cast<LPCWSTR>(path.utf16()),
                                           nullptr, WINHTTP_NO_REFERER,
                                           WINHTTP_DEFAULT_ACCEPT_TYPES, flags);
    if (!request) {
        HttpTransport::diag(QStringLiteral("WinHTTP 创建请求失败(%1ms,error=%2)")
                                .arg(elapsed()).arg(GetLastError()));
        WinHttpCloseHandle(connection);
        WinHttpCloseHandle(session);
        return {0, QByteArray()};
    }

    DWORD redirectPolicy = WINHTTP_OPTION_REDIRECT_POLICY_DISALLOW_HTTPS_TO_HTTP;
    WinHttpSetOption(request, WINHTTP_OPTION_REDIRECT_POLICY,
                     &redirectPolicy, sizeof(redirectPolicy));
    for (const QString& header : headers) {
        const QString line = header + QStringLiteral("\r\n");
        WinHttpAddRequestHeaders(request, reinterpret_cast<LPCWSTR>(line.utf16()),
                                 static_cast<DWORD>(-1L), WINHTTP_ADDREQ_FLAG_ADD);
    }

    const BOOL sent = WinHttpSendRequest(
        request, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
        body.isEmpty() ? WINHTTP_NO_REQUEST_DATA : const_cast<char*>(body.constData()),
        static_cast<DWORD>(body.size()), static_cast<DWORD>(body.size()), 0);
    if (!sent || !WinHttpReceiveResponse(request, nullptr)) {
        const DWORD error = GetLastError();
        HttpTransport::diag(QStringLiteral("WinHTTP 请求失败(%1ms,error=%2,host=%3)")
                                .arg(elapsed()).arg(error).arg(url.host()));
        WinHttpCloseHandle(request);
        WinHttpCloseHandle(connection);
        WinHttpCloseHandle(session);
        return {0, QByteArray()};
    }

    DWORD status = 0;
    DWORD statusSize = sizeof(status);
    WinHttpQueryHeaders(request, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                        WINHTTP_HEADER_NAME_BY_INDEX, &status, &statusSize,
                        WINHTTP_NO_HEADER_INDEX);

    QByteArray response;
    bool oversized = false;
    for (;;) {
        DWORD available = 0;
        if (!WinHttpQueryDataAvailable(request, &available) || available == 0)
            break;
        if (available > static_cast<DWORD>(maxResponseBytes - response.size())) {
            oversized = true;
            break;
        }
        QByteArray chunk(static_cast<int>(available), '\0');
        DWORD read = 0;
        if (!WinHttpReadData(request, chunk.data(), available, &read) || read == 0)
            break;
        chunk.resize(static_cast<int>(read));
        response.append(chunk);
    }

    WinHttpCloseHandle(request);
    WinHttpCloseHandle(connection);
    WinHttpCloseHandle(session);

    if (oversized) {
        HttpTransport::diag(QStringLiteral("WinHTTP 响应超过 %1 字节，已拒绝(host=%2)")
                                .arg(maxResponseBytes).arg(url.host()));
        return {0, QByteArray()};
    }
    return {static_cast<int>(status), response};
}
#endif

bool checkTarget(const QUrl& url, const QString& rawUrl)
{
    if (!url.isValid() || url.host().isEmpty()) {
        HttpTransport::diag(QStringLiteral("HTTP 地址无效:%1").arg(rawUrl));
        return false;
    }
    if (!transportAllowed(url)) {
        HttpTransport::diag(QStringLiteral("拒绝非 HTTPS 远端，只允许 HTTPS 或本机回环 HTTP(host=%1)")
                                .arg(url.host()));
        return false;
    }
    return true;
}

} // namespace

std::pair<int, QString> HttpTransport::postJson(const QString& rawUrl, const QString& body,
                                                const QStringList& headers,
                                                int timeoutSeconds)
{
    const QUrl url(rawUrl);
    if (!checkTarget(url, rawUrl))
        return {0, QString()};
#ifdef Q_OS_WIN
    constexpr int kMaxResponseBytes = 32 * 1024 * 1024;
    const auto res = winHttpSend(L"POST", url, body.toUtf8(), headers, timeoutSeconds, kMaxResponseBytes);
    return {res.first, QString::fromUtf8(res.second)};
#else
    Q_UNUSED(body);
    Q_UNUSED(headers);
    Q_UNUSED(timeoutSeconds);
    diag(QStringLiteral("当前 HTTP 传输实现仅支持 Windows"));
    return {0, QString()};
#endif
}

void HttpTransport::diag(const QString& line)
{
    static QMutex mutex;
    QMutexLocker lock(&mutex);

    constexpr qint64 kMaxBytes = 2 * 1024 * 1024;
    const QString path = QDir(programDataDir()).filePath(QStringLiteral("http_diag.log"));
    if (QFileInfo(path).size() >= kMaxBytes) {
        const QString previous = path + QStringLiteral(".1");
        QFile::remove(previous);
        QFile::rename(path, previous);
    }

    QFile file(path);
    if (!file.open(QIODevice::Append | QIODevice::WriteOnly | QIODevice::Text))
        return;
    const QString row = QDateTime::currentDateTime().toString(QStringLiteral("HH:mm:ss"))
        + QLatin1Char(' ') + line + QLatin1Char('\n');
    file.write(row.toUtf8());
}

} // namespace bulwark::service::reputation
