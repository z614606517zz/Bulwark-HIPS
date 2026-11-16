#pragma once

#include <QByteArray>
#include <QString>
#include <QStringList>

#include <utility>

namespace bulwark::service::reputation {

// 当前联网功能共用的有界 HTTPS 传输层。
// 只服务于 ThreatFox feed，不支持文件上传、自建 CA 或证书钉扎。
class HttpTransport {
public:
    static std::pair<int, QString> postJson(const QString& url, const QString& body,
                                            const QStringList& headers,
                                            int timeoutSeconds);

    static void diag(const QString& line);
};

} // namespace bulwark::service::reputation
