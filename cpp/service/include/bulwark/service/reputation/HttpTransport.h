#pragma once

#include <QByteArray>
#include <QString>
#include <QStringList>

#include <utility>

namespace bulwark::service::reputation {

// 当前联网功能共用的有界 HTTPS 传输层。
// 只服务于 ThreatFox feed 与 YARA 规则包下载，不支持文件上传、自建 CA 或证书钉扎。
class HttpTransport {
public:
    static std::pair<int, QString> postJson(const QString& url, const QString& body,
                                            const QStringList& headers,
                                            int timeoutSeconds);

    // 响应超过 maxBytes 即放弃,返回状态 0。跟随 HTTPS→HTTPS 跳转,拒绝降级到 HTTP。
    static std::pair<int, QByteArray> getBytes(const QString& url, const QStringList& headers,
                                               int timeoutSeconds, int maxBytes);

    static void diag(const QString& line);
};

} // namespace bulwark::service::reputation
