#pragma once
#include <QSet>
#include "bulwark/engine/NetworkEndpoint.h"
#include <QString>
#include <QStringList>

namespace bulwark::service {

inline bool parseIpv4Octets(const QString& ipv4, int Out[4]) {
    const QStringList parts = ipv4.split(QLatin1Char('.'));
    if (parts.size() != 4)
        return false;
    for (int i = 0; i < 4; ++i) {
        bool ok = false;
        const int v = parts[i].toInt(&ok);
        if (!ok || v < 0 || v > 255)
            return false;
        Out[i] = v;
    }
    return true;
}

inline bool isUnsafeToBlanketBlockIp(const QString& ip) {
    int b[4] = { 0, 0, 0, 0 };

    const auto endpoint = bulwark::engine::NetworkEndpoint::parse(ip);
    if (!endpoint) return true;
    if (endpoint->address.protocol() == QAbstractSocket::IPv6Protocol) {
        const QHostAddress& a = endpoint->address;
        if (!endpoint->isPublicUnicast()) return true;
        // Shared resolvers/CDN frontends retain the same guardrail as IPv4.
        for (const char* cidr : { "2001:4860::/32", "2606:4700::/32", "2620:fe::/48", "2620:119::/32", "2a04:4e42::/32" }) {
            const auto range = QHostAddress::parseSubnet(QString::fromLatin1(cidr));
            if (a.isInSubnet(range)) return true;
        }
        return false;
    }
    if (!parseIpv4Octets(endpoint->host(), b)) return true;

    // 私网 / 环回 / 链路本地 / CGNAT / 组播 / 保留:不可能是「攻击者的 C2 地址」。
    if (b[0] == 10) return true;
    if (b[0] == 172 && b[1] >= 16 && b[1] <= 31) return true;
    if (b[0] == 192 && b[1] == 168) return true;
    if (b[0] == 127) return true;
    if (b[0] == 169 && b[1] == 254) return true;
    if (b[0] == 0) return true;
    if (b[0] == 100 && b[1] >= 64 && b[1] <= 127) return true;
    if (b[0] >= 224) return true;

    static const QSet<QString> kPublicResolvers = {
        QStringLiteral("8.8.8.8"),         QStringLiteral("8.8.4.4"),
        QStringLiteral("1.1.1.1"),         QStringLiteral("1.0.0.1"),
        QStringLiteral("9.9.9.9"),         QStringLiteral("149.112.112.112"),
        QStringLiteral("208.67.222.222"),  QStringLiteral("208.67.220.220"),
        QStringLiteral("223.5.5.5"),       QStringLiteral("223.6.6.6"),
        QStringLiteral("119.29.29.29"),    QStringLiteral("182.254.116.116"),
        QStringLiteral("114.114.114.114"), QStringLiteral("114.114.115.115"),
        QStringLiteral("180.76.76.76"),
        QStringLiteral("117.50.10.10"),    QStringLiteral("52.80.66.66"),
        QStringLiteral("101.226.4.6"),     QStringLiteral("218.30.118.6"),
        QStringLiteral("4.2.2.1"),         QStringLiteral("4.2.2.2"),
    };
    if (kPublicResolvers.contains(ip))
        return true;

    struct Range { int a, b0, b1; };
    static const Range kSharedFrontends[] = {
        { 104, 16,  28 },
        { 172, 64,  71 },
        { 162, 158, 159 },
        { 188, 114, 114 },
        { 173, 245, 245 },
        { 198, 41,  41 },
        { 151, 101, 101 },
        { 199, 232, 232 },
        { 146, 75,  75 },
        { 23,  32,  67 },
        { 23,  192, 223 },
        { 2,   16,  23 },
        { 96,  16,  17 },
        { 184, 24,  31 },
        { 192, 229, 229 },
        { 93,  184, 184 },
        { 74,  125, 125 },
        { 142, 250, 251 },
        { 172, 217, 217 },
        { 216, 58,  58 },
        { 34,  117, 117 },
        { 208, 95,  95 },
        { 149, 154, 154 },
        { 91,  108, 108 },
        { 13,  107, 107 },
        { 20,  99,  99 },
    };
    for (const Range& r : kSharedFrontends) {
        if (b[0] == r.a && b[1] >= r.b0 && b[1] <= r.b1)
            return true;
    }

    return false;
}

}
