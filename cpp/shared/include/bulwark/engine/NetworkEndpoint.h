#pragma once
#include <QHostAddress>
#include <optional>

namespace bulwark::engine {
struct NetworkEndpoint {
    QHostAddress address;
    quint16 port = 0;
    bool isPublicUnicast() const {
        if (address.protocol() == QAbstractSocket::IPv4Protocol) {
            const quint32 v = address.toIPv4Address();
            const quint32 a = v >> 24, b = (v >> 16) & 255;
            return a != 0 && a != 10 && a != 127 && a < 224
                && !(a == 172 && b >= 16 && b <= 31) && !(a == 192 && b == 168)
                && !(a == 169 && b == 254) && !(a == 100 && b >= 64 && b <= 127);
        }
        if (address.protocol() != QAbstractSocket::IPv6Protocol) return false;
        const auto bytes = address.toIPv6Address();
        // Global unicast 2000::/3, excluding the documentation subnet.
        return (bytes[0] & 0xe0) == 0x20
            && !(bytes[0] == 0x20 && bytes[1] == 1 && bytes[2] == 0x0d && bytes[3] == 0xb8);
    }
    QString host() const { return address.toString().toLower(); }
    QString text() const {
        if (!port) return host();
        return address.protocol() == QAbstractSocket::IPv6Protocol
            ? QStringLiteral("[%1]:%2").arg(host()).arg(port)
            : QStringLiteral("%1:%2").arg(host()).arg(port);
    }
    static std::optional<NetworkEndpoint> parse(QString value) {
        value = value.trimmed();
        QString host = value, portText;
        if (value.startsWith(QLatin1Char('['))) {
            const qsizetype close = value.indexOf(QLatin1Char(']'));
            if (close <= 1) return {};
            host = value.mid(1, close - 1);
            if (close + 1 < value.size()) {
                if (value.at(close + 1) != QLatin1Char(':')) return {};
                portText = value.mid(close + 2);
                if (portText.isEmpty()) return {};
            }
        } else if (value.count(QLatin1Char(':')) == 1) {
            const qsizetype colon = value.indexOf(QLatin1Char(':'));
            host = value.left(colon);
            portText = value.mid(colon + 1);
            if (portText.isEmpty()) return {};
        }
        NetworkEndpoint out;
        if (host.contains(QLatin1Char('%')) || !out.address.setAddress(host)) return {};
        // A mapped IPv4 address has the same policy identity as native IPv4.
        bool mapped = false;
        const quint32 v4 = out.address.toIPv4Address(&mapped);
        if (mapped) out.address = QHostAddress(v4);
        if (!portText.isEmpty()) {
            for (const QChar c : portText) if (c < QLatin1Char('0') || c > QLatin1Char('9')) return {};
            bool ok = false;
            const uint p = portText.toUInt(&ok);
            if (!ok || p > 65535) return {};
            out.port = static_cast<quint16>(p);
        }
        return out;
    }
};
}
