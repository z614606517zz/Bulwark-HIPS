#include "bulwark/service/RepairDriverSession.h"

#include <QByteArray>
#include <QJsonObject>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <fltuser.h>

#include "Protocol.h"

namespace bulwark::service {
namespace {

class NativeRepairDriverTransport final : public RepairDriverTransport {
public:
    ~NativeRepairDriverTransport() override {
        if (port_ != nullptr && port_ != INVALID_HANDLE_VALUE)
            ::CloseHandle(port_);
    }

    bool connect(QString* error) override {
        if (port_ != nullptr && port_ != INVALID_HANDLE_VALUE)
            return true;
        HANDLE port = nullptr;
        const HRESULT hr = ::FilterConnectCommunicationPort(
            BLW_PORT_NAME, 0, nullptr, 0, nullptr, &port);
        if (FAILED(hr) || port == nullptr || port == INVALID_HANDLE_VALUE) {
            if (error)
                *error = QStringLiteral("FilterConnectCommunicationPort failed: 0x%1")
                             .arg(static_cast<quint32>(hr), 8, 16, QLatin1Char('0'));
            return false;
        }
        port_ = port;
        return true;
    }

    bool send(quint32 command, const QString& path, QByteArray* output,
              QString* error) override {
        if (port_ == nullptr || port_ == INVALID_HANDLE_VALUE) {
            if (error) *error = QStringLiteral("repair port is not connected");
            return false;
        }
        BLW_CONFIG_MESSAGE config{};
        config.Command = command;
        QString bounded = path;
        if (bounded.size() >= BLW_MAX_PATH)
            bounded = bounded.left(BLW_MAX_PATH - 1);
        config.PathLength = static_cast<USHORT>(bounded.size());
        const int copied = bounded.toWCharArray(config.Path);
        config.Path[copied] = L'\0';

        DWORD returned = 0;
        void* outData = output && !output->isEmpty() ? output->data() : nullptr;
        const DWORD outSize = output ? static_cast<DWORD>(output->size()) : 0;
        const HRESULT hr = ::FilterSendMessage(port_, &config, sizeof(config), outData,
                                               outSize, &returned);
        if (FAILED(hr)) {
            if (error)
                *error = QStringLiteral("FilterSendMessage(%1) failed: 0x%2")
                             .arg(command)
                             .arg(static_cast<quint32>(hr), 8, 16, QLatin1Char('0'));
            return false;
        }
        if (output)
            output->resize(static_cast<int>(returned));
        return true;
    }

private:
    HANDLE port_ = nullptr;
};

bool isAllowed(quint32 command, const QString& path) {
    if (command == BLW_CMD_HANDSHAKE)
        return path.isEmpty();
    if (command == BLW_CMD_DEL_EXECBLOCK)
        return path == RepairDriverSession::sentinelNeedle()
            || path == RepairDriverSession::targetNeedle();
    if (command == BLW_CMD_ADD_EXECBLOCK)
        return path == RepairDriverSession::targetNeedle();
    return false;
}

}

QJsonObject RepairCommandResult::toJson() const {
    QJsonObject object;
    object[QStringLiteral("command")] = static_cast<qint64>(command);
    object[QStringLiteral("path")] = path;
    object[QStringLiteral("ok")] = ok;
    if (!error.isEmpty()) object[QStringLiteral("error")] = error;
    return object;
}

QString RepairDriverSession::targetNeedle() {
    return QStringLiteral("\\新建文件夹 (3)\\CPP\\BUILD_PKG\\TESTS\\RELEASE\\BULWARK_SNAPSHOT.EXE");
}

QString RepairDriverSession::sentinelNeedle() {
    return QStringLiteral("\\BULWARK_REPAIR_SENTINEL_7EA4E5C4\\DO_NOT_CREATE.EXE");
}

RepairDriverSession::RepairDriverSession(std::unique_ptr<RepairDriverTransport> transport)
    : transport_(std::move(transport)) {}

RepairDriverSession::~RepairDriverSession() = default;

std::unique_ptr<RepairDriverSession> RepairDriverSession::createProduction() {
    return std::make_unique<RepairDriverSession>(
        std::make_unique<NativeRepairDriverTransport>());
}

bool RepairDriverSession::connect(QString* error) {
    if (!transport_) {
        if (error) *error = QStringLiteral("repair transport is unavailable");
        return false;
    }
    connected_ = transport_->connect(error);
    return connected_;
}

bool RepairDriverSession::sendClosed(quint32 command, const QString& path,
                                     QByteArray* output, QString* error) {
    RepairCommandResult result;
    result.command = command;
    result.path = path;
    if (!connected_) {
        result.error = QStringLiteral("repair session is not connected");
    } else if (!isAllowed(command, path)) {
        result.error = QStringLiteral("command/path rejected by closed repair surface");
    } else {
        result.ok = transport_->send(command, path, output, &result.error);
    }
    results_.append(result);
    if (!result.ok && error) *error = result.error;
    return result.ok;
}

bool RepairDriverSession::handshake(QString* error) {
    QByteArray output(static_cast<int>(sizeof(BLW_HANDSHAKE_REPLY)), Qt::Uninitialized);
    if (!sendClosed(BLW_CMD_HANDSHAKE, QString(), &output, error))
        return false;
    if (output.size() != static_cast<int>(sizeof(BLW_HANDSHAKE_REPLY))) {
        if (error) *error = QStringLiteral("repair handshake returned an unexpected size");
        return false;
    }
    const auto* reply = reinterpret_cast<const BLW_HANDSHAKE_REPLY*>(output.constData());
    if (reply->ProtocolVersion != BLW_PROTOCOL_VERSION
        || reply->EventMessageSize != sizeof(BLW_EVENT_MESSAGE)
        || reply->ConfigMessageSize != sizeof(BLW_CONFIG_MESSAGE)
        || reply->VerdictReplySize != sizeof(BLW_VERDICT_REPLY)) {
        if (error) *error = QStringLiteral("repair handshake layout mismatch");
        return false;
    }
    return true;
}

bool RepairDriverSession::deleteSentinel(QString* error) {
    return sendClosed(BLW_CMD_DEL_EXECBLOCK, sentinelNeedle(), nullptr, error);
}

bool RepairDriverSession::deleteTarget(QString* error) {
    return sendClosed(BLW_CMD_DEL_EXECBLOCK, targetNeedle(), nullptr, error);
}

bool RepairDriverSession::restoreTarget(QString* error) {
    return sendClosed(BLW_CMD_ADD_EXECBLOCK, targetNeedle(), nullptr, error);
}

}
