#pragma once
#include <QString>
#include <QJsonObject>
#include <optional>
#include "bulwark/ipc/IpcMessageType.h"

namespace bulwark::ipc {

struct IpcMessage {
    IpcMessageType type = IpcMessageType::Hello;
    QString payload;

    static IpcMessage create(IpcMessageType type, const QJsonObject& payloadObj);
    static IpcMessage createRaw(IpcMessageType type, const QString& rawPayload);

    template <class T>
    static IpcMessage from(IpcMessageType type, const T& p) {
        return create(type, p.toJson());
    }

    QString serialize() const;

    QJsonObject payloadObject() const;

    template <class T>
    T payloadAs() const { return T::fromJson(payloadObject()); }

    static std::optional<IpcMessage> deserialize(const QString& line);
};

}
