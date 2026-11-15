#pragma once

#include <QByteArray>
#include <QJsonObject>
#include <QString>
#include <QVector>

#include <memory>

namespace bulwark::service {

struct RepairCommandResult {
    quint32 command = 0;
    QString path;
    bool ok = false;
    QString error;

    QJsonObject toJson() const;
};

class RepairDriverTransport {
public:
    virtual ~RepairDriverTransport() = default;
    virtual bool connect(QString* error) = 0;
    virtual bool send(quint32 command, const QString& path, QByteArray* output,
                      QString* error) = 0;
};

class RepairDriverSession {
public:
    static QString targetNeedle();
    static QString sentinelNeedle();

    explicit RepairDriverSession(std::unique_ptr<RepairDriverTransport> transport);
    ~RepairDriverSession();

    static std::unique_ptr<RepairDriverSession> createProduction();

    bool connect(QString* error = nullptr);
    bool handshake(QString* error = nullptr);
    bool deleteSentinel(QString* error = nullptr);
    bool deleteTarget(QString* error = nullptr);
    bool restoreTarget(QString* error = nullptr);

    const QVector<RepairCommandResult>& commandResults() const { return results_; }

private:
    bool sendClosed(quint32 command, const QString& path, QByteArray* output,
                    QString* error);

    std::unique_ptr<RepairDriverTransport> transport_;
    QVector<RepairCommandResult> results_;
    bool connected_ = false;
};

}
