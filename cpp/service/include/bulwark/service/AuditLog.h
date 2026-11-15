#pragma once
#include <QString>
#include <QJsonObject>
#include <QMutex>

namespace bulwark::service {

class AuditLog {
public:
    AuditLog();
    void writeRecord(const QJsonObject& record);

private:
    QString currentFilePath();

    QString dir_;
    QMutex io_;

    QString cachedDay_;
    QString cachedPath_;
    qint64  cachedBytes_ = 0;
};

}
