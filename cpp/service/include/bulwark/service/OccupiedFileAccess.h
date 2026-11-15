#pragma once
#include <QByteArray>
#include <QList>
#include <QString>

namespace bulwark::service::occupied {

bool enableBackupPrivileges();

bool readWithBackupSemantics(const QString& path, QByteArray& out, QString& why);

bool deleteWithBackupSemantics(const QString& path, QString& why);

QString describeHolders(const QString& path);

QList<int> holderPids(const QString& path);

}
