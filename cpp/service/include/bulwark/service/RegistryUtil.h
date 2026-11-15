#pragma once
#include <QList>
#include <QString>
#include <QStringList>

namespace bulwark::service::regutil {

enum class Hive { Machine, Users };

constexpr quint32 kRegSz = 1;
constexpr quint32 kRegExpandSz = 2;
constexpr quint32 kRegDword = 4;

struct Value {
    bool present = false;
    quint32 type = 0;
    bool supported = false;
    QString text;
};

struct Named {
    QString name;
    Value value;
};

QString hiveName(Hive h);

Value readValue(Hive h, const QString& sub, const QString& name);
bool keyExists(Hive h, const QString& sub);
QStringList subKeys(Hive h, const QString& sub);
QList<Named> values(Hive h, const QString& sub);

bool writeValue(Hive h, const QString& sub, const QString& name, quint32 type, const QString& text,
                quint32* winerr = nullptr);
bool deleteValue(Hive h, const QString& sub, const QString& name, quint32* winerr = nullptr);
bool createKeyPath(Hive h, const QString& sub, QStringList* createdOut, quint32* winerr = nullptr);
bool deleteKeyIfEmpty(Hive h, const QString& sub);

QStringList interactiveUserSids();

}
