#pragma once
#include <QDateTime>
#include <QHash>
#include <QList>
#include <QMutex>
#include <QSet>
#include <QString>
#include <QStringList>
#include "bulwark/models/SecurityEvent.h"

namespace bulwark::engine {

struct BaselineProgram {
    QString key;
    QDateTime firstSeenUtc;
    QDateTime lastSeenUtc;
    int childObs = 0, hostObs = 0, writeObs = 0;
    QStringList children, hosts, writeDirs;
};

struct BaselineSnapshot {
    QList<BaselineProgram> programs;
};

// 只给软信号:正常程序升级、换配置后行为也会变。
class BaselineAnalyzer {
public:
    struct Result {
        int score = 0;
        QStringList reasons;
        bool deviation = false;
    };

    Result observe(const SecurityEvent& e);

    BaselineSnapshot exportSnapshot();
    void importSnapshot(const BaselineSnapshot& snapshot);

private:
    struct Profile {
        QDateTime firstSeenUtc;
        QDateTime lastSeenUtc;
        int obs[3] = { 0, 0, 0 };
        QSet<QString> values[3];
    };

    Result observeDimension(const QString& program, int dim, const QString& value, const QDateTime& now);
    void evictIfNeeded();

    QHash<QString, Profile> profiles_;
    QMutex gate_;
};

}
