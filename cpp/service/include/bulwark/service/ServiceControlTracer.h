#pragma once
#include <QList>
#include <QPair>
#include <QString>

namespace bulwark::service {

struct ServiceOriginator {
    int originatorPid = 0;
    QString originatorPath;
    QList<QPair<int, QString>> candidates;
    bool highConfidence() const { return originatorPid > 0; }
};

namespace ServiceControlTracer {

bool isServiceDatabaseKey(const QString& targetPath);

ServiceOriginator trace(int scmPid);

}

}
