#pragma once
#include <QString>
#include <QStringList>
#include "bulwark/models/Enums.h"

namespace bulwark::service::monitoring {

struct ProcessOrigin {
    bulwark::ProcessOriginKind kind = bulwark::ProcessOriginKind::Unknown;
    QString serviceName;
    QString serviceDisplayName;
    QString taskPath;
    QString detail;
    bool highConfidence = false;

    bool resolved() const { return kind != bulwark::ProcessOriginKind::Unknown; }
};

class ProcessOriginResolver {
public:
    static ProcessOrigin resolve(int pid, const QString& imagePath = QString(),
                                 int parentPid = -1, const QString& commandLine = QString());

    static QStringList servicesHostedBy(int pid);

    inline static bool taskComEnabled = true;

    static void invalidateCaches();
    static void invalidateMemo();
};

}
