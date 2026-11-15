#pragma once
#include <QString>
#include <QStringList>

namespace bulwark::service {

class IpcClientAuth {
public:
    struct Policy {
        QString installDir;
        QStringList allowedImageNames;
        bool requireElevatedAdministrator = false;
        bool enforceSignature = false;
        QStringList allowedThumbprints;
        QStringList allowedPublishers;
    };

    struct Result {
        bool    ok = false;
        quint32 pid = 0;
        int     sessionId = -1;
        QString imagePath;
        QString reason;
    };

    static void configure(const Policy& policy);

    static Result authenticate(qintptr socketDescriptor);

    static QString policySummary();
};

}
