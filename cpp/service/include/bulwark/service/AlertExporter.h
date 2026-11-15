#pragma once
#include <QString>
#include <QMutex>
#include "bulwark/models/SecurityEvent.h"
#include "bulwark/models/Verdict.h"

namespace bulwark::service {

class AlertExporter {
public:
    explicit AlertExporter(bool enabled);
    void exportAlert(const bulwark::SecurityEvent& e, const bulwark::Verdict& v);

private:
    QString currentFilePath();
    bool enabled_;
    QString dir_;
    QMutex io_;
};

}
