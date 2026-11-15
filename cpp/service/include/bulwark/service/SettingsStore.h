#pragma once
#include <optional>
#include <QString>
#include <QMutex>
#include "bulwark/models/RuntimeSettings.h"

namespace bulwark::service {

class SettingsStore {
public:
    SettingsStore();
    std::optional<bulwark::RuntimeSettings> load();
    void save(const bulwark::RuntimeSettings& settings);

private:
    QString path_;
    QMutex io_;
    QString unreadableProtectedAiApiKey_;
};

}
