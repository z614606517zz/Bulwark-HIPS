#pragma once
#include <optional>
#include <QString>
#include <QMutex>
#include "bulwark/engine/BaselineAnalyzer.h"

namespace bulwark::service {

class BaselineStore {
public:
    BaselineStore();
    std::optional<bulwark::engine::BaselineSnapshot> load();
    void save(const bulwark::engine::BaselineSnapshot& snapshot);

private:
    QString path_;
    QMutex io_;
};

}
