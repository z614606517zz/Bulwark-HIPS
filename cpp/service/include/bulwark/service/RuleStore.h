#pragma once
#include <QString>
#include <QVector>
#include <QMutex>
#include "bulwark/models/DefenseRule.h"

namespace bulwark::service {

class RuleStore {
public:
    RuleStore();
    QVector<bulwark::DefenseRule> load();
    void save(const QVector<bulwark::DefenseRule>& rules);

private:
    QString path_;
    QMutex io_;
};

}
