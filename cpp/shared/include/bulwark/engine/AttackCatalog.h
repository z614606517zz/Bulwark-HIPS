#pragma once
#include <QString>
#include <optional>

namespace bulwark::engine {

struct AttackCatalog {
    struct Technique {
        QString id;
        QString name;
        QString tactic;
    };

    static std::optional<Technique> lookup(const QString& id);
    static QString describe(const QString& id);
};

}
