#include "bulwark/engine/AttackAnnotator.h"
#include "bulwark/engine/AttackCatalog.h"
#include <QSet>
#include <QStringList>
#include <QRegularExpression>

namespace bulwark::engine {

void AttackAnnotator::annotate(bulwark::SecurityEvent& e) {
    if (e.evidenceChain.isEmpty()) return;

    static const QRegularExpression techniqueRe(
        QStringLiteral("T\\d{4}(?:\\.\\d{3})?"), QRegularExpression::CaseInsensitiveOption);

    QSet<QString> seen;
    QStringList techniques;

    for (bulwark::Evidence& ev : e.evidenceChain) {
        if (ev.description.isEmpty()) continue;

        const auto m = techniqueRe.match(ev.description);
        if (!m.hasMatch()) continue;

        const QString id = m.captured(0).toUpper();
        const auto t = AttackCatalog::lookup(id);

        const QString canonicalId = t.has_value() ? t->id : id;
        if (ev.technique.isEmpty()) ev.technique = canonicalId;
        if (ev.techniqueName.isEmpty() && t.has_value()) ev.techniqueName = t->name;

        if (!seen.contains(id)) {
            seen.insert(id);
            techniques << AttackCatalog::describe(id);
        }
    }

    if (!techniques.isEmpty())
        e.techniques = techniques;
}

}
