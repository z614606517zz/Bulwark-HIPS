#include "dialogs/ExplainCard.h"

#include "design/Components.h"
#include "design/Theme.h"
#include "widgets/WrapLabel.h"

#include "bulwark/engine/ThreatExplainer.h"
#include "bulwark/models/SecurityEvent.h"

#include <QHBoxLayout>
#include <QVBoxLayout>
#include <QWidget>

namespace explaincard {

namespace {

QColor toneColor(bulwark::engine::ThreatExplanation::Tone tone)
{
    using Tone = bulwark::engine::ThreatExplanation::Tone;
    switch (tone) {
        case Tone::Danger:  return theme::danger();
        case Tone::Caution: return theme::warning();
        case Tone::Info:    break;
    }
    return theme::info();
}

WrapLabel* para(const QString& text, const char* role, const QString& accessibleName)
{
    auto* l = new WrapLabel(text);
    if (role != nullptr)
        l->setProperty("role", role);
    l->setAccessibleName(accessibleName);
    return l;
}

}

QWidget* build(const bulwark::SecurityEvent& e, const Options& opt)
{
    using namespace bulwark::engine;

    const ThreatExplanation x = ThreatExplainer::explain(e);
    if (x.isEmpty())
        return nullptr;

    const QColor tone = toneColor(x.tone);

    QWidget* card = opt.compact ? new QWidget : ui::cardAlt();
    auto* cl = new QVBoxLayout(card);
    if (opt.compact)
        cl->setContentsMargins(0, 2, 0, 0);
    else
        cl->setContentsMargins(14, 12, 14, 12);
    cl->setSpacing(opt.compact ? 4 : 6);

    auto* head = new QHBoxLayout;
    head->setSpacing(8);
    head->addWidget(ui::eyebrow(opt.omitAdvice ? QStringLiteral("这是什么")
                                               : QStringLiteral("这是什么 · 该怎么办")),
                    0, Qt::AlignVCenter);
    // 标明来源。通知卡片上方可能同时挂着 AI 面板,不写清楚用户不知道这句话是谁说的;
    // 也让「本机判断」与「大模型推测」在可信度上的差别保持可见。
    head->addWidget(ui::pill(QStringLiteral("本机判断 · 不联网"), tone), 0, Qt::AlignVCenter);
    head->addStretch();
    cl->addLayout(head);

    cl->addWidget(para(x.meaning, opt.compact ? "secondary" : nullptr,
                       QStringLiteral("行为说明")));

    if (!x.recognize.isEmpty())
        cl->addWidget(para(x.recognize, "secondary",
                           QStringLiteral("如何判断是否为本人操作")));

    if (!opt.omitAdvice)
        cl->addWidget(para(x.advice, "secondary", QStringLiteral("处置建议")));

    card->setAccessibleName(QStringLiteral("本机离线判断"));
    return card;
}

}
