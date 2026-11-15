#pragma once
#include "design/GlowCard.h"
#include "design/Icons.h"
#include "design/Theme.h"
#include "widgets/ElidingLabel.h"

#include <QClipboard>
#include <QFont>
#include <QFrame>
#include <QGraphicsDropShadowEffect>
#include <QGuiApplication>
#include <QHBoxLayout>
#include <QLabel>
#include <QMenu>
#include <QPointer>
#include <QPushButton>
#include <QString>
#include <QStyle>
#include <QTimer>
#include <QToolButton>
#include <QVariant>
#include <QVBoxLayout>

#include <functional>
#include <utility>

namespace ui {

inline GlowCard* card(QWidget* parent = nullptr)
{
    auto* c = new GlowCard(parent);
    c->setObjectName(QStringLiteral("Card"));
    return c;
}

inline GlowCard* cardAlt(QWidget* parent = nullptr)
{
    auto* c = new GlowCard(parent);
    c->setObjectName(QStringLiteral("CardAlt"));
    c->setTone(GlowCard::Tone::Inset);
    c->setRadius(12);
    return c;
}

inline void elevate(QWidget* w, int blur = 24, int dy = 8, int alpha = 140)
{
    auto* sh = new QGraphicsDropShadowEffect(w);
    sh->setBlurRadius(blur);
    sh->setOffset(0, dy);
    sh->setColor(QColor(0, 0, 0, alpha));
    w->setGraphicsEffect(sh);
}

// 浮起的卡片:贴纸面板自带硬投影,不叠加模糊阴影。
inline GlowCard* floatingCard(const QColor& glow = QColor(), QWidget* parent = nullptr)
{
    auto* c = new GlowCard(parent);
    c->setObjectName(QStringLiteral("Card"));
    c->setTone(GlowCard::Tone::Floating);
    c->setRadius(18);
    if (glow.isValid())
        c->setGlow(glow, QPointF(0.0, 0.0), 0.85, 0.13);
    return c;
}

inline QLabel* label(const QString& text, const char* role = nullptr, QWidget* parent = nullptr)
{
    auto* l = new QLabel(text, parent);
    if (role)
        l->setProperty("role", role);
    return l;
}

inline ElidingLabel* elided(const QString& text, const char* role = nullptr, QWidget* parent = nullptr)
{
    auto* l = new ElidingLabel(text, parent);
    if (role)
        l->setProperty("role", role);
    return l;
}

inline QLabel* eyebrow(const QString& text, QWidget* parent = nullptr)
{
    auto* l = label(text, "eyebrow", parent);
    QFont f = l->font();
    f.setLetterSpacing(QFont::AbsoluteSpacing, 1.4);
    l->setFont(f);
    return l;
}

inline QLabel* coloredText(const QString& text, int pt, int weight, const QColor& c)
{
    auto* l = new QLabel(text);
    l->setStyleSheet(QStringLiteral("font-size:%1pt; font-weight:%2; color:%3;")
                         .arg(pt).arg(weight).arg(c.name()));
    return l;
}

inline QFrame* hDivider(QWidget* parent = nullptr)
{
    auto* f = new QFrame(parent);
    f->setObjectName(QStringLiteral("Divider"));
    f->setFixedHeight(1);
    return f;
}

// 胶囊标签 = 贴纸:浅色铺底 + 同色描边 + 同色粗体字。
inline void stylePill(QLabel* l, const QString& text, const QColor& c)
{
    l->setText(text);
    l->setStyleSheet(QStringLiteral(
        "background:%1; color:%2; border:2px solid %2; border-radius:%3px;"
        "padding:2px 9px; font-size:9pt; font-weight:800;")
        .arg(theme::blend(c, theme::surface(), 0.14).name(), c.name())
        .arg(theme::mecha() ? 3 : 11));
    l->setAlignment(Qt::AlignCenter);
}

inline QLabel* pill(const QString& text, const QColor& c, QWidget* parent = nullptr)
{
    auto* l = new QLabel(parent);
    stylePill(l, text, c);
    return l;
}

// 状态指示灯:色块 + 墨线。
inline QLabel* statusDot(const QColor& c)
{
    auto* d = new QLabel;
    d->setFixedSize(10, 10);
    d->setStyleSheet(QStringLiteral("background:%1; border:2px solid %2; border-radius:%3px;")
                         .arg(c.name(), theme::ink().name())
                         .arg(theme::mecha() ? 1 : 5));
    return d;
}

inline QFrame* iconBadge(const QString& name, const QColor& color, int box, int iconPx)
{
    auto* f = new QFrame;
    f->setFixedSize(box, box);
    f->setStyleSheet(QStringLiteral("QFrame{background:%1; border:2px solid %2; border-radius:%3px;}")
                         .arg(theme::blend(color, theme::surface(),
                                           theme::titan() ? 0.88 : theme::mecha() ? 0.30 : 0.42).name(),
                              theme::ink().name())
                         .arg(theme::mecha() ? qRound(box * 0.12) : qRound(box * 0.32)));
    auto* lay = new QVBoxLayout(f);
    lay->setContentsMargins(0, 0, 0, 0);
    auto* ic = new AppIcon(name);
    ic->setColor(theme::ink());
    ic->setPx(iconPx);
    lay->addWidget(ic);
    return f;
}

inline QFrame* statCard(const QString& icon, const QColor& color, const QString& value,
                        const QString& name, const QString& caption = QString())
{
    auto* c = new GlowCard;
    c->setObjectName(QStringLiteral("Card"));
    c->setGlow(color, QPointF(1.0, 0.0), 0.7, 0.12);
    c->setMinimumHeight(118);
    auto* v = new QVBoxLayout(c);
    v->setContentsMargins(18, 16, 18, 16);
    v->setSpacing(6);
    auto* top = new QHBoxLayout;
    top->setContentsMargins(0, 0, 0, 0);
    top->addWidget(label(name, "secondary"), 1, Qt::AlignVCenter);
    top->addWidget(iconBadge(icon, color, 34, 18), 0, Qt::AlignTop);
    v->addLayout(top);
    auto* val = label(value, "stat");
    v->addWidget(val);
    if (!caption.isEmpty())
        v->addWidget(label(caption, "muted"));
    v->addStretch();
    return c;
}

inline void repolish(QWidget* w)
{
    if (!w)
        return;
    w->style()->unpolish(w);
    w->style()->polish(w);
    w->update();
}

inline void setRole(QWidget* w, const char* role)
{
    if (!w)
        return;
    w->setProperty("role", role);
    repolish(w);
}

inline void setVariant(QWidget* w, const char* variant)
{
    if (!w)
        return;
    w->setProperty("variant", variant);
    repolish(w);
}

inline QPushButton* button(const QString& text, const char* variant = nullptr,
                           const QString& icon = QString(), bool small = false)
{
    auto* b = new QPushButton(text);
    if (variant)
        b->setProperty("variant", variant);
    if (small)
        b->setProperty("size", "sm");
    b->setCursor(Qt::PointingHandCursor);
    if (!icon.isEmpty()) {
        const bool primary = variant && qstrcmp(variant, "primary") == 0;
        const bool danger = variant && qstrcmp(variant, "danger") == 0;
        b->setIcon(AppIcon::icon(icon, primary ? theme::accentInk()
                                       : danger ? theme::danger()
                                                : theme::textSecondary(), 16));
    }
    return b;
}

inline QToolButton* iconButton(const QString& icon, const QString& tip,
                               const QColor& color = theme::textSecondary(), int px = 16)
{
    auto* b = new QToolButton;
    b->setIcon(AppIcon::icon(icon, color, px));
    b->setIconSize(QSize(px, px));
    b->setToolTip(tip);
    b->setAccessibleName(tip);
    b->setCursor(Qt::PointingHandCursor);
    b->setAutoRaise(true);
    b->setFocusPolicy(Qt::TabFocus);
    return b;
}

inline QToolButton* moreButton(QMenu* menu, const QString& tip = QString::fromUtf8("更多操作"))
{
    auto* b = iconButton(QStringLiteral("more"), tip, theme::textSecondary(), 18);
    b->setObjectName(QStringLiteral("MoreButton"));
    b->setMenu(menu);
    b->setPopupMode(QToolButton::InstantPopup);
    return b;
}

inline QToolButton* copyButton(std::function<QString()> text,
                               const QString& what = QString::fromUtf8("复制"))
{
    auto* b = iconButton(QStringLiteral("copy"), what, theme::textMuted(), 14);
    QObject::connect(b, &QToolButton::clicked, b, [b, what, text = std::move(text)] {
        if (QClipboard* cb = QGuiApplication::clipboard())
            cb->setText(text());
        b->setIcon(AppIcon::icon(QStringLiteral("check"), theme::success(), 14));
        b->setToolTip(QString::fromUtf8("已复制"));
        QTimer::singleShot(1400, b, [b, what] {
            b->setIcon(AppIcon::icon(QStringLiteral("copy"), theme::textMuted(), 14));
            b->setToolTip(what);
        });
    });
    return b;
}

inline void setPageActions(QWidget* page, QWidget* actions)
{
    if (page)
        page->setProperty("bw.pageActions", QVariant::fromValue(static_cast<QObject*>(actions)));
}

inline QWidget* pageActions(const QWidget* page)
{
    if (!page)
        return nullptr;
    return qobject_cast<QWidget*>(page->property("bw.pageActions").value<QObject*>());
}

inline QWidget* actionRow(QHBoxLayout** layoutOut)
{
    auto* w = new QWidget;
    auto* h = new QHBoxLayout(w);
    h->setContentsMargins(0, 0, 0, 0);
    h->setSpacing(8);
    if (layoutOut)
        *layoutOut = h;
    return w;
}

}
