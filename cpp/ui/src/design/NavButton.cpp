#include "design/NavButton.h"
#include "design/Icons.h"
#include "design/Motion.h"
#include "design/Theme.h"

#include <QEnterEvent>
#include <QFocusEvent>
#include <QPainter>
#include <QPainterPath>
#include <QVariantAnimation>

NavButton::NavButton(const QString& iconName, const QString& text, QWidget* parent)
    : QAbstractButton(parent), m_icon(iconName), m_badgeColor(theme::danger()), m_identity(theme::accent())
{
    setText(text);
    setCheckable(true);
    setCursor(Qt::PointingHandCursor);
    setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
    syncAccessible();

    m_anim = new QVariantAnimation(this);
    m_anim->setDuration(motion::duration(120));
    m_anim->setEasingCurve(QEasingCurve::OutCubic);
    connect(m_anim, &QVariantAnimation::valueChanged, this, [this](const QVariant& v) {
        m_hover = v.toReal();
        update();
    });

    m_selAnim = new QVariantAnimation(this);
    m_selAnim->setEasingCurve(QEasingCurve::OutCubic);
    connect(m_selAnim, &QVariantAnimation::valueChanged, this, [this](const QVariant& v) {
        m_select = v.toReal();
        update();
    });
    connect(this, &QAbstractButton::toggled, this, &NavButton::animateSelection);
}

QSize NavButton::sizeHint() const { return m_compact ? QSize(44, 38) : QSize(200, 38); }

void NavButton::setCompact(bool compact)
{
    if (compact == m_compact)
        return;
    m_compact = compact;
    setToolTip(compact ? text() : QString());
    updateGeometry();
    update();
}

void NavButton::setBadge(int count, const QColor& color)
{
    count = qMax(0, count);
    if (color.isValid())
        m_badgeColor = color;
    if (count == m_badge)
        return;
    m_badge = count;
    syncAccessible();
    update();
}

void NavButton::setIdentity(const QColor& hue)
{
    m_identity = hue.isValid() ? hue : theme::accent();
    update();
}

void NavButton::syncAccessible()
{
    setAccessibleName(m_badge > 0 ? QString::fromUtf8("%1,%2 条未读").arg(text()).arg(m_badge) : text());
}

void NavButton::fadeHover(qreal to)
{
    m_anim->stop();
    if (m_anim->duration() <= 0) {
        m_hover = to;
        update();
        return;
    }
    m_anim->setStartValue(m_hover);
    m_anim->setEndValue(to);
    m_anim->start();
}

void NavButton::animateSelection(bool on)
{
    const qreal to = on ? 1.0 : 0.0;
    m_selAnim->stop();
    m_selecting = on;
    const int ms = motion::onScreen(this) ? motion::duration(on ? 220 : 160) : 0;
    if (ms <= 0) {
        m_select = to;
        update();
        return;
    }
    m_selAnim->setDuration(ms);
    m_selAnim->setStartValue(m_select);
    m_selAnim->setEndValue(to);
    m_selAnim->start();
}

void NavButton::enterEvent(QEnterEvent*) { fadeHover(1.0); }
void NavButton::leaveEvent(QEvent*)      { fadeHover(0.0); }

void NavButton::focusInEvent(QFocusEvent* e)
{
    m_keyboardFocus = e->reason() == Qt::TabFocusReason || e->reason() == Qt::BacktabFocusReason;
    QAbstractButton::focusInEvent(e);
    update();
}

void NavButton::focusOutEvent(QFocusEvent* e)
{
    m_keyboardFocus = false;
    QAbstractButton::focusOutEvent(e);
    update();
}

void NavButton::paintEvent(QPaintEvent*)
{
    QPainter p(this);
    p.setRenderHint(QPainter::Antialiasing, true);

    const QRectF r = QRectF(rect()).adjusted(1.5, 1.5, -1.5, -1.5);
    const bool active = isChecked();
    const qreal sel = m_select;
    const bool k = !theme::mecha();
    const QColor hue = m_identity;
    const QColor ink = theme::ink();
    // 选中 / 悬停时图标与文字往「最醒目」的那一端走:浅色皮肤是墨色,金刚的暗面板上是主文字色。
    const QColor strong = theme::titan() ? theme::textPrimary() : ink;
    const QPainterPath shape = theme::panelPath(r, k ? 12.0 : 7.0);
    const Qt::PenJoinStyle join = k ? Qt::RoundJoin : Qt::MiterJoin;

    const qreal lift = m_hover * (1.0 - sel);
    if (lift > 0.001)
        p.fillPath(shape, theme::tint(theme::overlay(), 0.06 * lift));
    if (sel > 0.001) {
        // 选中 = 贴上一块色贴:身份色铺底 + 墨线描边。
        p.save();
        p.setOpacity(qMin<qreal>(1.0, sel * 1.5));
        p.fillPath(shape, theme::blend(hue, theme::surface(), k ? 0.40 : 0.28));
        p.strokePath(shape, QPen(ink, 2.0, Qt::SolidLine, Qt::FlatCap, join));
        p.restore();
    }

    if (m_keyboardFocus && hasFocus())
        p.strokePath(shape, QPen(theme::accentDeep(), 1.6, Qt::DashLine, Qt::FlatCap, join));

    const QColor glyph = theme::blend(strong, theme::textSecondary(), qMax(sel, m_hover));
    const QRectF iconRect = m_compact ? QRectF(r.center().x() - 9, r.center().y() - 9, 18, 18)
                                      : QRectF(r.left() + 12, r.center().y() - 9, 18, 18);
    AppIcon::draw(p, m_icon, iconRect, glyph, active ? 2.0 : 1.8);

    const QString badgeText = m_badge > 99 ? QStringLiteral("99+") : QString::number(m_badge);
    QFont bf = font();
    bf.setPointSizeF(m_compact ? 7.5 : 8.0);
    bf.setWeight(QFont::Black);
    const QFontMetricsF bfm(bf);
    const auto badge = [&](const QRectF& b) {
        const QPainterPath bp = theme::panelPath(b, k ? b.height() / 2.7 : 3.0);
        p.fillPath(bp, m_badgeColor);
        p.strokePath(bp, QPen(ink, 1.8, Qt::SolidLine, Qt::FlatCap, join));
        p.setFont(bf);
        p.setPen(theme::textOn(m_badgeColor));
        p.drawText(b, Qt::AlignCenter, badgeText);
    };

    if (m_compact) {
        if (m_badge > 0)
            badge(QRectF(iconRect.right() - 5, iconRect.top() - 7,
                         qMax<qreal>(16.0, bfm.horizontalAdvance(badgeText) + 9), 16));
        return;
    }

    qreal textRight = r.right() - 8;
    if (m_badge > 0) {
        const qreal bw = qMax<qreal>(22.0, bfm.horizontalAdvance(badgeText) + 12);
        const QRectF b(r.right() - 8 - bw, r.center().y() - 9, bw, 18);
        badge(b);
        textRight = b.left() - 6;
    }

    QFont f = font();
    f.setPointSizeF(10.0);
    f.setWeight(active ? QFont::Black : QFont::DemiBold);
    p.setFont(f);
    p.setPen(theme::blend(strong, theme::blend(strong, theme::textSecondary(), m_hover), qMax<qreal>(sel, 0.4)));
    const QRectF tr(r.left() + 40, r.top(), qMax<qreal>(0, textRight - (r.left() + 40)), r.height());
    p.drawText(tr, Qt::AlignVCenter | Qt::AlignLeft,
               QFontMetricsF(f).elidedText(text(), Qt::ElideRight, tr.width()));
}
