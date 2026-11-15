#include "design/FilterChip.h"
#include "design/Icons.h"
#include "design/Theme.h"

#include <QAction>
#include <QActionGroup>
#include <QEnterEvent>
#include <QFocusEvent>
#include <QKeyEvent>
#include <QMenu>
#include <QPainter>
#include <QPainterPath>

namespace {
constexpr int kH = 36;
constexpr int kPadL = 14;
constexpr int kChevron = 12;
constexpr int kGap = 6;
constexpr int kPadR = 11;
}

FilterChip::FilterChip(const QString& label, QWidget* parent)
    : QAbstractButton(parent), m_label(label)
{
    setCursor(Qt::PointingHandCursor);
    setFocusPolicy(Qt::StrongFocus);
    setSizePolicy(QSizePolicy::Fixed, QSizePolicy::Fixed);
    connect(this, &QAbstractButton::clicked, this, &FilterChip::openMenu);
    syncAccessible();
}

void FilterChip::addOption(const QString& text, const QVariant& value)
{
    m_options.append({text, value});
    syncAccessible();
    updateGeometry();
}

void FilterChip::clearOptions()
{
    m_options.clear();
    m_index = 0;
    syncAccessible();
    updateGeometry();
    update();
}

QVariant FilterChip::currentData() const
{
    return (m_index >= 0 && m_index < m_options.size()) ? m_options[m_index].second : QVariant();
}

QString FilterChip::currentText() const
{
    return (m_index >= 0 && m_index < m_options.size()) ? m_options[m_index].first : QString();
}

void FilterChip::setCurrentIndex(int index)
{
    if (index < 0 || index >= m_options.size() || index == m_index)
        return;
    m_index = index;
    syncAccessible();
    updateGeometry();
    update();
    emit currentChanged(index);
}

QString FilterChip::shownText() const
{
    return isActive() ? QStringLiteral("%1 · %2").arg(m_label, currentText()) : m_label;
}

QSize FilterChip::sizeHint() const
{
    QFont f = font();
    f.setPointSizeF(9.5);
    f.setWeight(isActive() ? QFont::DemiBold : QFont::Medium);
    const int tw = QFontMetrics(f).horizontalAdvance(shownText());
    return {kPadL + tw + kGap + kChevron + kPadR, kH};
}

void FilterChip::paintEvent(QPaintEvent*)
{
    QPainter p(this);
    p.setRenderHint(QPainter::Antialiasing, true);
    const bool k = !theme::mecha();
    const bool active = isActive();
    // 键帽:底边加厚一截当作按键厚度。
    const QRectF r = QRectF(rect()).adjusted(1.0, 1.0, -1.0, -3.0);
    const QPainterPath body = theme::panelPath(r, k ? r.height() / 2.7 : 5.0);
    const QColor fill = active ? (k ? theme::surfaceHi() : theme::blend(theme::accent(), theme::surface(), 0.30))
                               : (m_hover ? theme::surfaceAlt() : theme::field());
    const Qt::PenJoinStyle join = k ? Qt::RoundJoin : Qt::MiterJoin;
    p.fillPath(body.translated(0, 2.0), k ? theme::pal().shadow : theme::ink());
    p.fillPath(body, fill);
    p.strokePath(body, QPen(theme::rim(), 2.0, Qt::SolidLine, Qt::FlatCap, join));
    if (m_keyboardFocus && hasFocus())
        p.strokePath(body, QPen(theme::accentDeep(), 2.0, Qt::DashLine, Qt::FlatCap, join));

    QFont f = font();
    f.setPointSizeF(9.5);
    f.setWeight(active ? QFont::Black : QFont::Bold);
    p.setFont(f);
    const QColor text = !isEnabled() ? theme::textDisabled()
                        : active     ? theme::textPrimary()
                                     : theme::textSecondary();
    p.setPen(text);
    const QRectF tr(kPadL, r.top(), width() - kPadL - kGap - kChevron - kPadR, r.height());
    p.drawText(tr, Qt::AlignVCenter | Qt::AlignLeft,
               QFontMetrics(f).elidedText(shownText(), Qt::ElideRight, int(tr.width())));
    AppIcon::draw(p, QStringLiteral("chevron-down"),
                  QRectF(width() - kPadR - kChevron, r.center().y() - kChevron / 2.0, kChevron, kChevron),
                  theme::titan() ? theme::textSecondary() : theme::ink(), 2.0);
}

void FilterChip::enterEvent(QEnterEvent* e)
{
    m_hover = true;
    update();
    QAbstractButton::enterEvent(e);
}

void FilterChip::leaveEvent(QEvent* e)
{
    m_hover = false;
    update();
    QAbstractButton::leaveEvent(e);
}

void FilterChip::focusInEvent(QFocusEvent* e)
{
    m_keyboardFocus = e->reason() == Qt::TabFocusReason || e->reason() == Qt::BacktabFocusReason;
    QAbstractButton::focusInEvent(e);
    update();
}

void FilterChip::focusOutEvent(QFocusEvent* e)
{
    m_keyboardFocus = false;
    QAbstractButton::focusOutEvent(e);
    update();
}

void FilterChip::keyPressEvent(QKeyEvent* e)
{
    if (e->key() == Qt::Key_Return || e->key() == Qt::Key_Enter || e->key() == Qt::Key_Down) {
        openMenu();
        return;
    }
    QAbstractButton::keyPressEvent(e);
}

void FilterChip::openMenu()
{
    if (m_options.isEmpty())
        return;
    QMenu menu(this);
    menu.setAccessibleName(m_label);
    auto* group = new QActionGroup(&menu);
    group->setExclusive(true);
    QList<QAction*> acts;
    for (int i = 0; i < m_options.size(); ++i) {
        QAction* a = menu.addAction(m_options[i].first);
        a->setCheckable(true);
        a->setChecked(i == m_index);
        group->addAction(a);
        acts.append(a);
        if (i == 0 && m_options.size() > 1)
            menu.addSeparator();
    }
    if (m_index >= 0 && m_index < acts.size())
        menu.setActiveAction(acts[m_index]);
    const QAction* chosen = menu.exec(mapToGlobal(QPoint(0, height() + 4)));
    const int idx = int(acts.indexOf(const_cast<QAction*>(chosen)));
    if (idx >= 0)
        setCurrentIndex(idx);
}

void FilterChip::syncAccessible()
{
    setAccessibleName(QStringLiteral("%1:%2").arg(m_label, m_options.isEmpty() ? QString() : currentText()));
}
