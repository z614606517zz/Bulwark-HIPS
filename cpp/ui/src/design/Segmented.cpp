#include "design/Segmented.h"
#include "design/Theme.h"

#include <QAbstractButton>
#include <QButtonGroup>
#include <QEnterEvent>
#include <QFocusEvent>
#include <QHBoxLayout>
#include <QKeyEvent>
#include <QLinearGradient>
#include <QPainter>

#include <utility>

namespace {
constexpr int kPad = 3;
}

class SegmentButton : public QAbstractButton
{
public:
    SegmentButton(Segmented* owner, const QString& text, const QVariant& data)
        : QAbstractButton(owner), m_owner(owner), m_data(data)
    {
        setText(text);
        setCheckable(true);
        setCursor(Qt::PointingHandCursor);
        setSizePolicy(QSizePolicy::Preferred, QSizePolicy::Fixed);
        syncAccessible();
    }

    QVariant data() const { return m_data; }

    void setCount(int n)
    {
        if (n == m_count)
            return;
        m_count = n;
        syncAccessible();
        updateGeometry();
        update();
    }
    int countValue() const { return m_count; }

    void setAccent(const QColor& c)
    {
        m_accent = c;
        update();
    }

    void setLabel(const QString& t)
    {
        setText(t);
        syncAccessible();
        updateGeometry();
        update();
    }

    QSize sizeHint() const override
    {
        const QFont f = labelFont();
        const QFontMetrics fm(f);
        int w = fm.horizontalAdvance(text());
        if (m_count >= 0)
            w += 6 + QFontMetrics(countFont()).horizontalAdvance(QString::number(m_count));
        const bool compact = m_owner->isCompact();
        return {w + (compact ? 20 : 26), compact ? 24 : 28};
    }
    QSize minimumSizeHint() const override { return sizeHint(); }

protected:
    void paintEvent(QPaintEvent*) override
    {
        QPainter p(this);
        p.setRenderHint(QPainter::Antialiasing, true);
        const bool k = !theme::mecha();
        const QRectF r = QRectF(rect()).adjusted(1.0, 1.0, -1.0, -1.0);
        const QPainterPath path = theme::panelPath(r, k ? r.height() / 2.7 : 5.0);
        const bool on = isChecked();
        const Qt::PenJoinStyle join = k ? Qt::RoundJoin : Qt::MiterJoin;

        // 选中格 = 按下去的键帽:实色 + 墨线;机甲用橙色,卡哇伊用粉色。
        QColor fill;
        if (on) {
            const QColor hue = m_owner->identity();
            if (k)
                fill = hue.isValid() ? theme::blend(hue, theme::surface(), 0.55) : theme::surfaceHi();
            else
                fill = hue.isValid() ? hue : theme::accent();
            p.fillPath(path, fill);
            p.strokePath(path, QPen(theme::ink(), 1.8, Qt::SolidLine, Qt::FlatCap, join));
        } else if (m_hover && isEnabled()) {
            p.fillPath(path, theme::tint(theme::overlay(), 0.07));
        }
        if (m_keyboardFocus && hasFocus())
            p.strokePath(path, QPen(theme::accentDeep(), 2.0, Qt::DashLine, Qt::FlatCap, join));

        const QFont lf = labelFont();
        const QFont cf = countFont();
        const QFontMetrics lfm(lf), cfm(cf);
        const QString countText = m_count >= 0 ? QString::number(m_count) : QString();
        const int lw = lfm.horizontalAdvance(text());
        const int cw = countText.isEmpty() ? 0 : 6 + cfm.horizontalAdvance(countText);
        const qreal x0 = (width() - (lw + cw)) / 2.0;

        QColor lc = on ? theme::textOn(fill)
                       : (m_hover ? theme::textPrimary() : theme::textSecondary());
        if (!isEnabled())
            lc = theme::textDisabled();
        p.setFont(lf);
        p.setPen(lc);
        p.drawText(QRectF(x0, 0, lw + 1, height()), Qt::AlignVCenter | Qt::AlignLeft, text());
        if (!countText.isEmpty()) {
            QColor cc = on ? lc : theme::textMuted();
            if (m_count > 0 && m_accent.isValid() && !on)
                cc = m_accent;
            if (!isEnabled())
                cc = theme::textDisabled();
            p.setFont(cf);
            p.setPen(cc);
            p.drawText(QRectF(x0 + lw + 6, 0, cw, height()), Qt::AlignVCenter | Qt::AlignLeft, countText);
        }
    }

    void enterEvent(QEnterEvent* e) override { m_hover = true; update(); QAbstractButton::enterEvent(e); }
    void leaveEvent(QEvent* e) override { m_hover = false; update(); QAbstractButton::leaveEvent(e); }

    void focusInEvent(QFocusEvent* e) override
    {
        m_keyboardFocus = e->reason() == Qt::TabFocusReason || e->reason() == Qt::BacktabFocusReason
                          || e->reason() == Qt::OtherFocusReason;
        QAbstractButton::focusInEvent(e);
        update();
    }
    void focusOutEvent(QFocusEvent* e) override
    {
        m_keyboardFocus = false;
        QAbstractButton::focusOutEvent(e);
        update();
    }

    void keyPressEvent(QKeyEvent* e) override
    {
        const int idx = int(m_owner->m_buttons.indexOf(this));
        switch (e->key()) {
        case Qt::Key_Left:
        case Qt::Key_Up:
            m_owner->step(idx, -1);
            return;
        case Qt::Key_Right:
        case Qt::Key_Down:
            m_owner->step(idx, +1);
            return;
        case Qt::Key_Home:
            m_owner->step(-1, +1);
            return;
        case Qt::Key_End:
            m_owner->step(m_owner->count(), -1);
            return;
        default:
            break;
        }
        QAbstractButton::keyPressEvent(e);
    }

private:
    QFont labelFont() const
    {
        QFont f = font();
        f.setPointSizeF(m_owner->isCompact() ? 9.0 : 9.5);
        f.setWeight(isChecked() ? QFont::Black : QFont::Bold);
        return f;
    }
    QFont countFont() const
    {
        QFont f = font();
        f.setPointSizeF(m_owner->isCompact() ? 8.5 : 9.0);
        f.setWeight(QFont::DemiBold);
        return f;
    }
    void syncAccessible()
    {
        setAccessibleName(m_count >= 0 ? QStringLiteral("%1 %2 %3").arg(text()).arg(m_count)
                                             .arg(QString::fromUtf8("条"))
                                       : text());
    }

    Segmented* m_owner;
    QVariant m_data;
    int m_count = -1;
    QColor m_accent;
    bool m_hover = false;
    bool m_keyboardFocus = false;
};

Segmented::Segmented(QWidget* parent) : QWidget(parent)
{
    m_group = new QButtonGroup(this);
    m_group->setExclusive(true);
    m_row = new QHBoxLayout(this);
    m_row->setContentsMargins(kPad, kPad, kPad, kPad);
    m_row->setSpacing(2);
    setSizePolicy(QSizePolicy::Fixed, QSizePolicy::Fixed);
    connect(m_group, &QButtonGroup::idToggled, this, [this](int id, bool on) {
        if (!on)
            return;
        syncFocus();
        for (SegmentButton* b : std::as_const(m_buttons))
            b->updateGeometry();
        emit currentChanged(id);
    });
}

int Segmented::addSegment(const QString& text, const QVariant& data)
{
    auto* b = new SegmentButton(this, text, data);
    const int id = int(m_buttons.size());
    m_buttons.append(b);
    m_group->addButton(b, id);
    m_row->addWidget(b);
    if (id == 0) {
        QSignalBlocker block(m_group);
        b->setChecked(true);
    }
    syncFocus();
    return id;
}

void Segmented::setText(int index, const QString& text)
{
    if (index >= 0 && index < m_buttons.size())
        m_buttons[index]->setLabel(text);
}

void Segmented::setCount(int index, int count)
{
    if (index >= 0 && index < m_buttons.size())
        m_buttons[index]->setCount(count);
}

void Segmented::setAccent(int index, const QColor& color)
{
    if (index >= 0 && index < m_buttons.size())
        m_buttons[index]->setAccent(color);
}

int Segmented::currentIndex() const { return m_group->checkedId(); }

QVariant Segmented::currentData() const { return data(currentIndex()); }

QVariant Segmented::data(int index) const
{
    return (index >= 0 && index < m_buttons.size()) ? m_buttons[index]->data() : QVariant();
}

int Segmented::indexOfData(const QVariant& d) const
{
    for (int i = 0; i < m_buttons.size(); ++i)
        if (m_buttons[i]->data() == d)
            return i;
    return -1;
}

void Segmented::setCurrentIndex(int index)
{
    if (index < 0 || index >= m_buttons.size() || index == currentIndex())
        return;
    m_buttons[index]->setChecked(true);
}

void Segmented::setCompact(bool compact)
{
    m_compact = compact;
    for (SegmentButton* b : std::as_const(m_buttons))
        b->updateGeometry();
    updateGeometry();
    update();
}

void Segmented::setIdentity(const QColor& hue)
{
    m_identity = hue;
    for (SegmentButton* b : std::as_const(m_buttons))
        b->update();
}

void Segmented::step(int from, int delta)
{
    int i = from + delta;
    while (i >= 0 && i < m_buttons.size()) {
        if (m_buttons[i]->isEnabled()) {
            m_buttons[i]->setChecked(true);
            m_buttons[i]->setFocus(Qt::OtherFocusReason);
            return;
        }
        i += delta;
    }
}

void Segmented::syncFocus()
{
    const int cur = currentIndex();
    for (int i = 0; i < m_buttons.size(); ++i)
        m_buttons[i]->setFocusPolicy(i == cur ? Qt::StrongFocus : Qt::ClickFocus);
}

void Segmented::paintEvent(QPaintEvent*)
{
    QPainter p(this);
    p.setRenderHint(QPainter::Antialiasing, true);
    const bool k = !theme::mecha();
    const QRectF r = QRectF(rect()).adjusted(1.0, 1.0, -1.0, -1.0);
    const QPainterPath path = theme::panelPath(r, k ? r.height() / 2.7 : 6.0);
    p.fillPath(path, theme::surfaceAlt());
    p.strokePath(path, QPen(theme::ink(), 2.0, Qt::SolidLine, Qt::FlatCap, k ? Qt::RoundJoin : Qt::MiterJoin));
}
