#include "design/ToggleSwitch.h"
#include "design/Theme.h"

#include <QEnterEvent>
#include <QFocusEvent>
#include <QLinearGradient>
#include <QPainter>
#include <QVariantAnimation>

#include <cmath>

ToggleSwitch::ToggleSwitch(bool on, QWidget* parent) : QAbstractButton(parent)
{
    setCheckable(true);
    setCursor(Qt::PointingHandCursor);
    m_anim = new QVariantAnimation(this);
    m_anim->setDuration(140);
    m_anim->setEasingCurve(QEasingCurve::OutCubic);
    connect(m_anim, &QVariantAnimation::valueChanged, this, [this](const QVariant& v) {
        m_pos = v.toReal();
        update();
    });
    setChecked(on);
    m_pos = on ? 1.0 : 0.0;
}

QSize ToggleSwitch::sizeHint() const { return {48, 30}; }

void ToggleSwitch::setCaution(bool on)
{
    m_caution = on;
    update();
}

void ToggleSwitch::checkStateSet()
{
    QAbstractButton::checkStateSet();
    m_anim->stop();
    m_pos = isChecked() ? 1.0 : 0.0;
    update();
}

void ToggleSwitch::nextCheckState()
{
    QAbstractButton::nextCheckState();
    m_anim->stop();
    m_anim->setStartValue(m_pos);
    m_anim->setEndValue(isChecked() ? 1.0 : 0.0);
    m_anim->start();
}

void ToggleSwitch::enterEvent(QEnterEvent*) { m_hover = true; update(); }
void ToggleSwitch::leaveEvent(QEvent*)      { m_hover = false; update(); }

void ToggleSwitch::focusInEvent(QFocusEvent* e)
{
    m_keyboardFocus = e->reason() == Qt::TabFocusReason || e->reason() == Qt::BacktabFocusReason;
    QAbstractButton::focusInEvent(e);
    update();
}

void ToggleSwitch::focusOutEvent(QFocusEvent* e)
{
    m_keyboardFocus = false;
    QAbstractButton::focusOutEvent(e);
    update();
}

void ToggleSwitch::paintEvent(QPaintEvent*)
{
    QPainter p(this);
    p.setRenderHint(QPainter::Antialiasing, true);
    if (!isEnabled())
        p.setOpacity(0.45);

    const bool k = !theme::mecha();
    const QColor ink = theme::ink();
    constexpr qreal w = 44.0, h = 24.0;
    const QRectF track((width() - w) / 2.0, (height() - h) / 2.0, w, h);
    const qreal t = qBound<qreal>(0.0, m_pos, 1.0);

    if (theme::titan()) {
        // 金刚:扁平的小拨杆,不刻字。暗槽 + 内圈细线;开时槽里通能量蓝(开着有代价的开关通琥珀),滑块从暗铬变亮铬。
        const theme::Palette& P = theme::pal();
        constexpr qreal tw = 42.0, th = 22.0;
        const QRectF tr(std::floor((width() - tw) / 2.0), std::floor((height() - th) / 2.0), tw, th);
        p.setRenderHint(QPainter::Antialiasing, false);
        p.fillRect(tr, ink);
        p.fillRect(tr.adjusted(2, 2, -2, -2), theme::blend(m_caution ? P.warning : P.glow, P.borderStrong, t));
        p.fillRect(tr.adjusted(3, 3, -3, -3),
                   theme::blend(m_caution ? QColor(0x8A, 0x5A, 0x00) : QColor(0x14, 0x89, 0xB8), P.field, t));
        const QRectF knob(tr.left() + 4.0 + std::round(18.0 * t), tr.top() + 4.0, 16.0, 14.0);
        p.fillRect(knob, ink);
        p.fillRect(knob.adjusted(2, 2, -2, -2),
                   m_hover && isEnabled() ? QColor(0xFF, 0xFF, 0xFF)
                                          : theme::blend(QColor(0xF4, 0xF7, 0xFA), QColor(0x7B, 0x87, 0x98), t));
        if (m_keyboardFocus && hasFocus()) {
            p.setRenderHint(QPainter::Antialiasing, true);
            p.setPen(QPen(theme::accentDeep(), 1.6, Qt::DashLine));
            p.setBrush(Qt::NoBrush);
            p.drawRect(tr.adjusted(-3.0, -3.0, 3.0, 3.0));
        }
        return;
    }

    if (k) {
        // 卡哇伊:糖果开关,开 = 薄荷绿
        const QColor off(0xEE, 0xE4, 0xEA);
        const QColor on = theme::cyan();
        const QRectF tr = track.adjusted(1.1, 1.1, -1.1, -1.1);
        p.setPen(QPen(ink, 2.2));
        p.setBrush(theme::blend(on, off, t));
        p.drawRoundedRect(tr, tr.height() / 2.0, tr.height() / 2.0);
        const qreal d = tr.height() - 6.0;
        const QRectF knob(tr.left() + 3.0 + (tr.width() - 6.0 - d) * t, tr.top() + 3.0, d, d);
        p.setPen(QPen(ink, 2.0));
        p.setBrush(QColor(0xFF, 0xFF, 0xFF));
        p.drawEllipse(knob);
        p.setPen(Qt::NoPen);
        p.setBrush(theme::tint(theme::accentSoft(), m_hover ? 0.9 : 0.6));
        p.drawEllipse(QRectF(knob.left() + d * 0.28, knob.top() + d * 0.28, d * 0.44, d * 0.44));
    } else {
        // 机甲:拨杆。深色槽 + ON/OFF 刻字 + 装甲白滑块,开时滑块上的指示灯亮起。
        // 金刚:槽在暗面板上要亮一档的描边,开时槽里通上能量蓝;滑块是铬银色。
        const bool dark = theme::titan();
        const bool caution = dark && m_caution;
        const QColor lamp = caution ? theme::warning() : theme::glow();
        const QRectF tr = track.adjusted(1.0, 1.0, -1.0, -1.0);
        const QPainterPath slot = theme::panelPath(tr, 5.0);
        p.fillPath(slot, dark ? theme::blend(caution ? QColor(0x7A, 0x52, 0x08) : QColor(0x0E, 0x5A, 0x7C), theme::field(), t)
                              : theme::blend(QColor(0x2B, 0x21, 0x18), QColor(0x25, 0x24, 0x21), t));
        p.strokePath(slot, QPen(theme::rim(), 2.0, Qt::SolidLine, Qt::FlatCap, Qt::MiterJoin));
        QFont f;
        f.setFamilies({QStringLiteral("Bahnschrift"), QStringLiteral("Segoe UI")});
        f.setPixelSize(8);
        f.setWeight(QFont::Bold);
        p.setFont(f);
        p.setPen(t > 0.5 ? lamp : QColor(0x80, 0x7F, 0x7C));
        p.drawText(t > 0.5 ? QRectF(tr.left() + 4, tr.top(), 18, tr.height())
                           : QRectF(tr.right() - 22, tr.top(), 18, tr.height()),
                   Qt::AlignCenter, t > 0.5 ? QStringLiteral("ON") : QStringLiteral("OFF"));
        const qreal kw = 16.0;
        const QRectF knob(tr.left() + 2.0 + (tr.width() - 4.0 - kw) * t, tr.top() + 2.0, kw, tr.height() - 4.0);
        const QPainterPath kp = theme::panelPath(knob, 3.0);
        p.fillPath(kp, m_hover ? QColor(0xFF, 0xFF, 0xFF) : dark ? theme::pal().fin : theme::pal().surface);
        p.strokePath(kp, QPen(ink, 1.8, Qt::SolidLine, Qt::FlatCap, Qt::MiterJoin));
        p.setPen(QPen(ink, 1.2));
        p.setBrush(t > 0.5 ? lamp : QColor(0x3F, 0x3E, 0x3B));
        p.drawEllipse(knob.center(), 2.6, 2.6);
    }

    if (m_keyboardFocus && hasFocus()) {
        p.setPen(QPen(theme::accentDeep(), 1.6, Qt::DashLine));
        p.setBrush(Qt::NoBrush);
        p.drawPath(theme::panelPath(track.adjusted(-3.0, -3.0, 3.0, 3.0), k ? 14.0 : 6.0));
    }
}
