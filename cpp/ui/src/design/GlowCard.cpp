#include "design/GlowCard.h"
#include "design/Sticker.h"
#include "design/Theme.h"

#include <QLayout>
#include <QPainter>
#include <QPainterPath>
#include <QSizePolicy>

GlowCard::GlowCard(QWidget* parent) : QFrame(parent)
{
    setFrameShape(QFrame::NoFrame);
}

bool GlowCard::hasHeightForWidth() const
{
    if (const QLayout* l = layout())
        return l->hasHeightForWidth();
    return false;
}

int GlowCard::heightForWidth(int w) const
{
    if (QLayout* l = layout()) {
        if (l->hasHeightForWidth()) {
            const int h = l->totalHeightForWidth(w);
            if (h > 0)
                return h;
        }
    }
    return sizeHint().height();
}

void GlowCard::setTone(Tone tone)
{
    m_tone = tone;
    update();
}

void GlowCard::setRadius(qreal radius)
{
    m_radius = radius;
    update();
}

void GlowCard::setGlow(const QColor& color, QPointF anchor, qreal reach, qreal strength)
{
    m_glow = color;
    m_anchor = anchor;
    m_reach = reach;
    m_strength = strength;
    update();
}

void GlowCard::clearGlow()
{
    m_glow = QColor();
    update();
}

void GlowCard::setBand(const QColor& color, int height, bool striped)
{
    if (color == m_band && height == m_bandH && striped == m_bandStriped)
        return;
    m_band = color;
    m_bandH = height;
    m_bandStriped = striped;
    update();
}

void GlowCard::setBandOffset(qreal px)
{
    if (qFuzzyCompare(px + 1.0, m_bandOffset + 1.0))
        return;
    m_bandOffset = px;
    if (m_band.isValid() && m_bandH > 0 && m_bandStriped)
        update(QRect(0, 0, width(), m_bandH + 8));
}

void GlowCard::paintEvent(QPaintEvent*)
{
    QPainter p(this);
    p.setRenderHint(QPainter::Antialiasing, true);
    if (width() < 8 || height() < 8)
        return;

    QColor fill;
    bool shadow = true;
    switch (m_tone) {
    case Tone::Flat:
        fill = theme::surface();
        break;
    case Tone::Inset:
        fill = theme::surfaceAlt();
        shadow = false;
        break;
    case Tone::Floating:
        fill = theme::raised();
        break;
    case Tone::Rail:
        fill = theme::pal().screen;
        shadow = false;
        break;
    }
    const qreal corner = qBound<qreal>(4.0, m_radius * 0.85, 18.0);
    const QRectF body = sticker::panel(p, QRectF(rect()), fill, corner, shadow);

    if (m_band.isValid() && m_bandH > 0) {
        const QPainterPath shape = theme::panelPath(body, corner);
        p.save();
        p.setClipPath(shape);
        const QRectF band(body.left(), body.top(), body.width(), m_bandH);
        if (m_bandStriped)
            sticker::hazard(p, band, m_band, theme::mecha() ? theme::ink() : QColor(0xFF, 0xFF, 0xFF), 13.0,
                            m_bandOffset);
        else
            p.fillRect(band, m_band);
        p.setPen(QPen(theme::ink(), 2.0));
        p.drawLine(QPointF(body.left(), band.bottom() + 1), QPointF(body.right(), band.bottom() + 1));
        p.restore();
        p.strokePath(shape, QPen(theme::ink(), theme::inkWidth(), Qt::SolidLine, Qt::FlatCap,
                                 theme::mecha() ? Qt::MiterJoin : Qt::RoundJoin));
        return;
    }

    // 「辉光」在贴纸语汇里是面板顶上的一道色带:颜色即语气(风险、类型)。
    if (m_glow.isValid() && m_strength > 0.0) {
        const qreal band = qBound<qreal>(4.0, 4.0 + m_strength * 14.0, 7.0);
        const QPainterPath shape = theme::panelPath(body, corner);
        p.save();
        p.setClipPath(shape);
        const QRectF strip(body.left(), body.top(), body.width(), band);
        p.fillRect(strip, m_glow);
        p.setPen(QPen(theme::ink(), 1.4));
        p.drawLine(QPointF(body.left(), strip.bottom() + 0.7), QPointF(body.right(), strip.bottom() + 0.7));
        p.restore();
        p.strokePath(shape, QPen(theme::ink(), theme::inkWidth(), Qt::SolidLine, Qt::FlatCap,
                                 theme::mecha() ? Qt::MiterJoin : Qt::RoundJoin));
    }
}
