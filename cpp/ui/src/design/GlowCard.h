#pragma once
#include <QColor>
#include <QFrame>
#include <QPointF>

class GlowCard : public QFrame
{
public:
    enum class Tone { Flat, Inset, Floating, Rail };

    explicit GlowCard(QWidget* parent = nullptr);

    void setTone(Tone tone);
    Tone tone() const { return m_tone; }

    void setRadius(qreal radius);

    void setGlow(const QColor& color, QPointF anchor = QPointF(0.0, 0.0),
                 qreal reach = 0.75, qreal strength = 0.20);
    void clearGlow();
    QColor glowColor() const { return m_glow; }

    // 顶部的警示斑马带(弹窗用):颜色 = 风险,高度 = 眉标签那一行。striped=false 时是实色标题带。
    void setBand(const QColor& color, int height, bool striped = true);
    // 斑马条的横向偏移(像素),循环推进它就是「行进中」的警示带。只重画色带那一条。
    void setBandOffset(qreal px);
    int bandHeight() const { return m_bandH; }

protected:
    void paintEvent(QPaintEvent*) override;
    bool hasHeightForWidth() const override;
    int heightForWidth(int w) const override;

private:
    Tone m_tone = Tone::Flat;
    qreal m_radius = 16.0;
    QColor m_glow;
    QPointF m_anchor{0.0, 0.0};
    qreal m_reach = 0.75;
    qreal m_strength = 0.20;
    QColor m_band;
    int m_bandH = 0;
    bool m_bandStriped = true;
    qreal m_bandOffset = 0.0;
};
