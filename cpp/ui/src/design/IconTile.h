#pragma once
#include "design/Icons.h"
#include "design/Motion.h"
#include "design/Theme.h"

#include <QColor>
#include <QPainter>
#include <QString>
#include <QVariantAnimation>
#include <QWidget>

// 贴纸图标块:色块即语气,墨线描边,图标统一用墨色画,浅色面板上也看得清。
class IconTile : public QWidget
{
public:
    IconTile(const QString& icon, const QColor& color, int box, int iconPx, QWidget* parent = nullptr)
        : QWidget(parent), m_icon(icon), m_color(color), m_iconPx(iconPx)
    {
        setFixedSize(box, box);
        setAttribute(Qt::WA_TransparentForMouseEvents);
    }

    void set(const QString& icon, const QColor& color)
    {
        m_icon = icon;
        m_color = color;
        update();
    }

    QString icon() const { return m_icon; }
    QColor color() const { return m_color; }

    void pop()
    {
        if (!motion::enabled())
            return;
        if (!m_pop) {
            m_pop = new QVariantAnimation(this);
            m_pop->setStartValue(0.0);
            m_pop->setEndValue(1.0);
            m_pop->setDuration(340);
            QObject::connect(m_pop, &QVariantAnimation::valueChanged, this, [this](const QVariant& v) {
                m_t = v.toReal();
                update();
            });
        }
        m_pop->stop();
        m_t = 0.0;
        m_pop->start();
    }

protected:
    void paintEvent(QPaintEvent*) override
    {
        QPainter p(this);
        p.setRenderHint(QPainter::Antialiasing, true);
        const bool popping = m_pop && m_pop->state() == QAbstractAnimation::Running;
        const qreal plate = popping ? 0.84 + 0.16 * motion::outCubic(m_t) : 1.0;
        const qreal glyph = popping ? 0.70 + 0.30 * motion::outBack(m_t) : 1.0;

        const qreal w = width() >= 30 ? 1.8 : 1.5;
        const qreal inset = width() * (1.0 - plate) / 2.0 + w / 2.0;
        const QRectF r = QRectF(rect()).adjusted(inset, inset, -inset, -inset);
        const QPainterPath path = theme::panelPath(r, r.width() * (theme::mecha() ? 0.3 : 0.26));
        const bool k = !theme::mecha();
        // 金刚的面板是暗的,淡一档的色块上墨色图标看不见:色块几乎铺满本色。
        p.fillPath(path, theme::blend(m_color, theme::surface(), theme::titan() ? 0.88 : k ? 0.42 : 0.30));
        p.strokePath(path, QPen(theme::ink(), w, Qt::SolidLine, Qt::FlatCap, k ? Qt::RoundJoin : Qt::MiterJoin));
        const qreal s = m_iconPx * glyph;
        AppIcon::draw(p, m_icon, QRectF((width() - s) / 2.0, (height() - s) / 2.0, s, s), theme::ink(),
                      qBound<qreal>(1.5, m_iconPx * 0.1, 2.5));
    }

private:
    QString m_icon;
    QColor m_color;
    int m_iconPx;
    QVariantAnimation* m_pop = nullptr;
    qreal m_t = 0.0;
};
