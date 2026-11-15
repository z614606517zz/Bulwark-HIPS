#include "design/Backdrop.h"
#include "design/Theme.h"

#include <QEvent>
#include <QPaintEvent>
#include <QPainter>
#include <QResizeEvent>

namespace {

void blit(QPainter& p, const QPixmap& cache, const QRect& dirty)
{
    const qreal dpr = cache.devicePixelRatio();
    p.drawPixmap(QRectF(dirty), cache,
                 QRectF(dirty.x() * dpr, dirty.y() * dpr, dirty.width() * dpr, dirty.height() * dpr));
}

class WindowMaterial final : public QObject
{
public:
    explicit WindowMaterial(QWidget* window) : QObject(window) {}

protected:
    bool eventFilter(QObject* obj, QEvent* ev) override
    {
        auto* w = static_cast<QWidget*>(obj);
        if (ev->type() == QEvent::Resize) {
            m_cache = QPixmap();
        } else if (ev->type() == QEvent::Paint) {
            if (m_cache.isNull() || !qFuzzyCompare(m_cache.devicePixelRatio(), w->devicePixelRatioF()))
                m_cache = Backdrop::render(Backdrop::Kind::Content, w->size(), w->devicePixelRatioF());
            QPainter p(w);
            blit(p, m_cache, static_cast<QPaintEvent*>(ev)->rect());
        }
        return false;
    }

private:
    QPixmap m_cache;
};

}

Backdrop::Backdrop(Kind kind, QWidget* parent) : QFrame(parent), m_kind(kind)
{
    setFrameShape(QFrame::NoFrame);
    setAttribute(Qt::WA_OpaquePaintEvent);
}

void Backdrop::install(QWidget* window)
{
    if (window)
        window->installEventFilter(new WindowMaterial(window));
}

void Backdrop::resizeEvent(QResizeEvent* e)
{
    QFrame::resizeEvent(e);
    m_cache = QPixmap();
}

QPixmap Backdrop::render(Kind, const QSize& size, qreal dpr)
{
    const int w = qMax(1, size.width());
    const int h = qMax(1, size.height());
    QPixmap pm(qMax(1, int(w * dpr)), qMax(1, int(h * dpr)));
    pm.setDevicePixelRatio(dpr);

    QPainter p(&pm);
    const QRectF r(0, 0, w, h);
    p.fillRect(r, theme::bg());
    if (theme::mecha()) {
        // 机甲:墨色工程网格压在浅底上;金刚:同一张网格换成淡淡的蓝白线浮在暗底上。
        p.setRenderHint(QPainter::Antialiasing, false);
        constexpr int step = 24;
        const QColor grid = theme::titan() ? QColor(0x78, 0x96, 0xC8) : theme::ink();
        const QColor fine = theme::tint(grid, theme::titan() ? 0.05 : 0.045);
        const QColor bold = theme::tint(grid, theme::titan() ? 0.09 : 0.075);
        for (int x = 0; x <= w; x += step) {
            p.setPen(QPen(x % (step * 5) == 0 ? bold : fine, 1.0));
            p.drawLine(x, 0, x, h);
        }
        for (int y = 0; y <= h; y += step) {
            p.setPen(QPen(y % (step * 5) == 0 ? bold : fine, 1.0));
            p.drawLine(0, y, w, y);
        }
        p.fillRect(r, theme::grainBrush());
    } else {
        p.setRenderHint(QPainter::Antialiasing, true);
        p.setPen(Qt::NoPen);
        constexpr int step = 30;
        const QColor a(0xFF, 0xD6, 0xE1);
        const QColor b(0xE5, 0xDC, 0xFF);
        for (int y = 0; y <= h + step; y += step) {
            for (int x = 0; x <= w + step; x += step) {
                p.setBrush(a);
                p.drawEllipse(QPointF(x, y), 2.4, 2.4);
                p.setBrush(b);
                p.drawEllipse(QPointF(x + step / 2.0, y + step / 2.0), 2.4, 2.4);
            }
        }
    }
    p.end();
    return pm;
}

QPixmap Backdrop::canvas()
{
    if (m_cache.isNull() || !qFuzzyCompare(m_cache.devicePixelRatio(), devicePixelRatioF()))
        m_cache = render(m_kind, size(), devicePixelRatioF());
    return m_cache;
}

void Backdrop::paintEvent(QPaintEvent* e)
{
    const QPixmap plane = canvas();
    QPainter p(this);
    blit(p, plane, e->rect());
}
