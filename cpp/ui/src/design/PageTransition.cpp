#include "design/PageTransition.h"
#include "design/Backdrop.h"
#include "design/Motion.h"
#include "design/Skin.h"

#include <QCoreApplication>
#include <QEasingCurve>
#include <QEvent>
#include <QPainter>
#include <QPixmap>
#include <QTimer>
#include <QVariantAnimation>
#include <QWidget>
#include <QtMath>

#include <cmath>
#include <utility>

namespace {

constexpr int kDurationMs = 300;
constexpr int kResizeQuietMs = 250;
constexpr qreal kRise = 16.0;

// 金刚的变形切页:六块装甲板错开 20ms 从左右两边交替推进来,合拢停一下,再从另一边退出去。
constexpr int kPlates = 6;
constexpr int kPlateMs = 520;
constexpr int kPlateStaggerMs = 20;
constexpr qreal kPlateMove = 0.42;   // 每块板「推进来」「退出去」各占它自己 520ms 的比例,中间是合拢停住的一段

int durationMs()
{
    return theme::titan() ? kPlateMs + (kPlates - 1) * kPlateStaggerMs : kDurationMs;
}

struct Frame {
    QPixmap head;
    QPixmap body;
    QPoint headAt;
    QPoint bodyAt;
};

QPixmap blankLayer(const QSize& size, qreal dpr)
{
    QPixmap pm(qMax(1, qCeil(size.width() * dpr)), qMax(1, qCeil(size.height() * dpr)));
    pm.setDevicePixelRatio(dpr);
    pm.fill(Qt::transparent);
    return pm;
}

Frame capture(QWidget* host, QWidget* header, const QList<QPointer<QWidget>>& body)
{
    Frame f;
    const qreal dpr = host->devicePixelRatioF();
    f.headAt = header->mapTo(host, QPoint(0, 0));
    f.head = blankLayer(header->size(), dpr);
    header->render(&f.head, QPoint(), QRegion(), QWidget::DrawChildren);

    f.bodyAt = QPoint(0, f.headAt.y() + header->height());
    f.body = blankLayer(QSize(host->width(), host->height() - f.bodyAt.y()), dpr);
    for (const QPointer<QWidget>& w : body)
        if (w && w->isVisible())
            w->render(&f.body, w->mapTo(host, QPoint(0, 0)) - f.bodyAt, QRegion(), QWidget::DrawChildren);
    return f;
}

class Cover final : public QWidget
{
public:
    Cover(QWidget* host, const QPixmap& plane, Frame from)
        : QWidget(host), m_plane(plane), m_from(std::move(from))
    {
        setAttribute(Qt::WA_TransparentForMouseEvents);
        setAttribute(Qt::WA_OpaquePaintEvent);
        setFocusPolicy(Qt::NoFocus);
        setGeometry(host->rect());
    }

    bool revealed() const { return m_revealed; }
    void reveal(Frame to)
    {
        m_to = std::move(to);
        m_revealed = true;
        update();
    }
    void setProgress(qreal t)
    {
        m_t = t;
        update();
    }

protected:
    void paintEvent(QPaintEvent*) override
    {
        QPainter p(this);
        p.drawPixmap(0, 0, m_plane);
        if (!m_revealed) {
            p.drawPixmap(m_from.headAt, m_from.head);
            p.drawPixmap(m_from.bodyAt, m_from.body);
            return;
        }
        if (theme::titan()) {
            paintShutter(p);
            return;
        }
        const qreal head = motion::outCubic(motion::slice(m_t, 0.0, 0.8));
        const qreal out = 1.0 - motion::outCubic(motion::slice(m_t, 0.0, 0.45));
        const qreal inT = motion::slice(m_t, 0.12, 1.0);
        const qreal in = motion::outCubic(inT);
        // 新页面升上来时略微冲过头再落定,像机械臂把面板「咔」地推到位。
        const qreal lift = motion::outBack(inT);
        if (head < 1.0) {
            p.setOpacity(1.0 - head);
            p.drawPixmap(m_from.headAt, m_from.head);
        }
        if (head > 0.0) {
            p.setOpacity(head);
            p.drawPixmap(m_to.headAt, m_to.head);
        }
        if (out > 0.0) {
            p.setOpacity(out);
            p.drawPixmap(m_from.bodyAt, m_from.body);
        }
        if (in > 0.0) {
            const qreal dpr = devicePixelRatioF();
            const qreal rise = std::round(kRise * (1.0 - lift) * dpr) / dpr;
            p.setOpacity(in);
            p.drawPixmap(QPointF(m_to.bodyAt.x(), m_to.bodyAt.y() + rise), m_to.body);
        }
    }

private:
    // 每块板只在它完全合拢的那段里换掉身后那一条,所以任何时刻都看不到新旧页面被硬切开。
    void paintShutter(QPainter& p)
    {
        static const QEasingCurve ease = [] {
            QEasingCurve c(QEasingCurve::BezierSpline);
            c.addCubicBezierSegment(QPointF(0.7, 0.0), QPointF(0.3, 1.0), QPointF(1.0, 1.0));
            return c;
        }();
        const theme::Palette& P = theme::pal();
        const qreal travel = width() + 4.0;
        const qreal ms = m_t * durationMs();
        for (int i = 0; i < kPlates; ++i) {
            const QRect band(0, height() * i / kPlates, width(), height() * (i + 1) / kPlates - height() * i / kPlates);
            const qreal u = qBound(0.0, (ms - i * kPlateStaggerMs) / kPlateMs, 1.0);
            const qreal from = i % 2 == 0 ? -1.0 : 1.0;   // 第 1、3、5 块从左边进,2、4、6 块从右边进
            qreal x = 0.0;
            if (u < kPlateMove)
                x = from * (1.0 - ease.valueForProgress(u / kPlateMove)) * travel;
            else if (u > 1.0 - kPlateMove)
                x = -from * ease.valueForProgress((u - (1.0 - kPlateMove)) / kPlateMove) * travel;

            p.save();
            p.setClipRect(band);
            const Frame& page = u < 0.5 ? m_from : m_to;
            p.drawPixmap(page.headAt, page.head);
            p.drawPixmap(page.bodyAt, page.body);
            const QRectF plate = QRectF(band).translated(x, 0.0);
            if (plate.intersects(QRectF(rect()))) {
                p.fillRect(plate, P.surfaceTop);
                p.fillRect(QRectF(plate.left(), plate.top() + 2.0, plate.width(), 3.0), i % 2 == 0 ? P.structure : P.shell);
                p.fillRect(QRectF(plate.left(), plate.top(), plate.width(), 2.0), P.ink);
                p.fillRect(QRectF(plate.left(), plate.bottom() - 2.0, plate.width(), 2.0), P.ink);
                p.fillRect(QRectF(plate.left(), plate.top(), 2.0, plate.height()), P.ink);
                p.fillRect(QRectF(plate.right() - 2.0, plate.top(), 2.0, plate.height()), P.ink);
            }
            p.restore();
        }
    }

    QPixmap m_plane;
    Frame m_from;
    Frame m_to;
    bool m_revealed = false;
    qreal m_t = 0.0;
};

}

PageTransition::PageTransition(Backdrop* host, QWidget* header, const QList<QWidget*>& body)
    : QObject(host), m_host(host), m_header(header)
{
    for (QWidget* w : body)
        m_body << QPointer<QWidget>(w);
    m_anim = new QVariantAnimation(this);
    m_anim->setStartValue(0.0);
    m_anim->setEndValue(1.0);
    connect(m_anim, &QVariantAnimation::valueChanged, this, [this](const QVariant& v) {
        if (auto* cover = static_cast<Cover*>(m_cover.data()))
            cover->setProgress(v.toReal());
    });
    connect(m_anim, &QVariantAnimation::finished, this, [this] { finish(); });
    host->installEventFilter(this);
}

PageTransition::~PageTransition() = default;

bool PageTransition::isRunning() const
{
    return !m_cover.isNull();
}

bool PageTransition::start()
{
    if (isRunning()) {
        finish();
        return false;
    }
    if (!m_header || motion::duration(durationMs()) <= 0 || !motion::onScreen(m_host))
        return false;
    if (m_host->width() < 2 || m_host->height() <= m_header->height())
        return false;
    if (m_lastResize.isValid() && m_lastResize.elapsed() < kResizeQuietMs)
        return false;

    auto* cover = new Cover(m_host, m_host->canvas(), capture(m_host, m_header, m_body));
    cover->show();
    cover->raise();
    m_cover = cover;
    QTimer::singleShot(0, this, [this] { reveal(); });
    return true;
}

void PageTransition::reveal()
{
    auto* cover = static_cast<Cover*>(m_cover.data());
    if (!cover || cover->revealed())
        return;
    for (int i = 0; i < 3; ++i)
        QCoreApplication::sendPostedEvents(nullptr, QEvent::LayoutRequest);
    const int ms = motion::duration(durationMs());
    if (!m_header || ms <= 0 || !motion::onScreen(m_host) || cover->size() != m_host->size()) {
        finish();
        return;
    }
    cover->reveal(capture(m_host, m_header, m_body));
    m_anim->stop();
    m_anim->setDuration(ms);
    m_anim->start();
}

void PageTransition::finish()
{
    m_anim->stop();
    if (QWidget* cover = m_cover.data()) {
        m_cover.clear();
        cover->hide();
        cover->deleteLater();
    }
}

bool PageTransition::eventFilter(QObject* watched, QEvent* event)
{
    if (watched == m_host) {
        switch (event->type()) {
        case QEvent::Resize:
            m_lastResize.start();
            if (isRunning())
                finish();
            break;
        case QEvent::Hide:
#if QT_VERSION >= QT_VERSION_CHECK(6, 6, 0)
        case QEvent::DevicePixelRatioChange:
#endif
            if (isRunning())
                finish();
            break;
        default:
            break;
        }
    }
    return QObject::eventFilter(watched, event);
}
