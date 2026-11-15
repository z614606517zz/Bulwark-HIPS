#include "design/CountdownBar.h"
#include "design/Motion.h"
#include "design/Theme.h"

#include <QCursor>
#include <QFontMetrics>
#include <QPainter>
#include <QPainterPath>
#include <QRect>
#include <QTimer>

#include <cmath>

namespace {
constexpr int kHoverPollMs = 120;
}

CountdownBar::CountdownBar(QWidget* parent) : QWidget(parent), m_color(theme::accent())
{
    setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
    m_timer = new QTimer(this);
    m_timer->setInterval(motion::enabled() ? 50 : 250);
    connect(m_timer, &QTimer::timeout, this, &CountdownBar::tick);
    setAccessibleName(QString::fromUtf8("倒计时"));
}

void CountdownBar::start(int ms)
{
    m_total = qMax(1, ms);
    m_base = m_total;
    m_running = true;
    m_paused = false;
    m_lastSecond = -1;
    m_clock.start();
    m_timer->start();
    if (m_hoverTimer) {
        m_hoverArmed = false;
        m_lastCursor = QCursor::pos();
        m_hoverTimer->start();
    }
    tick();
}

void CountdownBar::stop()
{
    m_running = false;
    m_paused = false;
    m_hoverArmed = false;
    m_timer->stop();
    if (m_hoverTimer)
        m_hoverTimer->stop();
    update();
}

void CountdownBar::pause()
{
    if (!m_running || m_paused)
        return;
    m_base = remainingMs();
    m_paused = true;
    m_timer->stop();
    update();
}

void CountdownBar::resume()
{
    if (!m_running || !m_paused)
        return;
    m_paused = false;
    m_clock.start();
    m_timer->start();
    update();
}

void CountdownBar::ensureRemaining(int ms)
{
    if (!m_running) {
        start(ms);
        return;
    }
    if (remainingMs() >= ms)
        return;
    m_base = ms;
    m_total = qMax(m_total, ms);
    if (!m_paused)
        m_clock.start();
    m_lastSecond = -1;
    tick();
}

int CountdownBar::remainingMs() const
{
    if (!m_running)
        return 0;
    if (m_paused)
        return m_base;
    return qMax(0, m_base - int(m_clock.elapsed()));
}

void CountdownBar::setHoverPause(QWidget* target)
{
    m_hoverTarget = target;
    if (!target)
        return;
    if (!m_hoverTimer) {
        m_hoverTimer = new QTimer(this);
        m_hoverTimer->setInterval(kHoverPollMs);
        connect(m_hoverTimer, &QTimer::timeout, this, &CountdownBar::syncHoverPause);
    }
    if (m_running)
        m_hoverTimer->start();
}

void CountdownBar::syncHoverPause()
{
    if (!m_running || !m_hoverTarget) {
        if (m_hoverTimer)
            m_hoverTimer->stop();
        return;
    }
    const QPoint now = QCursor::pos();
    const bool moved = now != m_lastCursor;
    m_lastCursor = now;
    if (!pointerOnTarget(now)) {
        m_hoverArmed = false;
        resume();
        return;
    }
    if (moved)
        m_hoverArmed = true;
    if (m_hoverArmed)
        pause();
}

bool CountdownBar::pointerOnTarget(const QPoint& globalPos) const
{
    const QWidget* t = m_hoverTarget.data();
    if (!t || !t->isVisible())
        return false;
    const QWidget* win = t->window();
    if (!win || !win->isVisible() || win->isMinimized())
        return false;
    return QRect(t->mapToGlobal(QPoint(0, 0)), t->size()).contains(globalPos);
}

void CountdownBar::setColor(const QColor& c)
{
    m_color = c;
    update();
}

void CountdownBar::setFormatter(std::function<QString(int)> fmt)
{
    m_fmt = std::move(fmt);
    updateGeometry();
    update();
}

QSize CountdownBar::sizeHint() const
{
    return {200, m_fmt ? qMax(18, fontMetrics().height() + 2) : 8};
}

QSize CountdownBar::minimumSizeHint() const
{
    if (!m_fmt)
        return {40, 6};
    QFont f = font();
    f.setPointSizeF(9.0);
    const int capW = QFontMetrics(f).horizontalAdvance(m_fmt(88)) + 2;
    return {48 + 10 + capW, sizeHint().height()};
}

QString CountdownBar::caption() const
{
    if (!m_fmt)
        return QString();
    return m_fmt(int(std::ceil(remainingMs() / 1000.0)));
}

void CountdownBar::tick()
{
    const int left = remainingMs();
    const int secs = int(std::ceil(left / 1000.0));
    if (secs != m_lastSecond) {
        m_lastSecond = secs;
        const QString cap = caption();
        if (!cap.isEmpty())
            setAccessibleDescription(cap);
        emit secondChanged(secs);
    }
    update();
    if (m_running && !m_paused && left <= 0) {
        m_running = false;
        m_timer->stop();
        if (m_hoverTimer)
            m_hoverTimer->stop();
        emit finished();
    }
}

void CountdownBar::paintEvent(QPaintEvent*)
{
    QPainter p(this);
    p.setRenderHint(QPainter::Antialiasing, true);
    const QString cap = caption();
    QFont f = font();
    f.setPointSizeF(9.0);
    f.setWeight(QFont::Bold);
    constexpr int gap = 10;
    const int capW = cap.isEmpty() ? 0 : QFontMetrics(f).horizontalAdvance(cap) + 2;
    const qreal barW = qMax(10, width() - (cap.isEmpty() ? 0 : capW + gap));
    const bool k = !theme::mecha();
    const qreal h = qMin<qreal>(height() - 2.0, cap.isEmpty() ? 6.0 : 10.0);
    const QRectF track(1, (height() - h) / 2.0, barW - 2, h);
    const qreal frac = m_total > 0 ? qBound<qreal>(0.0, qreal(remainingMs()) / m_total, 1.0) : 0.0;

    // 能量格:一格一格熄灭。机甲是斜切的电池格,卡哇伊是圆糖豆。
    const qreal cell = k ? h + 4.0 : h * 0.9 + 3.0;
    const int n = qMax(4, int(track.width() / cell));
    const qreal step = track.width() / n;
    const int lit = int(std::ceil(frac * n - 1e-6));
    const QColor dim = theme::tint(theme::overlay(), 0.12);
    // 动画开着时:最后一格随剩余时间渐暗而不是突然熄灭;最后 5 秒所有亮格一起闪。
    const bool live = motion::enabled() && m_running && !m_paused;
    const qreal edge = qBound<qreal>(0.0, frac * n - (lit - 1), 1.0);
    const int left = remainingMs();
    const bool flash = live && left <= 5000 && (left / 250) % 2 == 0;
    for (int i = 0; i < n; ++i) {
        const QRectF c(track.left() + i * step + 1, track.top(), step - 2.5, h);
        QPainterPath path;
        if (k) {
            path.addRoundedRect(c, h / 2, h / 2);
        } else {
            const qreal sk = h * 0.35;
            path.moveTo(c.left() + sk, c.top());
            path.lineTo(c.right(), c.top());
            path.lineTo(c.right() - sk, c.bottom());
            path.lineTo(c.left(), c.bottom());
            path.closeSubpath();
        }
        const QColor fill = i < lit ? (flash ? m_color.lighter(150) : m_color) : dim;
        if (live && i == lit - 1) {
            p.fillPath(path, dim);
            p.setOpacity(0.3 + 0.7 * edge);
            p.fillPath(path, fill);
            p.setOpacity(1.0);
        } else {
            p.fillPath(path, fill);
        }
        if (i < lit && h >= 8)
            p.strokePath(path, QPen(theme::ink(), 1.2));
    }
    if (!cap.isEmpty()) {
        p.setFont(f);
        p.setPen(m_paused ? theme::textPrimary() : theme::textSecondary());
        p.drawText(QRectF(barW + gap, 0, capW, height()), Qt::AlignVCenter | Qt::AlignLeft, cap);
    }
}
