#include "design/Motion.h"

#include <QElapsedTimer>
#include <QLabel>
#include <QString>
#include <QTimer>
#include <QVariantAnimation>
#include <QWidget>
#include <QtGlobal>

#include <cmath>
#include <optional>
#include <utility>

#ifdef Q_OS_WIN
#  ifndef NOMINMAX
#    define NOMINMAX
#  endif
#  include <windows.h>
#endif

namespace motion {

bool enabled()
{
    static const bool on = [] {
        const QString forced = qEnvironmentVariable("BULWARK_UI_MOTION");
        if (!forced.isEmpty())
            return forced != QLatin1String("0");
#ifdef Q_OS_WIN
        BOOL v = TRUE;
        if (SystemParametersInfoW(SPI_GETCLIENTAREAANIMATION, 0, &v, 0))
            return v != FALSE;
#endif
        return true;
    }();
    return on;
}

int duration(int ms)
{
    return enabled() ? ms : 0;
}

qreal outCubic(qreal t)
{
    const qreal u = 1.0 - qBound<qreal>(0.0, t, 1.0);
    return 1.0 - u * u * u;
}

qreal inCubic(qreal t)
{
    const qreal c = qBound<qreal>(0.0, t, 1.0);
    return c * c * c;
}

qreal outBack(qreal t)
{
    constexpr qreal s = 1.70158;
    const qreal u = qBound<qreal>(0.0, t, 1.0) - 1.0;
    return 1.0 + (s + 1.0) * u * u * u + s * u * u;
}

qreal slice(qreal t, qreal from, qreal to)
{
    if (to <= from)
        return t >= to ? 1.0 : 0.0;
    return qBound<qreal>(0.0, (t - from) / (to - from), 1.0);
}

bool onScreen(const QWidget* w)
{
    if (!w || !w->isVisible())
        return false;
    const QWidget* win = w->window();
    return win && win->isVisible() && !win->isMinimized();
}

qint64 clockMs()
{
    static const QElapsedTimer clock = [] {
        QElapsedTimer t;
        t.start();
        return t;
    }();
    return clock.elapsed();
}

Ticker::Ticker(QWidget* owner, std::function<void(qint64)> onFrame, int intervalMs)
    : QObject(owner), m_owner(owner), m_onFrame(std::move(onFrame)), m_timer(new QTimer(this)),
      m_interval(intervalMs)
{
    m_timer->setInterval(m_interval);
    connect(m_timer, &QTimer::timeout, this, [this] { frame(); });
}

void Ticker::setActive(bool on)
{
    m_want = on && enabled();
    if (!m_want) {
        m_timer->stop();
        return;
    }
    if (!m_timer->isActive()) {
        m_timer->setInterval(m_interval);
        m_timer->start();
        frame();
    }
}

void Ticker::frame()
{
    constexpr int kIdlePoll = 400;
    if (!onScreen(m_owner)) {
        if (m_timer->interval() != kIdlePoll)
            m_timer->setInterval(kIdlePoll);
        return;
    }
    if (m_timer->interval() != m_interval)
        m_timer->setInterval(m_interval);
    if (m_onFrame)
        m_onFrame(clockMs());
}

namespace {

class CountRoll final : public QVariantAnimation
{
public:
    explicit CountRoll(QLabel* label) : QVariantAnimation(label), m_label(label)
    {
        setEasingCurve(QEasingCurve::OutCubic);
        connect(this, &QVariantAnimation::valueChanged, this, [this](const QVariant& v) {
            show(qint64(std::llround(v.toDouble())));
        });
    }

    QString render(qint64 v) const { return format ? format(v) : QString::number(v); }

    void show(qint64 v)
    {
        shown = v;
        const QString text = render(v);
        if (m_label->text() != text)
            m_label->setText(text);
    }

    std::function<QString(qint64)> format;
    qint64 shown = 0;

private:
    QLabel* m_label;
};

CountRoll* rollOf(QLabel* label)
{
    for (QObject* c : label->children())
        if (auto* r = dynamic_cast<CountRoll*>(c))
            return r;
    return nullptr;
}

}

void countTo(QLabel* label, qint64 value, std::function<QString(qint64)> format)
{
    if (!label)
        return;
    CountRoll* roll = rollOf(label);

    std::optional<qint64> from;
    if (roll && (roll->state() == QAbstractAnimation::Running || label->text() == roll->render(roll->shown))) {
        from = roll->shown;
    } else {
        bool ok = false;
        const qint64 parsed = label->text().trimmed().toLongLong(&ok);
        if (ok)
            from = parsed;
    }

    const qint64 delta = from ? value - *from : 0;
    const bool animate = from && (delta > 1 || delta < -1) && enabled() && onScreen(label);
    if (!animate) {
        if (roll) {
            roll->stop();
            roll->format = std::move(format);
            roll->show(value);
        } else {
            label->setText(format ? format(value) : QString::number(value));
        }
        return;
    }

    if (!roll)
        roll = new CountRoll(label);
    roll->stop();
    roll->format = std::move(format);
    roll->shown = *from;
    // Bigger jumps roll a little longer, but never long enough to wait for.
    const double magnitude = std::log10(double(delta > 0 ? delta : -delta));
    roll->setDuration(duration(qBound(360, 300 + int(magnitude * 150.0), 760)));
    roll->setStartValue(double(*from));
    roll->setEndValue(double(value));
    roll->start();
}

}
