#pragma once
#include <QColor>
#include <QElapsedTimer>
#include <QPoint>
#include <QPointer>
#include <QWidget>

#include <functional>

class QTimer;

class CountdownBar : public QWidget
{
    Q_OBJECT
public:
    explicit CountdownBar(QWidget* parent = nullptr);

    void start(int ms);
    void stop();
    void pause();
    void resume();
    void ensureRemaining(int ms);

    void setHoverPause(QWidget* target);
    bool isRunning() const { return m_running; }
    bool isPaused() const { return m_paused; }
    int remainingMs() const;
    int totalMs() const { return m_total; }

    void setColor(const QColor& c);
    void setFormatter(std::function<QString(int secondsLeft)> fmt);

    QSize sizeHint() const override;
    QSize minimumSizeHint() const override;

signals:
    void finished();
    void secondChanged(int secondsLeft);

protected:
    void paintEvent(QPaintEvent*) override;

private:
    void tick();
    QString caption() const;
    void syncHoverPause();
    bool pointerOnTarget(const QPoint& globalPos) const;

    QTimer* m_timer = nullptr;
    QElapsedTimer m_clock;
    int m_total = 0;
    int m_base = 0;
    bool m_running = false;
    bool m_paused = false;
    int m_lastSecond = -1;
    QColor m_color;
    std::function<QString(int)> m_fmt;

    QPointer<QWidget> m_hoverTarget;
    QTimer* m_hoverTimer = nullptr;
    QPoint m_lastCursor;
    bool m_hoverArmed = false;
};
