#pragma once
#include <QObject>
#include <QtGlobal>

#include <functional>

class QLabel;
class QString;
class QTimer;
class QWidget;

namespace motion {

bool enabled();

int duration(int ms);

qreal outCubic(qreal t);
qreal inCubic(qreal t);
qreal outBack(qreal t);
qreal slice(qreal t, qreal from, qreal to);

bool onScreen(const QWidget* w);

// 全进程共用的单调时钟(毫秒),让各处循环动画能按同一节拍算相位。
qint64 clockMs();

void countTo(QLabel* label, qint64 value, std::function<QString(qint64)> format = {});

// 循环动画的节拍器:只在 motion::enabled() 且 setActive(true) 时走帧;
// 宿主不在屏幕上(窗口最小化等)时降为低频轮询,不白画。
// 宿主隐藏 / 显示时由宿主自己调 setActive。
class Ticker final : public QObject
{
public:
    Ticker(QWidget* owner, std::function<void(qint64 nowMs)> onFrame, int intervalMs = 40);

    void setActive(bool on);
    bool isActive() const { return m_want; }

private:
    void frame();

    QWidget* m_owner;
    std::function<void(qint64)> m_onFrame;
    QTimer* m_timer;
    int m_interval;
    bool m_want = false;
};

}
