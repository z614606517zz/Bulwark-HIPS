#pragma once
#include "design/Robot.h"

#include <QPoint>
#include <QPointer>
#include <QString>
#include <QWidget>

class QTimer;
namespace motion { class Ticker; }

// 常驻机器人小垒:站在任务栏上方的置顶小窗。表情 = 防护状态;拦截 / 询问时冒气泡;
// 鼠标停在它身上递出「指挥终端」;双击切雷达(流量悬浮窗);右键菜单;可拖动,位置会记住。
class ResidentBot : public QWidget
{
    Q_OBJECT
public:
    explicit ResidentBot(QWidget* parent = nullptr);
    ~ResidentBot() override;

    static ResidentBot* instance();
    static bool savedEnabled();
    bool residentEnabled() const { return m_enabled; }
    void setResidentEnabled(bool on);
    void applySavedState();

    void setStatus(robot::Mood mood, const QString& text, const QString& tip);
    void setBlocked(int count);
    void setPending(int count);
    // ms <= 0:一直挂着,直到下一句或状态变化。
    void say(robot::Mood mood, const QString& text, int ms = 4000);

signals:
    void openMainRequested();
    void radarRequested();
    void pageRequested(const QString& key);
    void enabledChanged(bool on);

protected:
    void paintEvent(QPaintEvent*) override;
    void mousePressEvent(QMouseEvent* e) override;
    void mouseMoveEvent(QMouseEvent* e) override;
    void mouseReleaseEvent(QMouseEvent* e) override;
    void mouseDoubleClickEvent(QMouseEvent* e) override;
    void contextMenuEvent(QContextMenuEvent* e) override;
    void enterEvent(QEnterEvent* e) override;
    void leaveEvent(QEvent* e) override;
    void showEvent(QShowEvent* e) override;
    void hideEvent(QHideEvent* e) override;

private:
    robot::Mood mood() const;
    QRectF robotRect() const;
    void placeDefault();
    void clampToScreen();
    void savePosition();
    void showTerminal();
    void hideTerminal();
    void refreshTerminal();
    void scheduleBlink();
    // 动画:平时静止,只在出场、说话、抖动、蹦跳、挥手、喷焰和偶尔的「小动作」期间走帧。
    void kick();
    bool busy(qint64 now) const;
    void scheduleIdle();
    void startIdle();
    // 金刚:平时是停在任务栏上的小卡车;有话要说、等你下令、递出指挥终端时变形站起来。
    void syncForm();
    qreal form(qint64 now) const;

    bool m_enabled = true;
    robot::Mood m_statusMood = robot::Mood::Sleep;
    QString m_statusText;
    QString m_statusTip;
    robot::Mood m_sayMood = robot::Mood::Guard;
    QString m_bubble;
    int m_blocked = 0;
    int m_pending = 0;

    bool m_blinkNow = false;
    QTimer* m_blink = nullptr;
    motion::Ticker* m_ticker = nullptr;
    QTimer* m_idleTimer = nullptr;
    qint64 m_enterAt = -1;
    qint64 m_bubbleAt = -1;
    qint64 m_shakeAt = -1;
    qint64 m_hopAt = -1;
    qint64 m_idleAt = -1;
    int m_idleKind = 0;
    // 形态(robot::Look::vehicle):m_formAt 起的一段时间里从 m_formFrom 过渡到 m_formTo。
    qreal m_formFrom = 0.0;
    qreal m_formTo = 0.0;
    qint64 m_formAt = -1;
    QTimer* m_bubbleTimer = nullptr;
    QTimer* m_hoverTimer = nullptr;
    QTimer* m_leaveWatch = nullptr;
    QPointer<QWidget> m_terminal;

    bool m_pressed = false;
    bool m_dragged = false;
    QPoint m_pressGlobal;
    QPoint m_pressPos;
};
