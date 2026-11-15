#pragma once
#include <QColor>
#include <QRectF>
#include <QSizeF>
#include <QString>
#include <QWidget>

#include <limits>

class QPainter;
class QTimer;
namespace motion { class Ticker; }
namespace theme { enum class Skin; }

// 小垒:产品的机器人形象。机甲皮肤画 v4「要塞型」,卡哇伊皮肤画 v3 糖果机器人,
// 金刚皮肤画卡车机器人(能变形成一辆小卡车);
// 表情 = 防护状态,宝石 / 面罩 / 胸口核心同步变色。
namespace robot {

enum class Mood { Guard, Happy, Ask, Alert, Think, Boost, Info, Sleep };
enum class Pose { Stand, Wave, Shield, Sit, Reach, Hold };

struct Look {
    Mood mood = Mood::Guard;
    Pose pose = Pose::Stand;
    bool head = false;
    bool blink = false;
    bool lookLeft = false;
    bool extras = true;
    bool flame = false;
    bool shadow = true;
    qreal tilt = std::numeric_limits<qreal>::quiet_NaN();
    // 动画:phase 是 0..1 的循环时钟(<0 = 静止),驱动挥手、喷焰闪烁、小旗摆动;
    // pulse 是能量宝石 / 胸口核心的呼吸光晕强度 0..1。
    qreal phase = -1.0;
    qreal pulse = 0.0;
    // 金刚:0 = 机器人形态,1 = 载具(小卡车)形态,中间值是变形过程。其它皮肤不看它。
    qreal vehicle = 0.0;
    // 金刚整只机器人:>0 时墨线按这个屏幕像素宽画,不随机器人大小缩放(设计稿的 non-scaling-stroke)。
    qreal strokePx = 0.0;
};

QSizeF viewBox(bool head);
// 按宽度算出机器人在界面上应占的高度。
int heightFor(int width, bool head);

// 机器人底边居中对齐地画进 box,保持比例。
void paint(QPainter& p, const QRectF& box, const Look& look);
// 按指定皮肤画(设置页里给各套风格做预览用),与当前皮肤无关。
void paintAs(QPainter& p, const QRectF& box, const Look& look, theme::Skin skin);

// 只画面罩里的表情(仪表盘大屏用)。
void paintFace(QPainter& p, const QRectF& box, Mood mood, bool blink = false, bool lookLeft = false);

QColor led(Mood m);
QString moodName(Mood m);

}

class RobotWidget : public QWidget
{
    Q_OBJECT
public:
    explicit RobotWidget(int width, const robot::Look& look = {}, QWidget* parent = nullptr);

    void setLook(const robot::Look& look);
    robot::Look look() const { return m_look; }
    void setMood(robot::Mood mood);
    void setPose(robot::Pose pose);
    void setRobotWidth(int width);

    void setAutoBlink(bool on);
    // 上下悬浮。
    void setBob(bool on);
    // 活起来:宝石呼吸、挥手、喷焰闪烁、小旗摆动,守护态偶尔扫一眼。
    void setAnimated(bool on);

    QSize sizeHint() const override;
    QSize minimumSizeHint() const override { return sizeHint(); }

protected:
    void paintEvent(QPaintEvent*) override;
    void showEvent(QShowEvent* e) override;
    void hideEvent(QHideEvent* e) override;

private:
    void scheduleBlink();
    void syncTick();
    void tick(qint64 now);

    robot::Look m_look;
    int m_width = 120;
    bool m_autoBlink = false;
    bool m_blinkNow = false;
    QTimer* m_blinkTimer = nullptr;
    bool m_bobOn = false;
    bool m_animOn = false;
    motion::Ticker* m_ticker = nullptr;
    qint64 m_clockShift = 0;
    qreal m_bobY = 0.0;
    qreal m_phase = -1.0;
    qreal m_pulse = 0.0;
    qint64 m_glanceAt = 0;
    qint64 m_glanceUntil = 0;
};
