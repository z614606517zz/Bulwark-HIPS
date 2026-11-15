#pragma once
#include <QColor>
#include <QLabel>
#include <QPointF>
#include <QRectF>
#include <QString>
#include <QWidget>

#include <functional>

class QPainter;
class QTimer;
class QVariantAnimation;

// 两套皮肤共用的「贴纸 / 器件」语汇:墨线描边 + 硬投影的面板、警示斑马条、指示灯、
// 钢印、标签贴、贴纸大字、七段数码管、彩色贴纸图标。颜色与轮廓随当前皮肤变化。
namespace sticker {

// 面板:先画硬投影(向下偏移),再画带墨线的面板本体。返回面板本体所占矩形。
QRectF panel(QPainter& p, const QRectF& area, const QColor& fill, qreal corner = 14.0,
             bool shadow = true, const QColor& rim = QColor());
QRectF bodyRect(const QRectF& area, bool shadow = true);

// offset 让斜条整体右移(循环),用来做「行进中」的警示带。
void hazard(QPainter& p, const QRectF& r, const QColor& a, const QColor& b, qreal stripe = 12.0,
            qreal offset = 0.0);
void lamp(QPainter& p, const QRectF& r, const QColor& c, bool lit = true);
void stamp(QPainter& p, const QPointF& center, const QString& text, const QColor& c, qreal angle, qreal px);
QSizeF stampSize(const QString& text, qreal px);
void dymo(QPainter& p, const QRectF& r, const QString& text, const QColor& bg, const QColor& fg);
qreal dymoWidth(const QString& text, qreal px);

// 贴纸大字:机甲 = 右斜 9° + 尖角描边 + 橙色错位投影;卡哇伊 = 圆角描边 + 粉色投影。
// 各层颜色留空 = 用皮肤默认;画在深色屏幕上时把外描边换成发光色。
struct TextStyle {
    QColor fill;
    QColor mid;
    QColor out;
    QColor shade;
    bool shadow = true;
};
QSizeF stickerTextSize(const QString& text, qreal px);
void stickerText(QPainter& p, const QPointF& topLeft, const QString& text, qreal px,
                 const QColor& fill = QColor(), bool shadow = true);
void stickerText(QPainter& p, const QPointF& topLeft, const QString& text, qreal px, const TextStyle& style);
TextStyle screenTextStyle();

// 七段数码管。digits 中的空格画成全暗位;glow 0..1 = 亮段泛光强度。
void sevenSeg(QPainter& p, const QRectF& r, const QString& digits, const QColor& on, const QColor& off,
              int redLast = 0, const QColor& red = QColor(), qreal glow = 0.0);

void icon(QPainter& p, const QString& name, const QRectF& r, qreal strokeWidth = 2.0);
bool hasIcon(const QString& name);

QPolygonF hexagon(const QPointF& c, qreal r);
QFont headFont(qreal pt, int weight = 900);
QFont labelFont(qreal pt);

}

// 一段贴纸大字。
class StickerText : public QWidget
{
public:
    explicit StickerText(const QString& text, qreal px, QWidget* parent = nullptr);
    void setText(const QString& text);
    QString text() const { return m_text; }
    void setFill(const QColor& c);
    void setShadow(bool on);
    void setTextStyle(const sticker::TextStyle& style);
    // 从小弹到正常大小(状态切换时用)。
    void pop();
    QSize sizeHint() const override;
    QSize minimumSizeHint() const override { return sizeHint(); }

protected:
    void paintEvent(QPaintEvent*) override;

private:
    QString m_text;
    qreal m_px;
    sticker::TextStyle m_style;
    QVariantAnimation* m_pop = nullptr;
    qreal m_popT = 1.0;
};

// 数码管计数器:固定位数,不足补暗位。数值变化时滚动过去,亮段泛一下光。
class SevenSegCounter : public QWidget
{
public:
    SevenSegCounter(int digits, int digitW, int digitH, QWidget* parent = nullptr);
    void setValue(qint64 v);
    qint64 value() const { return m_value; }
    void setRedLast(bool on);
    void setColor(const QColor& c);
    QSize sizeHint() const override;

protected:
    void paintEvent(QPaintEvent*) override;

private:
    int m_digits;
    int m_dw;
    int m_dh;
    qint64 m_value = 0;
    qint64 m_shown = 0;
    qreal m_flash = 0.0;
    bool m_redLast = false;
    QColor m_color;
    QVariantAnimation* m_roll = nullptr;
    QVariantAnimation* m_flashAnim = nullptr;
};

// 一枚斜盖的钢印(拦截 / 放行 / 已清场……)。
class StampLabel : public QWidget
{
public:
    StampLabel(const QString& text, const QColor& color, qreal angle, qreal px = 13.0, QWidget* parent = nullptr);
    void setStamp(const QString& text, const QColor& color);
    // 控件比钢印本身大多少倍;盖章动画要从放大状态砸下来,得留出地方。
    void setOverscan(qreal k);
    // 延时 delayMs 后「啪」地盖下:放大 → 砸下 → 冲击波。落下那一刻调 onImpact。
    // from = 起砸时相对落点的偏移(靠近容器边缘时让它从里侧斜着砸过来,免得放大时被裁掉)。
    void slam(int delayMs = 0, std::function<void()> onImpact = {}, QPointF from = QPointF());
    QSize sizeHint() const override;

protected:
    void paintEvent(QPaintEvent*) override;

private:
    QString m_text;
    QColor m_color;
    qreal m_angle;
    qreal m_px;
    qreal m_overscan = 1.0;
    qreal m_slamT = 1.0;
    QPointF m_slamFrom;
    bool m_impacted = true;
    std::function<void()> m_onImpact;
    QVariantAnimation* m_slam = nullptr;
};

class LampWidget : public QWidget
{
public:
    explicit LampWidget(const QColor& c, int w = 14, int h = 10, QWidget* parent = nullptr);
    void setColor(const QColor& c);
    void setLit(bool lit);
    // 闪烁(待处理 / 告警)。关闭动画时保持常亮。
    void setBlink(bool on);
    QColor color() const { return m_color; }
    // 此刻是否亮着(闪烁的暗相算灭)。
    bool shining() const { return m_lit && !m_blinkDark; }
    QSize sizeHint() const override { return {m_w + 2, m_h + 2}; }

protected:
    void paintEvent(QPaintEvent*) override;
    void showEvent(QShowEvent* e) override;
    void hideEvent(QHideEvent* e) override;

private:
    QColor m_color;
    int m_w;
    int m_h;
    bool m_lit = true;
    bool m_blinkOn = false;
    bool m_blinkDark = false;
    QTimer* m_blink = nullptr;
};
