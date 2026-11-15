#include "pages/DashboardPage.h"
#include "dialogs/EventFormat.h"
#include "dialogs/EventViews.h"
#include "design/Components.h"
#include "design/GlowCard.h"
#include "design/Icons.h"
#include "design/Inspector.h"
#include "design/Motion.h"
#include "design/Reflow.h"
#include "design/Robot.h"
#include "design/Sticker.h"
#include "design/Theme.h"
#include "design/TitanKit.h"
#include "design/ToggleSwitch.h"
#include "ipc/IpcClient.h"
#include "Nav.h"

#include "bulwark/ipc/Payloads.h"
#include "bulwark/models/Enums.h"
#include "bulwark/models/RuntimeSettings.h"
#include "bulwark/models/SecurityEvent.h"

#include <QDateTime>
#include <QEnterEvent>
#include <QFontMetricsF>
#include <QFrame>
#include <QGraphicsOpacityEffect>
#include <QGridLayout>
#include <QHBoxLayout>
#include <QImage>
#include <QLabel>
#include <QLineF>
#include <QList>
#include <QLocale>
#include <QMouseEvent>
#include <QPainter>
#include <QPainterPath>
#include <QPropertyAnimation>
#include <QPushButton>
#include <QRandomGenerator>
#include <QScrollArea>
#include <QShowEvent>
#include <QTimer>
#include <QToolTip>
#include <QVariantAnimation>
#include <QVBoxLayout>
#include <QtMath>

#include <algorithm>
#include <array>
#include <cmath>
#include <functional>
#include <utility>

using evtfmt::u;

namespace {

void go(const char* key, const QVariantMap& args = {})
{
    nav::go(QString::fromLatin1(key), args);
}

// 深色屏幕上的状态色:浅色面板用的那套(尤其「放行」的石墨灰)在黑底上看不见。
QColor onScreen(const QColor& c)
{
    const bool m = theme::mecha();
    if (c == theme::danger())
        return m ? QColor(0xFF, 0x4A, 0x4A) : QColor(0xFF, 0x9C, 0x9C);
    if (c == theme::warning())
        return m ? QColor(0xFF, 0xCF, 0x33) : QColor(0xFF, 0xE2, 0x7A);
    return theme::pal().scrText2;
}

void paintScreen(QPainter& p, const QRect& rect, bool shadow)
{
    const theme::Palette& P = theme::pal();
    const QRectF body = sticker::panel(p, QRectF(rect), P.screen, 14.0, shadow);
    const QPainterPath shape = theme::panelPath(body, 14.0);
    p.save();
    p.setClipPath(shape);
    p.setRenderHint(QPainter::Antialiasing, false);
    if (theme::mecha()) {
        p.setPen(QPen(theme::tint(P.glow, 0.07), 1.0));
        for (int x = int(body.left()) + 22; x < body.right(); x += 22)
            p.drawLine(x, int(body.top()), x, int(body.bottom()));
        for (int y = int(body.top()) + 22; y < body.bottom(); y += 22)
            p.drawLine(int(body.left()), y, int(body.right()), y);
    } else {
        p.setRenderHint(QPainter::Antialiasing, true);
        p.setPen(Qt::NoPen);
        p.setBrush(QColor(255, 255, 255, 18));
        for (qreal y = body.top() + 7; y < body.bottom(); y += 14)
            for (qreal x = body.left() + 7; x < body.right(); x += 14)
                p.drawEllipse(QPointF(x, y), 1.3, 1.3);
    }
    p.restore();
    p.save();
    p.setRenderHint(QPainter::Antialiasing, true);
    p.strokePath(theme::panelPath(body.adjusted(4, 4, -4, -4), 11.0),
                 QPen(P.screen2, 2.5, Qt::SolidLine, Qt::FlatCap, theme::mecha() ? Qt::MiterJoin : Qt::RoundJoin));
    p.restore();
}

class ScreenFrame : public QWidget
{
public:
    explicit ScreenFrame(bool shadow = true) : m_shadow(shadow) {}

protected:
    void paintEvent(QPaintEvent*) override
    {
        QPainter p(this);
        p.setRenderHint(QPainter::Antialiasing, true);
        paintScreen(p, rect(), m_shadow);
    }

private:
    bool m_shadow;
};

// 表情屏:左边是小垒的眼睛(= 防护状态),右边是文字(子控件)。
// 动画:每隔几秒一道扫描光从上往下扫过瞄准框;守护态偶尔往旁边瞄一眼。
class FaceScreen : public ScreenFrame
{
public:
    FaceScreen()
    {
        m_blink = new QTimer(this);
        m_blink->setSingleShot(true);
        QObject::connect(m_blink, &QTimer::timeout, this, [this] {
            m_blinkNow = !m_blinkNow;
            update(faceArea());
            m_blink->start(m_blinkNow ? 140 : 2400 + int(QRandomGenerator::global()->bounded(3200)));
        });
        m_scan = new motion::Ticker(this, [this](qint64 now) {
            update(faceArea());
            if (now - m_scanAt > kScanMs) {
                m_scanAt = -1;
                m_scan->setActive(false);
                scheduleScan();
            }
        }, 33);
        m_scanNext = new QTimer(this);
        m_scanNext->setSingleShot(true);
        QObject::connect(m_scanNext, &QTimer::timeout, this, [this] {
            m_scanAt = motion::clockMs();
            m_scan->setActive(true);
        });
        m_glance = new QTimer(this);
        m_glance->setSingleShot(true);
        QObject::connect(m_glance, &QTimer::timeout, this, [this] {
            m_lookLeft = !m_lookLeft;
            update(faceArea());
            m_glance->start(m_lookLeft ? 700 : 6000 + int(QRandomGenerator::global()->bounded(5000)));
        });
    }

    void setMood(robot::Mood m)
    {
        m_mood = m;
        update();
    }

    int faceWidth() const { return qBound(180, int(width() * 0.36), 300); }

protected:
    void showEvent(QShowEvent* e) override
    {
        ScreenFrame::showEvent(e);
        if (motion::enabled()) {
            m_blink->start(1800);
            m_glance->start(4000);
            scheduleScan(600);
        }
    }
    void hideEvent(QHideEvent* e) override
    {
        ScreenFrame::hideEvent(e);
        m_blink->stop();
        m_blinkNow = false;
        m_glance->stop();
        m_lookLeft = false;
        m_scanNext->stop();
        m_scan->setActive(false);
        m_scanAt = -1;
    }
    void paintEvent(QPaintEvent* e) override
    {
        ScreenFrame::paintEvent(e);
        QPainter p(this);
        p.setRenderHint(QPainter::Antialiasing, true);
        const QRectF fr = faceRect();
        // 瞄准框
        const QColor g = theme::tint(theme::glow(), 0.7);
        QPainterPath ret;
        const qreal c = 22;
        ret.moveTo(fr.left(), fr.top() + c); ret.lineTo(fr.left(), fr.top()); ret.lineTo(fr.left() + c, fr.top());
        ret.moveTo(fr.right() - c, fr.top()); ret.lineTo(fr.right(), fr.top()); ret.lineTo(fr.right(), fr.top() + c);
        ret.moveTo(fr.right(), fr.bottom() - c); ret.lineTo(fr.right(), fr.bottom()); ret.lineTo(fr.right() - c, fr.bottom());
        ret.moveTo(fr.left() + c, fr.bottom()); ret.lineTo(fr.left(), fr.bottom()); ret.lineTo(fr.left(), fr.bottom() - c);
        p.strokePath(ret, QPen(g, 3, Qt::SolidLine, Qt::SquareCap, Qt::MiterJoin));
        const bool glance = m_lookLeft && m_mood == robot::Mood::Guard;
        robot::paintFace(p, fr.adjusted(18, 14, -18, -14), m_mood, m_blinkNow && m_mood != robot::Mood::Sleep, glance);
        if (m_scanAt >= 0) {
            const qreal t = qBound<qreal>(0.0, qreal(motion::clockMs() - m_scanAt) / kScanMs, 1.0);
            const qreal y = fr.top() - 18 + motion::outCubic(t) * (fr.height() + 36);
            const qreal fade = std::sin(t * M_PI);
            p.save();
            p.setClipRect(fr.adjusted(3, 3, -3, -3));
            QLinearGradient band(0, y - 26, 0, y + 6);
            band.setColorAt(0.0, theme::tint(theme::glow(), 0.0));
            band.setColorAt(0.8, theme::tint(theme::glow(), 0.16 * fade));
            band.setColorAt(1.0, theme::tint(theme::glow(), 0.0));
            p.fillRect(QRectF(fr.left(), y - 26, fr.width(), 32), band);
            p.setPen(QPen(theme::tint(theme::glow(), 0.55 * fade), 1.6));
            p.drawLine(QPointF(fr.left(), y), QPointF(fr.right(), y));
            p.restore();
        }
    }

private:
    static constexpr int kScanMs = 1500;

    QRectF faceRect() const { return QRectF(26, 26, faceWidth(), height() - 58); }
    QRect faceArea() const { return faceRect().toAlignedRect().adjusted(-4, -4, 4, 4); }
    void scheduleScan(int ms = -1)
    {
        if (motion::enabled() && isVisible())
            m_scanNext->start(ms >= 0 ? ms : 3600 + int(QRandomGenerator::global()->bounded(2600)));
    }

    robot::Mood m_mood = robot::Mood::Sleep;
    QTimer* m_blink = nullptr;
    bool m_blinkNow = false;
    QTimer* m_glance = nullptr;
    bool m_lookLeft = false;
    motion::Ticker* m_scan = nullptr;
    QTimer* m_scanNext = nullptr;
    qint64 m_scanAt = -1;
};

// 金刚:CSS box-shadow 0 0 6px 的近似,由外向内四圈渐浓的同色底。调用方随后在 r 里画实体。
void glowAround(QPainter& p, const QRectF& r, const QColor& c)
{
    static const qreal kGrow[] = {6.0, 4.5, 3.0, 1.5};
    static const qreal kAlpha[] = {0.04, 0.07, 0.12, 0.17};
    p.save();
    p.setRenderHint(QPainter::Antialiasing, true);
    p.setPen(Qt::NoPen);
    for (int i = 0; i < 4; ++i) {
        p.setBrush(theme::tint(c, kAlpha[i]));
        p.drawRoundedRect(r.adjusted(-kGrow[i], -kGrow[i], kGrow[i], kGrow[i]), kGrow[i], kGrow[i]);
    }
    p.restore();
}

// 金刚屏幕指示灯(设计稿 .lamp):13×9,2px 墨框,左上一点高光,亮时外泛 6px 同色光;
// 四周各留 6px 给泛光,所以控件比灯大一圈。
class TitanLamp final : public LampWidget
{
public:
    TitanLamp() : LampWidget(theme::glow(), 23, 19) {}

protected:
    void paintEvent(QPaintEvent*) override
    {
        QPainter p(this);
        const QRectF lamp(6.0, 6.0, 13.0, 9.0);
        const bool on = shining();
        const QColor c = on ? color() : QColor(0x45, 0x4F, 0x5F);
        if (on)
            glowAround(p, lamp, c);
        p.fillRect(lamp, theme::ink());
        p.fillRect(lamp.adjusted(2.0, 2.0, -2.0, -2.0), c);
        p.fillRect(QRectF(lamp.left() + 3.0, lamp.top() + 2.0, 4.0, 2.0), QColor(255, 255, 255, 204));
    }
};

// 屏幕上的一枚状态段:小灯 + 文字。
class SegChip : public QWidget
{
public:
    SegChip(LampWidget*& lamp, QLabel*& text, const QString& label)
    {
        const bool titan = theme::titan();
        auto* h = new QHBoxLayout(this);
        if (titan)
            h->setContentsMargins(3, 0, 9, 0); // 灯控件自带 6px 泛光边,合起来仍是设计稿的 9px 内边距 / 6px 间距
        else
            h->setContentsMargins(10, 4, 12, 4);
        h->setSpacing(titan ? 0 : 7);
        lamp = titan ? new TitanLamp : new LampWidget(theme::glow(), 12, 8);
        h->addWidget(lamp, 0, Qt::AlignVCenter);
        text = new QLabel(label);
        text->setStyleSheet(titan ? QStringLiteral("color:%1; font-size:12px;").arg(theme::pal().scrText2.name())
                                  : QStringLiteral("color:%1; font-size:9pt; font-weight:800;").arg(theme::pal().scrText.name()));
        h->addWidget(text, 0, Qt::AlignVCenter);
        setFixedHeight(titan ? 24 : 28);
    }

protected:
    void paintEvent(QPaintEvent*) override
    {
        QPainter p(this);
        if (theme::titan()) {
            // 金刚:细边矩形,不切角。
            const QRectF box = QRectF(rect()).adjusted(0.75, 0.75, -0.75, -0.75);
            p.fillRect(box, QColor(0x0C, 0x15, 0x24));
            p.setPen(QPen(QColor(0x1D, 0x31, 0x50), 1.5, Qt::SolidLine, Qt::SquareCap, Qt::MiterJoin));
            p.setBrush(Qt::NoBrush);
            p.drawRect(box);
            return;
        }
        p.setRenderHint(QPainter::Antialiasing, true);
        const QRectF r = QRectF(rect()).adjusted(1.2, 1.2, -1.2, -1.2);
        const QPainterPath path = theme::panelPath(r, theme::mecha() ? 7.0 : r.height() / 2.7);
        p.fillPath(path, theme::mecha() ? QColor(0x32, 0x31, 0x2E) : theme::pal().screen2);
        p.strokePath(path, QPen(theme::ink(), 2.2, Qt::SolidLine, Qt::FlatCap,
                                theme::mecha() ? Qt::MiterJoin : Qt::RoundJoin));
    }
};

class ClickRow : public QWidget
{
public:
    std::function<void()> onClick;
    explicit ClickRow(bool dark) : m_dark(dark)
    {
        setCursor(Qt::PointingHandCursor);
        setAttribute(Qt::WA_Hover);
    }

    // 新进来的一行先亮一下,再慢慢褪成普通行。
    void flash(const QColor& c)
    {
        if (!motion::enabled())
            return;
        m_flashColor = c;
        auto* anim = new QVariantAnimation(this);
        anim->setDuration(1100);
        anim->setStartValue(1.0);
        anim->setEndValue(0.0);
        anim->setEasingCurve(QEasingCurve::InQuad);
        QObject::connect(anim, &QVariantAnimation::valueChanged, this, [this](const QVariant& v) {
            m_flash = v.toReal();
            update();
        });
        anim->start(QAbstractAnimation::DeleteWhenStopped);
    }

protected:
    void paintEvent(QPaintEvent*) override
    {
        if (!underMouse() && m_flash <= 0.01)
            return;
        QPainter p(this);
        p.setRenderHint(QPainter::Antialiasing, true);
        p.setPen(Qt::NoPen);
        const QRectF r = QRectF(rect()).adjusted(-4, 1, 4, -1);
        if (m_flash > 0.01) {
            p.setBrush(theme::tint(m_flashColor, 0.22 * m_flash));
            p.drawRoundedRect(r, 6, 6);
            p.fillRect(QRectF(r.left(), r.top() + 4, 3, r.height() - 8), theme::tint(m_flashColor, m_flash));
        }
        if (underMouse()) {
            p.setBrush(m_dark ? QColor(255, 255, 255, 16) : theme::tint(theme::overlay(), 0.05));
            p.drawRoundedRect(r, 6, 6);
        }
    }
    void mouseReleaseEvent(QMouseEvent* e) override
    {
        if (e->button() == Qt::LeftButton && onClick)
            onClick();
    }
    void enterEvent(QEnterEvent*) override { update(); }
    void leaveEvent(QEvent*) override { update(); }

private:
    bool m_dark;
    QColor m_flashColor;
    qreal m_flash = 0.0;
};

// 战况雷达:24 小时柱 + 折线(放行)、三角(询问)、准星(拦截),画在深色屏幕上。
// 动画:数据到达时柱子从底部长出来;每隔几秒一道扫描线从左扫到右,扫过的柱子亮一下。
class HourChart : public QWidget
{
public:
    std::function<void()> onClick;

    HourChart()
    {
        setMinimumHeight(theme::titan() ? 64 : 142);
        setMouseTracking(true);
        setCursor(Qt::PointingHandCursor);
        setAccessibleName(u("过去 24 小时的事件分布,点击在事件时间线中查看"));
        m_sweep = new motion::Ticker(this, [this](qint64 now) { sweepFrame(now); }, 33);
        m_sweepNext = new QTimer(this);
        m_sweepNext->setSingleShot(true);
        QObject::connect(m_sweepNext, &QTimer::timeout, this, [this] { startSweep(); });
    }

    void reset()
    {
        m_counts.clear();
        update();
    }
    void add(const QDateTime& utc, int severity)
    {
        m_counts[hourKey(utc.toMSecsSinceEpoch())][std::clamp(severity, 0, 2)]++;
        update();
    }
    // 一整批数据刚灌进来:柱子从底部长出来,顺带扫一遍。
    void grow()
    {
        if (!motion::enabled() || !motion::onScreen(this)) {
            m_growT = 1.0;
            update();
            return;
        }
        if (!m_grow) {
            m_grow = new QVariantAnimation(this);
            m_grow->setStartValue(0.0);
            m_grow->setEndValue(1.0);
            m_grow->setDuration(760);
            QObject::connect(m_grow, &QVariantAnimation::valueChanged, this, [this](const QVariant& v) {
                m_growT = v.toReal();
                update();
            });
        }
        m_grow->stop();
        m_grow->start();
        startSweep();
    }

protected:
    void showEvent(QShowEvent* e) override
    {
        QWidget::showEvent(e);
        if (motion::enabled())
            m_sweepNext->start(1200);
    }
    void hideEvent(QHideEvent* e) override
    {
        QWidget::hideEvent(e);
        m_sweepNext->stop();
        m_sweep->setActive(false);
        m_sweepAt = -1;
    }
    void paintEvent(QPaintEvent*) override
    {
        QPainter p(this);
        p.setRenderHint(QPainter::Antialiasing, true);
        if (theme::titan()) {
            paintTitan(p);
            return;
        }
        paintScreen(p, rect(), false);
        const theme::Palette& P = theme::pal();
        const QRectF plot = plotRect();
        const qreal sweepX = m_sweepAt >= 0 ? sweepPos(motion::clockMs()) : -1e9;
        const qreal grow = motion::outCubic(m_growT);
        const qint64 nowHour = hourKey(QDateTime::currentMSecsSinceEpoch());
        int maxTotal = 0;
        std::array<std::array<int, 3>, 24> bars{};
        for (int i = 0; i < 24; ++i) {
            const auto it = m_counts.constFind(nowHour - qint64(23 - i) * 3600000);
            if (it != m_counts.constEnd())
                bars[size_t(i)] = *it;
            maxTotal = std::max(maxTotal, bars[size_t(i)][0] + bars[size_t(i)][1] + bars[size_t(i)][2]);
        }
        const qreal bw = plot.width() / 24.0;
        p.setPen(QPen(theme::tint(P.glow, 0.35), 1.5));
        p.drawLine(QPointF(plot.left(), plot.bottom() + 0.5), QPointF(plot.right(), plot.bottom() + 0.5));
        if (maxTotal == 0) {
            p.setPen(P.scrMuted);
            p.drawText(plot, Qt::AlignCenter, u("过去 24 小时没有事件"));
        }
        const QColor red = onScreen(theme::danger());
        const QColor yellow = onScreen(theme::warning());
        QPolygonF line;
        for (int i = 0; i < 24 && maxTotal > 0; ++i) {
            const auto& b = bars[size_t(i)];
            const int total = b[0] + b[1] + b[2];
            const qreal h = total == 0 ? 0.0
                                       : std::max(3.0, std::sqrt(qreal(total) / maxTotal) * plot.height()) * grow;
            const QRectF col(plot.left() + i * bw + 2, plot.bottom() - h, std::max(2.0, bw - 4), h);
            if (i == m_hover)
                p.fillRect(QRectF(plot.left() + i * bw, plot.top(), bw, plot.height()), QColor(255, 255, 255, 18));
            // 扫描线刚扫过的柱子亮一下,随后褪回去。
            const qreal behind = sweepX - col.center().x();
            const qreal lit = behind >= 0 && behind < kTrail ? 1.0 - behind / kTrail : 0.0;
            if (h > 0)
                p.fillRect(col, theme::tint(P.glow, 0.2 + 0.45 * lit));
            line << QPointF(col.center().x(), plot.bottom() - h);
            const qreal cx = col.center().x();
            if (b[2] > 0) {
                const qreal cy = plot.bottom() - h - 14;
                p.setPen(QPen(red, 2.2));
                p.setBrush(Qt::NoBrush);
                p.drawEllipse(QPointF(cx, cy), 6.5, 6.5);
                p.setBrush(red);
                p.drawEllipse(QPointF(cx, cy), 2.2, 2.2);
                p.drawLine(QPointF(cx - 11, cy), QPointF(cx - 7, cy));
                p.drawLine(QPointF(cx + 7, cy), QPointF(cx + 11, cy));
            }
            if (b[1] > 0) {
                const qreal cy = plot.bottom() - qMin<qreal>(h, plot.height()) + 12;
                QPolygonF tri;
                tri << QPointF(cx, cy - 5) << QPointF(cx + 5.5, cy + 4.5) << QPointF(cx - 5.5, cy + 4.5);
                p.setPen(QPen(theme::ink(), 1.4));
                p.setBrush(yellow);
                p.drawPolygon(tri);
            }
        }
        if (line.size() > 1) {
            p.setPen(QPen(P.glow, 2.6, Qt::SolidLine, Qt::RoundCap, Qt::MiterJoin));
            p.setBrush(Qt::NoBrush);
            p.drawPolyline(line);
        }
        if (sweepX > plot.left() - 1 && sweepX < plot.right() + kTrail) {
            const qreal x = sweepX;
            p.save();
            p.setClipRect(plot.adjusted(0, -6, 0, 1));
            QLinearGradient trail(x - kTrail, 0, x, 0);
            trail.setColorAt(0.0, theme::tint(P.glow, 0.0));
            trail.setColorAt(1.0, theme::tint(P.glow, 0.16));
            p.fillRect(QRectF(x - kTrail, plot.top() - 6, kTrail, plot.height() + 7), trail);
            if (sweepX <= plot.right()) {
                p.setPen(QPen(theme::tint(P.glow, 0.85), 2.0));
                p.drawLine(QPointF(x, plot.top() - 6), QPointF(x, plot.bottom()));
            }
            p.restore();
        }
        QFont f = sticker::labelFont(7.5);
        p.setFont(f);
        p.setPen(P.scrMuted);
        for (int i : {0, 6, 12, 18, 23}) {
            const QDateTime t = QDateTime::fromMSecsSinceEpoch(nowHour - qint64(23 - i) * 3600000).toLocalTime();
            const QRectF cell(plot.left() + i * bw - 20, plot.bottom() + 5, bw + 40, 14);
            p.drawText(cell, Qt::AlignHCenter | Qt::AlignVCenter, i == 23 ? u("现在") : t.toString(QStringLiteral("HH:00")));
        }
    }
    void mouseMoveEvent(QMouseEvent* e) override
    {
        const QRectF plot = plotRect();
        const int i = std::clamp(int((e->position().x() - plot.left()) / (plot.width() / 24.0)), 0, 23);
        if (i != m_hover) {
            m_hover = i;
            update();
        }
        const qint64 hour = hourKey(QDateTime::currentMSecsSinceEpoch()) - qint64(23 - i) * 3600000;
        const std::array<int, 3> b = m_counts.value(hour, std::array<int, 3>{});
        const QDateTime t = QDateTime::fromMSecsSinceEpoch(hour).toLocalTime();
        QString text = u("%1 – %2 · %3 条").arg(t.toString(QStringLiteral("HH:00")), t.addSecs(3600).toString(QStringLiteral("HH:00")))
                           .arg(b[0] + b[1] + b[2]);
        if (b[2] || b[1])
            text += u("(拦截 %1 · 询问 %2)").arg(b[2]).arg(b[1]);
        QToolTip::showText(e->globalPosition().toPoint(), text, this);
    }
    void leaveEvent(QEvent*) override
    {
        m_hover = -1;
        update();
    }
    void mouseReleaseEvent(QMouseEvent* e) override
    {
        if (e->button() == Qt::LeftButton && onClick)
            onClick();
    }

private:
    static constexpr int kSweepMs = 2200;
    static constexpr qreal kTrail = 70.0;

    static qint64 hourKey(qint64 ms) { return ms - ms % 3600000; }
    QRectF plotRect() const
    {
        return theme::titan() ? QRectF(rect()).adjusted(10, 12, -10, -24) : QRectF(rect()).adjusted(20, 22, -20, -26);
    }

    // 金刚:矩形终端屏上画半透明的柱子(顶上一道亮边),询问 = 三角,拦截 = 准星 + 次数。
    void paintTitan(QPainter& p)
    {
        const theme::Palette& P = theme::pal();
        const QRectF screen = QRectF(rect());
        const QRectF in = screen.adjusted(2, 2, -2, -2);
        p.fillRect(screen, P.ink);
        p.fillRect(in, P.screen);
        const QRectF plot = plotRect();
        const qreal sweepX = m_sweepAt >= 0 ? sweepPos(motion::clockMs()) : -1e9;
        const qreal grow = motion::outCubic(m_growT);
        const qint64 nowHour = hourKey(QDateTime::currentMSecsSinceEpoch());
        int maxTotal = 0;
        std::array<std::array<int, 3>, 24> bars{};
        for (int i = 0; i < 24; ++i) {
            const auto it = m_counts.constFind(nowHour - qint64(23 - i) * 3600000);
            if (it != m_counts.constEnd())
                bars[size_t(i)] = *it;
            maxTotal = std::max(maxTotal, bars[size_t(i)][0] + bars[size_t(i)][1] + bars[size_t(i)][2]);
        }

        p.save();
        p.setClipRect(in);
        p.setRenderHint(QPainter::Antialiasing, false);
        const QColor rule(120, 160, 220);
        QPen dash(theme::tint(rule, 0.12), 1.0);
        dash.setDashPattern({2.0, 5.0});
        p.setPen(dash);
        for (int i = 0; i < 4; ++i) {
            const int y = qRound(plot.top() + i * plot.height() / 4.0);
            p.drawLine(QPointF(plot.left(), y), QPointF(plot.right(), y));
        }
        p.setPen(QPen(theme::tint(rule, 0.4), 1.0));
        p.drawLine(QPointF(plot.left(), qRound(plot.bottom())), QPointF(plot.right(), qRound(plot.bottom())));
        p.setRenderHint(QPainter::Antialiasing, true);
        if (maxTotal == 0) {
            p.setPen(P.scrMuted);
            p.drawText(plot, Qt::AlignCenter, u("过去 24 小时没有事件"));
        }

        const qreal cw = plot.width() / 24.0;
        const qreal bw = qMin<qreal>(15.0, cw - 4.0);
        const qreal room = plot.height() - 22.0;   // 柱顶上方留给三角和准星
        const QFont countFont = titankit::numFont(10, QFont::Bold);
        for (int i = 0; i < 24 && maxTotal > 0; ++i) {
            const auto& b = bars[size_t(i)];
            const int total = b[0] + b[1] + b[2];
            const qreal x = plot.left() + i * cw + (cw - bw) / 2.0;
            const qreal mid = x + bw / 2.0;
            // 设计稿是线性刻度(另两套皮肤用平方根,小数值显得高些)。
            const qreal h = total == 0 ? 2.0 : std::max(2.0, qreal(total) / maxTotal * room) * grow;
            const qreal y = plot.bottom() - h;
            // 扫描线刚扫过的柱子亮一下,随后褪回去。
            const qreal behind = sweepX - mid;
            const qreal lit = behind >= 0 && behind < kTrail ? 1.0 - behind / kTrail : 0.0;
            p.fillRect(QRectF(x, y, bw, h), theme::tint(P.glow, i == m_hover ? 0.85 : 0.4 + 0.35 * lit));
            p.fillRect(QRectF(x, y, bw, qMin<qreal>(2.0, h)), P.glow);
            qreal yy = y - 4.0;
            if (b[1] > 0) {
                QPolygonF tri;
                tri << QPointF(mid, yy - 9.0) << QPointF(mid + 5.5, yy) << QPointF(mid - 5.5, yy);
                p.setPen(QPen(P.ink, 1.0));
                p.setBrush(P.warning);
                p.drawPolygon(tri);
                yy -= 12.0;
            }
            if (b[2] > 0) {
                const QPointF c(mid, yy - 5.5);
                p.setPen(QPen(P.danger, 2.0));
                p.setBrush(Qt::NoBrush);
                p.drawEllipse(c, 4.5, 4.5);
                p.setPen(Qt::NoPen);
                p.setBrush(P.danger);
                p.drawEllipse(c, 1.6, 1.6);
                if (b[2] > 1) {
                    p.setFont(countFont);
                    p.setPen(P.danger);
                    p.drawText(QRectF(mid + 7.0, yy - 11.5, 30.0, 12.0), Qt::AlignLeft | Qt::AlignVCenter,
                               QString::number(b[2]));
                }
            }
        }

        if (sweepX > plot.left() - 1 && sweepX < plot.right() + kTrail) {
            const QRectF lane(plot.left(), in.top(), plot.width(), plot.bottom() - in.top());
            p.save();
            p.setClipRect(lane);
            QLinearGradient trail(sweepX - kTrail, 0, sweepX, 0);
            trail.setColorAt(0.0, theme::tint(P.glow, 0.0));
            trail.setColorAt(0.85, theme::tint(P.glow, 0.16));
            trail.setColorAt(1.0, theme::tint(P.glow, 0.6));
            p.fillRect(QRectF(sweepX - kTrail, lane.top(), kTrail, lane.height()), trail);
            p.restore();
        }

        p.setFont(titankit::numFont(10, QFont::DemiBold));
        for (int i = 3; i < 24; i += 4) {
            const QDateTime t = QDateTime::fromMSecsSinceEpoch(nowHour - qint64(23 - i) * 3600000).toLocalTime();
            const qreal mid = plot.left() + (i + 0.5) * cw;
            p.setPen(i == 23 ? P.glow : P.scrMuted);
            p.drawText(QRectF(mid - 30.0, plot.bottom() + 5.0, 60.0, 14.0), Qt::AlignHCenter | Qt::AlignVCenter,
                       i == 23 ? u("现在") : t.toString(QStringLiteral("HH:00")));
        }

        // 屏面:扫描线 + 内描一圈光
        p.setRenderHint(QPainter::Antialiasing, false);
        for (int y = int(in.top()); y < in.bottom(); y += 3)
            p.fillRect(QRectF(in.left(), y, in.width(), 1), QColor(255, 255, 255, 8));
        p.setPen(QPen(theme::tint(P.glow, 0.22), 1.0));
        p.setBrush(Qt::NoBrush);
        p.drawRect(in.toRect().adjusted(0, 0, -1, -1));
        p.restore();
    }
    qreal sweepPos(qint64 now) const
    {
        const QRectF plot = plotRect();
        const qreal t = qreal(now - m_sweepAt) / kSweepMs;
        return plot.left() + t * (plot.width() + kTrail);
    }
    void startSweep()
    {
        if (!motion::enabled() || !isVisible())
            return;
        m_sweepNext->stop();
        m_sweepAt = motion::clockMs();
        m_lastSweepX = plotRect().left();
        m_sweep->setActive(true);
    }
    void sweepFrame(qint64 now)
    {
        // 只重画扫描线附近那一条(连同拖尾),不必整块屏幕每帧重画。
        const qreal x = sweepPos(now);
        const qreal lo = std::min(x, m_lastSweepX) - kTrail - 6;
        const qreal hi = std::max(x, m_lastSweepX) + 6;
        update(QRectF(lo, 0, hi - lo, height()).toAlignedRect());
        m_lastSweepX = x;
        if (now - m_sweepAt > kSweepMs) {
            m_sweepAt = -1;
            m_sweep->setActive(false);
            update();
            m_sweepNext->start(5200 + int(QRandomGenerator::global()->bounded(3000)));
        }
    }

    QHash<qint64, std::array<int, 3>> m_counts;
    int m_hover = -1;
    motion::Ticker* m_sweep = nullptr;
    QTimer* m_sweepNext = nullptr;
    qint64 m_sweepAt = -1;
    qreal m_lastSweepX = 0.0;
    QVariantAnimation* m_grow = nullptr;
    qreal m_growT = 1.0;
};

int severityOf(const bulwark::ipc::EventLogPayload& p)
{
    if (evtfmt::isRealBlock(p.action, p.enforcement))
        return 2;
    return p.action == bulwark::VerdictAction::Ask ? 1 : 0;
}

class StampChip : public QWidget
{
public:
    StampChip(const QString& text, const QColor& color, qreal angle)
        : m_text(text), m_color(color), m_angle(angle)
    {
        const QSizeF s = sticker::stampSize(text, 12.0);
        setFixedSize(int(s.width()) + 10, int(s.height()) + 8);
        setAttribute(Qt::WA_TransparentForMouseEvents);
    }

protected:
    void paintEvent(QPaintEvent*) override
    {
        QPainter p(this);
        sticker::stamp(p, QRectF(rect()).center(), m_text, m_color, m_angle, 12.0);
    }

private:
    QString m_text;
    QColor m_color;
    qreal m_angle;
};

class PanelHead : public QWidget
{
public:
    PanelHead(const QString& title, const QString& small, QWidget* trailing = nullptr)
    {
        auto* h = new QHBoxLayout(this);
        h->setContentsMargins(0, 0, 0, 0);
        h->setSpacing(8);
        auto* t = ui::label(title, "h2");
        h->addWidget(t, 0, Qt::AlignVCenter);
        if (!small.isEmpty()) {
            note = ui::label(small, "muted");
            h->addWidget(note, 0, Qt::AlignVCenter);
        }
        h->addStretch();
        if (trailing)
            h->addWidget(trailing, 0, Qt::AlignVCenter);
    }
    QLabel* note = nullptr;
};

QLabel* labTag(const QString& text)
{
    auto* l = new QLabel(text);
    l->setFont(sticker::labelFont(8.5));
    l->setStyleSheet(QStringLiteral("color:%1;").arg(theme::accentDeep().name()));
    return l;
}

// 任务简报卡:左侧色条 = 优先级。
class MissionCard : public QFrame
{
public:
    MissionCard(const QColor& tone, const QString& eyebrow, const QString& title, const QString& desc,
                const QString& action, std::function<void()> fn)
        : m_tone(tone)
    {
        auto* v = new QVBoxLayout(this);
        v->setContentsMargins(26, 11, 14, 14);
        v->setSpacing(3);
        auto* eb = new QLabel(eyebrow);
        eb->setFont(sticker::labelFont(8.0));
        eb->setStyleSheet(QStringLiteral("color:%1;").arg(theme::textMuted().name()));
        v->addWidget(eb);
        auto* t = ui::label(title, "lead");
        t->setWordWrap(true);
        v->addWidget(t);
        if (!desc.isEmpty()) {
            auto* d = ui::label(desc, "secondary");
            d->setWordWrap(true);
            v->addWidget(d);
        }
        if (!action.isEmpty() && fn) {
            auto* row = new QHBoxLayout;
            row->setContentsMargins(0, 4, 0, 0);
            auto* b = ui::button(action + u(" ▸"), "primary", QString(), true);
            QObject::connect(b, &QPushButton::clicked, b, [fn = std::move(fn)] { fn(); });
            row->addWidget(b);
            row->addStretch();
            v->addLayout(row);
        }
    }

protected:
    void paintEvent(QPaintEvent*) override
    {
        QPainter p(this);
        p.setRenderHint(QPainter::Antialiasing, true);
        const QRectF body = sticker::panel(p, QRectF(rect()), theme::surface(), 12.0, true);
        const QRectF bar(body.left() + 6, body.top() + 10, 8, body.height() - 20);
        p.fillRect(bar, m_tone);
        p.setPen(QPen(theme::ink(), 1.8));
        p.setBrush(Qt::NoBrush);
        p.drawRect(bar);
    }

private:
    QColor m_tone;
};

// 作战日志的标题条:石墨底 + 警示条。
class LogBar : public QWidget
{
public:
    explicit LogBar(QPushButton* all)
    {
        auto* h = new QHBoxLayout(this);
        h->setContentsMargins(12, 3, 6, 3);
        h->setSpacing(10);
        auto* icon = new AppIcon(QStringLiteral("terminal"));
        icon->setColor(QColor(0xFF, 0xFF, 0xFF));
        icon->setPx(15);
        h->addWidget(icon, 0, Qt::AlignVCenter);
        auto* t = new QLabel(u("作战日志 · 最近活动"));
        t->setStyleSheet(QStringLiteral("color:#FFFFFF; font-size:10pt; font-weight:900;"));
        h->addWidget(t, 0, Qt::AlignVCenter);
        h->addStretch(1);
        h->addWidget(all, 0, Qt::AlignVCenter);
        setFixedHeight(38);
    }

protected:
    void paintEvent(QPaintEvent*) override
    {
        QPainter p(this);
        p.setRenderHint(QPainter::Antialiasing, true);
        const QRectF r = QRectF(rect()).adjusted(1, 1, -1, -1);
        const QPainterPath path = theme::panelPath(r, theme::mecha() ? 6.0 : 12.0);
        p.fillPath(path, theme::mecha() ? theme::pal().structure : theme::accent());
        p.strokePath(path, QPen(theme::ink(), 2.2, Qt::SolidLine, Qt::FlatCap,
                                theme::mecha() ? Qt::MiterJoin : Qt::RoundJoin));
        const theme::Palette& P = theme::pal();
        const QRectF hz(r.left() + 190, r.center().y() - 4, qMax<qreal>(0, r.width() - 190 - 120), 8);
        if (hz.width() > 20) {
            sticker::hazard(p, hz, P.hazardA, P.hazardB, 5);
            p.setPen(QPen(theme::ink(), 1.2));
            p.setBrush(Qt::NoBrush);
            p.drawRect(hz);
        }
    }
};

void fadeInRow(QWidget* row, const QWidget* context)
{
    const int ms = motion::duration(300);
    if (ms <= 0 || !motion::onScreen(context))
        return;
    auto* fx = new QGraphicsOpacityEffect(row);
    fx->setOpacity(0.0);
    row->setGraphicsEffect(fx);
    auto* anim = new QPropertyAnimation(fx, "opacity", row);
    anim->setDuration(ms);
    anim->setStartValue(0.0);
    anim->setEndValue(1.0);
    anim->setEasingCurve(QEasingCurve::OutCubic);
    QObject::connect(anim, &QPropertyAnimation::finished, row, [row] { row->setGraphicsEffect(nullptr); });
    anim->start(QAbstractAnimation::DeleteWhenStopped);
    // 同时从左边滑进来:动的是行的内边距,不和外层布局抢位置。
    if (QLayout* lay = row->layout()) {
        const QMargins base = lay->contentsMargins();
        auto* slide = new QVariantAnimation(row);
        slide->setDuration(ms);
        slide->setStartValue(36.0);
        slide->setEndValue(0.0);
        slide->setEasingCurve(QEasingCurve::OutCubic);
        QObject::connect(slide, &QVariantAnimation::valueChanged, row, [lay, base](const QVariant& v) {
            lay->setContentsMargins(base.left() + qRound(v.toReal()), base.top(), base.right(), base.bottom());
        });
        slide->start(QAbstractAnimation::DeleteWhenStopped);
    }
}

QLabel* screenLabel(const QString& text, const QColor& c, qreal pt, int weight, bool mono = false)
{
    auto* l = new QLabel(text);
    QFont f;
    if (mono)
        f.setFamilies({QStringLiteral("Cascadia Mono"), QStringLiteral("Consolas")});
    f.setPointSizeF(pt);
    f.setWeight(QFont::Weight(weight));
    l->setFont(f);
    l->setStyleSheet(QStringLiteral("color:%1;").arg(c.name()));
    return l;
}

// 金刚:按设计稿另画的一套器件

// 雅黑排在首位:应用默认字体是 Segoe UI,中文走回退字体时粗体不生效。
QFont titanUi(int px, int weight)
{
    QFont f = sticker::headFont(9.0, weight);
    f.setPixelSize(px);
    return f;
}

QFont titanMono(int px, QFont::Weight weight)
{
    QFont f;
    f.setFamilies({QStringLiteral("Cascadia Mono"), QStringLiteral("Consolas"), QStringLiteral("Microsoft YaHei UI")});
    f.setPixelSize(px);
    f.setWeight(weight);
    return f;
}

QLabel* titanText(const QString& text, const QColor& c, int px, int weight)
{
    auto* l = new QLabel(text);
    l->setFont(titanUi(px, weight));
    l->setStyleSheet(QStringLiteral("color:%1;").arg(c.name()));
    return l;
}

// 赛博坦字符条:14 个字形按固定序列排开,纯装饰。cell = 每个字形占的方格边长。
void paintGlyphs(QPainter& p, const QPointF& topLeft, int n, int seed, qreal cell, const QColor& color)
{
    using L = QLineF;
    static const QList<QList<QLineF>> kGlyphs = {
        {L(1, 1, 7, 1), L(7, 1, 7, 9), L(7, 9, 1, 9), L(1, 9, 1, 1)},
        {L(1, 1, 7, 1), L(4, 1, 4, 9)},
        {L(1, 9, 4, 1), L(4, 1, 7, 9), L(2.5, 6, 5.5, 6)},
        {L(1, 1, 1, 9), L(1, 9, 7, 9)},
        {L(1, 1, 7, 1), L(7, 1, 1, 9), L(1, 9, 7, 9)},
        {L(1, 1, 1, 9), L(7, 1, 7, 9), L(1, 5, 7, 5)},
        {L(1, 1, 7, 9), L(7, 1, 1, 9)},
        {L(4, 1, 4, 9), L(1, 5, 7, 5)},
        {L(1, 9, 1, 1), L(1, 1, 7, 1), L(7, 1, 7, 5), L(7, 5, 1, 5)},
        {L(7, 1, 1, 1), L(1, 1, 1, 5), L(1, 5, 7, 5), L(7, 5, 7, 9), L(7, 9, 1, 9)},
        {L(1, 1, 7, 1), L(7, 1, 7, 9), L(1, 5, 7, 5)},
        {L(1, 5, 4, 1), L(4, 1, 7, 5), L(7, 5, 4, 9), L(4, 9, 1, 5)},
        {L(1, 1, 4, 9), L(4, 9, 7, 1)},
        {L(1, 9, 7, 9), L(4, 9, 4, 1), L(1, 1, 7, 1)},
    };
    const qreal k = cell / 10.0;
    p.save();
    p.setRenderHint(QPainter::Antialiasing, true);
    p.setPen(QPen(color, 1.6 * k, Qt::SolidLine, Qt::SquareCap, Qt::MiterJoin));
    int s = seed;
    for (int i = 0; i < n; ++i) {
        s = (s * 73 + 41) % 101;
        const QPointF o(topLeft.x() + i * cell, topLeft.y());
        for (const QLineF& l : kGlyphs.at(s % 14))
            p.drawLine(QLineF(o + l.p1() * k, o + l.p2() * k));
    }
    p.restore();
}

// 盒式模糊三遍,约等于 σ = √(r²+r) 的高斯(CSS 阴影模糊值 B 对应 σ = B/2)。a 是 w×h 的透明度。
void blurAlpha(QList<uchar>& a, int w, int h, int r)
{
    const int div = 2 * r + 1;
    QList<int> line(qMax(w, h));
    for (int pass = 0; pass < 3; ++pass) {
        for (int y = 0; y < h; ++y) {
            uchar* row = a.data() + qsizetype(y) * w;
            for (int x = 0; x < w; ++x)
                line[x] = row[x];
            int sum = 0;
            for (int x = 0; x <= r && x < w; ++x)
                sum += line[x];
            for (int x = 0; x < w; ++x) {
                row[x] = uchar(sum / div);
                if (x + r + 1 < w)
                    sum += line[x + r + 1];
                if (x - r >= 0)
                    sum -= line[x - r];
            }
        }
        uchar* data = a.data();
        for (int x = 0; x < w; ++x) {
            for (int y = 0; y < h; ++y)
                line[y] = data[qsizetype(y) * w + x];
            int sum = 0;
            for (int y = 0; y <= r && y < h; ++y)
                sum += line[y];
            for (int y = 0; y < h; ++y) {
                data[qsizetype(y) * w + x] = uchar(sum / div);
                if (y + r + 1 < h)
                    sum += line[y + r + 1];
                if (y - r >= 0)
                    sum -= line[y - r];
            }
        }
    }
}

// 单行标签:拉丁字用 latin 字体、中文用 cjk 字体。Bahnschrift 没有中文,回退出来的中文不会加粗。
// 颜色取前景色,样式表里的 color 照样生效。
class MixedLabel final : public QLabel
{
public:
    MixedLabel(const QFont& latin, const QFont& cjk) : m_latin(latin), m_cjk(cjk) {}

    QSize sizeHint() const override
    {
        qreal w = 0.0;
        for (const Run& r : runs())
            w += QFontMetricsF(r.cjk ? m_cjk : m_latin).horizontalAdvance(r.text);
        return QSize(qCeil(w), qCeil(qMax(QFontMetricsF(m_latin).height(), QFontMetricsF(m_cjk).height())));
    }
    QSize minimumSizeHint() const override { return QSize(0, sizeHint().height()); }

protected:
    void paintEvent(QPaintEvent*) override
    {
        QPainter p(this);
        p.setPen(palette().color(foregroundRole()));
        const QFontMetricsF a(m_latin), b(m_cjk);
        const qreal asc = qMax(a.ascent(), b.ascent());
        const qreal base = (height() - asc - qMax(a.descent(), b.descent())) / 2.0 + asc;
        qreal x = 0.0;
        for (const Run& r : runs()) {
            const QFont& f = r.cjk ? m_cjk : m_latin;
            p.setFont(f);
            p.drawText(QPointF(x, base), r.text);
            x += QFontMetricsF(f).horizontalAdvance(r.text);
        }
    }

private:
    struct Run {
        QString text;
        bool cjk = false;
    };

    QList<Run> runs() const
    {
        QList<Run> out;
        for (const QChar c : text()) {
            const bool cjk = c.unicode() >= 0x2E80;
            if (out.isEmpty() || out.last().cjk != cjk)
                out.append(Run{QString(), cjk});
            out.last().text.append(c);
        }
        return out;
    }

    QFont m_latin;
    QFont m_cjk;
};

// 设计稿的小号字(10.5px 之类)不是整数像素,用磅值设(1px = 0.75pt)。
QFont atPx(QFont f, qreal px)
{
    f.setPointSizeF(px * 0.75);
    return f;
}

// 表情屏(金刚):左边是机器人半身像,身后一团光学镜颜色的光晕,脚下一块透视地板;
// 右边的文字、状态段和按钮是子控件。光学镜颜色跟着防护状态走。
class TitanFace : public QWidget
{
public:
    static constexpr int kBotZone = 226;

    TitanFace()
    {
        m_blink = new QTimer(this);
        m_blink->setSingleShot(true);
        QObject::connect(m_blink, &QTimer::timeout, this, [this] {
            m_blinkNow = !m_blinkNow;
            update(botArea());
            m_blink->start(m_blinkNow ? 140 : 2400 + int(QRandomGenerator::global()->bounded(3200)));
        });
        m_glance = new QTimer(this);
        m_glance->setSingleShot(true);
        QObject::connect(m_glance, &QTimer::timeout, this, [this] {
            m_lookLeft = !m_lookLeft;
            update(botArea());
            m_glance->start(m_lookLeft ? 700 : 6000 + int(QRandomGenerator::global()->bounded(5000)));
        });
    }

    void setMood(robot::Mood m)
    {
        if (m_mood == m)
            return;
        m_mood = m;
        update();
    }

    void setService(bool on)
    {
        if (m_service == on)
            return;
        m_service = on;
        update();
    }

    // 大标题在布局里的占位。字由表情屏自己画:泛光和投影要伸到占位外面。
    QWidget* headlineSlot()
    {
        if (!m_slot) {
            m_slot = new QWidget(this);
            m_slot->setAttribute(Qt::WA_TransparentForMouseEvents);
        }
        return m_slot;
    }

    // 设计稿 .stk.on-screen:雅黑 900 46px、行高 1.05、字距 2、以左下角为原点右斜 9°;
    // 先压 4px 硬投影和 18px 光学镜色泛光,再描 6px 深青边、填字。占位含左 2 / 上 3 / 下 2 的外边距。
    void setHeadline(const QString& text, const QColor& fill)
    {
        if (m_headline == text && m_headFill == fill && m_slot)
            return;
        m_headFill = fill;
        if (m_headline != text || !m_slot) {
            m_headline = text;
            const QFont f = headlineFont();
            const QFontMetricsF fm(f);
            QPainterPath glyphs;
            glyphs.addText(QPointF(0.0, (kHeadLine - fm.ascent() - fm.descent()) / 2.0 + fm.ascent()), f, text);
            const qreal t = std::tan(qDegreesToRadians(9.0));
            m_headPath = QTransform(1.0, 0.0, -t, 1.0, t * kHeadLine, 0.0).map(glyphs);
            // 中文字形的笔画轮廓互相压叠,奇偶规则会在叠处挖出空洞。
            m_headPath.setFillRule(Qt::WindingFill);
            QPainterPathStroker stroker;
            stroker.setWidth(6.0);
            stroker.setJoinStyle(Qt::MiterJoin);
            stroker.setMiterLimit(4.0);
            m_headStroke = stroker.createStroke(m_headPath);
            m_headGlow = QImage();
            headlineSlot()->setFixedSize(qCeil(fm.horizontalAdvance(text)) + 2, qCeil(kHeadLine) + 5);
        }
        update();
    }

protected:
    void showEvent(QShowEvent* e) override
    {
        QWidget::showEvent(e);
        if (motion::enabled()) {
            m_blink->start(1800);
            m_glance->start(4000);
        }
    }
    void hideEvent(QHideEvent* e) override
    {
        QWidget::hideEvent(e);
        m_blink->stop();
        m_blinkNow = false;
        m_glance->stop();
        m_lookLeft = false;
    }
    void paintEvent(QPaintEvent*) override
    {
        const theme::Palette& P = theme::pal();
        QPainter p(this);
        p.setRenderHint(QPainter::Antialiasing, true);
        const QRectF body = sticker::panel(p, QRectF(rect()), P.screen, 20.0, true);
        const QRectF in = body.adjusted(2, 2, -2, -2);
        const QColor optic = robot::led(m_mood);
        p.save();
        p.setClipPath(theme::panelPath(in, 18.0));

        p.save();
        p.translate(in.left() + 120.0, in.top() + 110.0);
        p.scale(1.0, 160.0 / 190.0);
        QRadialGradient halo(QPointF(0.0, 0.0), 190.0);
        halo.setColorAt(0.0, theme::tint(optic, 0.36));
        halo.setColorAt(1.0, theme::tint(optic, 0.0));
        p.setPen(Qt::NoPen);
        p.setBrush(halo);
        p.drawEllipse(QPointF(0.0, 0.0), 190.0, 190.0);
        p.restore();

        paintFloor(p, in, optic);

        // 半身像:取设计稿坐标(240×300)里 x 34..206、y 4..176 那一块,画成 212×212,底边比屏幕低 6px。
        const QRectF bust(body.left() + 14.0, body.bottom() + 6.0 - 212.0, 212.0, 212.0);
        const qreal k = 212.0 / 172.0;
        robot::Look look;
        look.mood = m_mood;
        look.pose = m_mood == robot::Mood::Alert ? robot::Pose::Shield : robot::Pose::Stand;
        look.shadow = false;
        look.blink = m_blinkNow && m_mood != robot::Mood::Sleep;
        look.lookLeft = m_lookLeft && m_mood == robot::Mood::Guard;
        look.strokePx = 3.0;
        p.save();
        p.setClipRect(bust, Qt::IntersectClip);
        robot::paint(p, QRectF(bust.left() - 34.0 * k, bust.top() - 4.0 * k, 240.0 * k, 300.0 * k), look);
        p.restore();

        paintHeadline(p, optic);

        p.setRenderHint(QPainter::Antialiasing, false);
        for (int y = int(in.top()); y < in.bottom(); y += 3)
            p.fillRect(QRectF(in.left(), y, in.width(), 1), QColor(255, 255, 255, 8));
        p.setRenderHint(QPainter::Antialiasing, true);

        QFont hud = titankit::numFont(9, QFont::Bold);
        hud.setLetterSpacing(QFont::AbsoluteSpacing, 1.5);
        p.setFont(hud);
        p.setPen(theme::blend(optic, QColor(0x77, 0x88, 0x99), 0.75));
        const QRectF line(body.left() + 14.0, body.top() + 12.0, 200.0, 13.0);
        p.drawText(line, Qt::AlignLeft | Qt::AlignVCenter,
                   m_mood == robot::Mood::Sleep ? QStringLiteral("OPTICS OFFLINE") : QStringLiteral("OPTICS 100%"));
        p.drawText(line.translated(0.0, 13.0), Qt::AlignLeft | Qt::AlignVCenter,
                   m_service ? QStringLiteral("CORE STABLE") : QStringLiteral("CORE LOCKED"));

        QColor glyph = theme::blend(optic, QColor(0x44, 0x55, 0x66), 0.55);
        glyph.setAlphaF(0.8f);
        paintGlyphs(p, QPointF(body.right() - 22.0 - 90.0, body.top() + 14.0), 9, 13, 10.0, glyph);
        p.restore();
    }

private:
    // 地板:一块 36px 方格的平面绕底边后仰 64°,视距 240;越远越淡。
    static void paintFloor(QPainter& p, const QRectF& in, const QColor& optic)
    {
        const qreal kSin = 0.898794, kCos = 0.438371;
        const qreal kDepth = 130.0, kFade = 0.92 * kDepth, kEye = 240.0;
        const qreal cx = in.center().x();
        const qreal y0 = in.bottom() + 10.0;
        const qreal half = in.width() * 0.8;
        const auto project = [&](qreal x, qreal h) {
            const qreal s = kEye / (kEye + h * kSin);
            return QPointF(cx + x * s, y0 - h * kCos * s);
        };
        const auto alphaAt = [&](qreal h) { return 0.385 * qMax<qreal>(0.0, 1.0 - h / kFade); };
        p.save();
        p.setRenderHint(QPainter::Antialiasing, true);
        for (qreal x = -half; x <= half; x += 36.0) {
            const QPointF a = project(x, 0.0);
            const QPointF b = project(x, kFade);
            QLinearGradient g(a, b);
            g.setColorAt(0.0, theme::tint(optic, alphaAt(0.0)));
            g.setColorAt(1.0, theme::tint(optic, 0.0));
            p.setPen(QPen(QBrush(g), 1.3));
            p.drawLine(a, b);
        }
        for (qreal h = kDepth - 36.0 * 3.0; h < kFade; h += 36.0) {
            p.setPen(QPen(theme::tint(optic, alphaAt(h) * 0.7), 1.0));
            p.drawLine(project(-half, h), project(half, h));
        }
        p.restore();
    }

    QRect botArea() const { return QRect(0, 0, kBotZone + 16, height()); }

    static QFont headlineFont()
    {
        QFont f = sticker::headFont(9.0, QFont::Black);
        f.setPixelSize(46);
        f.setLetterSpacing(QFont::AbsoluteSpacing, 2.0);
        return f;
    }

    void paintHeadline(QPainter& p, const QColor& optic)
    {
        if (!m_slot || m_headline.isEmpty())
            return;
        const QColor glow = theme::tint(optic, 0.7);
        if (m_headGlow.isNull() || m_glowColor != glow) {
            m_glowColor = glow;
            const QRect box = m_headStroke.boundingRect().toAlignedRect().adjusted(-28, -28, 28, 28);
            QImage shape(box.size(), QImage::Format_ARGB32_Premultiplied);
            shape.fill(Qt::transparent);
            {
                QPainter q(&shape);
                q.setRenderHint(QPainter::Antialiasing, true);
                q.translate(-box.topLeft());
                q.fillPath(m_headStroke, Qt::white);
                q.fillPath(m_headPath, Qt::white);
            }
            const int w = box.width(), h = box.height();
            QList<uchar> alpha(qsizetype(w) * h);
            for (int y = 0; y < h; ++y) {
                const auto* row = reinterpret_cast<const QRgb*>(shape.constScanLine(y));
                for (int x = 0; x < w; ++x)
                    alpha[y * w + x] = uchar(qAlpha(row[x]));
            }
            blurAlpha(alpha, w, h, 9);
            m_headGlow = QImage(box.size(), QImage::Format_ARGB32_Premultiplied);
            for (int y = 0; y < h; ++y) {
                auto* row = reinterpret_cast<QRgb*>(m_headGlow.scanLine(y));
                for (int x = 0; x < w; ++x)
                    row[x] = qPremultiply(qRgba(glow.red(), glow.green(), glow.blue(), alpha[y * w + x] * glow.alpha() / 255));
            }
            m_glowAt = box.topLeft();
        }
        const QColor hard(qRound(optic.red() * 0.55), qRound(optic.green() * 0.55), qRound(optic.blue() * 0.55));
        p.save();
        p.setRenderHint(QPainter::Antialiasing, true);
        p.translate(QPointF(m_slot->pos()) + QPointF(2.0 + 4.0, 3.0 + 4.0));
        p.fillPath(m_headStroke, hard);
        p.fillPath(m_headPath, hard);
        p.translate(-4.0, -4.0);
        p.drawImage(m_glowAt, m_headGlow);
        p.fillPath(m_headStroke, QColor(0x0B, 0x2A, 0x3A));
        p.fillPath(m_headPath, m_headFill);
        p.restore();
    }

    static constexpr qreal kHeadLine = 46.0 * 1.05;

    robot::Mood m_mood = robot::Mood::Sleep;
    bool m_service = false;
    QTimer* m_blink = nullptr;
    bool m_blinkNow = false;
    QTimer* m_glance = nullptr;
    bool m_lookLeft = false;
    QWidget* m_slot = nullptr;
    QString m_headline;
    QColor m_headFill = Qt::white;
    QPainterPath m_headPath;   // 字形(已斜),原点 = 字框左上角
    QPainterPath m_headStroke; // 6px 描边的轮廓
    QImage m_headGlow;
    QColor m_glowColor;
    QPoint m_glowAt;
};

// 战绩计数的一行:左边一道色条,名称压在说明上面,数码管靠右。
class TitanCounterRow : public ClickRow
{
public:
    explicit TitanCounterRow(const QColor& hue) : ClickRow(false), m_hue(hue) { setFixedHeight(40); }

protected:
    void paintEvent(QPaintEvent*) override
    {
        QPainter p(this);
        const QRectF r(rect());
        if (underMouse())
            p.fillRect(r, QColor(255, 255, 255, 6));
        p.fillRect(QRectF(r.left(), r.top(), r.width(), 1.0), QColor(0x08, 0x0B, 0x12));
        const QRectF bar(r.left() + 2.0, r.center().y() - 11.0, 4.0, 22.0);
        glowAround(p, bar, m_hue);
        p.fillRect(bar, m_hue);
    }

private:
    QColor m_hue;
};

// 雷达图例的小色块。
class LegendDot : public QWidget
{
public:
    explicit LegendDot(const QColor& c) : m_color(c) { setFixedSize(10, 10); }

protected:
    void paintEvent(QPaintEvent*) override
    {
        QPainter p(this);
        p.setRenderHint(QPainter::Antialiasing, true);
        p.fillRect(QRectF(rect()), theme::ink());
        p.fillRect(QRectF(rect()).adjusted(1.5, 1.5, -1.5, -1.5), m_color);
    }

private:
    QColor m_color;
};

// 防护维度的一格:图标块 + 名称 + ONLINE / OFFLINE + 右边一根竖拨杆(只读,在「设置」里调整)。
class TitanDimCell : public QWidget
{
public:
    TitanDimCell(const QString& icon, const QString& name, const QColor& hue) : m_icon(icon), m_name(name), m_hue(hue)
    {
        setFixedHeight(46);
        setMinimumWidth(112);
        setAccessibleName(name);
    }

    // 1 = 开,0 = 关,-1 = 还不知道。
    void setState(int on)
    {
        if (m_on == on)
            return;
        m_on = on;
        update();
    }

protected:
    void paintEvent(QPaintEvent*) override
    {
        const theme::Palette& P = theme::pal();
        QPainter p(this);
        p.setRenderHint(QPainter::Antialiasing, true);
        const QRectF r = QRectF(rect()).adjusted(1, 1, -1, -1);
        const QPainterPath plate = theme::panelPath(r, 7.0);
        p.fillPath(plate, P.surfaceAlt);
        p.strokePath(plate, QPen(P.ink, 2.0, Qt::SolidLine, Qt::FlatCap, Qt::MiterJoin));

        const bool on = m_on == 1;
        const bool off = m_on == 0;
        const QRectF tile(r.left() + 9.0, r.center().y() - 13.0, 26.0, 26.0);
        const QPainterPath tilePath = theme::panelPath(tile, 5.0);
        p.fillPath(tilePath, off ? QColor(0x2A, 0x35, 0x50) : m_hue);
        p.strokePath(tilePath, QPen(P.ink, 2.0, Qt::SolidLine, Qt::FlatCap, Qt::MiterJoin));
        AppIcon::draw(p, m_icon, QRectF(tile.center().x() - 7.0, tile.center().y() - 7.0, 14.0, 14.0),
                      off ? P.textMuted : P.ink, 1.6);

        // 设计稿 .dim:右内边距 9;名称 800 12.5px/1.2 + 状态 700 8.5px/1.3,两行合起来竖直居中。
        const QRectF slot(r.right() - 8.0 - 14.0, r.center().y() - 16.0, 14.0, 32.0);
        const qreal tx = tile.right() + 8.0;
        const qreal tw = slot.left() - 3.0 - 8.0 - tx;
        const qreal ty = (height() - 15.0 - 11.05) / 2.0;
        p.setFont(atPx(sticker::headFont(9.0, QFont::ExtraBold), 12.5));
        p.setPen(off ? P.textMuted : P.text);
        p.drawText(QRectF(tx, ty, tw, 15.0), Qt::AlignLeft | Qt::AlignVCenter, m_name);
        QFont sf = atPx(titankit::numFont(9, QFont::Bold), 8.5);
        sf.setLetterSpacing(QFont::AbsoluteSpacing, 1.5);
        p.setFont(sf);
        p.setPen(on ? P.success : off ? P.danger : P.textMuted);
        p.drawText(QRectF(tx, ty + 15.0, tw, 11.05), Qt::AlignLeft | Qt::AlignVCenter,
                   on ? QStringLiteral("ONLINE") : off ? QStringLiteral("OFFLINE") : u("— —"));

        // 拨杆(设计稿 .lever):14×32 墨框槽,内衬 1px 描线;开 = 上 55% 亮青块,关 = 下 30% 红块(都是 55% 不透明);
        // 杆头 20×15 两侧各伸出 3px,开时贴槽顶、关时贴槽底,未知停在中间。
        p.setRenderHint(QPainter::Antialiasing, false);
        p.fillRect(slot, P.ink);
        const QRectF well = slot.adjusted(2, 2, -2, -2);
        p.fillRect(well, P.borderStrong);
        const QRectF inner = well.adjusted(1, 1, -1, -1);
        p.fillRect(inner, P.field);
        if (on)
            p.fillRect(QRectF(inner.left(), inner.top(), inner.width(), inner.height() * 0.55), theme::tint(P.glow, 0.55));
        else if (off)
            p.fillRect(QRectF(inner.left(), inner.bottom() - inner.height() * 0.3, inner.width(), inner.height() * 0.3),
                       theme::tint(P.danger, 0.55));
        const qreal ky = on ? slot.top() + 2.0 : off ? slot.bottom() - 17.0 : slot.center().y() - 7.5;
        const QRectF knob(slot.left() - 3.0, qRound(ky), 20.0, 15.0);
        p.fillRect(knob, P.ink);
        p.fillRect(knob.adjusted(2, 2, -2, -2), on ? QColor(0xC6, 0xCF, 0xDA) : QColor(0x7B, 0x87, 0x98));
    }

private:
    QString m_icon;
    QString m_name;
    QColor m_hue;
    int m_on = -1;
};

// 终端屏:直角、墨线框、扫描线、内描一圈光。
class TitanScreen : public QWidget
{
protected:
    void paintEvent(QPaintEvent*) override
    {
        const theme::Palette& P = theme::pal();
        QPainter p(this);
        const QRectF r(rect());
        const QRectF in = r.adjusted(2, 2, -2, -2);
        p.fillRect(r, P.ink);
        p.fillRect(in, P.screen);
        for (int y = int(in.top()); y < in.bottom(); y += 3)
            p.fillRect(QRectF(in.left(), y, in.width(), 1), QColor(255, 255, 255, 8));
        p.setPen(QPen(theme::tint(P.glow, 0.22), 1.0));
        p.setBrush(Qt::NoBrush);
        p.drawRect(in.toRect().adjusted(0, 0, -1, -1));
    }
};

// 日志行的取景框:行多了从底部裁掉,既不把面板撑高,也不挤压行高。
// 行放在 box 里;box 所在的内层控件不受外层布局管,高度只由行数决定。
class TitanLogClip : public QWidget
{
public:
    QVBoxLayout* box = nullptr;

    TitanLogClip()
    {
        setSizePolicy(QSizePolicy::Ignored, QSizePolicy::Ignored);
        m_list = new QWidget(this);
        auto* outer = new QVBoxLayout(m_list);
        outer->setContentsMargins(0, 0, 0, 0);
        outer->setSpacing(0);
        outer->setSizeConstraint(QLayout::SetMinimumSize);
        box = new QVBoxLayout;
        box->setSpacing(0);
        outer->addLayout(box);
        // 内层控件比行高总和高时,多出来的地方留在底下,行始终贴顶。
        outer->addStretch(1);
    }

protected:
    void resizeEvent(QResizeEvent*) override
    {
        m_list->setGeometry(0, 0, width(), qMax(height(), m_list->minimumHeight()));
    }

private:
    QWidget* m_list = nullptr;
};

// 作战日志的一行:时间 / 处置标签 / 进程 / 动作与目标 / 靠右的处置结果。
class TitanLogRow : public ClickRow
{
public:
    QString time;
    QString tag;
    QColor tagColor;
    QString proc;
    QString what;
    QString result;

    TitanLogRow() : ClickRow(true) { setFixedHeight(20); }

protected:
    void paintEvent(QPaintEvent* e) override
    {
        ClickRow::paintEvent(e);
        const theme::Palette& P = theme::pal();
        QPainter p(this);
        p.setRenderHint(QPainter::Antialiasing, true);
        const QRectF r(rect());
        const QFont mono = titanMono(12, QFont::Medium);
        const QFont monoBold = titanMono(12, QFont::Bold);
        const QFontMetricsF fm(mono);
        qreal x = r.left();
        const qreal timeW = fm.horizontalAdvance(QStringLiteral("00:00:00"));
        p.setFont(mono);
        p.setPen(P.scrMuted);
        p.drawText(QRectF(x, r.top(), timeW, r.height()), Qt::AlignLeft | Qt::AlignVCenter, time);
        x += timeW + 10.0;
        const QRectF chip(x, r.center().y() - 8.0, 34.0, 16.0);
        p.fillRect(chip, tagColor);
        p.setFont(titanUi(11, QFont::ExtraBold));
        p.setPen(P.ink);
        p.drawText(chip, Qt::AlignCenter, tag);
        x += chip.width() + 10.0;

        const QFont resultFont = titanUi(11, QFont::Normal);
        const QFontMetricsF rfm(resultFont);
        const qreal resultW = qMin(rfm.horizontalAdvance(result) + 1.0, r.width() * 0.3);
        p.setFont(resultFont);
        p.setPen(P.scrMuted);
        p.drawText(QRectF(r.right() - resultW, r.top(), resultW, r.height()), Qt::AlignRight | Qt::AlignVCenter,
                   rfm.elidedText(result, Qt::ElideRight, resultW));
        const qreal right = r.right() - resultW - 10.0;
        if (right - x < 24.0)
            return;
        const QFontMetricsF bfm(monoBold);
        const qreal procW = qMin(bfm.horizontalAdvance(proc) + 1.0, (right - x) * 0.5);
        p.setFont(monoBold);
        p.setPen(P.scrText);
        p.drawText(QRectF(x, r.top(), procW, r.height()), Qt::AlignLeft | Qt::AlignVCenter,
                   bfm.elidedText(proc, Qt::ElideRight, procW));
        x += procW + 10.0;
        if (right - x < 24.0)
            return;
        p.setFont(mono);
        p.setPen(P.scrText2);
        p.drawText(QRectF(x, r.top(), right - x, r.height()), Qt::AlignLeft | Qt::AlignVCenter,
                   fm.elidedText(what, Qt::ElideMiddle, right - x));
    }
};

// 任务卡:左边一道警示斜纹,编号与优先级、标题、说明(可省)在中间,按钮靠右。
class TitanMission : public QWidget
{
public:
    TitanMission(const QColor& tone, const QString& eyebrow, const QString& title, const QString& desc,
                 const QString& action, std::function<void()> fn)
        : m_tone(tone)
    {
        const theme::Palette& P = theme::pal();
        auto* h = new QHBoxLayout(this);
        h->setContentsMargins(21, 6, 11, 8);
        h->setSpacing(10);
        auto* col = new QVBoxLayout;
        col->setSpacing(0);
        QFont ef = titankit::numFont(10, QFont::ExtraBold);
        ef.setLetterSpacing(QFont::AbsoluteSpacing, 2.5);
        QFont efCjk = titanUi(10, QFont::ExtraBold);
        efCjk.setLetterSpacing(QFont::AbsoluteSpacing, 2.5);
        auto* eb = new MixedLabel(ef, efCjk);
        eb->setText(eyebrow);
        eb->setStyleSheet(QStringLiteral("color:%1;").arg(tone.name()));
        eb->setFixedHeight(10);
        col->addWidget(eb);
        col->addSpacing(4);
        col->addWidget(titankit::lined(title, titanUi(13, QFont::ExtraBold), P.text, 13 * 1.3));
        if (!desc.isEmpty())
            col->addWidget(titankit::lined(desc, atPx(titanUi(12, QFont::Normal), 11.5), P.textMuted, 11.5 * 1.45));
        h->addLayout(col, 1);
        auto* btn = titankit::button(action, "primary", QString(), QStringLiteral("chevron-right"));
        QObject::connect(btn, &QAbstractButton::clicked, btn, [f = std::move(fn)] {
            if (f)
                f();
        });
        h->addWidget(btn, 0, Qt::AlignVCenter);
    }

protected:
    void paintEvent(QPaintEvent*) override
    {
        const theme::Palette& P = theme::pal();
        QPainter p(this);
        p.setRenderHint(QPainter::Antialiasing, true);
        const QRectF r = QRectF(rect()).adjusted(1, 1, -1, -1);
        const QPainterPath plate = theme::panelPath(r, 8.0);
        p.fillPath(plate, P.surfaceAlt);
        p.save();
        p.setClipPath(plate);
        sticker::hazard(p, QRectF(r.left() + 2.0, r.top() + 2.0, 9.0, r.height() - 4.0), m_tone, P.ink, 8.5);
        p.restore();
        p.strokePath(plate, QPen(P.ink, 2.0, Qt::SolidLine, Qt::FlatCap, Qt::MiterJoin));
    }

private:
    QColor m_tone;
};

}

DashboardPage::DashboardPage(IpcClient* ipc, QWidget* parent) : QWidget(parent), m_ipc(ipc)
{
    auto* outer = new QVBoxLayout(this);
    outer->setContentsMargins(0, 0, 0, 0);
    auto* scroll = new QScrollArea;
    scroll->setWidgetResizable(true);
    scroll->setFrameShape(QFrame::NoFrame);
    scroll->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    scroll->viewport()->setAutoFillBackground(false);
    outer->addWidget(scroll);
    auto* content = new QWidget;
    auto* v = new QVBoxLayout(content);
    if (theme::titan()) {
        // 金刚:一屏三行两列(208 / 166 / 余下),窗口够高时不出滚动条;太矮时第三行保底,整页可滚。
        v->setContentsMargins(theme::metric::pagePad, 4, theme::metric::pagePad, 14);
        v->setSpacing(0);
        auto* grid = new QGridLayout;
        grid->setContentsMargins(0, 0, 0, 0);
        grid->setSpacing(14);
        grid->setColumnStretch(0, 3);
        grid->setColumnStretch(1, 2);
        grid->setRowStretch(2, 1);
        QList<QWidget*> cells;
        const auto place = [grid, &cells](QWidget* w, int row, int col, int height) {
            if (row < 2)
                w->setFixedHeight(height);
            else
                w->setMinimumHeight(height);
            grid->addWidget(w, row, col);
            cells.append(w);
        };
        place(buildFaceTitan(), 0, 0, 208);
        place(buildCountersTitan(), 0, 1, 208);
        place(buildRadarTitan(), 1, 0, 166);
        place(buildDimensionsTitan(), 1, 1, 166);
        place(buildLogTitan(), 2, 0, 156);
        place(buildMissionsTitan(), 2, 1, 156);
        v->addLayout(grid, 1);

        // 横向滚动条是关着的:两列放不下时先让出页边距,还不够就改成单列往下排,不让右列被切掉。
        QWidget* port = scroll->viewport();
        const auto reflow = [v, grid, cells, port] {
            int left = 0;
            int right = 0;
            for (int i = 0; i < cells.size(); ++i) {
                int& side = i % 2 == 0 ? left : right;
                side = qMax(side, ui::minWidthOf(cells[i]));
            }
            const int need = left + right + grid->horizontalSpacing();
            const int pad = qBound(8, (port->width() - need) / 2, int(theme::metric::pagePad));
            if (QMargins m = v->contentsMargins(); m.left() != pad) {
                m.setLeft(pad);
                m.setRight(pad);
                v->setContentsMargins(m);
            }
            const bool stack = port->width() - 2 * pad < need;
            if (stack == (grid->columnStretch(1) == 0))
                return;
            for (QWidget* w : cells)
                grid->removeWidget(w);
            for (int i = 0; i < cells.size(); ++i)
                grid->addWidget(cells[i], stack ? i : i / 2, stack ? 0 : i % 2);
            grid->setColumnStretch(1, stack ? 0 : 2);
            grid->setRowStretch(2, stack ? 0 : 1);
            grid->setRowStretch(4, stack ? 1 : 0);
            grid->setRowStretch(5, stack ? 1 : 0);
        };
        ui::onResize(port, reflow);
        ui::onResize(content, reflow);
    } else {
        v->setContentsMargins(theme::metric::pagePad, 10, theme::metric::pagePad, theme::metric::pagePad);
        v->setSpacing(16);

        auto* row1 = new QHBoxLayout;
        row1->setSpacing(16);
        row1->addWidget(buildFace(), 3);
        row1->addWidget(buildCounters(), 2);
        v->addLayout(row1);
        auto* row2 = new QHBoxLayout;
        row2->setSpacing(16);
        row2->addWidget(buildRadar(), 3);
        row2->addWidget(buildDimensions(), 2);
        v->addLayout(row2);
        auto* row3 = new QHBoxLayout;
        row3->setSpacing(16);
        row3->addWidget(buildLog(), 3);
        row3->addWidget(buildMissions(), 2);
        v->addLayout(row3);
        v->addStretch();

        // 横向滚动条是关着的:一行并排放不下时先让出页边距,还不够就把这一行改成上下叠放,不让右列被切掉。
        const QList<QBoxLayout*> rows{row1, row2, row3};
        QWidget* port = scroll->viewport();
        const auto reflow = [v, rows, port] {
            int need = 0;
            for (const QBoxLayout* row : rows)
                need = qMax(need, ui::sideBySideWidth(row));
            const int pad = qBound(8, (port->width() - need) / 2, int(theme::metric::pagePad));
            if (QMargins m = v->contentsMargins(); m.left() != pad) {
                m.setLeft(pad);
                m.setRight(pad);
                v->setContentsMargins(m);
            }
            const int room = port->width() - 2 * pad;
            for (QBoxLayout* row : rows) {
                const QBoxLayout::Direction dir =
                    room < ui::sideBySideWidth(row) ? QBoxLayout::TopToBottom : QBoxLayout::LeftToRight;
                if (row->direction() != dir)
                    row->setDirection(dir);
            }
        };
        ui::onResize(port, reflow);
        ui::onResize(content, reflow);
    }
    scroll->setWidget(content);
    content->setAutoFillBackground(false);
    refreshFace();
    refreshMissions();
    refreshTally();

    connect(ipc, &IpcClient::eventLogReceived, this, [this](const bulwark::ipc::EventLogPayload& p) {
        m_statEvents->setValue(++m_eventCount);
        if (evtfmt::isRealBlock(p.action, p.enforcement))
            m_statBlocked->setValue(++m_blockedCount);
        else if (p.action == bulwark::VerdictAction::Block
                 && evtfmt::needsManualAction(p.enforcement)) {
            ++m_unenforced;
            refreshMissions();
            refreshFace();
        }
        if (p.action == bulwark::VerdictAction::Ask)
            ++m_askCount;
        else if (p.action == bulwark::VerdictAction::Allow)
            ++m_allowCount;
        refreshTally();
        if (m_chartFetched.isValid())
            static_cast<HourChart*>(m_chart)->add(p.event.timestampUtc, severityOf(p));

        const bulwark::SecurityEvent& e = p.event;
        const evtfmt::Badge d = evtfmt::disposition(p.action, p.enforcement);
        const theme::Palette& P = theme::pal();
        const bool titan = theme::titan();
        ClickRow* row = nullptr;
        if (titan) {
            auto* line = new TitanLogRow;
            line->time = e.timestampUtc.toLocalTime().toString(QStringLiteral("HH:mm:ss"));
            if (p.action == bulwark::VerdictAction::Ask) {
                line->tag = u("询问");
                line->tagColor = P.warning;
            } else if (p.action == bulwark::VerdictAction::Allow) {
                line->tag = u("放行");
                line->tagColor = P.glow;
            } else if (evtfmt::isRealBlock(p.action, p.enforcement)) {
                line->tag = u("拦截");
                line->tagColor = P.danger;
            } else {
                line->tag = u("未拦");
                line->tagColor = P.amber;
            }
            line->proc = evtfmt::actorName(e.actorPath);
            line->what = evtfmt::action(e) + QLatin1Char(' ')
                         + (e.target.isEmpty() ? evtfmt::nativePath(e.actorPath) : e.target);
            line->result = d.text;
            row = line;
        } else {
            row = new ClickRow(true);
            row->setFixedHeight(36);
            auto* h = new QHBoxLayout(row);
            h->setContentsMargins(4, 2, 4, 2);
            h->setSpacing(10);
            auto* t = screenLabel(e.timestampUtc.toLocalTime().toString(QStringLiteral("HH:mm:ss")), P.glow, 9.0, 600, true);
            t->setFixedWidth(64);
            h->addWidget(t, 0, Qt::AlignVCenter);
            auto* who = new ElidingLabel(evtfmt::actorName(e.actorPath));
            who->setStyleSheet(QStringLiteral("color:%1; font-weight:800;").arg(P.scrText.name()));
            who->setFixedWidth(170);
            h->addWidget(who, 0, Qt::AlignVCenter);
            auto* act = new ElidingLabel(evtfmt::action(e));
            act->setStyleSheet(QStringLiteral("color:%1; font-weight:700;").arg(P.scrText2.name()));
            act->setFixedWidth(96);
            h->addWidget(act, 0, Qt::AlignVCenter);
            auto* tgt = new ElidingLabel(e.target.isEmpty() ? evtfmt::nativePath(e.actorPath) : e.target);
            tgt->setElideMode(Qt::ElideMiddle);
            QFont mf;
            mf.setFamilies({QStringLiteral("Cascadia Mono"), QStringLiteral("Consolas")});
            mf.setPointSizeF(8.5);
            tgt->setFont(mf);
            tgt->setStyleSheet(QStringLiteral("color:%1;").arg(P.scrMuted.name()));
            h->addWidget(tgt, 1, Qt::AlignVCenter);
            const qreal angle = (QRandomGenerator::global()->bounded(2) ? 1.0 : -1.0)
                                * (3.0 + QRandomGenerator::global()->bounded(4));
            h->addWidget(new StampChip(d.text, onScreen(d.color), angle), 0, Qt::AlignVCenter);
        }
        const QString key = evtview::keyOf(e);
        row->onClick = [key] { go(nav::Events, {{QStringLiteral("segment"), QStringLiteral("all")}, {QStringLiteral("select"), key}}); };
        row->setToolTip(u("在事件记录中查看"));
        m_logEmpty->hide();
        m_logBox->insertWidget(0, row);
        fadeInRow(row, this);
        if (motion::onScreen(this))
            row->flash(titan ? static_cast<TitanLogRow*>(row)->tagColor : onScreen(d.color));
        // 金刚:行高固定 20,能放几行由屏幕高度决定(多留一行,让最后半行露个头)。
        int cap = 6;
        if (titan) {
            const QWidget* list = m_logBox->parentWidget();
            const QWidget* view = list ? list->parentWidget() : nullptr;
            cap = qMax(5, view ? view->height() / 20 + 1 : 5);
        }
        ++m_logRows;
        while (m_logRows > cap) {
            if (QLayoutItem* item = m_logBox->takeAt(m_logBox->count() - 2)) {
                if (QWidget* w = item->widget()) {
                    w->hide();
                    w->deleteLater();
                }
                delete item;
            }
            --m_logRows;
        }
    });
    connect(ipc, &IpcClient::rulesReceived, this, [this](const QList<bulwark::DefenseRule>& rules) {
        const auto n = std::count_if(rules.cbegin(), rules.cend(), [](const bulwark::DefenseRule& r) { return !r.isTrustEntry(); });
        m_statRules->setValue(n);
    });
    connect(ipc, &IpcClient::quarantineReceived, this, [this](const QList<bulwark::ipc::QuarantineItemPayload>& items) {
        m_statQuarantine->setValue(items.size());
    });
    connect(ipc, &IpcClient::timelineReceived, this, [this](const bulwark::ipc::TimelineResponsePayload& p) {
        if (p.requestId != m_chartRequest)
            return;
        auto* chart = static_cast<HourChart*>(m_chart);
        chart->reset();
        for (const bulwark::ipc::EventLogPayload& e : p.events)
            chart->add(e.event.timestampUtc, severityOf(e));
        chart->grow();
        m_chartFetched = QDateTime::currentDateTimeUtc();
        const QString count = theme::titan() ? QLocale(QLocale::English).toString(p.events.size())
                                             : QString::number(p.events.size());
        m_chartNote->setText(p.truncated ? u("只统计了最近 %1 条").arg(count)
                                         : u("共 %1 条 · 点一下跳到时间线").arg(count));
    });
    connect(ipc, &IpcClient::settingsReceived, this, [this](const bulwark::RuntimeSettings& s) {
        m_haveSettings = true;
        m_protectionEnabled = s.protectionEnabled;
        m_kernelConnected = s.kernelConnected;
        m_kernelStatus = s.kernelStatus;
        setDimension(QStringLiteral("proc"), s.processProtection ? 1 : 0);
        setDimension(QStringLiteral("file"), s.fileProtection ? 1 : 0);
        setDimension(QStringLiteral("reg"), s.registryProtection ? 1 : 0);
        setDimension(QStringLiteral("self"), s.selfProtection ? 1 : 0);
        setDimension(QStringLiteral("net"), s.networkProtection ? 1 : 0);
        setDimension(QStringLiteral("mem"), s.memoryProtectionEnabled ? 1 : 0);
        refreshFace();
        refreshMissions();
    });
    connect(ipc, &IpcClient::connectionChanged, this, [this](bool c) {
        m_connected = c;
        if (c) {
            m_ipc->requestSettings();
            m_ipc->requestRules();
            m_ipc->requestQuarantine();
            QTimer::singleShot(2000, this, [this] { requestChart(true); });
        } else {
            m_haveSettings = false;
            for (auto it = m_dims.begin(); it != m_dims.end(); ++it)
                setDimension(it.key(), -1);
        }
        refreshFace();
        refreshMissions();
    });
    if (ipc->isConnected()) {
        m_connected = true;
        ipc->requestSettings();
        ipc->requestRules();
        ipc->requestQuarantine();
        QTimer::singleShot(2000, this, [this] { requestChart(true); });
        refreshFace();
        refreshMissions();
    }
}

void DashboardPage::showEvent(QShowEvent* e)
{
    QWidget::showEvent(e);
    requestChart(false);
}

void DashboardPage::requestChart(bool force)
{
    if (!m_ipc || !m_ipc->isConnected())
        return;
    if (!force && m_chartFetched.isValid() && m_chartFetched.secsTo(QDateTime::currentDateTimeUtc()) < 600)
        return;
    bulwark::ipc::TimelineRequestPayload req;
    req.fromUtc = QDateTime::currentDateTimeUtc().addSecs(-24 * 3600);
    req.limit = 2000;
    m_chartRequest = req.requestId;
    m_ipc->requestTimeline(req);
}

QWidget* DashboardPage::buildFace()
{
    auto* face = new FaceScreen;
    m_face = face;
    face->setMinimumHeight(226);
    auto* h = new QHBoxLayout(face);
    h->setContentsMargins(0, 18, 22, 22);
    h->setSpacing(0);
    auto* spacer = new QWidget;
    spacer->setAttribute(Qt::WA_TransparentForMouseEvents);
    h->addWidget(spacer);
    auto* col = new QVBoxLayout;
    col->setSpacing(2);
    const theme::Palette& P = theme::pal();
    m_faceStatus = screenLabel(QString(), P.glow, 8.5, 800);
    m_faceStatus->setFont(sticker::labelFont(8.5));
    col->addWidget(m_faceStatus);
    m_faceTitle = new StickerText(u("待机"), 50);
    m_faceTitle->setTextStyle(sticker::screenTextStyle());
    col->addWidget(m_faceTitle, 0, Qt::AlignLeft);
    m_faceSub = screenLabel(QString(), P.scrText2, 9.5, 500);
    m_faceSub->setWordWrap(true);
    col->addWidget(m_faceSub);
    col->addSpacing(8);
    auto* segs = new QHBoxLayout;
    segs->setSpacing(8);
    QLabel* serviceText = nullptr;
    segs->addWidget(new SegChip(m_segKernel, m_segKernelText, u("内核驱动")));
    segs->addWidget(new SegChip(m_segService, serviceText, u("后台服务")));
    segs->addWidget(new SegChip(m_segDims, m_segDimsText, u("防护维度")));
    segs->addWidget(new SegChip(m_segTasks, m_segTasksText, u("没有待处理")));
    segs->addStretch();
    col->addLayout(segs);
    col->addStretch();
    auto* quick = new QHBoxLayout;
    quick->setSpacing(8);
    auto* blocks = ui::button(u("查看拦截记录"), nullptr, QStringLiteral("activity"), true);
    connect(blocks, &QPushButton::clicked, blocks, [] { go(nav::Events, {{QStringLiteral("segment"), QStringLiteral("block")}}); });
    auto* scan = ui::button(u("扫描自启动项"), nullptr, QStringLiteral("power"), true);
    connect(scan, &QPushButton::clicked, scan, [] { go(nav::Persistence, {{QStringLiteral("scan"), true}}); });
    quick->addWidget(blocks);
    quick->addWidget(scan);
    quick->addStretch();
    col->addLayout(quick);
    h->addLayout(col, 1);

    // 表情区宽度跟着屏幕宽度走,文字列从它右边开始。
    auto* sync = new QTimer(face);
    sync->setSingleShot(true);
    sync->setInterval(0);
    connect(sync, &QTimer::timeout, face, [face, spacer] { spacer->setFixedWidth(face->faceWidth() + 52); });
    spacer->setFixedWidth(270);
    struct Watcher : QObject {
        QTimer* t;
        explicit Watcher(QTimer* timer, QObject* parent) : QObject(parent), t(timer) {}
        bool eventFilter(QObject*, QEvent* ev) override
        {
            if (ev->type() == QEvent::Resize)
                t->start();
            return false;
        }
    };
    face->installEventFilter(new Watcher(sync, face));
    return face;
}

void DashboardPage::refreshFace()
{
    const bool titan = theme::titan();
    robot::Mood mood = robot::Mood::Sleep;
    QString title, status, sub;
    const bool known = m_connected && m_haveSettings;
    if (!m_connected) {
        title = u("待机");
        status = u("STATUS · 等待后台服务");
        sub = u("连接后台服务后显示实时防护状态。");
    } else if (!m_haveSettings) {
        title = u("自检中");
        status = u("STATUS · 正在同步防护配置");
        mood = robot::Mood::Think;
        sub = u("已连接后台服务,正在读取防护配置…");
    } else if (!m_protectionEnabled) {
        mood = robot::Mood::Alert;
        title = u("防护关闭");
        status = u("STATUS · 总开关已关闭");
        sub = u("防护总开关处于关闭状态,系统当前不受保护。可在「设置」中重新开启。");
    } else if (!m_kernelConnected) {
        mood = robot::Mood::Info;
        title = u("半防护");
        status = u("STATUS · 实时防护 · 无内核");
        sub = !m_kernelStatus.isEmpty() ? m_kernelStatus
                                        : u("内核驱动未连接:仅有用户态观测与补偿处置,缺少「动作发生前阻断」能力。");
    } else {
        mood = robot::Mood::Guard;
        title = theme::mecha() ? u("防御中") : u("守护中");
        status = theme::titan()   ? u("STATUS · 实时防护 · 变形完毕")
                 : theme::mecha() ? u("STATUS · 实时防护 · 要塞已展开")
                                  : u("STATUS · 实时防护 · 小垒在岗");
        sub = !m_kernelStatus.isEmpty() ? m_kernelStatus : u("内核驱动已连接 · 动作发生前拦截 进程 / 文件 / 注册表 / 自保 / 网络");
    }
    if (titan) {
        auto* face = static_cast<TitanFace*>(m_face);
        face->setMood(mood);
        face->setService(m_connected);
        // 状态行跟光学镜同色;防护关闭时大字换成浅红。
        m_faceStatus->setStyleSheet(QStringLiteral("color:%1;").arg(robot::led(mood).name()));
        face->setHeadline(title, mood == robot::Mood::Alert ? QColor(0xFF, 0xD0, 0xD4) : QColor(Qt::white));
        m_faceSub->setToolTip(sub);
    } else {
        static_cast<FaceScreen*>(m_face)->setMood(mood);
    }
    if (m_faceTitle && m_faceTitle->text() != title) {
        m_faceTitle->setText(title);
        m_faceTitle->pop();
    }
    m_faceStatus->setText(status);
    m_faceSub->setText(sub);
    m_face->setAccessibleName(title);
    m_face->setAccessibleDescription(sub);

    const QColor red = onScreen(theme::danger());
    const QColor yellow = onScreen(theme::warning());
    const QColor ok = titan ? theme::pal().success : theme::glow();
    m_segService->setColor(m_connected ? ok : red);
    m_segService->setBlink(!m_connected);
    m_segTasks->setBlink(m_unenforced > 0);
    if (!known) {
        m_segKernel->setLit(false);
        m_segKernelText->setText(u("内核驱动 · ?"));
    } else {
        m_segKernel->setLit(true);
        m_segKernel->setColor(m_kernelConnected ? ok : yellow);
        m_segKernelText->setText(m_kernelConnected ? u("内核驱动") : u("内核未连接"));
    }
    int on = 0, total = 0;
    for (const Dimension& d : std::as_const(m_dims)) {
        ++total;
        if (d.on == 1)
            ++on;
    }
    if (!known || total == 0) {
        m_segDims->setLit(false);
        m_segDimsText->setText(u("防护维度 · —"));
    } else {
        m_segDims->setLit(true);
        m_segDims->setColor(on == total ? ok : (on == 0 ? red : yellow));
        m_segDimsText->setText(u("防护维度 %1/%2").arg(on).arg(total));
    }
    m_segTasks->setColor(m_unenforced > 0 ? yellow : ok);
    m_segTasksText->setText(m_unenforced > 0 ? u("%1 项待处理").arg(m_unenforced) : u("没有待处理"));
    if (m_dimsNote)
        m_dimsNote->setText(known && total > 0 ? u("%1 / %2 已上线").arg(on).arg(total) : u("— / 6"));
}

QWidget* DashboardPage::buildCounters()
{
    auto* c = ui::card();
    auto* v = new QVBoxLayout(c);
    v->setContentsMargins(20, 14, 22, 14);
    v->setSpacing(0);
    auto* head = new PanelHead(u("战绩计数"), u("本次运行"), labTag(QStringLiteral("COUNTERS")));
    v->addWidget(head);
    v->addSpacing(4);
    const auto row = [&](const QColor& lamp, const QString& name, const QString& caption, bool red,
                         SevenSegCounter*& out, std::function<void()> fn, bool last) {
        auto* r = new ClickRow(false);
        r->setFixedHeight(46);
        r->onClick = std::move(fn);
        auto* h = new QHBoxLayout(r);
        h->setContentsMargins(2, 4, 2, 4);
        h->setSpacing(10);
        h->addWidget(new LampWidget(lamp, 14, 10), 0, Qt::AlignVCenter);
        auto* n = ui::label(name, "title");
        n->setFixedWidth(76);
        h->addWidget(n, 0, Qt::AlignVCenter);
        out = new SevenSegCounter(5, 18, 26);
        out->setRedLast(red);
        h->addWidget(out, 0, Qt::AlignVCenter);
        h->addStretch();
        h->addWidget(ui::label(caption, "muted"), 0, Qt::AlignVCenter);
        v->addWidget(r);
        if (!last) {
            auto* sep = new QFrame;
            sep->setFixedHeight(2);
            sep->setStyleSheet(QStringLiteral("border:none; border-top:2px dashed %1;").arg(theme::border().name()));
            v->addWidget(sep);
        }
    };
    row(onScreen(theme::danger()), u("本次拦截"), u("仅计真实拦截"), true, m_statBlocked,
        [] { go(nav::Events, {{QStringLiteral("segment"), QStringLiteral("block")}}); }, false);
    row(theme::glow(), u("本次事件"), u("本次运行累计"), false, m_statEvents,
        [] { go(nav::Events, {{QStringLiteral("segment"), QStringLiteral("all")}}); }, false);
    row(theme::mecha() ? theme::pal().hazardA : theme::amber(), u("隔离文件"),
        u("隔离区现存"), false, m_statQuarantine, [] { go(nav::Quarantine); }, false);
    row(theme::pal().structure, u("防护规则"), u("当前规则数"), false, m_statRules, [] { go(nav::Rules); }, true);
    v->addStretch();
    return c;
}

QWidget* DashboardPage::buildRadar()
{
    auto* c = ui::card();
    auto* v = new QVBoxLayout(c);
    v->setContentsMargins(18, 14, 20, 16);
    v->setSpacing(8);
    auto* head = new PanelHead(theme::mecha() ? u("战况雷达 · 24 小时") : u("今日心情 · 24 小时"),
                               u("连接后台服务后显示"));
    m_chartNote = head->note;
    v->addWidget(head);
    auto* legend = new QHBoxLayout;
    legend->setSpacing(14);
    const auto key = [legend](const QColor& color, const QString& text) {
        auto* row = new QHBoxLayout;
        row->setSpacing(6);
        row->addWidget(new LampWidget(color, 12, 8), 0, Qt::AlignVCenter);
        row->addWidget(ui::label(text, "caption"), 0, Qt::AlignVCenter);
        legend->addLayout(row);
    };
    key(theme::glow(), u("放行"));
    key(onScreen(theme::warning()), u("询问 ▲"));
    key(onScreen(theme::danger()), u("拦截 ◎"));
    legend->addStretch();
    v->addLayout(legend);
    auto* chart = new HourChart;
    chart->onClick = [] { go(nav::Timeline, {{QStringLiteral("range"), QStringLiteral("24h")}}); };
    m_chart = chart;
    v->addWidget(chart, 1);
    return c;
}

QWidget* DashboardPage::buildDimensions()
{
    auto* c = ui::card();
    auto* v = new QVBoxLayout(c);
    v->setContentsMargins(18, 14, 20, 14);
    v->setSpacing(10);
    auto* edit = ui::button(u("调整"), "ghost", QStringLiteral("settings"), true);
    QObject::connect(edit, &QPushButton::clicked, edit,
                     [] { go(nav::Settings, {{QStringLiteral("section"), QStringLiteral("dims")}}); });
    auto* head = new PanelHead(u("防护维度"), u("— / 6"), edit);
    m_dimsNote = head->note;
    v->addWidget(head);

    auto* grid = new QGridLayout;
    grid->setHorizontalSpacing(8);
    grid->setVerticalSpacing(12);
    int i = 0;
    const auto add = [&](const QString& key, const QString& name) {
        auto* cell = new QWidget;
        auto* cv = new QVBoxLayout(cell);
        cv->setContentsMargins(0, 0, 0, 0);
        cv->setSpacing(4);
        auto* lever = new ToggleSwitch(false);
        lever->setAttribute(Qt::WA_TransparentForMouseEvents);
        lever->setFocusPolicy(Qt::NoFocus);
        lever->setEnabled(false);
        lever->setToolTip(name);
        cv->addWidget(lever, 0, Qt::AlignHCenter);
        auto* lab = ui::label(name, "title");
        lab->setAlignment(Qt::AlignHCenter);
        cv->addWidget(lab, 0, Qt::AlignHCenter);
        Dimension d;
        d.lever = lever;
        m_dims.insert(key, d);
        grid->addWidget(cell, i / 3, i % 3);
        ++i;
    };
    add(QStringLiteral("proc"), u("进程"));
    add(QStringLiteral("file"), u("文件"));
    add(QStringLiteral("reg"), u("注册表"));
    add(QStringLiteral("net"), u("网络"));
    add(QStringLiteral("self"), u("自保"));
    add(QStringLiteral("mem"), u("内存"));
    v->addLayout(grid);
    v->addStretch();
    v->addWidget(ui::label(u("关掉任一维度前会先弹确认"), "muted"));
    return c;
}

void DashboardPage::setDimension(const QString& key, int on)
{
    auto it = m_dims.find(key);
    if (it == m_dims.end())
        return;
    it->on = on;
    if (theme::titan()) {
        auto* cell = static_cast<TitanDimCell*>(it->lever);
        cell->setState(on);
        cell->setToolTip(on == 1 ? u("开启") : (on == 0 ? u("关闭") : u("未知")));
        refreshFace();
        return;
    }
    auto* lever = static_cast<ToggleSwitch*>(it->lever);
    lever->setEnabled(on >= 0);
    lever->setChecked(on == 1);
    lever->setToolTip(on == 1 ? u("开启") : (on == 0 ? u("关闭") : u("未知")));
    refreshFace();
}

QWidget* DashboardPage::buildLog()
{
    auto* box = new QWidget;
    auto* v = new QVBoxLayout(box);
    v->setContentsMargins(0, 0, 0, 0);
    v->setSpacing(6);
    auto* all = ui::button(u("全部事件 ▸"), nullptr, QString(), true);
    QObject::connect(all, &QPushButton::clicked, all, [] { go(nav::Events, {{QStringLiteral("segment"), QStringLiteral("all")}}); });
    v->addWidget(new LogBar(all));
    auto* screen = new ScreenFrame(true);
    screen->setMinimumHeight(170);
    auto* sv = new QVBoxLayout(screen);
    sv->setContentsMargins(16, 10, 18, 14);
    sv->setSpacing(0);
    m_logBox = new QVBoxLayout;
    m_logBox->setSpacing(0);
    sv->addLayout(m_logBox);
    m_logEmpty = screenLabel(u("> 暂无活动 · 事件会在这里实时滚动_"), theme::pal().scrMuted, 9.5, 600, true);
    m_logEmpty->setContentsMargins(4, 10, 0, 10);
    m_logBox->addWidget(m_logEmpty);
    sv->addStretch();
    v->addWidget(screen, 1);
    return box;
}

QWidget* DashboardPage::buildMissions()
{
    auto* c = ui::card();
    auto* v = new QVBoxLayout(c);
    v->setContentsMargins(18, 14, 20, 16);
    v->setSpacing(10);
    auto* head = new PanelHead(theme::mecha() ? u("任务简报") : u("待办便签"), u("等指挥官处理"));
    m_missionCount = head->note;
    v->addWidget(head);
    m_missionBox = new QVBoxLayout;
    m_missionBox->setSpacing(10);
    v->addLayout(m_missionBox);
    v->addStretch();
    m_tally = ui::label(QString(), "caption");
    m_tally->setWordWrap(true);
    v->addWidget(m_tally);
    return c;
}

QWidget* DashboardPage::buildFaceTitan()
{
    const theme::Palette& P = theme::pal();
    auto* face = new TitanFace;
    m_face = face;
    auto* h = new QHBoxLayout(face);
    // 面板本体比控件矮 4px(硬投影),下边距把它让出来。
    h->setContentsMargins(TitanFace::kBotZone + 10, 14, 22, 16);
    h->setSpacing(0);
    auto* col = new QVBoxLayout;
    col->setSpacing(0);
    QFont sf = atPx(titankit::numFont(11, QFont::ExtraBold), 10.5);
    sf.setLetterSpacing(QFont::AbsoluteSpacing, 2.0);
    QFont sfCjk = atPx(sticker::headFont(9.0, QFont::ExtraBold), 10.5);
    sfCjk.setLetterSpacing(QFont::AbsoluteSpacing, 2.0);
    m_faceStatus = new MixedLabel(sf, sfCjk);
    col->addWidget(m_faceStatus);
    face->setHeadline(u("待机"), Qt::white);
    col->addWidget(face->headlineSlot(), 0, Qt::AlignLeft);
    m_faceSub = titanText(QString(), P.scrText2, 12, QFont::Normal);
    m_faceSub->setWordWrap(true);
    m_faceSub->setMaximumHeight(36);
    col->addWidget(m_faceSub);
    col->addSpacing(8);
    auto* segs = new QHBoxLayout;
    segs->setSpacing(7);
    QLabel* serviceText = nullptr;
    segs->addWidget(new SegChip(m_segKernel, m_segKernelText, u("内核驱动")));
    segs->addWidget(new SegChip(m_segService, serviceText, u("后台服务")));
    segs->addWidget(new SegChip(m_segDims, m_segDimsText, u("防护维度")));
    segs->addWidget(new SegChip(m_segTasks, m_segTasksText, u("没有待处理")));
    segs->addStretch();
    col->addLayout(segs);
    col->addStretch();
    auto* quick = new QHBoxLayout;
    quick->setSpacing(8);
    auto* blocks = titankit::button(u("查看拦截记录"), nullptr, QStringLiteral("activity"));
    connect(blocks, &QAbstractButton::clicked, blocks, [] { go(nav::Events, {{QStringLiteral("segment"), QStringLiteral("block")}}); });
    auto* scan = titankit::button(u("扫描自启动项"), nullptr, QStringLiteral("power"));
    connect(scan, &QAbstractButton::clicked, scan, [] { go(nav::Persistence, {{QStringLiteral("scan"), true}}); });
    quick->addWidget(blocks);
    quick->addWidget(scan);
    quick->addStretch();
    col->addLayout(quick);
    h->addLayout(col, 1);
    return face;
}

QWidget* DashboardPage::buildCountersTitan()
{
    const theme::Palette& P = theme::pal();
    titankit::Panel pn = titankit::panel(u("战绩计数"), u("本次运行"), QStringLiteral("COUNTERS"), QColor());
    pn.body->setContentsMargins(16, 0, 14, 8);
    pn.body->setSpacing(0);
    const auto row = [&](const QColor& hue, const QString& name, const QString& caption, SevenSegCounter*& out,
                         std::function<void()> fn) {
        auto* r = new TitanCounterRow(hue);
        r->onClick = std::move(fn);
        auto* h = new QHBoxLayout(r);
        h->setContentsMargins(16, 0, 0, 0);
        h->setSpacing(10);
        auto* col = new QVBoxLayout;
        col->setSpacing(0);
        col->addStretch();
        col->addWidget(titanText(name, P.text, 13, QFont::Bold));
        col->addWidget(titanText(caption, P.textMuted, 11, QFont::Normal));
        col->addStretch();
        h->addLayout(col);
        h->addStretch();
        out = new SevenSegCounter(5, 13, 22);
        out->setColor(hue);
        h->addWidget(out, 0, Qt::AlignVCenter);
        pn.body->addWidget(r);
    };
    row(P.danger, u("本次拦截"), u("仅计真实拦截"), m_statBlocked,
        [] { go(nav::Events, {{QStringLiteral("segment"), QStringLiteral("block")}}); });
    row(P.glow, u("本次事件"), u("本次运行累计"), m_statEvents,
        [] { go(nav::Events, {{QStringLiteral("segment"), QStringLiteral("all")}}); });
    row(P.amber, u("隔离文件"), u("隔离区现存"), m_statQuarantine, [] { go(nav::Quarantine); });
    row(QColor(0x5F, 0x8D, 0xFA), u("防护规则"), u("当前规则数"), m_statRules, [] { go(nav::Rules); });
    pn.body->addStretch();
    return pn.card;
}

QWidget* DashboardPage::buildRadarTitan()
{
    const theme::Palette& P = theme::pal();
    titankit::Panel pn = titankit::panel(u("战况雷达 · 24 小时"), u("连接后台服务后显示"), QString(), QColor());
    m_chartNote = pn.head.note;
    pn.head.trailing->setSpacing(12);
    const auto key = [&](const QColor& color, const QString& text) {
        auto* row = new QHBoxLayout;
        row->setSpacing(5);
        row->addWidget(new LegendDot(color), 0, Qt::AlignVCenter);
        row->addWidget(titanText(text, P.textSecondary, 12, QFont::Normal), 0, Qt::AlignVCenter);
        pn.head.trailing->addLayout(row);
    };
    key(P.glow, u("放行"));
    key(P.warning, u("询问 ▲"));
    key(P.danger, u("拦截 ◎"));
    pn.body->setContentsMargins(16, 0, 14, 13);
    pn.body->setSpacing(0);
    auto* chart = new HourChart;
    chart->onClick = [] { go(nav::Timeline, {{QStringLiteral("range"), QStringLiteral("24h")}}); };
    m_chart = chart;
    pn.body->addWidget(chart, 1);
    return pn.card;
}

QWidget* DashboardPage::buildDimensionsTitan()
{
    const theme::Palette& P = theme::pal();
    titankit::Panel pn = titankit::panel(u("防护维度"), u("— / 6"), QString(), QColor());
    m_dimsNote = pn.head.note;
    auto* edit = titankit::button(u("调整"), "ghost", QStringLiteral("settings"));
    QObject::connect(edit, &QAbstractButton::clicked, edit,
                     [] { go(nav::Settings, {{QStringLiteral("section"), QStringLiteral("dims")}}); });
    pn.head.trailing->addWidget(edit);
    pn.body->setContentsMargins(16, 0, 14, 9);
    pn.body->setSpacing(0);
    auto* grid = new QGridLayout;
    grid->setContentsMargins(0, 0, 0, 0);
    grid->setSpacing(6);
    int i = 0;
    // 图标与「设置 → 防护维度」里同一维度用的保持一致。
    const auto add = [&](const QString& key, const QString& name, const char* icon, const QColor& hue) {
        auto* cell = new TitanDimCell(QString::fromLatin1(icon), name, hue);
        Dimension d;
        d.lever = cell;
        m_dims.insert(key, d);
        grid->addWidget(cell, i / 3, i % 3);
        ++i;
    };
    add(QStringLiteral("proc"), u("进程"), "activity", QColor(0xC6, 0xCF, 0xDA));
    add(QStringLiteral("file"), u("文件"), "file", P.olive);
    add(QStringLiteral("reg"), u("注册表"), "sliders", P.violet);
    add(QStringLiteral("net"), u("网络"), "globe", P.cyan);
    add(QStringLiteral("self"), u("自保"), "shield", P.glow);
    add(QStringLiteral("mem"), u("内存"), "cpu", P.periwinkle);
    pn.body->addLayout(grid);
    pn.body->addSpacing(6);
    auto* foot = new ElidingLabel(u("关掉任一维度前会先弹确认 · 六个维度对应窗口顶边的六盏示廓灯"));
    foot->setFont(titanUi(11, QFont::Normal));
    foot->setStyleSheet(QStringLiteral("color:%1;").arg(P.textMuted.name()));
    pn.body->addWidget(foot);
    pn.body->addStretch();
    return pn.card;
}

QWidget* DashboardPage::buildLogTitan()
{
    const theme::Palette& P = theme::pal();
    // 「今日战报」在这块面板的标题行里(另两套皮肤放在任务简报底下)。
    titankit::Panel pn = titankit::panel(u("作战日志 · 最近活动"), QString(), QString(), QColor());
    m_tally = pn.head.note;
    auto* all = titankit::button(u("全部事件"), "ghost", QString(), QStringLiteral("chevron-right"));
    QObject::connect(all, &QAbstractButton::clicked, all, [] { go(nav::Events, {{QStringLiteral("segment"), QStringLiteral("all")}}); });
    pn.head.trailing->addWidget(all);
    pn.body->setContentsMargins(16, 0, 14, 13);
    pn.body->setSpacing(0);
    auto* screen = new TitanScreen;
    auto* sv = new QVBoxLayout(screen);
    sv->setContentsMargins(10, 5, 10, 5);
    sv->setSpacing(0);
    auto* clip = new TitanLogClip;
    m_logBox = clip->box;
    m_logEmpty = new QLabel(u("> 暂无活动 · 事件会在这里实时滚动_"));
    m_logEmpty->setFont(titanMono(12, QFont::Medium));
    m_logEmpty->setStyleSheet(QStringLiteral("color:%1;").arg(P.scrMuted.name()));
    m_logEmpty->setFixedHeight(20);
    m_logEmpty->setSizePolicy(QSizePolicy::Ignored, QSizePolicy::Fixed);
    m_logBox->addWidget(m_logEmpty);
    sv->addWidget(clip, 1);
    pn.body->addWidget(screen, 1);
    return pn.card;
}

QWidget* DashboardPage::buildMissionsTitan()
{
    titankit::Panel pn = titankit::panel(u("任务简报"), QString(), QString(), QColor());
    m_missionCount = pn.head.note;
    m_missionMarker = pn.head.marker;
    pn.body->setContentsMargins(16, 0, 14, 12);
    pn.body->setSpacing(0);
    m_missionBox = new QVBoxLayout;
    m_missionBox->setSpacing(6);
    pn.body->addLayout(m_missionBox);
    pn.body->addStretch();
    return pn.card;
}

void DashboardPage::refreshMissions()
{
    Inspector::clearLayout(m_missionBox);
    int n = 0;
    const bool titan = theme::titan();
    const bool known = m_connected && m_haveSettings;
    // 金刚:同时有两条任务时只留标题,两张卡才放得进一屏的第三行。
    const bool compact = titan && known && (!m_protectionEnabled || !m_kernelConnected) && m_unenforced > 0;
    const auto add = [this, &n, titan, compact](const QColor& tone, const QString& title, const QString& desc,
                                                const QString& action, std::function<void()> fn) {
        ++n;
        const QString eb = u("MISSION %1 · %2").arg(n, 2, 10, QLatin1Char('0'))
                               .arg(tone == theme::danger() ? u("优先级 紧急") : u("优先级 高"));
        if (titan)
            m_missionBox->addWidget(new TitanMission(tone, eb, title, compact ? QString() : desc, action, std::move(fn)));
        else
            m_missionBox->addWidget(new MissionCard(tone, eb, title, desc, action, std::move(fn)));
    };
    if (known && !m_protectionEnabled)
        add(theme::danger(), u("实时防护已关闭"), u("系统此刻不受本软件保护。"), u("去开启"),
            [] { go(nav::Settings, {{QStringLiteral("section"), QStringLiteral("protection")}}); });
    else if (known && !m_kernelConnected)
        add(theme::warning(), u("内核驱动未连接"),
            u("只有用户态观测与事后处置,缺少动作发生前的阻断。"), u("查看设置"),
            [] { go(nav::Settings, {{QStringLiteral("section"), QStringLiteral("decision")}}); });
    if (m_unenforced > 0)
        add(theme::warning(), u("%1 次拦截没有真正执行").arg(m_unenforced),
            u("判为拦截,但只告警或处置失败 —— 需要确认它们造成了什么影响。"), u("前往处理"),
            [] { go(nav::Events, {{QStringLiteral("segment"), QStringLiteral("missed")}}); });
    if (m_missionCount)
        m_missionCount->setText(n > 0 ? u("等指挥官处理 · %1").arg(n) : (titan && !known) ? QString() : u("全部就绪"));
    if (titan)
        titankit::setMarkerHue(m_missionMarker, n > 0 ? theme::warning() : QColor());
    if (n > 0)
        return;
    // 没有任务:小垒坐着待命。
    auto* idle = new QWidget;
    auto* h = new QHBoxLayout(idle);
    h->setContentsMargins(0, 6, 0, 6);
    h->setSpacing(14);
    robot::Look look;
    look.mood = known ? robot::Mood::Happy : robot::Mood::Sleep;
    look.pose = robot::Pose::Sit;
    look.shadow = false;
    auto* bot = new RobotWidget(76, look);
    bot->setAutoBlink(true);
    bot->setAnimated(true);
    h->addWidget(bot, 0, Qt::AlignVCenter);
    auto* col = new QVBoxLayout;
    col->setSpacing(3);
    col->addWidget(ui::label(known ? u("目前没有需要你处理的事") : u("防护状态未知"), "lead"));
    auto* d = ui::label(known ? u("出现没能真正执行的拦截,或防护被关闭时,会在这里派任务给你。")
                              : u("连接后台服务并读到防护配置后,需要你处理的事会列在这里。"),
                        "secondary");
    d->setWordWrap(true);
    col->addWidget(d);
    h->addLayout(col, 1);
    m_missionBox->addWidget(idle);
}

void DashboardPage::refreshTally()
{
    if (!m_tally)
        return;
    m_tally->setText(u("今日战报 · 击退 %1 · 询问 %2 · 放行 %3").arg(m_blockedCount).arg(m_askCount).arg(m_allowCount));
}
