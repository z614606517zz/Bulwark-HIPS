#include "UiHost.h"
#include "MainWindow.h"
#include "WindowGuard.h"
#include "design/Icons.h"
#include "design/Motion.h"
#include "design/Sticker.h"
#include "design/Theme.h"

#include <QApplication>
#include <QEasingCurve>
#include <QElapsedTimer>
#include <QImage>
#include <QPainter>
#include <QPainterPath>
#include <QPixmap>
#include <QTimer>
#include <QWidget>

namespace {

// 换装转场:旧外观的截图盖在新窗口上面,一条警示斑马带从左往右斜着扫过去,
// 扫过的地方露出新皮肤。斑马带只画在旧窗口的轮廓里(按截图的 alpha 裁)。
class SkinWipe final : public QWidget
{
public:
    SkinWipe(const QPixmap& shot, const QRect& at)
        : QWidget(nullptr, Qt::Tool | Qt::FramelessWindowHint | Qt::WindowStaysOnTopHint
                               | Qt::WindowTransparentForInput | Qt::WindowDoesNotAcceptFocus),
          m_shot(shot), m_mask(shot.toImage().convertToFormat(QImage::Format_ARGB32_Premultiplied))
    {
        setAttribute(Qt::WA_TranslucentBackground);
        setAttribute(Qt::WA_TransparentForMouseEvents);
        setAttribute(Qt::WA_ShowWithoutActivating);
        setAttribute(Qt::WA_DeleteOnClose);
        setFocusPolicy(Qt::NoFocus);
        setGeometry(at);
        show();
    }

    void start()
    {
        // 新窗口第一次排版 / 绘制会卡住事件循环几百毫秒。按墙钟走的动画会因此一下跳到后半程,
        // 所以每帧最多只推进 34ms 的进度:卡顿期间带子停住,之后接着匀速扫完。
        auto* tick = new QTimer(this);
        tick->setInterval(16);
        m_clock.start();
        connect(tick, &QTimer::timeout, this, [this, tick] {
            const qint64 now = m_clock.elapsed();
            m_progress += qreal(qMin<qint64>(now - m_last, 34)) / kWipeMs;
            m_last = now;
            m_t = QEasingCurve(QEasingCurve::InOutCubic).valueForProgress(qMin<qreal>(1.0, m_progress));
            update();
            if (m_progress >= 1.0) {
                tick->stop();
                close();
            }
        });
        raise();
        tick->start();
    }

protected:
    void paintEvent(QPaintEvent*) override
    {
        QPainter p(this);
        p.setRenderHint(QPainter::Antialiasing, true);
        const qreal w = width(), h = height();
        const qreal skew = h * 0.3;
        constexpr qreal kBand = 34.0;
        // e = 斜边在窗口底边处的 x,从「整条带子还在左外侧」走到「右边全露出来」。
        const qreal e = -kBand - skew + m_t * (w + kBand + skew);
        const auto quad = [&](qreal a, qreal b) {
            QPainterPath path;
            path.moveTo(a + skew, 0);
            path.lineTo(b + skew, 0);
            path.lineTo(b, h);
            path.lineTo(a, h);
            path.closeSubpath();
            return path;
        };
        p.save();
        p.setClipPath(quad(e + kBand, w + skew + 2));
        p.drawPixmap(0, 0, m_shot);
        p.restore();

        const QPainterPath band = quad(e, e + kBand);
        const QRectF bb = band.boundingRect().intersected(QRectF(rect()));
        if (bb.isEmpty())
            return;
        const qreal dpr = m_mask.devicePixelRatio();
        const QRect src = QRectF(bb.topLeft() * dpr, bb.size() * dpr).toAlignedRect().intersected(m_mask.rect());
        if (src.isEmpty())
            return;
        QImage layer(src.size(), QImage::Format_ARGB32_Premultiplied);
        layer.setDevicePixelRatio(dpr);
        layer.fill(Qt::transparent);
        {
            QPainter lp(&layer);
            lp.setRenderHint(QPainter::Antialiasing, true);
            lp.translate(-QPointF(src.topLeft()) / dpr);
            lp.setClipPath(band);
            const theme::Palette& P = theme::pal();
            sticker::hazard(lp, band.boundingRect(), P.hazardA, P.hazardB, 14.0, m_t * 120.0);
            lp.setClipping(false);
            lp.setPen(QPen(P.ink, 3.0));
            lp.drawLine(QPointF(e + skew, 0), QPointF(e, h));
            lp.drawLine(QPointF(e + kBand + skew, 0), QPointF(e + kBand, h));
            lp.resetTransform();
            lp.setCompositionMode(QPainter::CompositionMode_DestinationIn);
            lp.drawImage(QPointF(0, 0), m_mask, QRectF(src));
        }
        p.drawImage(QPointF(src.topLeft()) / dpr, layer);
    }

private:
    static constexpr int kWipeMs = 760;

    QPixmap m_shot;
    QImage m_mask;
    QElapsedTimer m_clock;
    qint64 m_last = 0;
    qreal m_progress = 0.0;
    qreal m_t = 0.0;
};

}

UiHost::UiHost(QApplication& app, bool withGuard, QObject* parent)
    : QObject(parent), m_app(app), m_withGuard(withGuard)
{
    connect(theme::SkinHub::instance(), &theme::SkinHub::switchRequested, this, [this](theme::Skin s) {
        if (s == theme::skin())
            return;
        theme::saveSkin(s);
        QTimer::singleShot(0, this, [this, s] { switchSkin(s); });
    });
}

UiHost::~UiHost()
{
    delete m_win.data();
}

void UiHost::start(bool show)
{
    build(show, false);
}

MainWindow* UiHost::window() const { return m_win.data(); }

bulwark::ui::WindowGuard* UiHost::guard() const { return m_guard.data(); }

void UiHost::bringToFront()
{
    if (m_guard)
        m_guard->setExpectedHidden(false);
    if (m_win)
        m_win->showFromTray();
}

void UiHost::build(bool show, bool quiet)
{
    auto* w = new MainWindow(nullptr, quiet);
    if (show)
        w->show();
    m_win = w;
    if (m_withGuard) {
        auto* g = new bulwark::ui::WindowGuard(w, w);
        g->setReportHandler([w](const QString& what, const QString& detail) {
            w->reportSelfProtectionEvent(what, detail);
        });
        connect(w, &MainWindow::windowVisibilityIntentChanged, g, &bulwark::ui::WindowGuard::setExpectedHidden);
        // --tray 是构造 WindowGuard 之前就发生的合法隐藏，必须显式补上初始意图。
        g->setExpectedHidden(!show);
        g->arm();
        w->setQuitAuthorizer([g](const QString& reason) { g->allowQuit(reason); });
        w->setCloseToTrayAuthorizer([g] { return g->consumeCloseToTrayAuthorization(); });
        w->setNativeEventHook([g](const QByteArray& eventType, void* message, qintptr* result) {
            return g->windowNativeEvent(eventType, message, result);
        });
        m_guard = g;
    }
    emit windowCreated(w);
}

// 询问弹窗(嵌套事件循环)、模态框或弹出菜单开着时不能拆窗口:等它们关掉再换。
// 旧窗口连同 IpcClient、托盘图标、通知、悬浮窗与常驻机器人一起销毁,新窗口按同样的路径重新接线;
// IPC 断开到重连只有几百毫秒,落在服务端「界面离线 → 待机」的宽限期内,防护不会因此停下。
void UiHost::switchSkin(theme::Skin s)
{
    if (!m_win)
        return;
    if (!m_win->canRebuild() || QApplication::activePopupWidget()) {
        QTimer::singleShot(600, this, [this, s] { switchSkin(s); });
        return;
    }
    if (s == theme::skin())
        return;
    if (motion::enabled() && m_win->isVisible() && !m_win->isMinimized() && !m_wipe) {
        // 先把旧外观的截图作为浮层盖上去,等它真画到屏幕上再拆旧窗口,中间不会闪出桌面。
        m_wipe = new SkinWipe(m_win->grab(), m_win->geometry());
        QTimer::singleShot(40, this, [this, s] { rebuildFor(s); });
        return;
    }
    rebuildFor(s);
}

void UiHost::rebuildFor(theme::Skin s)
{
    if (!m_win)
        return;
    if (!m_win->canRebuild() || QApplication::activePopupWidget()) {
        // 盖浮层的这几十毫秒里来了询问弹窗:撤掉浮层,稍后整套重来。
        if (m_wipe)
            m_wipe->close();
        QTimer::singleShot(600, this, [this, s] { switchSkin(s); });
        return;
    }
    if (s == theme::skin()) {
        if (m_wipe)
            m_wipe->close();
        return;
    }
    qInfo("[UiHost] 切换界面风格 -> %s,重建主窗口", qUtf8Printable(theme::skinKey(s)));
    const bool visible = m_win->isVisible() && !m_win->isMinimized();
    const QRect geom = m_win->geometry();
    const QString page = m_win->currentPageKey();
    MainWindow* old = m_win.data();
    if (m_guard)
        m_guard->allowQuit(QString::fromUtf8("切换界面风格,重建主窗口"));
    m_win = nullptr;
    m_guard = nullptr;
    old->hide();
    delete old;

    theme::setSkin(s);
    theme::apply(m_app);
    m_app.setWindowIcon(AppIcon::appBadge());

    build(false, true);
    m_win->setGeometry(geom);
    m_win->openPage(page);
    auto* wipe = static_cast<SkinWipe*>(m_wipe.data());
    m_wipe = nullptr;
    if (visible) {
        if (wipe)
            m_win->skipNextIntro();
        m_win->showFromTray();
    } else if (m_guard) {
        m_guard->setExpectedHidden(true);
    }
    if (wipe) {
        if (visible)
            wipe->start();
        else
            wipe->close();
    }
}
