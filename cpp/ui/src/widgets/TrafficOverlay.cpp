#include "widgets/TrafficOverlay.h"

#include "ai/AiScanner.h"
#include "bulwark/models/ProcessEntry.h"
#include "bulwark/models/SecurityEvent.h"
#include "design/Components.h"
#include "design/Icons.h"
#include "design/Motion.h"
#include "design/Sheet.h"
#include "design/Sticker.h"
#include "design/Theme.h"
#include "dialogs/EventFormat.h"
#include "dialogs/ProcessViews.h"
#include "ipc/IpcClient.h"
#include "widgets/FileIconSafe.h"
#include "widgets/TrafficDetailWindow.h"
#include "widgets/WrapLabel.h"
#include "Nav.h"

#include <QAction>
#include <QApplication>
#include <QClipboard>
#include <QContextMenuEvent>
#include <QDateTime>
#include <QDir>
#include <QFileInfo>
#include <QGuiApplication>
#include <QHelpEvent>
#include <QLinearGradient>
#include <QMenu>
#include <QMouseEvent>
#include <QPainter>
#include <QPainterPath>
#include <QPointer>
#include <QProcess>
#include <QPushButton>
#include <QScreen>
#include <QSet>
#include <QSettings>
#include <QTimer>
#include <QToolTip>

#include <QtMath>

#include <algorithm>
#include <cmath>
#include <memory>

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <shlobj.h>

using evtfmt::u;
using bulwark::ipc::NetTrafficRowPayload;
using bulwark::ipc::NetTrafficSnapshotPayload;

namespace {

// 雷达模式:上半是机甲头(两只雷达表眼睛 + 数码读数嘴 + 侧面按钮),下半是深色屏幕列表。
constexpr int kWidth = 360;
constexpr int kCrown = 18;
constexpr int kHeadH = 158;
constexpr int kHeaderH = kCrown + kHeadH;
constexpr int kNeck = 6;
constexpr int kListHead = 26;
constexpr int kRowH = 28;
constexpr int kMaxRows = 8;
constexpr int kNoticeH = 24;
constexpr int kColW = 58;
constexpr int kHistory = 60;
constexpr qint64 kHoldMs = 3000;
constexpr qint64 kActiveWindowMs = 5000;
constexpr qint64 kStaleMs = 3500;
constexpr double kEma = 0.55;

const char* const kKeyEnabled = "ui/trafficOverlay/enabled";
const char* const kKeyCollapsed = "ui/trafficOverlay/collapsed";
const char* const kKeyOnlyActive = "ui/trafficOverlay/onlyActive";
const char* const kKeyPos = "ui/trafficOverlay/pos";

QPointer<TrafficOverlay> g_instance;

struct RateParts {
    QString num;
    QString unit;
};

RateParts splitRate(double bps)
{
    static const char* const units[] = {"B/s", "KB/s", "MB/s", "GB/s"};
    double v = std::max(0.0, bps);
    int i = 0;
    while (v >= 1024.0 && i < 3) {
        v /= 1024.0;
        ++i;
    }
    QString num;
    if (i == 0 || v >= 100.0)
        num = QString::number(qRound(v));
    else if (v >= 10.0)
        num = QString::number(v, 'f', 1);
    else
        num = QString::number(v, 'f', 2);
    return {num, QString::fromLatin1(units[i])};
}

QString rateText(double bps)
{
    const RateParts r = splitRate(bps);
    return r.num + QLatin1Char(' ') + r.unit;
}

QString bytesText(qint64 n)
{
    static const char* const units[] = {"B", "KB", "MB", "GB", "TB"};
    double v = double(std::max<qint64>(0, n));
    int i = 0;
    while (v >= 1024.0 && i < 4) {
        v /= 1024.0;
        ++i;
    }
    return (i == 0 ? QString::number(qRound(v)) : QString::number(v, 'f', v >= 100 ? 0 : 1)) + QLatin1Char(' ')
           + QString::fromLatin1(units[i]);
}

QString bandText(qint64 bps)
{
    if (bps < 1024)
        return u("几乎没有");
    if (bps < 50 * 1024)
        return u("较低");
    if (bps < 1024 * 1024)
        return u("中等");
    if (bps < 10 * 1024 * 1024)
        return u("较高");
    return u("很高");
}

QString ageText(qint64 ms)
{
    const qint64 s = ms / 1000;
    if (s < 90)
        return u("刚刚");
    if (s < 3600)
        return u("%1 分钟前").arg(s / 60);
    if (s < 86400)
        return u("%1 小时前").arg(s / 3600);
    return u("%1 天前").arg(s / 86400);
}

bool locateInExplorer(const QString& path)
{
    const QString native = QDir::toNativeSeparators(path.trimmed());
    if (native.isEmpty() || !QFileInfo::exists(native))
        return false;
    if (PIDLIST_ABSOLUTE pidl = ::ILCreateFromPathW(reinterpret_cast<PCWSTR>(native.utf16()))) {
        const HRESULT hr = ::SHOpenFolderAndSelectItems(pidl, 0, nullptr, 0);
        ::ILFree(pidl);
        if (SUCCEEDED(hr))
            return true;
    }
    return QProcess::startDetached(QStringLiteral("explorer.exe"), {QStringLiteral("/select,"), native});
}

QString trafficSummary(const NetTrafficRowPayload& r, bool perProcessAvailable)
{
    QString s = u("来自桌面流量悬浮窗(用户主动点选,没有任何规则命中);");
    if (perProcessAvailable)
        s += u("当前下行%1、上行%2;").arg(bandText(r.downBps), bandText(r.upBps));
    s += u("已建立的 TCP 连接 %1 个").arg(r.tcpConns);
    if (!r.proxyName.isEmpty())
        s += u(";经本机代理 %1 联网(%2 个连接,真实目的地址只有代理知道)").arg(r.proxyName).arg(r.proxyConns);
    return s;
}

}

bool TrafficOverlay::savedEnabled()
{
    return QSettings().value(QString::fromLatin1(kKeyEnabled), true).toBool();
}

TrafficOverlay* TrafficOverlay::instance() { return g_instance; }

TrafficOverlay::TrafficOverlay(IpcClient* ipc, QWidget* parent)
    : QWidget(parent, Qt::FramelessWindowHint | Qt::Tool | Qt::WindowStaysOnTopHint | Qt::WindowDoesNotAcceptFocus)
    , m_ipc(ipc)
{
    g_instance = this;
    // 与右下角 toast 同一套窗口属性:置顶、无边框、不抢键盘焦点。
    setAttribute(Qt::WA_TranslucentBackground);
    setAttribute(Qt::WA_ShowWithoutActivating);
    setAttribute(Qt::WA_NoSystemBackground);
    setAttribute(Qt::WA_QuitOnClose, false);
    setStyleSheet(QStringLiteral("TrafficOverlay{background:transparent;border:none;}"));
    setMouseTracking(true);
    setFocusPolicy(Qt::NoFocus);
    setAccessibleName(u("桌面实时流量悬浮窗"));
    setWindowTitle(u("实时流量"));
    setWindowOpacity(0.92);

    QSettings s;
    m_enabled = s.value(QString::fromLatin1(kKeyEnabled), true).toBool();
    m_collapsed = s.value(QString::fromLatin1(kKeyCollapsed), false).toBool();
    m_onlyActive = s.value(QString::fromLatin1(kKeyOnlyActive), false).toBool();

    setFixedSize(kWidth, kHeaderH + bodyHeight());
    const QVariant saved = s.value(QString::fromLatin1(kKeyPos));
    bool placed = false;
    if (saved.isValid() && saved.canConvert<QPoint>()) {
        const QPoint p = saved.toPoint();
        for (const QScreen* scr : QGuiApplication::screens()) {
            if (scr->availableGeometry().intersects(QRect(p, size()))) {
                move(p);
                m_userMoved = true;
                placed = true;
                break;
            }
        }
    }
    if (!placed)
        positionDefault();

    m_tick = new QTimer(this);
    m_tick->setInterval(1000);
    connect(m_tick, &QTimer::timeout, this, &TrafficOverlay::onTick);
    m_needleTick = new motion::Ticker(this, [this](qint64) { stepNeedles(); }, 40);

    if (m_ipc) {
        connect(m_ipc, &IpcClient::netTrafficReceived, this, &TrafficOverlay::onSnapshot);
        connect(m_ipc, &IpcClient::connectionChanged, this, [this](bool connected) {
            // 服务端在连接断开时已自动退订;重连后必须重新订阅(订阅是服务端按连接记的)。
            m_subscribed = false;
            m_sentFocus.clear();
            if (!connected) {
                m_rows.clear();
                m_order.clear();
                m_hidden = 0;
                m_gotData = false;
                m_histDown.clear();
                m_histUp.clear();
                m_sysDown = m_sysUp = 0.0;
                applyGeometry();
                kickNeedles();
            }
            syncSubscription();
            update();
        });
        connect(m_ipc, &IpcClient::processActionResult, this, &TrafficOverlay::onProcessActionResult);
        connect(m_ipc, &IpcClient::systemBoostReceived, this, &TrafficOverlay::onSystemBoostResult);
    }
}

TrafficOverlay::~TrafficOverlay()
{
    if (g_instance == this)
        g_instance = nullptr;
    // 详情窗口是独立顶层窗口,不会随本对象析构;它们手里有 IpcClient 指针,必须先关掉。
    const auto details = m_details;
    m_details.clear();
    for (const QPointer<QWidget>& w : details)
        delete w.data();
    if (m_ipc && m_subscribed)
        m_ipc->setNetTrafficSubscribed(false);
}

void TrafficOverlay::applySavedState()
{
    if (m_enabled)
        show();
}

void TrafficOverlay::setOverlayEnabled(bool on)
{
    if (m_enabled == on && isVisible() == on)
        return;
    const bool changed = (m_enabled != on);
    m_enabled = on;
    QSettings().setValue(QString::fromLatin1(kKeyEnabled), on);
    if (on) {
        if (!m_userMoved)
            positionDefault();
        else
            clampToScreen();
        show();
    } else {
        hide();
    }
    syncSubscription();
    if (changed)
        emit overlayEnabledChanged(on);
}

void TrafficOverlay::resetPosition()
{
    m_userMoved = false;
    QSettings().remove(QString::fromLatin1(kKeyPos));
    positionDefault();
}

void TrafficOverlay::showEvent(QShowEvent* e)
{
    QWidget::showEvent(e);
    m_tick->start();
    syncSubscription();
    kickNeedles();
}

void TrafficOverlay::hideEvent(QHideEvent* e)
{
    QWidget::hideEvent(e);
    m_tick->stop();
    m_needleTick->setActive(false);
    syncSubscription();
}

double TrafficOverlay::gaugeTarget(int i) const
{
    if (!m_gotData)
        return 0.0;
    const double kb = std::max(0.0, i == 0 ? m_sysDown : m_sysUp) / 1024.0;
    return std::clamp(std::log10(1.0 + kb) / std::log10(1.0 + 10240.0), 0.0, 1.0);
}

void TrafficOverlay::kickNeedles()
{
    if (!motion::enabled() || !isVisible()) {
        for (int i = 0; i < 2; ++i) {
            m_needle[i] = gaugeTarget(i);
            m_needleV[i] = 0.0;
        }
        return;
    }
    m_needleTick->setActive(true);
}

void TrafficOverlay::stepNeedles()
{
    // 欠阻尼弹簧:指针追到位时会轻轻过冲一下再停住,像真表头。
    constexpr double kStiff = 0.16;
    constexpr double kDamp = 0.30;
    bool settled = true;
    for (int i = 0; i < 2; ++i) {
        const double target = gaugeTarget(i);
        m_needleV[i] += (target - m_needle[i]) * kStiff - m_needleV[i] * kDamp;
        m_needle[i] = std::clamp(m_needle[i] + m_needleV[i], -0.02, 1.02);
        if (std::abs(target - m_needle[i]) > 0.003 || std::abs(m_needleV[i]) > 0.003)
            settled = false;
        else
            m_needle[i] = target, m_needleV[i] = 0.0;
    }
    // 只重画两块表盘(画在头部面板左侧,见 paintEvent 里的 gauge(...))。
    update(QRect(12, kCrown + 22, 196, 100));
    if (settled)
        m_needleTick->setActive(false);
}

void TrafficOverlay::syncSubscription()
{
    QList<int> focus;
    for (auto it = m_details.constBegin(); it != m_details.constEnd(); ++it)
        if (it.value())
            focus << it.key();
    std::sort(focus.begin(), focus.end());
    const bool want = ((m_enabled && isVisible()) || !focus.isEmpty()) && m_ipc && m_ipc->isConnected();
    if (!want)
        focus.clear();
    if (want == m_subscribed && focus == m_sentFocus)
        return;
    m_subscribed = want;
    m_sentFocus = focus;
    if (m_ipc)
        m_ipc->setNetTrafficSubscribed(want, focus);
}

void TrafficOverlay::openDetails(const NetTrafficRowPayload& row)
{
    if (row.pid <= 0)
        return;
    if (QWidget* w = m_details.value(row.pid)) {
        w->showNormal();
        w->raise();
        w->activateWindow();
        return;
    }
    auto* w = new TrafficDetailWindow(m_ipc, row, nullptr);
    w->setAttribute(Qt::WA_DeleteOnClose);
    m_details.insert(row.pid, w);
    const int pid = row.pid;
    connect(w, &QObject::destroyed, this, [this, pid] {
        m_details.remove(pid);
        syncSubscription();
    });
    w->show();
    syncSubscription();
}

bool TrafficOverlay::locateFile(const QString& path) { return locateInExplorer(path); }

void TrafficOverlay::positionDefault()
{
    const QScreen* scr = QGuiApplication::primaryScreen();
    if (!scr)
        return;
    const QRect a = scr->availableGeometry();
    move(a.right() + 1 - width() - 14, a.top() + 14);
}

void TrafficOverlay::clampToScreen()
{
    const QScreen* scr = QGuiApplication::screenAt(frameGeometry().center());
    if (!scr) {
        positionDefault();
        m_userMoved = false;
        return;
    }
    const QRect a = scr->availableGeometry();
    QRect g = frameGeometry();
    if (g.right() > a.right()) g.moveRight(a.right());
    if (g.bottom() > a.bottom()) g.moveBottom(a.bottom());
    if (g.left() < a.left()) g.moveLeft(a.left());
    if (g.top() < a.top()) g.moveTop(a.top());
    move(g.topLeft());
}

const TrafficOverlay::RowView* TrafficOverlay::viewOf(int pid) const
{
    const auto it = m_rows.constFind(pid);
    return it == m_rows.constEnd() ? nullptr : &it.value();
}

void TrafficOverlay::onSnapshot(const NetTrafficSnapshotPayload& snap)
{
    const qint64 now = QDateTime::currentMSecsSinceEpoch();
    m_snap = snap;
    m_lastSnapMs = now;
    m_gotData = true;

    m_sysDown = m_histDown.size() > 0 ? m_sysDown * (1 - kEma) + double(snap.totalDownBps) * kEma
                                      : double(snap.totalDownBps);
    m_sysUp = m_histUp.size() > 0 ? m_sysUp * (1 - kEma) + double(snap.totalUpBps) * kEma
                                  : double(snap.totalUpBps);
    m_histDown.append(double(snap.totalDownBps));
    m_histUp.append(double(snap.totalUpBps));
    while (m_histDown.size() > kHistory) m_histDown.removeFirst();
    while (m_histUp.size() > kHistory) m_histUp.removeFirst();
    kickNeedles();

    QSet<int> present;
    for (const NetTrafficRowPayload& r : snap.rows) {
        present.insert(r.pid);
        RowView& v = m_rows[r.pid];
        const bool fresh = (v.lastSeenMs == 0);
        v.r = r;
        v.down = fresh ? double(r.downBps) : v.down * (1 - kEma) + double(r.downBps) * kEma;
        v.up = fresh ? double(r.upBps) : v.up * (1 - kEma) + double(r.upBps) * kEma;
        v.pdown = fresh ? double(r.proxyDownBps) : v.pdown * (1 - kEma) + double(r.proxyDownBps) * kEma;
        v.pup = fresh ? double(r.proxyUpBps) : v.pup * (1 - kEma) + double(r.proxyUpBps) * kEma;
        v.lastSeenMs = now;
        if (r.upBps + r.downBps + r.proxyUpBps + r.proxyDownBps > 0)
            v.lastActiveMs = now;
    }
    for (auto it = m_rows.begin(); it != m_rows.end();) {
        if (present.contains(it.key())) {
            ++it;
            continue;
        }
        if (now - it->lastSeenMs > kHoldMs) {
            it = m_rows.erase(it);
        } else {
            it->down *= 0.5;
            it->up *= 0.5;
            it->pdown *= 0.5;
            it->pup *= 0.5;
            ++it;
        }
    }
    rebuildOrder();
    applyGeometry();
    update();
}

void TrafficOverlay::rebuildOrder()
{
    const qint64 now = QDateTime::currentMSecsSinceEpoch();
    QVector<const RowView*> list;
    list.reserve(m_rows.size());
    for (auto it = m_rows.constBegin(); it != m_rows.constEnd(); ++it) {
        const RowView& v = it.value();
        if (m_onlyActive && now - v.lastActiveMs > kActiveWindowMs)
            continue;
        list.append(&v);
    }
    const auto rateOf = [](const RowView* v) { return v->down + v->up + v->pdown + v->pup; };

    std::sort(list.begin(), list.end(), [&](const RowView* a, const RowView* b) {
        const double ra = rateOf(a), rb = rateOf(b);
        if (ra != rb)
            return ra > rb;
        if (a->r.tcpConns != b->r.tcpConns)
            return a->r.tcpConns > b->r.tcpConns;
        const int c = QString::compare(a->r.name, b->r.name, Qt::CaseInsensitive);
        return c != 0 ? c < 0 : a->r.pid < b->r.pid;
    });

    QHash<int, int> prevPos;
    for (int i = 0; i < m_order.size(); ++i)
        prevPos.insert(m_order[i], i);
    const auto posOf = [&](const RowView* v) { return prevPos.value(v->r.pid, 1 << 20); };
    for (int pass = 0; pass < list.size(); ++pass) {
        bool moved = false;
        for (int i = 0; i + 1 < list.size(); ++i) {
            if (posOf(list[i + 1]) < posOf(list[i]) && rateOf(list[i]) <= rateOf(list[i + 1]) * 1.15 + 2048.0) {
                std::swap(list[i], list[i + 1]);
                moved = true;
            }
        }
        if (!moved)
            break;
    }
    m_hidden = std::max(0, int(list.size()) - kMaxRows);
    m_order.clear();
    for (int i = 0; i < list.size() && i < kMaxRows; ++i)
        m_order.append(list[i]->r.pid);
}

void TrafficOverlay::onTick()
{
    const qint64 now = QDateTime::currentMSecsSinceEpoch();
    bool changed = false;
    if (m_ipc && m_ipc->isConnected() && m_subscribed && m_lastSnapMs > 0 && now - m_lastSnapMs > kStaleMs) {
        for (auto it = m_rows.begin(); it != m_rows.end();) {
            if (now - it->lastSeenMs > kHoldMs) {
                it = m_rows.erase(it);
                changed = true;
            } else {
                ++it;
            }
        }
    }
    if (m_onlyActive)
        changed = true;
    if (changed) {
        rebuildOrder();
        applyGeometry();
    }
    update();
}

int TrafficOverlay::bodyHeight() const
{
    if (m_collapsed)
        return 6;
    const bool notice = m_gotData && !m_snap.perProcessAvailable && !m_snap.message.isEmpty();
    const int rows = std::max<int>(1, int(m_order.size()));
    return kNeck + kListHead + (notice ? kNoticeH : 0) + rows * kRowH + (m_hidden > 0 ? 24 : 6) + 18;
}

void TrafficOverlay::applyGeometry()
{
    const int h = kHeaderH + bodyHeight();
    if (h == height() && width() == kWidth)
        return;
    setFixedSize(kWidth, h);
    if (!m_userMoved)
        positionDefault();
    else if (isVisible())
        clampToScreen();
}

// 机甲头右侧竖排的三颗六角按钮:加速 / 收起 / 关闭。
QRect TrafficOverlay::headerRect() const { return QRect(0, 0, width(), kHeaderH); }
QRect TrafficOverlay::boostRect() const { return QRect(width() - 52, kCrown + 16, 32, 28); }
QRect TrafficOverlay::chevronRect() const { return QRect(width() - 52, kCrown + 50, 32, 28); }
QRect TrafficOverlay::closeRect() const { return QRect(width() - 52, kCrown + 84, 32, 28); }

QRect TrafficOverlay::rowRect(int index) const
{
    const bool notice = m_gotData && !m_snap.perProcessAvailable && !m_snap.message.isEmpty();
    return QRect(20, kHeaderH + kNeck + kListHead + (notice ? kNoticeH : 0) + index * kRowH, width() - 46, kRowH);
}

int TrafficOverlay::rowAt(const QPoint& pos) const
{
    if (m_collapsed)
        return -1;
    for (int i = 0; i < m_order.size(); ++i)
        if (rowRect(i).contains(pos))
            return i;
    return -1;
}

TrafficOverlay::Hit TrafficOverlay::buttonAt(const QPoint& pos) const
{
    if (closeRect().contains(pos))
        return Hit::Close;
    if (chevronRect().contains(pos))
        return Hit::Chevron;
    if (boostRect().contains(pos))
        return Hit::Boost;
    return Hit::None;
}

QIcon TrafficOverlay::iconFor(const QString& path)
{
    const auto it = m_icons.constFind(path);
    if (it != m_icons.constEnd())
        return it.value();
    QIcon ic;
    if (!path.isEmpty() && QFileInfo::exists(path))
        ic = fileicon::iconForPath(path, 16, devicePixelRatioF());
    if (ic.isNull())
        ic = AppIcon::icon(QStringLiteral("activity"), theme::textMuted(), 16);
    if (m_icons.size() > 256)
        m_icons.clear();
    m_icons.insert(path, ic);
    return ic;
}

void TrafficOverlay::paintEvent(QPaintEvent*)
{
    QPainter p(this);
    p.setRenderHint(QPainter::Antialiasing, true);
    p.setRenderHint(QPainter::TextAntialiasing, true);

    const theme::Palette& P = theme::pal();
    const bool k = !theme::mecha();
    const QColor ink = P.ink;
    const QColor downC = P.glow;
    const QColor upC = k ? QColor(0xFF, 0xB8, 0xCB) : theme::titan() ? P.pink : QColor(0xFF, 0x6A, 0x13);
    const QColor redC = k ? QColor(0xFF, 0x9C, 0x9C) : QColor(0xFF, 0x4A, 0x4A);
    const Qt::PenJoinStyle join = k ? Qt::RoundJoin : Qt::MiterJoin;

    const bool connected = m_ipc && m_ipc->isConnected();
    const qint64 now = QDateTime::currentMSecsSinceEpoch();
    const bool stale = connected && m_subscribed && m_lastSnapMs > 0 && now - m_lastSnapMs > kStaleMs;
    const bool boosting = !m_boostReq.isNull();
    const QColor gem = !connected ? redC : (!m_gotData || stale) ? QColor(0xFF, 0xD8, 0x4A) : downC;

    QFont base = QApplication::font();
    base.setPixelSize(12);

    // 头顶:城垛 + V 字天线 / 小旗
    const QRectF head(4, kCrown, width() - 10, kHeadH - 4);
    {
        const qreal y0 = head.top();
        const qreal cx = head.center().x() - 22;
        for (const qreal bx : {head.left() + 26, head.left() + 70, head.right() - 150, head.right() - 106}) {
            QPainterPath cr;
            if (k)
                cr.addRoundedRect(QRectF(bx, y0 - 13, 30, 22), 9, 9);
            else {
                cr.moveTo(bx, y0 + 6); cr.lineTo(bx, y0 - 9); cr.lineTo(bx + 4, y0 - 13);
                cr.lineTo(bx + 26, y0 - 13); cr.lineTo(bx + 30, y0 - 9); cr.lineTo(bx + 30, y0 + 6);
                cr.closeSubpath();
            }
            p.fillPath(cr, P.structure);
            p.strokePath(cr, QPen(ink, 2.4, Qt::SolidLine, Qt::FlatCap, join));
        }
        if (k) {
            p.setPen(QPen(ink, 3, Qt::SolidLine, Qt::RoundCap));
            p.drawLine(QPointF(cx, y0 + 2), QPointF(cx, y0 - 16));
            QPainterPath flag;
            flag.moveTo(cx + 1, y0 - 16);
            flag.quadTo(cx + 14, y0 - 13, cx + 24, y0 - 9);
            flag.quadTo(cx + 14, y0 - 5, cx + 1, y0 - 3);
            flag.closeSubpath();
            p.fillPath(flag, gem);
            p.strokePath(flag, QPen(ink, 2.0, Qt::SolidLine, Qt::RoundCap, Qt::RoundJoin));
        } else {
            for (const qreal sgn : {-1.0, 1.0}) {
                QPainterPath fin;
                fin.moveTo(cx - sgn * 3, y0 + 2);
                fin.lineTo(cx - sgn * 34, y0 - 16);
                fin.lineTo(cx - sgn * 27, y0 - 18);
                fin.lineTo(cx + sgn * 5, y0 - 5);
                fin.closeSubpath();
                p.fillPath(fin, P.fin);
                p.strokePath(fin, QPen(ink, 2.2, Qt::SolidLine, Qt::RoundCap, Qt::RoundJoin));
            }
        }
    }
    // 头部面板上的状态字用的是次要文字色:机甲是浅色装甲,金刚得用暗面板才读得出来。
    const QRectF headBody = sticker::panel(p, head, k ? P.shell : theme::titan() ? P.raised : QColor(0xEF, 0xED, 0xE8),
                                           14.0, true);
    if (!k) {
        QPainterPath gemP;
        gemP.addPolygon(sticker::hexagon(QPointF(headBody.center().x() - 22, headBody.top() + 1), 8));
        gemP.closeSubpath();
        p.fillPath(gemP, gem);
        p.strokePath(gemP, QPen(ink, 2.0, Qt::SolidLine, Qt::FlatCap, Qt::MiterJoin));
    }

    // 状态行
    {
        sticker::lamp(p, QRectF(headBody.left() + 14, headBody.top() + 11, 12, 9), gem);
        QFont cap = base;
        cap.setPixelSize(11);
        cap.setWeight(QFont::Bold);
        p.setFont(cap);
        p.setPen(P.textSecondary);
        p.drawText(QRectF(headBody.left() + 32, headBody.top() + 6, boostRect().left() - headBody.left() - 40, 20),
                   Qt::AlignVCenter | Qt::AlignLeft,
                   boosting      ? u("雷达 · 正在加速…")
                   : !connected  ? u("雷达 · 未连接后台服务")
                   : !m_gotData  ? u("雷达 · 等待数据…")
                   : stale       ? u("雷达 · 数据中断")
                                 : u("雷达 · 实时流量"));
    }

    // 两只眼睛 = 两块雷达表:左下行,右上行。刻度按对数排到 10 MB/s,末段是红区。
    const auto gauge = [&](const QRectF& r, int which, const QColor& c, const QString& label) {
        const QPointF ctr = r.center();
        const qreal R = r.width() / 2.0;
        p.setPen(QPen(ink, 3.0));
        p.setBrush(P.screen);
        p.drawEllipse(ctr, R - 1.5, R - 1.5);
        p.setPen(QPen(P.screen2, 2.0));
        p.setBrush(Qt::NoBrush);
        p.drawEllipse(ctr, R - 6, R - 6);
        const bool live = m_gotData;
        const double t = motion::enabled() ? m_needle[which] : gaugeTarget(which);
        const auto ang = [](double tt) { return (-125.0 + tt * 250.0) * M_PI / 180.0; };
        for (int i = 0; i < 25; ++i) {
            const double tt = i / 24.0;
            const bool lit = live && tt <= t + 1e-6;
            const double a = ang(tt);
            QColor col = i >= 21 ? redC : c;
            col.setAlphaF(lit ? 1.0 : 0.22);
            p.setPen(QPen(col, 3.0, Qt::SolidLine, Qt::RoundCap));
            p.drawLine(QPointF(ctr.x() + (R - 16) * std::sin(a), ctr.y() - (R - 16) * std::cos(a)),
                       QPointF(ctr.x() + (R - 9) * std::sin(a), ctr.y() - (R - 9) * std::cos(a)));
        }
        QFont tick = base;
        tick.setPixelSize(8);
        tick.setWeight(QFont::Bold);
        p.setFont(tick);
        p.setPen(P.scrMuted);
        const char* marks[] = {"0", "1M", "10M"};
        const double at[] = {0.0, 0.75, 1.0};
        for (int i = 0; i < 3; ++i) {
            const double a = ang(at[i]);
            const QPointF q(ctr.x() + (R - 25) * std::sin(a), ctr.y() - (R - 25) * std::cos(a));
            p.drawText(QRectF(q.x() - 12, q.y() - 6, 24, 12), Qt::AlignCenter, QString::fromLatin1(marks[i]));
        }
        const double a = ang(t);
        const QPointF tip(ctr.x() + (R - 19) * std::sin(a), ctr.y() - (R - 19) * std::cos(a));
        p.setPen(QPen(live ? QColor(0xFF, 0xFF, 0xFF) : P.scrMuted, 2.6, Qt::SolidLine, Qt::RoundCap));
        p.drawLine(ctr, tip);
        p.setPen(Qt::NoPen);
        p.setBrush(c);
        p.drawEllipse(tip, 2.6, 2.6);
        QPainterPath pivot;
        pivot.addPolygon(sticker::hexagon(ctr, 6.5));
        pivot.closeSubpath();
        p.fillPath(pivot, live ? P.fin : P.scrMuted);
        p.strokePath(pivot, QPen(ink, 2.0, Qt::SolidLine, Qt::FlatCap, Qt::MiterJoin));
        QFont lf = base;
        lf.setPixelSize(10);
        lf.setWeight(QFont::Bold);
        p.setFont(lf);
        p.setPen(P.scrText2);
        p.drawText(QRectF(ctr.x() - 24, ctr.y() + R * 0.42, 48, 14), Qt::AlignCenter, label);
    };
    const qreal dial = 88.0;
    gauge(QRectF(headBody.left() + 12, headBody.top() + 27, dial, dial), 0, downC, u("下行"));
    gauge(QRectF(headBody.left() + 106, headBody.top() + 27, dial, dial), 1, upC, u("上行"));

    // 示波器:最近 60 秒的上下行曲线
    {
        const QRectF scope(headBody.left() + 202, headBody.top() + 31, 82, 80);
        const QPainterPath sp = theme::panelPath(scope, k ? 10.0 : 5.0);
        p.fillPath(sp, P.screen);
        p.strokePath(sp, QPen(ink, 2.0, Qt::SolidLine, Qt::FlatCap, join));
        const QRectF plot = scope.adjusted(6, 8, -6, -8);
        p.save();
        p.setClipRect(plot);
        p.setPen(QPen(theme::tint(downC, 0.10), 1.0));
        for (qreal y = plot.top(); y <= plot.bottom(); y += plot.height() / 4)
            p.drawLine(QPointF(plot.left(), y), QPointF(plot.right(), y));
        double scale = 128.0 * 1024.0;
        for (double v : m_histDown) scale = std::max(scale, v);
        for (double v : m_histUp) scale = std::max(scale, v);
        const auto series = [&](const QVector<double>& hist, const QColor& c) {
            const int n = int(hist.size());
            if (n < 2)
                return;
            QPolygonF line;
            const double step = plot.width() / double(kHistory - 1);
            const double off = double(kHistory - n);
            for (int i = 0; i < n; ++i)
                line << QPointF(plot.left() + (off + i) * step,
                                plot.bottom() - plot.height() * std::min(1.0, hist[i] / scale));
            p.setPen(QPen(c, 1.8, Qt::SolidLine, Qt::RoundCap, Qt::RoundJoin));
            p.setBrush(Qt::NoBrush);
            p.drawPolyline(line);
        };
        series(m_histUp, upC);
        series(m_histDown, downC);
        p.restore();
    }

    // 嘴 = 数码读数条
    {
        const QRectF lcd(headBody.left() + 12, headBody.top() + 120, 272, 22);
        const QPainterPath lp = theme::panelPath(lcd, k ? 10.0 : 5.0);
        p.fillPath(lp, P.screen);
        p.strokePath(lp, QPen(ink, 2.0, Qt::SolidLine, Qt::FlatCap, join));
        QFont nf = base;
        nf.setFamilies({QStringLiteral("Bahnschrift"), QStringLiteral("Segoe UI")});
        nf.setPixelSize(13);
        nf.setWeight(QFont::Bold);
        p.setFont(nf);
        const RateParts d = splitRate(m_gotData ? m_sysDown : 0.0);
        const RateParts up = splitRate(m_gotData ? m_sysUp : 0.0);
        p.setPen(downC);
        p.drawText(lcd.adjusted(8, 0, -lcd.width() / 2, 0), Qt::AlignVCenter | Qt::AlignLeft,
                   m_gotData ? u("↓ %1 %2").arg(d.num, d.unit) : u("↓ —"));
        p.setPen(upC);
        p.drawText(lcd.adjusted(lcd.width() / 2, 0, -8, 0), Qt::AlignVCenter | Qt::AlignRight,
                   m_gotData ? u("↑ %1 %2").arg(up.num, up.unit) : u("↑ —"));
    }

    // 右侧三颗按钮
    const auto button = [&](const QRect& r, const char* icon, Hit which, const QColor& fill, bool disabled) {
        const QRectF b = QRectF(r).adjusted(1.5, 1.5, -1.5, -1.5);
        QPainterPath path;
        if (k) {
            const qreal dd = qMin(b.width(), b.height());
            path.addEllipse(QRectF(b.center().x() - dd / 2, b.center().y() - dd / 2, dd, dd));
        } else {
            QPolygonF poly;
            poly << QPointF(b.left() + b.width() * 0.25, b.top()) << QPointF(b.left() + b.width() * 0.75, b.top())
                 << QPointF(b.right(), b.center().y()) << QPointF(b.left() + b.width() * 0.75, b.bottom())
                 << QPointF(b.left() + b.width() * 0.25, b.bottom()) << QPointF(b.left(), b.center().y());
            path.addPolygon(poly);
            path.closeSubpath();
        }
        QColor f = disabled ? QColor(0xA9, 0xA6, 0x9F) : fill;
        if (m_hoverBtn == which && !disabled)
            f = f.lighter(112);
        p.fillPath(path, f);
        p.strokePath(path, QPen(ink, 2.0, Qt::SolidLine, Qt::FlatCap, join));
        sticker::icon(p, QString::fromLatin1(icon), QRectF(b.center().x() - 8, b.center().y() - 8, 16, 16), 2.8);
    };
    button(boostRect(), "boost", Hit::Boost, k ? QColor(0xFF, 0xD9, 0x6B) : QColor(0xFF, 0xCF, 0x33),
           boosting || !connected);
    button(chevronRect(), m_collapsed ? "down" : "up", Hit::Chevron, k ? QColor(0x7F, 0xE3, 0xC6) : QColor(0xD4, 0xD1, 0xCA),
           false);
    button(closeRect(), "x", Hit::Close, k ? QColor(0xFF, 0x8E, 0x8E) : QColor(0xE5, 0x38, 0x3B), false);

    if (m_collapsed)
        return;

    // 身体:深色屏幕上的联网程序列表
    const QRectF torso(12, kHeaderH + kNeck - 4, width() - 26, height() - kHeaderH - kNeck + 2);
    const QRectF screen = sticker::panel(p, torso, P.screen, 12.0, true);
    {
        p.save();
        p.setClipPath(theme::panelPath(screen, 12.0));
        p.setRenderHint(QPainter::Antialiasing, false);
        p.setPen(QPen(theme::tint(downC, 0.06), 1.0));
        for (int x = int(screen.left()) + 18; x < screen.right(); x += 18)
            p.drawLine(x, int(screen.top()), x, int(screen.bottom()));
        for (int y = int(screen.top()) + 18; y < screen.bottom(); y += 18)
            p.drawLine(int(screen.left()), y, int(screen.right()), y);
        p.restore();
    }
    {
        QFont hf = base;
        hf.setPixelSize(10);
        hf.setWeight(QFont::Bold);
        p.setFont(hf);
        p.setPen(P.scrMuted);
        const qreal hy = kHeaderH + kNeck + 2;
        p.drawText(QRectF(screen.left() + 12, hy, 160, 16), Qt::AlignVCenter | Qt::AlignLeft,
                   m_onlyActive ? u("目标列表 · 只看有流量的") : u("目标列表 · 按速率"));
        const int right = rowRect(0).right() - 8;
        p.drawText(QRectF(right - kColW, hy, kColW, 16), Qt::AlignVCenter | Qt::AlignRight, u("上行"));
        p.drawText(QRectF(right - 2 * kColW - 4, hy, kColW, 16), Qt::AlignVCenter | Qt::AlignRight, u("下行"));
        p.setPen(QPen(theme::tint(downC, 0.45), 1.5, Qt::DashLine));
        p.drawLine(QPointF(screen.left() + 10, hy + 18), QPointF(screen.right() - 10, hy + 18));
    }

    const bool notice = m_gotData && !m_snap.perProcessAvailable && !m_snap.message.isEmpty();
    if (notice) {
        QFont f = base;
        f.setPixelSize(11);
        p.setFont(f);
        p.setPen(QColor(0xFF, 0xD8, 0x4A));
        const QRect nr(rowRect(0).left(), kHeaderH + kNeck + kListHead, rowRect(0).width(), kNoticeH - 4);
        p.drawText(nr, Qt::AlignVCenter | Qt::AlignLeft,
                   QFontMetrics(f).elidedText(m_snap.message, Qt::ElideRight, nr.width()));
    }

    p.setFont(base);
    if (m_order.isEmpty()) {
        const QRect r = rowRect(0);
        p.setPen(P.scrMuted);
        p.drawText(r, Qt::AlignCenter,
                   !connected ? u("> 未连接后台服务_") : (!m_gotData ? u("> 正在等待服务端数据…")
                                                                    : (m_onlyActive ? u("> 当前没有产生流量的程序") : u("> 暂无联网程序"))));
        return;
    }
    double peak = 1.0;
    for (int pid : std::as_const(m_order))
        if (const RowView* v = viewOf(pid))
            peak = std::max(peak, v->down + v->up);
    QFont bold = base;
    bold.setWeight(QFont::Bold);
    const QFontMetrics fm(bold);
    for (int i = 0; i < m_order.size(); ++i) {
        const RowView* v = viewOf(m_order[i]);
        if (!v)
            continue;
        const QRect rr = rowRect(i);
        const bool hover = (i == m_hoverRow);
        const bool selected = (v->r.pid == m_selectedPid);
        if (selected) {
            const QPainterPath sp = theme::panelPath(QRectF(rr).adjusted(-4, 1, 4, -1), k ? 8.0 : 4.0);
            p.fillPath(sp, k ? QColor(0x6B, 0x5B, 0x8E) : QColor(0x3A, 0x39, 0x36));
            p.strokePath(sp, QPen(downC, 1.6, Qt::SolidLine, Qt::FlatCap, join));
        } else if (hover) {
            p.setPen(Qt::NoPen);
            p.setBrush(QColor(255, 255, 255, 18));
            p.drawRoundedRect(QRectF(rr).adjusted(-4, 1, 4, -1), 5, 5);
        }
        iconFor(v->r.path).paint(&p, QRect(rr.left() + 2, rr.top() + (kRowH - 16) / 2, 16, 16));

        const QRect upCol(rr.right() - 8 - kColW, rr.top(), kColW, kRowH);
        const QRect downCol(upCol.left() - 4 - kColW, rr.top(), kColW, kRowH);
        const bool viaProxy = !v->r.proxyName.isEmpty();
        const bool ownTraffic = v->r.upBps + v->r.downBps > 0 || v->down >= 1.0 || v->up >= 1.0;
        const bool proxyTraffic = v->r.proxyUpBps + v->r.proxyDownBps > 0 || v->pdown >= 1.0 || v->pup >= 1.0;
        const bool idle = !ownTraffic && !proxyTraffic;
        const bool showProxyRates = !ownTraffic && proxyTraffic;
        QFont num = base;
        num.setFamilies({QStringLiteral("Bahnschrift"), QStringLiteral("Segoe UI")});
        num.setPixelSize(11);
        num.setWeight(QFont::Bold);
        QString single;
        const int conns = v->r.tcpConns + v->r.proxyConns;
        if (!m_snap.perProcessAvailable)
            single = u("%1 连接").arg(conns);   // 没有逐进程速率:只显示连接数,绝不画一排看起来像「没有流量」的零
        else if (idle)
            single = conns > 0 ? u("空闲 · %1 连接").arg(conns) : u("空闲");
        const int rightEdge = rr.right() - 8;
        const int rightW = single.isEmpty() ? (rightEdge - downCol.left()) : QFontMetrics(num).horizontalAdvance(single) + 2;
        // 速率条:十格,按本列表里的最大值归一
        const int barW = single.isEmpty() ? 52 : 0;
        const int nameLeft = rr.left() + 24;
        const int nameRight = rightEdge - rightW - 8 - (barW > 0 ? barW + 6 : 0);
        QFont chipFont = base;
        chipFont.setPixelSize(10);
        const QString chipText = u("经代理");
        const int chipW = viaProxy ? QFontMetrics(chipFont).horizontalAdvance(chipText) + 10 : 0;
        const int nameW = std::max(20, nameRight - nameLeft - (viaProxy ? chipW + 6 : 0));
        p.setFont(bold);
        p.setPen(v->r.protectedSelf || v->r.critical ? P.scrText2 : P.scrText);
        const QString shownName = fm.elidedText(v->r.name, Qt::ElideMiddle, nameW);
        p.drawText(QRect(nameLeft, rr.top(), nameW, kRowH), Qt::AlignVCenter | Qt::AlignLeft, shownName);
        if (viaProxy) {
            const QRectF chip(nameLeft + fm.horizontalAdvance(shownName) + 6, rr.top() + (kRowH - 16) / 2.0, chipW, 16);
            p.setPen(QPen(P.scrText2, 1.2));
            p.setBrush(Qt::NoBrush);
            p.drawRoundedRect(chip, 3, 3);
            p.setFont(chipFont);
            p.setPen(P.scrText2);
            p.drawText(chip, Qt::AlignCenter, chipText);
        }
        if (barW > 0) {
            const double frac = std::clamp((v->down + v->up) / peak, 0.0, 1.0);
            const int cells = 8;
            const int lit = int(std::ceil(frac * cells - 1e-6));
            const qreal cw = (barW - (cells - 1) * 2.0) / cells;
            const qreal bx = rightEdge - rightW - 6 - barW;
            for (int c = 0; c < cells; ++c) {
                const QRectF cell(bx + c * (cw + 2.0), rr.center().y() - 4, cw, 8);
                QPainterPath cp;
                cp.moveTo(cell.left() + 2, cell.top());
                cp.lineTo(cell.right(), cell.top());
                cp.lineTo(cell.right() - 2, cell.bottom());
                cp.lineTo(cell.left(), cell.bottom());
                cp.closeSubpath();
                p.fillPath(cp, c < lit ? downC : theme::tint(downC, 0.16));
            }
        }

        p.setFont(num);
        if (!single.isEmpty()) {
            p.setPen(P.scrMuted);
            p.drawText(QRect(rightEdge - rightW, rr.top(), rightW, kRowH), Qt::AlignVCenter | Qt::AlignRight, single);
        } else if (showProxyRates) {
            p.setPen(v->pdown >= 1.0 ? P.scrText2 : P.scrMuted);
            p.drawText(downCol, Qt::AlignVCenter | Qt::AlignRight, v->pdown >= 1.0 ? rateText(v->pdown) : QStringLiteral("—"));
            p.setPen(v->pup >= 1.0 ? P.scrText2 : P.scrMuted);
            p.drawText(upCol, Qt::AlignVCenter | Qt::AlignRight, v->pup >= 1.0 ? rateText(v->pup) : QStringLiteral("—"));
        } else {
            p.setPen(v->down >= 1.0 ? downC : P.scrMuted);
            p.drawText(downCol, Qt::AlignVCenter | Qt::AlignRight, v->down >= 1.0 ? rateText(v->down) : QStringLiteral("—"));
            p.setPen(v->up >= 1.0 ? upC : P.scrMuted);
            p.drawText(upCol, Qt::AlignVCenter | Qt::AlignRight, v->up >= 1.0 ? rateText(v->up) : QStringLiteral("—"));
        }
    }
    if (m_hidden > 0) {
        QFont f = base;
        f.setPixelSize(11);
        p.setFont(f);
        p.setPen(P.scrMuted);
        const QRect last = rowRect(int(m_order.size()) - 1);
        p.drawText(QRect(int(screen.left()) + 8, last.bottom() + 2, int(screen.width()) - 16, 18),
                   Qt::AlignVCenter | Qt::AlignHCenter,
                   u("还有 %1 个联网程序未显示 · 右键可只看有流量的").arg(m_hidden));
    }
}

QString TrafficOverlay::rowTip(const RowView& v) const
{
    QStringList lines;
    lines << u("%1  (PID %2)").arg(v.r.name).arg(v.r.pid);
    if (!v.r.path.isEmpty())
        lines << QDir::toNativeSeparators(v.r.path);
    if (m_snap.perProcessAvailable)
        lines << u("↓ %1   ↑ %2").arg(rateText(v.r.downBps), rateText(v.r.upBps));
    if (m_snap.perProcessAvailable)
        lines << u("自开始监控累计:↓ %1   ↑ %2").arg(bytesText(v.r.downTotal), bytesText(v.r.upTotal));
    lines << u("已建立的 TCP 连接:%1 个").arg(v.r.tcpConns);
    if (!v.r.proxyName.isEmpty()) {
        lines << u("经本机代理 %1 联网:%2 个连接").arg(v.r.proxyName).arg(v.r.proxyConns);
        if (m_snap.perProcessAvailable)
            lines << u("  与代理之间 ↓ %1   ↑ %2(走本机环回,不计入出网;真实出网记在 %3 那一行)")
                         .arg(rateText(v.r.proxyDownBps), rateText(v.r.proxyUpBps), v.r.proxyName);
    }
    if (!v.r.remotes.isEmpty())
        lines << u("对端:") + v.r.remotes.join(QStringLiteral("  "));
    if (v.r.protectedSelf)
        lines << u("本软件自身组件:自我保护,不能从这里结束");
    else if (v.r.critical)
        lines << u("关键系统进程:结束会导致系统崩溃,不能从这里结束");
    lines << u("双击:定位文件    右键:连接详情 / 结束 / AI 分析");
    return lines.join(QLatin1Char('\n'));
}

bool TrafficOverlay::event(QEvent* e)
{
    if (e->type() == QEvent::ToolTip) {
        auto* he = static_cast<QHelpEvent*>(e);
        QString tip;
        const Hit b = buttonAt(he->pos());
        if (b == Hit::Close)
            tip = u("关闭悬浮窗(托盘菜单或设置页可重新打开)");
        else if (b == Hit::Chevron)
            tip = m_collapsed ? u("展开") : u("收起");
        else if (b == Hit::Boost)
            tip = !m_boostReq.isNull()
                      ? u("正在回收,请稍候…")
                      : (m_ipc && m_ipc->isConnected()
                             ? u("一键加速:请系统把各程序暂时用不到的内存页交还出来\n"
                                 "不结束任何程序,被换出的页下次用到时自动调回\n"
                                 "内存真的吃紧时能缓解卡顿,不紧张时收益有限")
                             : u("一键加速不可用:未连接后台服务\n内存回收必须由服务(SYSTEM)执行"));
        else if (const int row = rowAt(he->pos()); row >= 0) {
            if (const RowView* v = viewOf(m_order[row]))
                tip = rowTip(*v);
        } else if (headerRect().contains(he->pos())) {
            tip = u("网卡口径的实时速率(不含本机环回)\n自开始监控累计:↓ %1   ↑ %2\n拖动可移动;双击收起 / 展开")
                      .arg(bytesText(m_snap.sessionDownBytes), bytesText(m_snap.sessionUpBytes));
        }
        if (tip.isEmpty())
            QToolTip::hideText();
        else
            QToolTip::showText(he->globalPos(), tip, this);
        return true;
    }
    return QWidget::event(e);
}

void TrafficOverlay::enterEvent(QEnterEvent* e)
{
    QWidget::enterEvent(e);
    setWindowOpacity(1.0);
}

void TrafficOverlay::leaveEvent(QEvent* e)
{
    QWidget::leaveEvent(e);
    m_hoverRow = -1;
    m_hoverBtn = Hit::None;
    setWindowOpacity(0.92);
    update();
}

void TrafficOverlay::mousePressEvent(QMouseEvent* e)
{
    if (e->button() != Qt::LeftButton) {
        QWidget::mousePressEvent(e);
        return;
    }
    const QPoint pos = e->position().toPoint();
    m_pressBtn = buttonAt(pos);
    if (m_pressBtn != Hit::None)
        return;
    const int row = rowAt(pos);
    if (row >= 0) {
        m_selectedPid = m_order[row];
        update();
        return;
    }
    m_dragging = true;
    m_dragMoved = false;
    m_dragStartGlobal = e->globalPosition().toPoint();
    m_dragStartPos = this->pos();
}

void TrafficOverlay::mouseMoveEvent(QMouseEvent* e)
{
    const QPoint pos = e->position().toPoint();
    if (m_dragging) {
        const QPoint delta = e->globalPosition().toPoint() - m_dragStartGlobal;
        if (!m_dragMoved && delta.manhattanLength() < 4)
            return;
        m_dragMoved = true;
        move(m_dragStartPos + delta);
        return;
    }
    const int row = rowAt(pos);
    const Hit b = buttonAt(pos);
    if (row != m_hoverRow || b != m_hoverBtn) {
        m_hoverRow = row;
        m_hoverBtn = b;
        setCursor(row >= 0 || b != Hit::None ? Qt::PointingHandCursor : Qt::ArrowCursor);
        update();
    }
}

void TrafficOverlay::mouseReleaseEvent(QMouseEvent* e)
{
    if (e->button() != Qt::LeftButton) {
        QWidget::mouseReleaseEvent(e);
        return;
    }
    const QPoint pos = e->position().toPoint();
    if (m_dragging) {
        m_dragging = false;
        if (m_dragMoved) {
            clampToScreen();
            m_userMoved = true;
            QSettings().setValue(QString::fromLatin1(kKeyPos), this->pos());
        }
        return;
    }
    const Hit pressed = m_pressBtn;
    m_pressBtn = Hit::None;
    if (pressed != Hit::None && buttonAt(pos) == pressed) {
        if (pressed == Hit::Close)
            setOverlayEnabled(false);
        else if (pressed == Hit::Boost)
            runBoost();
        else
            setCollapsed(!m_collapsed);
    }
}

void TrafficOverlay::mouseDoubleClickEvent(QMouseEvent* e)
{
    if (e->button() != Qt::LeftButton) {
        QWidget::mouseDoubleClickEvent(e);
        return;
    }
    const QPoint pos = e->position().toPoint();
    if (buttonAt(pos) != Hit::None)
        return;
    const int row = rowAt(pos);
    if (row >= 0) {
        if (const RowView* v = viewOf(m_order[row]))
            locate(*v);
        return;
    }
    if (headerRect().contains(pos))
        setCollapsed(!m_collapsed);
}

void TrafficOverlay::setCollapsed(bool on)
{
    if (m_collapsed == on)
        return;
    m_collapsed = on;
    QSettings().setValue(QString::fromLatin1(kKeyCollapsed), on);
    applyGeometry();
    update();
}

void TrafficOverlay::setOnlyActive(bool on)
{
    m_onlyActive = on;
    QSettings().setValue(QString::fromLatin1(kKeyOnlyActive), on);
    rebuildOrder();
    applyGeometry();
    update();
}

void TrafficOverlay::contextMenuEvent(QContextMenuEvent* e)
{
    const int row = rowAt(e->pos());
    QMenu menu(this);
    menu.setToolTipsVisible(true);
    const auto icon = [](const char* name, const QColor& c = theme::textSecondary()) {
        return AppIcon::icon(QString::fromLatin1(name), c, 16);
    };

    QAction *aDetail = nullptr, *aKill = nullptr, *aTree = nullptr, *aAi = nullptr, *aLocate = nullptr,
            *aProcs = nullptr, *aCopy = nullptr;
    RowView picked;
    if (row >= 0) {
        if (const RowView* v = viewOf(m_order[row]))
            picked = *v;
        m_selectedPid = picked.r.pid;
        update();

        const QString locked = picked.r.protectedSelf
            ? u("本软件自身组件:自我保护,不允许从这里结束。如需停止防护,请在设置里关闭总开关。")
            : picked.r.critical ? u("关键系统进程:结束会导致系统崩溃(0xEF),不能从这里结束。") : QString();
        aDetail = menu.addAction(icon("globe", theme::info()), u("连接详情…"));
        aDetail->setToolTip(u("每条连接的对端、域名、字节数,以及这个程序最近写入的文件。看不到加密内容。"));
        menu.addSeparator();
        aKill = menu.addAction(icon("close"), u("结束进程…"));
        aTree = menu.addAction(icon("tree"), u("结束进程树…"));
        if (!locked.isEmpty()) {
            aKill->setEnabled(false);
            aTree->setEnabled(false);
            aKill->setToolTip(locked);
            aTree->setToolTip(locked);
        }
        menu.addSeparator();
        aAi = menu.addAction(icon("sparkles", theme::accentAlt()), u("AI 分析…"));
        aAi->setToolTip(u("让大模型解读这个程序是什么、联网是否正常。只作参考,不影响任何拦截 / 放行。"));
        menu.addSeparator();
        aLocate = menu.addAction(icon("folder"), u("定位文件(双击)"));
        aProcs = menu.addAction(icon("activity"), u("在进程管理中查看"));
        aCopy = menu.addAction(icon("copy"), u("复制路径"));
        if (picked.r.path.isEmpty()) {
            for (QAction* a : {aLocate, aCopy}) {
                a->setEnabled(false);
                a->setToolTip(u("取不到这个进程的映像路径(受保护进程 / 已退出)。"));
            }
        }
        menu.addSeparator();
    }
    QAction* aBoost = menu.addAction(icon("zap", theme::accent()), u("一键加速(回收内存)"));
    aBoost->setToolTip(u("请系统把各程序暂时用不到的内存页交还出来。不结束任何程序,"
                         "被换出的页下次用到时自动调回;内存不紧张时收益有限。"));
    if (!m_boostReq.isNull()) {
        aBoost->setEnabled(false);
        aBoost->setToolTip(u("正在加速,请稍候…"));
    } else if (!m_ipc || !m_ipc->isConnected()) {
        aBoost->setEnabled(false);
        aBoost->setToolTip(u("未连接后台服务。内存回收必须由服务(SYSTEM)执行。"));
    }
    QAction* aBoostPage = menu.addAction(icon("external"), u("打开「一键加速」页…"));
    aBoostPage->setToolTip(u("在主界面里查看内存占用率,并做开机自启动 / 占资源程序的进一步优化。"));
    menu.addSeparator();
    QAction* aCollapse = menu.addAction(icon("chevron-down"), m_collapsed ? u("展开") : u("收起"));
    QAction* aOnly = menu.addAction(u("只显示有流量的程序"));
    aOnly->setCheckable(true);
    aOnly->setChecked(m_onlyActive);
    QAction* aReset = menu.addAction(icon("pin"), u("回到右上角"));
    menu.addSeparator();
    QAction* aHide = menu.addAction(icon("close"), u("关闭悬浮窗"));
    aHide->setToolTip(u("可在托盘菜单或「设置 → 防护总控」里重新打开。"));

    QAction* chosen = menu.exec(e->globalPos());
    if (!chosen)
        return;
    if (chosen == aDetail)        openDetails(picked.r);
    else if (chosen == aKill)     kill(picked, false);
    else if (chosen == aTree)     kill(picked, true);
    else if (chosen == aAi)       analyze(picked);
    else if (chosen == aLocate)   locate(picked);
    else if (chosen == aProcs)    openInProcesses(picked.r.pid);
    else if (chosen == aCopy)     copyPath(picked);
    else if (chosen == aBoost)    runBoost();
    else if (chosen == aBoostPage) nav::go(QString::fromLatin1(nav::Boost));
    else if (chosen == aCollapse) setCollapsed(!m_collapsed);
    else if (chosen == aOnly)     setOnlyActive(aOnly->isChecked());
    else if (chosen == aReset)    { resetPosition(); clampToScreen(); }
    else if (chosen == aHide)     setOverlayEnabled(false);
}

void TrafficOverlay::locate(const RowView& v)
{
    if (v.r.path.isEmpty()) {
        emit notice(u("无法定位文件"), u("%1 没有可见的映像路径(受保护进程或已退出)。").arg(v.r.name));
        return;
    }
    if (!locateInExplorer(v.r.path))
        emit notice(u("无法定位文件"), u("%1 的文件已不存在,或资源管理器没能打开:\n%2")
                                          .arg(v.r.name, QDir::toNativeSeparators(v.r.path)));
}

void TrafficOverlay::copyPath(const RowView& v)
{
    if (QClipboard* cb = QGuiApplication::clipboard())
        cb->setText(QDir::toNativeSeparators(v.r.path));
}

void TrafficOverlay::openInProcesses(int pid)
{
    nav::go(QString::fromLatin1(nav::Processes), {{QStringLiteral("pid"), pid}});
}

void TrafficOverlay::kill(const RowView& v, bool tree)
{
    if (!m_ipc || !m_ipc->isConnected()) {
        emit notice(u("无法结束进程"), u("未连接后台服务。"));
        return;
    }
    bulwark::ProcessEntry e;
    e.pid = v.r.pid;
    e.name = v.r.name;
    e.imagePath = v.r.path;
    e.isCritical = v.r.critical;
    e.isProtectedSelf = v.r.protectedSelf;
    using Kind = bulwark::ipc::ProcessActionKind;
    m_last.pid = v.r.pid;
    m_last.kind = int(tree ? Kind::TerminateTree : Kind::Terminate);
    m_last.atMs = QDateTime::currentMSecsSinceEpoch();
    m_last.name = v.r.name;
    procview::run(nullptr, m_ipc, e, tree ? Kind::TerminateTree : Kind::Terminate);
}

void TrafficOverlay::runBoost()
{
    if (!m_boostReq.isNull()) {
        emit notice(u("正在加速"), u("上一次加速还在进行中,请稍候。"));
        return;
    }
    if (!m_ipc || !m_ipc->isConnected()) {
        emit notice(u("无法加速"), u("未连接后台服务。内存回收必须由服务(SYSTEM)执行。"));
        return;
    }
    m_boostReq = m_ipc->requestSystemBoost();
    m_boostStartMs = QDateTime::currentMSecsSinceEpoch();
    update();

    const QUuid mine = m_boostReq;
    QTimer::singleShot(25000, this, [this, mine] {
        if (m_boostReq != mine)
            return;
        m_boostReq = QUuid();
        update();
        emit notice(u("加速超时"), u("服务未在预期时间内返回结果,请稍后重试。"));
    });
}

void TrafficOverlay::onSystemBoostResult(const bulwark::ipc::SystemBoostResultPayload& r)
{
    if (m_boostReq.isNull() || r.requestId != m_boostReq)
        return;
    m_boostReq = QUuid();
    update();

    if (!r.success) {
        emit notice(u("加速失败"), r.message.isEmpty() ? u("服务没有给出原因。") : r.message);
        return;
    }
    if (r.freedBytes > 0) {
        emit notice(u("已交还 %1 内存").arg(bytesText(r.freedBytes)),
                    u("内存占用 %1% → %2%,共修剪 %3 个进程。这些页在程序下次用到时会自动调回,不丢数据。"
                      "内存本来不紧张时,这件事的收益有限。")
                        .arg(r.loadBefore).arg(r.loadAfter).arg(r.processesTrimmed));
    } else {
        emit notice(u("没有可交还的内存"),
                    u("已修剪 %1 个进程的工作集,系统当前没有可回收的页。").arg(r.processesTrimmed));
    }
}

void TrafficOverlay::onProcessActionResult(const bulwark::ipc::ProcessActionResultPayload& r)
{
    const qint64 now = QDateTime::currentMSecsSinceEpoch();
    if (m_last.pid == 0 || r.pid != m_last.pid || int(r.kind) != m_last.kind || now - m_last.atMs > 60000)
        return;
    const QString name = m_last.name;
    m_last = LastAction{};
    emit notice(r.success ? u("已处置 %1").arg(name) : u("没能处置 %1").arg(name),
                r.message.isEmpty() ? (r.success ? u("操作已完成。") : u("服务没有给出原因。")) : r.message);
}

void TrafficOverlay::analyze(const RowView& v)
{
    if (!m_ipc)
        return;
    AiScanner* ai = m_ipc->aiScanner();
    const NetTrafficRowPayload row = v.r;
    const bool perProcess = m_snap.perProcessAvailable;

    auto* sheet = new Sheet(nullptr);
    sheet->setAttribute(Qt::WA_DeleteOnClose);
    sheet->setSheetWidth(500);
    sheet->setHeader(QStringLiteral("sparkles"), theme::accentAlt(), u("AI 分析 · %1").arg(row.name),
                     u("PID %1 · 正在联网的程序").arg(row.pid));
    QVBoxLayout* body = sheet->body();

    auto* stage = ui::label(u("正在收集进程信息(签名、命令行、父进程、启动来源)…"), "secondary");
    stage->setWordWrap(true);
    body->addWidget(stage);

    QPointer<TrafficOverlay> self(this);
    QPushButton* locateBtn = sheet->addButton(u("定位文件"), "ghost", [self, row] {
        if (self) {
            RowView tmp;
            tmp.r = row;
            self->locate(tmp);
        }
    });
    locateBtn->setEnabled(!row.path.isEmpty());
    QPushButton* killBtn = sheet->addButton(u("结束进程…"), "danger", [self, row] {
        if (self) {
            RowView tmp;
            tmp.r = row;
            self->kill(tmp, false);
        }
    });
    killBtn->setVisible(false);
    QPushButton* closeBtn = sheet->addButton(u("关闭"), "primary", [sheet] { sheet->reject(); });
    closeBtn->setDefault(true);
    sheet->show();

    struct Ctx {
        QUuid req;
        bool done = false;
        QMetaObject::Connection conn;
    };
    auto ctx = std::make_shared<Ctx>();
    ctx->req = m_ipc->requestProcesses(true, true);
    QPointer<Sheet> guard(sheet);
    QPointer<QLabel> stageGuard(stage);

    const auto proceed = [=](const bulwark::ProcessEntry* pe) {
        if (!guard)
            return;
        bulwark::SecurityEvent ev;
        ev.type = bulwark::EventType::NetworkConnect;
        ev.actorPid = row.pid;
        ev.actorPath = row.path;
        ev.target = row.remotes.join(QStringLiteral(", "));
        ev.detail = trafficSummary(row, perProcess);
        if (pe) {
            ev.actorSigned = pe->isSigned;
            ev.signatureMismatch = pe->signatureMismatch;
            ev.actorPublisher = pe->publisher;
            ev.fileDescription = pe->fileDescription;
            ev.commandLine = pe->commandLine;
            ev.parentPath = pe->parentName;
            ev.originKind = pe->originKind;
            ev.originService = pe->originService;
            ev.originServiceDisplay = pe->originServiceDisplay;
            ev.originTask = pe->originTask;
            ev.originDetail = pe->originDetail;
            ev.riskScore = pe->riskScore;
            ev.riskReasons = pe->riskReasons;
        }
        if (stageGuard)
            stageGuard->setText(ai->isConfigured() ? u("AI 分析中(通常几秒)…") : u("正在检查大模型配置…"));

        const QString sigText = !pe                     ? u("未取到(进程可能已退出)")
                                : pe->signatureMismatch ? u("签名校验失败")
                                : pe->isSigned          ? (pe->publisher.isEmpty() ? u("有效签名")
                                                                                   : u("有效签名 · %1").arg(pe->publisher))
                                                        : u("无有效签名");

        ai->explainEvent(ev, guard.data(), [=](const AiExplanation& r) {
            if (!guard)
                return;
            if (stageGuard)
                stageGuard->hide();
            QVBoxLayout* b = guard->body();
            if (!r.ok) {
                auto* l = ui::label(u("暂不可用:%1").arg(r.error), "secondary");
                l->setWordWrap(true);
                l->setTextInteractionFlags(Qt::TextSelectableByMouse);
                b->addWidget(l);
                if (r.error.contains(u("未配置"))) {
                    auto* hint = ui::label(u("到「设置 → AI 辅助」填写大模型接口地址与 Key 后即可使用。"), "muted");
                    hint->setWordWrap(true);
                    b->addWidget(hint);
                }
                guard->refit();
                return;
            }
            auto* head = new QHBoxLayout;
            head->setSpacing(8);
            QLabel* verdict = r.advice == AiExplanation::Advice::Block   ? ui::pill(u("可疑"), theme::danger())
                              : r.advice == AiExplanation::Advice::Allow ? ui::pill(u("看起来正常"), theme::success())
                                                                          : ui::pill(u("拿不准"), theme::warning());
            head->addWidget(verdict);
            if (!r.confidence.isEmpty())
                head->addWidget(ui::pill(u("置信度 %1").arg(r.confidence), theme::accentAlt()));
            head->addStretch();
            b->addLayout(head);
            auto* summary = new WrapLabel(r.summary);
            summary->setProperty("role", "title");
            summary->setTextInteractionFlags(Qt::TextSelectableByMouse);
            b->addWidget(summary);
            QString meta;
            if (r.cached)
                meta = u("沿用%1%2的解读(这次没有请求模型)")
                           .arg(r.cachedSimilar ? u("同类程序 ") : QString(), ageText(r.cachedAgeMs));
            else
                meta = u("%1 · %2 tokens").arg(QString::number(r.elapsedMs / 1000.0, 'f', 1) + QStringLiteral("s"))
                           .arg(r.tokens);
            auto* metaLabel = ui::label(meta, "caption");
            b->addWidget(metaLabel);

            auto* facts = ui::cardAlt();
            auto* fv = new QVBoxLayout(facts);
            fv->setContentsMargins(14, 10, 14, 12);
            fv->setSpacing(4);
            fv->addWidget(ui::label(u("发送给模型的事实(已隐去本机用户名)"), "caption"));
            auto* fl = new WrapLabel(
                u("程序:%1\n路径:%2\n签名:%3\n连接:%4 个 TCP;对端 %5")
                    .arg(row.name,
                         row.path.isEmpty() ? u("(取不到)") : QDir::toNativeSeparators(row.path),
                         sigText,
                         QString::number(row.tcpConns),
                         row.remotes.isEmpty() ? u("(无)") : row.remotes.join(QStringLiteral("  "))));
            fl->setProperty("role", "mono");
            fv->addWidget(fl);
            b->addWidget(facts);
            b->addWidget(ui::label(u("由你配置的大模型生成,仅供参考,不影响任何拦截 / 放行决定。"), "muted"));

            killBtn->setVisible(r.advice == AiExplanation::Advice::Block && !row.critical && !row.protectedSelf);
            guard->refit();
        }, AiExplainContext::Traffic);
    };

    ctx->conn = connect(m_ipc, &IpcClient::processListReceived, sheet,
                        [ctx, row, proceed](const bulwark::ipc::ProcessListResponsePayload& p) {
        if (ctx->done || p.requestId != ctx->req)
            return;
        ctx->done = true;
        QObject::disconnect(ctx->conn);
        for (const bulwark::ProcessEntry& pe : p.processes) {
            if (pe.pid == row.pid) {
                proceed(&pe);
                return;
            }
        }
        proceed(nullptr);
    });
    // 拿不到进程快照(服务忙 / 超时)也不能让分析卡死:10 秒后只带流量侧的事实继续。
    QTimer::singleShot(10000, sheet, [ctx, proceed] {
        if (ctx->done)
            return;
        ctx->done = true;
        QObject::disconnect(ctx->conn);
        proceed(nullptr);
    });
}
