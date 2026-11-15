#include "pages/CardPages.h"

#include "Nav.h"
#include "design/Banner.h"
#include "design/Components.h"
#include "design/Format.h"
#include "design/GlowCard.h"
#include "design/IconTile.h"
#include "design/Icons.h"
#include "design/Identity.h"
#include "design/Motion.h"
#include "design/Skin.h"
#include "design/Theme.h"
#include "design/TitanKit.h"
#include "ipc/IpcClient.h"
#include "pages/PageKit.h"
#include "widgets/TrafficOverlay.h"

#include "bulwark/ipc/Payloads.h"
#include "bulwark/models/PersistenceEntry.h"

#include <QDateTime>
#include <QFontMetrics>
#include <QFrame>
#include <QGridLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QPainter>
#include <QPointer>
#include <QPushButton>
#include <QScrollArea>
#include <QStringList>
#include <QTimer>
#include <QUuid>
#include <QVariantAnimation>
#include <QVBoxLayout>
#include <QtMath>

#include <algorithm>
#include <array>
#include <cmath>
#include <functional>
#include <memory>

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

using bulwark::PersistenceCategory;
using bulwark::PersistenceEntry;
using bulwark::ipc::PersistenceListResponsePayload;
using bulwark::ipc::SystemBoostResultPayload;

namespace {

QString u(const char* s) { return QString::fromUtf8(s); }

constexpr int kTightLoad = 85;
constexpr int kWatchRisk = 50;   // 和「自启动项」页的「需留意」同一条线

struct MemInfo {
    bool ok = false;
    qint64 total = 0;
    qint64 inUse = 0;
    int load = 0;
};

MemInfo readMemory()
{
    MemInfo m;
    MEMORYSTATUSEX ms{};
    ms.dwLength = sizeof(ms);
    if (::GlobalMemoryStatusEx(&ms)) {
        m.ok = true;
        m.total = static_cast<qint64>(ms.ullTotalPhys);
        m.inUse = static_cast<qint64>(ms.ullTotalPhys - ms.ullAvailPhys);
        m.load = static_cast<int>(ms.dwMemoryLoad);
    }
    return m;
}

QColor loadColor(int load, bool known)
{
    if (!known)
        return theme::textMuted();
    if (load < 60)
        return theme::success();
    if (load < kTightLoad)
        return theme::warning();
    return theme::danger();
}

bool isStartupProgram(PersistenceCategory c)
{
    return c == PersistenceCategory::RegistryRun
        || c == PersistenceCategory::RegistryRunOnce
        || c == PersistenceCategory::StartupFolder;
}

QString categoryLabel(PersistenceCategory c)
{
    switch (c) {
        case PersistenceCategory::RegistryRun:     return u("注册表 Run");
        case PersistenceCategory::RegistryRunOnce: return u("注册表 RunOnce");
        case PersistenceCategory::StartupFolder:   return u("启动文件夹");
        case PersistenceCategory::ScheduledTask:   return u("计划任务");
        case PersistenceCategory::Service:         return u("服务");
        case PersistenceCategory::WmiSubscription: return u("WMI 订阅");
        case PersistenceCategory::IfeoDebugger:    return u("映像劫持");
        case PersistenceCategory::Winlogon:        return u("Winlogon");
        case PersistenceCategory::AppInitDll:      return u("AppInit_DLLs");
        case PersistenceCategory::Other:           break;
    }
    return u("其它");
}

// 和「自启动项」页同一套分类图标。
QString categoryGlyph(PersistenceCategory c)
{
    switch (c) {
        case PersistenceCategory::RegistryRun:
        case PersistenceCategory::RegistryRunOnce: return QStringLiteral("sliders");
        case PersistenceCategory::StartupFolder:   return QStringLiteral("folder");
        case PersistenceCategory::ScheduledTask:   return QStringLiteral("clock");
        case PersistenceCategory::Service:         return QStringLiteral("server");
        case PersistenceCategory::WmiSubscription: return QStringLiteral("zap");
        case PersistenceCategory::IfeoDebugger:    return QStringLiteral("target");
        case PersistenceCategory::Winlogon:        return QStringLiteral("user");
        case PersistenceCategory::AppInitDll:      return QStringLiteral("layers");
        case PersistenceCategory::Other:           break;
    }
    return QStringLiteral("power");
}

// 内存占用表盘的公共部分:目标值、动画、「还没读到」的状态。经典版式画成圆环,金刚画成转速表。
class LoadDial : public QWidget
{
public:
    LoadDial(int durationMs, QEasingCurve::Type curve)
    {
        m_anim = new QVariantAnimation(this);
        m_anim->setDuration(motion::duration(durationMs));
        m_anim->setEasingCurve(curve);
        connect(m_anim, &QVariantAnimation::valueChanged, this, [this](const QVariant& v) {
            m_shown = v.toReal();
            update();
        });
    }

    // known=false:还没读到内存状态 —— 画成空表盘 + 「—」,绝不画一个看起来像真数据的 0。
    void setValue(int percent, bool known)
    {
        const qreal target = qBound(0, percent, 100) / 100.0;
        m_known = known;
        if (!known) {
            m_anim->stop();
            m_shown = 0.0;
            update();
            return;
        }
        if (!motion::enabled() || !motion::onScreen(this)) {
            m_anim->stop();
            m_shown = target;
            update();
            return;
        }
        m_anim->stop();
        m_anim->setStartValue(m_shown);
        m_anim->setEndValue(target);
        m_anim->start();
    }

protected:
    QVariantAnimation* m_anim = nullptr;
    qreal m_shown = 0.0;
    bool m_known = false;
};

class MemoryRing : public LoadDial
{
public:
    MemoryRing() : LoadDial(520, QEasingCurve::OutCubic)
    {
        setFixedSize(150, 150);
        setAttribute(Qt::WA_TransparentForMouseEvents);
    }

protected:
    void paintEvent(QPaintEvent*) override
    {
        QPainter p(this);
        p.setRenderHint(QPainter::Antialiasing, true);
        p.setRenderHint(QPainter::TextAntialiasing, true);

        const qreal thickness = 11.0;
        const QRectF box = QRectF(rect()).adjusted(thickness / 2 + 2, thickness / 2 + 2,
                                                   -thickness / 2 - 2, -thickness / 2 - 2);
        const int pct = int(std::lround(m_shown * 100.0));
        const QColor tone = loadColor(pct, m_known);

        QPen track(theme::blend(theme::textMuted(), theme::surface(), 0.22), thickness);
        track.setCapStyle(Qt::FlatCap);
        p.setPen(track);
        p.setBrush(Qt::NoBrush);
        p.drawEllipse(box);

        if (m_known && m_shown > 0.0) {
            QPen arc(tone, thickness);
            arc.setCapStyle(Qt::RoundCap);
            p.setPen(arc);
            p.drawArc(box, 90 * 16, -int(std::lround(m_shown * 360.0)) * 16);
        }

        QFont big = font();
        big.setPixelSize(36);
        big.setWeight(QFont::Bold);
        p.setFont(big);
        p.setPen(m_known ? theme::textPrimary() : theme::textMuted());
        const QString text = m_known ? QString::number(pct) : QStringLiteral("—");
        const QFontMetrics fmBig(big);
        const int tw = fmBig.horizontalAdvance(text);
        const int baseY = height() / 2 + fmBig.capHeight() / 2 - 4;

        QFont small = font();
        small.setPixelSize(15);
        small.setWeight(QFont::DemiBold);
        const QFontMetrics fmSmall(small);
        const int pw = m_known ? fmSmall.horizontalAdvance(QStringLiteral("%")) : 0;
        const int startX = (width() - tw - pw) / 2;
        p.drawText(QPoint(startX, baseY), text);
        if (m_known) {
            p.setFont(small);
            p.setPen(theme::textSecondary());
            p.drawText(QPoint(startX + tw + 2, baseY), QStringLiteral("%"));
        }

        QFont cap = font();
        cap.setPixelSize(11);
        p.setFont(cap);
        p.setPen(theme::textMuted());
        p.drawText(QRect(0, baseY + 8, width(), 20), Qt::AlignHCenter | Qt::AlignTop, u("内存占用"));
    }
};

// 金刚:内存占用画成转速表。表盘分区和「吃紧」的判定是同一组门槛:60 以下能量蓝,60–85 琥珀,85 以上红区。
// 指针带一点过冲,像真表针甩到位。
class Tachometer : public LoadDial
{
public:
    Tachometer() : LoadDial(700, QEasingCurve::OutBack)
    {
        setFixedSize(320, 196);
        setAttribute(Qt::WA_TransparentForMouseEvents);
    }

protected:
    void paintEvent(QPaintEvent*) override
    {
        const theme::Palette& P = theme::pal();
        QPainter p(this);
        p.setRenderHint(QPainter::Antialiasing, true);
        p.setRenderHint(QPainter::TextAntialiasing, true);

        const QPointF c(160.0, 132.0);
        constexpr qreal R = 112.0;
        const auto deg = [](qreal v) { return 150.0 + 240.0 * v; };   // 屏幕坐标里顺时针的角度
        const auto at = [c](qreal r, qreal d) {
            const qreal a = qDegreesToRadians(d);
            return QPointF(c.x() + r * std::cos(a), c.y() + r * std::sin(a));
        };
        const auto arc = [&](qreal v0, qreal v1, const QColor& color, qreal w) {
            QPen pen(color, w);
            pen.setCapStyle(Qt::FlatCap);
            p.setPen(pen);
            p.setBrush(Qt::NoBrush);
            p.drawArc(QRectF(c.x() - R, c.y() - R, 2 * R, 2 * R), int(std::lround(-deg(v0) * 16.0)),
                      int(std::lround(-(deg(v1) - deg(v0)) * 16.0)));
        };
        constexpr qreal kAmber = 0.60;
        constexpr qreal kRed = kTightLoad / 100.0;
        arc(0.0, 1.0, P.ink, 18.0);
        arc(0.0, kAmber, P.glow, 11.0);
        arc(kAmber, kRed, P.amber, 11.0);
        arc(kRed, 1.0, P.danger, 11.0);

        QFont tick = titankit::numFont(12, QFont::Bold);
        p.setFont(tick);
        for (int i = 0; i <= 20; ++i) {
            const qreal v = i / 20.0;
            const bool major = i % 2 == 0;
            const bool red = v >= kRed;
            QPen pen(red ? P.danger : P.textMuted, major ? 2.5 : 1.5);
            pen.setCapStyle(Qt::FlatCap);
            p.setPen(pen);
            p.drawLine(at(R - 9.0, deg(v)), at(R - (major ? 24.0 : 17.0), deg(v)));
            if (i % 4 == 0) {
                const QPointF t = at(R - 38.0, deg(v));
                p.setPen(red ? P.danger : P.textSecondary);
                p.drawText(QRectF(t.x() - 20.0, t.y() - 9.0, 40.0, 18.0), Qt::AlignCenter, QString::number(i * 5));
            }
        }

        QFont cap = titankit::numFont(9, QFont::Bold);
        cap.setLetterSpacing(QFont::AbsoluteSpacing, 3.0);
        p.setFont(cap);
        p.setPen(P.textDisabled);
        p.drawText(QRectF(0.0, c.y() - 54.0, width(), 16.0), Qt::AlignCenter, QStringLiteral("MEMORY · %"));

        if (m_known) {
            const qreal n = deg(qBound(-0.03, m_shown, 1.04));
            const QPolygonF needle{at(R - 20.0, n), at(9.0, n + 90.0), at(22.0, n + 180.0), at(9.0, n - 90.0)};
            p.setPen(QPen(P.ink, 2.5, Qt::SolidLine, Qt::SquareCap, Qt::MiterJoin));
            p.setBrush(P.shell);
            p.drawPolygon(needle);
        }
        p.setPen(QPen(P.ink, 2.5));
        p.setBrush(P.fin);
        p.drawEllipse(c, 13.0, 13.0);
        p.setPen(Qt::NoPen);
        p.setBrush(P.ink);
        p.drawEllipse(c, 4.5, 4.5);

        const int pct = int(std::lround(qBound(0.0, m_shown, 1.0) * 100.0));
        const QString text = m_known ? QString::number(pct) : QStringLiteral("—");
        const QFont big = titankit::numFont(44, QFont::ExtraBold);
        const QFont unit = titankit::numFont(18, QFont::Bold);
        const QFontMetrics fb(big);
        const QFontMetrics fu(unit);
        const int tw = fb.horizontalAdvance(text);
        const int uw = m_known ? fu.horizontalAdvance(QStringLiteral("%")) + 3 : 0;
        const qreal x0 = (width() - tw - uw) / 2.0;
        const qreal base = 190.0;
        p.setFont(big);
        p.setPen(m_known ? P.text : P.textMuted);
        p.drawText(QPointF(x0, base), text);
        if (m_known) {
            p.setFont(unit);
            p.setPen(P.textMuted);
            p.drawText(QPointF(x0 + tw + 3.0, base), QStringLiteral("%"));
        }
    }
};

// 金刚的「立即加速」:红色装甲大键,底部 5px 键裙,字右斜。内存不紧张时降成钢灰色的普通键 ——
// 和经典版式一样,标题说「无需回收」时最显眼的按钮不该在招呼人去点。
class TurboButton final : public QPushButton
{
public:
    explicit TurboButton(const QString& text) : QPushButton(text)
    {
        setCursor(Qt::PointingHandCursor);
        setFixedSize(236, 54);
    }

    void setHot(bool hot)
    {
        m_hot = hot;
        update();
    }

protected:
    void paintEvent(QPaintEvent*) override
    {
        const theme::Palette& P = theme::pal();
        QPainter p(this);
        p.setRenderHint(QPainter::Antialiasing, true);
        p.setRenderHint(QPainter::TextAntialiasing, true);
        const bool on = isEnabled();
        const bool down = on && isDown();
        const bool hover = on && underMouse();

        const QRectF body = QRectF(rect()).adjusted(1.5, down ? 3.5 : 1.5, -1.5, -1.5);
        const QPainterPath path = theme::panelPath(body, 12.0);
        QColor fill = m_hot ? P.shell : QColor(0x22, 0x2C, 0x42);
        if (hover)
            fill = fill.lighter(112);
        if (!on)
            fill = P.surfaceAlt;
        p.fillPath(path, fill);
        if (!down && on) {
            p.save();
            p.setClipPath(path);
            p.fillRect(QRectF(body.left(), body.bottom() - 5.0, body.width(), 5.0),
                       m_hot ? QColor(0x96, 0x13, 0x1A) : QColor(0x10, 0x16, 0x22));
            p.fillRect(QRectF(body.left() + 14.0, body.top() + 3.0, body.width() - 28.0, 2.0), QColor(255, 255, 255, 46));
            p.restore();
        }
        p.setPen(QPen(focusPolicy() != Qt::NoFocus && hasFocus() ? P.glow : P.ink, 2.5, Qt::SolidLine, Qt::SquareCap,
                      Qt::MiterJoin));
        p.setBrush(Qt::NoBrush);
        p.drawPath(path);

        const QColor fg = !on ? P.textDisabled : m_hot ? QColor(Qt::white) : P.text;
        QFont f = font();
        f.setPixelSize(19);
        f.setWeight(QFont::Black);
        f.setLetterSpacing(QFont::AbsoluteSpacing, 6.0);
        const QFontMetrics fm(f);
        const qreal iconPx = 20.0;
        const qreal gap = 10.0;
        const qreal tw = fm.horizontalAdvance(text()) - 6.0;
        const qreal total = iconPx + gap + tw;
        const qreal cy = body.center().y() - 2.0;
        p.save();
        p.translate(body.center().x(), cy);
        p.setTransform(QTransform().shear(-0.16, 0.0), true);
        AppIcon::draw(p, QStringLiteral("zap"), QRectF(-total / 2.0, -iconPx / 2.0, iconPx, iconPx), fg, 2.4);
        p.setFont(f);
        p.setPen(fg);
        p.drawText(QPointF(-total / 2.0 + iconPx + gap, fm.capHeight() / 2.0), text());
        p.restore();
    }

private:
    bool m_hot = false;
};

// 金刚「开机加速」里的一格:分类图标 + 名称 + 数量;这一类里有需留意的项时数字转琥珀。
class CategoryCell final : public QWidget
{
public:
    explicit CategoryCell(PersistenceCategory c) : m_category(c)
    {
        setFixedHeight(40);
        setMinimumWidth(100);
        setAttribute(Qt::WA_TransparentForMouseEvents);
        setAccessibleName(categoryLabel(c));
    }

    void setCount(int n, bool hot)
    {
        m_count = n;
        m_hot = hot;
        setToolTip(n < 0 ? QString() : hot ? u("%1 项,其中有需留意的").arg(n) : u("%1 项").arg(n));
        update();
    }

protected:
    void paintEvent(QPaintEvent*) override
    {
        const theme::Palette& P = theme::pal();
        QPainter p(this);
        p.setRenderHint(QPainter::Antialiasing, true);
        p.setRenderHint(QPainter::TextAntialiasing, true);
        const QRectF r = QRectF(rect()).adjusted(1.0, 1.0, -1.0, -1.0);
        const QPainterPath path = theme::panelPath(r, 6.0);
        p.fillPath(path, m_hot ? theme::blend(P.warning, P.surfaceAlt, 0.10) : P.surfaceAlt);
        p.strokePath(path, QPen(m_hot ? theme::blend(P.warning, P.ink, 0.55) : P.ink, 2.0, Qt::SolidLine,
                                Qt::SquareCap, Qt::MiterJoin));
        AppIcon::draw(p, categoryGlyph(m_category), QRectF(11.0, (height() - 14.0) / 2.0, 14.0, 14.0), P.textSecondary,
                      1.6);
        QFont f = font();
        f.setPixelSize(12);
        p.setFont(f);
        p.setPen(P.textSecondary);
        const QString count = m_count < 0 ? QStringLiteral("—") : QString::number(m_count);
        const QFont num = titankit::numFont(15, QFont::ExtraBold);
        const int cw = QFontMetrics(num).horizontalAdvance(count);
        p.drawText(QRectF(33.0, 0.0, width() - 33.0 - cw - 18.0, height()), Qt::AlignVCenter | Qt::AlignLeft,
                   QFontMetrics(f).elidedText(categoryLabel(m_category), Qt::ElideRight, width() - 33 - cw - 18));
        p.setFont(num);
        p.setPen(m_count < 0 ? P.textMuted : m_hot ? P.warning : P.text);
        p.drawText(QRectF(0.0, 0.0, width() - 11.0, height()), Qt::AlignVCenter | Qt::AlignRight, count);
    }

private:
    PersistenceCategory m_category;
    int m_count = -1;
    bool m_hot = false;
};

// 金刚「开机加速」面板里随检测结果刷新的部分。
struct TitanBoot {
    QLabel* startup = nullptr;
    QLabel* watch = nullptr;
    QLabel* total = nullptr;
    std::array<CategoryCell*, 9> cells{};
    QWidget* examples = nullptr;
    QVBoxLayout* exampleRows = nullptr;
};

QWidget* exampleRow(const PersistenceEntry& e)
{
    auto* w = new QFrame;
    w->setObjectName(QStringLiteral("BoostExample"));
    w->setStyleSheet(QStringLiteral("#BoostExample { border-top:1px solid %1; }").arg(theme::pal().ink.name()));
    w->setFixedHeight(32);
    auto* h = new QHBoxLayout(w);
    h->setContentsMargins(2, 0, 2, 0);
    h->setSpacing(8);
    auto* icon = new AppIcon(categoryGlyph(e.category));
    icon->setPx(14);
    icon->setColor(theme::textSecondary());
    h->addWidget(icon, 0, Qt::AlignVCenter);
    auto* name = ui::elided(e.name.isEmpty() ? u("未命名") : e.name, "title");
    name->setToolTip(e.command.isEmpty() ? e.imagePath : e.command);
    h->addWidget(name, 1, Qt::AlignVCenter);
    h->addWidget(ui::label(u("(%1)").arg(categoryLabel(e.category)), "muted"), 0, Qt::AlignVCenter);
    if (e.riskScore >= kWatchRisk)
        h->addWidget(ui::pill(u("需留意 %1").arg(e.riskScore), theme::warning()), 0, Qt::AlignVCenter);
    if (e.isSigned.has_value()) {
        const bool ok = *e.isSigned;
        h->addWidget(ui::pill(ok ? (e.publisher.isEmpty() ? u("已签名") : u("已签名 · ") + e.publisher) : u("无签名"),
                              ok ? theme::success() : theme::warning()),
                     0, Qt::AlignVCenter);
    }
    return w;
}

struct State {
    QUuid inflight;
    bool startupAsked = false;
    int memLoad = -1;
    // 「立即加速」当前是不是主按钮样式;-1 表示还没定过。
    int emphasized = -1;
};

}

namespace pages {

QWidget* boost(IpcClient* ipc)
{
    auto* page = new QWidget;
    auto st = std::make_shared<State>();
    const QColor hue = identity::page(QString::fromLatin1(nav::Boost));
    const bool titan = theme::titan();

    auto* outer = new QVBoxLayout(page);
    outer->setContentsMargins(0, 0, 0, 0);
    auto* scroll = new QScrollArea;
    scroll->setWidgetResizable(true);
    scroll->setFrameShape(QFrame::NoFrame);
    scroll->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    scroll->viewport()->setAutoFillBackground(false);
    outer->addWidget(scroll);
    auto* content = new QWidget;
    content->setAutoFillBackground(false);
    auto* v = new QVBoxLayout(content);
    v->setContentsMargins(theme::metric::pagePad, 16, theme::metric::pagePad, theme::metric::pagePad);
    v->setSpacing(16);
    scroll->setWidget(content);

    LoadDial* ring = nullptr;
    GlowCard* hero = nullptr;
    QLabel* headline = nullptr;
    QLabel* amounts = nullptr;
    QLabel* resultLine = nullptr;
    QPushButton* boostBtn = nullptr;
    TurboButton* turbo = nullptr;
    QLabel* btnHint = nullptr;
    QLabel* bootResult = nullptr;
    QLabel* bootList = nullptr;
    QPushButton* detectBtn = nullptr;
    QPushButton* manageBtn = nullptr;
    TitanBoot tb;
    const QString caveatText = u("Windows 平时会主动拿空闲内存做缓存和预加载,所以占用率高本身不代表有问题。"
                                 "回收做的是请系统把各程序暂时用不到的内存页交还出来:内存真的吃紧时能缓解卡顿,"
                                 "不紧张时收益有限 —— 它不会结束任何程序,被换出的页在下次用到时自动调回,不丢数据。");

    if (titan) {
        // 金刚:左边转速表 + 红色大键,右边开机加速的分类格子;下面两张「下一步」卡。
        auto* grid = new QGridLayout;
        grid->setHorizontalSpacing(14);
        grid->setVerticalSpacing(14);
        grid->setColumnStretch(1, 1);

        titankit::Panel mem = titankit::panel(u("内存回收"), QString(), QStringLiteral("TACHO"), hue);
        hero = mem.card;
        hero->setGlow(hue, QPointF(1.0, 0.0), 0.8, 0.12);
        amounts = mem.head.note;
        auto* tacho = new Tachometer;
        ring = tacho;
        mem.body->addWidget(tacho, 0, Qt::AlignHCenter);
        headline = ui::label(u("正在读取内存状态…"));
        headline->setAlignment(Qt::AlignHCenter);
        headline->setWordWrap(true);
        mem.body->addWidget(headline);
        mem.body->addSpacing(8);
        turbo = new TurboButton(u("立即加速"));
        boostBtn = turbo;
        mem.body->addWidget(turbo, 0, Qt::AlignHCenter);
        btnHint = ui::label(QString(), "muted");
        btnHint->setAlignment(Qt::AlignHCenter);
        btnHint->setWordWrap(true);
        mem.body->addWidget(btnHint);
        resultLine = ui::label(QString(), "muted");
        resultLine->setAlignment(Qt::AlignHCenter);
        resultLine->setWordWrap(true);
        resultLine->hide();
        mem.body->addWidget(resultLine);
        mem.body->addStretch();
        mem.body->addWidget(ui::hDivider());
        auto* caveat = ui::label(caveatText, "muted");
        caveat->setWordWrap(true);
        mem.body->addWidget(caveat);
        mem.card->setMinimumWidth(360);
        mem.card->setMaximumWidth(430);
        grid->addWidget(mem.card, 0, 0);

        titankit::Panel bootPanel = titankit::panel(u("开机加速"), QString(), QString(),
                                                    identity::page(QString::fromLatin1(nav::Persistence)));
        bootPanel.head.trailing->addWidget(ui::pill(u("效果最实在"), theme::success()));
        detectBtn = ui::button(u("检测"), nullptr, QStringLiteral("search"), true);
        manageBtn = ui::button(u("去管理"), "primary", QString(), true);
        bootPanel.head.trailing->addWidget(detectBtn);
        bootPanel.head.trailing->addWidget(manageBtn);
        auto* intro = ui::label(u("开机自启的程序越多,开机就越慢、刚进桌面越卡。精简它是唯一有实测效果的加速手段。"),
                                "secondary");
        intro->setWordWrap(true);
        bootPanel.body->addWidget(intro);
        auto* readings = new QHBoxLayout;
        readings->setSpacing(26);
        readings->addWidget(titankit::reading(&tb.startup, u("项开机自启")));
        readings->addWidget(titankit::reading(&tb.watch, u("项需留意")));
        readings->addWidget(titankit::reading(&tb.total, u("项持久化点")));
        readings->addStretch();
        bootPanel.body->addLayout(readings);
        auto* cells = new QGridLayout;
        cells->setSpacing(6);
        for (int i = 0; i < int(tb.cells.size()); ++i) {
            tb.cells[i] = new CategoryCell(PersistenceCategory(i));
            cells->addWidget(tb.cells[i], i / 3, i % 3);
        }
        bootPanel.body->addLayout(cells);
        bootResult = ui::label(u("还没有检测。检测是只读的,不会改动任何一项。"), "secondary");
        bootResult->setWordWrap(true);
        bootPanel.body->addWidget(bootResult);
        tb.examples = new QWidget;
        tb.exampleRows = new QVBoxLayout(tb.examples);
        tb.exampleRows->setContentsMargins(0, 0, 0, 0);
        tb.exampleRows->setSpacing(0);
        tb.examples->hide();
        bootPanel.body->addWidget(tb.examples);
        bootPanel.body->addStretch();
        auto* restraint = ui::label(u("「一键加速」只做工作集修剪和自启动项入口,不清理磁盘或注册表,也不承诺提高实际性能。"),
                                    "muted");
        restraint->setWordWrap(true);
        bootPanel.body->addWidget(restraint);
        grid->addWidget(bootPanel.card, 0, 1);

        const auto step = [hue](const QString& title, const QString& tag, const QString& icon, const QColor& tone,
                                const QString& desc, QPushButton* button) {
            titankit::Panel s = titankit::panel(title, QString(), tag, hue);
            auto* row = new QHBoxLayout;
            row->setSpacing(12);
            row->addWidget(new IconTile(icon, tone, 40, 20), 0, Qt::AlignVCenter);
            auto* d = ui::label(desc, "muted");
            d->setWordWrap(true);
            row->addWidget(d, 1);
            button->setMinimumWidth(96);
            row->addWidget(button, 0, Qt::AlignVCenter);
            s.body->addLayout(row);
            return s.card;
        };
        auto* procBtn = ui::button(u("去查看"), "ghost", QString(), true);
        QObject::connect(procBtn, &QPushButton::clicked, page, [] { nav::go(QString::fromLatin1(nav::Processes)); });
        grid->addWidget(step(u("找出占资源的程序"), QStringLiteral("STEP 2"), QStringLiteral("target"),
                             identity::page(QString::fromLatin1(nav::Processes)),
                             u("内存回收只解决「此刻占着不放」。真正拖慢机器的往往是某一个具体的程序 —— "
                               "按内存、线程数、启动来源排查正在跑的进程,谁在占着内存和 CPU 不放,一眼看到。"),
                             procBtn),
                        1, 0);
        TrafficOverlay* ov = TrafficOverlay::instance();
        auto* trafficBtn = ui::button(ov && ov->overlayEnabled() ? u("关闭") : u("打开"), "ghost", QString(), true);
        if (ov) {
            QObject::connect(trafficBtn, &QPushButton::clicked, trafficBtn, [trafficBtn] {
                if (TrafficOverlay* o = TrafficOverlay::instance()) {
                    const bool next = !o->overlayEnabled();
                    o->setOverlayEnabled(next);
                    trafficBtn->setText(next ? u("关闭") : u("打开"));
                }
            });
            QObject::connect(ov, &TrafficOverlay::overlayEnabledChanged, trafficBtn,
                             [trafficBtn](bool enabled) { trafficBtn->setText(enabled ? u("关闭") : u("打开")); });
        } else {
            trafficBtn->setEnabled(false);
            trafficBtn->setToolTip(u("悬浮窗尚未就绪。"));
        }
        grid->addWidget(step(u("找出占网速的程序"), QStringLiteral("STEP 3"), QStringLiteral("activity"), theme::cyan(),
                             u("桌面悬浮窗(雷达)实时显示哪个程序在联网、各自多快;在它标题栏上也能直接一键加速。"),
                             trafficBtn),
                        1, 1);
        v->addLayout(grid);
        v->addStretch();
    } else {
        hero = ui::card();
        hero->setGlow(hue, QPointF(1.0, 0.0), 0.8, 0.12);
        auto* heroV = new QVBoxLayout(hero);
        heroV->setContentsMargins(24, 18, 24, 16);
        heroV->setSpacing(10);

        auto* hh = new QHBoxLayout;
        hh->setSpacing(22);
        ring = new MemoryRing;
        hh->addWidget(ring, 0, Qt::AlignVCenter);

        auto* col = new QVBoxLayout;
        col->setSpacing(5);
        col->addStretch();
        col->addWidget(ui::eyebrow(u("内存回收")));
        headline = ui::coloredText(u("正在读取内存状态…"), 19, 700, theme::textPrimary());
        headline->setWordWrap(true);
        col->addWidget(headline);
        amounts = ui::label(QString(), "secondary");
        amounts->setWordWrap(true);
        col->addWidget(amounts);
        resultLine = ui::label(QString(), "muted");
        resultLine->setWordWrap(true);
        resultLine->hide();
        col->addWidget(resultLine);
        col->addStretch();
        hh->addLayout(col, 1);

        auto* right = new QVBoxLayout;
        right->setSpacing(8);
        right->addStretch();
        // 样式由 refreshMemory 按内存状态决定:只有真的吃紧时才是主按钮。
        boostBtn = ui::button(u("立即加速"), nullptr, QStringLiteral("zap"));
        boostBtn->setMinimumSize(158, 42);
        right->addWidget(boostBtn, 0, Qt::AlignRight);
        btnHint = ui::label(QString(), "muted");
        btnHint->setAlignment(Qt::AlignRight);
        btnHint->setWordWrap(true);
        right->addWidget(btnHint);
        right->addStretch();
        hh->addLayout(right);
        heroV->addLayout(hh);

        {
            auto* rule = new QFrame;
            rule->setFixedHeight(1);
            rule->setStyleSheet(QStringLiteral("background:%1;").arg(theme::border().name()));
            heroV->addWidget(rule);
            auto* caveat = ui::label(caveatText, "muted");
            caveat->setWordWrap(true);
            heroV->addWidget(caveat);
        }
        v->addWidget(hero);

        auto* boot = ui::card();
        auto* bv = new QVBoxLayout(boot);
        bv->setContentsMargins(24, 18, 24, 16);
        bv->setSpacing(10);
        {
            auto* head = new QHBoxLayout;
            head->setSpacing(10);
            head->addWidget(new IconTile(QStringLiteral("power"),
                                         identity::page(QString::fromLatin1(nav::Persistence)), 34, 17),
                            0, Qt::AlignVCenter);
            auto* tcol = new QVBoxLayout;
            tcol->setSpacing(2);
            auto* titleRow = new QHBoxLayout;
            titleRow->setSpacing(8);
            titleRow->addWidget(ui::label(u("开机加速"), "title"));
            titleRow->addWidget(ui::pill(u("效果最实在"), theme::success()), 0, Qt::AlignVCenter);
            titleRow->addStretch();
            tcol->addLayout(titleRow);
            auto* sub = ui::label(u("开机自启的程序越多,开机就越慢、刚进桌面越卡。精简它是唯一有实测效果的加速手段。"),
                                  "muted");
            sub->setWordWrap(true);
            tcol->addWidget(sub);
            head->addLayout(tcol, 1);
            bv->addLayout(head);
        }
        bootResult = ui::label(u("还没有检测。检测是只读的,不会改动任何一项。"), "secondary");
        bootResult->setWordWrap(true);
        bv->addWidget(bootResult);
        bootList = ui::label(QString(), "muted");
        bootList->setWordWrap(true);
        bootList->hide();
        bv->addWidget(bootList);
        {
            auto* row = new QHBoxLayout;
            row->setSpacing(8);
            row->addStretch();
            detectBtn = ui::button(u("检测"), nullptr, QStringLiteral("search"), true);
            manageBtn = ui::button(u("去管理"), "ghost", QString(), true);
            row->addWidget(detectBtn);
            row->addWidget(manageBtn);
            bv->addLayout(row);
        }
        v->addWidget(boot);

        auto* more = ui::card();
        auto* mv = new QVBoxLayout(more);
        mv->setContentsMargins(24, 18, 24, 14);
        mv->setSpacing(10);
        {
            auto* head = new QHBoxLayout;
            head->setSpacing(10);
            head->addWidget(new IconTile(QStringLiteral("sliders"), hue, 30, 15));
            head->addWidget(ui::label(u("进一步优化"), "title"));
            head->addStretch();
            mv->addLayout(head);
            auto* note = ui::label(u("内存回收只解决「此刻占着不放」。真正拖慢机器的往往是某一个具体的程序 —— 先把它找出来。"),
                                   "muted");
            note->setWordWrap(true);
            mv->addWidget(note);
        }

        const auto row = [mv](const QString& icon, const QColor& tone, const QString& title,
                              const QString& desc, const QString& btnText,
                              std::function<void(QPushButton*)> onClick) -> QPushButton* {
            auto* rule = new QFrame;
            rule->setFixedHeight(1);
            rule->setStyleSheet(QStringLiteral("background:%1;").arg(theme::border().name()));
            mv->addWidget(rule);

            auto* w = new QWidget;
            auto* h = new QHBoxLayout(w);
            h->setContentsMargins(0, 8, 0, 8);
            h->setSpacing(12);
            h->addWidget(new IconTile(icon, tone, 34, 17), 0, Qt::AlignVCenter);
            auto* c = new QVBoxLayout;
            c->setSpacing(2);
            c->addWidget(ui::label(title, "title"));
            auto* d = ui::label(desc, "muted");
            d->setWordWrap(true);
            c->addWidget(d);
            h->addLayout(c, 1);
            auto* b = ui::button(btnText, "ghost", QString(), true);
            b->setMinimumWidth(96);
            h->addWidget(b, 0, Qt::AlignVCenter);
            mv->addWidget(w);
            QObject::connect(b, &QPushButton::clicked, b, [b, onClick] { onClick(b); });
            return b;
        };

        row(QStringLiteral("target"), identity::page(QString::fromLatin1(nav::Processes)),
            u("找出占资源的程序"), u("按内存、线程数、启动来源排查正在跑的进程 —— 谁在占着内存和 CPU 不放,一眼看到。"),
            u("去查看"), [](QPushButton*) { nav::go(QString::fromLatin1(nav::Processes)); });

        {
            TrafficOverlay* ov = TrafficOverlay::instance();
            const bool on = ov && ov->overlayEnabled();
            QPushButton* b = row(QStringLiteral("activity"), theme::cyan(), u("找出占网速的程序"),
                                 u("桌面悬浮窗实时显示哪个程序在联网、各自多快;在它标题栏上也能直接一键加速。"),
                                 on ? u("关闭") : u("打开"), [](QPushButton* self) {
                if (TrafficOverlay* o = TrafficOverlay::instance()) {
                    const bool next = !o->overlayEnabled();
                    o->setOverlayEnabled(next);
                    self->setText(next ? u("关闭") : u("打开"));
                }
            });
            if (ov) {
                QObject::connect(ov, &TrafficOverlay::overlayEnabledChanged, b,
                                 [b](bool enabled) { b->setText(enabled ? u("关闭") : u("打开")); });
            } else {
                b->setEnabled(false);
                b->setToolTip(u("悬浮窗尚未就绪。"));
            }
        }
        v->addWidget(more);
        v->addStretch();
    }

    QObject::connect(detectBtn, &QPushButton::clicked, page, [ipc, page, st, bootResult, detectBtn] {
        if (!ipc->isConnected()) {
            ui::notify(page, ui::Tone::Warning, u("未连接后台服务,无法检测自启动项。"));
            return;
        }
        st->startupAsked = true;
        detectBtn->setEnabled(false);
        detectBtn->setText(u("检测中…"));
        bootResult->setText(u("正在枚举开机自启动项…"));
        ipc->requestPersistence();
        QTimer::singleShot(15000, detectBtn, [detectBtn] {
            if (!detectBtn->isEnabled()) {
                detectBtn->setEnabled(true);
                detectBtn->setText(u("检测"));
            }
        });
    });
    QObject::connect(manageBtn, &QPushButton::clicked, page, [] {
        nav::go(QString::fromLatin1(nav::Persistence), {{QStringLiteral("scan"), true}});
    });

    QObject::connect(ipc, &IpcClient::persistenceReceived, page,
                     [tb, bootResult, bootList, detectBtn](const PersistenceListResponsePayload& p) {
        detectBtn->setEnabled(true);
        detectBtn->setText(u("重新检测"));
        int startup = 0;
        QStringList names;
        for (const PersistenceEntry& e : p.entries) {
            if (!isStartupProgram(e.category))
                continue;
            ++startup;
            if (names.size() < 4)
                names << u("%1(%2)").arg(e.name.isEmpty() ? u("未命名") : e.name,
                                          categoryLabel(e.category));
        }
        if (tb.startup) {
            std::array<int, 9> count{};
            std::array<bool, 9> hot{};
            int watch = 0;
            QList<const PersistenceEntry*> starters;
            for (const PersistenceEntry& e : p.entries) {
                const int c = int(e.category);
                const bool flagged = e.riskScore >= kWatchRisk;
                watch += flagged ? 1 : 0;
                if (c >= 0 && c < int(count.size())) {
                    ++count[c];
                    hot[c] = hot[c] || flagged;
                }
                if (isStartupProgram(e.category))
                    starters << &e;
            }
            titankit::setReading(tb.startup, startup);
            titankit::setReading(tb.watch, watch, watch > 0 ? theme::warning() : QColor());
            titankit::setReading(tb.total, int(p.entries.size()));
            for (int i = 0; i < int(tb.cells.size()); ++i)
                tb.cells[i]->setCount(count[i], hot[i]);
            // 例子先列需留意的,其余按原来的顺序。
            std::stable_sort(starters.begin(), starters.end(), [](const PersistenceEntry* a, const PersistenceEntry* b) {
                return (a->riskScore >= kWatchRisk) > (b->riskScore >= kWatchRisk);
            });
            while (QLayoutItem* item = tb.exampleRows->takeAt(0)) {
                delete item->widget();
                delete item;
            }
            for (int i = 0; i < starters.size() && i < 3; ++i)
                tb.exampleRows->addWidget(exampleRow(*starters.at(i)));
            tb.examples->setVisible(!starters.isEmpty());
        }
        if (startup == 0) {
            bootResult->setText(u("没有发现开机自启动的程序 —— 共扫到 %1 项持久化点,"
                                  "其余是服务与计划任务,绝大多数是系统自己的。")
                                    .arg(p.entries.size()));
            if (bootList)
                bootList->hide();
            return;
        }
        bootResult->setText(u("共 %1 项开机自启动的程序(注册表 Run / RunOnce / 启动文件夹);"
                              "另扫到 %2 项服务与计划任务等持久化点,多为系统自有,不建议动。")
                                .arg(startup).arg(p.entries.size() - startup));
        if (bootList) {
            bootList->setText(u("例如:%1%2").arg(names.join(u("、")),
                                                 startup > names.size() ? u(" 等") : QString()));
            bootList->show();
        }
    });

    // 只有内存真的吃紧时「立即加速」才是主按钮;不紧张时降为普通按钮,
    // 免得标题说「无需回收」、最显眼的按钮却在招呼人去点。每 2 秒轮询一次,所以只在状态变了时才重设。
    const auto setEmphasis = [boostBtn, turbo, st](bool on) {
        if (st->emphasized == int(on))
            return;
        st->emphasized = int(on);
        if (turbo) {
            turbo->setHot(on);
            return;
        }
        ui::setVariant(boostBtn, on ? "primary" : "");
        boostBtn->setIcon(
            AppIcon::icon(QStringLiteral("zap"), on ? theme::accentInk() : theme::textSecondary(), 16));
    };
    const auto refreshMemory = [ring, headline, amounts, btnHint, hero, hue, st, setEmphasis, titan] {
        const MemInfo m = readMemory();
        ring->setValue(m.load, m.ok);
        st->memLoad = m.ok ? m.load : -1;
        if (!m.ok) {
            headline->setText(u("读不到内存状态"));
            amounts->setText(u("系统没有返回物理内存信息。回收仍可执行。"));
            btnHint->setText(QString());
            setEmphasis(false);
            return;
        }
        // 占用率高不等于有问题(见卡片底部的说明),所以没到吃紧就直说不用处理,标题也不染成告警色;
        // 占用高低仍由左边的环用颜色表示。
        const bool tight = m.load >= kTightLoad;
        const bool ample = m.load < 60;
        headline->setText(tight ? u("内存吃紧") : ample ? u("内存充足,无需回收") : u("内存够用,暂时不用回收"));
        const QColor tone = tight ? theme::danger() : ample ? theme::success() : theme::textPrimary();
        if (titan)
            headline->setStyleSheet(QStringLiteral("font-size:10.5pt; font-weight:700; color:%1;").arg(tone.name()));
        else
            headline->setStyleSheet(QStringLiteral("font-size:19pt; font-weight:700; color:%1;").arg(tone.name()));
        amounts->setText(u("已用 %1 / 共 %2").arg(fmt::bytes(m.inUse), fmt::bytes(m.total)));
        btnHint->setText(tight ? u("内存确实紧张,现在回收有意义") : u("当前不紧张,回收收益有限"));
        hero->setGlow(tight ? theme::danger() : hue, QPointF(1.0, 0.0), 0.8, 0.12);
        setEmphasis(tight);
    };
    refreshMemory();
    auto* poll = new QTimer(page);
    poll->setInterval(2000);
    QObject::connect(poll, &QTimer::timeout, page, [page, refreshMemory] {
        if (page->isVisible())
            refreshMemory();
    });
    poll->start();

    QHBoxLayout* actions = pagekit::headerActions(page);
    QPushButton* refreshBtn = pagekit::headerButton(actions, QStringLiteral("refresh"), u("刷新"));
    QObject::connect(refreshBtn, &QPushButton::clicked, page, [refreshMemory] { refreshMemory(); });

    QPointer<QWidget> pageGuard(page);
    const auto setBusy = [boostBtn, btnHint](bool busy) {
        boostBtn->setEnabled(!busy);
        boostBtn->setText(busy ? u("正在回收…") : u("立即加速"));
        if (busy)
            btnHint->setText(u("正在请求系统交还内存,请稍候"));
    };

    QObject::connect(boostBtn, &QPushButton::clicked, page, [=] {
        if (!ipc->isConnected()) {
            ui::notify(page, ui::Tone::Warning,
                       u("未连接后台服务,无法回收内存。修剪别的程序的工作集需要系统权限,必须由服务执行。"));
            return;
        }
        if (!st->inflight.isNull())
            return;
        st->inflight = ipc->requestSystemBoost();
        setBusy(true);
        const QUuid mine = st->inflight;
        QTimer::singleShot(25000, page, [st, mine, setBusy, refreshMemory, pageGuard] {
            if (!pageGuard || st->inflight != mine)
                return;
            st->inflight = QUuid();
            setBusy(false);
            refreshMemory();
            ui::notify(pageGuard, ui::Tone::Danger,
                       u("回收超时:服务未在预期时间内返回结果,请稍后重试。"));
        });
    });

    QObject::connect(ipc, &IpcClient::systemBoostReceived, page,
                     [=](const SystemBoostResultPayload& r) {
        if (st->inflight.isNull() || r.requestId != st->inflight)
            return;
        st->inflight = QUuid();
        setBusy(false);
        refreshMemory();

        if (!r.success) {
            ui::notify(page, ui::Tone::Danger,
                       r.message.isEmpty() ? u("回收失败,服务没有给出原因。") : r.message);
            return;
        }
        if (r.freedBytes > 0) {
            resultLine->setText(u("上次回收:交还 %1 · 内存占用 %2% → %3% · 修剪 %4 个进程")
                                    .arg(fmt::bytes(r.freedBytes))
                                    .arg(r.loadBefore).arg(r.loadAfter)
                                    .arg(r.processesTrimmed));
            resultLine->show();
            ui::notify(page, ui::Tone::Success,
                       u("已交还 %1 内存(占用 %2% → %3%)。这些页在程序下次用到时会自动调回,不丢数据。")
                           .arg(fmt::bytes(r.freedBytes)).arg(r.loadBefore).arg(r.loadAfter));
        } else {
            resultLine->setText(u("上次回收:已修剪 %1 个进程,没有可交还的内存")
                                    .arg(r.processesTrimmed));
            resultLine->show();
            ui::notify(page, ui::Tone::Info,
                       u("没有可交还的内存:已修剪 %1 个进程的工作集,系统当前没有可回收的页。")
                           .arg(r.processesTrimmed));
        }
    });

    // 断线时把在途请求作废并解锁按钮 —— 回执永远不会来了,不能让按钮一直卡着。
    QObject::connect(ipc, &IpcClient::connectionChanged, page,
                     [st, setBusy, refreshMemory](bool connected) {
        if (!connected && !st->inflight.isNull()) {
            st->inflight = QUuid();
            setBusy(false);
            refreshMemory();
        }
    });

    nav::onArrive(page, QString::fromLatin1(nav::Boost),
                  [refreshMemory](const QVariantMap&) { refreshMemory(); });
    return page;
}

}
