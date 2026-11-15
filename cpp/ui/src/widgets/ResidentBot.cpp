#include "widgets/ResidentBot.h"
#include "Nav.h"
#include "design/Components.h"
#include "design/Motion.h"
#include "design/Sticker.h"
#include "design/Theme.h"

#include <QContextMenuEvent>
#include <QCursor>
#include <QEnterEvent>
#include <QFontMetricsF>
#include <QGuiApplication>
#include <QHBoxLayout>
#include <QLabel>
#include <QMenu>
#include <QMouseEvent>
#include <QPainter>
#include <QPainterPath>
#include <QPushButton>
#include <QRandomGenerator>
#include <QScreen>
#include <QSettings>
#include <QTimer>
#include <QVBoxLayout>
#include <QtMath>

#include <cmath>

namespace {

QString u(const char* s) { return QString::fromUtf8(s); }

constexpr int kBotW = 92;
constexpr int kWinW = 230;
constexpr int kBubbleH = 54;
constexpr int kEnterMs = 720;
constexpr int kBubblePopMs = 300;
constexpr int kShakeMs = 520;
constexpr int kHopMs = 460;
constexpr int kIdleMs = 1800;
constexpr int kFormMs = 820;

enum IdleAct { IdleBob, IdleBreathe, IdleGlance, IdleActCount };

// 带「戏」的心情:挥手 / 喷焰期间一直走帧。
bool moving(robot::Mood m)
{
    return m == robot::Mood::Ask || m == robot::Mood::Happy || m == robot::Mood::Boost;
}

qreal progress(qint64 now, qint64 start, int ms)
{
    if (start < 0 || ms <= 0)
        return 1.0;
    return qBound<qreal>(0.0, qreal(now - start) / ms, 1.0);
}
const QString kEnabledKey = QStringLiteral("ui/residentBot");
const QString kPosKey = QStringLiteral("ui/residentPos");
ResidentBot* g_instance = nullptr;

robot::Pose poseFor(robot::Mood m)
{
    switch (m) {
    case robot::Mood::Alert: return robot::Pose::Shield;
    case robot::Mood::Ask:
    case robot::Mood::Happy: return robot::Pose::Wave;
    case robot::Mood::Sleep: return robot::Pose::Sit;
    default: break;
    }
    return robot::Pose::Stand;
}

QString headline(robot::Mood m)
{
    const bool k = !theme::mecha();
    switch (m) {
    case robot::Mood::Alert: return u("防护关闭");
    case robot::Mood::Info:  return u("半防护");
    case robot::Mood::Sleep: return k ? u("打盹中") : u("待机");
    default: break;
    }
    return k ? u("守护中") : u("防御中");
}

// 指挥终端:鼠标停在小垒身上时递出来的小面板。
class Terminal final : public QWidget
{
public:
    Terminal()
        : QWidget(nullptr, Qt::Tool | Qt::FramelessWindowHint | Qt::WindowStaysOnTopHint
                               | Qt::WindowDoesNotAcceptFocus)
    {
        setAttribute(Qt::WA_TranslucentBackground);
        setAttribute(Qt::WA_ShowWithoutActivating);
        // 底部四个按钮并排至少要 307:再窄按钮上的字就被切掉。
        setFixedWidth(308);
        auto* v = new QVBoxLayout(this);
        v->setContentsMargins(16, 14, 20, 20);
        v->setSpacing(8);
        auto* top = new QHBoxLayout;
        top->setSpacing(8);
        title = new StickerText(u("防御中"), 22);
        top->addWidget(title, 0, Qt::AlignLeft | Qt::AlignVCenter);
        top->addStretch();
        name = ui::label(u("小垒 · BWK-01"), "caption");
        top->addWidget(name, 0, Qt::AlignVCenter);
        v->addLayout(top);
        detail = ui::label(QString(), "secondary");
        detail->setWordWrap(true);
        v->addWidget(detail);

        auto* counts = new QHBoxLayout;
        counts->setSpacing(10);
        const auto counter = [&](const QString& label, SevenSegCounter*& out, bool red) {
            auto* col = new QVBoxLayout;
            col->setSpacing(3);
            col->addWidget(ui::label(label, "caption"));
            out = new SevenSegCounter(3, 14, 22);
            out->setRedLast(red);
            col->addWidget(out);
            counts->addLayout(col);
        };
        counter(u("今日击退"), blocked, true);
        counter(u("待下令"), pending, false);
        counts->addStretch();
        v->addLayout(counts);

        auto* row = new QHBoxLayout;
        row->setSpacing(6);
        const auto key = [&](const QString& text) {
            auto* b = ui::button(text, nullptr, QString(), true);
            b->setFocusPolicy(Qt::NoFocus);
            row->addWidget(b);
            return b;
        };
        openMain = key(u("主界面"));
        radar = key(u("雷达"));
        boost = key(u("加速"));
        events = key(u("战报"));
        v->addLayout(row);
    }

    StickerText* title = nullptr;
    QLabel* name = nullptr;
    QLabel* detail = nullptr;
    SevenSegCounter* blocked = nullptr;
    SevenSegCounter* pending = nullptr;
    QPushButton* openMain = nullptr;
    QPushButton* radar = nullptr;
    QPushButton* boost = nullptr;
    QPushButton* events = nullptr;

protected:
    void paintEvent(QPaintEvent*) override
    {
        QPainter p(this);
        sticker::panel(p, QRectF(rect()).adjusted(1, 1, -2, -2), theme::surface(), 14.0, true);
        // 顶边色带 = 防护状态
        const QRectF b = sticker::bodyRect(QRectF(rect()).adjusted(1, 1, -2, -2), true);
        p.save();
        p.setClipPath(theme::panelPath(b, 14.0));
        p.fillRect(QRectF(b.left(), b.top(), b.width(), 5), theme::accent());
        p.restore();
    }
};

}

ResidentBot::ResidentBot(QWidget* parent)
    : QWidget(parent, Qt::Tool | Qt::FramelessWindowHint | Qt::WindowStaysOnTopHint
                          | Qt::WindowDoesNotAcceptFocus)
{
    g_instance = this;
    setAttribute(Qt::WA_TranslucentBackground);
    setAttribute(Qt::WA_ShowWithoutActivating);
    setAttribute(Qt::WA_QuitOnClose, false);
    setWindowTitle(u("小垒"));
    setFixedSize(kWinW, kBubbleH + robot::heightFor(kBotW, false) + 10);
    setCursor(Qt::PointingHandCursor);
    setToolTip(QString());
    m_formFrom = m_formTo = theme::titan() ? 1.0 : 0.0;

    m_blink = new QTimer(this);
    m_blink->setSingleShot(true);
    connect(m_blink, &QTimer::timeout, this, [this] {
        m_blinkNow = !m_blinkNow;
        update(robotRect().toAlignedRect());
        if (m_blinkNow)
            m_blink->start(140);
        else
            scheduleBlink();
    });

    m_ticker = new motion::Ticker(this, [this](qint64 now) {
        update();
        if (!busy(now))
            m_ticker->setActive(false);
    });
    m_idleTimer = new QTimer(this);
    m_idleTimer->setSingleShot(true);
    connect(m_idleTimer, &QTimer::timeout, this, &ResidentBot::startIdle);

    m_bubbleTimer = new QTimer(this);
    m_bubbleTimer->setSingleShot(true);
    connect(m_bubbleTimer, &QTimer::timeout, this, [this] {
        m_bubble.clear();
        syncForm();
        update();
    });

    m_hoverTimer = new QTimer(this);
    m_hoverTimer->setSingleShot(true);
    m_hoverTimer->setInterval(450);
    connect(m_hoverTimer, &QTimer::timeout, this, &ResidentBot::showTerminal);

    m_leaveWatch = new QTimer(this);
    m_leaveWatch->setInterval(250);
    connect(m_leaveWatch, &QTimer::timeout, this, [this] {
        const QPoint c = QCursor::pos();
        const bool overMe = frameGeometry().contains(c);
        const bool overTerm = m_terminal && m_terminal->isVisible() && m_terminal->frameGeometry().contains(c);
        if (!overMe && !overTerm)
            hideTerminal();
    });
}

ResidentBot::~ResidentBot()
{
    if (g_instance == this)
        g_instance = nullptr;
    delete m_terminal;
}

ResidentBot* ResidentBot::instance() { return g_instance; }

bool ResidentBot::savedEnabled() { return QSettings().value(kEnabledKey, true).toBool(); }

void ResidentBot::applySavedState()
{
    m_enabled = savedEnabled();
    const QPoint pos = QSettings().value(kPosKey).toPoint();
    if (!pos.isNull())
        move(pos);
    else
        placeDefault();
    if (m_enabled)
        show();
}

void ResidentBot::setResidentEnabled(bool on)
{
    if (on == m_enabled && isVisible() == on)
        return;
    m_enabled = on;
    QSettings().setValue(kEnabledKey, on);
    if (on) {
        clampToScreen();
        show();
    } else {
        hideTerminal();
        hide();
    }
    emit enabledChanged(on);
}

void ResidentBot::setStatus(robot::Mood mood, const QString& text, const QString& tip)
{
    m_statusMood = mood;
    m_statusText = text;
    m_statusTip = tip;
    setAccessibleName(u("小垒:") + text);
    refreshTerminal();
    kick();
    update();
}

void ResidentBot::setBlocked(int count)
{
    m_blocked = count;
    refreshTerminal();
}

void ResidentBot::setPending(int count)
{
    m_pending = count;
    if (count == 0 && m_sayMood == robot::Mood::Ask && m_bubbleTimer && !m_bubbleTimer->isActive()) {
        m_bubble.clear();
        update();
    }
    refreshTerminal();
    syncForm();
    kick();
}

void ResidentBot::say(robot::Mood mood, const QString& text, int ms)
{
    const bool fresh = !text.isEmpty() && (text != m_bubble || mood != m_sayMood);
    m_sayMood = mood;
    m_bubble = text;
    m_bubbleTimer->stop();
    if (ms > 0)
        m_bubbleTimer->start(ms);
    if (fresh && motion::enabled()) {
        // 气泡从尾巴尖弹出来;拦截时小垒抖一抖,询问 / 收到时蹦一下。
        const qint64 now = motion::clockMs();
        m_bubbleAt = now;
        if (mood == robot::Mood::Alert)
            m_shakeAt = now;
        else if (mood == robot::Mood::Ask || mood == robot::Mood::Happy)
            m_hopAt = now;
    }
    syncForm();
    kick();
    update();
}

void ResidentBot::syncForm()
{
    const bool standing = !m_bubble.isEmpty() || m_pending > 0 || (m_terminal && m_terminal->isVisible());
    const qreal want = theme::titan() && !standing ? 1.0 : 0.0;
    if (qFuzzyCompare(want + 1.0, m_formTo + 1.0))
        return;
    const qint64 now = motion::clockMs();
    m_formFrom = form(now);
    m_formTo = want;
    m_formAt = motion::enabled() ? now : -1;
    kick();
    update();
}

qreal ResidentBot::form(qint64 now) const
{
    return m_formFrom + (m_formTo - m_formFrom) * progress(now, m_formAt, kFormMs);
}

void ResidentBot::kick()
{
    if (motion::enabled() && isVisible())
        m_ticker->setActive(true);
}

bool ResidentBot::busy(qint64 now) const
{
    if (moving(mood()))
        return true;
    return progress(now, m_enterAt, kEnterMs) < 1.0 || progress(now, m_bubbleAt, kBubblePopMs) < 1.0
        || progress(now, m_shakeAt, kShakeMs) < 1.0 || progress(now, m_hopAt, kHopMs) < 1.0
        || progress(now, m_idleAt, kIdleMs) < 1.0 || progress(now, m_formAt, kFormMs) < 1.0;
}

void ResidentBot::scheduleIdle()
{
    if (!motion::enabled() || !isVisible())
        return;
    m_idleTimer->start(7000 + int(QRandomGenerator::global()->bounded(6000)));
}

void ResidentBot::startIdle()
{
    // 平时偶尔做个小动作:浮一下、宝石呼吸一次、或者往旁边瞄一眼。打盹时不动。
    if (mood() != robot::Mood::Sleep && !m_pressed) {
        m_idleKind = int(QRandomGenerator::global()->bounded(int(IdleActCount)));
        m_idleAt = motion::clockMs();
        kick();
    }
    scheduleIdle();
}

robot::Mood ResidentBot::mood() const
{
    if (!m_bubble.isEmpty())
        return m_sayMood;
    if (m_pending > 0)
        return robot::Mood::Ask;
    return m_statusMood;
}

QRectF ResidentBot::robotRect() const
{
    const int h = robot::heightFor(kBotW, false);
    return QRectF(width() - kBotW - 14, height() - h - 6, kBotW, h);
}

void ResidentBot::paintEvent(QPaintEvent*)
{
    QPainter p(this);
    p.setRenderHint(QPainter::Antialiasing, true);
    const robot::Mood m = mood();
    robot::Look lk;
    lk.mood = m;
    lk.pose = poseFor(m);
    lk.blink = m_blinkNow && m != robot::Mood::Sleep;

    const qint64 now = motion::clockMs();
    const bool anim = motion::enabled();
    lk.vehicle = form(now);
    QPointF shift;
    if (anim) {
        const qreal t = qreal(now) / 1000.0;
        if (moving(m)) {
            lk.phase = std::fmod(t / 2.4, 1.0);
            lk.pulse = 0.5 + 0.5 * std::sin(t * 2.0 * M_PI / 1.6);
        }
        // 出场:从任务栏下面喷着火升上来,到位时略微过冲。
        if (const qreal e = progress(now, m_enterAt, kEnterMs); e < 1.0) {
            shift.ry() += (1.0 - motion::outBack(e)) * robotRect().height() * 0.85;
            lk.flame = e < 0.85;
            if (lk.phase < 0)
                lk.phase = e;
        }
        if (const qreal s = progress(now, m_shakeAt, kShakeMs); s < 1.0)
            shift.rx() += std::sin(s * M_PI * 8.0) * 5.0 * (1.0 - s);
        if (const qreal h = progress(now, m_hopAt, kHopMs); h < 1.0)
            shift.ry() -= std::sin(h * M_PI) * 12.0;
        if (const qreal i = progress(now, m_idleAt, kIdleMs); i < 1.0) {
            switch (m_idleKind) {
            case IdleBob:
                shift.ry() -= std::sin(i * M_PI) * 4.0 * (0.5 - 0.5 * std::cos(i * 4.0 * M_PI));
                break;
            case IdleBreathe:
                lk.pulse = qMax(lk.pulse, std::sin(i * M_PI));
                break;
            case IdleGlance:
                lk.lookLeft = i > 0.2 && i < 0.7;
                break;
            default:
                break;
            }
        }
    }
    robot::paint(p, robotRect().translated(shift), lk);

    if (m_bubble.isEmpty())
        return;
    QFont f = sticker::headFont(10.0, 900);
    p.setFont(f);
    const QFontMetricsF fm(f);
    const qreal tw = qMin<qreal>(fm.horizontalAdvance(m_bubble), width() - 40.0);
    const QRectF rr = robotRect();
    QRectF b(0, 4, tw + 28, 34);
    b.moveRight(qMin<qreal>(width() - 4.0, rr.center().x() + 46));
    if (b.left() < 2)
        b.moveLeft(2);
    const bool k = !theme::mecha();
    QPainterPath bubble = theme::panelPath(b, k ? 14.0 : 8.0);
    QPainterPath tail;
    const qreal tx = qBound(b.left() + 16, rr.center().x() - 10, b.right() - 16);
    tail.moveTo(tx - 7, b.bottom() - 1);
    tail.lineTo(tx + 8, b.bottom() - 1);
    tail.lineTo(tx + 2, b.bottom() + 11);
    tail.closeSubpath();
    bubble = bubble.united(tail);
    if (const qreal pop = anim ? progress(now, m_bubbleAt, kBubblePopMs) : 1.0; pop < 1.0) {
        // 以尾巴尖为支点从小弹到正常大小。
        const QPointF pivot(tx + 2, b.bottom() + 11);
        const qreal s = 0.35 + 0.65 * motion::outBack(pop);
        p.translate(pivot);
        p.scale(s, s);
        p.translate(-pivot);
        p.setOpacity(qMin<qreal>(1.0, pop * 3.0));
    }
    p.fillPath(bubble.translated(theme::shadowOffset() * 0.75), theme::pal().shadow);
    const QColor fill = m == robot::Mood::Alert ? theme::pal().hazardA
                      : (k ? theme::surface() : QColor(0xFF, 0xFF, 0xFF));
    p.fillPath(bubble, fill);
    p.strokePath(bubble, QPen(theme::ink(), 2.2, Qt::SolidLine, Qt::FlatCap,
                              k ? Qt::RoundJoin : Qt::MiterJoin));
    p.setPen(theme::ink());
    p.drawText(b, Qt::AlignCenter, fm.elidedText(m_bubble, Qt::ElideRight, tw));
}

void ResidentBot::placeDefault()
{
    const QScreen* scr = QGuiApplication::primaryScreen();
    if (!scr)
        return;
    const QRect a = scr->availableGeometry();
    move(a.right() - width() - 12, a.bottom() - height() + 2);
}

void ResidentBot::clampToScreen()
{
    const QScreen* scr = QGuiApplication::screenAt(frameGeometry().center());
    if (!scr)
        scr = QGuiApplication::primaryScreen();
    if (!scr)
        return;
    const QRect a = scr->availableGeometry();
    QRect g = frameGeometry();
    g.moveLeft(qBound(a.left(), g.left(), a.right() - g.width() + 1));
    g.moveTop(qBound(a.top(), g.top(), a.bottom() - g.height() + 1));
    if (g.topLeft() != frameGeometry().topLeft())
        move(g.topLeft());
}

void ResidentBot::savePosition() { QSettings().setValue(kPosKey, pos()); }

void ResidentBot::showEvent(QShowEvent* e)
{
    QWidget::showEvent(e);
    clampToScreen();
    scheduleBlink();
    if (motion::enabled()) {
        m_enterAt = motion::clockMs();
        kick();
    }
    scheduleIdle();
}

void ResidentBot::hideEvent(QHideEvent* e)
{
    QWidget::hideEvent(e);
    m_blink->stop();
    m_blinkNow = false;
    m_ticker->setActive(false);
    m_idleTimer->stop();
    hideTerminal();
}

void ResidentBot::scheduleBlink()
{
    if (!motion::enabled() || !isVisible())
        return;
    m_blink->start(2800 + int(QRandomGenerator::global()->bounded(3400)));
}

void ResidentBot::mousePressEvent(QMouseEvent* e)
{
    if (e->button() == Qt::LeftButton) {
        m_pressed = true;
        m_dragged = false;
        m_pressGlobal = e->globalPosition().toPoint();
        m_pressPos = pos();
        hideTerminal();
        m_hoverTimer->stop();
    }
    QWidget::mousePressEvent(e);
}

void ResidentBot::mouseMoveEvent(QMouseEvent* e)
{
    if (m_pressed && (e->buttons() & Qt::LeftButton)) {
        const QPoint d = e->globalPosition().toPoint() - m_pressGlobal;
        if (m_dragged || d.manhattanLength() > 4) {
            m_dragged = true;
            move(m_pressPos + d);
        }
    }
    QWidget::mouseMoveEvent(e);
}

void ResidentBot::mouseReleaseEvent(QMouseEvent* e)
{
    if (e->button() == Qt::LeftButton && m_pressed) {
        m_pressed = false;
        if (m_dragged) {
            clampToScreen();
            savePosition();
        } else {
            showTerminal();
        }
    }
    QWidget::mouseReleaseEvent(e);
}

void ResidentBot::mouseDoubleClickEvent(QMouseEvent* e)
{
    if (e->button() == Qt::LeftButton) {
        hideTerminal();
        emit radarRequested();
        e->accept();
        return;
    }
    QWidget::mouseDoubleClickEvent(e);
}

void ResidentBot::contextMenuEvent(QContextMenuEvent* e)
{
    hideTerminal();
    QMenu menu;
    menu.addAction(u("打开主界面"), this, &ResidentBot::openMainRequested);
    menu.addAction(u("雷达模式(流量表)"), this, &ResidentBot::radarRequested);
    menu.addAction(u("一键加速"), this, [this] { emit pageRequested(QString::fromLatin1(nav::Boost)); });
    menu.addAction(u("查看战报"), this, [this] { emit pageRequested(QString::fromLatin1(nav::Events)); });
    menu.addSeparator();
    menu.addAction(u("回到右下角"), this, [this] {
        placeDefault();
        savePosition();
    });
    menu.addAction(u("收起小垒"), this, [this] { setResidentEnabled(false); });
    menu.exec(e->globalPos());
}

void ResidentBot::enterEvent(QEnterEvent* e)
{
    QWidget::enterEvent(e);
    if (!m_pressed)
        m_hoverTimer->start();
}

void ResidentBot::leaveEvent(QEvent* e)
{
    QWidget::leaveEvent(e);
    m_hoverTimer->stop();
}

void ResidentBot::showTerminal()
{
    if (!isVisible())
        return;
    if (!m_terminal) {
        auto* t = new Terminal;
        connect(t->openMain, &QPushButton::clicked, this, [this] {
            hideTerminal();
            emit openMainRequested();
        });
        connect(t->radar, &QPushButton::clicked, this, [this] {
            hideTerminal();
            emit radarRequested();
        });
        connect(t->boost, &QPushButton::clicked, this, [this] {
            hideTerminal();
            emit pageRequested(QString::fromLatin1(nav::Boost));
        });
        connect(t->events, &QPushButton::clicked, this, [this] {
            hideTerminal();
            emit pageRequested(QString::fromLatin1(nav::Events));
        });
        m_terminal = t;
    }
    refreshTerminal();
    QWidget* t = m_terminal;
    t->adjustSize();
    const QScreen* scr = QGuiApplication::screenAt(frameGeometry().center());
    if (!scr)
        scr = QGuiApplication::primaryScreen();
    const QRect a = scr ? scr->availableGeometry() : QRect();
    QPoint at(frameGeometry().left() + int(robotRect().left()) - t->width() + 18,
              frameGeometry().bottom() - t->height() - 6);
    if (a.isValid()) {
        if (at.x() < a.left())
            at.setX(frameGeometry().right() - 10);
        at.setX(qBound(a.left(), at.x(), a.right() - t->width() + 1));
        at.setY(qBound(a.top(), at.y(), a.bottom() - t->height() + 1));
    }
    t->move(at);
    t->show();
    t->raise();
    m_leaveWatch->start();
    syncForm();
}

void ResidentBot::hideTerminal()
{
    m_leaveWatch->stop();
    if (m_terminal)
        m_terminal->hide();
    syncForm();
}

void ResidentBot::refreshTerminal()
{
    auto* t = static_cast<Terminal*>(m_terminal.data());
    if (!t)
        return;
    t->title->setText(headline(m_statusMood));
    t->detail->setText(m_statusText.isEmpty() ? m_statusTip : m_statusText + u("\n") + m_statusTip);
    t->blocked->setValue(m_blocked);
    t->pending->setValue(m_pending);
    t->adjustSize();
}
