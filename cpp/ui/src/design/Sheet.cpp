#include "design/Sheet.h"
#include "design/Banner.h"
#include "design/Components.h"
#include "design/GlowCard.h"
#include "design/IconTile.h"
#include "design/Motion.h"
#include "design/Robot.h"
#include "design/Sticker.h"
#include "design/Theme.h"

#include <QCoreApplication>
#include <QCursor>
#include <QEvent>
#include <QGuiApplication>
#include <QHBoxLayout>
#include <QKeyEvent>
#include <QLabel>
#include <QMouseEvent>
#include <QPainter>
#include <QPropertyAnimation>
#include <QPushButton>
#include <QScreen>
#include <QTimer>
#include <QToolButton>
#include <QVariantAnimation>
#include <QVBoxLayout>
#include <QtMath>

#include <cmath>

namespace {
constexpr int kShell = 24;
constexpr int kCornerInset = 15;

constexpr int kEnterMs = 180;
constexpr int kExitMs = 140;
constexpr int kRise = 14;
constexpr int kSlide = 32;

class Ghost final : public QWidget
{
public:
    Ghost(const QPixmap& shot, const QPoint& at, const QPoint& travel, int ms)
        : QWidget(nullptr, Qt::FramelessWindowHint | Qt::Tool | Qt::WindowStaysOnTopHint), m_shot(shot)
    {
        setAttribute(Qt::WA_TranslucentBackground);
        setAttribute(Qt::WA_TransparentForMouseEvents);
        setAttribute(Qt::WA_ShowWithoutActivating);
        setAttribute(Qt::WA_DeleteOnClose);
        setFocusPolicy(Qt::NoFocus);
        setFixedSize(shot.deviceIndependentSize().toSize());
        move(at);
        show();

        auto* fade = new QPropertyAnimation(this, "windowOpacity", this);
        fade->setDuration(ms);
        fade->setStartValue(1.0);
        fade->setEndValue(0.0);
        auto* slide = new QPropertyAnimation(this, "pos", this);
        slide->setDuration(ms);
        slide->setEasingCurve(QEasingCurve::InCubic);
        slide->setStartValue(at);
        slide->setEndValue(at + travel);
        connect(fade, &QPropertyAnimation::finished, this, &QObject::deleteLater);
        fade->start();
        slide->start();
    }

protected:
    void paintEvent(QPaintEvent*) override
    {
        QPainter p(this);
        p.drawPixmap(0, 0, m_shot);
    }

private:
    QPixmap m_shot;
};

class Strip : public QWidget
{
public:
    explicit Strip(QWidget* parent = nullptr) : QWidget(parent) { setFixedSize(14, 12); }
    QColor color = theme::accent();
    qreal glow = 0.0;

protected:
    void paintEvent(QPaintEvent*) override
    {
        QPainter p(this);
        p.setRenderHint(QPainter::Antialiasing, true);
        sticker::lamp(p, QRectF(rect()).adjusted(0.5, 0.5, -0.5, -0.5),
                      glow > 0.0 ? theme::blend(theme::soft(color), color, glow) : color);
    }
};
}

Sheet::Sheet(QWidget* parent) : QDialog(parent)
{
    setWindowFlags(Qt::Dialog | Qt::FramelessWindowHint);
    setAttribute(Qt::WA_TranslucentBackground);
    setModal(true);

    auto* shell = new QVBoxLayout(this);
    shell->setContentsMargins(kShell, kShell, kShell, kShell);
    m_card = ui::floatingCard();
    shell->addWidget(m_card);

    auto* v = new QVBoxLayout(m_card);
    v->setContentsMargins(24, 20, 24, 20);
    v->setSpacing(14);

    m_eyebrowRow = new QWidget;
    auto* er = new QHBoxLayout(m_eyebrowRow);
    er->setContentsMargins(0, 0, 0, 0);
    er->setSpacing(8);
    auto* strip = new Strip;
    m_strip = strip;
    er->addWidget(strip, 0, Qt::AlignVCenter);
    m_eyebrow = ui::eyebrow(QString());
    er->addWidget(m_eyebrow, 1, Qt::AlignVCenter);
    m_eyebrowRow->hide();
    v->addWidget(m_eyebrowRow);

    auto* head = new QHBoxLayout;
    head->setContentsMargins(0, 0, 0, 0);
    head->setSpacing(14);
    m_tile = new IconTile(QStringLiteral("info"), theme::accent(), 42, 21);
    m_tile->hide();
    head->addWidget(m_tile, 0, Qt::AlignTop);
    auto* tc = new QVBoxLayout;
    tc->setSpacing(3);
    m_title = ui::label(QString(), "h2");
    m_title->setWordWrap(true);
    m_title->setTextInteractionFlags(Qt::TextSelectableByMouse);
    m_subtitle = ui::label(QString(), "secondary");
    m_subtitle->setWordWrap(true);
    m_subtitle->hide();
    tc->addWidget(m_title);
    tc->addWidget(m_subtitle);
    head->addLayout(tc, 1);
    m_close = ui::iconButton(QStringLiteral("close"), QString::fromUtf8("关闭 (Esc)"), theme::textMuted(), 16);
    m_close->setFocusPolicy(Qt::NoFocus);
    connect(m_close, &QToolButton::clicked, this, &QDialog::reject);
    head->addWidget(m_close, 0, Qt::AlignTop);
    v->addLayout(head);

    m_banners = new BannerHost;
    v->addWidget(m_banners);

    m_body = new QVBoxLayout;
    m_body->setContentsMargins(0, 0, 0, 0);
    m_body->setSpacing(12);
    v->addLayout(m_body, 1);

    m_footerHost = new QWidget;
    m_footer = new QHBoxLayout(m_footerHost);
    m_footer->setContentsMargins(0, 4, 0, 0);
    m_footer->setSpacing(10);
    m_footer->addStretch(1);
    v->addWidget(m_footerHost);

    m_fade = new QPropertyAnimation(this, "windowOpacity", this);
    m_move = new QPropertyAnimation(this, "pos", this);
    m_move->setEasingCurve(QEasingCurve::OutCubic);

    setSheetWidth(520);
}

void Sheet::setHeader(const QString& icon, const QColor& tone, const QString& title, const QString& subtitle)
{
    if (!icon.isEmpty()) {
        m_tile->set(icon, tone);
        m_tile->show();
    } else {
        m_tile->hide();
    }
    setTitle(title);
    setSubtitle(subtitle);
    if (tone.isValid())
        setGlow(tone);
}

void Sheet::setEyebrow(const QString& text, const QColor& color)
{
    m_eyebrow->setText(text);
    if (m_hazard.isValid()) {
        // 贴在斑马带上的标签胶带。金刚的输入底色是暗的,胶带改用亮色字 + 亮一档的边。
        const QColor tapeInk = theme::titan() ? theme::textPrimary() : theme::ink();
        m_eyebrow->setStyleSheet(QStringLiteral("color:%1; background:%2; border:2px solid %4; border-radius:%3px;"
                                                "padding:2px 10px; font-weight:900;")
                                     .arg(tapeInk.name(), theme::field().name())
                                     .arg(theme::mecha() ? 2 : 10)
                                     .arg(theme::titan() ? theme::rim().name() : tapeInk.name()));
    } else {
        m_eyebrow->setStyleSheet(QStringLiteral("color:%1;").arg(color.name()));
    }
    static_cast<Strip*>(m_strip)->color = color;
    m_strip->update();
    m_eyebrowRow->setVisible(!text.isEmpty());
    syncDecor();
}

void Sheet::setHazard(const QColor& color)
{
    m_hazard = color;
    m_strip->hide();
    // 标签胶带只包住文字,不铺满整行。
    if (auto* er = qobject_cast<QHBoxLayout*>(m_eyebrowRow->layout())) {
        er->setStretchFactor(m_eyebrow, 0);
        if (er->count() < 3)
            er->addStretch(1);
    }
    if (auto* l = qobject_cast<QVBoxLayout*>(m_card->layout()))
        l->setContentsMargins(22, 12, 22, 20);
    if (!m_eyebrow->text().isEmpty())
        setEyebrow(m_eyebrow->text(), color);
    syncDecor();
}

void Sheet::setMascot(int mood)
{
    robot::Look look;
    look.mood = robot::Mood(mood);
    look.pose = look.mood == robot::Mood::Alert ? robot::Pose::Shield
              : look.mood == robot::Mood::Ask   ? robot::Pose::Wave
                                                : robot::Pose::Stand;
    look.shadow = false;
    if (!m_mascot) {
        auto* bot = new RobotWidget(82, look, this);
        bot->setAttribute(Qt::WA_TransparentForMouseEvents);
        bot->setAutoBlink(true);
        bot->setAnimated(true);
        m_mascot = bot;
        if (QLayout* l = layout())
            l->setContentsMargins(kShell, kShell + bot->sizeHint().height() - 46, kShell, kShell);
    } else {
        static_cast<RobotWidget*>(m_mascot)->setLook(look);
    }
    m_mascot->resize(m_mascot->sizeHint());
    if (!m_mascotPending)
        m_mascot->show();
    syncDecor();
}

QPoint Sheet::mascotRest() const
{
    const QRect c = m_card->geometry();
    return QPoint(c.right() - m_mascot->width() - 34, c.top() - m_mascot->height() + 46);
}

void Sheet::syncDecor()
{
    if (m_hazard.isValid()) {
        const int h = m_eyebrowRow->isVisible() ? m_eyebrowRow->geometry().bottom() + 12 : 14;
        m_card->setBand(m_hazard, qMax(14, h));
    }
    if (m_mascot) {
        if (m_mascotDrop && m_mascotDrop->state() == QAbstractAnimation::Running)
            m_mascotDrop->setEndValue(mascotRest());
        else if (!m_mascotPending)
            m_mascot->move(mascotRest());
        m_mascot->raise();
    }
}

void Sheet::dropMascot()
{
    // 卡片升起之后,小垒从上方跳到卡片边沿:机甲是沉重落地的回弹,卡哇伊是蹦两下。
    if (!m_mascot)
        return;
    m_mascotPending = false;
    const QPoint rest = mascotRest();
    if (!m_mascotDrop) {
        m_mascotDrop = new QPropertyAnimation(m_mascot, "pos", this);
        m_mascotDrop->setDuration(theme::mecha() ? 460 : 620);
        m_mascotDrop->setEasingCurve(theme::mecha() ? QEasingCurve::OutBack : QEasingCurve::OutBounce);
    }
    // 起点不能高过窗口顶边(上方只有一圈阴影边距),否则头会被裁掉。
    const QPoint from(rest.x(), qMax(0, rest.y() - 30));
    m_mascotDrop->stop();
    m_mascotDrop->setStartValue(from);
    m_mascotDrop->setEndValue(rest);
    m_mascot->move(from);
    m_mascot->show();
    m_mascot->raise();
    m_mascotDrop->start();
}

void Sheet::resizeEvent(QResizeEvent* e)
{
    QDialog::resizeEvent(e);
    syncDecor();
}

void Sheet::setPulse(bool on)
{
    m_pulseWanted = on;
    if (on && !m_pulse) {
        m_pulse = new QVariantAnimation(this);
        m_pulse->setStartValue(0.0);
        m_pulse->setEndValue(1.0);
        m_pulse->setDuration(1600);
        m_pulse->setLoopCount(-1);
        connect(m_pulse, &QVariantAnimation::valueChanged, this, [this](const QVariant& v) {
            static_cast<Strip*>(m_strip)->glow = 0.5 - 0.5 * std::cos(v.toReal() * 2.0 * M_PI);
            m_strip->update();
        });
    }
    syncPulse();
}

void Sheet::syncPulse()
{
    if (m_hazard.isValid() && motion::enabled()) {
        if (!m_march) {
            // 斑马带缓缓向右推进;高风险(带呼吸灯)时走得快一倍。
            m_march = new motion::Ticker(this, [this](qint64 now) {
                m_card->setBandOffset(qreal(now) * (m_pulseWanted ? 0.042 : 0.021));
            }, 33);
        }
        m_march->setActive(isVisible());
    }
    if (!m_pulse)
        return;
    const bool run = m_pulseWanted && motion::enabled() && motion::onScreen(this);
    if (run == (m_pulse->state() == QAbstractAnimation::Running))
        return;
    if (run) {
        m_pulse->start();
        return;
    }
    m_pulse->stop();
    static_cast<Strip*>(m_strip)->glow = 0.0;
    m_strip->update();
}

void Sheet::setTitle(const QString& title)
{
    m_title->setText(title);
    setWindowTitle(title);
    setAccessibleName(title);
}

void Sheet::setSubtitle(const QString& subtitle)
{
    m_subtitle->setText(subtitle);
    m_subtitle->setVisible(!subtitle.isEmpty());
}

void Sheet::setGlow(const QColor& color)
{
    if (color.isValid())
        m_card->setGlow(color, QPointF(0.0, 0.0), 0.85, 0.13);
    else
        m_card->clearGlow();
}

void Sheet::setSheetWidth(int width)
{
    setFixedWidth(width + 2 * kShell);
}

void Sheet::setClosable(bool closable)
{
    m_closable = closable;
    m_close->setVisible(closable);
}

void Sheet::setCloseButtonVisible(bool visible)
{
    m_close->setVisible(visible);
}

void Sheet::refit()
{
    settleEnter();
    const bool anchorBottom = m_placed && m_placement == Placement::BottomRight;
    const int bottom = frameGeometry().bottom();
    QTimer::singleShot(0, this, [this, anchorBottom, bottom] {
        for (int i = 0; i < 3; ++i)
            QCoreApplication::sendPostedEvents(nullptr, QEvent::LayoutRequest);
        if (QLayout* l = layout())
            l->invalidate();
        fitHeight();
        const QScreen* scr = screen();
        if (!scr)
            return;
        const QRect avail = scr->availableGeometry();
        QRect g = frameGeometry();
        if (anchorBottom)
            g.moveBottom(bottom);
        if (g.bottom() > avail.bottom())
            g.moveBottom(avail.bottom());
        if (g.top() < avail.top())
            g.moveTop(avail.top());
        move(g.topLeft());
        m_restPos = pos();
    });
}

void Sheet::fitHeight()
{
    QLayout* l = layout();
    if (!l) {
        adjustSize();
        return;
    }
    l->activate();
    const int w = width();
    int h = l->hasHeightForWidth() ? l->totalHeightForWidth(w) : l->totalSizeHint().height();
    h = qMax(h, l->totalMinimumSize().height());
    const QScreen* scr = screen();
    if (!scr)
        scr = QGuiApplication::primaryScreen();
    if (scr)
        h = qMin(h, scr->availableGeometry().height());
    resize(w, h);
}

void Sheet::addFooterLeft(QWidget* w)
{
    m_footer->insertWidget(m_footerLeft++, w);
}

QPushButton* Sheet::addButton(const QString& text, const char* variant, std::function<void()> fn)
{
    auto* b = ui::button(text, variant);
    b->setMinimumWidth(96);
    if (fn)
        connect(b, &QPushButton::clicked, this, [fn = std::move(fn)] { fn(); });
    m_footer->addWidget(b);
    return b;
}

int Sheet::screenHeightFor(const QWidget* anchor, qreal fraction)
{
    const QScreen* scr = anchor ? anchor->screen() : nullptr;
    if (!scr)
        scr = QGuiApplication::screenAt(QCursor::pos());
    if (!scr)
        scr = QGuiApplication::primaryScreen();
    const int h = scr ? scr->availableGeometry().height() : 900;
    return int(h * fraction);
}

void Sheet::placeOnScreen()
{
    fitHeight();
    if (m_placement == Placement::BottomRight) {
        // 角落卡片出现在用户此刻正在用的那块屏幕(鼠标所在的屏)上;多屏时固定落在主屏,
        // 人正看着副屏的话,一条带倒计时的询问会在没人看见的地方走完。
        const QScreen* scr = QGuiApplication::screenAt(QCursor::pos());
        if (!scr)
            scr = QGuiApplication::primaryScreen();
        if (!scr)
            return;
        const QRect avail = scr->availableGeometry();
        // Never taller than the screen: the footer (the answer buttons) must stay reachable.
        if (height() > avail.height())
            resize(width(), avail.height());
        QRect g(QPoint(0, 0), size());
        g.moveBottomRight(QPoint(avail.right() - kCornerInset, avail.bottom() - kCornerInset));
        g.moveLeft(qMax(avail.left(), g.left()));
        g.moveTop(qMax(avail.top(), g.top()));
        move(g.topLeft());
        return;
    }
    const QWidget* anchor = parentWidget() ? parentWidget()->window() : nullptr;
    QScreen* scr = nullptr;
    QRect target;
    if (anchor && anchor->isVisible() && !anchor->isMinimized()) {
        target = anchor->frameGeometry();
        scr = anchor->screen();
    } else {
        scr = QGuiApplication::screenAt(QCursor::pos());
        if (!scr)
            scr = QGuiApplication::primaryScreen();
        if (scr)
            target = scr->availableGeometry();
    }
    if (!scr)
        return;
    const QRect avail = scr->availableGeometry();
    // Never taller than the screen: the footer (the answer buttons) must stay reachable.
    if (height() > avail.height())
        resize(width(), avail.height());
    QRect g(QPoint(0, 0), size());
    g.moveCenter(target.center());
    g.moveLeft(qBound(avail.left(), g.left(), avail.right() - g.width() + 1));
    g.moveTop(qBound(avail.top(), g.top(), avail.bottom() - g.height() + 1));
    move(g.topLeft());
}

void Sheet::showEvent(QShowEvent* e)
{
    if (!m_placed) {
        m_placed = true;
        if (!focusWidget()) {
            const auto usable = [this](QPushButton* b) {
                return b && b->isEnabled() && b->isVisibleTo(this);
            };
            QPushButton* target = nullptr;
            for (QPushButton* b : findChildren<QPushButton*>())
                if (b->isDefault() && usable(b))
                    target = b;
            for (int i = m_footer->count() - 1; !target && i >= 0; --i)
                if (auto* b = qobject_cast<QPushButton*>(m_footer->itemAt(i)->widget()); usable(b))
                    target = b;
            if (target)
                target->setFocus(Qt::OtherFocusReason);
        }
        placeOnScreen();
        startEnter();
        if (m_mascot && motion::enabled()) {
            m_mascotPending = true;
            m_mascot->hide();
            QTimer::singleShot(kEnterMs + 60, this, &Sheet::dropMascot);
        }
    }
    QDialog::showEvent(e);
    syncPulse();
    QTimer::singleShot(0, this, &Sheet::syncDecor);
}

void Sheet::hideEvent(QHideEvent* e)
{
    QDialog::hideEvent(e);
    syncPulse();
}

QPoint Sheet::travel() const
{
    return m_placement == Placement::BottomRight ? QPoint(kSlide, 0) : QPoint(0, kRise);
}

void Sheet::startEnter()
{
    m_restPos = pos();
    const int ms = motion::duration(kEnterMs);
    if (ms <= 0)
        return;
    m_entering = true;
    setWindowOpacity(0.0);
    move(m_restPos + travel());
    m_fade->stop();
    m_fade->setDuration(ms);
    m_fade->setStartValue(0.0);
    m_fade->setEndValue(1.0);
    m_fade->start();
    m_move->stop();
    m_move->setDuration(ms);
    m_move->setStartValue(pos());
    m_move->setEndValue(m_restPos);
    m_move->start();
}

void Sheet::settleEnter()
{
    if (!m_entering)
        return;
    m_entering = false;
    m_fade->stop();
    m_move->stop();
    setWindowOpacity(1.0);
    move(m_restPos);
}

void Sheet::done(int result)
{
    playExit();
    QDialog::done(result);
}

void Sheet::playExit()
{
    settleEnter();
    const int ms = motion::duration(kExitMs);
    if (ms <= 0 || !isVisible() || !motion::onScreen(this))
        return;
    const qreal dpr = devicePixelRatioF();
    QPixmap shot(int(std::ceil(width() * dpr)), int(std::ceil(height() * dpr)));
    shot.setDevicePixelRatio(dpr);
    shot.fill(Qt::transparent);
    render(&shot, QPoint(), QRegion(), QWidget::DrawChildren);
    new Ghost(shot, pos(), travel(), ms);
}

void Sheet::keyPressEvent(QKeyEvent* e)
{
    if (e->key() == Qt::Key_Escape && !m_closable) {
        e->accept();
        return;
    }
    QDialog::keyPressEvent(e);
}

void Sheet::mousePressEvent(QMouseEvent* e)
{
    if (e->button() == Qt::LeftButton) {
        settleEnter();
        m_dragging = true;
        m_dragOffset = e->globalPosition().toPoint() - frameGeometry().topLeft();
        e->accept();
        return;
    }
    QDialog::mousePressEvent(e);
}

void Sheet::mouseMoveEvent(QMouseEvent* e)
{
    if (m_dragging && (e->buttons() & Qt::LeftButton)) {
        move(e->globalPosition().toPoint() - m_dragOffset);
        m_restPos = pos();
        e->accept();
        return;
    }
    QDialog::mouseMoveEvent(e);
}

void Sheet::mouseReleaseEvent(QMouseEvent* e)
{
    m_dragging = false;
    QDialog::mouseReleaseEvent(e);
}
