#include "dialogs/ToastWindow.h"
#include "design/Components.h"
#include "design/CountdownBar.h"
#include "design/FlowLayout.h"
#include "design/Motion.h"
#include "design/Robot.h"
#include "design/Sticker.h"
#include "design/Theme.h"
#include "widgets/ElidingLabel.h"
#include "widgets/WrapLabel.h"

#include <QEvent>
#include <QHBoxLayout>
#include <QLabel>
#include <QPainter>
#include <QPropertyAnimation>
#include <QPushButton>
#include <QTime>
#include <QTimer>
#include <QToolButton>
#include <QVariantAnimation>
#include <QVBoxLayout>
#include <QtMath>

#include <cmath>

namespace {

QString u(const char* s) { return QString::fromUtf8(s); }

constexpr int kBandH = 38;

struct Look {
    QColor color;          // 语义色:钢印、威胁类型胶囊
    robot::Mood mood;
};

Look lookFor(ToastWindow::Kind k)
{
    switch (k) {
    case ToastWindow::Kind::Block:             return {theme::danger(), robot::Mood::Alert};
    case ToastWindow::Kind::BlockAlertedOnly:  return {theme::warning(), robot::Mood::Ask};
    case ToastWindow::Kind::BlockFailed:       return {theme::warning(), robot::Mood::Alert};
    case ToastWindow::Kind::Info:              return {theme::info(), robot::Mood::Info};
    case ToastWindow::Kind::Cleanup:           return {theme::accentDeep(), robot::Mood::Happy};
    case ToastWindow::Kind::CleanupIncomplete: return {theme::warning(), robot::Mood::Think};
    }
    return {theme::info(), robot::Mood::Info};
}

// 战报标题带的颜色:红 = 拦截战报,黄 = 告警(仅记录),橙 / 薄荷 = 清场,石墨 / 薰衣草 = 通报。
QColor bandFor(ToastWindow::Kind k)
{
    const bool m = theme::mecha();
    // 金刚的卡片是暗的:石墨色的通报带会和卡片糊在一起,改用机身钴蓝;清场用青绿。
    if (theme::titan()) {
        if (k == ToastWindow::Kind::Info)
            return theme::pal().structure;
        if (k == ToastWindow::Kind::Cleanup)
            return theme::teal();
    }
    switch (k) {
    case ToastWindow::Kind::Block:             return m ? QColor(0xE5, 0x38, 0x3B) : QColor(0xFF, 0x8E, 0x8E);
    case ToastWindow::Kind::BlockAlertedOnly:  return m ? QColor(0xFF, 0xCF, 0x33) : QColor(0xFF, 0xD9, 0x6B);
    case ToastWindow::Kind::BlockFailed:
    case ToastWindow::Kind::CleanupIncomplete: return m ? QColor(0xC7, 0x77, 0x12) : QColor(0xFF, 0xB3, 0x7A);
    case ToastWindow::Kind::Cleanup:           return m ? QColor(0xFF, 0x6A, 0x13) : QColor(0x7F, 0xE3, 0xC6);
    case ToastWindow::Kind::Info:              break;
    }
    return m ? QColor(0x33, 0x32, 0x2F) : QColor(0xB9, 0xA6, 0xFF);
}

}

ToastWindow::ToastWindow(Kind kind, const QString& heading, const QString& sentence,
                         const QString& meta, const QStringList& tags, int lifetimeMs,
                         const QString& badgeText, const QString& actionText, QWidget* parent)
    : QWidget(parent), m_lifetimeMs(lifetimeMs)
{
    setWindowFlags(Qt::FramelessWindowHint | Qt::Tool | Qt::WindowStaysOnTopHint);
    setAttribute(Qt::WA_TranslucentBackground);
    setAttribute(Qt::WA_ShowWithoutActivating);
    setFixedWidth(kDefaultCardWidth);

    const Look look = lookFor(kind);
    m_accent = look.color;
    const QColor band = bandFor(kind);
    const QColor onBand = theme::textOn(band);

    auto* shell = new QVBoxLayout(this);
    shell->setContentsMargins(16, 12, 16, 16);

    // 战报卡牌:顶上一条实色标题带(颜色 = 战报类型),小垒的头 + 标题;正文右上角盖钢印。
    auto* cardW = ui::floatingCard();
    cardW->setBand(band, kBandH, false);
    shell->addWidget(cardW);

    auto* v = new QVBoxLayout(cardW);
    v->setContentsMargins(0, 0, 0, 0);
    v->setSpacing(0);

    auto* headRow = new QWidget;
    headRow->setFixedHeight(kBandH);
    auto* hh = new QHBoxLayout(headRow);
    hh->setContentsMargins(12, 2, 8, 2);
    hh->setSpacing(8);
    robot::Look bl;
    bl.head = true;
    bl.extras = false;
    bl.mood = look.mood;
    m_bot = new RobotWidget(30, bl);
    m_bot->setAnimated(true);
    hh->addWidget(m_bot, 0, Qt::AlignVCenter);
    auto* headingLabel = new ElidingLabel(heading);
    headingLabel->setStyleSheet(QStringLiteral("color:%1; font-size:10.5pt; font-weight:900;").arg(onBand.name()));
    hh->addWidget(headingLabel, 1, Qt::AlignVCenter);
    auto* when = new QLabel(QTime::currentTime().toString(QStringLiteral("HH:mm")));
    when->setFont(sticker::labelFont(8.5));
    when->setStyleSheet(QStringLiteral("color:%1;").arg(theme::tint(onBand, 0.8).name(QColor::HexArgb)));
    hh->addWidget(when, 0, Qt::AlignVCenter);
    auto* close = ui::iconButton(QStringLiteral("close"), u("关闭通知"), onBand, 14);
    close->setFocusPolicy(Qt::NoFocus);
    connect(close, &QToolButton::clicked, this, &ToastWindow::beginClose);
    hh->addWidget(close, 0, Qt::AlignVCenter);
    v->addWidget(headRow);

    auto* row = new QHBoxLayout;
    row->setContentsMargins(16, 10, 12, 0);
    row->setSpacing(10);

    auto* col = new QVBoxLayout;
    col->setSpacing(4);

    auto* sentenceLabel = new WrapLabel(sentence);
    sentenceLabel->setProperty("role", "title");
    sentenceLabel->setVisible(!sentence.isEmpty());
    col->addWidget(sentenceLabel);
    m_threatRow = new HeightForWidthBox;
    auto* threatRow = new QHBoxLayout(m_threatRow);
    threatRow->setContentsMargins(0, 2, 0, 2);
    threatRow->setSpacing(8);
    threatRow->addWidget(ui::label(u("威胁类型"), "caption"), 0, Qt::AlignVCenter);
    m_threatPill = ui::pill(QString(), look.color);
    threatRow->addWidget(m_threatPill, 0, Qt::AlignVCenter);
    m_threatName = ui::elided(QString(), "secondary");
    m_threatName->hide();
    threatRow->addWidget(m_threatName, 1, Qt::AlignVCenter);
    threatRow->addStretch();
    m_threatRow->hide();
    col->addWidget(m_threatRow);
    auto* metaLabel = new WrapLabel(meta);
    metaLabel->setProperty("role", "muted");
    metaLabel->setVisible(!meta.isEmpty());
    col->addWidget(metaLabel);
    if (!tags.isEmpty()) {
        auto* tw = new HeightForWidthBox;
        auto* flow = new FlowLayout(tw, 6, 6);
        flow->setContentsMargins(0, 2, 0, 0);
        int shown = 0;
        for (const QString& t : tags) {
            if (shown++ >= 4)
                break;
            flow->addWidget(ui::pill(t, theme::info()));
        }
        if (tags.size() > 4)
            flow->addWidget(ui::pill(QStringLiteral("+%1").arg(tags.size() - 4), theme::textSecondary()));
        col->addWidget(tw);
    }
    m_codeSlot = new HeightForWidthBox;
    auto* codeLay = new QVBoxLayout(m_codeSlot);
    codeLay->setContentsMargins(0, 4, 0, 2);
    codeLay->setSpacing(0);
    m_codeSlot->hide();
    col->addWidget(m_codeSlot);
    m_insightSlot = new HeightForWidthBox;
    auto* insight = new QVBoxLayout(m_insightSlot);
    insight->setContentsMargins(0, 4, 0, 0);
    insight->setSpacing(0);
    m_insightSlot->hide();
    col->addWidget(m_insightSlot);
    m_actions = new QHBoxLayout;
    m_actions->setSpacing(8);
    if (!actionText.isEmpty()) {
        auto* act = ui::button(actionText, "primary", QString(), true);
        act->setFocusPolicy(Qt::NoFocus);
        connect(act, &QPushButton::clicked, this, [this] {
            emit clicked(this);
            beginClose();
        });
        m_actions->addWidget(act);
    }
    m_actions->addStretch(1);
    // 按钮行不跟钢印挤在同一列里:独占卡片整行,412 宽的通知也放得下两个按钮。
    m_actions->setContentsMargins(16, actionText.isEmpty() ? 0 : 12, 12, 8);
    row->addLayout(col, 1);
    if (!badgeText.isEmpty()) {
        // 布局里只占钢印本身的位置;真正的钢印是个更大的浮层,盖章时从放大状态砸下来。
        m_stamp = new StampLabel(badgeText, look.color, kind == Kind::Info ? 4.0 : -7.0, 15.0, cardW);
        m_stampHole = new QWidget;
        m_stampHole->setFixedSize(m_stamp->sizeHint());
        m_stampHole->setAttribute(Qt::WA_TransparentForMouseEvents);
        m_stampHole->installEventFilter(this);
        m_stamp->setOverscan(2.3);
        m_stamp->resize(m_stamp->sizeHint());
        row->addWidget(m_stampHole, 0, Qt::AlignTop);
    }
    m_card = cardW;
    v->addLayout(row);
    v->addLayout(m_actions);

    m_bar = new CountdownBar;
    m_bar->setColor(band);
    m_bar->setHoverPause(cardW);
    auto* barRow = new QHBoxLayout;
    barRow->setContentsMargins(16, 0, 16, 12);
    barRow->addWidget(m_bar);
    v->addLayout(barRow);
    connect(m_bar, &CountdownBar::finished, this, &ToastWindow::onCountdownFinished);

    setAccessibleName(heading);
    m_description = sentence + (meta.isEmpty() ? QString() : u("。") + meta);
    setAccessibleDescription(m_description);
    refitHeight();

    m_fade = new QPropertyAnimation(this, "windowOpacity", this);
    m_slide = new QPropertyAnimation(this, "pos", this);
    m_slide->setDuration(motion::duration(220));
    m_slide->setEasingCurve(QEasingCurve::OutCubic);
}

void ToastWindow::setSecondaryAction(const QString& text)
{
    if (text.isEmpty() || !m_actions)
        return;
    auto* b = ui::button(text, "ghost", QString(), true);
    b->setFocusPolicy(Qt::NoFocus);
    connect(b, &QPushButton::clicked, this, [this] {
        emit secondaryClicked(this);
        beginClose();
    });
    m_actions->insertWidget(m_actions->count() - 1, b);
    if (QMargins m = m_actions->contentsMargins(); m.top() == 0) {
        m.setTop(4);
        m_actions->setContentsMargins(m);
    }
    if (QLayout* l = layout())
        l->invalidate();
    refitHeight();
}

void ToastWindow::thump()
{
    kick();
}

void ToastWindow::setThreat(const QString& category, const QString& name)
{
    const QString cat = category.trimmed();
    const QString nm = name.trimmed();
    if (!cat.isEmpty()) {
        ui::stylePill(m_threatPill, cat, m_accent);
        m_threatName->setText(nm);
        m_threatName->setVisible(!nm.isEmpty());
        setAccessibleDescription(u("威胁类型:") + cat + (nm.isEmpty() ? QString() : u("(") + nm + u(")"))
                                 + u("。") + m_description);
    } else {
        setAccessibleDescription(m_description);
    }
    m_threatRow->setVisible(!cat.isEmpty());
    m_threatRow->setMinimumHeight(m_threatRow->sizeHint().height());
    if (QLayout* l = layout())
        l->invalidate();
    refitHeight();
}

void ToastWindow::refitHeight()
{
    QLayout* l = layout();
    if (!l)
        return;
    const int h = fittedHeight();
    if (h > 0 && h != height())
        resize(width(), h);
}

int ToastWindow::fittedHeight()
{
    QLayout* l = layout();
    if (!l)
        return height();
    ensurePolished();
    l->activate();
    int h = l->hasHeightForWidth() ? l->totalHeightForWidth(width()) : -1;
    if (h <= 0)
        h = sizeHint().height();
    return h;
}

void ToastWindow::setCode(QWidget* block)
{
    if (!block || !m_codeSlot)
        return;
    m_codeSlot->layout()->addWidget(block);
    m_codeSlot->show();
    setFixedWidth(kCodeCardWidth);
    if (QLayout* l = layout())
        l->invalidate();
    refitHeight();
}

void ToastWindow::setInsight(QWidget* panel)
{
    if (!panel || !m_insightSlot)
        return;
    m_insightSlot->layout()->addWidget(panel);
    m_insightSlot->show();
    m_insightPending = true;
    m_insightSlot->setMinimumHeight(m_insightSlot->sizeHint().height());
    if (QLayout* l = layout())
        l->invalidate();
    refitHeight();
}

void ToastWindow::settleInsight(int minRemainingMs)
{
    m_insightPending = false;
    // AI 结果是异步回来的,纠错行等按钮显示后必须重新量高;嵌套布局的
    // 高度不随宽度链式传导,要用最小高度强制兜住,否则面板底部按钮会被截断。
    if (m_insightSlot && m_insightSlot->isVisible())
        m_insightSlot->setMinimumHeight(m_insightSlot->sizeHint().height());
    if (QLayout* l = layout())
        l->invalidate();
    if (!m_shown) {
        refitHeight();
        m_lifetimeMs = qMax(m_lifetimeMs, minRemainingMs);
        return;
    }
    if (m_closing)
        return;
    const int h = fittedHeight();
    if (h > 0 && h != height()) {
        m_slide->stop();
        const int bottom = y() + height();
        setGeometry(x(), bottom - h, width(), h);
        emit resized(this);
    }
    if (m_expired) {
        m_expired = false;
        if (minRemainingMs > 0)
            m_bar->start(minRemainingMs);
        else
            beginClose();
        return;
    }
    if (minRemainingMs > 0)
        m_bar->ensureRemaining(minRemainingMs);
}

void ToastWindow::onCountdownFinished()
{
    if (m_insightPending && !m_closing) {
        m_expired = true;
        QTimer::singleShot(kMaxInsightHoldMs, this, [this] {
            if (m_expired && !m_closing)
                beginClose();
        });
        return;
    }
    beginClose();
}

void ToastWindow::showEvent(QShowEvent* event)
{
    QWidget::showEvent(event);
    const int before = height();
    refitHeight();
    if (height() != before)
        emit resized(this);
    syncStamp();
}

bool ToastWindow::eventFilter(QObject* watched, QEvent* event)
{
    if (watched == m_stampHole
        && (event->type() == QEvent::Move || event->type() == QEvent::Resize || event->type() == QEvent::Show))
        syncStamp();
    return QWidget::eventFilter(watched, event);
}

void ToastWindow::syncStamp()
{
    if (!m_stamp || !m_stampHole)
        return;
    QRect r(QPoint(0, 0), m_stamp->size());
    r.moveCenter(m_stampHole->geometry().center());
    m_stamp->move(r.topLeft());
    m_stamp->raise();
    m_stamp->show();
}

void ToastWindow::kick()
{
    // 钢印落下时卡片被「砸」得往下一沉,再弹两下回原位。
    if (!m_card || m_closing || !motion::enabled())
        return;
    auto* anim = new QVariantAnimation(this);
    anim->setDuration(280);
    anim->setStartValue(0.0);
    anim->setEndValue(1.0);
    const QPoint base = m_card->pos();
    connect(anim, &QVariantAnimation::valueChanged, this, [this, base](const QVariant& v) {
        const qreal t = v.toReal();
        m_card->move(base + QPoint(0, qRound(std::sin(t * M_PI * 3.0) * (1.0 - t) * 4.0)));
    });
    connect(anim, &QVariantAnimation::finished, this, [this, base] {
        m_card->move(base);
        if (QLayout* l = layout())
            l->invalidate();
    });
    anim->start(QAbstractAnimation::DeleteWhenStopped);
}

void ToastWindow::place(const QPoint& topLeft)
{
    if (!m_shown) {
        m_shown = true;
        move(topLeft);
        setWindowOpacity(0.0);
        show();
        m_fade->stop();
        m_fade->setDuration(qMax(1, motion::duration(200)));
        m_fade->setStartValue(0.0);
        m_fade->setEndValue(1.0);
        m_fade->start();
        m_bar->start(m_lifetimeMs);
        if (m_stamp)
            m_stamp->slam(motion::duration(240), [this] { kick(); }, QPointF(-30, -10));
        return;
    }
    if (m_closing)
        return;
    if (pos() == topLeft)
        return;
    if (m_fade && m_fade->state() == QAbstractAnimation::Running) {
        move(topLeft);
        return;
    }
    m_slide->stop();
    if (m_slide->duration() <= 0) {
        move(topLeft);
        return;
    }
    m_slide->setStartValue(pos());
    m_slide->setEndValue(topLeft);
    m_slide->start();
}

void ToastWindow::beginClose()
{
    if (m_closing)
        return;
    m_closing = true;
    m_bar->stop();
    m_fade->stop();
    m_fade->setDuration(qMax(1, motion::duration(200)));
    m_fade->setStartValue(windowOpacity());
    m_fade->setEndValue(0.0);
    connect(m_fade, &QPropertyAnimation::finished, this, [this] {
        emit closed(this);
        deleteLater();
    });
    m_fade->start();
}
