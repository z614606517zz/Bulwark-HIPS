#include "design/Banner.h"
#include "design/Components.h"
#include "design/Icons.h"
#include "design/Motion.h"
#include "design/Sticker.h"
#include "design/Theme.h"

#include <QCursor>
#include <QGraphicsOpacityEffect>
#include <QHBoxLayout>
#include <QLabel>
#include <QPainter>
#include <QPainterPath>
#include <QPropertyAnimation>
#include <QPushButton>
#include <QRect>
#include <QTimer>
#include <QToolTip>
#include <QVBoxLayout>

#include <utility>

namespace {

constexpr int kHoverPollMs = 120;

int defaultTimeout(ui::Tone t)
{
    switch (t) {
    case ui::Tone::Success: return 4500;
    case ui::Tone::Info:    return 5000;
    case ui::Tone::Warning: return 9000;
    case ui::Tone::Danger:  return 0;
    }
    return 5000;
}

class ToneGlyph : public QWidget
{
public:
    ToneGlyph(ui::Tone tone, QWidget* parent = nullptr) : QWidget(parent), m_tone(tone)
    {
        setFixedSize(20, 20);
        setAttribute(Qt::WA_TransparentForMouseEvents);
    }

protected:
    void paintEvent(QPaintEvent*) override
    {
        QPainter p(this);
        AppIcon::draw(p, ui::toneIcon(m_tone), QRectF(1, 1, 18, 18), theme::ink(), 2.0);
    }

private:
    ui::Tone m_tone;
};

}

Banner::Banner(ui::Tone tone, const QString& text, QWidget* parent)
    : QFrame(parent), m_tone(tone)
{
    setAttribute(Qt::WA_StyledBackground, false);
    auto* h = new QHBoxLayout(this);
    h->setContentsMargins(20, 10, 12, 13);
    h->setSpacing(10);
    h->addWidget(new ToneGlyph(tone), 0, Qt::AlignTop);

    m_text = ui::label(text);
    m_text->setWordWrap(true);
    m_text->setTextInteractionFlags(Qt::TextSelectableByMouse);
    m_text->setStyleSheet(QStringLiteral("color:%1;").arg(theme::textPrimary().name()));
    h->addWidget(m_text, 1, Qt::AlignVCenter);

    m_action = ui::button(QString(), "ghost", QString(), true);
    m_action->hide();
    connect(m_action, &QPushButton::clicked, this, [this] {
        if (m_fn)
            m_fn();
        dismiss();
    });
    h->addWidget(m_action, 0, Qt::AlignVCenter);

    auto* close = ui::iconButton(QStringLiteral("close"), QString::fromUtf8("关闭提示"),
                                 theme::textMuted(), 14);
    connect(close, &QToolButton::clicked, this, &Banner::dismiss);
    h->addWidget(close, 0, Qt::AlignTop);

    m_timer = new QTimer(this);
    m_timer->setSingleShot(true);
    connect(m_timer, &QTimer::timeout, this, &Banner::dismiss);

    m_hoverWatch = new QTimer(this);
    m_hoverWatch->setInterval(kHoverPollMs);
    connect(m_hoverWatch, &QTimer::timeout, this, &Banner::syncHoverPause);

    setAccessibleName(QString::fromUtf8("提示"));
    setAccessibleDescription(text);
}

QString Banner::text() const { return m_text->text(); }

void Banner::setText(const QString& text)
{
    m_text->setText(text);
    setAccessibleDescription(text);
}

void Banner::setAction(const QString& text, std::function<void()> fn)
{
    m_fn = std::move(fn);
    m_action->setText(text);
    m_action->setVisible(!text.isEmpty());
}

void Banner::setTimeout(int ms)
{
    m_remaining = ms;
    m_timer->stop();
    m_holding = false;
    m_hoverArmed = false;
    if (ms > 0) {
        m_since.start();
        m_timer->start(ms);
        m_lastCursor = QCursor::pos();
        m_hoverWatch->start();
    } else {
        m_hoverWatch->stop();
    }
}

void Banner::syncHoverPause()
{
    if (m_closing || m_remaining <= 0) {
        m_hoverWatch->stop();
        return;
    }
    const QPoint now = QCursor::pos();
    const bool moved = now != m_lastCursor;
    m_lastCursor = now;
    const QWidget* win = window();
    const bool over = isVisible() && win && win->isVisible() && !win->isMinimized()
                      && QRect(mapToGlobal(QPoint(0, 0)), size()).contains(now);
    if (!over) {
        m_hoverArmed = false;
        if (m_holding) {
            m_holding = false;
            m_since.start();
            m_timer->start(m_remaining);
        }
        return;
    }
    if (moved)
        m_hoverArmed = true;
    if (m_hoverArmed && !m_holding && m_timer->isActive()) {
        m_remaining = qMax(800, m_remaining - int(m_since.elapsed()));
        m_timer->stop();
        m_holding = true;
    }
}

void Banner::dismiss()
{
    if (m_closing)
        return;
    m_closing = true;
    m_timer->stop();
    m_hoverWatch->stop();
    const int ms = motion::duration(160);
    if (ms <= 0) {
        emit dismissed();
        deleteLater();
        return;
    }
    auto* fx = new QGraphicsOpacityEffect(this);
    fx->setOpacity(1.0);
    setGraphicsEffect(fx);
    auto* anim = new QPropertyAnimation(fx, "opacity", this);
    anim->setDuration(ms);
    anim->setStartValue(1.0);
    anim->setEndValue(0.0);
    connect(anim, &QPropertyAnimation::finished, this, [this] {
        emit dismissed();
        deleteLater();
    });
    anim->start(QAbstractAnimation::DeleteWhenStopped);
}

void Banner::paintEvent(QPaintEvent*)
{
    QPainter p(this);
    p.setRenderHint(QPainter::Antialiasing, true);
    const QColor c = ui::toneColor(m_tone);
    const bool k = !theme::mecha();
    const QRectF body = sticker::panel(p, QRectF(rect()), theme::blend(c, theme::surface(), k ? 0.16 : 0.12),
                                       k ? 10.0 : 8.0, true);
    const QPainterPath shape = theme::panelPath(body, k ? 10.0 : 8.0);
    // 左侧色条:警告 / 危险是警示斑马条,其余是实色。
    p.save();
    p.setClipPath(shape);
    const QRectF strip(body.left(), body.top(), 8.0, body.height());
    if (m_tone == ui::Tone::Warning || m_tone == ui::Tone::Danger)
        sticker::hazard(p, strip, c, k ? QColor(0xFF, 0xFF, 0xFF) : theme::ink(), 5.0);
    else
        p.fillRect(strip, c);
    p.setPen(QPen(theme::ink(), 1.6));
    p.drawLine(QPointF(strip.right(), strip.top()), QPointF(strip.right(), strip.bottom()));
    p.restore();
    p.strokePath(shape, QPen(theme::ink(), theme::inkWidth(), Qt::SolidLine, Qt::FlatCap,
                             k ? Qt::RoundJoin : Qt::MiterJoin));
}

BannerHost::BannerHost(QWidget* parent) : QWidget(parent)
{
    setObjectName(QStringLiteral("BannerHost"));
    m_stack = new QVBoxLayout(this);
    m_stack->setContentsMargins(0, 0, 0, 0);
    m_stack->setSpacing(8);
    hide();
}

Banner* BannerHost::post(ui::Tone tone, const QString& text, int timeoutMs)
{
    const int timeout = timeoutMs < 0 ? defaultTimeout(tone) : timeoutMs;

    for (const QPointer<Banner>& b : std::as_const(m_banners)) {
        if (b && b->tone() == tone && b->text() == text) {
            b->setTimeout(timeout);
            return b;
        }
    }

    m_banners.removeAll(QPointer<Banner>());
    while (m_banners.size() >= 3) {
        if (Banner* old = m_banners.takeFirst())
            old->dismiss();
    }

    auto* b = new Banner(tone, text, this);
    m_stack->addWidget(b);
    m_banners.append(b);
    connect(b, &Banner::dismissed, this, [this, b] {
        m_banners.removeAll(QPointer<Banner>(b));
        m_banners.removeAll(QPointer<Banner>());
        if (m_banners.isEmpty())
            hide();
    });
    show();

    if (const int ms = motion::duration(160); ms > 0) {
        auto* fx = new QGraphicsOpacityEffect(b);
        fx->setOpacity(0.0);
        b->setGraphicsEffect(fx);
        auto* anim = new QPropertyAnimation(fx, "opacity", b);
        anim->setDuration(ms);
        anim->setStartValue(0.0);
        anim->setEndValue(1.0);
        QObject::connect(anim, &QPropertyAnimation::finished, b, [b] { b->setGraphicsEffect(nullptr); });
        anim->start(QAbstractAnimation::DeleteWhenStopped);
    }
    b->setTimeout(timeout);
    return b;
}

void BannerHost::clear(bool animated)
{
    if (animated) {
        for (const QPointer<Banner>& b : std::as_const(m_banners))
            if (b)
                b->dismiss();
        return;
    }
    const QList<QPointer<Banner>> gone = std::exchange(m_banners, {});
    for (const QPointer<Banner>& b : gone) {
        if (b) {
            b->hide();
            b->deleteLater();
        }
    }
    hide();
}

BannerHost* BannerHost::find(QWidget* from)
{
    for (QWidget* w = from; w; w = w->parentWidget()) {
        if (auto* self = dynamic_cast<BannerHost*>(w))
            return self;
        if (auto* h = w->findChild<BannerHost*>(QString(), Qt::FindDirectChildrenOnly))
            return h;
        if (w->isWindow())
            break;
    }
    return nullptr;
}

Banner* ui::notify(QWidget* context, Tone tone, const QString& text, int timeoutMs)
{
    if (BannerHost* host = BannerHost::find(context))
        return host->post(tone, text, timeoutMs);
    if (context)
        QToolTip::showText(context->mapToGlobal(context->rect().center()), text, context, QRect(),
                           tone == Tone::Danger ? 10000 : 5000);
    return nullptr;
}
