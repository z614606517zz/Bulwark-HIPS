#include "design/Cockpit.h"
#include "design/Components.h"
#include "design/Icons.h"
#include "design/Motion.h"
#include "design/Sticker.h"
#include "design/Theme.h"
#include "design/TitanKit.h"
#include "widgets/ElidingLabel.h"

#include <QEnterEvent>
#include <QFocusEvent>
#include <QFontMetricsF>
#include <QHBoxLayout>
#include <QMouseEvent>
#include <QPainter>
#include <QPainterPath>
#include <QPushButton>
#include <QSpacerItem>
#include <QTransform>
#include <QVariantAnimation>
#include <QVBoxLayout>

namespace {

Qt::PenJoinStyle joinStyle() { return theme::mecha() ? Qt::MiterJoin : Qt::RoundJoin; }

constexpr qreal kDepth = 4.0;

// 金刚的键帽:固定 56×50(收起文字时 42 宽)。
constexpr int kTitanKeyW = 56;
constexpr int kTitanKeyCompactW = 42;
constexpr int kTitanKeyH = 50;

// 金刚的品牌面板:铬银底板(内边距 6)上并排两扇风挡,第一扇 100 宽,第二扇 77 宽,中间隔 5。
constexpr int kBrandH = 68;
constexpr int kBrandPad = 6;
constexpr int kPanePad = 6;
constexpr int kPaneGap = 5;
constexpr int kPaneA = 100;
constexpr int kPaneB = 77;
// 小垒的头:设计稿把 viewBox「78 8 84 84」排进 36px 的方框;RobotWidget 的金刚头取的是 x 70..170,
// 所以控件要宽 36 × 100 / 84 ≈ 43,左边比方框多探出 8 × 36 / 84 ≈ 3。
constexpr int kBotBox = 36;
constexpr int kBotW = 43;
constexpr int kBotLead = 3;

}

KeyCap::KeyCap(const QString& stickerIcon, const QString& text, QWidget* parent)
    : QAbstractButton(parent), m_icon(stickerIcon)
{
    setText(text);
    setCheckable(true);
    setCursor(Qt::PointingHandCursor);
    setFocusPolicy(Qt::TabFocus);
    setSizePolicy(QSizePolicy::Fixed, QSizePolicy::Fixed);
    syncAccessible();
    connect(this, &QAbstractButton::pressed, this, &KeyCap::syncPress);
    connect(this, &QAbstractButton::released, this, &KeyCap::syncPress);
    connect(this, &QAbstractButton::toggled, this, &KeyCap::syncPress);
}

void KeyCap::syncPress()
{
    const qreal target = (isChecked() || isDown()) ? 1.0 : 0.0;
    if (!motion::enabled() || !isVisible()) {
        if (m_pressAnim)
            m_pressAnim->stop();
        m_press = target;
        update();
        return;
    }
    if (!m_pressAnim) {
        m_pressAnim = new QVariantAnimation(this);
        connect(m_pressAnim, &QVariantAnimation::valueChanged, this, [this](const QVariant& v) {
            m_press = v.toReal();
            update();
        });
    }
    if (qFuzzyCompare(m_pressAnim->endValue().toReal() + 1.0, target + 1.0)
        && m_pressAnim->state() == QAbstractAnimation::Running)
        return;
    // 按下干脆利落;松开时键帽弹回来还会略微过冲一点。
    m_pressAnim->stop();
    m_pressAnim->setDuration(target > 0.5 ? 70 : 190);
    m_pressAnim->setEasingCurve(target > 0.5 ? QEasingCurve::OutQuad : QEasingCurve::OutBack);
    m_pressAnim->setStartValue(m_press);
    m_pressAnim->setEndValue(target);
    m_pressAnim->start();
}

void KeyCap::setCompact(bool compact)
{
    if (compact == m_compact)
        return;
    m_compact = compact;
    setToolTip(compact ? text() : QString());
    updateGeometry();
    update();
}

void KeyCap::setBadge(int count)
{
    count = qMax(0, count);
    if (count == m_badge)
        return;
    const bool grew = count > m_badge;
    m_badge = count;
    syncAccessible();
    // 新的未读:角标「蹦」出来。
    if (grew && motion::enabled() && motion::onScreen(this)) {
        if (!m_badgeAnim) {
            m_badgeAnim = new QVariantAnimation(this);
            m_badgeAnim->setStartValue(0.0);
            m_badgeAnim->setEndValue(1.0);
            m_badgeAnim->setDuration(380);
            connect(m_badgeAnim, &QVariantAnimation::valueChanged, this, [this](const QVariant& v) {
                m_badgeT = v.toReal();
                update();
            });
        }
        m_badgeAnim->stop();
        m_badgeAnim->start();
    }
    update();
}

void KeyCap::syncAccessible()
{
    setAccessibleName(m_badge > 0 ? QString::fromUtf8("%1,%2 条未读").arg(text()).arg(m_badge) : text());
}

void KeyCap::setLineIcon(const QString& name)
{
    m_lineIcon = name;
    update();
}

int KeyCap::widthFor(bool compact) const
{
    if (theme::titan())
        return compact ? kTitanKeyCompactW : kTitanKeyW;
    if (compact)
        return 50;
    QFont f = font();
    f.setPointSizeF(8.5);
    f.setWeight(QFont::Bold);
    const int tw = int(QFontMetricsF(f).horizontalAdvance(text())) + 12;
    return qMax(60, tw + 5);
}

QSize KeyCap::sizeHint() const
{
    if (theme::titan())
        return {widthFor(m_compact), kTitanKeyH};
    return {widthFor(m_compact), m_compact ? 52 : 64};
}

void KeyCap::enterEvent(QEnterEvent*) { m_hover = true; update(); }
void KeyCap::leaveEvent(QEvent*) { m_hover = false; update(); }

void KeyCap::focusInEvent(QFocusEvent* e)
{
    m_keyboardFocus = e->reason() == Qt::TabFocusReason || e->reason() == Qt::BacktabFocusReason;
    QAbstractButton::focusInEvent(e);
    update();
}

void KeyCap::focusOutEvent(QFocusEvent* e)
{
    m_keyboardFocus = false;
    QAbstractButton::focusOutEvent(e);
    update();
}

void KeyCap::paintEvent(QPaintEvent*)
{
    QPainter p(this);
    p.setRenderHint(QPainter::Antialiasing, true);
    if (theme::titan()) {
        paintTitan(p);
        return;
    }
    const bool k = !theme::mecha();
    const bool on = isChecked();
    const QColor ink = theme::ink();

    // 顶部 / 右侧留出角标的位置;按下时键帽整体下沉一个键程(m_press 0..1 是下沉的进度)。
    const QRectF area(1.5, 6.0, width() - 7.5, height() - 7.5);
    const QRectF rest(area.left(), area.top(), area.width(), area.height() - kDepth);
    const QRectF key = rest.translated(0, kDepth * m_press);
    const QPainterPath body = theme::panelPath(key, k ? 14.0 : 6.0);
    if (m_press < 0.999)
        p.fillPath(theme::panelPath(rest.translated(0, kDepth), k ? 14.0 : 6.0), k ? theme::pal().shadow : ink);
    QColor fill;
    if (on)
        fill = k ? theme::surfaceHi() : theme::accent();
    else if (m_hover)
        fill = k ? theme::surfaceAlt() : QColor(0xF1, 0xEF, 0xEA);
    else
        fill = k ? theme::surface() : QColor(0xFF, 0xFF, 0xFF);
    p.fillPath(body, fill);
    p.save();
    p.setClipPath(body);
    const QRectF gleam(key.left() + 10, key.top() + 5, key.width() - 20, 3);
    if (k) {
        p.setPen(Qt::NoPen);
        p.setBrush(QColor(255, 255, 255, 240));
        p.drawRoundedRect(gleam, 1.5, 1.5);
    } else {
        p.fillRect(gleam, on ? QColor(255, 255, 255, 90) : theme::surfaceAlt());
    }
    p.restore();
    p.strokePath(body, QPen(ink, 2.0, Qt::SolidLine, Qt::FlatCap, joinStyle()));

    if (!m_compact) {
        const QRectF lp(key.right() - 14, key.top() + 7, 8, k ? 8 : 5);
        p.setPen(QPen(ink, 1.4));
        p.setBrush(on ? (k ? theme::accent() : QColor(0xFF, 0xFF, 0xFF)) : theme::pal().border);
        if (k)
            p.drawEllipse(lp);
        else
            p.drawRect(lp);
    }

    const qreal is = 22.0;
    const QRectF ir(key.center().x() - is / 2.0,
                    m_compact ? key.center().y() - is / 2.0 : key.top() + 7.0, is, is);
    if (sticker::hasIcon(m_icon))
        sticker::icon(p, m_icon, ir, 2.0);
    if (!m_compact) {
        QFont f = font();
        f.setPointSizeF(8.5);
        f.setWeight(QFont::Bold);
        p.setFont(f);
        p.setPen(on && !k ? QColor(0xFF, 0xFF, 0xFF) : ink);
        const QRectF tr(key.left() + 3, ir.bottom() + 1, key.width() - 6, key.bottom() - ir.bottom() - 2);
        p.drawText(tr, Qt::AlignHCenter | Qt::AlignVCenter,
                   QFontMetricsF(f).elidedText(text(), Qt::ElideRight, tr.width()));
    }
    if (m_keyboardFocus && hasFocus())
        p.strokePath(theme::panelPath(key.adjusted(-2.5, -2.5, 2.5, 2.5), k ? 16.0 : 7.0),
                     QPen(theme::accentDeep(), 1.6, Qt::DashLine, Qt::FlatCap, joinStyle()));

    if (m_badge > 0) {
        const QString t = m_badge > 99 ? QStringLiteral("99+") : QString::number(m_badge);
        QFont bf = font();
        bf.setPointSizeF(7.5);
        bf.setWeight(QFont::Black);
        const qreal bw = qMax<qreal>(20.0, QFontMetricsF(bf).horizontalAdvance(t) + 10);
        const QRectF b(width() - bw - 0.5, 0.5, bw, 17);
        const QPainterPath bp = theme::panelPath(b, k ? 8.0 : 3.0);
        p.save();
        if (m_badgeT < 1.0) {
            const qreal s = 0.4 + 0.6 * motion::outBack(m_badgeT);
            p.translate(b.center());
            p.scale(s, s);
            p.translate(-b.center());
        }
        p.fillPath(bp, theme::danger());
        p.strokePath(bp, QPen(ink, 2.0, Qt::SolidLine, Qt::FlatCap, joinStyle()));
        p.setFont(bf);
        p.setPen(QColor(0xFF, 0xFF, 0xFF));
        p.drawText(b, Qt::AlignCenter, t);
        p.restore();
    }
}

// 金刚:上两角切角的深色装甲键,底沿一道「键裙」;当前页 = 通电的钴蓝键,顶沿亮一条能量蓝。
// 图标是线条图标,下面一行键名;收起时只剩图标(键名进提示)。
void KeyCap::paintTitan(QPainter& p)
{
    const theme::Palette& P = theme::pal();
    const bool on = isChecked();
    const bool lit = m_hover || isDown();
    const QRectF r = QRectF(rect()).adjusted(1.0, 1.0, -1.0, -1.0);
    const QPainterPath body = theme::panelPath(r, 6.0);
    p.fillPath(body, on ? P.structure : lit ? QColor(0x28, 0x34, 0x50) : QColor(0x1D, 0x26, 0x38));
    p.save();
    p.setClipPath(body);
    // 键裙平时露 4px;键被按下去(或者就是当前页)时只露 2px。
    const qreal skirt = 4.0 - 2.0 * qBound<qreal>(0.0, m_press, 1.0);
    p.fillRect(QRectF(r.left() + 1.0, r.bottom() - 1.0 - skirt, r.width() - 2.0, skirt),
               on ? QColor(0x14, 0x37, 0x92) : QColor(0, 0, 0, 115));
    if (on) {
        QColor halo = P.glow;
        halo.setAlphaF(0.25);
        p.fillRect(QRectF(r.left() + 6.0, r.top() + 1.0, r.width() - 12.0, 6.0), halo);
        p.fillRect(QRectF(r.left() + 8.0, r.top() + 1.0, r.width() - 16.0, 3.0), P.glow);
    }
    p.restore();
    p.strokePath(body, QPen(P.ink, 2.0, Qt::SolidLine, Qt::FlatCap, Qt::MiterJoin));

    const QColor fg = on ? QColor(0xFF, 0xFF, 0xFF) : lit ? P.text : P.textSecondary;
    const qreal is = 18.0;
    const qreal labelH = 11.0;
    const qreal contentH = m_compact ? is : is + 3.0 + labelH;
    const qreal top = (height() - 4.0 - contentH) / 2.0 + (isDown() && !on ? 1.0 : 0.0);
    const QRectF ir((width() - is) / 2.0, top, is, is);
    AppIcon::draw(p, m_lineIcon, ir, on ? QColor(0xDD, 0xF4, 0xFF) : fg, 1.8);
    if (!m_compact) {
        p.setFont(sticker::headFont(8.0, QFont::Bold));
        p.setPen(fg);
        p.drawText(QRectF(1.0, ir.bottom() + 1.5, width() - 2.0, labelH + 3.0),
                   Qt::AlignHCenter | Qt::AlignVCenter, text());
    }
    if (m_keyboardFocus && hasFocus())
        p.strokePath(theme::panelPath(r.adjusted(3.0, 3.0, -3.0, -3.0), 4.0),
                     QPen(on ? QColor(0xFF, 0xFF, 0xFF) : P.glow, 1.2, Qt::DashLine, Qt::FlatCap, Qt::MiterJoin));

    if (m_badge > 0) {
        const QString t = m_badge > 99 ? QStringLiteral("99+") : QString::number(m_badge);
        const QFont bf = titankit::numFont(10, QFont::ExtraBold);
        const qreal bw = qMax<qreal>(15.0, QFontMetricsF(bf).horizontalAdvance(t) + 7.0);
        const QRectF b(width() - 3.0 - bw, 4.0, bw, 14.0);
        p.save();
        if (m_badgeT < 1.0) {
            const qreal s = 0.4 + 0.6 * motion::outBack(m_badgeT);
            p.translate(b.center());
            p.scale(s, s);
            p.translate(-b.center());
        }
        p.fillRect(b, P.ink);
        p.fillRect(b.adjusted(1.5, 1.5, -1.5, -1.5), P.danger);
        p.setFont(bf);
        p.setPen(QColor(0xFF, 0xFF, 0xFF));
        p.drawText(b, Qt::AlignCenter, t);
        p.restore();
    }
}

KeyGroup::KeyGroup(const QString& title, QWidget* parent) : QWidget(parent), m_title(title)
{
    // 金刚:键帽嵌在暗槽里,槽四周留 6px,键距 3px;顶上 16px 放组名铭牌和英文代号。
    const bool titan = theme::titan();
    auto* v = new QVBoxLayout(this);
    v->setContentsMargins(titan ? 6 : 0, 16, titan ? 6 : 0, titan ? 6 : 0);
    v->setSpacing(0);
    m_row = new QHBoxLayout;
    m_row->setContentsMargins(0, 0, 0, 0);
    m_row->setSpacing(titan ? 3 : 2);
    v->addLayout(m_row);
    setSizePolicy(QSizePolicy::Fixed, QSizePolicy::Fixed);
}

void KeyGroup::addKey(KeyCap* key)
{
    m_row->addWidget(key);
}

void KeyGroup::setCode(const QString& code)
{
    m_code = code;
    update();
}

int KeyGroup::widthFor(bool compact) const
{
    int w = 0;
    int n = 0;
    for (int i = 0; i < m_row->count(); ++i)
        if (auto* k = qobject_cast<KeyCap*>(m_row->itemAt(i)->widget())) {
            w += k->widthFor(compact);
            ++n;
        }
    const QMargins m = layout() ? layout()->contentsMargins() : QMargins();
    return w + m_row->spacing() * qMax(0, n - 1) + m.left() + m.right();
}

void KeyGroup::setCompact(bool compact)
{
    m_compact = compact;
    for (int i = 0; i < m_row->count(); ++i)
        if (auto* k = qobject_cast<KeyCap*>(m_row->itemAt(i)->widget()))
            k->setCompact(compact);
    update();
}

void KeyGroup::paintEvent(QPaintEvent*)
{
    QPainter p(this);
    p.setRenderHint(QPainter::Antialiasing, true);
    if (theme::titan()) {
        // 金刚:一组键帽嵌在胸甲上一块下沉的暗槽里;槽口左上是一块斜切的铬银组名铭牌,右上一行英文代号。
        const theme::Palette& P = theme::pal();
        const QRectF slot = QRectF(rect()).adjusted(1.25, 1.25, -1.25, -1.25);
        const QPainterPath sp = theme::panelPath(slot, 8.0);
        p.fillPath(sp, QColor(0x08, 0x0B, 0x11));
        p.fillRect(QRectF(10.0, height() - 3.5, width() - 20.0, 1.0), QColor(255, 255, 255, 41));
        p.strokePath(sp, QPen(P.ink, 2.5, Qt::SolidLine, Qt::FlatCap, Qt::MiterJoin));

        QFont tf = sticker::headFont(7.0, QFont::ExtraBold);
        tf.setPixelSize(9);
        tf.setLetterSpacing(QFont::AbsoluteSpacing, 3.0);
        // 字距也跟在最后一个字后面,算铭牌宽度和居中时要把这 3px 让出来。
        const qreal titleW = QFontMetricsF(tf).horizontalAdvance(m_title) - 3.0;
        const QRectF plate(12.0, 2.5, titleW + 18.0, 12.0);
        const qreal lean = 2.2;
        QPainterPath tag;
        tag.moveTo(plate.left() + lean, plate.top());
        tag.lineTo(plate.right() + lean, plate.top());
        tag.lineTo(plate.right() - lean, plate.bottom());
        tag.lineTo(plate.left() - lean, plate.bottom());
        tag.closeSubpath();
        p.fillPath(tag, P.fin);
        p.setFont(tf);
        p.setPen(P.ink);
        p.drawText(QRectF(plate.left() + 9.0, plate.top(), titleW + 3.0, plate.height()),
                   Qt::AlignLeft | Qt::AlignVCenter, m_title);

        if (!m_code.isEmpty()) {
            QFont cf = titankit::numFont(8, QFont::Bold);
            cf.setLetterSpacing(QFont::AbsoluteSpacing, 1.5);
            const qreal codeW = QFontMetricsF(cf).horizontalAdvance(m_code) - 1.5;
            const qreal codeLeft = width() - 12.0 - codeW;
            if (codeLeft >= plate.right() + lean + 6.0) {
                p.setFont(cf);
                p.setPen(QColor(0x4A, 0x56, 0x6E));
                p.drawText(QRectF(codeLeft, 3.0, codeW + 1.5, 11.0), Qt::AlignLeft | Qt::AlignVCenter, m_code);
            }
        }
        return;
    }
    QFont f = sticker::labelFont(8.0);
    p.setFont(f);
    p.setPen(theme::ink());
    const QFontMetricsF fm(f);
    const qreal tw = fm.horizontalAdvance(m_title);
    p.drawText(QRectF(2, 0, tw + 2, 14), Qt::AlignLeft | Qt::AlignVCenter, m_title);
    const QRectF strip(tw + 10, 4, width() - tw - 14, 6);
    if (strip.width() > 8) {
        const theme::Palette& P = theme::pal();
        sticker::hazard(p, strip, P.hazardA, P.hazardB, 4);
        p.setPen(QPen(theme::ink(), 1.2));
        p.setBrush(Qt::NoBrush);
        p.drawRect(strip);
    }
}

HexButton::HexButton(const QString& stickerIcon, const QColor& fill, const QString& tip, QWidget* parent)
    : QAbstractButton(parent), m_icon(stickerIcon), m_fill(fill)
{
    setCursor(Qt::PointingHandCursor);
    setToolTip(tip);
    setAccessibleName(tip);
    setFocusPolicy(Qt::NoFocus);
    setSizePolicy(QSizePolicy::Fixed, QSizePolicy::Fixed);
}

void HexButton::setIconName(const QString& name)
{
    m_icon = name;
    update();
}

void HexButton::enterEvent(QEnterEvent*) { m_hover = true; update(); }
void HexButton::leaveEvent(QEvent*) { m_hover = false; update(); }

void HexButton::paintEvent(QPaintEvent*)
{
    QPainter p(this);
    p.setRenderHint(QPainter::Antialiasing, true);
    const QRectF r = QRectF(rect()).adjusted(1.5, 1.5, -1.5, -1.5).translated(0, isDown() ? 1.0 : 0.0);
    QPainterPath path;
    if (theme::mecha()) {
        const qreal w = r.width(), h = r.height();
        QPolygonF poly;
        poly << QPointF(r.left() + w * 0.25, r.top()) << QPointF(r.left() + w * 0.75, r.top())
             << QPointF(r.right(), r.top() + h / 2) << QPointF(r.left() + w * 0.75, r.bottom())
             << QPointF(r.left() + w * 0.25, r.bottom()) << QPointF(r.left(), r.top() + h / 2);
        path.addPolygon(poly);
        path.closeSubpath();
    } else {
        const qreal d = qMin(r.width(), r.height());
        path.addEllipse(QRectF(r.center().x() - d / 2, r.center().y() - d / 2, d, d));
    }
    p.fillPath(path, m_hover ? m_fill.lighter(112) : m_fill);
    p.strokePath(path, QPen(theme::ink(), 2.0, Qt::SolidLine, Qt::FlatCap, joinStyle()));
    const qreal is = 15.0;
    sticker::icon(p, m_icon, QRectF(r.center().x() - is / 2, r.center().y() - is / 2, is, is), 3.0);
}

BrandPanel::BrandPanel(QWidget* parent) : QWidget(parent)
{
    // 金刚:面板上的字全是自己画的(见 paintTitan),布局里只留小垒的头、一段占位和「启动服务」按钮。
    const bool titan = theme::titan();
    setCursor(Qt::PointingHandCursor);
    setSizePolicy(QSizePolicy::Fixed, QSizePolicy::Fixed);
    auto* h = new QHBoxLayout(this);
    if (titan) {
        h->setContentsMargins(kBrandPad + kPanePad - kBotLead, 0, kBrandPad, 0);
        h->setSpacing(0);
        setFixedHeight(kBrandH);
    } else {
        h->setContentsMargins(10, 6, 14, 10);
        h->setSpacing(8);
    }
    robot::Look look;
    look.head = true;
    look.extras = false;
    m_bot = new RobotWidget(titan ? kBotW : 46, look);
    m_bot->setAutoBlink(true);
    m_bot->setAnimated(true);
    m_bot->setAttribute(Qt::WA_TransparentForMouseEvents);
    h->addWidget(m_bot, 0, Qt::AlignVCenter);
    if (titan) {
        m_gap = new QSpacerItem(0, 0, QSizePolicy::Fixed, QSizePolicy::Minimum);
        h->addItem(m_gap);
    }

    m_text = new QWidget;
    m_text->setAttribute(Qt::WA_TransparentForMouseEvents);
    auto* v = new QVBoxLayout(m_text);
    v->setContentsMargins(0, 0, 0, 0);
    v->setSpacing(0);
    m_name = new StickerText(QString::fromUtf8("磐垒"), 21);
    v->addWidget(m_name, 0, Qt::AlignLeft);
    m_state = ui::elided(QString::fromUtf8("状态未知"), "caption");
    m_state->setFixedWidth(118);
    v->addWidget(m_state);
    h->addWidget(m_text, 0, Qt::AlignVCenter);

    m_start = ui::button(QString::fromUtf8("启动服务"), "primary", QString(), true);
    m_start->setToolTip(QString::fromUtf8("启动后台服务(需要管理员权限)"));
    m_start->hide();
    connect(m_start, &QPushButton::clicked, this, [this] {
        if (m_onStart)
            m_onStart();
    });
    h->addWidget(m_start, 0, Qt::AlignVCenter);
    setAccessibleName(QString::fromUtf8("磐垒 · 防护状态"));
    if (titan) {
        m_text->hide();
        syncTitanLayout();
    }
}

void BrandPanel::setProtection(robot::Mood mood, const QString& text, const QColor& color, const QString& tip)
{
    m_bot->setMood(mood);
    m_state->setText(text);
    m_state->setStyleSheet(QStringLiteral("color:%1; font-size:9pt; font-weight:800;").arg(color.name()));
    setToolTip(tip);
    setAccessibleDescription(text + QStringLiteral(" — ") + tip);
}

void BrandPanel::setTitanStatus(const QString& title, const QString& sub, const QColor& lamp)
{
    m_titanTitle = title;
    m_titanSub = sub;
    m_titanLamp = lamp;
    update();
}

// 小垒的头右边到「启动服务」按钮(没有按钮时到底板右内沿)之间要空出来的宽度:
// 第一扇风挡剩下的部分 + 第二扇风挡;收起时只剩第一扇风挡的右内边距。
int BrandPanel::titanGap(bool compact) const
{
    const int lead = kPanePad - kBotLead;
    const int botW = m_bot->sizeHint().width();
    int w = (compact ? kBotBox + 2 * kPanePad : kPaneA + kPaneGap + kPaneB) - lead - botW;
    if (m_starting || !m_connected)
        w += kPaneGap;
    return w;
}

void BrandPanel::syncTitanLayout()
{
    if (!m_gap)
        return;
    m_gap->changeSize(titanGap(m_compact), 0, QSizePolicy::Fixed, QSizePolicy::Minimum);
    if (QLayout* l = layout())
        l->invalidate();
    updateGeometry();
    update();
}

void BrandPanel::setService(bool connected)
{
    m_connected = connected;
    syncAction();
}

void BrandPanel::setServiceStarting(bool starting)
{
    m_starting = starting;
    syncAction();
}

void BrandPanel::syncAction()
{
    m_start->setText(m_starting ? QString::fromUtf8("启动中…") : QString::fromUtf8("启动服务"));
    m_start->setEnabled(!m_starting);
    m_start->setVisible(m_starting || !m_connected);
    syncTitanLayout();
    updateGeometry();
}

void BrandPanel::setCompact(bool compact)
{
    m_compact = compact;
    if (theme::titan()) {
        syncTitanLayout();
        return;
    }
    m_text->setVisible(!compact);
    updateGeometry();
}

int BrandPanel::widthFor(bool compact) const
{
    const QLayout* l = layout();
    const QMargins m = l ? l->contentsMargins() : QMargins();
    if (theme::titan()) {
        int w = m.left() + m.right() + m_bot->sizeHint().width() + titanGap(compact);
        if (m_starting || !m_connected)
            w += m_start->sizeHint().width();
        return w;
    }
    const int sp = l ? l->spacing() : 8;
    int w = m.left() + m.right() + m_bot->sizeHint().width();
    if (!compact)
        w += sp + qMax(m_name->sizeHint().width(), m_state->width());
    if (m_starting || !m_connected)
        w += sp + m_start->sizeHint().width();
    return w;
}

void BrandPanel::paintEvent(QPaintEvent*)
{
    QPainter p(this);
    if (theme::titan()) {
        paintTitan(p);
        return;
    }
    sticker::panel(p, QRectF(rect()), theme::mecha() ? QColor(0xFF, 0xFF, 0xFF) : theme::surface(), 12.0, true);
}

// 金刚:铬银底板上并排两扇风挡玻璃 —— 左边是小垒的头和「磐垒」,右边是指示灯 + 防护状态两行字。
// 收起时只剩左边那扇窗里的头。
void BrandPanel::paintTitan(QPainter& p)
{
    const theme::Palette& P = theme::pal();
    p.setRenderHint(QPainter::Antialiasing, true);
    const QPainterPath frame = theme::panelPath(QRectF(rect()).adjusted(1.25, 1.25, -1.25, -1.25), 10.0);
    p.fillPath(frame, P.fin);
    p.strokePath(frame, QPen(P.ink, 2.5, Qt::SolidLine, Qt::FlatCap, Qt::MiterJoin));

    const auto pane = [&](const QRectF& r) {
        const QPainterPath path = theme::panelPath(r.adjusted(1.0, 1.0, -1.0, -1.0), 7.0);
        p.fillPath(path, QColor(0x8D, 0xD9, 0xFF));
        // 玻璃上两道斜反光
        p.save();
        p.setClipPath(path);
        const qreal gx = r.left() + r.width() * 0.56;
        const qreal gw = r.width() * 0.30;
        const qreal lean = r.height() * 0.2226;
        const auto stripe = [&](qreal from, qreal to, int alpha) {
            QPainterPath s;
            s.moveTo(gx + gw * from + lean, r.top());
            s.lineTo(gx + gw * to + lean, r.top());
            s.lineTo(gx + gw * to - lean, r.bottom());
            s.lineTo(gx + gw * from - lean, r.bottom());
            s.closeSubpath();
            p.fillPath(s, QColor(255, 255, 255, alpha));
        };
        stripe(0.0, 0.36, 140);
        stripe(0.56, 0.72, 102);
        p.restore();
        p.strokePath(path, QPen(P.ink, 2.0, Qt::SolidLine, Qt::FlatCap, Qt::MiterJoin));
    };

    const qreal paneH = height() - 2.0 * kBrandPad;
    const QRectF a(kBrandPad, kBrandPad, m_compact ? kBotBox + 2.0 * kPanePad : kPaneA, paneH);
    pane(a);
    if (m_compact)
        return;

    // 「磐垒」:墨色斜体字,外面一圈白边。
    {
        QFont f = sticker::headFont(14.0, 900);
        f.setPixelSize(19);
        f.setLetterSpacing(QFont::AbsoluteSpacing, 1.0);
        const QFontMetricsF fm(f);
        QPainterPath glyphs;
        glyphs.addText(0.0, 0.0, f, QString::fromUtf8("磐垒"));
        QTransform t;
        t.translate(a.left() + kPanePad + kBotBox + 5.0, a.center().y() + (fm.ascent() - fm.descent()) / 2.0);
        t.shear(-0.158, 0.0);
        QPainterPath name = t.map(glyphs);
        // 雅黑的笔画轮廓互相叠着:奇偶填充会把叠住的地方挖空。
        name.setFillRule(Qt::WindingFill);
        p.strokePath(name, QPen(QColor(0xFF, 0xFF, 0xFF), 3.0, Qt::SolidLine, Qt::RoundCap, Qt::RoundJoin));
        p.fillPath(name, P.ink);
    }

    const QRectF b(a.right() + kPaneGap, kBrandPad, kPaneB, paneH);
    pane(b);
    const qreal tx = b.left() + 8.0;
    const qreal textRight = b.right() - 4.0;
    const QSizeF lamp(13.0, 9.0);
    QFont tf = sticker::headFont(10.0, QFont::ExtraBold);
    tf.setPixelSize(13);
    // 四个字的状态(「防护关闭」)在 13px 下放不进这扇窗:逐级缩小到放得下为止。
    const qreal titleW = textRight - (tx + lamp.width() + 5.0);
    while (tf.pixelSize() > 10 && QFontMetricsF(tf).horizontalAdvance(m_titanTitle) > titleW)
        tf.setPixelSize(tf.pixelSize() - 1);
    QFont sf = sticker::headFont(7.5, QFont::Bold);
    sf.setPixelSize(10);
    sf.setLetterSpacing(QFont::AbsoluteSpacing, 0.5);
    const qreal titleH = 15.0;
    const qreal subH = 12.0;
    const qreal y0 = b.center().y() - (titleH + 2.0 + subH) / 2.0;

    const QRectF lr(tx, y0 + (titleH - lamp.height()) / 2.0, lamp.width(), lamp.height());
    p.fillRect(lr, P.ink);
    p.fillRect(lr.adjusted(2.0, 2.0, -2.0, -2.0), m_titanLamp.isValid() ? m_titanLamp : QColor(0x45, 0x4F, 0x5F));
    p.fillRect(QRectF(lr.left() + 3.0, lr.top() + 2.0, 4.0, 2.0), QColor(255, 255, 255, 204));

    p.setFont(tf);
    p.setPen(P.ink);
    p.drawText(QRectF(lr.right() + 5.0, y0, titleW + 4.0, titleH), Qt::AlignLeft | Qt::AlignVCenter, m_titanTitle);
    p.setFont(sf);
    p.setPen(QColor(0x1F, 0x5B, 0x80));
    p.drawText(QRectF(tx, y0 + titleH + 2.0, textRight - tx + 2.0, subH), Qt::AlignLeft | Qt::AlignVCenter,
               QFontMetricsF(sf).elidedText(m_titanSub, Qt::ElideRight, textRight - tx + 2.0));
}

void BrandPanel::mouseReleaseEvent(QMouseEvent* e)
{
    if (e->button() == Qt::LeftButton && rect().contains(e->position().toPoint()))
        emit clicked();
    QWidget::mouseReleaseEvent(e);
}
