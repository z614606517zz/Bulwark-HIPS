#include "design/TitanKit.h"
#include "design/Components.h"
#include "design/GlowCard.h"
#include "design/Icons.h"
#include "design/Skin.h"
#include "design/Sticker.h"
#include "design/Theme.h"

#include <QAbstractButton>
#include <QFocusEvent>
#include <QFontMetricsF>
#include <QHBoxLayout>
#include <QLabel>
#include <QPainter>
#include <QPainterPath>
#include <QStringList>
#include <QTextLayout>
#include <QTextOption>
#include <QVBoxLayout>
#include <QtMath>

namespace titankit {

namespace {

// 面板头标题前的色标:9×12 的色块右斜 18°。
class Marker final : public QWidget
{
public:
    explicit Marker(const QColor& c) : m_color(c)
    {
        setFixedSize(15, 14);
        setAttribute(Qt::WA_TransparentForMouseEvents);
    }

    void setColor(const QColor& c)
    {
        if (m_color == c)
            return;
        m_color = c;
        update();
    }

protected:
    void paintEvent(QPaintEvent*) override
    {
        QPainter p(this);
        p.setRenderHint(QPainter::Antialiasing, true);
        p.setPen(Qt::NoPen);
        p.setBrush(m_color);
        p.drawPolygon(QPolygonF{QPointF(5.9, 1), QPointF(14.9, 1), QPointF(11, 13), QPointF(2, 13)});
    }

private:
    QColor m_color;
};

// 上两角切 c、下两角切 s 的板子(设计稿 .plate 的 clip-path)。
QPainterPath chamfered(const QRectF& r, qreal c, qreal s)
{
    QPainterPath path;
    path.moveTo(r.left() + c, r.top());
    path.lineTo(r.right() - c, r.top());
    path.lineTo(r.right(), r.top() + c);
    path.lineTo(r.right(), r.bottom() - s);
    path.lineTo(r.right() - s, r.bottom());
    path.lineTo(r.left() + s, r.bottom());
    path.lineTo(r.left(), r.bottom() - s);
    path.lineTo(r.left(), r.top() + c);
    path.closeSubpath();
    return path;
}

// 设计稿 .btn:切角键帽 + 2px 墨线 + 底部 3px 键裙(内容因此上移 1.5px);ghost 只在悬停时铺浅底;
// 按下整体下沉 1px。
class Button final : public QAbstractButton
{
public:
    enum class Kind { Normal, Primary, Ghost };

    Button(const QString& text, const char* variant, const QString& icon, const QString& iconRight, bool small)
        : m_icon(icon), m_iconRight(iconRight), m_small(small)
    {
        const QByteArray v(variant ? variant : "");
        m_kind = v == "primary" ? Kind::Primary : v == "ghost" ? Kind::Ghost : Kind::Normal;
        m_font = sticker::headFont(small ? 9.0 : 9.375, QFont::Bold);
        setFont(m_font);
        setText(text);
        setCursor(Qt::PointingHandCursor);
        setFocusPolicy(Qt::TabFocus);
        setSizePolicy(QSizePolicy::Fixed, QSizePolicy::Fixed);
        setAttribute(Qt::WA_Hover, true);
    }

    QSize sizeHint() const override
    {
        // 只有图标的方键:设计稿 .btn.icon 宽 30,.btn.icon.sm 宽 26。
        if (text().isEmpty() && m_iconRight.isEmpty())
            return QSize(m_small ? 26 : 30, m_small ? 26 : 32);
        return QSize(qCeil(2.0 * padX() + contentWidth()), m_small ? 26 : 32);
    }
    QSize minimumSizeHint() const override { return sizeHint(); }

protected:
    void focusInEvent(QFocusEvent* e) override
    {
        m_keyFocus = e->reason() == Qt::TabFocusReason || e->reason() == Qt::BacktabFocusReason;
        QAbstractButton::focusInEvent(e);
    }

    void paintEvent(QPaintEvent*) override
    {
        QPainter p(this);
        p.setRenderHint(QPainter::Antialiasing, true);
        p.setRenderHint(QPainter::TextAntialiasing, true);
        if (!isEnabled())
            p.setOpacity(0.45);
        const bool hover = isEnabled() && underMouse();
        if (isDown())
            p.translate(0.0, 1.0);
        const QRectF r(rect());
        const QPainterPath outer = chamfered(r, 7.0, 2.0);
        if (m_kind == Kind::Ghost) {
            if (hover || isDown())
                p.fillPath(outer, QColor(255, 255, 255, 18));
        } else {
            p.fillPath(outer, theme::ink());
            const QPainterPath inner = chamfered(r.adjusted(2, 2, -2, -2), 7.0 - 2.0 * 0.586, 2.0 - 2.0 * 0.586);
            const QColor fill = m_kind == Kind::Primary ? QColor(hover ? 0x2F68EC : 0x2459D8)
                                                        : QColor(hover ? 0x2C3958 : 0x222C42);
            p.fillPath(inner, fill);
            p.save();
            p.setClipPath(inner);
            p.fillRect(QRectF(2.0, r.height() - 5.0, r.width() - 4.0, 3.0), QColor(0, 0, 0, 107));
            p.restore();
        }

        QColor ink = theme::textPrimary();
        QColor glyph = theme::textSecondary();
        if (m_kind == Kind::Primary) {
            ink = glyph = Qt::white;
        } else if (m_kind == Kind::Ghost) {
            ink = glyph = hover ? theme::textPrimary() : theme::textSecondary();
        }
        const qreal cy = (r.height() - (m_kind == Kind::Ghost ? 0.0 : 3.0)) / 2.0;
        qreal x = (r.width() - contentWidth()) / 2.0;
        if (!m_icon.isEmpty()) {
            const qreal s = iconPx();
            AppIcon::draw(p, m_icon, QRectF(x, cy - s / 2.0, s, s), glyph, 1.8);
            x += s + gap();
        }
        const QFontMetricsF fm(m_font);
        p.setFont(m_font);
        p.setPen(ink);
        p.drawText(QPointF(x, cy - (fm.ascent() + fm.descent()) / 2.0 + fm.ascent()), text());
        x += fm.horizontalAdvance(text());
        if (!m_iconRight.isEmpty()) {
            const qreal s = iconRightPx();
            x += gap();
            AppIcon::draw(p, m_iconRight, QRectF(x, cy - s / 2.0, s, s), glyph, 1.8);
        }
        if (hasFocus() && m_keyFocus) {
            p.setPen(QPen(theme::glow(), 1.5));
            p.setBrush(Qt::NoBrush);
            p.drawPath(chamfered(r.adjusted(0.75, 0.75, -0.75, -0.75), 7.0, 2.0));
        }
    }

private:
    qreal padX() const { return m_small ? 10.0 : 14.0; }
    qreal gap() const { return m_small ? 5.0 : 7.0; }
    qreal iconPx() const { return m_small ? 14.0 : 16.0; }
    qreal iconRightPx() const { return m_small ? 13.0 : 15.0; }

    qreal contentWidth() const
    {
        qreal w = QFontMetricsF(m_font).horizontalAdvance(text());
        if (!m_icon.isEmpty())
            w += iconPx() + (text().isEmpty() ? 0.0 : gap());
        if (!m_iconRight.isEmpty())
            w += gap() + iconRightPx();
        return w;
    }

    Kind m_kind = Kind::Normal;
    QString m_icon;
    QString m_iconRight;
    bool m_small = true;
    bool m_keyFocus = false;
    QFont m_font;
};

class LinedText final : public QWidget
{
public:
    LinedText(const QString& text, const QFont& font, const QColor& color, qreal lineHeight, Qt::Alignment align)
        : m_text(text), m_color(color), m_line(lineHeight), m_align(align)
    {
        m_text.replace(QLatin1Char('\n'), QChar::LineSeparator);
        setFont(font);
        QSizePolicy sp(QSizePolicy::Preferred, QSizePolicy::Preferred);
        sp.setHeightForWidth(true);
        setSizePolicy(sp);
    }

    bool hasHeightForWidth() const override { return true; }
    int heightForWidth(int w) const override { return qCeil(lines(w).size() * m_line); }
    QSize sizeHint() const override
    {
        qreal w = 0.0;
        for (const QString& s : m_text.split(QChar::LineSeparator))
            w = qMax(w, QFontMetricsF(font()).horizontalAdvance(s));
        return QSize(qCeil(w), heightForWidth(qCeil(w)));
    }
    QSize minimumSizeHint() const override { return QSize(0, qCeil(m_line)); }

protected:
    void paintEvent(QPaintEvent*) override
    {
        QPainter p(this);
        p.setPen(m_color);
        p.setFont(font());
        const QFontMetricsF fm(font());
        const qreal base = (m_line - fm.ascent() - fm.descent()) / 2.0 + fm.ascent();
        const QStringList ls = lines(width());
        for (int i = 0; i < ls.size(); ++i) {
            qreal x = 0.0;
            if (m_align & Qt::AlignHCenter)
                x = (width() - fm.horizontalAdvance(ls.at(i))) / 2.0;
            else if (m_align & Qt::AlignRight)
                x = width() - fm.horizontalAdvance(ls.at(i));
            p.drawText(QPointF(x, i * m_line + base), ls.at(i));
        }
    }

private:
    QStringList lines(int width) const
    {
        QStringList out;
        QTextLayout layout(m_text, font());
        QTextOption opt;
        opt.setWrapMode(QTextOption::WrapAtWordBoundaryOrAnywhere);
        layout.setTextOption(opt);
        layout.beginLayout();
        for (QTextLine line = layout.createLine(); line.isValid(); line = layout.createLine()) {
            line.setLineWidth(qMax(1, width));
            QString s = m_text.mid(line.textStart(), line.textLength());
            while (!s.isEmpty() && (s.back() == QChar::LineSeparator || s.back().isSpace()))
                s.chop(1);
            out << s;
        }
        layout.endLayout();
        return out;
    }

    QString m_text;
    QColor m_color;
    qreal m_line;
    Qt::Alignment m_align;
};

}

QAbstractButton* button(const QString& text, const char* variant, const QString& icon, const QString& iconRight,
                        bool small)
{
    return new Button(text, variant, icon, iconRight, small);
}

QWidget* lined(const QString& text, const QFont& font, const QColor& color, qreal lineHeight, Qt::Alignment align)
{
    return new LinedText(text, font, color, lineHeight, align);
}

QFont numFont(int px, QFont::Weight weight)
{
    QFont f;
    f.setFamilies({QStringLiteral("Bahnschrift"), QStringLiteral("Segoe UI"), QStringLiteral("Microsoft YaHei UI")});
    f.setPixelSize(px);
    f.setWeight(weight);
    return f;
}

QLabel* labTag(const QString& text)
{
    auto* l = new QLabel(text);
    QFont f = numFont(10, QFont::Bold);
    f.setLetterSpacing(QFont::AbsoluteSpacing, 2.0);
    l->setFont(f);
    l->setFixedHeight(18);
    l->setAlignment(Qt::AlignCenter);
    l->setStyleSheet(QStringLiteral("color:%1; border:1px solid %2; padding:0 5px 0 7px;")
                         .arg(theme::textMuted().name(), theme::pal().borderStrong.name()));
    return l;
}

PanelHead panelHead(const QString& title, const QString& note, const QString& tag, const QColor& hue)
{
    PanelHead h;
    h.widget = new QWidget;
    h.widget->setFixedHeight(38);
    auto* row = new QHBoxLayout(h.widget);
    row->setContentsMargins(16, 2, 14, 0);
    row->setSpacing(8);
    h.marker = new Marker(hue.isValid() ? hue : theme::pal().glow);
    row->addWidget(h.marker, 0, Qt::AlignVCenter);
    // 设计稿 .panel-head h3:800 13px,字距 0.5;雅黑排第一,中文才有真粗体。
    auto* titleLabel = new QLabel(title);
    QFont tf = sticker::headFont(9.75, QFont::ExtraBold);
    tf.setLetterSpacing(QFont::AbsoluteSpacing, 0.5);
    titleLabel->setFont(tf);
    titleLabel->setStyleSheet(QStringLiteral("color:%1;").arg(theme::textPrimary().name()));
    row->addWidget(titleLabel, 0, Qt::AlignVCenter);
    h.note = ui::label(note, "muted");
    row->addWidget(h.note, 0, Qt::AlignVCenter);
    row->addStretch();
    if (!tag.isEmpty())
        row->addWidget(labTag(tag), 0, Qt::AlignVCenter);
    h.trailing = new QHBoxLayout;
    h.trailing->setSpacing(6);
    row->addLayout(h.trailing);
    return h;
}

void setMarkerHue(QWidget* marker, const QColor& hue)
{
    if (marker)
        static_cast<Marker*>(marker)->setColor(hue.isValid() ? hue : theme::pal().glow);
}

Panel panel(const QString& title, const QString& note, const QString& tag, const QColor& hue)
{
    Panel p;
    p.card = ui::card();
    auto* v = new QVBoxLayout(p.card);
    v->setContentsMargins(0, 0, 0, 0);
    v->setSpacing(0);
    p.head = panelHead(title, note, tag, hue);
    v->addWidget(p.head.widget);
    auto* body = new QWidget;
    p.body = new QVBoxLayout(body);
    p.body->setContentsMargins(16, 2, 14, 14);
    p.body->setSpacing(8);
    v->addWidget(body, 1);
    return p;
}

QWidget* reading(QLabel** value, const QString& label)
{
    auto* w = new QWidget;
    auto* h = new QHBoxLayout(w);
    h->setContentsMargins(0, 0, 0, 0);
    h->setSpacing(6);
    auto* v = new QLabel;
    v->setFont(numFont(19, QFont::ExtraBold));
    setReading(v, -1);
    h->addWidget(v, 0, Qt::AlignBaseline);
    h->addWidget(ui::label(label, "muted"), 0, Qt::AlignBaseline);
    if (value)
        *value = v;
    return w;
}

void setReading(QLabel* value, int n, const QColor& color)
{
    value->setText(n < 0 ? QStringLiteral("—") : QString::number(n));
    const QColor c = n < 0 ? theme::textMuted() : color.isValid() ? color : theme::textPrimary();
    value->setStyleSheet(QStringLiteral("color:%1;").arg(c.name()));
}

namespace {
constexpr int kSpecRow = 20;
}

SpecBars::SpecBars(QList<Bar> bars) : m_bars(std::move(bars))
{
    setFixedHeight(int(m_bars.size()) * kSpecRow);
    setAttribute(Qt::WA_TransparentForMouseEvents);
}

void SpecBars::paintEvent(QPaintEvent*)
{
    const theme::Palette& P = theme::pal();
    QPainter p(this);
    p.setRenderHint(QPainter::TextAntialiasing, true);
    QFont f = font();
    f.setPixelSize(12);
    const QFont num = numFont(12, QFont::Bold);
    constexpr int kName = 64;
    constexpr int kValue = 66;
    constexpr int kCell = 5;
    constexpr int kGap = 2;
    const QColor off = theme::blend(P.textMuted, P.surface, 0.2);
    const int cells = qMax(4, (width() - kName - kValue - 6 + kGap) / (kCell + kGap));
    for (int i = 0; i < m_bars.size(); ++i) {
        const Bar& b = m_bars.at(i);
        const int y = i * kSpecRow;
        p.setFont(f);
        p.setPen(P.textMuted);
        p.drawText(QRect(0, y, kName, kSpecRow), Qt::AlignVCenter | Qt::AlignLeft, b.name);
        const double ratio = b.full > 0.0 ? b.value / b.full : 0.0;
        const int lit = b.value <= 0.0 ? 0 : qBound(1, int(ratio * cells + 0.5), cells);
        for (int c = 0; c < cells; ++c)
            p.fillRect(QRect(kName + c * (kCell + kGap), y + (kSpecRow - 10) / 2, kCell, 10), c < lit ? b.color : off);
        p.setFont(num);
        p.setPen(b.value > 0.0 ? P.text : P.textMuted);
        p.drawText(QRect(width() - kValue, y, kValue, kSpecRow), Qt::AlignVCenter | Qt::AlignRight, b.text);
    }
}

}
