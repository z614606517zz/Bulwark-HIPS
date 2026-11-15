#include "widgets/CodeBlock.h"
#include "design/Theme.h"

#include <QFontMetrics>
#include <QPainter>
#include <QPainterPath>
#include <QPaintEvent>
#include <QPair>

using bulwark::SnippetLine;
using bulwark::ThreatSnippet;

namespace {

constexpr int kPadH = 10;
constexpr int kPadV = 7;
constexpr int kBar = 3;
constexpr int kGutterGap = 10;
constexpr int kRadius = 8;
constexpr int kLead = 8;

const QChar kEllipsis(0x2026);

QString u(const char* s) { return QString::fromUtf8(s); }

void fitWindow(const QFontMetrics& fm, const QString& t, int hs, int hl, int widthPx,
               QString* out, int* ohs, int* ohl)
{
    *ohs = -1;
    *ohl = 0;
    if (fm.horizontalAdvance(t) <= widthPx) {
        *out = t;
        if (hs >= 0 && hl > 0) {
            *ohs = hs;
            *ohl = hl;
        }
        return;
    }
    const int n = int(t.size());
    QVector<int> pw(n + 1, 0);
    for (int i = 0; i < n; ++i)
        pw[i + 1] = pw[i] + fm.horizontalAdvance(t[i]);
    const int ell = fm.horizontalAdvance(kEllipsis);

    const int he = (hs >= 0) ? qMin(n, hs + qMax(hl, 0)) : 0;
    int a = 0;
    if (hs >= 0 && pw[he] > widthPx - ell)
        a = qMax(0, hs - kLead);
    if (a > 0 && a < n && t[a].isLowSurrogate() && t[a - 1].isHighSurrogate())
        ++a;

    const bool pre = a > 0;
    const int budget = widthPx - (pre ? ell : 0);
    int b = a;
    while (b < n && pw[b + 1] - pw[a] <= budget - ell)
        ++b;
    bool suf = b < n;
    if (suf && pw[n] - pw[a] <= budget) {
        b = n;
        suf = false;
    }
    if (suf && b > a && b < n && t[b].isLowSurrogate() && t[b - 1].isHighSurrogate())
        --b;

    QString text;
    if (pre) text += kEllipsis;
    text += t.mid(a, b - a);
    if (suf) text += kEllipsis;
    *out = text;

    if (hs >= 0 && hl > 0 && hs < b && he > a) {
        const int s = qMax(hs, a);
        const int e = qMin(he, b);
        *ohs = s - a + (pre ? 1 : 0);
        *ohl = qMax(0, e - s);
    }
}

QVector<QPair<int, int>> wrapRanges(const QFontMetrics& fm, const QString& t, int widthPx)
{
    QVector<QPair<int, int>> out;
    const int n = int(t.size());
    if (n == 0) {
        out.push_back({0, 0});
        return out;
    }
    int start = 0;
    int acc = 0;
    int lastBreak = -1;
    for (int i = 0; i < n; ++i) {
        const int adv = fm.horizontalAdvance(t[i]);
        if (acc + adv > widthPx && i > start) {
            int cut = i;
            if (lastBreak > start && (lastBreak - start) * 2 >= (i - start))
                cut = lastBreak;
            if (cut > start + 1 && t[cut].isLowSurrogate() && t[cut - 1].isHighSurrogate())
                --cut;
            out.push_back({start, cut});
            start = cut;
            acc = fm.horizontalAdvance(t.mid(start, i - start));
            lastBreak = -1;
        }
        acc += adv;
        if (t[i] == QLatin1Char(' '))
            lastBreak = i + 1;
    }
    out.push_back({start, n});
    return out;
}

}

CodeBlock::CodeBlock(const ThreatSnippet& snippet, const QColor& accent, int maxRows, QWidget* parent)
    : QWidget(parent), m_snippet(snippet), m_accent(accent), m_maxRows(qMax(2, maxRows))
{
    QFont f;
    f.setFamilies({QStringLiteral("Cascadia Mono"), QStringLiteral("Consolas")});
    f.setStyleHint(QFont::Monospace);
    f.setFixedPitch(true);
    f.setPointSizeF(9.0);
    m_font = f;

    QSizePolicy sp(QSizePolicy::Expanding, QSizePolicy::Preferred);
    sp.setHeightForWidth(true);
    setSizePolicy(sp);
    setFocusPolicy(Qt::NoFocus);

    int maxNo = 0;
    for (const SnippetLine& l : m_snippet.lines)
        maxNo = qMax(maxNo, l.number);
    if (maxNo > 0) {
        const QFontMetrics fm(m_font, this);
        m_gutterW = fm.horizontalAdvance(QString(qMax(2, int(QString::number(maxNo).size())), QLatin1Char('0')))
                  + kGutterGap;
    }

    setAccessibleName(u("威胁代码段"));
    setAccessibleDescription(m_snippet.plainText().left(400));
}

int CodeBlock::rowHeight() const
{
    const QFontMetrics fm(m_font, this);
    return fm.lineSpacing() + 3;
}

QVector<CodeBlock::Row> CodeBlock::buildRows(int width) const
{
    const QFontMetrics fm(m_font, this);
    const int textW = qMax(48, width - 2 * kPadH - m_gutterW);

    QVector<Row> rows;
    int prevNo = 0;
    for (const SnippetLine& l : m_snippet.lines) {
        if (!m_snippet.wrap) {
            if (prevNo > 0 && l.number > prevNo + 1) {
                Row gap;
                gap.kind = Row::Kind::Gap;
                rows.push_back(gap);
            }
            Row r;
            r.number = l.number;
            r.hit = l.hit;
            fitWindow(fm, l.text, l.hitStart, l.hitLength, textW, &r.text, &r.hitStart, &r.hitLength);
            rows.push_back(r);
            if (l.number > 0)
                prevNo = l.number;
            continue;
        }
        const int he = l.hitStart >= 0 ? l.hitStart + l.hitLength : -1;
        const auto pieces = wrapRanges(fm, l.text, textW);
        bool first = true;
        for (const auto& pc : pieces) {
            Row r;
            r.number = first ? l.number : 0;
            r.hit = l.hit;
            r.text = l.text.mid(pc.first, pc.second - pc.first);
            if (l.hitStart >= 0 && l.hitLength > 0 && l.hitStart < pc.second && he > pc.first) {
                const int s = qMax(l.hitStart, pc.first);
                const int e = qMin(he, pc.second);
                r.hitStart = s - pc.first;
                r.hitLength = e - s;
            }
            rows.push_back(r);
            first = false;
        }
    }

    // 超出行数上限:留 maxRows-1 行,最后一行写明还有多少没画。
    if (rows.size() > m_maxRows) {
        const int hidden = int(rows.size()) - (m_maxRows - 1);
        rows.resize(m_maxRows - 1);
        Row more;
        more.kind = Row::Kind::More;
        more.text = m_snippet.wrap ? u("… 其余内容已省略(可复制查看全文)")
                                   : u("… 另有 %1 行未显示").arg(hidden);
        rows.push_back(more);
    }
    return rows;
}

const QVector<CodeBlock::Row>& CodeBlock::rowsFor(int width) const
{
    if (width != m_cacheW) {
        m_rows = buildRows(width);
        m_cacheW = width;
    }
    return m_rows;
}

int CodeBlock::heightForWidth(int w) const
{
    return int(rowsFor(w).size()) * rowHeight() + 2 * kPadV;
}

QSize CodeBlock::sizeHint() const
{
    return {360, heightForWidth(360)};
}

QSize CodeBlock::minimumSizeHint() const
{
    return {120, rowHeight() + 2 * kPadV};
}

void CodeBlock::paintEvent(QPaintEvent*)
{
    QPainter p(this);
    p.setRenderHint(QPainter::Antialiasing, true);

    // 代码画在深色「终端屏」上:命中行亮黄,其余行灰白。
    const theme::Palette& P = theme::pal();
    const bool mecha = theme::mecha();
    const QRectF box = QRectF(rect()).adjusted(1.0, 1.0, -1.0, -1.0);
    const QPainterPath frame = theme::panelPath(box, mecha ? 5.0 : 9.0);
    p.fillPath(frame, P.screen);
    p.strokePath(frame, QPen(P.ink, 2.0, Qt::SolidLine, Qt::FlatCap, mecha ? Qt::MiterJoin : Qt::RoundJoin));

    p.setClipRect(rect().adjusted(2, 2, -2, -2));
    p.setFont(m_font);
    p.setRenderHint(QPainter::Antialiasing, false);

    const QFontMetrics fm(m_font, this);
    const int rh = rowHeight();
    const int textX = kPadH + m_gutterW;
    const QColor accent = m_accent == theme::success() ? P.glow : m_accent;
    const QColor hitText = mecha ? QColor(0xFF, 0xCF, 0x33) : QColor(0xFF, 0xE2, 0x7A);
    const QColor hitBg = theme::blend(accent, P.screen, 0.22);
    const QColor spanBg = theme::blend(accent, P.screen, 0.50);

    int y = kPadV;
    for (const Row& row : rowsFor(width())) {
        const int baseline = y + (rh - fm.height()) / 2 + fm.ascent();

        if (row.kind == Row::Kind::Code && row.hit) {
            p.fillRect(QRect(2, y, width() - 4, rh), hitBg);
            p.fillRect(QRect(2, y, kBar, rh), accent);
        }

        if (row.kind == Row::Kind::Gap) {
            p.setPen(P.scrMuted);
            p.drawText(textX, baseline, QString(kEllipsis));
        } else if (row.kind == Row::Kind::More) {
            p.setPen(P.scrMuted);
            p.drawText(textX, baseline, row.text);
        } else {
            if (m_gutterW > 0 && row.number > 0) {
                p.setPen(row.hit ? accent : P.scrMuted);
                const QString no = QString::number(row.number);
                const int right = kPadH + m_gutterW - kGutterGap;
                p.drawText(right - fm.horizontalAdvance(no), baseline, no);
            }
            if (row.hitStart >= 0 && row.hitLength > 0) {
                const int x0 = textX + fm.horizontalAdvance(row.text.left(row.hitStart));
                const int w = fm.horizontalAdvance(row.text.mid(row.hitStart, row.hitLength));
                p.fillRect(QRect(x0, y + 1, w, rh - 2), spanBg);
            }
            p.setPen(row.hit ? hitText : P.scrText2);
            p.drawText(textX, baseline, row.text);
        }
        y += rh;
    }
}
