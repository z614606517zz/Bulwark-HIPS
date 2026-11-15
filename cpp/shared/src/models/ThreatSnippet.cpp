#include "bulwark/models/ThreatSnippet.h"
#include "bulwark/json/JsonSupport.h"

#include <QChar>
#include <QJsonArray>

#include <limits>

namespace bulwark {
using namespace bulwark::json;

namespace {

bool needsEscape(char32_t cp)
{
    switch (QChar::category(cp)) {
    case QChar::Other_Control:
    case QChar::Other_Format:
    case QChar::Other_Surrogate:
    case QChar::Other_PrivateUse:
    case QChar::Other_NotAssigned:
    case QChar::Separator_Line:
    case QChar::Separator_Paragraph:
        return true;
    default:
        return false;
    }
}

QString escapeOf(char32_t cp)
{
    if (cp < 0x100)
        return QStringLiteral("\\x%1").arg(uint(cp), 2, 16, QLatin1Char('0'));
    if (cp <= 0xFFFF)
        return QStringLiteral("\\u%1").arg(uint(cp), 4, 16, QLatin1Char('0'));
    return QStringLiteral("\\u{%1}").arg(uint(cp), 0, 16);
}

struct Mapped {
    QString text;
    QVector<int> map;
};

Mapped sanitizeMapped(QStringView raw)
{
    Mapped m;
    m.text.reserve(int(raw.size()));
    m.map.resize(int(raw.size()) + 1);
    for (qsizetype i = 0; i < raw.size();) {
        const QChar c = raw[i];
        char32_t cp = c.unicode();
        qsizetype len = 1;
        if (c.isHighSurrogate() && i + 1 < raw.size() && raw[i + 1].isLowSurrogate()) {
            cp = QChar::surrogateToUcs4(c, raw[i + 1]);
            len = 2;
        }
        const int at = int(m.text.size());
        for (qsizetype k = 0; k < len; ++k)
            m.map[int(i + k)] = at;
        if (cp == U'\t') {
            m.text += QLatin1String("    ");
        } else if (needsEscape(cp)) {
            m.text += escapeOf(cp);
        } else {
            m.text += c;
            if (len == 2)
                m.text += raw[i + 1];
        }
        i += len;
    }
    m.map[int(raw.size())] = int(m.text.size());
    return m;
}

const QChar kEllipsis(0x2026);

}

QJsonObject SnippetLine::toJson() const
{
    QJsonObject o;
    if (number != 0) o["n"] = number;
    o["t"] = text;
    if (hit) o["h"] = true;
    if (hitStart >= 0) o["s"] = hitStart;
    if (hitLength > 0) o["l"] = hitLength;
    return o;
}

SnippetLine SnippetLine::fromJson(const QJsonObject& o)
{
    SnippetLine l;
    l.number = qMax(0, getInt(o, "n"));
    QString t = getStr(o, "t");
    if (t.size() > ThreatSnippet::kMaxWrapChars + 8)
        t = t.left(ThreatSnippet::kMaxWrapChars + 8);
    l.text = snippet::sanitize(t);
    l.hit = getBool(o, "h");
    l.hitStart = getInt(o, "s", -1);
    l.hitLength = qMax(0, getInt(o, "l"));
    if (l.hitStart < 0 || l.hitStart > l.text.size()) {
        l.hitStart = -1;
        l.hitLength = 0;
    } else {
        l.hitLength = qMin(l.hitLength, int(l.text.size()) - l.hitStart);
    }
    return l;
}

bool ThreatSnippet::sameAs(const ThreatSnippet& other) const
{
    if (title != other.title || lines.size() != other.lines.size())
        return false;
    if (lines.isEmpty())
        return true;
    return lines.first() == other.lines.first() && lines.last() == other.lines.last();
}

QString ThreatSnippet::plainText() const
{
    QStringList parts;
    parts.reserve(lines.size());
    for (const SnippetLine& l : lines)
        parts << l.text;
    return parts.join(QLatin1Char('\n'));
}

QJsonObject ThreatSnippet::toJson() const
{
    QJsonObject o;
    o["title"] = title;
    QJsonArray arr;
    for (const SnippetLine& l : lines)
        arr.append(l.toJson());
    o["lines"] = arr;
    if (wrap) o["wrap"] = true;
    if (totalChars > 0) o["total"] = totalChars;
    if (truncated) o["cut"] = true;
    return o;
}

ThreatSnippet ThreatSnippet::fromJson(const QJsonObject& o)
{
    ThreatSnippet s;
    s.title = snippet::titleFromName(getStr(o, "title"));
    s.wrap = getBool(o, "wrap");
    s.totalChars = qMax(0, getInt(o, "total"));
    s.truncated = getBool(o, "cut");
    const QJsonArray arr = o.value(QLatin1String("lines")).toArray();
    for (const QJsonValue& v : arr) {
        if (s.lines.size() >= kMaxLines) {
            s.truncated = true;
            break;
        }
        s.lines.push_back(SnippetLine::fromJson(v.toObject()));
    }
    return s;
}

namespace snippet {

QString sanitize(QStringView raw)
{
    return sanitizeMapped(raw).text;
}

SnippetLine makeLine(int number, QStringView raw, bool hit, qsizetype hitStart, qsizetype hitLength,
                     int maxChars, bool* cut)
{
    SnippetLine out;
    out.number = number;
    out.hit = hit;
    maxChars = qMax(8, maxChars);

    const qsizetype n = raw.size();
    const bool hasPos = hitStart >= 0 && hitStart <= n;
    if (hasPos)
        hitLength = qBound<qsizetype>(0, hitLength, n - hitStart);
    const bool hasSpan = hasPos && hitLength > 0;

    qsizetype rs = 0;
    qsizetype re = n;
    if (hasPos) {
        rs = qMax<qsizetype>(0, hitStart - 96);
        re = qMin<qsizetype>(n, hitStart + hitLength + qsizetype(maxChars) * 2);
    } else {
        re = qMin<qsizetype>(n, qsizetype(maxChars) * 2);
    }
    if (rs > 0 && rs < n && raw[rs].isLowSurrogate() && raw[rs - 1].isHighSurrogate())
        --rs;
    if (re < n && re > 0 && raw[re].isLowSurrogate() && raw[re - 1].isHighSurrogate())
        ++re;

    const Mapped m = sanitizeMapped(raw.mid(rs, re - rs));
    const QString& sa = m.text;
    const int total = int(sa.size());

    int sHs = -1, sHe = -1;
    if (hasPos) {
        sHs = m.map[int(hitStart - rs)];
        sHe = m.map[int(qMin<qsizetype>(hitStart + hitLength, re) - rs)];
    }

    const bool moreLeft = rs > 0;
    const bool moreRight = re < n;

    int a = 0;
    if (hasPos) {
        const int room = maxChars - (moreLeft ? 1 : 0) - 1;
        if (sHe > room)
            a = qMax(0, sHs - 24);
    }
    if (a > 0 && a < total && sa[a].isLowSurrogate() && sa[a - 1].isHighSurrogate())
        ++a;

    const bool prefix = a > 0 || moreLeft;
    int avail = maxChars - (prefix ? 1 : 0);
    int b = qMin(total, a + avail);
    const bool suffix = b < total || moreRight;
    if (suffix) {
        avail -= 1;
        b = qMin(total, a + avail);
    }
    if (b < total && b > a && sa[b].isLowSurrogate() && sa[b - 1].isHighSurrogate())
        --b;
    b = qMax(a, b);

    QString text;
    text.reserve(b - a + 2);
    if (prefix) text += kEllipsis;
    text.append(QStringView(sa).mid(a, b - a));
    if (suffix) text += kEllipsis;
    out.text = text;
    if (cut && (prefix || suffix))
        *cut = true;

    if (hasSpan && sHs < b && sHe > a) {
        const int s = qMax(sHs, a);
        const int e = qMin(sHe, b);
        out.hitStart = s - a + (prefix ? 1 : 0);
        out.hitLength = qMax(0, e - s);
    }
    return out;
}

QString titleFromName(const QString& name)
{
    QString s = sanitize(name).trimmed();
    constexpr int kMax = ThreatSnippet::kMaxTitleChars;
    if (s.size() > kMax) {
        const int keep = kMax - 1;
        const int head = (keep + 1) / 2;
        s = s.left(head) + kEllipsis + s.right(keep - head);
    }
    return s;
}

ThreatSnippet fromText(const QString& title, const QString& text)
{
    ThreatSnippet s;
    s.title = titleFromName(title);
    s.wrap = true;
    s.totalChars = int(qMin<qsizetype>(text.size(), std::numeric_limits<int>::max()));

    qsizetype budget = ThreatSnippet::kMaxWrapChars;
    qsizetype pos = 0;
    const QStringView all(text);
    while (pos <= all.size()) {
        if (s.lines.size() >= ThreatSnippet::kMaxLines || budget <= 0) {
            s.truncated = true;
            break;
        }
        qsizetype nl = all.indexOf(QLatin1Char('\n'), pos);
        const bool last = nl < 0;
        if (last)
            nl = all.size();
        QStringView raw = all.mid(pos, nl - pos);
        if (!raw.isEmpty() && raw.last() == QLatin1Char('\r'))
            raw.chop(1);
        const qsizetype take = qMin<qsizetype>(raw.size(), budget);
        SnippetLine line;
        line.text = sanitize(raw.left(take));
        if (take < raw.size()) {
            line.text += kEllipsis;
            s.truncated = true;
        }
        budget -= take;
        s.lines.push_back(line);
        if (last)
            break;
        pos = nl + 1;
    }
    while (s.lines.size() > 1 && s.lines.last().text.trimmed().isEmpty())
        s.lines.removeLast();
    return s;
}

}
}
