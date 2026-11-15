#include "design/SvgPath.h"

#include <QTransform>
#include <QtMath>

#include <cmath>

namespace svg {
namespace {

class Reader
{
public:
    explicit Reader(QStringView s) : m_s(s) {}

    void skip()
    {
        while (m_i < m_s.size() && (m_s[m_i].isSpace() || m_s[m_i] == QLatin1Char(',')))
            ++m_i;
    }
    bool atEnd()
    {
        skip();
        return m_i >= m_s.size();
    }
    bool atCommand()
    {
        skip();
        return m_i < m_s.size() && m_s[m_i].isLetter() && m_s[m_i] != QLatin1Char('e')
               && m_s[m_i] != QLatin1Char('E');
    }
    QChar command() { return m_s[m_i++]; }

    bool number(qreal& out)
    {
        skip();
        const qsizetype start = m_i;
        if (m_i < m_s.size() && (m_s[m_i] == QLatin1Char('-') || m_s[m_i] == QLatin1Char('+')))
            ++m_i;
        bool digits = false, dot = false;
        while (m_i < m_s.size()) {
            const QChar c = m_s[m_i];
            if (c.isDigit()) {
                digits = true;
                ++m_i;
            } else if (c == QLatin1Char('.') && !dot) {
                dot = true;
                ++m_i;
            } else {
                break;
            }
        }
        if (digits && m_i < m_s.size() && (m_s[m_i] == QLatin1Char('e') || m_s[m_i] == QLatin1Char('E'))) {
            qsizetype j = m_i + 1;
            if (j < m_s.size() && (m_s[j] == QLatin1Char('-') || m_s[j] == QLatin1Char('+')))
                ++j;
            if (j < m_s.size() && m_s[j].isDigit()) {
                m_i = j;
                while (m_i < m_s.size() && m_s[m_i].isDigit())
                    ++m_i;
            }
        }
        if (!digits) {
            m_i = start;
            return false;
        }
        out = m_s.mid(start, m_i - start).toDouble();
        return true;
    }

    // Arc flags may be written without separators ("0 01 15 0").
    bool flag(bool& out)
    {
        skip();
        if (m_i >= m_s.size())
            return false;
        const QChar c = m_s[m_i];
        if (c != QLatin1Char('0') && c != QLatin1Char('1'))
            return false;
        out = c == QLatin1Char('1');
        ++m_i;
        return true;
    }

private:
    QStringView m_s;
    qsizetype m_i = 0;
};

void arcTo(QPainterPath& p, QPointF from, qreal rx, qreal ry, qreal angleDeg, bool large, bool sweep, QPointF to)
{
    if (rx == 0.0 || ry == 0.0 || from == to) {
        p.lineTo(to);
        return;
    }
    rx = std::abs(rx);
    ry = std::abs(ry);
    const qreal phi = qDegreesToRadians(angleDeg);
    const qreal cphi = std::cos(phi), sphi = std::sin(phi);
    const qreal dx = (from.x() - to.x()) / 2.0, dy = (from.y() - to.y()) / 2.0;
    const qreal x1 = cphi * dx + sphi * dy;
    const qreal y1 = -sphi * dx + cphi * dy;
    qreal lambda = (x1 * x1) / (rx * rx) + (y1 * y1) / (ry * ry);
    if (lambda > 1.0) {
        const qreal k = std::sqrt(lambda);
        rx *= k;
        ry *= k;
    }
    const qreal num = rx * rx * ry * ry - rx * rx * y1 * y1 - ry * ry * x1 * x1;
    const qreal den = rx * rx * y1 * y1 + ry * ry * x1 * x1;
    qreal coef = den == 0.0 ? 0.0 : std::sqrt(qMax<qreal>(0.0, num / den));
    if (large == sweep)
        coef = -coef;
    const qreal cx1 = coef * (rx * y1 / ry);
    const qreal cy1 = coef * -(ry * x1 / rx);
    const qreal cx = cphi * cx1 - sphi * cy1 + (from.x() + to.x()) / 2.0;
    const qreal cy = sphi * cx1 + cphi * cy1 + (from.y() + to.y()) / 2.0;

    const auto angle = [](qreal ux, qreal uy, qreal vx, qreal vy) {
        const qreal a = std::atan2(ux * vy - uy * vx, ux * vx + uy * vy);
        return a;
    };
    const qreal t1 = angle(1.0, 0.0, (x1 - cx1) / rx, (y1 - cy1) / ry);
    qreal dt = angle((x1 - cx1) / rx, (y1 - cy1) / ry, (-x1 - cx1) / rx, (-y1 - cy1) / ry);
    if (!sweep && dt > 0)
        dt -= 2 * M_PI;
    else if (sweep && dt < 0)
        dt += 2 * M_PI;

    const int segs = qMax(1, int(std::ceil(std::abs(dt) / (M_PI / 2.0) - 1e-6)));
    const qreal step = dt / segs;
    const qreal alpha = 4.0 / 3.0 * std::tan(step / 4.0);
    const auto pt = [&](qreal t) {
        const qreal x = rx * std::cos(t), y = ry * std::sin(t);
        return QPointF(cphi * x - sphi * y + cx, sphi * x + cphi * y + cy);
    };
    const auto deriv = [&](qreal t) {
        const qreal x = -rx * std::sin(t), y = ry * std::cos(t);
        return QPointF(cphi * x - sphi * y, sphi * x + cphi * y);
    };
    qreal t = t1;
    for (int i = 0; i < segs; ++i) {
        const qreal tn = t + step;
        const QPointF p0 = pt(t), p3 = pt(tn);
        const QPointF c1 = p0 + alpha * deriv(t);
        const QPointF c2 = p3 - alpha * deriv(tn);
        p.cubicTo(c1, c2, i == segs - 1 ? to : p3);
        t = tn;
    }
}

}

QPainterPath path(QStringView d)
{
    QPainterPath p;
    Reader r(d);
    QChar cmd;
    QPointF cur, start, lastCtrl;
    QChar lastCmd;
    while (!r.atEnd()) {
        if (r.atCommand())
            cmd = r.command();
        else if (cmd.isNull())
            break;
        const bool rel = cmd.isLower();
        const QChar C = cmd.toUpper();
        const QPointF base = rel ? cur : QPointF(0, 0);
        qreal a = 0, b = 0, c = 0, dd = 0, e = 0, f = 0;
        bool ok = true;
        if (C == QLatin1Char('Z')) {
            p.closeSubpath();
            cur = start;
            lastCmd = C;
            cmd = QChar();
            continue;
        }
        if (C == QLatin1Char('M')) {
            ok = r.number(a) && r.number(b);
            if (!ok)
                break;
            cur = base + QPointF(a, b);
            start = cur;
            p.moveTo(cur);
            cmd = rel ? QLatin1Char('l') : QLatin1Char('L');
            lastCmd = QLatin1Char('M');
            continue;
        }
        if (C == QLatin1Char('L')) {
            ok = r.number(a) && r.number(b);
            if (ok) {
                cur = base + QPointF(a, b);
                p.lineTo(cur);
            }
        } else if (C == QLatin1Char('H')) {
            ok = r.number(a);
            if (ok) {
                cur.setX(rel ? cur.x() + a : a);
                p.lineTo(cur);
            }
        } else if (C == QLatin1Char('V')) {
            ok = r.number(a);
            if (ok) {
                cur.setY(rel ? cur.y() + a : a);
                p.lineTo(cur);
            }
        } else if (C == QLatin1Char('C')) {
            ok = r.number(a) && r.number(b) && r.number(c) && r.number(dd) && r.number(e) && r.number(f);
            if (ok) {
                const QPointF c1 = base + QPointF(a, b), c2 = base + QPointF(c, dd), to = base + QPointF(e, f);
                p.cubicTo(c1, c2, to);
                lastCtrl = c2;
                cur = to;
            }
        } else if (C == QLatin1Char('S')) {
            ok = r.number(c) && r.number(dd) && r.number(e) && r.number(f);
            if (ok) {
                const QPointF c1 = (lastCmd == QLatin1Char('C') || lastCmd == QLatin1Char('S'))
                                       ? 2 * cur - lastCtrl : cur;
                const QPointF c2 = base + QPointF(c, dd), to = base + QPointF(e, f);
                p.cubicTo(c1, c2, to);
                lastCtrl = c2;
                cur = to;
            }
        } else if (C == QLatin1Char('Q')) {
            ok = r.number(a) && r.number(b) && r.number(c) && r.number(dd);
            if (ok) {
                const QPointF q = base + QPointF(a, b), to = base + QPointF(c, dd);
                p.quadTo(q, to);
                lastCtrl = q;
                cur = to;
            }
        } else if (C == QLatin1Char('T')) {
            ok = r.number(c) && r.number(dd);
            if (ok) {
                const QPointF q = (lastCmd == QLatin1Char('Q') || lastCmd == QLatin1Char('T'))
                                      ? 2 * cur - lastCtrl : cur;
                const QPointF to = base + QPointF(c, dd);
                p.quadTo(q, to);
                lastCtrl = q;
                cur = to;
            }
        } else if (C == QLatin1Char('A')) {
            bool large = false, sweep = false;
            ok = r.number(a) && r.number(b) && r.number(c) && r.flag(large) && r.flag(sweep) && r.number(e)
                 && r.number(f);
            if (ok) {
                const QPointF to = base + QPointF(e, f);
                arcTo(p, cur, a, b, c, large, sweep, to);
                cur = to;
            }
        } else {
            break;
        }
        if (!ok)
            break;
        lastCmd = C;
    }
    return p;
}

QPolygonF points(QStringView pts)
{
    QPolygonF out;
    Reader r(pts);
    qreal x = 0, y = 0;
    while (r.number(x) && r.number(y))
        out << QPointF(x, y);
    return out;
}

}
