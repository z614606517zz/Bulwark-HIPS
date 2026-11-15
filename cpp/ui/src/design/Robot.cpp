#include "design/Robot.h"
#include "design/Motion.h"
#include "design/Skin.h"
#include "design/SvgPath.h"

#include <QEasingCurve>
#include <QFont>
#include <QPainter>
#include <QPainterPath>
#include <QRandomGenerator>
#include <QShowEvent>
#include <QTimer>
#include <QTransform>
#include <QtMath>

#include <cmath>
#include <functional>
#include <initializer_list>
#include <utility>

namespace robot {
namespace {

QColor hexc(const char* h) { return QColor::fromString(QLatin1StringView(h)); }
const QColor kWhite(0xFF, 0xFF, 0xFF);

enum class Ex { Guard, Happy, Ask, Alert, Think, Boost, Info, Sleep, Blink, LookL };

Ex exprOf(const Look& lk)
{
    if (lk.blink)
        return Ex::Blink;
    if (lk.lookLeft)
        return Ex::LookL;
    return Ex(int(lk.mood));
}

// 基本形状(全部在设计稿的 viewBox 坐标里)
QPainterPath rectP(qreal x, qreal y, qreal w, qreal h, qreal r = 0)
{
    QPainterPath p;
    if (r > 0)
        p.addRoundedRect(QRectF(x, y, w, h), r, r);
    else
        p.addRect(QRectF(x, y, w, h));
    return p;
}
QPainterPath ellP(qreal cx, qreal cy, qreal rx, qreal ry)
{
    QPainterPath p;
    p.addEllipse(QPointF(cx, cy), rx, ry);
    return p;
}
QPainterPath circP(qreal cx, qreal cy, qreal r) { return ellP(cx, cy, r, r); }
QPainterPath polyP(std::initializer_list<QPointF> pts)
{
    QPainterPath p;
    p.addPolygon(QPolygonF(QList<QPointF>(pts)));
    p.closeSubpath();
    return p;
}
QPainterPath polyP(const QPolygonF& pts)
{
    QPainterPath p;
    p.addPolygon(pts);
    p.closeSubpath();
    return p;
}
QPolygonF hexPts(qreal cx, qreal cy, qreal r)
{
    QPolygonF out;
    for (int i = 0; i < 6; ++i) {
        const qreal a = M_PI / 3.0 * i - M_PI / 2.0;
        out << QPointF(cx + r * std::cos(a), cy + r * std::sin(a));
    }
    return out;
}
QPainterPath hexP(qreal cx, qreal cy, qreal r) { return polyP(hexPts(cx, cy, r)); }
QPainterPath lineP(qreal x1, qreal y1, qreal x2, qreal y2)
{
    QPainterPath p;
    p.moveTo(x1, y1);
    p.lineTo(x2, y2);
    return p;
}

void fill(QPainter& p, const QPainterPath& path, const QColor& c, qreal opacity = 1.0)
{
    if (opacity >= 1.0) {
        p.fillPath(path, c);
        return;
    }
    p.save();
    p.setOpacity(p.opacity() * opacity);
    p.fillPath(path, c);
    p.restore();
}

void stroke(QPainter& p, const QPainterPath& path, const QColor& c, qreal w, qreal opacity = 1.0,
            Qt::PenCapStyle cap = Qt::RoundCap, Qt::PenJoinStyle join = Qt::RoundJoin, qreal dash = 0.0)
{
    p.save();
    if (opacity < 1.0)
        p.setOpacity(p.opacity() * opacity);
    QPen pen(c, w, Qt::SolidLine, cap, join);
    if (dash > 0.0)
        pen.setDashPattern({dash / w, dash / w});
    p.strokePath(path, pen);
    p.restore();
}

void fillStroke(QPainter& p, const QPainterPath& path, const QColor& f, const QColor& s, qreal w,
                Qt::PenJoinStyle join = Qt::RoundJoin)
{
    p.fillPath(path, f);
    p.strokePath(path, QPen(s, w, Qt::SolidLine, Qt::RoundCap, join));
}

void rotateAbout(QPainter& p, qreal deg, qreal cx, qreal cy)
{
    p.translate(cx, cy);
    p.rotate(deg);
    p.translate(-cx, -cy);
}

// text-anchor="middle" 的字形:按 100px 排一次再缩放,允许小数字号。
void glyph(QPainter& p, const QString& text, qreal x, qreal y, qreal size, const QStringList& families,
           const QColor& fillC, const QColor& strokeC = QColor(), qreal sw = 0.0)
{
    QFont f;
    f.setFamilies(families);
    f.setPixelSize(100);
    f.setWeight(QFont::Black);
    QPainterPath t;
    t.addText(0, 0, f, text);
    const qreal k = size / 100.0;
    QTransform tr;
    tr.translate(x - t.boundingRect().width() * k / 2.0 - t.boundingRect().left() * k, y);
    tr.scale(k, k);
    const QPainterPath g = tr.map(t);
    p.fillPath(g, fillC);
    if (strokeC.isValid() && sw > 0)
        p.strokePath(g, QPen(strokeC, sw, Qt::SolidLine, Qt::RoundCap, Qt::RoundJoin));
}

const QStringList& numFont()
{
    static const QStringList f{QStringLiteral("Bahnschrift"), QStringLiteral("Arial Black")};
    return f;
}
const QStringList& handFont()
{
    static const QStringList f{QStringLiteral("Comic Sans MS"), QStringLiteral("Segoe UI Black")};
    return f;
}

const QPainterPath& shieldGlyph()
{
    static const QPainterPath s = svg::path("M12 21.5s8-3.8 8-10V5l-8-3-8 3v6.5c0 6.2 8 10 8 10z");
    return s;
}

void star5(QPainter& p, qreal x, qreal y, qreal r, const QColor& f, const QColor& s, qreal sw = 2.0)
{
    QPolygonF pts;
    for (int i = 0; i < 10; ++i) {
        const qreal a = M_PI / 5.0 * i - M_PI / 2.0;
        const qreal rr = (i % 2) ? r * 0.45 : r;
        pts << QPointF(x + rr * std::cos(a), y + rr * std::sin(a));
    }
    fillStroke(p, polyP(pts), f, s, sw);
}

void bolt(QPainter& p, qreal x, qreal y, qreal s, const QColor& f, const QColor& st, qreal sw = 2.0)
{
    const QPointF raw[] = {{2, -12}, {-7, 2}, {-1, 2}, {-3, 12}, {7, -3}, {1, -3}};
    QPolygonF pts;
    for (const QPointF& q : raw)
        pts << QPointF(x + q.x() * s, y + q.y() * s);
    fillStroke(p, polyP(pts), f, st, sw);
}

QPainterPath star4P(qreal x, qreal y, qreal r)
{
    const qreal k = 0.26;
    QPainterPath s;
    s.moveTo(x, y - r);
    s.quadTo(x + r * k, y - r * k, x + r, y);
    s.quadTo(x + r * k, y + r * k, x, y + r);
    s.quadTo(x - r * k, y + r * k, x - r, y);
    s.quadTo(x - r * k, y - r * k, x, y - r);
    s.closeSubpath();
    return s;
}

QPainterPath heartP(qreal x, qreal y, qreal s)
{
    QPainterPath h;
    h.moveTo(x, y + 6 * s);
    h.cubicTo(x - 7 * s, y + 1.5 * s, x - 8.5 * s, y - 3.5 * s, x - 5.5 * s, y - 5.8 * s);
    h.cubicTo(x - 3.2 * s, y - 7.4 * s, x - 1 * s, y - 6.4 * s, x, y - 4.2 * s);
    h.cubicTo(x + 1 * s, y - 6.4 * s, x + 3.2 * s, y - 7.4 * s, x + 5.5 * s, y - 5.8 * s);
    h.cubicTo(x + 8.5 * s, y - 3.5 * s, x + 7 * s, y + 1.5 * s, x, y + 6 * s);
    h.closeSubpath();
    return h;
}

// 挥手臂每个循环来回摆两次。
qreal swing(const Look& lk)
{
    return lk.phase < 0 ? 0.0 : 16.0 * std::sin(lk.phase * 4.0 * M_PI);
}

// 喷焰长度的抖动系数,两只脚错开相位。
qreal flicker(const Look& lk, int side)
{
    if (lk.phase < 0)
        return 1.0;
    const qreal a = lk.phase * 2.0 * M_PI;
    return 1.0 + 0.16 * std::sin(a * 9.0 + side * 1.9) + 0.08 * std::sin(a * 23.0 + side * 0.7);
}

// 机甲 v4
namespace mk {
const QColor ink = hexc("#181714");
const QColor armor = hexc("#EFEDE8");
const QColor armor2 = hexc("#D4D1CA");
const QColor cobalt = hexc("#33322F");
const QColor cobaltL = hexc("#FF8A3D");
const QColor navy2 = hexc("#252421");
const QColor visor = hexc("#161512");
const QColor orange = hexc("#FF6A13");
const QColor yellow = hexc("#FFCF33");
const QColor steel = hexc("#83827F");
const QColor zee = hexc("#A9A69F");
}

QColor ledMecha(Mood m)
{
    switch (m) {
    case Mood::Ask:   return hexc("#FFD84A");
    case Mood::Alert: return hexc("#FF4A4A");
    case Mood::Think:
    case Mood::Info:  return hexc("#F3EEE4");
    case Mood::Sleep: return hexc("#807F7C");
    case Mood::Guard:
    case Mood::Happy:
    case Mood::Boost: break;
    }
    return hexc("#FFA23A");
}

qreal strokeMecha(qreal size) { return size >= 96 ? 4.0 : size >= 64 ? 5.0 : size >= 40 ? 6.5 : 8.5; }

void mechaEyes(QPainter& p, Ex ex, const QColor& c)
{
    const qreal L = 76, R = 124, Y = 100;
    const auto glow = [&] { fill(p, rectP(48, 84, 104, 32, 6), c, 0.12); };
    const auto bar = [&](qreal x, qreal rot, qreal w = 24, qreal h = 9) {
        p.save();
        rotateAbout(p, rot, x, Y);
        p.fillPath(rectP(x - w / 2, Y - h / 2, w, h, 2.5), c);
        fill(p, rectP(x - w / 2 + 3, Y - h / 2 + 2, w * 0.35, 2.2, 1.1), kWhite, 0.85);
        p.restore();
    };
    switch (ex) {
    case Ex::Happy: {
        glow();
        QPainterPath e;
        e.moveTo(L - 11, Y + 5); e.lineTo(L, Y - 5); e.lineTo(L + 11, Y + 5);
        e.moveTo(R - 11, Y + 5); e.lineTo(R, Y - 5); e.lineTo(R + 11, Y + 5);
        stroke(p, e, c, 5.5);
        break;
    }
    case Ex::Ask:
        glow();
        bar(L, 0);
        glyph(p, QStringLiteral("?"), R, Y + 8, 24, numFont(), c);
        break;
    case Ex::Alert:
        glow();
        bar(L, 16, 26, 9);
        bar(R, -16, 26, 9);
        break;
    case Ex::Think:
        glow();
        p.fillPath(rectP(L - 12, Y - 2, 24, 4, 2), c);
        p.fillPath(rectP(R - 12, Y - 2, 24, 4, 2), c);
        p.fillPath(circP(R + 6, Y, 4.5), kWhite);
        p.fillPath(circP(R + 6, Y, 3), c);
        break;
    case Ex::Boost: {
        glow();
        QPainterPath e;
        e.moveTo(L - 9, Y - 7); e.lineTo(L + 8, Y); e.lineTo(L - 9, Y + 7);
        e.moveTo(R + 9, Y - 7); e.lineTo(R - 8, Y); e.lineTo(R + 9, Y + 7);
        stroke(p, e, c, 5.5);
        break;
    }
    case Ex::Info:
        glow();
        for (const qreal x : {L, R}) {
            stroke(p, circP(x, Y, 9), c, 3);
            p.fillPath(circP(x, Y, 3.4), c);
            QPainterPath t;
            t.moveTo(x - 13, Y); t.lineTo(x - 9, Y);
            t.moveTo(x + 9, Y); t.lineTo(x + 13, Y);
            t.moveTo(x, Y - 13); t.lineTo(x, Y - 9);
            stroke(p, t, c, 2.4);
        }
        break;
    case Ex::Sleep:
        p.fillPath(rectP(L - 12, Y, 24, 3.5, 1.75), c);
        p.fillPath(rectP(R - 12, Y, 24, 3.5, 1.75), c);
        break;
    case Ex::Blink:
        glow();
        p.fillPath(rectP(L - 12, Y - 1.5, 24, 3.5, 1.75), c);
        p.fillPath(rectP(R - 12, Y - 1.5, 24, 3.5, 1.75), c);
        break;
    case Ex::LookL:
        glow();
        bar(L - 7, 6);
        bar(R - 7, -6);
        break;
    case Ex::Guard:
        glow();
        bar(L, 7);
        bar(R, -7);
        break;
    }
}

void mechaExtras(QPainter& p, Mood m, const QColor& led)
{
    // 机甲的 AI / 扫描态是暖白光,画在浅色面板上会看不见,漫画符号改用钢灰。
    const QColor mark = led.lightness() > 200 ? mk::steel : led;
    switch (m) {
    case Mood::Happy:
        star5(p, 28, 58, 10, mk::yellow, mk::ink);
        star5(p, 178, 62, 7, kWhite, mk::ink);
        break;
    case Mood::Ask:
        fillStroke(p, hexP(30, 46, 13), mk::yellow, mk::ink, 2.6);
        glyph(p, QStringLiteral("?"), 30, 52.5, 17, numFont(), mk::ink);
        break;
    case Mood::Alert:
        fillStroke(p, polyP({{176, 37}, {190, 62}, {162, 62}}), mk::yellow, mk::ink, 2.8);
        stroke(p, lineP(176, 46, 176, 54), mk::ink, 3);
        p.fillPath(circP(176, 58, 1.8), mk::ink);
        break;
    case Mood::Think:
        stroke(p, circP(176, 56, 13), mark, 2.4, 1.0, Qt::FlatCap, Qt::MiterJoin, 4.0);
        stroke(p, circP(176, 56, 6), mark, 2.4);
        break;
    case Mood::Boost: {
        bolt(p, 28, 60, 1.1, mk::yellow, mk::ink);
        bolt(p, 178, 54, 0.9, mk::orange, mk::ink);
        QPainterPath s;
        s.moveTo(4, 92); s.lineTo(18, 92);
        s.moveTo(0, 104); s.lineTo(16, 104);
        s.moveTo(4, 116); s.lineTo(18, 116);
        stroke(p, s, mk::ink, 3, 0.45);
        break;
    }
    case Mood::Info: {
        QPainterPath b;
        b.moveTo(164, 40); b.lineTo(178, 40); b.lineTo(178, 54);
        b.moveTo(36, 40); b.lineTo(22, 40); b.lineTo(22, 54);
        stroke(p, b, mark, 3, 1.0, Qt::SquareCap, Qt::MiterJoin);
        break;
    }
    case Mood::Sleep:
        glyph(p, QStringLiteral("z"), 160, 58, 16, numFont(), mk::zee, mk::ink, 0.8);
        glyph(p, QStringLiteral("Z"), 175, 42, 22, numFont(), mk::zee, mk::ink, 0.9);
        break;
    case Mood::Guard:
        break;
    }
}

void mechaHead(QPainter& p, const Look& lk, qreal sw, bool simple)
{
    const QColor led = ledMecha(lk.mood);
    const qreal tilt = std::isnan(lk.tilt) ? (lk.mood == Mood::Ask ? -6.0 : 0.0) : lk.tilt;
    p.save();
    rotateAbout(p, tilt, 100, 108);

    const qreal crenels[3][4] = {{54, 34, 26, 30}, {87, 26, 26, 38}, {120, 34, 26, 30}};
    for (const auto& c : crenels) {
        const qreal x = c[0], y = c[1], w = c[2], h = c[3];
        QPainterPath cr;
        cr.moveTo(x, y + h); cr.lineTo(x, y + 5); cr.lineTo(x + 5, y);
        cr.lineTo(x + w - 5, y); cr.lineTo(x + w, y + 5); cr.lineTo(x + w, y + h);
        cr.closeSubpath();
        fillStroke(p, cr, mk::cobalt, mk::ink, sw);
        if (!simple)
            fill(p, rectP(x + 5, y + 5, w - 10, 4), kWhite, 0.55);
    }
    for (const qreal x : {22.0, 178.0}) {
        fillStroke(p, hexP(x, 106, 16), mk::cobalt, mk::ink, sw);
        if (!simple)
            p.fillPath(hexP(x, 106, 7), mk::cobaltL);
    }
    if (!simple) {
        stroke(p, lineP(184, 94, 190, 66), mk::ink, sw * 0.75);
        if (lk.pulse > 0.01)
            fill(p, circP(190.5, 63, 7 + 3 * lk.pulse), mk::orange, 0.3 * lk.pulse);
        fillStroke(p, circP(190.5, 63, 5), mk::orange, mk::ink, 2.5);
    }

    static const QPainterPath helm = svg::path("M44 52H156L170 66V124L154 154H46L30 124V66Z");
    p.fillPath(helm, mk::armor);
    p.save();
    p.setClipPath(helm, Qt::IntersectClip);
    p.fillPath(rectP(20, 134, 160, 30), mk::armor2);
    fill(p, polyP({{150, 52}, {172, 52}, {172, 160}, {132, 160}}), mk::armor2, 0.55);
    p.restore();
    stroke(p, helm, mk::ink, sw);
    if (!simple)
        stroke(p, lineP(40, 70, 52, 60), kWhite, 5);

    static const QPainterPath visorP = svg::path("M44 80H156L152 118H48Z");
    fillStroke(p, visorP, mk::visor, mk::ink, sw);
    if (!simple)
        stroke(p, lineP(56, 86, 70, 86), kWhite, 3, 0.3);
    mechaEyes(p, exprOf(lk), led);

    static const QPainterPath mouth = svg::path("M62 122H138L130 148H70Z");
    fillStroke(p, mouth, mk::armor2, mk::ink, sw * 0.8);
    if (!simple)
        for (const qreal x : {84.0, 94.0, 104.0, 114.0})
            fill(p, rectP(x - 2, 128, 4.5, 14, 2.2), mk::ink, 0.75);
    p.fillPath(polyP({{34, 128}, {48, 128}, {45, 135}, {31, 135}}), mk::orange);
    p.fillPath(polyP({{152, 128}, {166, 128}, {169, 135}, {155, 135}}), mk::orange);

    static const QPainterPath finL = svg::path("M98 66L72 30L80 27L104 58Z");
    static const QPainterPath finR = svg::path("M102 66L128 30L120 27L96 58Z");
    fillStroke(p, finL, mk::orange, mk::ink, sw * 0.75);
    fillStroke(p, finR, mk::orange, mk::ink, sw * 0.75);
    if (lk.pulse > 0.01)
        fill(p, hexP(100, 66, 13 + 4 * lk.pulse), led, 0.16 + 0.34 * lk.pulse);
    fillStroke(p, hexP(100, 66, 9), led, mk::ink, sw * 0.7);
    if (!simple)
        fill(p, circP(97, 63, 2.4), kWhite, 0.9);
    p.restore();

    if (!simple && lk.extras)
        mechaExtras(p, lk.mood, led);
}

void mechaBody(QPainter& p, const Look& lk, qreal sw)
{
    const QColor led = ledMecha(lk.mood);
    const bool sit = lk.pose == Pose::Sit;
    const bool flame = lk.flame || lk.mood == Mood::Boost;
    if (!sit && lk.shadow)
        fill(p, ellP(100, 240, 46, 5), mk::ink, 0.3);
    if (!sit && flame) {
        int side = 0;
        for (const qreal x : {84.0, 116.0}) {
            const qreal fl = flicker(lk, side++);
            QPainterPath f;
            f.moveTo(x - 9, 234); f.quadTo(x, 234 + 28 * fl, x + 9, 234); f.closeSubpath();
            fillStroke(p, f, mk::orange, mk::ink, 2.4);
            QPainterPath g;
            g.moveTo(x - 4.5, 234); g.quadTo(x, 234 + 16 * fl, x + 4.5, 234); g.closeSubpath();
            p.fillPath(g, mk::yellow);
        }
    }
    const auto boot = [&](qreal x, qreal rot) {
        p.save();
        rotateAbout(p, rot, x, 226);
        fillStroke(p, rectP(x - 7, 208, 14, 14), mk::navy2, mk::ink, sw * 0.8, Qt::MiterJoin);
        QPainterPath b;
        b.moveTo(x - 15, 220); b.lineTo(x + 15, 220); b.lineTo(x + 17, 236); b.lineTo(x - 17, 236);
        b.closeSubpath();
        fillStroke(p, b, mk::cobalt, mk::ink, sw);
        p.fillPath(rectP(x - 13, 229, 11, 4), mk::orange);
        p.restore();
    };
    if (sit) {
        boot(82, -16);
        boot(120, 18);
    } else {
        boot(84, 0);
        boot(116, 0);
    }
    const auto arm = [&](qreal x, qreal y, qreal rot) {
        p.save();
        p.translate(x, y);
        p.rotate(rot);
        fillStroke(p, rectP(-8, -4, 16, 26, 5), mk::navy2, mk::ink, sw * 0.85);
        fillStroke(p, rectP(-12, 18, 24, 19, 6), mk::armor, mk::ink, sw);
        QPainterPath g;
        for (const qreal gx : {-6.0, 0.0, 6.0}) {
            g.moveTo(gx, 24);
            g.lineTo(gx, 31);
        }
        stroke(p, g, mk::ink, 1.8, 0.55);
        p.restore();
    };
    struct A { qreal x, y, r; };
    A a0{64, 174, 26}, a1{136, 174, -26};
    switch (lk.pose) {
    case Pose::Wave:   a1 = {140, 170, -128 + swing(lk)}; break;
    case Pose::Shield: a0 = {66, 174, -34}; a1 = {134, 174, 34}; break;
    case Pose::Sit:    a0 = {64, 180, 58}; a1 = {136, 180, -58}; break;
    case Pose::Reach:  a0 = {62, 174, 96}; break;
    case Pose::Hold:   a1 = {140, 170, -134}; break;
    case Pose::Stand:  break;
    }
    if (lk.pose != Pose::Shield) {
        arm(a0.x, a0.y, a0.r);
        arm(a1.x, a1.y, a1.r);
    }
    static const QPainterPath torso = svg::path("M70 160H130L140 172L132 216H68L60 172Z");
    fillStroke(p, torso, mk::armor, mk::ink, sw);
    fillStroke(p, rectP(66, 203, 68, 10), mk::navy2, mk::ink, sw * 0.7, Qt::MiterJoin);
    fillStroke(p, rectP(93, 201, 14, 14, 2), mk::orange, mk::ink, sw * 0.6);
    fill(p, hexP(100, 184, 14 + 3 * lk.pulse), led, 0.3 + 0.3 * lk.pulse);
    fillStroke(p, hexP(100, 184, 11), led, mk::ink, sw * 0.7);
    p.save();
    p.translate(100, 184);
    p.scale(0.55, 0.55);
    p.translate(-12, -12);
    p.fillPath(shieldGlyph(), kWhite);
    p.restore();
    for (const QPointF& c : {QPointF(58, 168), QPointF(142, 168)}) {
        const qreal x = c.x(), y = c.y();
        QPainterPath pad;
        pad.moveTo(x - 16, y + 8); pad.lineTo(x - 16, y - 4); pad.lineTo(x - 8, y - 12);
        pad.lineTo(x + 8, y - 12); pad.lineTo(x + 16, y - 4); pad.lineTo(x + 16, y + 8);
        pad.closeSubpath();
        fillStroke(p, pad, mk::cobalt, mk::ink, sw);
        fill(p, rectP(x - 10, y - 6, 20, 4), kWhite, 0.6);
    }
    if (lk.pose == Pose::Shield) {
        fillStroke(p, hexP(100, 192, 34), mk::cobalt, mk::ink, sw);
        stroke(p, hexP(100, 192, 25), mk::cobaltL, 3);
        p.save();
        p.translate(100, 192);
        p.scale(1.25, 1.25);
        p.translate(-12, -12);
        fillStroke(p, shieldGlyph(), mk::orange, mk::ink, 2);
        static const QPainterPath check = svg::path("m8.5 11.5 2.5 2.5 4.5-5");
        stroke(p, check, mk::ink, 2.4);
        p.restore();
        arm(a0.x, a0.y, a0.r);
        arm(a1.x, a1.y, a1.r);
    }
    if (lk.pose == Pose::Wave) {
        static const QPainterPath w = svg::path("M180 120l10-6M184 132l12-2M178 108l6-9");
        stroke(p, w, mk::ink, 3, 0.5);
    }
}

// 卡哇伊 v3
namespace kw {
const QColor ink = hexc("#5B4036");
const QColor milk = hexc("#FFFDF9");
const QColor shade = hexc("#F6E8E4");
const QColor pink = hexc("#FFB8CB");
const QColor pinkL = hexc("#FFDCE6");
const QColor blush = hexc("#FF96B2");
const QColor plum = hexc("#4E4166");
const QColor mint = hexc("#6FDDBE");
const QColor butter = hexc("#FFD96B");
const QColor drop = hexc("#B9E2FF");
const QColor zee = hexc("#B9A6D6");
}

QColor ledKawaii(Mood m)
{
    switch (m) {
    case Mood::Happy: return hexc("#A8F5C2");
    case Mood::Ask:   return hexc("#FFE27A");
    case Mood::Alert: return hexc("#FF9C9C");
    case Mood::Think: return hexc("#D2C2FF");
    case Mood::Boost: return hexc("#9CF0FA");
    case Mood::Info:  return hexc("#B3DCFF");
    case Mood::Sleep: return hexc("#CFC6DA");
    case Mood::Guard: break;
    }
    return hexc("#8FF5D6");
}

QColor flagKawaii(Mood m)
{
    switch (m) {
    case Mood::Happy: return hexc("#8FE3A8");
    case Mood::Ask:   return hexc("#FFD15C");
    case Mood::Alert: return hexc("#FF7F7F");
    case Mood::Think: return hexc("#B9A6FF");
    case Mood::Boost: return hexc("#7FE0EE");
    case Mood::Info:  return hexc("#8FCBFF");
    case Mood::Sleep: return hexc("#D5CAD8");
    case Mood::Guard: break;
    }
    return hexc("#6FDDBE");
}

qreal strokeKawaii(qreal size) { return size >= 96 ? 4.5 : size >= 64 ? 5.5 : size >= 40 ? 7.0 : 9.0; }

void kawaiiFace(QPainter& p, Ex ex, const QColor& c)
{
    const qreal L = 78, R = 122, Y = 112;
    const auto hl = [&](qreal x, qreal y, qreal k) {
        p.fillPath(circP(x - 3.6 * k, y - 4.4 * k, 3.7 * k), kWhite);
        fill(p, circP(x + 3.4 * k, y + 4.2 * k, 1.8 * k), kWhite, 0.9);
    };
    const auto eye = [&](qreal x, qreal y, qreal rx, qreal ry, qreal k = 1.0) {
        p.fillPath(ellP(x, y, rx, ry), c);
        hl(x, y, k);
    };
    const auto omega = [&](qreal x, qreal y, qreal w = 3.0) {
        QPainterPath o;
        o.moveTo(x - 8, y - 1);
        o.quadTo(x - 4, y + 4, x, y - 1);
        o.quadTo(x + 4, y + 4, x + 8, y - 1);
        stroke(p, o, c, w);
    };
    const auto openMouth = [&](qreal x, qreal y) {
        QPainterPath m;
        m.moveTo(x - 8, y);
        m.lineTo(x + 8, y);
        m.quadTo(x + 7, y + 9, x, y + 9);
        m.quadTo(x - 7, y + 9, x - 8, y);
        m.closeSubpath();
        p.fillPath(m, c);
        QPainterPath t;
        t.moveTo(x - 3.5, y + 5.5);
        t.quadTo(x, y + 8, x + 3.5, y + 5.5);
        stroke(p, t, kw::blush, 2.4);
    };
    const auto arcs = [&](qreal dy, qreal w) {
        QPainterPath a;
        for (const qreal x : {L, R}) {
            a.moveTo(x - 10, Y);
            a.quadTo(x, Y + dy, x + 10, Y);
        }
        stroke(p, a, c, w);
    };
    const auto ring = [&] { stroke(p, circP(100, Y + 21, 3.4), c, 2.6); };
    switch (ex) {
    case Ex::Happy: {
        QPainterPath a;
        for (const qreal x : {L, R}) {
            a.moveTo(x - 10, Y + 4);
            a.quadTo(x, Y - 10, x + 10, Y + 4);
        }
        stroke(p, a, c, 5.2);
        openMouth(100, Y + 14);
        break;
    }
    case Ex::Blink:
        arcs(8, 4.6);
        omega(100, Y + 21);
        break;
    case Ex::Ask:
        eye(L, Y, 9.5, 11.5);
        eye(R, Y + 1.5, 8, 9.5, 0.85);
        ring();
        break;
    case Ex::Alert: {
        eye(L, Y + 2, 10, 10.5);
        eye(R, Y + 2, 10, 10.5);
        QPainterPath b;
        b.moveTo(L - 12, Y - 15); b.lineTo(L + 9, Y - 9);
        b.moveTo(R + 12, Y - 15); b.lineTo(R - 9, Y - 9);
        stroke(p, b, c, 4.6);
        QPainterPath m;
        m.moveTo(92, Y + 23);
        m.quadTo(96, Y + 18, 100, Y + 23);
        m.quadTo(104, Y + 18, 108, Y + 23);
        stroke(p, m, c, 3);
        break;
    }
    case Ex::Think:
        eye(L + 5, Y - 4, 9.5, 11.5);
        eye(R + 5, Y - 4, 9.5, 11.5);
        stroke(p, lineP(97, Y + 20, 106, Y + 20), c, 3);
        break;
    case Ex::Boost: {
        QPainterPath e;
        e.moveTo(L - 8, Y - 9); e.lineTo(L + 8, Y); e.lineTo(L - 8, Y + 9);
        e.moveTo(R + 8, Y - 9); e.lineTo(R - 8, Y); e.lineTo(R + 8, Y + 9);
        stroke(p, e, c, 5.2);
        openMouth(100, Y + 14);
        break;
    }
    case Ex::Info:
        for (const qreal x : {L, R}) {
            p.fillPath(ellP(x, Y, 11, 12.5), c);
            p.fillPath(star4P(x - 3.2, Y - 4, 5.2), kWhite);
            p.fillPath(circP(x + 4, Y + 5, 1.8), kWhite);
        }
        ring();
        break;
    case Ex::Sleep:
        arcs(7, 4);
        omega(100, Y + 20, 2.6);
        break;
    case Ex::LookL:
        eye(L - 6, Y, 10.5, 12.5);
        eye(R - 6, Y, 10.5, 12.5);
        omega(95, Y + 21);
        break;
    case Ex::Guard:
        eye(L, Y, 10.5, 12.5);
        eye(R, Y, 10.5, 12.5);
        omega(100, Y + 21);
        break;
    }
}

void kawaiiExtras(QPainter& p, Mood m)
{
    switch (m) {
    case Mood::Happy:
        fillStroke(p, star4P(28, 60, 9), kw::butter, kw::ink, 2);
        fillStroke(p, star4P(176, 50, 7), kw::pink, kw::ink, 2);
        p.fillPath(star4P(186, 74, 4.5), kw::butter);
        break;
    case Mood::Ask: {
        static const QPainterPath d = svg::path("M175 64c-4.5 6.5-7.5 10.5-7.5 14.5a7.5 7.5 0 0 0 15 0c0-4-3-8-7.5-14.5z");
        fillStroke(p, d, kw::drop, kw::ink, 2.6);
        p.fillPath(circP(173, 80, 2), kWhite);
        fillStroke(p, circP(32, 44, 12), kWhite, kw::ink, 2.6);
        glyph(p, QStringLiteral("?"), 32, 50, 16, {QStringLiteral("Segoe UI Black"), QStringLiteral("Arial Black")},
              kw::butter, kw::ink, 1.2);
        break;
    }
    case Mood::Alert: {
        p.save();
        p.translate(168, 60);
        static const QPainterPath a = svg::path("M-10 -3Q-4 -3 -3 -10M3 -10Q4 -3 10 -3M10 3Q4 3 3 10M-3 10Q-4 3 -10 3");
        stroke(p, a, hexc("#FF6F7F"), 3.6);
        p.restore();
        break;
    }
    case Mood::Think:
        fillStroke(p, circP(160, 64, 4), kWhite, kw::ink, 2.2);
        fillStroke(p, circP(171, 51, 6), kWhite, kw::ink, 2.2);
        fillStroke(p, circP(184, 35, 8.5), kWhite, kw::ink, 2.2);
        break;
    case Mood::Boost: {
        QPainterPath s;
        s.moveTo(6, 96); s.lineTo(18, 96);
        s.moveTo(2, 108); s.lineTo(16, 108);
        s.moveTo(6, 120); s.lineTo(18, 120);
        stroke(p, s, kw::ink, 3, 0.55);
        static const QPainterPath d = svg::path("M182 70c-3 4-5 7-5 9.5a5 5 0 0 0 10 0c0-2.5-2-5.5-5-9.5z");
        fillStroke(p, d, kw::drop, kw::ink, 2.2);
        break;
    }
    case Mood::Info:
        fillStroke(p, star4P(30, 56, 8), kw::butter, kw::ink, 2);
        fillStroke(p, star4P(178, 58, 6), hexc("#B3DCFF"), kw::ink, 2);
        break;
    case Mood::Sleep:
        glyph(p, QStringLiteral("z"), 160, 64, 17, handFont(), kw::zee, kw::ink, 0.8);
        glyph(p, QStringLiteral("Z"), 176, 46, 23, handFont(), kw::zee, kw::ink, 0.9);
        break;
    case Mood::Guard:
        break;
    }
}

void kawaiiHead(QPainter& p, const Look& lk, qreal sw, bool simple)
{
    const QColor led = ledKawaii(lk.mood);
    const QColor flag = flagKawaii(lk.mood);
    const qreal tilt = std::isnan(lk.tilt) ? (lk.mood == Mood::Ask ? -7.0 : 0.0) : lk.tilt;
    p.save();
    rotateAbout(p, tilt, 100, 112);

    stroke(p, lineP(100, 33, 100, 7), kw::ink, qMax<qreal>(3.0, sw * 0.75));
    if (lk.pulse > 0.01)
        fill(p, circP(100, 6, 6.5 + 3 * lk.pulse), led, 0.35 * lk.pulse);
    p.fillPath(circP(100, 6, qMax<qreal>(3.6, sw * 0.8)), kw::ink);
    if (lk.mood == Mood::Sleep) {
        static const QPainterPath f = svg::path("M101.5 12Q106 20 104 30L101.5 30Z");
        fillStroke(p, f, flag, kw::ink, sw * 0.65);
    } else {
        // 小旗随风摆:绕旗杆上的挂点转,尾端再多甩一点。
        p.save();
        if (lk.phase >= 0) {
            const qreal a = lk.phase * 2.0 * M_PI;
            rotateAbout(p, 7.0 * std::sin(a * 2.0), 101, 16);
            p.translate(102, 16);
            p.shear(0.0, 0.12 * std::sin(a * 2.0 - 1.1));
            p.translate(-102, -16);
        }
        static const QPainterPath f = svg::path("M102 8.5Q118 11 131 16Q118 21 102 23.5Z");
        fillStroke(p, f, flag, kw::ink, sw * 0.65);
        if (!simple)
            p.fillPath(heartP(113, 16, 0.62), kWhite);
        p.restore();
    }
    const qreal crenels[3][4] = {{44, 38, 32, 34}, {84, 30, 32, 42}, {124, 38, 32, 34}};
    for (const auto& c : crenels) {
        fillStroke(p, rectP(c[0], c[1], c[2], c[3], 15), kw::pink, kw::ink, sw);
        if (!simple)
            fill(p, ellP(c[0] + 10, c[1] + 9, 4.6, 3), kWhite, 0.85);
    }
    for (const qreal x : {24.0, 176.0}) {
        fillStroke(p, circP(x, 116, 15.5), kw::pink, kw::ink, sw);
        if (!simple)
            p.fillPath(circP(x, 116, 7), kw::pinkL);
    }
    const QPainterPath head = rectP(26, 54, 148, 116, 54);
    p.fillPath(head, kw::milk);
    p.save();
    p.setClipPath(head, Qt::IntersectClip);
    p.fillPath(ellP(112, 182, 96, 32), kw::shade);
    p.restore();
    stroke(p, head, kw::ink, sw);
    if (!simple) {
        QPainterPath s;
        s.moveTo(44, 96);
        s.quadTo(48, 74, 70, 66);
        stroke(p, s, kWhite, 6.5);
    }
    fillStroke(p, rectP(46, 78, 108, 68, 32), kw::plum, kw::ink, sw);
    if (!simple) {
        QPainterPath s;
        s.moveTo(59, 95);
        s.quadTo(61, 87, 70, 86);
        stroke(p, s, kWhite, 3.2, 0.38);
    }
    kawaiiFace(p, exprOf(lk), led);
    fill(p, ellP(50, 155, 11, 6), kw::blush, 0.75);
    fill(p, ellP(150, 155, 11, 6), kw::blush, 0.75);
    if (!simple) {
        QPainterPath s;
        for (const qreal x : {45.0, 50.5, 56.0, 145.0, 150.5, 156.0}) {
            s.moveTo(x, 152.5);
            s.lineTo(x - 2.2, 156.9);
        }
        stroke(p, s, kWhite, 1.7, 0.85);
    }
    p.restore();

    if (!simple && lk.extras)
        kawaiiExtras(p, lk.mood);
}

void kawaiiShieldBadge(QPainter& p, qreal cx, qreal cy, qreal k, qreal sw)
{
    p.save();
    p.translate(cx - 12 * k, cy - 12 * k);
    p.scale(k, k);
    fillStroke(p, shieldGlyph(), kw::mint, kw::ink, (sw * 0.7) / k);
    p.fillPath(heartP(12, 11, 0.62), kWhite);
    QPainterPath g;
    g.moveTo(6.5, 6.5);
    g.quadTo(8, 5, 10, 4.6);
    stroke(p, g, kWhite, 1.6 / k * 1.2, 0.8);
    p.restore();
}

void kawaiiBody(QPainter& p, const Look& lk, qreal sw)
{
    const bool sit = lk.pose == Pose::Sit;
    if (!sit && lk.shadow)
        fill(p, ellP(100, 236, 46, 5.5), kw::ink, 0.13);
    if (sit) {
        p.save();
        rotateAbout(p, -16, 81, 231);
        fillStroke(p, ellP(81, 231, 15, 10), kw::pink, kw::ink, sw);
        p.restore();
        p.save();
        rotateAbout(p, 20, 121, 228);
        fillStroke(p, ellP(121, 228, 15, 10), kw::pink, kw::ink, sw);
        p.restore();
    } else {
        fillStroke(p, ellP(83, 225, 15.5, 10), kw::pink, kw::ink, sw);
        fillStroke(p, ellP(117, 225, 15.5, 10), kw::pink, kw::ink, sw);
        fill(p, ellP(79, 221, 4, 2.4), kWhite, 0.8);
        fill(p, ellP(113, 221, 4, 2.4), kWhite, 0.8);
    }
    const auto arm = [&](qreal x, qreal y, qreal rot) {
        p.save();
        p.translate(x, y);
        p.rotate(rot);
        fillStroke(p, rectP(-9.5, -6, 19, 35, 9.5), kw::milk, kw::ink, sw);
        p.fillPath(ellP(-2.5, 3, 3, 6.5), kWhite);
        p.fillPath(ellP(0, 23, 6, 3.4), kw::pinkL);
        p.restore();
    };
    struct A { qreal x, y, r; };
    A a0{67, 180, 42}, a1{133, 180, -42};
    switch (lk.pose) {
    case Pose::Wave:   a1 = {140, 176, -118 + swing(lk)}; break;
    case Pose::Shield: a0 = {72, 178, -28}; a1 = {128, 178, 28}; break;
    case Pose::Sit:    a0 = {67, 188, 64}; a1 = {133, 188, -64}; break;
    case Pose::Reach:  a0 = {66, 180, 100}; break;
    case Pose::Hold:   a1 = {140, 176, -128}; break;
    case Pose::Stand:  break;
    }
    if (lk.pose != Pose::Shield) {
        arm(a0.x, a0.y, a0.r);
        arm(a1.x, a1.y, a1.r);
    }
    if (lk.pose == Pose::Wave) {
        static const QPainterPath w = svg::path("M176 146q6 6 3 13M184 138q10 10 5 22");
        stroke(p, w, kw::ink, 3);
    }
    const QPainterPath torso = rectP(64, 164, 72, 56, 27);
    p.fillPath(torso, kw::milk);
    p.save();
    p.setClipPath(torso, Qt::IntersectClip);
    p.fillPath(ellP(108, 226, 50, 16), kw::shade);
    p.restore();
    stroke(p, torso, kw::ink, sw);
    if (lk.pose == Pose::Shield) {
        p.save();
        p.translate(100, 196);
        p.scale(2.1, 2.1);
        p.translate(-12, -12);
        fillStroke(p, shieldGlyph(), kw::mint, kw::ink, sw / 2.1);
        p.fillPath(heartP(12, 11, 0.7), kWhite);
        QPainterPath g;
        g.moveTo(6.5, 6.5);
        g.quadTo(8, 5, 10, 4.6);
        stroke(p, g, kWhite, 1.3);
        p.restore();
        arm(a0.x, a0.y, a0.r);
        arm(a1.x, a1.y, a1.r);
    } else {
        if (lk.pulse > 0.01)
            fill(p, circP(100, 193, 15 + 5 * lk.pulse), ledKawaii(lk.mood), 0.16 + 0.3 * lk.pulse);
        kawaiiShieldBadge(p, 100, 193, 1.15, sw);
    }
}

// 金刚:卡车机器人
// 零件都画在 240×300 的「机器人形态」坐标里(和设计稿同一套坐标)。载具形态不另画一套:每个零件有自己的
// 「载具位姿」—— 以零件包围盒中心为原点的缩放 + 平移,Look.vehicle 在两套位姿之间插值,变形时能看到
// 零件各自滑到位。只变换轮廓、不缩放笔宽,描边粗细在变形中保持不变。
namespace tt {
const QColor ink = hexc("#05070C");
const QColor red = hexc("#D3232B");
const QColor redHi = hexc("#F2565B");
const QColor redDeep = hexc("#96131A");
const QColor blue = hexc("#2459D8");
const QColor blueHi = hexc("#5F8DFA");
const QColor blueDeep = hexc("#143792");
const QColor chrome = hexc("#C6CFDA");
const QColor chromeHi = hexc("#F4F7FA");
const QColor chromeDeep = hexc("#7B8798");
const QColor chromeDark = hexc("#454F5F");
const QColor amber = hexc("#FFC12E");
const QColor glass = hexc("#8DD9FF");
const QColor glassHi = hexc("#DDF4FF");
const QColor tire = hexc("#14181F");
const QColor tread = hexc("#2A303B");
const QColor visor = hexc("#060A11");
}

QColor ledTitan(Mood m)
{
    switch (m) {
    case Mood::Happy: return hexc("#5CF0CF");
    case Mood::Ask:   return hexc("#FFB42E");
    case Mood::Alert: return hexc("#FF3D4C");
    case Mood::Think: return hexc("#8FA6FF");
    case Mood::Boost: return hexc("#FFE14A");
    case Mood::Info:  return hexc("#9FD0FF");
    case Mood::Sleep: return hexc("#56627A");
    case Mood::Guard: break;
    }
    return hexc("#35D4FF");
}

QColor mixc(const QColor& a, const QColor& b, qreal t)
{
    t = qBound<qreal>(0.0, t, 1.0);
    return QColor::fromRgbF(float(a.redF() + (b.redF() - a.redF()) * t), float(a.greenF() + (b.greenF() - a.greenF()) * t),
                            float(a.blueF() + (b.blueF() - a.blueF()) * t));
}

// 零件的载具位姿:以 pivot 为原点缩放 scale,再整体平移 shift。
struct Morph {
    QPointF pivot;
    QPointF shift;
    QPointF scale;
};

QTransform morphAt(const Morph& m, qreal t)
{
    QTransform x;
    x.translate(m.pivot.x() + m.shift.x() * t, m.pivot.y() + m.shift.y() * t);
    x.scale(1.0 + (m.scale.x() - 1.0) * t, 1.0 + (m.scale.y() - 1.0) * t);
    x.translate(-m.pivot.x(), -m.pivot.y());
    return x;
}

// 单个零件的变形进度:按 order(0..1)错开先后,落位时略微过冲,像齿轮咬合。
qreal partProgress(qreal v, qreal order)
{
    static const QEasingCurve curve = [] {
        QEasingCurve c(QEasingCurve::BezierSpline);
        c.addCubicBezierSegment(QPointF(0.6, -0.22), QPointF(0.3, 1.28), QPointF(1.0, 1.0));
        return c;
    }();
    constexpr qreal span = 0.76;
    const qreal x = qBound<qreal>(0.0, (v - order * (1.0 - span)) / span, 1.0);
    return x <= 0.0 ? 0.0 : x >= 1.0 ? 1.0 : curve.valueForProgress(x);
}

// 面窗里的眼灯:形状 = 表情,颜色 = 防护状态。
void titanEyes(QPainter& p, const QTransform& x, Ex ex, const QColor& c, qreal phase)
{
    const auto lit = [&](const QPainterPath& raw) {
        const QPainterPath e = x.map(raw);
        stroke(p, e, c, 2.6, 0.35);
        p.fillPath(e, c);
    };
    const auto quad = [&](std::initializer_list<QPointF> pts) { lit(polyP(pts)); };
    const auto bar = [&](qreal bx, qreal by, qreal w, qreal h) { lit(rectP(bx, by, w, h)); };
    switch (ex) {
    case Ex::Happy: {
        QPainterPath e;
        e.moveTo(102, 55); e.quadTo(108.5, 44, 115, 55);
        e.moveTo(125, 55); e.quadTo(131.5, 44, 138, 55);
        stroke(p, x.map(e), c, 6.0, 0.3);
        stroke(p, x.map(e), c, 3.6);
        break;
    }
    case Ex::Ask:
        quad({{102, 50}, {115, 50}, {114, 56}, {103, 56}});
        quad({{124, 44}, {139, 44}, {137, 57}, {126, 57}});
        break;
    case Ex::Alert:
        quad({{100, 44}, {116, 50}, {115, 57}, {102, 55}});
        quad({{140, 44}, {124, 50}, {125, 57}, {138, 55}});
        break;
    case Ex::Think: {
        fill(p, x.map(rectP(101, 49, 38, 5)), c, 0.28);
        // 研判:一截光带在面窗里来回扫
        const qreal s = phase < 0 ? 0.5 : 0.5 - 0.5 * std::cos(phase * 4.0 * M_PI);
        bar(101 + 28 * s, 49, 10, 5);
        break;
    }
    case Ex::Boost:
        quad({{100, 45}, {117, 46}, {116, 57}, {101, 57}});
        quad({{140, 45}, {123, 46}, {124, 57}, {139, 57}});
        break;
    case Ex::Info:
        bar(103, 47, 11, 9);
        bar(126, 47, 11, 9);
        break;
    case Ex::Sleep:
        bar(102, 52, 13, 2.5);
        bar(125, 52, 13, 2.5);
        break;
    case Ex::Blink:
        bar(102, 51, 13, 3);
        bar(125, 51, 13, 3);
        break;
    case Ex::LookL:
        quad({{98, 46}, {113, 48}, {112, 56}, {100, 56}});
        quad({{136, 46}, {121, 48}, {122, 56}, {134, 56}});
        break;
    case Ex::Guard:
        quad({{101, 46}, {116, 48}, {115, 56}, {103, 56}});
        quad({{139, 46}, {124, 48}, {125, 56}, {137, 56}});
        break;
    }
}

void titanExtras(QPainter& p, Mood m, const QColor& led)
{
    const QColor mark = led.lightness() > 200 ? tt::chromeDeep : led;
    switch (m) {
    case Mood::Happy:
        star5(p, 66, 34, 8, tt::amber, tt::ink);
        star5(p, 176, 28, 5.5, kWhite, tt::ink, 1.6);
        break;
    case Mood::Ask:
        fillStroke(p, hexP(66, 28, 10), tt::amber, tt::ink, 2.2);
        glyph(p, QStringLiteral("?"), 66, 33, 13, numFont(), tt::ink);
        break;
    case Mood::Alert:
        fillStroke(p, polyP({{176, 14}, {187, 34}, {165, 34}}), tt::amber, tt::ink, 2.2);
        stroke(p, lineP(176, 21, 176, 27), tt::ink, 2.4);
        p.fillPath(circP(176, 30.5, 1.5), tt::ink);
        break;
    case Mood::Think:
        stroke(p, circP(176, 28, 10), mark, 2.0, 1.0, Qt::FlatCap, Qt::MiterJoin, 3.0);
        stroke(p, circP(176, 28, 4.5), mark, 2.0);
        break;
    case Mood::Boost:
        bolt(p, 64, 32, 0.8, tt::amber, tt::ink, 1.8);
        bolt(p, 177, 28, 0.65, tt::red, tt::ink, 1.6);
        break;
    case Mood::Info: {
        QPainterPath b;
        b.moveTo(166, 14); b.lineTo(176, 14); b.lineTo(176, 24);
        b.moveTo(74, 14); b.lineTo(64, 14); b.lineTo(64, 24);
        stroke(p, b, mark, 2.4, 1.0, Qt::SquareCap, Qt::MiterJoin);
        break;
    }
    case Mood::Sleep:
        glyph(p, QStringLiteral("z"), 168, 32, 12, numFont(), tt::chromeDeep, tt::ink, 0.6);
        glyph(p, QStringLiteral("Z"), 179, 20, 16, numFont(), tt::chromeDeep, tt::ink, 0.7);
        break;
    case Mood::Guard:
        break;
    }
}

// 头:城垛盔冠(小垒自己的识别特征,磐垒 = 堡垒)+ 钴蓝头盔 + 暗色面窗 + 铬银面甲。
// x = 头的整体变换(歪头、变形时收进驾驶室)。
void titanHead(QPainter& p, const Look& lk, qreal sw, bool simple, const QTransform& x)
{
    const auto fs = [&](const QPainterPath& raw, const QColor& f, qreal w) {
        const QPainterPath s = x.map(raw);
        p.fillPath(s, f);
        p.strokePath(s, QPen(tt::ink, w, Qt::SolidLine, Qt::FlatCap, Qt::MiterJoin));
    };
    const auto flat = [&](const QPainterPath& raw, const QColor& f) { p.fillPath(x.map(raw), f); };
    const qreal k2 = sw * 0.75;
    fs(rectP(110, 78, 20, 12), tt::chromeDark, sw);
    fs(rectP(85, 22, 4, 14), tt::chrome, sw);
    fs(rectP(151, 22, 4, 14), tt::chrome, sw);
    fs(polyP({{83, 36}, {92, 32}, {92, 66}, {83, 62}}), tt::chrome, sw);
    fs(polyP({{157, 36}, {148, 32}, {148, 66}, {157, 62}}), tt::chrome, sw);
    fs(polyP({{92, 40}, {98, 26}, {142, 26}, {148, 40}, {148, 70}, {140, 80}, {100, 80}, {92, 70}}), tt::blue, sw);
    if (!simple) {
        flat(polyP({{99.5, 28.5}, {140.5, 28.5}, {143.5, 34}, {96.5, 34}}), tt::blueHi);
        flat(polyP({{93.5, 63}, {100, 63}, {103, 78.5}, {100.6, 78.5}, {93.5, 69.4}}), tt::blueDeep);
        flat(polyP({{146.5, 63}, {140, 63}, {137, 78.5}, {139.4, 78.5}, {146.5, 69.4}}), tt::blueDeep);
    }
    fs(polyP({{106, 26}, {106, 13}, {113, 13}, {113, 19}, {117, 19}, {117, 13}, {123, 13}, {123, 19},
              {127, 19}, {127, 13}, {134, 13}, {134, 26}}), tt::red, sw);
    fs(polyP({{98, 42}, {142, 42}, {144, 56}, {140, 62}, {100, 62}, {96, 56}}), tt::visor, k2);
    const QColor led = ledTitan(lk.mood);
    if (lk.pulse > 0.01)
        fill(p, x.map(rectP(99, 43, 42, 18)), led, 0.08 + 0.14 * lk.pulse);
    titanEyes(p, x, exprOf(lk), led, lk.phase);
    fs(polyP({{102, 62}, {138, 62}, {136, 77}, {104, 77}}), tt::chrome, k2);
    QPainterPath slats;
    slats.moveTo(120, 62); slats.lineTo(120, 77);
    slats.moveTo(110, 66); slats.lineTo(110, 73);
    slats.moveTo(130, 66); slats.lineTo(130, 73);
    p.strokePath(x.map(slats), QPen(tt::ink, k2, Qt::SolidLine, Qt::FlatCap));
}

// 整只小垒。v = Look.vehicle:0 站着,1 是一辆小卡车。
void titanRobot(QPainter& p, const Look& lk, qreal sw, bool simple)
{
    const qreal v = qBound<qreal>(0.0, lk.vehicle, 1.0);
    const QColor led = ledTitan(lk.mood);
    const qreal k2 = sw * 0.75;
    QTransform x;
    const auto fs = [&](const QPainterPath& raw, const QColor& f, qreal w) {
        const QPainterPath s = x.map(raw);
        p.fillPath(s, f);
        p.strokePath(s, QPen(tt::ink, w, Qt::SolidLine, Qt::FlatCap, Qt::MiterJoin));
    };
    const auto flat = [&](const QPainterPath& raw, const QColor& f) { p.fillPath(x.map(raw), f); };
    const auto faded = [&](qreal opacity, const std::function<void()>& draw) {
        if (opacity <= 0.02)
            return;
        p.save();
        p.setOpacity(p.opacity() * qMin<qreal>(1.0, opacity));
        draw();
        p.restore();
    };

    if (lk.shadow)
        fill(p, ellP(120, 289, 62 * (1.0 + 0.12 * v), 5), tt::ink, 0.4);

    // 腿 → 收进车底
    const qreal tl = partProgress(v, 0.0);
    x = morphAt({{120, 235}, {0, 16}, {0.6, 0.2}}, tl);
    faded(1.0 - tl, [&] {
        fs(rectP(94, 184, 22, 38), tt::chrome, sw);
        fs(rectP(124, 184, 22, 38), tt::chrome, sw);
        flat(rectP(95.5, 212, 19, 8.5), tt::chromeDeep);
        flat(rectP(125.5, 212, 19, 8.5), tt::chromeDeep);
        fs(polyP({{90, 222}, {118, 222}, {120, 272}, {86, 272}}), tt::blue, sw);
        fs(polyP({{122, 222}, {150, 222}, {154, 272}, {120, 272}}), tt::blue, sw);
        if (!simple) {
            flat(polyP({{92, 224}, {97, 224}, {94, 270}, {88.5, 270}}), tt::blueHi);
            flat(polyP({{124, 224}, {129, 224}, {127, 270}, {122, 270}}), tt::blueHi);
        }
        fs(rectP(95, 224, 18, 8), tt::red, k2);
        fs(rectP(127, 224, 18, 8), tt::red, k2);
        fs(polyP({{82, 272}, {120, 272}, {122, 286}, {78, 286}}), tt::blueDeep, sw);
        fs(polyP({{120, 272}, {158, 272}, {162, 286}, {118, 286}}), tt::blueDeep, sw);
    });

    // 小腿外侧的轮胎 → 车轮
    const qreal tw = partProgress(v, 0.2);
    for (const auto& [cx, dx] : {std::pair<qreal, qreal>{82, -20}, std::pair<qreal, qreal>{158, 20}}) {
        x = morphAt({{cx, 247}, {dx, 25}, {1.5, 1.5}}, tw);
        fs(rectP(cx - 6, 236, 12, 22, 3), tt::tire, sw);
        if (!simple) {
            QPainterPath tr;
            tr.moveTo(cx - 2, 239); tr.lineTo(cx - 2, 255);
            tr.moveTo(cx + 2, 239); tr.lineTo(cx + 2, 255);
            p.strokePath(x.map(tr), QPen(tt::tread, sw * 0.65, Qt::SolidLine, Qt::FlatCap));
        }
    }

    // 头 → 缩进驾驶室后面
    const qreal th = partProgress(v, 1.0);
    faded(1.0 - th * 1.6, [&] {
        const qreal tilt = std::isnan(lk.tilt) ? (lk.mood == Mood::Ask ? -6.0 : 0.0) : lk.tilt;
        QTransform hx;
        hx.translate(120, 84);
        hx.rotate(tilt * (1.0 - th));
        hx.translate(-120, -84);
        titanHead(p, lk, sw, simple, hx * morphAt({{120, 51.5}, {0, 150}, {0.3, 0.3}}, th));
    });

    // 手臂 → 驾驶室两侧的护板。挥手 / 伸手 / 举盾只在机器人形态里做,变形时先收回来。
    const qreal ta = partProgress(v, 0.4);
    const auto armAngle = [&](bool right) -> qreal {
        switch (lk.pose) {
        case Pose::Wave:  return right ? -152.0 + swing(lk) * 0.75 : 0.0;
        case Pose::Hold:  return right ? -150.0 : 0.0;
        case Pose::Reach: return right ? 0.0 : 78.0;
        default:          return 0.0;
        }
    };
    for (const bool right : {false, true}) {
        const qreal ux = right ? 168.0 : 50.0;
        const qreal fx = right ? 166.0 : 46.0;
        const qreal ax = right ? 180.0 : 60.0;
        QTransform rx;
        if (!right && lk.pose == Pose::Shield) {
            rx.translate(6.0 * (1.0 - ta), -4.0 * (1.0 - ta));
        } else {
            rx.translate(ax, 114);
            rx.rotate(armAngle(right) * (1.0 - ta));
            rx.translate(-ax, -114);
        }
        x = rx * morphAt({{ax, 159}, {right ? 3.0 : -3.0, 72}, {0.5, 0.69}}, ta);
        fs(rectP(ux, 110, 22, 40), tt::red, sw);
        flat(rectP(ux + 1.5, 138, 19, 10.5), tt::redDeep);
        fs(polyP({{fx, 150}, {fx + 28, 150}, {fx + 30, 190}, {fx - 2, 190}}), tt::blue, sw);
        if (!simple)
            flat(polyP({{fx + 2, 152}, {fx + 7, 152}, {fx + 5.5, 188}, {fx + 0.2, 188}}), tt::blueHi);
        fs(rectP(fx + 2, 190, 24, 18), tt::blueDeep, sw);
        QPainterPath fingers;
        for (const qreal gx : {fx + 8, fx + 14, fx + 20}) {
            fingers.moveTo(gx, 198);
            fingers.lineTo(gx, 208);
        }
        p.strokePath(x.map(fingers), QPen(tt::ink, k2, Qt::SolidLine, Qt::FlatCap));
    }

    // 烟囱 → 驾驶室两侧的排气管;加速 / 出场时冒气
    const qreal ts = partProgress(v, 0.5);
    const bool puff = (lk.flame || lk.mood == Mood::Boost) && !simple;
    for (const bool right : {false, true}) {
        const qreal cx = right ? 192.5 : 47.5;
        x = morphAt({{cx, 84}, {right ? -8.5 : 8.5, 114}, {1.0, 1.36}}, ts);
        fs(right ? polyP({{197, 56}, {188, 62}, {188, 112}, {197, 112}}) : polyP({{43, 56}, {52, 62}, {52, 112}, {43, 112}}),
           tt::chrome, sw);
        flat(rectP(cx - 2, 72, 4, 32), tt::chromeDark);
        if (puff) {
            const QPointF top = x.map(QPointF(cx, 56));
            const qreal a = lk.phase < 0 ? 0.3 : std::fmod(lk.phase * 3.0 + (right ? 0.5 : 0.0), 1.0);
            fill(p, circP(top.x(), top.y() - 7 - 10 * a, 4 + 4 * a), tt::amber, 0.85 * (1.0 - a));
            fill(p, circP(top.x(), top.y() - 16 - 10 * a, 3 + 3 * a), tt::chrome, 0.55 * (1.0 - a));
        }
    }

    // 腰带 → 保险杠;腹部格栅 → 车头格栅
    const qreal tg = partProgress(v, 0.8);
    x = morphAt({{120, 177}, {0, 102}, {1.64, 1.0}}, tg);
    fs(polyP({{96, 170}, {144, 170}, {148, 184}, {92, 184}}), tt::chrome, sw);
    flat(rectP(99, 172, 42, 2.5), tt::chromeHi);
    fs(rectP(113, 173, 14, 9), tt::red, k2);
    x = morphAt({{120, 155}, {0, 106}, {1.4, 0.67}}, tg);
    fs(polyP({{92, 140}, {148, 140}, {144, 170}, {96, 170}}), tt::chrome, sw);
    for (const qreal gx : {101.0, 109.0, 118.0, 127.0, 135.0})
        flat(rectP(gx, 145, 4, 20), tt::chromeDark);

    // 肩甲 → 车顶
    const qreal tsh = partProgress(v, 0.6);
    x = morphAt({{70, 100}, {22, 75}, {1.27, 0.42}}, tsh);
    fs(polyP({{52, 88}, {92, 88}, {92, 112}, {48, 112}, {48, 94}}), tt::red, sw);
    if (!simple)
        flat(polyP({{54, 90.5}, {90, 90.5}, {90, 95}, {50.5, 95}}), tt::redHi);
    x = morphAt({{170, 100}, {-22, 75}, {1.27, 0.42}}, tsh);
    fs(polyP({{188, 88}, {148, 88}, {148, 112}, {192, 112}, {192, 94}}), tt::red, sw);
    if (!simple)
        flat(polyP({{186, 90.5}, {150, 90.5}, {150, 95}, {189.5, 95}}), tt::redHi);

    // 胸甲 → 驾驶室:两块风挡、车灯、胸口核心。伪装成卡车时没有脸,车灯替眼灯显示防护状态。
    const qreal tc = partProgress(v, 0.7);
    x = morphAt({{120, 114}, {0, 102}, {1.5, 1.5}}, tc);
    fs(polyP({{88, 88}, {152, 88}, {158, 96}, {158, 140}, {82, 140}, {82, 96}}), tt::red, sw);
    flat(rectP(83.5, 126, 73, 12.5), tt::redDeep);
    fs(polyP({{90, 96}, {117, 96}, {117, 122}, {93, 122}}), tt::glass, k2);
    fs(polyP({{123, 96}, {150, 96}, {147, 122}, {123, 122}}), tt::glass, k2);
    if (!simple) {
        flat(polyP({{98, 97.5}, {104, 97.5}, {100, 120.5}, {95, 120.5}}), tt::glassHi);
        flat(polyP({{107, 97.5}, {109, 97.5}, {105.5, 120.5}, {103.5, 120.5}}), tt::glassHi);
        flat(polyP({{130, 97.5}, {136, 97.5}, {132, 120.5}, {127, 120.5}}), tt::glassHi);
        flat(polyP({{139, 97.5}, {141, 97.5}, {137.5, 120.5}, {135.5, 120.5}}), tt::glassHi);
    }
    const QColor beam = mixc(tt::amber, led, tc);
    for (const qreal hx : {85.0, 146.0}) {
        if (tc > 0.3)
            fill(p, x.map(rectP(hx - 2.5, 124.5, 14, 14)), led, 0.3 * qMin<qreal>(1.0, tc));
        fs(rectP(hx, 127, 9, 9), beam, k2);
    }
    const QPainterPath core = polyP({{120, 124.5}, {125.6, 127.75}, {125.6, 134.25}, {120, 137.5}, {114.4, 134.25}, {114.4, 127.75}});
    if (lk.pulse > 0.01)
        fill(p, x.map(hexP(120, 131, 9 + 3 * lk.pulse)), led, 0.16 + 0.3 * lk.pulse);
    fs(core, led, k2);

    // 载具形态才有的车顶示廓灯(灯很小,描边细一点,不然看不出琥珀色)
    x = QTransform();
    faded(qBound<qreal>(0.0, (v - 0.62) / 0.3, 1.0), [&] {
        for (const qreal lx : {76.0, 98.0, 120.0, 142.0, 164.0})
            fs(rectP(lx - 5, 164.5, 10, 5), tt::amber, sw * 0.35);
    });

    // 举盾
    if (lk.pose == Pose::Shield) {
        x = morphAt({{52, 178}, {0, 24}, {0.3, 0.3}}, ta);
        faded(1.0 - ta, [&] {
            fs(polyP({{26, 142}, {78, 142}, {84, 158}, {78, 198}, {52, 214}, {26, 198}, {20, 158}}), tt::blue, sw);
            if (!simple)
                flat(polyP({{29, 145}, {75, 145}, {78.5, 154}, {25.5, 154}}), tt::blueHi);
            fs(polyP({{52, 160}, {66, 168}, {66, 184}, {52, 196}, {38, 184}, {38, 168}}), tt::chrome, k2);
            flat(polyP({{52, 168}, {59, 172}, {59, 181}, {52, 187}, {45, 181}, {45, 172}}), led);
        });
    }

    if (lk.extras && !simple && v < 0.05)
        titanExtras(p, lk.mood, led);
}

}

QSizeF viewBox(bool head)
{
    if (theme::mecha())
        return QSizeF(200, head ? 162 : 250);
    return QSizeF(200, head ? 176 : 244);
}

int heightFor(int width, bool head)
{
    const QSizeF vb = viewBox(head);
    return qRound(width * vb.height() / vb.width());
}

void paint(QPainter& p, const QRectF& box, const Look& lk)
{
    paintAs(p, box, lk, theme::skin());
}

void paintAs(QPainter& p, const QRectF& box, const Look& lk, theme::Skin skin)
{
    const bool kawaii = skin == theme::Skin::Kawaii;
    const QSizeF vb(200, kawaii ? (lk.head ? 176 : 244) : (lk.head ? 162 : 250));
    const qreal s = qMin(box.width() / vb.width(), box.height() / vb.height());
    if (s <= 0.0)
        return;
    const qreal size = vb.width() * s;
    const bool simple = size < 56.0;
    p.save();
    p.setRenderHint(QPainter::Antialiasing, true);
    p.translate(box.center().x() - vb.width() * s / 2.0, box.bottom() - vb.height() * s);
    p.scale(s, s);
    if (skin == theme::Skin::Titan) {
        // 设计稿坐标 → 200 宽的 viewBox。笔宽按 viewBox 单位算好,再折回设计稿坐标。
        const qreal sw = strokeMecha(size);
        if (lk.head) {
            // 只要头:取设计稿里 x 70..170、y 10..91 这一块(盔冠到脖子)。
            p.scale(2.0, 2.0);
            p.translate(-70.0, -10.0);
            titanHead(p, lk, sw / 2.0, simple, QTransform());
        } else {
            p.scale(200.0 / 240.0, 200.0 / 240.0);
            titanRobot(p, lk, lk.strokePx > 0.0 ? lk.strokePx / (s * 200.0 / 240.0) : sw * 1.2, simple);
        }
    } else if (!kawaii) {
        const qreal sw = strokeMecha(size);
        if (!lk.head)
            mechaBody(p, lk, sw);
        mechaHead(p, lk, sw, simple);
    } else {
        const qreal sw = strokeKawaii(size);
        if (!lk.head)
            kawaiiBody(p, lk, sw);
        kawaiiHead(p, lk, sw, simple);
    }
    p.restore();
}

void paintFace(QPainter& p, const QRectF& box, Mood mood, bool blink, bool lookLeft)
{
    const bool m = theme::mecha();
    const bool t = theme::titan();
    const QRectF vb = t ? QRectF(96, 41, 48, 21) : m ? QRectF(44, 80, 112, 40) : QRectF(42, 78, 116, 70);
    const qreal s = qMin(box.width() / vb.width(), box.height() / vb.height());
    if (s <= 0.0)
        return;
    Look lk;
    lk.mood = mood;
    lk.blink = blink;
    lk.lookLeft = lookLeft;
    p.save();
    p.setRenderHint(QPainter::Antialiasing, true);
    p.translate(box.center().x() - vb.width() * s / 2.0, box.center().y() - vb.height() * s / 2.0);
    p.scale(s, s);
    p.translate(-vb.left(), -vb.top());
    if (t) {
        titanEyes(p, QTransform(), exprOf(lk), ledTitan(mood), -1.0);
    } else if (m) {
        mechaEyes(p, exprOf(lk), ledMecha(mood));
    } else {
        kawaiiFace(p, exprOf(lk), ledKawaii(mood));
        fill(p, ellP(54, 134, 9, 5), kw::blush, 0.6);
        fill(p, ellP(146, 134, 9, 5), kw::blush, 0.6);
    }
    p.restore();
}

QColor led(Mood m) { return theme::titan() ? ledTitan(m) : theme::mecha() ? ledMecha(m) : ledKawaii(m); }

QString moodName(Mood m)
{
    const bool k = !theme::mecha();
    switch (m) {
    case Mood::Guard: return QString::fromUtf8(k ? "守护中" : "要塞防御");
    case Mood::Happy: return QString::fromUtf8(k ? "开心" : "任务完成");
    case Mood::Ask:   return QString::fromUtf8(k ? "询问" : "请求指令");
    case Mood::Alert: return QString::fromUtf8("拦截");
    case Mood::Think: return QString::fromUtf8(k ? "思考" : "战术分析");
    case Mood::Boost: return QString::fromUtf8(k ? "加速" : "超频加速");
    case Mood::Info:  return QString::fromUtf8(k ? "好奇" : "扫描");
    case Mood::Sleep: return QString::fromUtf8(k ? "打盹" : "待机");
    }
    return QString();
}

}

RobotWidget::RobotWidget(int width, const robot::Look& look, QWidget* parent)
    : QWidget(parent), m_look(look), m_width(width)
{
    setAttribute(Qt::WA_TranslucentBackground);
    setSizePolicy(QSizePolicy::Fixed, QSizePolicy::Fixed);
}

void RobotWidget::setLook(const robot::Look& look)
{
    const bool resize = look.head != m_look.head || look.flame != m_look.flame;
    m_look = look;
    if (resize)
        updateGeometry();
    update();
}

void RobotWidget::setMood(robot::Mood mood)
{
    if (mood == m_look.mood)
        return;
    m_look.mood = mood;
    update();
}

void RobotWidget::setPose(robot::Pose pose)
{
    if (pose == m_look.pose)
        return;
    m_look.pose = pose;
    update();
}

void RobotWidget::setRobotWidth(int width)
{
    if (width == m_width)
        return;
    m_width = width;
    updateGeometry();
    update();
}

QSize RobotWidget::sizeHint() const
{
    int h = robot::heightFor(m_width, m_look.head);
    if (!m_look.head && (m_look.flame || m_look.mood == robot::Mood::Boost))
        h += m_width / 10;
    if (m_bobOn)
        h += 5;
    // 漫画符号与天线会略微超出机身轮廓。
    return QSize(m_width + m_width / 12, h + m_width / 40);
}

void RobotWidget::setAutoBlink(bool on)
{
    m_autoBlink = on && motion::enabled();
    if (!m_blinkTimer) {
        m_blinkTimer = new QTimer(this);
        m_blinkTimer->setSingleShot(true);
        connect(m_blinkTimer, &QTimer::timeout, this, [this] {
            if (m_blinkNow) {
                m_blinkNow = false;
                update();
                scheduleBlink();
                return;
            }
            m_blinkNow = true;
            update();
            m_blinkTimer->start(140);
        });
    }
    if (m_autoBlink && isVisible())
        scheduleBlink();
    else
        m_blinkTimer->stop();
}

void RobotWidget::scheduleBlink()
{
    if (m_autoBlink && m_blinkTimer && isVisible())
        m_blinkTimer->start(2600 + int(QRandomGenerator::global()->bounded(3200)));
}

void RobotWidget::setBob(bool on)
{
    on = on && motion::enabled();
    if (on == m_bobOn)
        return;
    m_bobOn = on;
    if (!on)
        m_bobY = 0.0;
    updateGeometry();
    syncTick();
    update();
}

void RobotWidget::setAnimated(bool on)
{
    on = on && motion::enabled();
    if (on == m_animOn)
        return;
    m_animOn = on;
    if (!on) {
        m_phase = -1.0;
        m_pulse = 0.0;
        m_glanceUntil = 0;
    }
    syncTick();
    update();
}

void RobotWidget::syncTick()
{
    const bool want = (m_bobOn || m_animOn) && isVisible();
    if (want && !m_ticker) {
        // 每只小垒错开一点相位,同屏几只不会齐步走。
        m_clockShift = QRandomGenerator::global()->bounded(2400);
        m_ticker = new motion::Ticker(this, [this](qint64 now) { tick(now); });
    }
    if (m_ticker)
        m_ticker->setActive(want);
}

void RobotWidget::tick(qint64 now)
{
    const qreal t = qreal(now + m_clockShift) / 1000.0;
    if (m_animOn) {
        m_phase = std::fmod(t / 2.4, 1.0);
        m_pulse = 0.5 + 0.5 * std::sin(t * 2.0 * M_PI / 2.2);
        if (now >= m_glanceAt) {
            if (m_glanceAt != 0 && m_look.mood == robot::Mood::Guard)
                m_glanceUntil = now + 700;
            m_glanceAt = now + 5500 + QRandomGenerator::global()->bounded(5000);
        }
    }
    if (m_bobOn)
        m_bobY = 2.2 * std::sin(t * 2.0 * M_PI / 3.0);
    update();
}

void RobotWidget::showEvent(QShowEvent* e)
{
    QWidget::showEvent(e);
    syncTick();
    scheduleBlink();
}

void RobotWidget::hideEvent(QHideEvent* e)
{
    QWidget::hideEvent(e);
    syncTick();
    if (m_blinkTimer)
        m_blinkTimer->stop();
    m_blinkNow = false;
}

void RobotWidget::paintEvent(QPaintEvent*)
{
    QPainter p(this);
    robot::Look lk = m_look;
    lk.blink = lk.blink || m_blinkNow;
    if (m_animOn) {
        lk.phase = m_phase;
        lk.pulse = m_pulse;
        lk.lookLeft = lk.lookLeft || motion::clockMs() < m_glanceUntil;
    }
    const int h = robot::heightFor(m_width, lk.head);
    const int flame = (!lk.head && (lk.flame || lk.mood == robot::Mood::Boost)) ? m_width / 10 : 0;
    const qreal bottom = height() - flame - (m_bobOn ? 2.5 : 0.0) - m_width / 40.0 + m_bobY;
    const QRectF box((width() - m_width) / 2.0, bottom - h, m_width, h);
    robot::paint(p, box, lk);
}
