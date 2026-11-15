#include "design/Shell.h"
#include "design/Robot.h"
#include "design/Skin.h"
#include "design/Sticker.h"
#include "design/Theme.h"

#include <QFont>
#include <QPainter>
#include <QPainterPath>
#include <QRadialGradient>
#include <QtMath>

#include <cmath>
#include <utility>

namespace shell {
namespace {

QPainterPath hexPath(const QPointF& c, qreal r)
{
    QPainterPath p;
    p.addPolygon(sticker::hexagon(c, r));
    p.closeSubpath();
    return p;
}

void fs(QPainter& p, const QPainterPath& path, const QColor& fill, const QColor& ink, qreal w)
{
    p.fillPath(path, fill);
    p.strokePath(path, QPen(ink, w, Qt::SolidLine, Qt::RoundCap, Qt::RoundJoin));
}

QPainterPath bodyPath(const QRectF& b, bool maximized)
{
    if (theme::mecha()) {
        const qreal c = maximized ? 0.0 : 18.0;
        QPainterPath p;
        p.moveTo(b.left() + c, b.top());
        p.lineTo(b.right() - c, b.top());
        p.lineTo(b.right(), b.top() + c);
        p.lineTo(b.right(), b.bottom() - c);
        p.lineTo(b.right() - c, b.bottom());
        p.lineTo(b.left() + c, b.bottom());
        p.lineTo(b.left(), b.bottom() - c);
        p.lineTo(b.left(), b.top() + c);
        p.closeSubpath();
        return p;
    }
    QPainterPath p;
    const qreal r = maximized ? 0.0 : 30.0;
    if (r > 0)
        p.addRoundedRect(b, r, r);
    else
        p.addRect(b);
    return p;
}

// 呼吸光晕强度 0..1。
qreal breath(qreal phase)
{
    return phase < 0 ? 0.0 : 0.5 - 0.5 * std::cos(phase * 2.0 * M_PI);
}

// 信标灯:左耳在循环开头闪一下,右耳在半程闪一下;返回 0..1 的亮度(闪完迅速熄灭)。
qreal beacon(qreal phase, bool right)
{
    if (phase < 0)
        return 0.0;
    const qreal local = std::fmod(phase + (right ? 0.5 : 0.0), 1.0);
    constexpr qreal kOn = 0.14;
    return local < kOn ? 1.0 - local / kOn : 0.0;
}

void beaconHalo(QPainter& p, const QPointF& c, const QColor& color, qreal k)
{
    if (k <= 0.01)
        return;
    QRadialGradient g(c, 15);
    g.setColorAt(0.0, theme::tint(color, 0.75 * k));
    g.setColorAt(1.0, theme::tint(color, 0.0));
    p.setPen(Qt::NoPen);
    p.setBrush(g);
    p.drawEllipse(c, 15, 15);
}

void mechaShell(QPainter& p, const QRectF& b, bool maximized, const QColor& gem, qreal phase)
{
    const theme::Palette& P = theme::pal();
    const QColor ink = P.ink;
    const QColor cobalt = P.structure;
    const QColor orange = P.fin;
    const QColor orangeL = P.structureHi;
    const qreal x0 = b.left(), y0 = b.top(), x1 = b.right(), y1 = b.bottom();
    const qreal W = b.width(), cx = b.center().x(), cy = b.center().y();

    if (!maximized) {
        // 喷射靴
        for (const qreal fx : {x0 + W * 0.2, x1 - W * 0.2}) {
            QPainterPath boot;
            boot.moveTo(fx - 66, y1 - 8);
            boot.lineTo(fx + 66, y1 - 8);
            boot.lineTo(fx + 72, y1 + 13);
            boot.lineTo(fx - 72, y1 + 13);
            boot.closeSubpath();
            fs(p, boot, cobalt, ink, 3);
            p.fillRect(QRectF(fx - 60, y1 + 3, 36, 5), orange);
        }
        // 六角耳舱 + 天线
        for (const auto& [ex, sgn] : {std::pair<qreal, qreal>{x0 - 2, -1.0}, std::pair<qreal, qreal>{x1 + 2, 1.0}}) {
            const qreal ey = qMin(cy, y0 + 150);
            QPainterPath ant;
            ant.moveTo(ex + sgn * 18, ey - 32);
            ant.lineTo(ex + sgn * 27, ey - 86);
            p.strokePath(ant, QPen(ink, 4, Qt::SolidLine, Qt::RoundCap));
            fs(p, hexPath(QPointF(ex, ey), 34), cobalt, ink, 3);
            fs(p, hexPath(QPointF(ex, ey), 16), orangeL, ink, 2.4);
            const QPointF bc(ex + sgn * 28, ey - 90);
            const qreal lit = beacon(phase, sgn > 0);
            beaconHalo(p, bc, P.glow, lit);
            QPainterPath ball;
            ball.addEllipse(bc, 7, 7);
            fs(p, ball, lit > 0.01 ? theme::blend(P.glow.lighter(130), orange, lit) : orange, ink, 3);
        }
        // 城垛(中间那个位置留给 V 字天线)
        const int n = 7;
        const qreal bw = qMin<qreal>(64.0, (W - 160) / 9.0);
        const qreal gap = (W - 108 - n * bw) / (n - 1);
        for (int i = 0; i < n; ++i) {
            if (i == 3)
                continue;
            const qreal bx = x0 + 54 + i * (bw + gap);
            QPainterPath cr;
            cr.moveTo(bx, y0 + 12);
            cr.lineTo(bx, y0 - 18);
            cr.lineTo(bx + 6, y0 - 24);
            cr.lineTo(bx + bw - 6, y0 - 24);
            cr.lineTo(bx + bw, y0 - 18);
            cr.lineTo(bx + bw, y0 + 12);
            cr.closeSubpath();
            fs(p, cr, cobalt, ink, 3);
            p.fillRect(QRectF(bx + 8, y0 - 18, bw - 16, 4), QColor(255, 255, 255, 128));
            p.fillRect(QRectF(bx + bw / 2 - 3, y0 - 13, 6, 11), ink);
        }
        // V 字天线 + 能量宝石
        for (const qreal sgn : {-1.0, 1.0}) {
            QPainterPath fin;
            fin.moveTo(cx - sgn * 4, y0 + 2);
            fin.lineTo(cx - sgn * 72, y0 - 46);
            fin.lineTo(cx - sgn * 60, y0 - 50);
            fin.lineTo(cx + sgn * 7, y0 - 7);
            fin.closeSubpath();
            fs(p, fin, orange, ink, 3);
        }
        if (const qreal k = breath(phase); k > 0.01)
            p.fillPath(hexPath(QPointF(cx, y0 - 5), 21 + 5 * k), theme::tint(gem, 0.14 + 0.32 * k));
        fs(p, hexPath(QPointF(cx, y0 - 5), 16), gem, ink, 3);
        p.setPen(Qt::NoPen);
        p.setBrush(QColor(255, 255, 255, 215));
        p.drawEllipse(QPointF(cx - 4, y0 - 10), 3, 3);
    }

    const QPainterPath body = bodyPath(b, maximized);
    if (!maximized)
        p.fillPath(body.translated(6, 6), ink);
    p.fillPath(body, P.shell);
    p.strokePath(body, QPen(ink, 3, Qt::SolidLine, Qt::FlatCap, Qt::MiterJoin));
    p.setPen(QPen(QColor(255, 255, 255, 230), 3, Qt::SolidLine, Qt::SquareCap));
    p.drawLine(QPointF(x0 + 9, y0 + 30), QPointF(x0 + 9, y1 - 30));
    if (maximized) {
        // 最大化时把能量宝石收进机身顶边。
        if (const qreal k = breath(phase); k > 0.01)
            p.fillPath(hexPath(QPointF(cx, y0 + 9), 10 + 3 * k), theme::tint(gem, 0.12 + 0.3 * k));
        fs(p, hexPath(QPointF(cx, y0 + 9), 7), gem, ink, 2);
    }

    // 底边:警示条 + 机体编号
    sticker::hazard(p, QRectF(x0 + 36, y1 - 11, 120, 6), P.hazardA, P.hazardB, 5);
    QFont f;
    f.setFamilies({QStringLiteral("Bahnschrift"), QStringLiteral("Segoe UI")});
    f.setPixelSize(10);
    f.setWeight(QFont::Bold);
    f.setLetterSpacing(QFont::AbsoluteSpacing, 2.5);
    p.setFont(f);
    p.setPen(QColor(0x83, 0x82, 0x7F));
    p.drawText(QRectF(x1 - 260, y1 - 16, 220, 14), Qt::AlignRight | Qt::AlignVCenter,
               QStringLiteral("BWK-01 · FORTRESS"));
}

void kawaiiShell(QPainter& p, const QRectF& b, bool maximized, const QColor& gem, qreal phase)
{
    const theme::Palette& P = theme::pal();
    const QColor ink = P.ink;
    const QColor pink = P.structure;
    const QColor pinkL = P.structureHi;
    const qreal x0 = b.left(), y0 = b.top(), x1 = b.right(), y1 = b.bottom();
    const qreal W = b.width(), cx = b.center().x(), cy = b.center().y();

    if (!maximized) {
        // 软靴
        for (const qreal fx : {x0 + W * 0.2, x1 - W * 0.2}) {
            QPainterPath boot;
            boot.addRoundedRect(QRectF(fx - 66, y1 - 12, 132, 26), 13, 13);
            fs(p, boot, pink, ink, 3);
            QPainterPath hl;
            hl.addEllipse(QPointF(fx - 40, y1 - 3), 9, 4);
            p.fillPath(hl, QColor(255, 255, 255, 200));
        }
        // 圆耳朵 + 糖果天线
        for (const auto& [ex, sgn] : {std::pair<qreal, qreal>{x0 - 2, -1.0}, std::pair<qreal, qreal>{x1 + 2, 1.0}}) {
            const qreal ey = qMin(cy, y0 + 150);
            QPainterPath ant;
            ant.moveTo(ex + sgn * 16, ey - 30);
            ant.lineTo(ex + sgn * 24, ey - 80);
            p.strokePath(ant, QPen(ink, 4, Qt::SolidLine, Qt::RoundCap));
            QPainterPath ear;
            ear.addEllipse(QPointF(ex, ey), 33, 33);
            fs(p, ear, pink, ink, 3);
            QPainterPath in;
            in.addEllipse(QPointF(ex, ey), 15, 15);
            p.fillPath(in, pinkL);
            const QPointF bc(ex + sgn * 25, ey - 86);
            const qreal lit = beacon(phase, sgn > 0);
            beaconHalo(p, bc, gem, lit);
            QPainterPath ball;
            ball.addEllipse(bc, 7, 7);
            fs(p, ball, lit > 0.01 ? theme::blend(gem.lighter(125), gem, lit) : gem, ink, 3);
        }
        // 糖果城垛
        const int n = 7;
        const qreal bw = qMin<qreal>(64.0, (W - 160) / 9.0);
        const qreal gap = (W - 108 - n * bw) / (n - 1);
        for (int i = 0; i < n; ++i) {
            if (i == 3)
                continue;
            const qreal bx = x0 + 54 + i * (bw + gap);
            QPainterPath cr;
            cr.addRoundedRect(QRectF(bx, y0 - 24, bw, 40), 15, 15);
            fs(p, cr, pink, ink, 3);
            QPainterPath hl;
            hl.addEllipse(QPointF(bx + 14, y0 - 15), 6, 3.5);
            p.fillPath(hl, QColor(255, 255, 255, 215));
        }
        // 中间:小旗天线
        QPainterPath mast;
        mast.moveTo(cx, y0 + 2);
        mast.lineTo(cx, y0 - 42);
        p.strokePath(mast, QPen(ink, 4, Qt::SolidLine, Qt::RoundCap));
        QPainterPath top;
        top.addEllipse(QPointF(cx, y0 - 44), 5.5, 5.5);
        p.fillPath(top, ink);
        // 小旗迎风飘:旗尖上下甩、旗身两道波纹往外走。
        const qreal a = phase < 0 ? 0.0 : phase * 2.0 * M_PI * 2.0;
        const qreal amp = phase < 0 ? 0.0 : 1.0;
        const qreal tipY = y0 - 30 + 4.5 * amp * std::sin(a);
        QPainterPath flag;
        flag.moveTo(cx + 2, y0 - 41);
        const qreal w1 = 3.5 * amp * std::sin(a + 1.4), w2 = 3.5 * amp * std::sin(a + 0.6);
        flag.cubicTo(cx + 18, y0 - 38.3 + w1, cx + 32, y0 - 34.7 + w2, cx + 44, tipY);
        flag.cubicTo(cx + 32, y0 - 25.3 + w2, cx + 18, y0 - 21.7 + w1, cx + 2, y0 - 19);
        flag.closeSubpath();
        fs(p, flag, gem, ink, 2.6);
    }

    const QPainterPath body = bodyPath(b, maximized);
    if (!maximized)
        p.fillPath(body.translated(0, 7), P.shadow);
    p.fillPath(body, P.shell);
    p.strokePath(body, QPen(ink, 3, Qt::SolidLine, Qt::FlatCap, Qt::RoundJoin));
    p.setPen(QPen(QColor(255, 255, 255, 240), 5, Qt::SolidLine, Qt::RoundCap));
    p.drawLine(QPointF(x0 + 12, y0 + 40), QPointF(x0 + 12, y1 - 40));

    sticker::hazard(p, QRectF(x0 + 40, y1 - 12, 110, 6), P.hazardA, P.hazardB, 5);
    QFont f;
    f.setFamilies({QStringLiteral("Comic Sans MS"), QStringLiteral("Segoe UI")});
    f.setPixelSize(11);
    f.setWeight(QFont::Bold);
    f.setLetterSpacing(QFont::AbsoluteSpacing, 1.0);
    p.setFont(f);
    p.setPen(P.textSecondary);
    p.drawText(QRectF(x1 - 260, y1 - 18, 220, 15), Qt::AlignRight | Qt::AlignVCenter,
               QString::fromUtf8("BWK-01 · 小垒 ♥"));
}

// 金刚
namespace tt {
const QColor redHi(0xF2, 0x56, 0x5B);
const QColor redDeep(0x96, 0x13, 0x1A);
const QColor blueHi(0x5F, 0x8D, 0xFA);
const QColor chromeHi(0xF4, 0xF7, 0xFA);
const QColor chromeDeep(0x7B, 0x87, 0x98);
const QColor chromeDark(0x45, 0x4F, 0x5F);
const QColor tire(0x23, 0x2A, 0x36);
const QColor tread(0x4A, 0x55, 0x68);
const QColor alarm(0xFF, 0x3D, 0x4C);
}

// 六盏示廓灯相对机身中线的位置(按机身宽度的比例):左三盏、右三盏,顺序同 Extras::lights 的位。
constexpr qreal kLightAt[6] = {-0.294, -0.213, -0.132, 0.132, 0.213, 0.294};

void fsm(QPainter& p, const QPainterPath& path, const QColor& fill, const QColor& ink, qreal w)
{
    p.fillPath(path, fill);
    p.strokePath(path, QPen(ink, w, Qt::SolidLine, Qt::FlatCap, Qt::MiterJoin));
}

// 顶边中间探出来的头(盔冠到面甲);脖子藏在机身后面。头部 viewBox 200×162 画成 78 宽。
QRectF titanHeadBox(const QRectF& b)
{
    constexpr qreal w = 78.0;
    const qreal h = w * 162.0 / 200.0;
    return QRectF(b.center().x() - w / 2.0, b.top() + 11.0 - h, w, h);
}

// 警报时两组灯交替亮:group 0 / 1 在半个周期里轮流。
bool alarmOn(int group, qreal phase)
{
    return phase < 0 || (std::fmod(phase * 2.0, 1.0) < 0.5) == (group == 0);
}

QColor lightColor(int i, const Extras& ex, qreal phase, bool& lit)
{
    if (ex.alarm) {
        lit = alarmOn(i % 2, phase);
        return lit ? tt::alarm : theme::blend(tt::alarm, tt::chromeDark, 0.35);
    }
    lit = (ex.lights >> i) & 1;
    return lit ? theme::pal().hazardA : tt::chromeDark;
}

void titanShell(QPainter& p, const QRectF& b, bool maximized, const QColor& eye, qreal phase, const Extras& ex)
{
    const theme::Palette& P = theme::pal();
    const QColor ink = P.ink;
    const qreal x0 = b.left(), y0 = b.top(), x1 = b.right(), y1 = b.bottom();
    const qreal W = b.width(), cx = b.center().x();
    // 胸甲(红)画到页面区上沿,保险杠(铬)从页面区下沿开始;不知道页面区时按默认顶栏高度估。
    const qreal chest = ex.content.isValid() ? ex.content.top() - 3.0 : y0 + 98.0;
    const qreal bumper = ex.content.isValid() ? ex.content.bottom() + 3.0 : y1 - 16.0;

    if (!maximized) {
        // 车轮:画在机身后面,只露出下半截
        for (const qreal tx : {x0 + W * 0.135, x0 + W * 0.182, x1 - W * 0.182, x1 - W * 0.135}) {
            QPainterPath wheel;
            wheel.addRoundedRect(QRectF(tx - 25, y1 - 26, 50, 46), 8, 8);
            fsm(p, wheel, tt::tire, ink, 3);
            QPainterPath tread;
            for (const qreal dx : {-14.0, -5.0, 5.0, 14.0}) {
                tread.moveTo(tx + dx, y1 + 3);
                tread.lineTo(tx + dx, y1 + 16);
            }
            p.strokePath(tread, QPen(tt::tread, 3, Qt::SolidLine, Qt::FlatCap));
        }
        // 烟囱:两侧各一根,两道卡箍把它固定在机身上
        for (const qreal sgn : {-1.0, 1.0}) {
            const qreal edge = sgn < 0 ? x0 : x1;
            const qreal in = edge + sgn * 12;
            const qreal out = edge + sgn * 30;
            const qreal left = qMin(in, out);
            for (const qreal cy : {y0 + 22, y0 + 112}) {
                QPainterPath clamp;
                clamp.addRect(QRectF(qMin(edge, in), cy, 12, 9));
                fsm(p, clamp, tt::chromeDeep, ink, 2.5);
            }
            QPainterPath pipe;
            pipe.moveTo(out, y0 - 40);
            pipe.lineTo(in, y0 - 30);
            pipe.lineTo(in, y0 + 150);
            pipe.lineTo(out, y0 + 150);
            pipe.closeSubpath();
            fsm(p, pipe, P.fin, ink, 3);
            p.fillRect(QRectF(left + 3, y0 - 26, 3.5, 172), tt::chromeHi);
            QPainterPath groove;
            groove.addRect(QRectF(left + 9, y0 - 14, 6, 152));
            fsm(p, groove, tt::chromeDark, ink, 1.6);
        }
        // 肩甲:机身两个上角的钴蓝护板,四颗铆钉
        for (const qreal sgn : {-1.0, 1.0}) {
            const qreal a = sgn < 0 ? x0 + 10 : x1 - 10;
            const auto at = [&](qreal d) { return a - sgn * d; };
            QPainterPath pad;
            pad.moveTo(at(0), y0 + 4);
            pad.lineTo(at(0), y0 - 12);
            pad.lineTo(at(12), y0 - 24);
            pad.lineTo(at(150), y0 - 24);
            pad.lineTo(at(168), y0 + 4);
            pad.closeSubpath();
            fsm(p, pad, P.structure, ink, 3);
            QPainterPath hl;
            hl.moveTo(at(4), y0 - 13);
            hl.lineTo(at(13), y0 - 21.5);
            hl.lineTo(at(148), y0 - 21.5);
            hl.lineTo(at(152), y0 - 15.5);
            hl.lineTo(at(4), y0 - 15.5);
            hl.closeSubpath();
            p.fillPath(hl, tt::blueHi);
            p.setPen(Qt::NoPen);
            p.setBrush(ink);
            for (const qreal d : {36.0, 64.0, 92.0, 120.0})
                p.drawEllipse(QPointF(at(d), y0 - 7), 2.4, 2.4);
        }
        // 示廓灯:顶边六盏 = 六个防护维度,关掉一维就灭一盏
        for (int i = 0; i < 6; ++i) {
            const qreal lx = cx + kLightAt[i] * W;
            bool lit = false;
            const QColor c = lightColor(i, ex, phase, lit);
            if (lit) {
                QRadialGradient g(QPointF(lx, y0 - 4), 30);
                g.setColorAt(0.0, theme::tint(c, 0.45));
                g.setColorAt(1.0, theme::tint(c, 0.0));
                p.setPen(Qt::NoPen);
                p.setBrush(g);
                p.drawEllipse(QPointF(lx, y0 - 4), 30, 30);
            }
            QPainterPath lamp;
            lamp.moveTo(lx - 21, y0 + 3);
            lamp.lineTo(lx - 15, y0 - 12);
            lamp.lineTo(lx + 15, y0 - 12);
            lamp.lineTo(lx + 21, y0 + 3);
            lamp.closeSubpath();
            fsm(p, lamp, c, ink, 2.5);
            QPainterPath glint;
            glint.moveTo(lx - 11, y0 - 9.5);
            glint.lineTo(lx - 3, y0 - 9.5);
            glint.lineTo(lx - 6, y0 - 2);
            glint.lineTo(lx - 14, y0 - 2);
            glint.closeSubpath();
            p.fillPath(glint, QColor(255, 255, 255, lit ? 150 : 50));
        }
        // 护颈 + 探出顶边的头,眼灯 = 防护状态
        QPainterPath collar;
        collar.moveTo(cx - 54, y0 + 2);
        collar.lineTo(cx - 42, y0 - 15);
        collar.lineTo(cx + 42, y0 - 15);
        collar.lineTo(cx + 54, y0 + 2);
        collar.closeSubpath();
        fsm(p, collar, P.shell, ink, 3);
        robot::Look look;
        look.head = true;
        look.extras = false;
        look.mood = ex.mood >= 0 ? robot::Mood(ex.mood) : robot::Mood::Guard;
        look.phase = phase;
        look.pulse = breath(phase);
        robot::paint(p, titanHeadBox(b), look);
    }

    // 机身:钴蓝底,上面一截红色胸甲(顶栏在里面),底下一条铬保险杠
    const QPainterPath body = bodyPath(b, maximized);
    if (!maximized)
        p.fillPath(body.translated(6, 6), ink);
    p.fillPath(body, P.structure);
    p.save();
    p.setClipPath(body);
    p.fillRect(QRectF(x0, y0, W, chest - y0), P.shell);
    p.fillRect(QRectF(x0, chest - 8, W, 8), tt::redDeep);
    p.fillRect(QRectF(x0, chest, W, 3), ink);
    p.fillRect(QRectF(x0 + 29, y0 + 8, W - 58, 3), tt::redHi);
    p.fillRect(QRectF(x0 + 6, chest + 14, 2, qMax<qreal>(0.0, bumper - chest - 28)), tt::blueHi);
    p.fillRect(QRectF(x0, bumper - 3, W, 3), ink);
    p.fillRect(QRectF(x0, bumper, W, y1 - bumper), P.fin);
    p.fillRect(QRectF(x0, y1 - 4, W, 4), tt::chromeDeep);
    p.restore();
    p.strokePath(body, QPen(ink, 3, Qt::SolidLine, Qt::FlatCap, Qt::MiterJoin));

    if (maximized) {
        // 最大化:示廓灯和眼灯收进胸甲上沿
        for (int i = 0; i < 6; ++i) {
            bool lit = false;
            const QColor c = lightColor(i, ex, phase, lit);
            const QRectF r(cx + kLightAt[i] * W - 9, y0 + 2, 18, 5);
            p.fillRect(r, c);
            p.setPen(QPen(ink, 1.5));
            p.setBrush(Qt::NoBrush);
            p.drawRect(r);
        }
        const QRectF visor(cx - 22, y0 + 1.5, 44, 9);
        p.fillRect(visor, P.screen);
        p.setPen(QPen(ink, 1.5));
        p.setBrush(Qt::NoBrush);
        p.drawRect(visor);
        const qreal k = breath(phase);
        for (const qreal ex0 : {cx - 15.0, cx + 4.0}) {
            if (k > 0.01)
                p.fillRect(QRectF(ex0 - 2, y0 + 2.5, 15, 7), theme::tint(eye, 0.25 * k));
            p.fillRect(QRectF(ex0, y0 + 4, 11, 4), eye);
        }
    }

    // 保险杠:警示条、格栅、两盏车灯(= 信标:警报时转红交替闪,状态未知时熄灭)、机体编号
    const qreal bh = y1 - bumper;
    if (bh >= 8) {
        const qreal mid = bumper + bh / 2.0;
        const QRectF hz(x0 + 36, mid - 3.5, 120, 7);
        sticker::hazard(p, hz, P.hazardA, P.hazardB, 5);
        p.setPen(QPen(ink, 1.5));
        p.setBrush(Qt::NoBrush);
        p.drawRect(hz);
        const QRectF grille(cx - 150, mid - 4.5, 300, 9);
        p.fillRect(grille, tt::chromeDark);
        for (qreal gx = grille.left() + 5; gx < grille.right() - 2; gx += 13)
            p.fillRect(QRectF(gx, grille.top(), 2, grille.height()), tt::chromeHi);
        p.setPen(QPen(ink, 2));
        p.drawRect(grille);
        for (int side = 0; side < 2; ++side) {
            const QRectF hl(side == 0 ? cx - 200 : cx + 164, mid - 4.5, 36, 9);
            QColor c = P.hazardA;
            if (ex.alarm)
                c = alarmOn(side, phase) ? tt::alarm : theme::blend(tt::alarm, tt::chromeDark, 0.35);
            else if (ex.lights == 0)
                c = tt::chromeDark;
            p.fillRect(hl, c);
            p.setPen(QPen(ink, 2));
            p.drawRect(hl);
            p.fillRect(QRectF(hl.left() + 4, hl.top() + 2, 9, 2), QColor(255, 255, 255, 190));
        }
        QFont f;
        f.setFamilies({QStringLiteral("Bahnschrift"), QStringLiteral("Segoe UI")});
        f.setPixelSize(10);
        f.setWeight(QFont::Bold);
        f.setLetterSpacing(QFont::AbsoluteSpacing, 2.5);
        p.setFont(f);
        p.setPen(tt::chromeDark);
        p.drawText(QRectF(x1 - 260, bumper, 220, bh), Qt::AlignRight | Qt::AlignVCenter,
                   QStringLiteral("BWK-01 · ROBOT MODE"));
    }
}

}

QMargins insets(bool maximized)
{
    if (maximized)
        return QMargins(0, 0, 0, 0);
    return QMargins(40, 50, 40, 22);
}

void paint(QPainter& p, const QRectF& body, bool maximized, const QColor& gem, qreal phase, const Extras& extras)
{
    p.save();
    p.setRenderHint(QPainter::Antialiasing, true);
    if (theme::titan())
        titanShell(p, body, maximized, gem, phase, extras);
    else if (theme::mecha())
        mechaShell(p, body, maximized, gem, phase);
    else
        kawaiiShell(p, body, maximized, gem, phase);
    p.restore();
}

QRegion animatedRegion(const QRectF& b, bool maximized)
{
    const qreal cx = b.center().x(), y0 = b.top();
    if (theme::titan()) {
        const qreal W = b.width();
        if (maximized) {
            QRegion r(QRectF(cx - 26, y0, 52, 14).toAlignedRect());
            for (const qreal k : kLightAt)
                r += QRectF(cx + k * W - 12, y0, 24, 10).toAlignedRect();
            return r;
        }
        QRegion r(titanHeadBox(b).adjusted(-4, -4, 4, 4).toAlignedRect());
        for (const qreal k : kLightAt)
            r += QRectF(cx + k * W - 32, y0 - 36, 64, 44).toAlignedRect();
        r += QRectF(cx - 206, b.bottom() - 18, 48, 18).toAlignedRect();
        r += QRectF(cx + 158, b.bottom() - 18, 48, 18).toAlignedRect();
        return r;
    }
    if (maximized)
        return QRegion(QRectF(cx - 18, y0 - 6, 36, 34).toAlignedRect());
    QRegion r(QRectF(cx - 34, y0 - 58, 92, 82).toAlignedRect());
    const qreal ey = qMin(b.center().y(), y0 + 150);
    const qreal dy = theme::mecha() ? 90 : 86;
    const qreal dx = theme::mecha() ? 28 : 25;
    for (const auto& [ex, sgn] : {std::pair<qreal, qreal>{b.left() - 2, -1.0}, std::pair<qreal, qreal>{b.right() + 2, 1.0}})
        r += QRectF(ex + sgn * dx - 17, ey - dy - 17, 34, 34).toAlignedRect();
    return r;
}

void frameContent(QPainter& p, const QRectF& content)
{
    p.save();
    p.setRenderHint(QPainter::Antialiasing, true);
    const QRectF r = content.adjusted(-1.5, -1.5, 1.5, 1.5);
    QPainterPath path;
    if (theme::mecha())
        path.addRect(r);
    else
        path.addRoundedRect(r, 6, 6);
    p.strokePath(path, QPen(theme::pal().ink, 3, Qt::SolidLine, Qt::FlatCap, Qt::MiterJoin));
    if (theme::titan()) {
        // 胸口大屏的内缘一圈淡淡的能量蓝
        p.setPen(QPen(theme::tint(theme::glow(), 0.18), 1.0));
        p.setBrush(Qt::NoBrush);
        p.drawRect(content.adjusted(0.5, 0.5, -0.5, -0.5));
    }
    p.restore();
}

}
