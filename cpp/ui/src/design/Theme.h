#pragma once
#include "design/Skin.h"

#include <QBrush>
#include <QColor>
#include <QLinearGradient>
#include <QRectF>
#include <QString>

class QApplication;

namespace theme {

inline QColor bg()           { return pal().bg; }
inline QColor bgSidebar()    { return pal().structure; }
inline QColor railInset()    { return pal().screen; }
inline QColor railBorder()   { return pal().ink; }
inline QColor railMuted()    { return pal().scrMuted; }
inline QColor surface()      { return pal().surface; }
inline QColor surfaceTop()   { return pal().surfaceTop; }
inline QColor surfaceAlt()   { return pal().surfaceAlt; }
inline QColor surfaceHi()    { return pal().surfaceHi; }
inline QColor raised()       { return pal().raised; }
inline QColor field()        { return pal().field; }
inline QColor border()       { return pal().border; }
inline QColor borderStrong() { return pal().borderStrong; }
inline QColor borderLit()    { return pal().borderLit; }

inline QColor textPrimary()   { return pal().text; }
inline QColor textSecondary() { return pal().textSecondary; }
inline QColor textMuted()     { return pal().textMuted; }
inline QColor textDisabled()  { return pal().textDisabled; }

inline QColor accent()       { return pal().accent; }
inline QColor accentSoft()   { return pal().accentSoft; }
inline QColor accentStrong() { return pal().accentStrong; }
inline QColor accentDeep()   { return pal().accentDeep; }
inline QColor accentAlt()    { return pal().accentAlt; }
inline QColor accentInk()    { return pal().accentInk; }
inline QColor brass()        { return pal().brass; }
inline QColor brassDeep()    { return pal().brassDeep; }

inline QColor success() { return pal().success; }
inline QColor warning() { return pal().warning; }
inline QColor danger()  { return pal().danger; }
inline QColor info()    { return pal().info; }

inline QColor violet()     { return pal().violet; }
inline QColor purple()     { return pal().purple; }
inline QColor sky()        { return pal().sky; }
inline QColor cyan()       { return pal().cyan; }
inline QColor teal()       { return pal().teal; }
inline QColor amber()      { return pal().amber; }
inline QColor pink()       { return pal().pink; }
inline QColor olive()      { return pal().olive; }
inline QColor periwinkle() { return pal().periwinkle; }

inline QColor ink()     { return pal().ink; }
inline QColor screen()  { return pal().screen; }
inline QColor glow()    { return pal().glow; }

// 叠在面板上的淡色层(悬停底、暗格、网格线、虚线)的底色:浅色皮肤用墨色压暗一点,
// 金刚的面板本身就是暗的,压暗看不出来,反过来用亮色提一点。
inline QColor overlay() { return titan() ? QColor(0xC8, 0xD6, 0xF0) : pal().ink; }
// 比所在面板更暗的小部件(输入框、复选框、拨杆槽)的描边:暗色面板上墨线和底色分不开,金刚改用亮一档的边框色。
inline QColor rim()     { return titan() ? pal().borderStrong : pal().ink; }

inline QColor tint(const QColor& c, qreal alpha)
{
    QColor r = c;
    r.setAlphaF(qBound<qreal>(0.0, alpha, 1.0));
    return r;
}

inline QColor blend(const QColor& fg, const QColor& bg, qreal a)
{
    return QColor(int(fg.red()   * a + bg.red()   * (1 - a)),
                  int(fg.green() * a + bg.green() * (1 - a)),
                  int(fg.blue()  * a + bg.blue()  * (1 - a)));
}

inline QColor soft(const QColor& c)
{
    return blend(accentInk(), c, 0.40);
}

inline QLinearGradient brandGradient(const QRectF& r)
{
    QLinearGradient g(r.topLeft(), r.bottomRight());
    g.setColorAt(0.0, accentStrong());
    g.setColorAt(1.0, accentDeep());
    return g;
}

namespace metric {
inline constexpr int topbarH    = 66;
inline constexpr int radiusCard = 14;
inline constexpr int radiusCtl  = 8;
inline constexpr int pagePad    = 24;
}

QBrush canvasBrush();

QBrush grainBrush();

QString styleSheet();

// 可重复调用:切换皮肤后重新下发调色板、样式表与原生标题栏颜色。
void apply(QApplication& app);

}
