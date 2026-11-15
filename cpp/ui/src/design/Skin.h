#pragma once
#include <QColor>
#include <QObject>
#include <QPainterPath>
#include <QPointF>
#include <QRectF>
#include <QString>

// 三套机器人皮肤:「机甲」(炭黑 + 装甲白 + 赛车橙,切角)、「卡哇伊」(可可棕描边 + 粉彩,大圆角)
// 与「金刚」(装甲红 + 钴蓝 + 铬银的卡车机器人,切角,暗色内容区)。
// 结构完全相同,只换涂装与轮廓;theme:: 的全部取色都经由这里的当前调色板。
namespace theme {

enum class Skin { Mecha, Kawaii, Titan };

struct Palette {
    QColor bg, surface, surfaceTop, surfaceAlt, surfaceHi, raised, field;
    QColor border, borderStrong, borderLit;
    QColor text, textSecondary, textMuted, textDisabled;
    QColor accent, accentSoft, accentStrong, accentDeep, accentAlt, accentInk;
    QColor brass, brassDeep;
    QColor success, warning, danger, info;
    QColor violet, purple, sky, cyan, teal, amber, pink, olive, periwinkle;

    QColor ink;          // 描边与贴纸投影的主色
    QColor shadow;       // 硬投影
    QColor shell;        // 机身外壳
    QColor structure;    // 城垛 / 耳舱 / 靴子
    QColor structureHi;  // 结构件上的点缀
    QColor fin;          // V 字天线(机甲)/ 头顶小旗(卡哇伊)
    QColor screen, screen2, scrText, scrText2, scrMuted;   // 深色「屏幕」
    QColor glow;         // 屏幕里的发光色
    QColor hazardA, hazardB;                               // 警示斑马条
    QColor menuSel, menuSelText;
    QColor blush;        // 卡哇伊腮红;机甲为橙色点缀
};

Skin skin();
// 机甲一系(机甲、金刚):切角轮廓、尖角墨线、战报腔。金刚是这一系里唯一的暗色内容区,
// 只在浅色面板上才看得清的取色要另行区分时,用 titan()。
bool mecha();
bool titan();
const Palette& pal();
void setSkin(Skin s);

Skin savedSkin();
void saveSkin(Skin s);
QString skinKey(Skin s);
QString skinName(Skin s);
Skin skinFromKey(const QString& key, Skin fallback = Skin::Mecha);

// 轮廓语汇:机甲 = 左上 / 右下大切角、另两角小切角;卡哇伊 = 大圆角;
// 金刚 = 上两角大切角(风挡 / 胸甲的形状)、下两角小切角。
QPainterPath panelPath(const QRectF& r, qreal size);
qreal inkWidth();
QPointF shadowOffset();
// 色块上的文字色:亮底用墨色,暗底用白色。
QColor textOn(const QColor& bg);

class SkinHub : public QObject
{
    Q_OBJECT
public:
    static SkinHub* instance();

signals:
    void switchRequested(theme::Skin skin);

private:
    using QObject::QObject;
};

inline void requestSkin(Skin s) { emit SkinHub::instance()->switchRequested(s); }

}
