#pragma once
#include <QColor>
#include <QMargins>
#include <QRectF>
#include <QRegion>

class QPainter;

// 主窗口外壳:整扇窗口就是小垒的机身。机甲 = 切角机身 + 城垛 + V 字天线 + 六角耳舱 + 喷射靴;
// 卡哇伊 = 圆角机身 + 糖果城垛 + 小旗天线 + 圆耳朵 + 软靴;金刚 = 卡车机器人的上半身:红色胸甲(顶栏)、
// 钴蓝机身、铬银保险杠,头从顶边探出来,两侧立着烟囱,顶边六盏示廓灯。最大化时只留机身,装饰收进窗内。
namespace shell {

// 机身之外留给耳舱 / 天线 / 靴子的透明边距。
QMargins insets(bool maximized);

// 金刚外壳要多知道一点:胸甲画到哪、六盏示廓灯哪几盏亮、是不是警报。其它皮肤不看这些。
struct Extras {
    QRectF content;      // 页面区(窗口坐标):胸甲画到它上沿,保险杠从它下沿开始;空 = 按默认顶栏高度
    int lights = 0x3F;   // 六个防护维度,第 i 位 = 第 i 盏(进程 / 文件 / 注册表 / 网络 / 自保 / 内存)
    bool alarm = false;  // 防护关闭:示廓灯与车灯转红、交替闪
    int mood = -1;       // 顶边探出来的头用哪种表情(robot::Mood);<0 = 守卫
};

// phase:0..1 的循环动画时钟(<0 = 静止)。机甲 = 能量宝石呼吸 + 两侧耳舱信标轮流闪;
// 卡哇伊 = 小旗迎风飘 + 耳朵上的糖果灯轮流闪;金刚 = 眼灯呼吸,警报时示廓灯交替闪。
void paint(QPainter& p, const QRectF& body, bool maximized, const QColor& gem, qreal phase = -1.0,
           const Extras& extras = Extras());
// 会随 phase 变化的那几块区域(窗口坐标),动画每帧只需重画这里。
QRegion animatedRegion(const QRectF& body, bool maximized);

// 机身内的「屏幕框」(页面区)外缘描边。
void frameContent(QPainter& p, const QRectF& content);

}
