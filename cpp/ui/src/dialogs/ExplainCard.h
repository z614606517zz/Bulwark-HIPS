#pragma once

class QWidget;

namespace bulwark {
struct SecurityEvent;
}

// 离线解释卡片(ThreatExplainer 的界面外壳)。询问弹窗与拦截通知都用它,两处取舍不同,但视觉语言必须一致。
namespace explaincard {

struct Options {
    // 通知卡片用:省掉「建议怎么做」,处置已经做完了。
    // 留下「这是什么」和「是不是你自己的操作」,后者是判断该不该点撤销的依据。
    bool omitAdvice = false;

    // 紧凑排版:通知卡片宽度有限且会自动消失,留白收紧、不加外框。
    bool compact = false;
};

// 构造解释卡片。返回 nullptr 表示无可展示内容。
QWidget* build(const bulwark::SecurityEvent& e, const Options& opt = Options{});

}
