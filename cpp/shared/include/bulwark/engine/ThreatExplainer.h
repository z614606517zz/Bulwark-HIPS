#pragma once
#include <QString>

namespace bulwark {
struct SecurityEvent;
}

namespace bulwark::engine {

// 离线告警解释:把一条事件翻译成普通用户能据此做决定的几句话——这类行为是什么、怎么判断是不是自己的操作、建议怎么做。
// AI 解释要用户自己配好 OpenAI 兼容端点,默认没配时这里是唯一的解释来源。
// 纯函数、全离线:不联网、不读磁盘、不碰注册表;跑在 UI 线程上,开销必须可忽略。
// 只说能从事件字段推出来的事,不猜文件用途、攻击者意图或家族归属:错的解释会让用户放心地点「放行」。
// 不重复界面上已有的标题(evtfmt::sentence)、riskReasons、命令行与哈希。与 AI 解释并存,界面上分别标明来源。
struct ThreatExplanation {
    enum class Tone {
        Info,      // 够不上硬指标,且形态像正常安装
        Caution,   // 可疑但没有硬指标
        Danger,    // 已有硬指标
    };

    // 这类行为是什么、为什么会被盯上。永远非空。
    QString meaning;
    // 怎么判断这是不是你自己的操作。推不出来时为空。
    QString recognize;
    // 建议怎么做,含放行的后果。永远非空。
    QString advice;

    Tone tone = Tone::Info;

    bool isEmpty() const { return meaning.isEmpty() || advice.isEmpty(); }
};

struct ThreatExplainer {
    static ThreatExplanation explain(const SecurityEvent& e);
};

}
