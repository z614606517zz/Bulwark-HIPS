#pragma once
#include "bulwark/models/Enums.h"

#include <QString>

class QWidget;

namespace bulwark {
struct SecurityEvent;
}

// YARA 命中的呈现:把 YARA Forge 规则名拆成「家族 / 类别 / 平台 / 来源」,配上扫描屏、
// 由 SHA-256 生成的指纹条码与处置步骤。战报(家族规则命中、已自动处置)与询问弹窗共用。
namespace yaraview {

struct RuleInfo {
    QString source;    // 规则来源仓库(按 YARA Forge 加的前缀认),认不出为空
    QString family;    // 家族名(Remcos、Mimikatz…);规则描述的是技法 / 迹象时为空
    QString title;     // 当大字的名字:家族名,否则是去掉前后缀的规则主体
    QString category;  // 中文类别:远控木马、窃密木马、可疑特征…
    QString platform;  // Windows / Linux / macOS…
};

// verified = 命中的是已验证的家族规则(YaraRules.MaliciousRules);认不出类别时据此兜底。
RuleInfo parseRule(const QString& rule, bool verified);

// 战报主体:扫描屏 + 家族大字 + 钢印(卡片出现后砸下)、规则全名与来源、文件、
// SHA-256 指纹、处置步骤。
QWidget* reportHero(const bulwark::SecurityEvent& e, bulwark::EnforcementOutcome outcome,
                    bool execBlocked, const QString& stampText);

// 询问弹窗里的一条:扫描屏 + 名字 + 类别 + 规则是否验证过。事件没有 YARA 命中时返回 nullptr。
QWidget* promptStrip(const bulwark::SecurityEvent& e);

// 询问弹窗「为什么提示」里由 YARA 生成的那条(已由 promptStrip 单独展示)。
bool isYaraReason(const QString& reason);

}
