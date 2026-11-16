#pragma once
#include <QString>
#include <QStringList>

namespace bulwark {
struct SecurityEvent;
}

namespace bulwark::engine {

// 命令行还原:把 cmd / PowerShell 的转义与拼接混淆(p^o^w^e^r^s^h^e^l^l、i`e`x、"fromBase64"+"String")还原成
// 实际会被执行的那一串,供规则匹配与特征扫描多比对一遍。
// 只做字面层面的确定性改写,不执行、不求值;不展开 %var:~n,m%(要有目标机器的环境变量才算得出),
// 不做字符串反转、-join、[string]::join 这类需要求值的构造。
// Base64 解出的正文单独成块(decodedBlocks),不拼回命令行,避免模式跨边界误命中。
// 还原结果与规整形态(canonical)都只用于扩大拦截 / 询问面(见 DefenseRule::matchesCommandLine),
// 放行规则永远只看原文,否则攻击者可以把命令行写成正好命中放行规则的形状。
// 开销有界:超过 kMaxInputChars 不还原;每种改写各自限次,整条流水线最多跑 kMaxPasses 遍。
// 规整是一遍线性扫描,上限放到 kMaxCanonicalInputChars:否则往命令行里填充几 KB 就能绕开它。
struct CommandDeobfuscator {
    struct Result {
        // 还原后的命令行。与原文逐字一致(或未做任何还原)时为空 —— 调用方据此判断
        // "这条命令行到底有没有被混淆过",空值不代表还原失败。
        QString normalized;

        // Base64 等解码出来的独立正文。不拼进 normalized,各自作为一段文本参与匹配。
        QStringList decodedBlocks;

        // 实际生效的还原手法,用于在证据链与弹窗里说清"我们改了什么"。
        QStringList layers;

        // 原文的规整形态,至多两份:
        //   1) 只把连续的空格 / Tab / 换行压成一个空格;
        //   2) 在 1) 的基础上再去掉包着单个 token 的引号。
        // `sc  stop X`、`sc<Tab>stop X`、`"sc" stop X` 与 `sc stop X` 执行起来是同一条命令,
        // 而规则模式里的空格是字面量,不规整就整条失配。两份都要留:有的模式本身带引号
        // (*.creationtime = '*),去了引号反而对不上。
        // 这不是混淆还原:正常命令行也常带引号和多余空白,所以它不进 normalized、不记 layers,
        // 不能拿来判断"有没有被混淆"。与原文(去掉首尾空白后)、normalized 或前一份逐字一致的不留。
        QStringList canonicalForms;

        bool changed() const { return !normalized.isEmpty() || !decodedBlocks.isEmpty(); }
    };

    static Result run(const QString& commandLine);

    // 还原发生在事件热路径上,必须是有界开销。超长命令行(压缩包参数列表、构建命令)
    // 直接放过:它们不是混淆的典型形态,而逐字符改写的成本随长度线性涨。
    static constexpr int kMaxInputChars = 8192;
    static constexpr int kMaxOutputChars = 16384;
    // Windows 命令行最长 32767 个字符,规整覆盖到这个长度。
    static constexpr int kMaxCanonicalInputChars = 32768;

    // 给直接读原文做词匹配的检测点用:压空白、去掉包着单个 token 的引号之后的文本;
    // 没有可规整的(或超过上限)就是原文本身。不做混淆还原。
    static QString tidied(const QString& commandLine);
    static constexpr int kMaxPasses = 2;
    static constexpr int kMaxDecodedBlocks = 2;
    static constexpr int kMaxDecodedChars = 8192;
    static constexpr int kMinBase64Chars = 16;
};

// 把「这条结论是还原之后才得到的」连同还原后的文本片段记进证据链,同一个事件只记一次。
// 只应在还原确实改变了结论时调用:正常命令行也会被还原,把还原本身当证据等于给正常软件写「使用了混淆」。
// why 说明是哪一侧的结论变了。
void reportCommandDeobfuscation(SecurityEvent& e, const QString& why);

// 规则只在规整形态上命中时,把规整后的文本记进证据链:界面显示的是原文,不说清就和命中的判据对不上。
// 只陈述比对用的是哪一串,不加分、不称为混淆。matchedForm 是命中的那一份规整形态。
void reportCommandCanonicalization(SecurityEvent& e, const QString& matchedForm);

}
