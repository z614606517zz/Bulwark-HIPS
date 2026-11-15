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
// 还原结果只用于扩大拦截 / 询问面(见 DefenseRule::matchesCommandLine),放行规则永远只看原文,
// 否则攻击者可以把命令行混淆成正好命中放行规则的形状。
// 开销有界:超过 kMaxInputChars 不还原;每种改写各自限次,整条流水线最多跑 kMaxPasses 遍。
struct CommandDeobfuscator {
    struct Result {
        // 还原后的命令行。与原文逐字一致(或未做任何还原)时为空 —— 调用方据此判断
        // "这条命令行到底有没有被混淆过",空值不代表还原失败。
        QString normalized;

        // Base64 等解码出来的独立正文。不拼进 normalized,各自作为一段文本参与匹配。
        QStringList decodedBlocks;

        // 实际生效的还原手法,用于在证据链与弹窗里说清"我们改了什么"。
        QStringList layers;

        bool changed() const { return !normalized.isEmpty() || !decodedBlocks.isEmpty(); }
    };

    static Result run(const QString& commandLine);

    // 还原发生在事件热路径上,必须是有界开销。超长命令行(压缩包参数列表、构建命令)
    // 直接放过:它们不是混淆的典型形态,而逐字符改写的成本随长度线性涨。
    static constexpr int kMaxInputChars = 8192;
    static constexpr int kMaxOutputChars = 16384;
    static constexpr int kMaxPasses = 2;
    static constexpr int kMaxDecodedBlocks = 2;
    static constexpr int kMaxDecodedChars = 8192;
    static constexpr int kMinBase64Chars = 16;
};

// 把「这条结论是还原之后才得到的」连同还原后的文本片段记进证据链,同一个事件只记一次。
// 只应在还原确实改变了结论时调用:正常命令行也会被还原,把还原本身当证据等于给正常软件写「使用了混淆」。
// why 说明是哪一侧的结论变了。
void reportCommandDeobfuscation(SecurityEvent& e, const QString& why);

}
