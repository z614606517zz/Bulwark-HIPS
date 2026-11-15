#pragma once
#include <QRegularExpression>
#include <QString>
#include <QStringList>
#include "bulwark/engine/CommandLineAnalyzer.h"
#include "bulwark/engine/EngineCommon.h"

namespace bulwark::engine {

struct AmsiBlockDecision {
    bool        block = false;
    QStringList hits;
    QStringList reasons;
    QStringList techniques;

    bool empty() const { return hits.isEmpty(); }
};

namespace amsi_scan_policy {

// /all 必须落在同一条 delete shadows 命令里:只清最旧一份(/oldest)的维护脚本,别处出现 -AllowClobber 不算。
inline const QRegularExpression& deleteAllShadowsRe() {
    static const QRegularExpression re(QStringLiteral(R"(delete\s+shadows[^\r\n;|&]*[/-]all\b)"));
    return re;
}

// 以 ^ 开头的关键词必须落在词首(前面是开头或非字母数字):confirm 里的 irm、$iex 变量都不算。
inline bool containsKeyword(const QString& lower, const char* kw) {
    if (kw[0] != '^')
        return lower.contains(QLatin1String(kw));
    const QLatin1String needle(kw + 1);
    for (qsizetype at = lower.indexOf(needle); at >= 0; at = lower.indexOf(needle, at + 1)) {
        const QChar before = at > 0 ? lower.at(at - 1) : QChar(u' ');
        if (!before.isLetterOrNumber() && before != u'_' && before != u'-' && before != u'$')
            return true;
    }
    return false;
}

// AMSI 是同步拦截:回「已检出」的那一刻脚本就不会执行,也没有询问的机会。所以这里只收
// 「一段正在执行的脚本里出现这个组合,不可能是正常工作」的形态;单纯下载、单纯 IEX、
// 两者兼有(Chocolatey / Scoop 官方一行安装就是这样)都不拦。
struct Rule {
    const char* id;
    const char* reason;
    const char* technique;
    bool        needsBase64Pe;
    const char* groups[4][10];
    // 最后一组也可由「隐藏窗口 / 编码命令」的精确判定满足(Out-File -Enc utf8 这类编码名不算)。
    bool        stealthCountsForLastGroup = false;
    // 非空时还要求这条正则在小写后的脚本里命中:各组关键词必须出现在同一条命令里。
    const QRegularExpression& (*sameCommand)() = nullptr;
};

inline const Rule* rules(int& count) {
    static const Rule kRules[] = {
        { "amsi-bypass", "脚本内含 AMSI 致盲代码 —— 正在尝试摘掉脚本检测通道本身", "T1562.001", false,
          { { "amsiinitfailed", "amsiutils", "amsicontext", "amsiscanbuffer", "amsiopensession", nullptr } } },

        { "etw-bypass", "脚本改写 ETW 写事件函数 —— 正在尝试摘掉行为遥测通道", "T1562.006", false,
          { { "etweventwrite", "etweventunregister", "ntteventwrite", nullptr },
            { "virtualprotect", "writeprocessmemory", "marshal]::copy", nullptr } } },

        { "download-exec-hidden", "下载后内存执行,且刻意隐藏窗口或编码自身(投递器标准形态)", "T1059.001", false,
          { { "downloadstring", "downloaddata", "downloadfile", "net.webclient", "invoke-webrequest", "^iwr ",
              "invoke-restmethod", "^irm ", "start-bitstransfer", nullptr },
            { "invoke-expression", "^iex ", "^iex(", "[scriptblock]::create", "eval(", "executeglobal", nullptr },
            { "createnowindow", "windowstyle=hidden", nullptr } },
          true },

        { "embedded-pe-reflective-load", "脚本内嵌 Base64 编码的 PE 可执行体并准备反射加载(无文件载荷)",
          "T1620", true,
          { { "reflection.assembly", "assembly]::load", "[appdomain]", "system.reflection", nullptr } } },

        { "credential-dump", "脚本内含凭据转储代码(LSASS / SAM / 票据)", "T1003", false,
          { { "invoke-mimikatz", "sekurlsa::", "lsadump::", "kerberos::", "invoke-ntdsutil", "mimikatz.exe",
              nullptr } } },

        { "lsass-minidump", "脚本调用 comsvcs.dll MiniDump 转储 LSASS 内存", "T1003.001", false,
          { { "comsvcs", nullptr }, { "minidump", nullptr } } },

        { "kerberoast", "脚本批量请求 Kerberos 服务票据(Kerberoasting)", "T1558.003", false,
          { { "kerberosrequestorsecuritytoken", nullptr } } },

        { "shadow-copy-wipe", "脚本销毁全部卷影副本(勒索加密前的标准动作)", "T1490", false,
          { { "delete shadows", nullptr } }, false, deleteAllShadowsRe },

        { "shadow-copy-wipe-wmi", "脚本经 WMI 删除卷影副本(勒索加密前的标准动作)", "T1490", false,
          { { "win32_shadowcopy", nullptr }, { ".delete(", "remove-ciminstance", "remove-wmiobject", nullptr } } },

        { "backup-catalog-wipe", "脚本删除系统备份目录(勒索加密前的标准动作)", "T1490", false,
          { { "wbadmin delete catalog", nullptr } } },

        { "offsec-tool", "脚本内含公开攻击框架载荷(PowerSploit / Nishang 等)", "T1059.001", false,
          { { "invoke-shellcode", "invoke-dllinjection", "invoke-reflectivepeinjection", "invoke-psinject",
              "invoke-tokenmanipulation", "powersploit", "invoke-powershelltcp", "powercat", nullptr } } },

        { "shellcode-loader", "脚本申请可执行内存并在其中起线程(手搓 Shellcode 装载器)", "T1055", false,
          { { "virtualalloc", "virtualallocex", "ntallocatevirtualmemory", nullptr },
            { "createthread", "createremotethread", "queueuserapc", "ntcreatethreadex", "callwindowproc",
              "enumdesktopwindows", nullptr } } },

        // 只建连接、读写数据的网络脚本很常见;把远端发来的内容交给 IEX 执行才是反弹 Shell。
        { "reverse-shell", "脚本把远端发来的内容交给 IEX 执行(反弹 Shell)", "T1059.001", false,
          { { "net.sockets.tcpclient", nullptr }, { "getstream", nullptr },
            { "invoke-expression", "^iex ", "^iex(", "|iex", "| iex", nullptr } } },

        { "wmi-persistence", "脚本创建 WMI 事件订阅后门", "T1546.003", false,
          { { "__eventfilter", nullptr }, { "commandlineeventconsumer", "activescripteventconsumer", nullptr } } },

        { "script-dropper", "脚本下载文件、落地后运行(JScript / VBScript 投递器)", "T1105", false,
          { { "xmlhttp", "winhttprequest", nullptr }, { "adodb.stream", nullptr }, { "savetofile", nullptr },
            { ".run", "shellexecute", ".exec(", nullptr } } },
    };
    count = static_cast<int>(sizeof(kRules) / sizeof(kRules[0]));
    return kRules;
}

inline const QRegularExpression& base64PeRe() {
    static const QRegularExpression re(QStringLiteral("TV[qopr][A-Za-z0-9+/]{200,}"));
    return re;
}

}

inline AmsiBlockDecision amsiShouldBlock(const QString& content) {
    using namespace amsi_scan_policy;
    AmsiBlockDecision d;
    if (content.isEmpty())
        return d;

    const QString lower = content.toLower();
    int ruleCount = 0;
    const Rule* rs = rules(ruleCount);
    const bool stealth = CommandLineAnalyzer::hasHiddenWindowFlag(lower)
                         || CommandLineAnalyzer::hasEncodedCommandArgument(lower);
    for (int i = 0; i < ruleCount; ++i) {
        const Rule& r = rs[i];
        bool ok = true;
        for (int g = 0; ok && g < 4 && r.groups[g][0] != nullptr; ++g) {
            const bool lastGroup = g == 3 || r.groups[g + 1][0] == nullptr;
            bool groupHit = lastGroup && r.stealthCountsForLastGroup && stealth;
            for (int k = 0; !groupHit && k < 10 && r.groups[g][k] != nullptr; ++k)
                groupHit = containsKeyword(lower, r.groups[g][k]);
            ok = groupHit;
        }
        if (ok && r.sameCommand)
            ok = r.sameCommand().match(lower).hasMatch();
        if (ok && r.needsBase64Pe)
            ok = base64PeRe().match(content).hasMatch();
        if (!ok)
            continue;

        d.block = true;
        d.hits << QLatin1String(r.id);
        d.reasons << detail::u(r.reason);
        const QString t = QLatin1String(r.technique);
        if (!d.techniques.contains(t))
            d.techniques << t;
    }
    return d;
}

}
