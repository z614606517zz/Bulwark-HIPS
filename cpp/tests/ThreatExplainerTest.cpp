// 离线告警解释的回归测试,钉住四件事:
//   1) 契约:meaning 与 advice 永远非空,界面会无条件渲染这张卡片。
//   2) 不编造:不得重复界面上已有的内容(riskReasons),也不得泄漏占位符。
//   3) 会区分:各类手法必须给出互不相同的解释,不能都塌回兜底文案。
//   4) 优先级:身份问题(证书被吊销 / 签名后被改)必须盖过手法类解释。

#include "bulwark/engine/ThreatDetector.h"
#include "bulwark/engine/ThreatExplainer.h"
#include "bulwark/models/Enums.h"
#include "bulwark/models/SecurityEvent.h"

#include <QCoreApplication>
#include <QSet>
#include <QString>
#include <QStringList>
#include <QTextStream>

using namespace bulwark;
using namespace bulwark::engine;
using Tone = ThreatExplanation::Tone;

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

SecurityEvent base()
{
    SecurityEvent e;
    e.type = EventType::ProcessCreate;
    e.actorPath = QStringLiteral("C:\\Users\\u\\AppData\\Local\\Temp\\x.exe");
    e.actorPid = 4242;
    return e;
}

// 1) 契约:任何事件形态都必须给出 meaning 与 advice

void testContract()
{
    QList<QPair<QString, SecurityEvent>> shapes;

    {   // 全默认事件 —— 最容易被漏掉的那一档
        SecurityEvent e;
        shapes << qMakePair(QStringLiteral("全默认事件"), e);
    }

    for (int t = 0; t <= int(EventType::ScriptScan); ++t) {
        SecurityEvent e = base();
        e.type = static_cast<EventType>(t);
        shapes << qMakePair(QStringLiteral("EventType=") + eventTypeToString(e.type), e);

        // 低分档会在手法链之后被「先问一声」那一支接走,按事件类型分的兜底文案
        // 因此只有在带硬指标时才可达 —— 必须单独扫一遍,否则那段 switch 无人覆盖。
        SecurityEvent hardOfType = e;
        hardOfType.hasThreatIndicator = true;
        hardOfType.riskScore = 90;
        shapes << qMakePair(QStringLiteral("EventType=") + eventTypeToString(e.type)
                                + QStringLiteral("+hard"),
                            hardOfType);
    }

    for (int k = 0; k <= int(ProcessOriginKind::SystemBoot); ++k) {
        SecurityEvent e = base();
        e.originKind = static_cast<ProcessOriginKind>(k);
        shapes << qMakePair(QStringLiteral("OriginKind=") + processOriginKindToString(e.originKind), e);
    }

    {
        SecurityEvent e = base();
        e.hasThreatIndicator = true;
        shapes << qMakePair(QStringLiteral("带硬指标"), e);
    }
    {
        SecurityEvent e = base();
        e.isInstaller = true;
        shapes << qMakePair(QStringLiteral("安装程序"), e);
    }
    {
        SecurityEvent e = base();
        e.actorSigned = true;
        e.actorPublisher = QStringLiteral("Some Vendor");
        shapes << qMakePair(QStringLiteral("已签名"), e);
    }

    for (const auto& [what, e] : shapes) {
        const ThreatExplanation x = ThreatExplainer::explain(e);
        expect(!x.meaning.trimmed().isEmpty(), QStringLiteral("meaning 不得为空 —— ") + what);
        expect(!x.advice.trimmed().isEmpty(), QStringLiteral("advice 不得为空 —— ") + what);
        expect(!x.isEmpty(), QStringLiteral("isEmpty() 必须为假 —— ") + what);

        // 占位符 / 未替换的格式符泄漏
        for (const QString& s : { x.meaning, x.recognize, x.advice }) {
            expect(!s.contains(QStringLiteral("%1")) && !s.contains(QStringLiteral("TODO"))
                       && !s.contains(QStringLiteral("()")),
                   QStringLiteral("文案不得含占位符残留 —— ") + what + QStringLiteral(" : ") + s);
        }
    }
}

// 2) 不得重复界面上已有的内容

void testNoDuplicationWithReasons()
{
    SecurityEvent e = base();
    e.hasThreatIndicator = true;
    e.techniques = QStringList{ QStringLiteral("T1003.001 LSASS 内存转储") };
    e.riskReasons = QStringList{
        QStringLiteral("对 LSASS 做内存转储(凭据窃取,T1003.001)"),
        QStringLiteral("未签名程序从可疑目录运行"),
        QStringLiteral("无可信数字签名"),
    };

    const ThreatExplanation x = ThreatExplainer::explain(e);
    const QString all = x.meaning + x.recognize + x.advice;
    for (const QString& r : e.riskReasons)
        expect(!all.contains(r),
               QStringLiteral("解释不得逐字重复 riskReasons(界面已单独列出):") + r);
}

// 3) 各类手法必须给出互不相同的解释

void testDiscriminates()
{
    struct Shape { QString what; SecurityEvent e; };
    QList<Shape> shapes;

    auto withTech = [](const char* tech) {
        SecurityEvent e = base();
        e.hasThreatIndicator = true;
        e.techniques = QStringList{ QString::fromUtf8(tech) };
        return e;
    };

    shapes << Shape{ QStringLiteral("签名被篡改"), [] {
        SecurityEvent e = base(); e.actorSigned = true; e.signatureTampered = true; return e; }() };
    shapes << Shape{ QStringLiteral("证书被吊销"), [] {
        SecurityEvent e = base(); e.actorSigned = true; e.certRevoked = true; return e; }() };
    shapes << Shape{ QStringLiteral("过期后签名"), [] {
        SecurityEvent e = base(); e.actorSigned = true; e.signedAfterCertExpiry = true; return e; }() };
    shapes << Shape{ QStringLiteral("勒索"), [] {
        SecurityEvent e = base(); e.type = EventType::FileWrite;
        e.ransomwareContainmentRequired = true; return e; }() };
    shapes << Shape{ QStringLiteral("删卷影"), withTech("T1490 抑制系统恢复(删卷影/备份)") };
    shapes << Shape{ QStringLiteral("凭据转储"), withTech("T1003.001 LSASS 内存转储") };
    shapes << Shape{ QStringLiteral("浏览器凭据"), withTech("T1555.003 浏览器存储凭据") };
    shapes << Shape{ QStringLiteral("注入"), [] {
        SecurityEvent e = base(); e.memoryInjection = true; return e; }() };
    shapes << Shape{ QStringLiteral("白加黑侧载"), [] {
        SecurityEvent e = base(); e.type = EventType::ImageLoad;
        e.sideloadedUnsignedModulePath = QStringLiteral("C:\\x\\version.dll"); return e; }() };
    shapes << Shape{ QStringLiteral("自我复制"), [] {
        SecurityEvent e = base(); e.type = EventType::FileWrite;
        e.selfCopyTargetPath = QStringLiteral("C:\\ProgramData\\a\\x.exe"); return e; }() };
    shapes << Shape{ QStringLiteral("下载执行"), withTech("T1105 工具传输/下载执行") };
    shapes << Shape{ QStringLiteral("持久化"), withTech("T1547.001 注册表 Run 键/启动文件夹") };
    shapes << Shape{ QStringLiteral("关防护"), withTech("T1562.001 削弱防御") };
    shapes << Shape{ QStringLiteral("脚本"), [] {
        SecurityEvent e = base(); e.type = EventType::ScriptScan; return e; }() };
    shapes << Shape{ QStringLiteral("混淆"), withTech("T1027 混淆文件或信息") };
    shapes << Shape{ QStringLiteral("LOLBin"), withTech("T1218.010 Regsvr32 代理执行(Squiblydoo)") };
    shapes << Shape{ QStringLiteral("伪装"), withTech("T1036.005 伪装为合法名称/位置") };
    shapes << Shape{ QStringLiteral("PowerShell"), withTech("T1059.001 PowerShell") };
    shapes << Shape{ QStringLiteral("外联"), withTech("T1071 应用层协议外联") };

    QSet<QString> seen;
    for (const Shape& s : shapes) {
        const ThreatExplanation x = ThreatExplainer::explain(s.e);
        expect(!seen.contains(x.meaning),
               QStringLiteral("解释必须能区分手法,这一档塌回了别处的文案 —— ") + s.what);
        seen.insert(x.meaning);
    }
    expect(seen.size() == shapes.size(),
           QStringLiteral("应有 ") + QString::number(shapes.size())
               + QStringLiteral(" 种不同解释,实际 ") + QString::number(seen.size()));

    // 兜底文案不得与任何具体手法的文案相同
    const ThreatExplanation fallback = ThreatExplainer::explain(base());
    expect(!seen.contains(fallback.meaning),
           QStringLiteral("兜底文案不得与具体手法文案重合"));
}

// 4) 优先级:身份问题盖过手法

void testPriority()
{
    SecurityEvent ident = base();
    ident.actorSigned = true;
    ident.certRevoked = true;
    ident.hasThreatIndicator = true;
    ident.techniques = QStringList{ QStringLiteral("T1059.001 PowerShell"),
                                    QStringLiteral("T1105 工具传输/下载执行") };

    SecurityEvent techOnly = base();
    techOnly.hasThreatIndicator = true;
    techOnly.techniques = ident.techniques;

    const ThreatExplanation a = ThreatExplainer::explain(ident);
    const ThreatExplanation b = ThreatExplainer::explain(techOnly);
    expect(a.meaning != b.meaning,
           QStringLiteral("证书被吊销必须盖过手法类解释"));
    expect(a.meaning.contains(QStringLiteral("吊销")),
           QStringLiteral("证书被吊销的解释应点明「吊销」,实际:") + a.meaning);

    // 勒索必须盖过它同时会带的「删卷影」「持久化」等手法:三者几乎总是同时出现,
    // 而用户最需要先知道的是"文件正在被加密,且不可逆"。
    SecurityEvent ransom = base();
    ransom.type = EventType::FileWrite;
    ransom.ransomwareContainmentRequired = true;
    ransom.hasThreatIndicator = true;
    ransom.techniques = QStringList{ QStringLiteral("T1490 抑制系统恢复(删卷影/备份)"),
                                     QStringLiteral("T1547.001 注册表 Run 键/启动文件夹") };

    SecurityEvent shadowOnly = base();
    shadowOnly.hasThreatIndicator = true;
    shadowOnly.techniques = QStringList{ QStringLiteral("T1490 抑制系统恢复(删卷影/备份)") };

    const ThreatExplanation r = ThreatExplainer::explain(ransom);
    expect(r.meaning != ThreatExplainer::explain(shadowOnly).meaning,
           QStringLiteral("勒索必须盖过删卷影"));
    expect(r.meaning.contains(QStringLiteral("不可逆")),
           QStringLiteral("勒索的解释必须点明不可逆,实际:") + r.meaning);
}

// 5) 语气只跟证据强度挂钩

void testTone()
{
    SecurityEvent hard = base();
    hard.hasThreatIndicator = true;
    expect(ThreatExplainer::explain(hard).tone == Tone::Danger,
           QStringLiteral("有硬指标 -> Danger"));

    // 分档必须跟引擎自己的阈值一致,不另发明数字
    SecurityEvent susp = base();
    susp.riskScore = ThreatDetector::Suspicious;
    expect(ThreatExplainer::explain(susp).tone == Tone::Caution,
           QStringLiteral("达到可疑线但无硬指标 -> Caution"));

    SecurityEvent low = base();
    low.riskScore = ThreatDetector::Suspicious - 1;
    expect(ThreatExplainer::explain(low).tone == Tone::Info,
           QStringLiteral("低于可疑线且无硬指标 -> Info"));

    SecurityEvent inst = base();
    inst.isInstaller = true;
    inst.riskScore = 70;   // 安装管控即使分数不低,只要没有硬指标就仍是「确认」而非「检出」
    expect(ThreatExplainer::explain(inst).tone == Tone::Info,
           QStringLiteral("安装程序且无硬指标 -> Info"));

    // 安装程序一旦带硬指标,不得再降成 Info
    SecurityEvent instHard = base();
    instHard.isInstaller = true;
    instHard.hasThreatIndicator = true;
    expect(ThreatExplainer::explain(instHard).tone == Tone::Danger,
           QStringLiteral("安装程序带硬指标 -> 仍是 Danger"));

    // 未签名这件事应在建议里被点出来
    SecurityEvent unsigned_ = base();
    unsigned_.actorSigned = false;
    expect(ThreatExplainer::explain(unsigned_).advice.contains(QStringLiteral("签名")),
           QStringLiteral("未签名应在建议里点明"));
}

// 6) 识别线索

void testRecognize()
{
    SecurityEvent office = base();
    office.parentPath = QStringLiteral("C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE");
    const QString o = ThreatExplainer::explain(office).recognize;
    expect(o.contains(QStringLiteral("winword.exe")) && o.contains(QStringLiteral("宏")),
           QStringLiteral("Office 父进程应给出宏/漏洞利用线索,实际:") + o);

    SecurityEvent browser = base();
    browser.parentPath = QStringLiteral("C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe");
    expect(ThreatExplainer::explain(browser).recognize.contains(QStringLiteral("chrome.exe")),
           QStringLiteral("浏览器父进程应给出下载线索"));

    SecurityEvent zip = base();
    zip.parentPath = QStringLiteral("C:\\Program Files\\7-Zip\\7zG.exe");
    expect(ThreatExplainer::explain(zip).recognize.contains(QStringLiteral("压缩包")),
           QStringLiteral("压缩包父进程应给出解压即运行线索"));

    SecurityEvent boot = base();
    boot.originKind = ProcessOriginKind::LogonAutostart;
    expect(ThreatExplainer::explain(boot).recognize.contains(QStringLiteral("登录")),
           QStringLiteral("登录自启动应说明与当前操作无关"));

    SecurityEvent firstSeen = base();
    firstSeen.isFirstSeen = true;
    expect(ThreatExplainer::explain(firstSeen).recognize.contains(QStringLiteral("首次")),
           QStringLiteral("本机首见应被点出"));

    // 推不出线索时必须留空,而不是硬凑一句
    SecurityEvent bare = base();
    bare.originKind = ProcessOriginKind::Interactive;
    expect(ThreatExplainer::explain(bare).recognize.isEmpty(),
           QStringLiteral("没有线索时 recognize 应为空,实际:")
               + ThreatExplainer::explain(bare).recognize);
}

// 7) 解释不得与本产品自己的裁决打架
// 例如未签名、从 Temp 运行、本机首见、风险分 40 的程序裁决是 Allow,解释卡片就不能写「建议拦截」。

void testAdviceNeverContradictsVerdict()
{
    QList<QPair<QString, SecurityEvent>> benign;
    for (int t = 0; t <= int(EventType::ScriptScan); ++t) {
        SecurityEvent e = base();
        e.type = static_cast<EventType>(t);
        e.riskScore = ThreatDetector::Suspicious - 10;   // 引擎在这一档默认放行
        const QString tag = eventTypeToString(e.type);
        benign << qMakePair(tag, e);

        SecurityEvent inst = e;
        inst.isInstaller = true;
        benign << qMakePair(tag + QStringLiteral("+installer"), inst);

        SecurityEvent sig = e;
        sig.actorSigned = true;
        sig.actorPublisher = QStringLiteral("Example Software GmbH");
        benign << qMakePair(tag + QStringLiteral("+signed"), sig);

        SecurityEvent seen = e;
        seen.isFirstSeen = true;
        benign << qMakePair(tag + QStringLiteral("+firstSeen"), seen);
    }

    for (const auto& [tag, e] : benign) {
        const ThreatExplanation x = ThreatExplainer::explain(e);
        expect(x.tone == Tone::Info,
               QStringLiteral("低于可疑线且无硬指标必须是 Info —— ") + tag);
        expect(!x.advice.contains(QStringLiteral("建议拦截")),
               QStringLiteral("默认放行档不得劝用户拦截 —— ") + tag
                   + QStringLiteral(" : ") + x.advice);
        expect(!x.meaning.contains(QStringLiteral("达到了提示阈值")),
               QStringLiteral("默认放行档不得说成「达到提示阈值」 —— ") + tag);
    }

    // 反向:带硬指标时必须明确给出拦截建议,不能一味和气。
    SecurityEvent hard = base();
    hard.hasThreatIndicator = true;
    hard.riskScore = 100;
    expect(ThreatExplainer::explain(hard).advice.contains(QStringLiteral("建议拦截")),
           QStringLiteral("有硬指标时必须明确建议拦截"));

    // 中间档也必须给出倾向,不能只描述不表态。
    SecurityEvent susp = base();
    susp.riskScore = ThreatDetector::Suspicious + 10;
    expect(ThreatExplainer::explain(susp).advice.contains(QStringLiteral("先拦")),
           QStringLiteral("达到可疑线时应建议先拦"));

    // Danger 档不得再加「拿不准」这类对冲:证据已经够硬,含糊只会让人犹豫。
    expect(!ThreatExplainer::explain(hard).advice.contains(QStringLiteral("拿不准")),
           QStringLiteral("Danger 档不应出现对冲措辞"));
}

// 6b) 篇幅:弹窗只给几十秒,文案必须一眼看完
// 上限留了余量,触发它说明文案确实写长了。

void testLength()
{
    struct Shape { QString what; SecurityEvent e; };
    QList<Shape> shapes;

    auto withTech = [](const char* tech) {
        SecurityEvent e = base();
        e.hasThreatIndicator = true;
        e.riskScore = 100;
        e.techniques = QStringList{ QString::fromUtf8(tech) };
        return e;
    };

    shapes << Shape{ QStringLiteral("凭据转储"), withTech("T1003.001 LSASS 内存转储") };
    shapes << Shape{ QStringLiteral("注入"), withTech("T1055 进程注入") };
    shapes << Shape{ QStringLiteral("下载执行"), withTech("T1105 工具传输/下载执行") };
    shapes << Shape{ QStringLiteral("LOLBin"), withTech("T1218.010 Regsvr32 代理执行") };
    shapes << Shape{ QStringLiteral("混淆"), withTech("T1027 混淆文件或信息") };
    shapes << Shape{ QStringLiteral("持久化"), withTech("T1547.001 注册表 Run 键") };
    shapes << Shape{ QStringLiteral("证书吊销"), [] {
        SecurityEvent e = base(); e.actorSigned = true; e.certRevoked = true;
        e.hasThreatIndicator = true; return e; }() };
    shapes << Shape{ QStringLiteral("勒索"), [] {
        SecurityEvent e = base(); e.type = EventType::FileWrite;
        e.ransomwareContainmentRequired = true; e.hasThreatIndicator = true; return e; }() };
    shapes << Shape{ QStringLiteral("可疑档"), [] {
        SecurityEvent e = base(); e.riskScore = ThreatDetector::Suspicious + 10; return e; }() };
    shapes << Shape{ QStringLiteral("安装程序"), [] {
        SecurityEvent e = base(); e.isInstaller = true; e.actorSigned = true;
        e.isFirstSeen = true;
        e.parentPath = QStringLiteral("C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe");
        return e; }() };
    shapes << Shape{ QStringLiteral("低风险档"), base() };

    constexpr int kMaxMeaning = 140;
    constexpr int kMaxRecognize = 170;
    constexpr int kMaxAdvice = 110;

    for (const Shape& s : shapes) {
        const ThreatExplanation x = ThreatExplainer::explain(s.e);
        expect(x.meaning.size() <= kMaxMeaning,
               QStringLiteral("meaning 过长(") + QString::number(x.meaning.size())
                   + QStringLiteral(" > ") + QString::number(kMaxMeaning)
                   + QStringLiteral(")—— ") + s.what);
        expect(x.recognize.size() <= kMaxRecognize,
               QStringLiteral("recognize 过长(") + QString::number(x.recognize.size())
                   + QStringLiteral(" > ") + QString::number(kMaxRecognize)
                   + QStringLiteral(")—— ") + s.what);
        expect(x.advice.size() <= kMaxAdvice,
               QStringLiteral("advice 过长(") + QString::number(x.advice.size())
                   + QStringLiteral(" > ") + QString::number(kMaxAdvice)
                   + QStringLiteral(")—— ") + s.what);
    }
}

// 8) 中文排版:句子之间不得留半角空格
// 用 join(' ') 拼接自带句号的中文句子,会在「。」后面留出一道豁口。

void testTypography()
{
    QList<SecurityEvent> shapes;
    {
        SecurityEvent e = base();
        e.parentPath = QStringLiteral("C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE");
        e.isFirstSeen = true;
        e.hasThreatIndicator = true;
        e.techniques = QStringList{ QStringLiteral("T1003.001 LSASS 内存转储") };
        shapes << e;
    }
    {
        SecurityEvent e = base();
        e.isInstaller = true;
        e.isFirstSeen = true;
        e.parentPath = QStringLiteral("C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe");
        shapes << e;
    }
    {
        SecurityEvent e = base();
        e.originKind = ProcessOriginKind::LogonAutostart;
        e.isFirstSeen = true;
        e.actorSigned = false;
        e.riskScore = 60;
        shapes << e;
    }

    for (const SecurityEvent& e : shapes) {
        const ThreatExplanation x = ThreatExplainer::explain(e);
        for (const QString& s : { x.meaning, x.recognize, x.advice }) {
            expect(!s.contains(QStringLiteral("。 ")),
                   QStringLiteral("句号后不得有半角空格:") + s);
            expect(!s.contains(QStringLiteral("， ")) && !s.contains(QStringLiteral(", ")),
                   QStringLiteral("逗号后不得有半角空格:") + s);
            expect(!s.startsWith(QLatin1Char(' ')) && !s.endsWith(QLatin1Char(' ')),
                   QStringLiteral("首尾不得有空格:") + s);
        }
    }
}

// 9) 确定性

void testDeterministic()
{
    SecurityEvent e = base();
    e.hasThreatIndicator = true;
    e.techniques = QStringList{ QStringLiteral("T1055 进程注入") };
    e.parentPath = QStringLiteral("C:\\Windows\\explorer.exe");
    e.isFirstSeen = true;

    const ThreatExplanation a = ThreatExplainer::explain(e);
    for (int i = 0; i < 5; ++i) {
        const ThreatExplanation b = ThreatExplainer::explain(e);
        expect(a.meaning == b.meaning && a.recognize == b.recognize
                   && a.advice == b.advice && a.tone == b.tone,
               QStringLiteral("同一事件必须得到同一解释"));
    }
}

}

int main(int argc, char** argv)
{
    QCoreApplication app(argc, argv);

    testContract();
    testNoDuplicationWithReasons();
    testDiscriminates();
    testPriority();
    testTone();
    testRecognize();
    testAdviceNeverContradictsVerdict();
    testLength();
    testTypography();
    testDeterministic();

    out() << (g_failed == 0 ? "OK  " : "FAILED  ") << g_checked << " 项断言,"
          << g_failed << " 项失败\n";
    out().flush();
    return g_failed == 0 ? 0 : 1;
}
