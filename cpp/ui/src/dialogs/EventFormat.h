#pragma once
#include <QColor>
#include <QDir>
#include <QFileInfo>
#include <QHash>
#include <QRegularExpression>
#include <QString>
#include <QStringList>

#include "bulwark/engine/DefaultRules.h"
#include "bulwark/models/Enums.h"
#include "bulwark/models/SecurityEvent.h"
#include "design/Identity.h"
#include "design/Theme.h"

namespace evtfmt {

inline QString u(const char* s) { return QString::fromUtf8(s); }

struct Badge {
    QString text;
    QColor color;
};

inline QString typeLabel(bulwark::EventType t) {
    using E = bulwark::EventType;
    switch (t) {
    case E::ProcessCreate:    return u("进程创建");
    case E::ProcessTerminate: return u("结束进程");
    case E::RemoteThread:     return u("远程线程注入");
    case E::ImageLoad:        return u("模块 / 驱动加载");
    case E::FileWrite:        return u("文件写入");
    case E::FileDelete:       return u("文件删除");
    case E::RegistryWrite:    return u("注册表写入");
    case E::NetworkConnect:   return u("网络外联");
    case E::SelfProtect:      return u("自我保护");
    case E::DnsQuery:         return u("DNS 解析");
    case E::ScriptScan:       return u("脚本内容送检");
    case E::WmiSubscription:  return u("WMI 永久订阅");
    case E::FileRead: return u("敏感文件读取");
    case E::ThreadAccess: return u("线程访问");
    case E::DiskProtectionChange: return u("磁盘保护变更");
    case E::RemoteShareAccess: return u("远端共享访问");
    }
    return u("行为");
}

inline QString typeShort(bulwark::EventType t) {
    using E = bulwark::EventType;
    switch (t) {
    case E::RemoteThread: return u("远程线程");
    case E::ImageLoad:    return u("模块加载");
    default:              return typeLabel(t);
    }
}

inline QString typeGlyph(bulwark::EventType t) {
    using E = bulwark::EventType;
    switch (t) {
    case E::ProcessCreate:    return QStringLiteral("target");
    case E::ProcessTerminate: return QStringLiteral("power");
    case E::RemoteThread:     return QStringLiteral("zap");
    case E::ImageLoad:        return QStringLiteral("layers");
    case E::FileWrite:
    case E::FileDelete:       return QStringLiteral("file");
    case E::RegistryWrite:    return QStringLiteral("sliders");
    case E::NetworkConnect:
    case E::DnsQuery:         return QStringLiteral("globe");
    case E::SelfProtect:      return QStringLiteral("shield");
    case E::ScriptScan:       return QStringLiteral("terminal");
    case E::WmiSubscription:  return QStringLiteral("terminal");
    case E::FileRead: return QStringLiteral("file");
    case E::ThreadAccess: return QStringLiteral("terminal");
    case E::DiskProtectionChange: return QStringLiteral("shield");
    case E::RemoteShareAccess: return QStringLiteral("network");
    }
    return QStringLiteral("activity");
}

inline identity::Kind typeKind(bulwark::EventType t) {
    using E = bulwark::EventType;
    using K = identity::Kind;
    switch (t) {
    case E::ProcessCreate:
    case E::ProcessTerminate: return K::Process;
    case E::RemoteThread:     return K::Injection;
    case E::ImageLoad:        return K::Module;
    case E::FileWrite:
    case E::FileDelete:       return K::File;
    case E::RegistryWrite:
    case E::WmiSubscription:  return K::Registry;
    case E::FileRead: return K::File;
    case E::ThreadAccess: return K::Injection;
    case E::DiskProtectionChange: return K::File;
    case E::RemoteShareAccess: return K::Network;
    case E::NetworkConnect:
    case E::DnsQuery:         return K::Network;
    case E::SelfProtect:      break; // neutral, like processes: records never wear the brand jade
    case E::ScriptScan:       break;
    }
    return K::Neutral;
}

inline QColor typeColor(bulwark::EventType t) { return identity::kind(typeKind(t)); }

inline QString verb(bulwark::EventType t) {
    using E = bulwark::EventType;
    switch (t) {
    case E::ProcessCreate:    return u("尝试创建进程");
    case E::ProcessTerminate: return u("尝试结束进程");
    case E::RemoteThread:     return u("尝试注入远程线程");
    case E::ImageLoad:        return u("尝试加载模块 / 驱动");
    case E::FileWrite:        return u("尝试写入 / 修改文件");
    case E::FileDelete:       return u("尝试删除文件");
    case E::RegistryWrite:    return u("尝试写入注册表");
    case E::NetworkConnect:   return u("尝试网络外联");
    case E::SelfProtect:      return u("触发自我保护");
    case E::DnsQuery:         return u("发起 DNS 解析");
    case E::ScriptScan:       return u("尝试执行脚本内容");
    case E::WmiSubscription:  return u("注册 WMI 永久事件订阅");
    case E::FileRead: return u("读取敏感文件");
    case E::ThreadAccess: return u("请求修改线程上下文权限");
    case E::DiskProtectionChange: return u("修改磁盘加密或密钥保护器");
    case E::RemoteShareAccess: return u("请求访问网络共享");
    }
    return u("敏感行为");
}

inline QString action(bulwark::EventType t) {
    using E = bulwark::EventType;
    switch (t) {
    case E::ProcessCreate:    return u("启动进程");
    case E::ProcessTerminate: return u("结束进程");
    case E::RemoteThread:     return u("注入远程线程");
    case E::ImageLoad:        return u("加载模块");
    case E::FileWrite:        return u("写入文件");
    case E::FileDelete:       return u("删除文件");
    case E::RegistryWrite:    return u("写入注册表");
    case E::NetworkConnect:   return u("网络外联");
    case E::SelfProtect:      return u("触发自我保护");
    case E::DnsQuery:         return u("解析域名");
    case E::ScriptScan:       return u("执行脚本内容");
    case E::WmiSubscription:  return u("注册 WMI 永久事件订阅");
    case E::FileRead: return u("读取敏感文件");
    case E::ThreadAccess: return u("请求修改线程上下文权限");
    case E::DiskProtectionChange: return u("修改磁盘加密或密钥保护器");
    case E::RemoteShareAccess: return u("请求访问网络共享");
    }
    return u("敏感行为");
}

inline QString actorName(const QString& path) {
    const QString n = QFileInfo(path).fileName();
    return n.isEmpty() ? (path.isEmpty() ? u("未知程序") : path) : n;
}

inline bool isMemoryScanFinding(const bulwark::SecurityEvent& e) {
    return e.type == bulwark::EventType::RemoteThread
        && e.memoryInjection && e.userModeObserved
        && e.target.startsWith(QLatin1String("PID "), Qt::CaseInsensitive);
}

inline QString memoryScanFinding(const bulwark::SecurityEvent& e) {
    static const QString kSep = u(" · ");
    const QString t = e.target.trimmed();
    const int at = t.indexOf(kSep);
    return at > 0 ? t.mid(at + kSep.size()).trimmed() : QString();
}

inline QString memoryScanSubject(const bulwark::SecurityEvent& e) {
    const QString a = actorName(e.actorPath);
    return e.actorPid > 0 ? u("%1 (PID %2)").arg(a).arg(e.actorPid) : a;
}

inline QString typeLabel(const bulwark::SecurityEvent& e) {
    return isMemoryScanFinding(e) ? u("内存巡检") : typeLabel(e.type);
}
inline QString verb(const bulwark::SecurityEvent& e) {
    return isMemoryScanFinding(e) ? u("进程内存中存在可疑代码") : verb(e.type);
}
inline QString action(const bulwark::SecurityEvent& e) {
    return isMemoryScanFinding(e) ? u("内存巡检发现") : action(e.type);
}

inline QString actionWithTarget(const bulwark::SecurityEvent& e) {
    if (isMemoryScanFinding(e)) {
        const QString f = memoryScanFinding(e);
        return f.isEmpty() ? action(e) : action(e) + u(" · ") + f;
    }
    return action(e.type) + (e.target.trimmed().isEmpty() ? QString() : u(" → ") + e.target);
}

inline QString sentence(const bulwark::SecurityEvent& e, bool present) {
    using E = bulwark::EventType;
    const QString a = actorName(e.actorPath);
    const QString t = e.target.trimmed();
    const QString tense = present ? u("正试图") : QString();
    if (isMemoryScanFinding(e)) {
        const QString f = memoryScanFinding(e);
        return f.isEmpty() ? u("%1 的进程内存中发现可疑代码").arg(memoryScanSubject(e))
                           : u("%1 的进程内存中发现:%2").arg(memoryScanSubject(e), f);
    }
    if (t.isEmpty())
        return a + u(" ") + (present ? verb(e.type) : action(e.type));
    switch (e.type) {
    case E::RemoteThread:     return u("%1 %2向 %3 注入远程线程").arg(a, tense, t);
    case E::ProcessCreate:    return u("%1 %2启动 %3").arg(a, tense, t);
    case E::ProcessTerminate: return u("%1 %2结束 %3").arg(a, tense, t);
    case E::ImageLoad:        return u("%1 %2加载 %3").arg(a, tense, t);
    case E::FileWrite:        return u("%1 %2写入 %3").arg(a, tense, t);
    case E::FileDelete:       return u("%1 %2删除 %3").arg(a, tense, t);
    case E::RegistryWrite:    return u("%1 %2修改注册表 %3").arg(a, tense, t);
    case E::NetworkConnect:   return u("%1 %2连接 %3").arg(a, tense, t);
    case E::SelfProtect:      return u("%1 触发自我保护:%2").arg(a, t);
    case E::DnsQuery:         return u("%1 %2解析域名 %3").arg(a, present ? u("正在") : QString(), t);
    }
    return a + u(" ") + action(e.type);
}

inline QString arrowLine(const bulwark::SecurityEvent& e) {
    const QString a = actorName(e.actorPath);
    const QString t = e.target.trimmed();
    if (isMemoryScanFinding(e)) {
        const QString f = memoryScanFinding(e);
        return f.isEmpty() ? u("%1 %2").arg(memoryScanSubject(e), action(e))
                           : u("%1 · %2").arg(memoryScanSubject(e), f);
    }
    return t.isEmpty() ? a + u(" ") + action(e.type)
                       : u("%1 %2 → %3").arg(a, action(e.type), t);
}

inline QColor riskColor(int score) {
    if (score >= 80) return theme::danger();
    if (score >= 50) return theme::warning();
    return theme::success();
}

inline QString riskLevel(int score) {
    if (score >= 80) return u("高危");
    if (score >= 50) return u("可疑");
    return u("正常");
}

inline QColor glyphColor(const bulwark::SecurityEvent& e) {
    return e.riskScore >= 50 ? riskColor(e.riskScore) : typeColor(e.type);
}

inline Badge verdict(bulwark::VerdictAction a) {
    switch (a) {
    case bulwark::VerdictAction::Block: return {u("拦截"), theme::danger()};
    case bulwark::VerdictAction::Ask:   return {u("询问"), theme::warning()};
    case bulwark::VerdictAction::Allow: break;
    }
    return {u("放行"), theme::success()};
}

inline Badge disposition(bulwark::VerdictAction act, bulwark::EnforcementOutcome enf) {
    if (act != bulwark::VerdictAction::Block) {
        if (act == bulwark::VerdictAction::Ask)
            return {u("已询问"), theme::warning()};
        return {u("已放行"), theme::success()};
    }
    using EO = bulwark::EnforcementOutcome;
    switch (enf) {
    case EO::KernelBlocked:     return {u("已拦截"), theme::danger()};
    case EO::Terminated:        return {u("已结束进程"), theme::danger()};
    case EO::ModuleBlacklisted: return {u("已禁止加载"), theme::danger()};
    case EO::ExecDenied:        return {u("已禁止启动"), theme::danger()};
    case EO::ActorAlreadyGone:  return {u("主体已结束"), theme::danger()};
    case EO::WriteUndone:       return {u("已撤销写入"), theme::danger()};
    case EO::PayloadQuarantined: return {u("已隔离载荷"), theme::danger()};
    case EO::AlertedOnly:       return {u("仅告警·未拦截"), theme::warning()};
    case EO::Failed:            return {u("拦截失败"), theme::warning()};
    case EO::NotApplicable:     break;
    }
    return {u("已拦截"), theme::danger()};
}

inline QString verdictSourceLabel(bulwark::VerdictSource s) {
    using S = bulwark::VerdictSource;
    switch (s) {
    case S::Rule:          return u("命中规则");
    case S::Heuristic:     return u("启发式评分");
    case S::TrustedSigner: return u("受信签名放行");
    case S::UserPrompt:    return u("用户裁决");
    case S::Timeout:       return u("询问超时,按默认处理");
    case S::DefaultPolicy: return u("默认策略");
    case S::Ai:            return u("大模型裁决");
    }
    return u("—");
}

inline bool isRealBlock(bulwark::VerdictAction act, bulwark::EnforcementOutcome enf) {
    using EO = bulwark::EnforcementOutcome;
    return act == bulwark::VerdictAction::Block
        && (enf == EO::KernelBlocked || enf == EO::Terminated || enf == EO::ModuleBlacklisted
            || enf == EO::ExecDenied || enf == EO::WriteUndone || enf == EO::PayloadQuarantined
            || enf == EO::NotApplicable);
}

inline bool needsManualAction(bulwark::EnforcementOutcome enf) {
    using EO = bulwark::EnforcementOutcome;
    return enf == EO::AlertedOnly || enf == EO::Failed;
}

inline QString dispositionDetail(bulwark::VerdictAction act, bulwark::EnforcementOutcome enf) {
    if (act == bulwark::VerdictAction::Ask)
        return u("该行为交由用户裁决。");
    if (act != bulwark::VerdictAction::Block)
        return u("该行为已放行。");
    using EO = bulwark::EnforcementOutcome;
    switch (enf) {
    case EO::KernelBlocked:     return u("内核在操作发生前将其阻断,动作没有发生。");
    case EO::Terminated:        return u("动作已经发生,发起它的进程树已被结束。");
    case EO::ModuleBlacklisted: return u("这次加载没能拦下;该模块已加入内核禁止加载名单,下次加载会在发生前被阻断。");
    case EO::ExecDenied:        return u("这次没有可结束的进程(它已经退出);该程序已被禁止启动,再次双击会直接失败。撤销入口:拦截通知上的『撤销拦截 · 信任 1 小时』,或在界面把它加白(两者都会解除禁止启动)。");
    case EO::ActorAlreadyGone:  return u("这条是发起进程退出【之前】排队的动作;那个进程已在本次之前被结束,不需要再处置。");
    case EO::WriteUndone:       return u("动作已落地,但目标侧副作用已撤销(自启动值已删 / 启动文件夹载荷已隔离)。发起方常是系统工具,未结束进程。");
    case EO::PayloadQuarantined: return u("那个文件刚落地、还没运行,已被移入隔离区(可还原),它起不来了。写出它的程序多是系统工具或浏览器,未结束进程。");
    case EO::AlertedOnly:       return u("仅告警:内核无法前拦且没有可结束的进程,未做任何实际阻断,需要人工关注。");
    case EO::Failed:            return u("尝试处置但没有成功(进程已退出、受保护或为关键进程)。");
    case EO::NotApplicable:     break;
    }
    return u("裁决为拦截;这条历史记录没有保存实际处置结果。");
}

inline QString evidenceKindLabel(bulwark::EvidenceKind k) {
    using K = bulwark::EvidenceKind;
    switch (k) {
    case K::Info:          return u("上下文");
    case K::SoftSignal:    return u("软信号");
    case K::HardIndicator: return u("硬指标");
    case K::Corroboration: return u("互证");
    case K::Trust:         return u("信任");
    case K::Rule:          return u("规则");
    case K::Decision:      return u("裁决");
    }
    return u("证据");
}

inline QColor evidenceKindColor(bulwark::EvidenceKind k) {
    using K = bulwark::EvidenceKind;
    switch (k) {
    case K::HardIndicator: return theme::danger();
    case K::SoftSignal:    return theme::warning();
    case K::Corroboration: return theme::warning();
    case K::Trust:         return theme::success();
    case K::Rule:          return theme::info();
    case K::Decision:      return theme::accent();
    case K::Info:          return theme::textMuted();
    }
    return theme::textMuted();
}

struct Threat {
    QString category;
    QString name;
    QString basis;

    bool isEmpty() const { return category.isEmpty(); }
    QString text() const { return name.isEmpty() ? category : category + u(" · ") + name; }
};

namespace threat_detail {

inline QString threatNameCategory(const QString& label, bool malicious) {
    const QString l = label.toLower();
    static const QRegularExpression sep(QStringLiteral("[^a-z0-9]+"));
    const QStringList tokens = l.split(sep, Qt::SkipEmptyParts);
    const auto has = [&l](const char* s) { return l.contains(QLatin1String(s)); };
    const auto zh = [&label](const char* s) { return label.contains(u(s)); };
    const auto token = [&tokens](const char* s) { return tokens.contains(QLatin1String(s)); };
    const auto ratFamily = [&tokens] {
        for (const QString& t : tokens)
            if (t == QLatin1String("rat") || (t.size() > 4 && t.endsWith(QLatin1String("rat"))))
                return true;
        return false;
    };
    if (has("not-a-virus") || token("pua") || token("pup") || has("riskware") || has("risktool")
        || has("grayware") || has("unwanted"))
        return u("风险软件");
    if (has("ransom") || has("lockbit") || has("wannacry") || zh("勒索"))
        return u("勒索软件");
    if (has("miner") || has("xmrig") || zh("挖矿"))
        return u("挖矿木马");
    if (has("banker") || has("banking"))
        return u("网银木马");
    if (has("stealer") || has("spy") || has("keylog") || token("pws") || zh("窃密") || zh("盗号"))
        return u("窃密木马");
    if (has("backdoor") || ratFamily() || has("cobalt") || zh("远控") || zh("后门"))
        return u("远控木马");
    if (has("rootkit") || has("bootkit"))
        return u("Rootkit");
    if (has("worm") || zh("蠕虫"))
        return u("蠕虫");
    if (has("exploit") || zh("漏洞"))
        return u("漏洞利用");
    if (has("downloader"))
        return u("木马下载器");
    if (has("dropper"))
        return u("木马释放器");
    if (has("loader"))
        return u("木马加载器");
    if (has("adware") || zh("广告"))
        return u("广告软件");
    if (has("hacktool") || token("hktl") || zh("黑客工具"))
        return u("黑客工具");
    if (has("phish") || zh("钓鱼"))
        return u("钓鱼");
    if (token("bot") || has("botnet") || zh("僵尸"))
        return u("僵尸网络");
    if (has("webshell"))
        return u("WebShell");
    if (token("virus") || has("infector") || has("virut") || has("sality") || zh("感染"))
        return u("感染型病毒");
    if (has("trojan") || token("troj") || token("trj") || zh("木马"))
        return u("木马");
    return malicious ? u("恶意程序") : u("可疑程序");
}

inline QString techniqueCategory(const QString& id) {
    static const QHash<QString, QString> table = [] {
        QHash<QString, QString> t;
        const auto add = [&t](std::initializer_list<const char*> ids, const char* category) {
            for (const char* tech : ids)
                t.insert(QString::fromLatin1(tech), u(category));
        };
        add({"T1003", "T1555", "T1552", "T1558"}, "凭据窃取");
        add({"T1055"}, "进程注入");
        add({"T1574"}, "DLL 侧载");
        add({"T1036"}, "伪装");
        add({"T1564"}, "隐藏载荷");
        add({"T1027", "T1140", "T1620"}, "混淆载荷");
        add({"T1105", "T1197"}, "下载执行");
        add({"T1059"}, "恶意脚本");
        add({"T1486"}, "勒索加密");
        add({"T1490", "T1485", "T1565"}, "勒索与破坏");
        add({"T1547", "T1546", "T1543", "T1053", "T1136"}, "持久化");
        add({"T1562", "T1070", "T1553", "T1112"}, "防御规避");
        add({"T1548", "T1068"}, "权限提升");
        add({"T1218", "T1127", "T1202", "T1216", "T1047"}, "执行与 LOLBin");
        add({"T1566", "T1204"}, "钓鱼诱导");
        add({"T1071", "T1568", "T1573", "T1090"}, "C2 通信");
        add({"T1219", "T1563"}, "远程控制");
        add({"T1021", "T1570"}, "横向移动");
        return t;
    }();
    return table.value(id.trimmed().left(5).toUpper());
}

inline QString techniqueOf(const bulwark::Evidence& ev) {
    if (!ev.technique.isEmpty())
        return ev.technique;
    static const QRegularExpression re(QStringLiteral("T\\d{4}(?:\\.\\d{3})?"));
    const QRegularExpressionMatch m = re.match(ev.description);
    return m.hasMatch() ? m.captured(0) : QString();
}

inline bool isMetaEvidence(const bulwark::Evidence& ev) {
    return ev.source == QLatin1String("KillChainAnalyzer");
}

inline QString evidenceCategory(const bulwark::Evidence& ev) {
    const QString& d = ev.description;
    const auto is = [&ev](const char* name) { return ev.source == QLatin1String(name); };
    if (is("RansomwareBehaviorMonitor"))                return u("勒索加密");
    if (is("DownloaderBehaviorMonitor"))                return u("木马下载器");
    if (is("BeaconDetector") || is("DgaDomainAnalyzer")) return u("C2 通信");
    if (is("EgressRateMonitor"))                        return u("异常外联");
    if (is("RemoteControlAnalyzer"))                    return u("远程控制");
    if (is("CommandObfuscationAnalyzer"))               return u("混淆载荷");
    if (is("ScriptAnalyzer") || is("ScriptFileAnalyzer")) return u("恶意脚本");
    if (is("PersistenceAnalyzer"))                      return u("持久化");
    if (is("KillChainAnalyzer"))                        return u("攻击链");
    if (is("LaunchingParent"))                          return u("恶意发起方");
    if (is("ThreatDetector")) {
        if (d.contains(u("白加黑")) || d.contains(u("签名壳")))   return u("白加黑侧载");
        if (d.contains(u("证书")) || d.contains(u("签名校验失败"))) return u("签名异常");
        if (d.contains(u("膨胀")))                               return u("文件膨胀规避");
        if (d.contains(u("宏病毒")) || d.contains(u("钓鱼")))     return u("钓鱼诱导");
        if (d.contains(u("隐藏窗口")))                            return u("隐蔽执行");
    }
    const QString byTechnique = techniqueCategory(techniqueOf(ev));
    if (!byTechnique.isEmpty())
        return byTechnique;
    if (is("InjectionAnalyzer"))        return u("进程注入");
    if (is("CredentialAccessAnalyzer")) return u("凭据窃取");
    if (is("DefenseEvasionAnalyzer"))   return u("防御规避");
    if (is("LolbinAnalyzer"))           return u("执行与 LOLBin");
    if (is("ThreatDetector") && d.contains(u("脚本")))
        return u("恶意脚本");
    return QString();
}

inline bool ruleThreat(const bulwark::SecurityEvent& e, Threat* out) {
    const QString note = e.matchedRuleNote.trimmed();
    if (note.isEmpty())
        return false;
    const QString dot = u(" · ");
    const QString builtin = bulwark::engine::DefaultRules::builtInTag();
    if (note.startsWith(builtin)) {
        const QString rest = note.mid(builtin.size()).trimmed();
        const int at = rest.indexOf(dot);
        if (at <= 0)
            return false;
        out->category = rest.left(at).trimmed();
        out->basis = rest.mid(at + dot.size()).trimmed();
        return !out->category.isEmpty();
    }
    const QString taint = u("[污点-释放物]");
    if (note.startsWith(taint)) {
        out->category = note.contains(u("询问")) ? u("可疑释放物") : u("恶意释放物");
        out->basis = note.mid(taint.size()).trimmed();
        return true;
    }
    const QString threatFox = u("[情报-ThreatFox]");
    if (note.startsWith(threatFox)) {
        QString family = note.mid(threatFox.size()).trimmed();
        const int confidence = family.lastIndexOf(QStringLiteral(" ("));
        if (confidence > 0)
            family = family.left(confidence).trimmed();
        out->name = family;
        out->category = threatNameCategory(family, true);
        out->basis = note.mid(threatFox.size()).trimmed();
        return true;
    }
    return false;
}

inline bool evidenceThreat(const bulwark::SecurityEvent& e, Threat* out) {
    for (int pass = 0; pass < 2; ++pass) {
        const bulwark::Evidence* best = nullptr;
        QString bestCategory;
        for (const bulwark::Evidence& ev : e.evidenceChain) {
            if (ev.kind != bulwark::EvidenceKind::HardIndicator)
                continue;
            if (isMetaEvidence(ev) != (pass == 1))
                continue;
            const QString c = evidenceCategory(ev);
            if (!c.isEmpty() && (!best || ev.scoreDelta > best->scoreDelta)) {
                best = &ev;
                bestCategory = c;
            }
        }
        if (best) {
            out->category = bestCategory;
            out->basis = best->description.trimmed();
            return true;
        }
    }
    return false;
}

inline bool hitRule(const bulwark::SecurityEvent& e) {
    if (!e.matchedRuleNote.trimmed().isEmpty())
        return true;
    for (const bulwark::Evidence& ev : e.evidenceChain)
        if (ev.kind == bulwark::EvidenceKind::Rule)
            return true;
    return false;
}

}

// 自我保护事件的来源是否为可信系统工具(任务管理器等微软签名/系统目录程序)。
// 这类操作是人为管理行为而非攻击:威胁定性要降级,拦截弹窗要大幅限频。
inline bool isSelfProtectBySystemTool(const bulwark::SecurityEvent& e) {
    return e.type == bulwark::EventType::SelfProtect
        && e.actorSigned
        && (e.actorPublisher.contains(QLatin1String("Microsoft"), Qt::CaseInsensitive)
            || e.actorPath.contains(QLatin1String("\\windows\\"), Qt::CaseInsensitive));
}

inline Threat threatOf(const bulwark::SecurityEvent& e) {
    using namespace threat_detail;
    Threat t;
    if (ruleThreat(e, &t))
        return t;
    if (evidenceThreat(e, &t))
        return t;
    if (e.memoryInjection) {
        t.category = u("进程注入");
        t.basis = e.detail.trimmed();
        return t;
    }
    if (e.type == bulwark::EventType::SelfProtect) {
        // 微软签名的系统工具(如任务管理器)操作本产品进程是人为/系统管理行为,
        // 不是攻击:降级为自我保护说明,不标"对抗安全软件"。
        if (isSelfProtectBySystemTool(e)) {
            t.category = u("自我保护(系统工具)");
            t.basis = u("%1 试图操作本产品进程,已被自我保护拦截。这不是攻击行为;"
                        "要退出本产品请用托盘菜单或界面关闭按钮。")
                          .arg(actorName(e.actorPath));
            return t;
        }
        t.category = u("对抗安全软件");
        t.basis = e.detail.trimmed();
        return t;
    }
    if (hitRule(e)) {
        t.category = u("自定义规则");
        t.basis = e.matchedRuleNote.trimmed().isEmpty() ? u("命中你设置的规则") : e.matchedRuleNote.trimmed();
    }
    return t;
}

inline QString strongestReason(const bulwark::SecurityEvent& e) {
    using K = bulwark::EvidenceKind;
    for (const K kind : {K::HardIndicator, K::Corroboration, K::SoftSignal}) {
        const bulwark::Evidence* best = nullptr;
        for (const bulwark::Evidence& ev : e.evidenceChain)
            if (ev.kind == kind && !ev.description.trimmed().isEmpty()
                && (!best || ev.scoreDelta > best->scoreDelta))
                best = &ev;
        if (best)
            return best->description.trimmed();
    }
    if (!e.matchedRuleNote.trimmed().isEmpty())
        return e.matchedRuleNote.trimmed();
    return e.riskReasons.isEmpty() ? QString() : e.riskReasons.first().trimmed();
}

inline QString originKindLabel(bulwark::ProcessOriginKind k) {
    using O = bulwark::ProcessOriginKind;
    switch (k) {
    case O::Interactive:    return u("交互式启动");
    case O::Service:        return u("服务");
    case O::ScheduledTask:  return u("计划任务");
    case O::WmiProvider:    return u("WMI 提供者");
    case O::LogonAutostart: return u("登录自启动");
    case O::SystemBoot:     return u("系统启动");
    case O::Unknown:        break;
    }
    return u("未知");
}

inline identity::Kind originKindOf(bulwark::ProcessOriginKind k) {
    using O = bulwark::ProcessOriginKind;
    using K = identity::Kind;
    switch (k) {
    case O::Interactive:    return K::Process;
    case O::Service:        return K::Service;
    case O::ScheduledTask:  return K::Task;
    case O::WmiProvider:    return K::Network;
    case O::LogonAutostart: return K::Registry;
    case O::SystemBoot:
    case O::Unknown:        break;
    }
    return K::Neutral;
}

inline QColor originColor(bulwark::ProcessOriginKind k) { return identity::kind(originKindOf(k)); }

inline QString originGlyph(bulwark::ProcessOriginKind k) {
    using O = bulwark::ProcessOriginKind;
    switch (k) {
    case O::Service:        return QStringLiteral("server");
    case O::ScheduledTask:  return QStringLiteral("clock");
    case O::WmiProvider:    return QStringLiteral("zap");
    case O::LogonAutostart: return QStringLiteral("power");
    case O::SystemBoot:     return QStringLiteral("cpu");
    case O::Interactive:
    case O::Unknown:        break;
    }
    return QStringLiteral("target");
}

inline QString nativePath(const QString& p) { return QDir::toNativeSeparators(p); }

}
