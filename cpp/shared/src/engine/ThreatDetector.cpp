#include "bulwark/engine/ThreatDetector.h"
#include "bulwark/engine/CommandLineAnalyzer.h"
#include "bulwark/engine/EngineCommon.h"
#include "bulwark/engine/SystemPaths.h"
#include "bulwark/engine/TrustPolicy.h"
#include <QHash>
#include <QSet>
#include <QStringList>

namespace bulwark::engine {

using detail::u;
using detail::fileNameLower;

namespace {

const QStringList& highSuspiciousDirs() {
    static const QStringList s = {
        "\\appdata\\local\\temp\\", "\\windows\\temp\\",
        "\\users\\public\\", "\\programdata\\", "\\$recycle.bin\\",
        "\\perflogs\\",
    };
    return s;
}

const QStringList& mediumSuspiciousDirs() {
    static const QStringList s = {
        "\\downloads\\", "\\appdata\\roaming\\",
        "\\desktop\\", "\\documents\\", "\\onedrive\\desktop\\", "\\onedrive\\documents\\",
    };
    return s;
}

// ProgramData 是正常软件的主要安装位置之一,运行位置的软信号不算它。
const QStringList& executionDropDirs() {
    static const QStringList s = {
        "\\appdata\\local\\temp\\", "\\windows\\temp\\", "\\users\\public\\", "\\$recycle.bin\\",
        "\\perflogs\\",
    };
    return s;
}

const QSet<QString>& legitWindowsSubdirNames() {
    static const QSet<QString> s = {
        "system32", "syswow64", "winsxs", "servicing", "microsoft.net", "assembly",
        "systemapps", "systemresources", "immersivecontrolpanel", "shellexperiences",
        "shellcomponents", "softwaredistribution", "fonts", "inf", "diagnostics",
        "debug", "security", "setup", "ime", "appcompat", "apppatch", "schemas",
        "globalization", "policydefinitions", "branding", "resources", "web", "media",
        "boot", "help", "cursors", "speech", "speech_onecore", "vss", "twain_32",
        "system", "l2schemas", "addins", "containers", "migration", "plugplay",
        "registration", "rescache", "servicestate", "tasks", "temp", "tracing",
        "waas", "winrm", "performance", "panther", "prefetch", "logs", "pchealth",
        "pla", "sysnative", "wbem", "windowspowershell", "downloaded program files",
        "offline web pages", "fixit", "diagtrack", "waasmedic",
    };
    return s;
}

const QHash<QString, QStringList>& systemProcessDirs() {
    static const QHash<QString, QStringList> m = {
        { "svchost.exe",       { "\\windows\\system32\\", "\\windows\\syswow64\\", "\\windows\\winsxs\\" } },
        { "lsass.exe",         { "\\windows\\system32\\" } },
        { "csrss.exe",         { "\\windows\\system32\\" } },
        { "services.exe",      { "\\windows\\system32\\" } },
        { "winlogon.exe",      { "\\windows\\system32\\" } },
        { "smss.exe",          { "\\windows\\system32\\" } },
        { "wininit.exe",       { "\\windows\\system32\\" } },
        { "dllhost.exe",       { "\\windows\\system32\\", "\\windows\\syswow64\\", "\\windows\\winsxs\\" } },
        { "taskhostw.exe",     { "\\windows\\system32\\", "\\windows\\winsxs\\" } },
        { "spoolsv.exe",       { "\\windows\\system32\\" } },
        { "conhost.exe",       { "\\windows\\system32\\" } },
        { "explorer.exe",      { "\\windows\\explorer.exe", "\\windows\\winsxs\\" } },
        { "dwm.exe",           { "\\windows\\system32\\" } },
        { "runtimebroker.exe", { "\\windows\\system32\\" } },
        { "sihost.exe",        { "\\windows\\system32\\" } },
        { "ctfmon.exe",        { "\\windows\\system32\\", "\\windows\\syswow64\\" } },
        { "userinit.exe",      { "\\windows\\system32\\" } },
        { "searchindexer.exe", { "\\windows\\system32\\" } },
        { "audiodg.exe",       { "\\windows\\system32\\" } },
    };
    return m;
}

const QSet<QString>& criticalTargets() {
    static const QSet<QString> s = {
        "lsass.exe", "csrss.exe", "winlogon.exe", "services.exe", "smss.exe", "wininit.exe",
    };
    return s;
}

const QSet<QString>& documentHosts() {
    static const QSet<QString> s = {
        "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "msaccess.exe", "mspub.exe",
        "onenote.exe", "visio.exe", "eqnedt32.exe", "wps.exe", "et.exe", "wpp.exe",
        "acrord32.exe", "acrobat.exe", "foxitreader.exe", "foxitpdfreader.exe",
    };
    return s;
}

const QSet<QString>& browserHosts() {
    static const QSet<QString> s = {
        "chrome.exe", "msedge.exe", "firefox.exe", "iexplore.exe", "brave.exe", "opera.exe", "vivaldi.exe",
    };
    return s;
}

const QSet<QString>& launchedByDocuments() {
    static const QSet<QString> s = {
        "powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe",
        "regsvr32.exe", "rundll32.exe", "certutil.exe", "bitsadmin.exe", "msbuild.exe", "schtasks.exe",
        "wmic.exe", "cmstp.exe", "installutil.exe",
    };
    return s;
}

const QSet<QString>& securityProcesses() {
    static const QSet<QString> s = {
        "msmpeng.exe", "nissrv.exe", "mssense.exe", "securityhealthservice.exe", "360tray.exe",
        "360sd.exe", "360rp.exe", "zhudongfangyu.exe", "hipsdaemon.exe", "hipstray.exe", "wsctrl.exe",
        "usysdiag.exe", "qqpcrtp.exe", "qqpctray.exe", "kxetray.exe", "kxescore.exe", "avp.exe",
        "ekrn.exe", "bdagent.exe", "vsserv.exe", "mcshield.exe", "ccsvchst.exe", "savservice.exe",
        "csfalconservice.exe", "sentinelagent.exe", "avastsvc.exe", "avgsvc.exe", "mbamservice.exe",
    };
    return s;
}

bool isFetchingWriter(const QString& actorName) {
    static const QSet<QString> s = {
        "powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe",
        "certutil.exe", "bitsadmin.exe", "curl.exe", "wget.exe",
    };
    return s.contains(actorName);
}

bool isLaunchableContent(const QString& pathLower) {
    static const char* exts[] = { ".exe", ".dll", ".scr", ".com", ".pif", ".ps1", ".vbs", ".vbe", ".js", ".jse",
                                  ".wsf", ".hta", ".bat", ".cmd" };
    for (const char* x : exts)
        if (pathLower.endsWith(QLatin1String(x)))
            return true;
    return false;
}

bool anyContains(const QStringList& needles, const QString& hay) {
    for (const QString& n : needles)
        if (hay.contains(n)) return true;
    return false;
}

QString normalizedLower(const QString& path) {
    QString p = path.toLower();
    p.replace(QLatin1Char('/'), QLatin1Char('\\'));
    return p;
}

bool isNonStandardWindowsSubdir(const QString& path) {
    if (path.isEmpty()) return false;
    const QString pathLower = normalizedLower(path);
    if (pathLower.size() < 4 || pathLower.at(1) != QLatin1Char(':')) return false;
    const QString rest = pathLower.mid(2);
    static const QString win = QStringLiteral("\\windows\\");
    if (!rest.startsWith(win)) return false;
    const qsizetype nextSlash = rest.indexOf(QLatin1Char('\\'), win.size());
    if (nextSlash < 0) return false;
    const QString firstSub = rest.mid(win.size(), nextSlash - win.size());
    return !legitWindowsSubdirNames().contains(firstSub);
}

QString deHomoglyph(const QString& s) {
    QString out;
    out.reserve(s.size());
    for (const QChar c : s) {
        switch (c.toLower().unicode()) {
            case u'0':   out.append(QLatin1Char('o')); break;
            case u'1':   out.append(QLatin1Char('l')); break;
            case 0x0430: out.append(QLatin1Char('a')); break;
            case 0x0435: out.append(QLatin1Char('e')); break;
            case 0x043e: out.append(QLatin1Char('o')); break;
            case 0x0440: out.append(QLatin1Char('p')); break;
            case 0x0441: out.append(QLatin1Char('c')); break;
            case 0x0445: out.append(QLatin1Char('x')); break;
            default:     out.append(c.toLower()); break;
        }
    }
    return out;
}

bool levenshteinAtMost1(const QString& a, const QString& b) {
    const qsizetype la = a.size(), lb = b.size();
    if (qAbs(la - lb) > 1 || a == b) return false;
    if (la == lb) {
        int diff = 0;
        for (qsizetype i = 0; i < la; ++i)
            if (a.at(i) != b.at(i) && ++diff > 1) return false;
        return diff == 1;
    }
    const QString& shorter = la < lb ? a : b;
    const QString& longer = la < lb ? b : a;
    qsizetype si = 0, li = 0;
    bool skipped = false;
    while (si < shorter.size() && li < longer.size()) {
        if (shorter.at(si) == longer.at(li)) { ++si; ++li; continue; }
        if (skipped) return false;
        skipped = true;
        ++li;
    }
    return true;
}

// strong:去空格或同形字后与系统进程名完全相同;否则为只差一个字符的近似名。
QString impersonatedSystemName(const QString& actorName, bool* strong) {
    *strong = false;
    if (!actorName.endsWith(QLatin1String(".exe")) || systemProcessDirs().contains(actorName))
        return QString();
    QString noSpace;
    for (const QChar c : actorName)
        if (!c.isSpace()) noSpace.append(c);
    const QString deHomo = deHomoglyph(noSpace);
    for (auto it = systemProcessDirs().constBegin(); it != systemProcessDirs().constEnd(); ++it) {
        if (noSpace == it.key() || deHomo == it.key()) {
            *strong = true;
            return it.key();
        }
    }
    const QString stem = actorName.chopped(4);
    if (stem.size() < 6)
        return QString();
    for (auto it = systemProcessDirs().constBegin(); it != systemProcessDirs().constEnd(); ++it)
        if (levenshteinAtMost1(stem, it.key().chopped(4)))
            return it.key();
    return QString();
}

bool isInExpectedSystemDir(const QString& actorName, const QString& actorPath) {
    const auto it = systemProcessDirs().constFind(actorName);
    if (it == systemProcessDirs().constEnd())
        return true;
    const QString rel = SystemPaths::systemVolumeRelative(normalizedLower(actorPath));
    for (const QString& d : it.value())
        if (rel.startsWith(d)) return true;
    return false;
}

bool hasDeepRandomDirChain(const QString& pathLower) {
    static const char* kDependencyDirs[] = {
        "\\node_modules\\", "\\_cacache\\", "\\.nuget\\", "\\packages\\", "\\.cargo\\", "\\gradle\\",
        "\\.m2\\", "\\winsxs\\", "\\pip\\", "\\steamapps\\", "\\overlay2\\", "\\.git\\",
    };
    for (const char* d : kDependencyDirs)
        if (pathLower.contains(QLatin1String(d))) return false;
    int run = 0, best = 0;
    for (const QString& seg : pathLower.split(QLatin1Char('\\'), Qt::SkipEmptyParts)) {
        bool letter = false, digit = false, other = false;
        for (const QChar c : seg) {
            if (c.isLetter()) letter = true;
            else if (c.isDigit()) digit = true;
            else other = true;
        }
        const bool randomLooking = seg.size() >= 6 && seg.size() <= 16 && letter && digit && !other;
        run = randomLooking ? run + 1 : 0;
        best = qMax(best, run);
    }
    return best >= 4;
}

// 版本资源里的原始文件名是被滥用的系统工具、实际文件名却不同:拷出来改名运行。
// 只对系统 / 安装目录以外的程序有原始文件名(富化阶段不读那两处)。
QString renamedSystemTool(const QString& originalName, const QString& actualName) {
    static const QHash<QString, QStringList> tools = {
        { "powershell.exe", { "powershell.exe" } }, { "pwsh.dll", { "pwsh.exe" } },
        { "cmd.exe", { "cmd.exe" } }, { "rundll32.exe", { "rundll32.exe" } },
        { "regsvr32.exe", { "regsvr32.exe" } }, { "mshta.exe", { "mshta.exe" } },
        { "wscript.exe", { "wscript.exe" } }, { "cscript.exe", { "cscript.exe" } },
        { "certutil.exe", { "certutil.exe" } }, { "bitsadmin.exe", { "bitsadmin.exe" } },
        { "msbuild.exe", { "msbuild.exe" } }, { "installutil.exe", { "installutil.exe" } },
        { "regasm.exe", { "regasm.exe" } }, { "regsvcs.exe", { "regsvcs.exe" } },
        { "wmic.exe", { "wmic.exe" } }, { "schtasks.exe", { "schtasks.exe" } }, { "sc.exe", { "sc.exe" } },
        { "reg.exe", { "reg.exe" } }, { "net.exe", { "net.exe" } }, { "net1.exe", { "net1.exe" } },
        { "vssadmin.exe", { "vssadmin.exe" } }, { "wbadmin.exe", { "wbadmin.exe" } },
        { "bcdedit.exe", { "bcdedit.exe" } }, { "cmstp.exe", { "cmstp.exe" } },
        { "odbcconf.exe", { "odbcconf.exe" } }, { "forfiles.exe", { "forfiles.exe" } },
        { "curl.exe", { "curl.exe" } }, { "psexec.c", { "psexec.exe", "psexec64.exe" } },
    };
    const auto it = tools.constFind(originalName);
    if (it == tools.constEnd() || it.value().contains(actualName))
        return QString();
    return it.value().first();
}

bool hasDoubleExtension(const QString& name) {
    static const char* docs[] = { ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".jpg", ".jpeg",
                                  ".png", ".txt", ".rtf", ".mp4" };
    static const char* exes[] = { ".exe", ".scr", ".com", ".pif", ".bat", ".cmd", ".vbs", ".js", ".hta" };
    for (const char* d : docs)
        for (const char* x : exes)
            if (name.endsWith(QString::fromLatin1(d) + QLatin1String(x)))
                return true;
    return false;
}

bool isAlternateDataStreamPath(const QString& path) {
    QString p = path;
    for (const char* pre : { "\\??\\", "\\\\?\\", "\\\\.\\" })
        if (p.startsWith(QLatin1String(pre))) { p = p.mid(4); break; }
    const qsizetype start = (p.size() > 1 && p.at(1) == QLatin1Char(':')) ? 2 : 0;
    const qsizetype colon = p.indexOf(QLatin1Char(':'), start);
    return colon >= 0 && colon + 1 < p.size();
}

// PowerShell 每次启动都会在 Temp 下写删 __PSScriptPolicyTest_*.ps1 探测执行策略。
bool isPowerShellPolicyProbe(const SecurityEvent& e) {
    if (e.type != EventType::FileWrite && e.type != EventType::FileDelete)
        return false;
    const QString actor = fileNameLower(e.actorPath);
    if (actor != QLatin1String("powershell.exe") && actor != QLatin1String("pwsh.exe"))
        return false;
    const QString target = normalizedLower(e.target);
    return target.contains(QLatin1String("\\temp\\"))
        && fileNameLower(target).startsWith(QLatin1String("__psscriptpolicytest"));
}

class Scorer {
public:
    explicit Scorer(SecurityEvent& e) : e_(e) {}

    void add(const QString& key, const QString& source, int delta, const QString& reason, bool hard,
             EvidenceSubject subject = EvidenceSubject::Actor) {
        if (seen_.contains(key))
            return;
        seen_.insert(key);
        score_ += delta;
        e_.addEvidence(source, hard ? EvidenceKind::HardIndicator : EvidenceKind::SoftSignal, reason, delta,
                       true, subject);
        if (hard)
            e_.hasThreatIndicator = true;
    }
    bool has(const QString& key) const { return seen_.contains(key); }
    int score() const { return score_; }

private:
    SecurityEvent& e_;
    QSet<QString> seen_;
    int score_ = 0;
};

const QString kDetector = QStringLiteral("ThreatDetector");

void identitySignals(const SecurityEvent& e, Scorer& sc) {
    const QString pathLower = normalizedLower(e.actorPath);
    const QString name = fileNameLower(pathLower);
    if (name.isEmpty())
        return;

    if (!e.actorSigned && anyContains(executionDropDirs(), pathLower))
        sc.add(QStringLiteral("drop-dir"), kDetector, 20, u("未签名程序从临时 / 公共目录运行(T1204.002)"), false);
    if (isNonStandardWindowsSubdir(pathLower))
        sc.add(QStringLiteral("odd-windir"), kDetector, e.actorSigned ? 10 : 30,
               u("可执行体位于 Windows 非标准子目录(疑似伪装系统组件,T1036.005)"), false);
    if (hasDeepRandomDirChain(pathLower))
        sc.add(QStringLiteral("random-dirs"), kDetector, e.actorSigned ? 10 : 20,
               u("可执行体位于连续多层随机命名目录中(分层投放,T1027)"), false);

    if (systemProcessDirs().contains(name) && !isInExpectedSystemDir(name, e.actorPath))
        sc.add(QStringLiteral("masquerade"), kDetector, e.actorSigned ? 60 : 80,
               u("系统进程名 ") + name + u(" 运行在非系统目录(进程伪装,T1036.005)"), true);
    bool strong = false;
    const QString imitated = impersonatedSystemName(name, &strong);
    if (!imitated.isEmpty())
        sc.add(QStringLiteral("lookalike"), kDetector, strong ? 60 : 25,
               u("程序名仿冒系统进程 ") + imitated + u("(同形字 / 空格 / 近似拼写,T1036.004)"), strong);
    if (hasDoubleExtension(name))
        sc.add(QStringLiteral("double-ext"), kDetector, 60, u("可执行文件使用文档双扩展名(T1036.007)"), true);
    const QString renamedFrom = renamedSystemTool(e.originalFileName, name);
    if (!renamedFrom.isEmpty())
        sc.add(QStringLiteral("renamed-tool"), kDetector, anyContains(highSuspiciousDirs(), pathLower) ? 80 : 60,
               u("系统工具 ") + renamedFrom + u(" 被改名为 ") + name + u(" 运行(规避按名检测,T1036.003)"), true);
    // 少数更新程序会在运行中把自己改名腾位置,投递目录以外只问。
    if (e.actorImageMissing)
        sc.add(QStringLiteral("image-missing"), kDetector, anyContains(executionDropDirs(), pathLower) ? 80 : 70,
               u("进程仍在运行,映像文件却已不在原路径(进程幽灵化 / 启动即自删,T1055.012/T1070.004)"), true);
    // 正常 CreateProcess 由系统自己以只读打开映像,这三种状态只出现在「先造映像节再建进程」的手法里。
    if (e.actorImageFlags & SecurityEvent::ImageDeletePending)
        sc.add(QStringLiteral("ghost-image"), kDetector, 80,
               u("新进程创建时映像文件已处于删除挂起状态(进程幽灵化,T1055.012)"), true);
    if (e.actorImageFlags & SecurityEvent::ImageTransacted)
        sc.add(QStringLiteral("txf-image"), kDetector, 80,
               u("新进程的映像来自未提交的 NTFS 事务(进程替身 Doppelgänging,T1055.013)"), true);
    if (e.actorImageFlags & SecurityEvent::ImageWritable)
        sc.add(QStringLiteral("writable-image"), kDetector, 70,
               u("新进程的映像文件被以写权限打开着(映射后改写文件 Herpaderping,T1055)"), true);
    if (e.actorPath.contains(QChar(0x202E)))
        sc.add(QStringLiteral("rlo"), kDetector, 60, u("文件名含反转字符 RLO(T1036.002)"), true);
    if (isAlternateDataStreamPath(e.actorPath))
        sc.add(QStringLiteral("ads"), kDetector, 50, u("从 NTFS 备用数据流运行(T1564.004)"), true);

    if (e.signatureTampered)
        sc.add(QStringLiteral("sig-tampered"), kDetector, 60, u("签名校验失败:文件在签名后被改动(T1036.001)"), true);
    else if (e.signatureMismatch)
        sc.add(QStringLiteral("sig-mismatch"), kDetector, 30, u("内嵌签名无效(证书链不受信或签名损坏)"), false);
    if (e.certRevoked)
        sc.add(QStringLiteral("cert-revoked"), kDetector, 80, u("签名证书已被吊销(T1553.002)"), true);
    if (e.signedAfterCertExpiry)
        sc.add(QStringLiteral("cert-expired"), kDetector, 80, u("在证书过期后才签名(盗用过期证书,T1553.002)"), true);
    const TrustDecision abused = TrustPolicy::isAbusedSigner(e);
    if (abused.ok)
        sc.add(QStringLiteral("cert-abused"), kDetector, 60, abused.reason, true);

    constexpr qint64 kBloatBytes = 100LL * 1024 * 1024;
    if (!e.actorSigned && e.actorFileSize >= kBloatBytes && anyContains(highSuspiciousDirs(), pathLower))
        sc.add(QStringLiteral("bloat"), kDetector, 20, u("投递目录中的超大未签名程序(文件膨胀规避扫描,T1027.001)"), false);
}

void chainSignals(const SecurityEvent& e, Scorer& sc) {
    const QString actor = fileNameLower(e.actorPath);
    const QString parent = fileNameLower(e.parentPath);
    // 富化阶段已把 parent* 换成真实创建者。安全软件、远控工具「以普通用户身份运行」也会指定父进程,
    // 装在 Program Files / Windows 下的创建者只记软信号;宏、浏览器漏洞、脚本、投递程序借此甩掉父子链才是要害。
    if (e.spoofedParentPid > 0) {
        const QString creatorLower = normalizedLower(e.parentPath);
        const bool attackHost = documentHosts().contains(parent) || browserHosts().contains(parent)
                                || CommandLineAnalyzer::isScriptHost(parent)
                                || anyContains(executionDropDirs(), creatorLower);
        const bool installed = creatorLower.contains(QLatin1String(":\\program files\\"))
                               || creatorLower.contains(QLatin1String(":\\program files (x86)\\"))
                               || creatorLower.contains(QLatin1String(":\\windows\\"));
        const int score = attackHost ? 80 : installed ? 30 : 60;
        const QString creatorName = parent.isEmpty() ? u("PID %1").arg(e.parentPid) : parent;
        const QString claimedName = e.spoofedParentPath.isEmpty() ? u("PID %1").arg(e.spoofedParentPid)
                                                                  : fileNameLower(e.spoofedParentPath);
        sc.add(QStringLiteral("ppid-spoof"), kDetector, score,
               u("父进程被伪造:实际由 ") + creatorName + u(" 创建,却挂在 ") + claimedName
                   + u(" 名下(甩掉父子关系,PPID 欺骗,T1134.004)"),
               score >= 60);
    }
    if (parent.isEmpty())
        return;
    if (documentHosts().contains(parent) && launchedByDocuments().contains(actor))
        sc.add(QStringLiteral("doc-child"), kDetector, 50,
               u("文档程序 ") + parent + u(" 派生 ") + actor + u("(宏病毒 / 钓鱼文档,T1204.002)"), true);
    if (browserHosts().contains(parent) && CommandLineAnalyzer::isScriptHost(actor)
        && !detail::isBrowserNativeMessagingLaunch(e.actorPath, e.parentPath, e.commandLine))
        sc.add(QStringLiteral("browser-child"), kDetector, 25,
               u("浏览器 ") + parent + u(" 直接派生 ") + actor + u("(下载即执行,T1189)"), false);
    const bool wshParent = parent == QLatin1String("wscript.exe") || parent == QLatin1String("cscript.exe")
                           || parent == QLatin1String("mshta.exe");
    if (wshParent && CommandLineAnalyzer::isScriptHost(actor))
        sc.add(QStringLiteral("wsh-chain"), kDetector, 20,
               u("Windows 脚本宿主拉起 ") + actor + u("(脚本投递链,T1059)"), false);
}

void commandLineSignals(const SecurityEvent& e, Scorer& sc) {
    const bool healthy = e.actorSigned && !e.signatureMismatch && !e.certRevoked && !e.signedAfterCertExpiry;
    if (e.commandLine.isEmpty() || detail::isContentInspectionProcess(e.actorPath, healthy))
        return;
    const QString actor = fileNameLower(e.actorPath);

    QStringList texts{ e.commandLine.toLower() };
    if (!e.normalizedCommandLine.isEmpty())
        texts << e.normalizedCommandLine.toLower();
    for (const QString& block : e.decodedCommandBlocks)
        texts << block.toLower();

    bool download = false, execute = false, hidden = false, encoded = false, ipUrl = false;
    for (int i = 0; i < texts.size(); ++i) {
        const bool decoded = i > 0 && i >= texts.size() - e.decodedCommandBlocks.size();
        for (const CommandLineAnalyzer::Hit& h : CommandLineAnalyzer::scan(texts.at(i), actor)) {
            const QString reason = decoded ? h.reason + u("(Base64 解码后)") : h.reason;
            sc.add(QLatin1String(h.id), h.source, h.score, reason, h.hard);
            download = download || qstrcmp(h.id, "download") == 0;
            execute = execute || qstrcmp(h.id, "dynamic-exec") == 0;
            hidden = hidden || qstrcmp(h.id, "ps-hidden") == 0;
            encoded = encoded || qstrcmp(h.id, "ps-encoded") == 0;
        }
        if (texts.at(i).contains(QLatin1String("start-process")) || texts.at(i).contains(QLatin1String("invoke-item")))
            execute = true;
        ipUrl = ipUrl || CommandLineAnalyzer::hasIpLiteralUrl(texts.at(i));
    }
    // Chocolatey / Scoop 的官方一行安装也是「下载即执行」,只问不拦;
    // 再叠加隐藏窗口、编码命令或直连公网 IP,正常安装脚本就没有理由这样写了。
    if (download && execute && (hidden || encoded || ipUrl))
        sc.add(QStringLiteral("download-exec"), kDetector, 80,
               u("隐藏 / 编码 / 直连公网 IP 的下载后立即执行(投递器形态,T1059.001/T1105)"), true);
    else if (download && execute)
        sc.add(QStringLiteral("download-exec"), kDetector, 25,
               u("下载后立即执行(投递器形态,T1059.001/T1105)"), true);
    if (hidden && encoded)
        sc.add(QStringLiteral("ps-hidden-encoded"), kDetector, 80,
               u("PowerShell 隐藏窗口运行编码命令(攻击框架默认启动形态,T1059.001/T1027)"), true);

    // 快捷方式属性窗口只显示参数的开头:中间塞上大段空白 / 换行,真正执行的命令就藏到显示范围之外。
    // 正常命令行里的缩进与空行远到不了这个长度。
    static const QSet<QString> paddedHosts = {
        "cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe",
        "regsvr32.exe", "msiexec.exe", "conhost.exe", "forfiles.exe",
    };
    if (paddedHosts.contains(actor)) {
        constexpr int kPaddingRun = 64;
        int run = 0, longest = 0;
        for (const QChar c : e.commandLine) {
            const ushort ch = c.unicode();
            if (ch == ' ' || (ch >= 0x09 && ch <= 0x0D))
                longest = qMax(longest, ++run);
            else
                run = 0;
        }
        if (longest >= kPaddingRun)
            sc.add(QStringLiteral("padded-args"), kDetector, 60,
                   u("命令行夹着 %1 个连续空白 / 换行,把真实参数挤出快捷方式属性窗口的显示范围(参数隐藏,T1027/T1204.002)")
                       .arg(longest),
                   true);
    }

    if (actor == QLatin1String("rundll32.exe")) {
        const QString args = e.commandLine.section(QStringLiteral("rundll32"), 1, 1,
                                                   QString::SectionCaseInsensitiveSeps).trimmed().toLower();
        if (args.isEmpty() || args == QLatin1String(".exe") || args == QLatin1String(".exe\""))
            sc.add(QStringLiteral("rundll32-bare"), QStringLiteral("InjectionAnalyzer"), 30,
                   u("无参数运行的 rundll32(常被用作注入宿主,T1218.011)"), false);
    }

    QStringList obfReasons;
    const int obf = CommandLineAnalyzer::obfuscationScore(e.commandLine, &obfReasons);
    if (obf > 0)
        sc.add(QStringLiteral("obfuscation"), QStringLiteral("CommandObfuscationAnalyzer"), obf,
               obfReasons.join(QStringLiteral("、")), false);
}

void eventSignals(const SecurityEvent& e, Scorer& sc) {
    const QString actor = fileNameLower(e.actorPath);
    const QString target = fileNameLower(e.target);
    switch (e.type) {
    case EventType::RemoteThread: {
        if (e.isMemoryCarrierFinding() || e.actorPath.compare(e.target, Qt::CaseInsensitive) == 0)
            break;
        const bool scripted = CommandLineAnalyzer::isScriptHost(actor) || actor == QLatin1String("rundll32.exe")
                              || actor == QLatin1String("regsvr32.exe");
        if (scripted)
            sc.add(QStringLiteral("rt-scripted"), QStringLiteral("InjectionAnalyzer"), 50,
                   actor + u(" 跨进程创建线程(脚本 / 代理宿主注入,T1055)"), true, EvidenceSubject::Target);
        else if (!e.actorSigned && criticalTargets().contains(target))
            sc.add(QStringLiteral("rt-critical"), QStringLiteral("InjectionAnalyzer"), 60,
                   u("未签名程序向系统关键进程 ") + target + u(" 注入线程(T1055)"), true, EvidenceSubject::Target);
        else if (!e.actorSigned)
            sc.add(QStringLiteral("rt-unsigned"), QStringLiteral("InjectionAnalyzer"), 35,
                   u("未签名程序跨进程创建线程(T1055)"), false, EvidenceSubject::Target);
        break;
    }
    case EventType::ImageLoad: {
        if (e.targetSigned)
            break;
        const QString moduleLower = normalizedLower(e.target);
        if (actor == QLatin1String("lsass.exe"))
            sc.add(QStringLiteral("lsass-module"), QStringLiteral("InjectionAnalyzer"), 60,
                   u("LSASS 加载未签名模块(SSP / 密码筛选器注入,T1547.005)"), true, EvidenceSubject::Target);
        else if (anyContains(highSuspiciousDirs(), moduleLower) && ThreatDetector::isSideloadProneModuleName(moduleLower))
            sc.add(QStringLiteral("sideload-system-name"), QStringLiteral("InjectionAnalyzer"), 50,
                   u("从投递目录加载未签名的系统同名模块 ") + target + u("(白加黑 / DLL 搜索顺序劫持,T1574.001)"),
                   true, EvidenceSubject::Target);
        else if (anyContains(highSuspiciousDirs(), moduleLower) && e.actorSigned)
            sc.add(QStringLiteral("dropdir-module"), QStringLiteral("InjectionAnalyzer"), 30,
                   u("签名程序加载投递目录中的未签名模块(T1574.002)"), false, EvidenceSubject::Target);
        break;
    }
    case EventType::ProcessTerminate:
        if (securityProcesses().contains(target) && actor != target)
            sc.add(QStringLiteral("kill-security"), QStringLiteral("DefenseEvasionAnalyzer"), e.actorSigned ? 20 : 50,
                   u("结束安全软件进程 ") + target + u("(T1562.001)"), !e.actorSigned, EvidenceSubject::Target);
        break;
    case EventType::FileWrite: {
        const QString targetLower = normalizedLower(e.target);
        if (!e.actorSigned && targetLower.contains(QLatin1String("\\start menu\\programs\\startup\\")))
            sc.add(QStringLiteral("startup-drop"), QStringLiteral("PersistenceAnalyzer"), 25,
                   u("未签名程序向启动文件夹写入文件(T1547.001)"), false, EvidenceSubject::Target);
        // 签名的 powershell / curl 出站连接在 ETW 源头就被丢弃,下载器的前半段只能从写入方命令行看出来。
        if (isFetchingWriter(actor) && isLaunchableContent(targetLower)
            && anyContains(highSuspiciousDirs(), targetLower)) {
            const QString cmd = e.commandLine.toLower();
            if (CommandLineAnalyzer::fetchesRemote(cmd)) {
                const bool stealth = CommandLineAnalyzer::hasHiddenWindowFlag(cmd)
                                     || CommandLineAnalyzer::hasEncodedCommandArgument(cmd)
                                     || CommandLineAnalyzer::hasIpLiteralUrl(cmd);
                if (stealth)
                    sc.add(QStringLiteral("fetch-drop"), QStringLiteral("DownloaderBehaviorMonitor"), 80,
                           actor + u(" 以隐藏 / 编码 / 直连公网 IP 的方式取远端,落地可执行内容 ") + e.target
                               + u("(木马下载器,T1105)"),
                           true, EvidenceSubject::Target);
                else
                    sc.add(QStringLiteral("fetch-drop"), QStringLiteral("DownloaderBehaviorMonitor"), 20,
                           actor + u(" 取远端后向投递目录落地可执行内容(下载本身不定性,T1105)"), false,
                           EvidenceSubject::Target);
            }
        }
        break;
    }
    default:
        break;
    }
}

void enrichedFacts(const SecurityEvent& e, Scorer& sc) {
    if (!e.tamperedModulePath.isEmpty())
        sc.add(QStringLiteral("sideload-tampered"), kDetector, 50,
               u("签名壳旁的模块签名校验失败(白加黑,模块被篡改):") + e.tamperedModulePath, true,
               EvidenceSubject::Target);
    if (!e.sideloadedUnsignedModulePath.isEmpty()) {
        const QString why = e.sideloadedUnsignedModuleWhy;
        const bool strong = why.contains(u("系统同名")) || why.contains(u("最近落地"));
        sc.add(QStringLiteral("sideload-unsigned"), kDetector, strong ? 45 : 25,
               u("白加黑侧载:签名壳旁放着未签名模块") + (why.isEmpty() ? QString() : u("(") + why + u(")"))
                   + u(":") + e.sideloadedUnsignedModulePath,
               strong, EvidenceSubject::Target);
    }
    if (e.scriptFileScore > 0 || e.scriptFileHardIndicator) {
        bool first = true;
        for (const QString& r : e.scriptFileReasons) {
            sc.add(u("script-file:") + r, QStringLiteral("ScriptFileAnalyzer"), first ? e.scriptFileScore : 0, r,
                   e.scriptFileHardIndicator, EvidenceSubject::Target);
            first = false;
        }
    }
}

}

void ThreatDetector::analyze(SecurityEvent& e) {
    e.hasThreatIndicator = false;
    e.riskScore = 0;
    if (isPowerShellPolicyProbe(e))
        return;

    Scorer sc(e);
    if (e.type != EventType::ImageLoad)
        identitySignals(e, sc);
    if (e.type == EventType::ProcessCreate) {
        chainSignals(e, sc);
        commandLineSignals(e, sc);
    }
    eventSignals(e, sc);
    enrichedFacts(e, sc);

    int score = sc.score();
    // 签名健康的程序只有弱信号时(更新器、安装器、浏览器内核本就会堆满软分),分数停在可疑线下;
    // 真恶意靠硬指标抬上去。
    const bool healthy = e.actorSigned && !e.signatureMismatch && !e.certRevoked && !e.signedAfterCertExpiry;
    if (healthy && !e.hasThreatIndicator && score >= Suspicious)
        score = Suspicious - 10;
    e.riskScore = qMin(100, score);
}

bool ThreatDetector::isSuspiciousDropDir(const QString& path) {
    if (path.isEmpty()) return false;
    const QString pathLower = normalizedLower(path);
    return anyContains(highSuspiciousDirs(), pathLower)
        || anyContains(mediumSuspiciousDirs(), pathLower)
        || isNonStandardWindowsSubdir(pathLower);
}

bool ThreatDetector::isSideloadProneModuleName(const QString& pathOrName) {
    static const QSet<QString> kNames = {
        QStringLiteral("powrprof.dll"), QStringLiteral("wsc.dll"),
        QStringLiteral("wscapi.dll"),
        QStringLiteral("version.dll"), QStringLiteral("winmm.dll"),
        QStringLiteral("msimg32.dll"), QStringLiteral("dwmapi.dll"),
        QStringLiteral("uxtheme.dll"), QStringLiteral("dbghelp.dll"),
        QStringLiteral("dbgcore.dll"), QStringLiteral("textinputframework.dll"),
        QStringLiteral("cryptsp.dll"), QStringLiteral("cryptbase.dll"),
        QStringLiteral("secur32.dll"), QStringLiteral("sspicli.dll"),
        QStringLiteral("bcrypt.dll"), QStringLiteral("ncrypt.dll"),
        QStringLiteral("wintrust.dll"),
        QStringLiteral("profapi.dll"), QStringLiteral("userenv.dll"),
        QStringLiteral("dwrite.dll"), QStringLiteral("textshaping.dll"),
        QStringLiteral("winhttp.dll"), QStringLiteral("wininet.dll"),
        QStringLiteral("iphlpapi.dll"), QStringLiteral("dnsapi.dll"),
        QStringLiteral("winsta.dll"), QStringLiteral("mswsock.dll"),
        QStringLiteral("propsys.dll"), QStringLiteral("shcore.dll"),
        QStringLiteral("apphelp.dll"), QStringLiteral("dxgi.dll"),
        QStringLiteral("d3d9.dll"), QStringLiteral("oleacc.dll"),
        QStringLiteral("comctl32.dll"), QStringLiteral("riched20.dll"),
        QStringLiteral("msctf.dll"), QStringLiteral("mfc42loc.dll"),
        QStringLiteral("srvcli.dll"), QStringLiteral("netapi32.dll"),
        QStringLiteral("logoncli.dll"), QStringLiteral("samcli.dll"),
    };
    QString name = pathOrName.trimmed();
    name.replace(QLatin1Char('/'), QLatin1Char('\\'));
    const qsizetype slash = name.lastIndexOf(QLatin1Char('\\'));
    if (slash >= 0) name = name.mid(slash + 1);
    return kNames.contains(name.toLower());
}

}
