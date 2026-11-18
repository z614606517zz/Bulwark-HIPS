#include "bulwark/engine/TrustPolicy.h"
#include "bulwark/engine/CommandDeobfuscator.h"
#include "bulwark/engine/EngineCommon.h"
#include "bulwark/engine/TrustedSoftwareCatalog.h"
#include "bulwark/engine/SelfProtection.h"
#include "bulwark/engine/SystemPaths.h"
#include "bulwark/models/DefenseRule.h"
#include <QSet>
#include <QStringList>
#include <QDateTime>

namespace bulwark::engine {
using detail::u;
using detail::fileNameLower;

namespace {

const QSet<QString>& strongTrustThumbprints() {
    static const QSet<QString> s = {
        "8FBE4D070EF8AB1BCCAF2A9D5CCAE7282A2C66B3",
        "A4341B9FD50FB9964283220A36A1EF6F6FAA7840",
        "3B1EFD3A66EA28B16697394703A72CA340A05BD5",
    };
    return s;
}
const QStringList& strongPublishers() {
    static const QStringList s = { "Microsoft Corporation", "Microsoft Windows", "Microsoft Windows Publisher" };
    return s;
}
const QSet<QString>& knownSecurityProcessNames() {
    static const QSet<QString> s = {
        "msmpeng.exe", "mpcmdrun.exe", "nissrv.exe", "mpdefendercoreservice.exe", "securityhealthservice.exe",
        "avp.exe", "avpui.exe", "kavfs.exe", "kavfswp.exe", "ksde.exe", "ksdeui.exe",
        "avpsus.exe", "klnagent.exe", "ksn.exe",
        "ekrn.exe", "egui.exe",
        "mcshield.exe", "masvc.exe", "macmnsvc.exe", "mfemms.exe",
        "ccsvchst.exe", "symcorpui.exe", "nortonsecurity.exe", "rtvscan.exe",
        "avastsvc.exe", "avastui.exe", "afwserv.exe", "avgsvc.exe", "avgui.exe",
        "avguard.exe", "avgnt.exe", "sched.exe",
        "bdagent.exe", "vsserv.exe", "bdservicehost.exe",
        "ntrtscan.exe", "pccntmon.exe", "tmbmsrv.exe",
        "savservice.exe", "sophosfs.exe", "sophosfilescanner.exe",
        "360tray.exe", "360sd.exe", "360rp.exe", "zhudongfangyu.exe", "360safe.exe",
        "hipstray.exe", "hipsdaemon.exe", "usysdiag.exe", "wsctrl.exe",
        "qqpcrtp.exe", "qqpctray.exe", "qqpcmgr.exe",
        "kxetray.exe", "kxescore.exe", "kscan.exe", "ksafetray.exe", "kwsprotect64.exe",
    };
    return s;
}
const QStringList& protectedInstallDirs() {
    static const QStringList s = {
        "\\program files\\", "\\program files (x86)\\",
        "\\windows\\system32\\", "\\windows\\syswow64\\", "\\windows\\defender\\",
    };
    return s;
}
const QStringList& benignPublishers() {
    static const QStringList s = {
        "Microsoft Corporation", "Microsoft Windows",
        "Google LLC", "Google Inc", "Mozilla Corporation", "Apple Inc",
        "Adobe Inc", "Adobe Systems",
        "Intel Corporation", "NVIDIA Corporation", "Advanced Micro Devices",
        "Realtek", "Lenovo", "Dell", "HP Inc", "Hewlett",
        "Valve", "Tencent", "Alibaba", "Bytedance",
        "Oracle", "VMware", "Citrix", "JetBrains", "GitHub", "Docker",
        "Igor Pavlov", "Notepad++",
        "Kaspersky", "Beijing Qihu", "Qizhi", "360",
        "Huorong", "Beijing Huorong", "北京火绒网络科技有限公司",
        "Kingsoft", "WPS", "Baidu",
        "NetEase", "Sogou", "Bilibili", "Shanghai Hode",
        "Beijing Sankuai", "Meituan", "Spotify", "Discord", "Telegram", "Telegram FZ",
        "Zoom", "Slack Technologies", "Dropbox", "Logitech", "Logi",
        "ASUS", "ASUSTeK", "Razer", "Qualcomm", "MediaTek",
        "Western Digital", "Seagate", "Samsung", "WinRAR", "win.rar",
        "TeamViewer", "Cisco", "Postman", "Python Software Foundation",
        "The Git", "Git for Windows", "Canonical", "Epic Games",
        "Blizzard", "Riot Games", "Electronic Arts", "Ubisoft",
        "miHoYo", "Cognosphere", "OBS", "VideoLAN", "Audacity", "GIMP",
        "Doc-Cmd", "Foxit", "Tencent Technology", "Shenzhen Tencent",
    };
    return s;
}
const QSet<QString>& trustedVendorApps() {
    static const QSet<QString> s = {
        "qq.exe", "tim.exe", "wechat.exe", "weixin.exe", "wxwork.exe",
    };
    return s;
}
const QStringList& systemDirs() {
    static const QStringList s = {
        "\\windows\\system32\\", "\\windows\\syswow64\\", "\\windows\\winsxs\\",
        "\\windows\\servicing\\", "\\windows\\uus\\",
    };
    return s;
}
const QStringList& trustedDirs() {
    static const QStringList s = {
        "\\windows\\system32\\", "\\windows\\syswow64\\", "\\windows\\winsxs\\",
        "\\windows\\uus\\", "\\program files\\", "\\program files (x86)\\",
    };
    return s;
}
const QSet<QString>& lolBinsAndHosts() {
    static const QSet<QString> s = {
        "reg.exe", "regedit.exe", "regini.exe",
        "powershell.exe", "pwsh.exe", "cmd.exe",
        "wscript.exe", "cscript.exe", "mshta.exe",
        "rundll32.exe", "regsvr32.exe", "sc.exe",
        "wmic.exe", "cmstp.exe", "fodhelper.exe",
        "xcopy.exe", "robocopy.exe", "replace.exe",
        "expand.exe", "extrac32.exe", "esentutl.exe",
    };
    return s;
}
const QStringList& hardDangerTokens() {
    static const QStringList s = {
        "-enc", "-encodedcommand", "downloadstring", "downloadfile",
        "invoke-expression", "iex(", "frombase64string", "urlcache",
        "javascript:", "vbscript:",
        "bitsadmin /transfer", "-decode",
        "comsvcs.dll", "minidump", "sekurlsa", "lsadump", "mimikatz", "invoke-mimikatz",
        "vssadmin delete", "wmic shadowcopy delete", "wbadmin delete",
        "invoke-webrequest", "start-bitstransfer", "reflection.assembly",
    };
    return s;
}

const QStringList& softDangerTokens() {
    static const QStringList s = {
        "bypass", "-w hidden", "-windowstyle hidden",
    };
    return s;
}
const QSet<QString>& officeAndBrowsers() {
    static const QSet<QString> s = {
        "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "msaccess.exe",
        "chrome.exe", "msedge.exe", "firefox.exe", "iexplore.exe", "acrord32.exe",
    };
    return s;
}
const QSet<QString>& scriptHostsSet() {
    static const QSet<QString> s = {
        "powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe",
        "mshta.exe", "rundll32.exe", "regsvr32.exe", "certutil.exe",
    };
    return s;
}

// 任意盘符。只用于「拒绝」类判断(拒绝得宽一点无害);授予信任必须用 containsDir。
bool startsAfterDrive(const QString& pathLower, const QString& dirLower) {
    if (pathLower.size() < 2 || pathLower.at(1) != QLatin1Char(':')) return false;
    return QStringView(pathLower).mid(2).startsWith(dirLower);
}
bool containsDir(const QStringList& dirs, const QString& pathLower) {
    const QString rel = SystemPaths::systemVolumeRelative(pathLower);
    if (rel.isEmpty()) return false;
    for (const QString& d : dirs) if (rel.startsWith(d)) return true;
    return false;
}

bool isWildcardOnly(const QString& s) {
    for (const QChar c : s) {
        if (c != QLatin1Char('*') && c != QLatin1Char('?') && c != QLatin1Char('\\')
            && c != QLatin1Char('/') && c != QLatin1Char('.') && c != QLatin1Char(':')
            && !c.isSpace())
            return false;
    }
    return true;
}
QString matchedPublisher(const QString& publisher, const QStringList& list) {
    if (publisher.isEmpty()) return QString();
    const QString hay = publisher.toLower();
    for (const QString& p : list) {
        const QString needle = p.toLower();
        if (needle.isEmpty()) continue;
        int from = 0;
        for (;;) {
            const int at = hay.indexOf(needle, from);
            if (at < 0) break;
            const int end = at + needle.size();
            const bool leftOk = (at == 0) || !hay.at(at - 1).isLetterOrNumber();
            const bool rightOk = (end == hay.size()) || !hay.at(end).isLetterOrNumber();
            if (leftOk && rightOk) return p;
            from = at + 1;
        }
    }
    return QString();
}
bool publisherMatches(const QString& publisher, const QStringList& list) {
    return !matchedPublisher(publisher, list).isEmpty();
}

QSet<QString>& abusedThumbprints() {
    static QSet<QString> s;
    return s;
}
QStringList& abusedPublishers() {
    static QStringList s;
    return s;
}
// 指纹归一:去掉空格 / 冒号 / 连字符,转大写。配置里抄自证书管理器的指纹常带空格,
// 而 e.actorCertThumbprint 是无分隔大写十六进制,两边必须先对齐再比。
QString normalizeThumbprint(const QString& raw) {
    QString out;
    out.reserve(raw.size());
    for (const QChar ch : raw) {
        if (ch.isLetterOrNumber()) out.append(ch.toUpper());
    }
    return out;
}

bool hasDangerousCommandLine(const QString& cmd) {
    if (cmd.isEmpty()) return false;
    const QString c = cmd.toLower();
    for (const QString& t : hardDangerTokens()) if (c.contains(t)) return true;
    int soft = 0;
    for (const QString& t : softDangerTokens()) if (c.contains(t)) ++soft;
    return soft >= 2;
}
bool isLolBinOrScriptHost(const QString& path) {
    const QString name = fileNameLower(path);
    return !name.isEmpty() && lolBinsAndHosts().contains(name);
}
bool targetsProductSelf(const bulwark::SecurityEvent& e) {
    return SelfProtection::enabled.load(std::memory_order_relaxed)
        && SelfProtection::commandTargetsProduct(e.commandLine);
}
bool hasDangerousCommandLineOrSelfTarget(const bulwark::SecurityEvent& e) {
    const bool healthyIdentity = e.actorSigned && !e.signatureMismatch
                              && !e.certRevoked && !e.signedAfterCertExpiry;
    if (detail::isContentInspectionProcess(e.actorPath, healthyIdentity))
        return false;
    if (hasDangerousCommandLine(e.commandLine) || targetsProductSelf(e))
        return true;
    // 词表里的 "-w hidden"、"vssadmin delete" 是单空格字面量:多打空格、换成 Tab、给词加引号后执行效果不变,
    // 不能因此就不算危险词而拿到信任。这里是拒绝信任方向的判断,多比对一份只会更严。
    const QString tidy = CommandDeobfuscator::tidied(e.commandLine);
    return tidy != e.commandLine && hasDangerousCommandLine(tidy);
}
bool isAbnormalChain(const bulwark::SecurityEvent& e) {
    const QString actor = fileNameLower(e.actorPath);
    const QString parent = fileNameLower(e.parentPath);
    return officeAndBrowsers().contains(parent) && scriptHostsSet().contains(actor)
        && !detail::isBrowserNativeMessagingLaunch(e.actorPath, e.parentPath, e.commandLine);
}

}

void TrustPolicy::setAbusedSigners(const QStringList& thumbprints, const QStringList& publishers) {
    QSet<QString>& tp = abusedThumbprints();
    tp.clear();
    for (const QString& t : thumbprints) {
        const QString n = normalizeThumbprint(t);
        if (!n.isEmpty()) tp.insert(n);
    }
    QStringList& pubs = abusedPublishers();
    pubs.clear();
    for (const QString& p : publishers) {
        const QString trimmed = p.trimmed();
        if (trimmed.size() >= 4) pubs.append(trimmed);
    }
}

TrustDecision TrustPolicy::isAbusedSigner(const bulwark::SecurityEvent& e) {
    if (!e.actorCertThumbprint.isEmpty()) {
        const QString n = normalizeThumbprint(e.actorCertThumbprint);
        if (!n.isEmpty() && abusedThumbprints().contains(n))
            return { true, u("签名证书在【被盗用证书】名单内(指纹 ") + n + u(")") };
    }
    const QString pub = matchedPublisher(e.actorPublisher, abusedPublishers());
    if (!pub.isEmpty())
        return { true, u("签名主体在【被盗用证书】名单内:") + pub };
    return {};
}

TrustDecision TrustPolicy::isTrustedSecurityProduct(const bulwark::SecurityEvent& e) {
    if (e.actorPath.isEmpty()) return {};
    const QString name = fileNameLower(e.actorPath);
    if (name.isEmpty() || !knownSecurityProcessNames().contains(name)) return {};
    if (!e.actorSigned || e.signatureMismatch || e.certRevoked || e.signedAfterCertExpiry)
        return {};
    // 共存身份也必须排除已知被盗用的证书(见 isAbusedSigner)。
    if (isAbusedSigner(e).ok) return {};
    // Bind each protected product identity to its own publisher, not just any
    // valid certificate on a familiar filename.
    const struct ProductIdentity { const char* images; const char* publisher; } identities[] = {
        { "msmpeng.exe|mpcmdrun.exe|nissrv.exe|mpdefendercoreservice.exe|securityhealthservice.exe", "Microsoft" },
        { "avp.exe|avpui.exe|kavfs.exe|kavfswp.exe|ksde.exe|ksdeui.exe|avpsus.exe|klnagent.exe|ksn.exe", "Kaspersky" },
        { "ekrn.exe|egui.exe", "ESET" },
        { "mcshield.exe|masvc.exe|macmnsvc.exe|mfemms.exe", "McAfee|Trellix" },
        { "ccsvchst.exe|symcorpui.exe|nortonsecurity.exe|rtvscan.exe", "Symantec|Norton|Gen Digital|Broadcom" },
        { "avastsvc.exe|avastui.exe|afwserv.exe|avgsvc.exe|avgui.exe", "Avast|AVG|Gen Digital" },
        { "avguard.exe|avgnt.exe|sched.exe", "Avira" },
        { "bdagent.exe|vsserv.exe|bdservicehost.exe", "Bitdefender" },
        { "ntrtscan.exe|pccntmon.exe|tmbmsrv.exe", "Trend Micro" },
        { "savservice.exe|sophosfs.exe|sophosfilescanner.exe", "Sophos" },
        { "360tray.exe|360sd.exe|360rp.exe|zhudongfangyu.exe|360safe.exe", "Beijing Qihu|Qizhi|360 Security|奇虎|奇智" },
        { "hipstray.exe|hipsdaemon.exe|usysdiag.exe|wsctrl.exe", "Huorong|火绒" },
        { "qqpcrtp.exe|qqpctray.exe|qqpcmgr.exe", "Tencent|腾讯" },
        { "kxetray.exe|kxescore.exe|kscan.exe|ksafetray.exe|kwsprotect64.exe", "Kingsoft|金山" },
    };
    bool publisherBound = false;
    for (const ProductIdentity& product : identities) {
        if (QString::fromLatin1(product.images).split(QLatin1Char('|')).contains(name)) {
            publisherBound = publisherMatches(e.actorPublisher,
                QString::fromUtf8(product.publisher).split(QLatin1Char('|')));
            break;
        }
    }
    if (!publisherBound) return {};
    QString lower = e.actorPath.toLower();
    lower.replace(QLatin1Char('/'), QLatin1Char('\\'));
    if (!containsDir(protectedInstallDirs(), lower)) return {};
    return { true, u("已安装的知名安全软件(") + name + u(")·签名健康,共存放行") };
}

TrustDecision TrustPolicy::isStronglyTrusted(const bulwark::SecurityEvent& e) {
    if (e.hasThreatIndicator) return {};
    if (hasDangerousCommandLineOrSelfTarget(e)) return {};
    if (isAbnormalChain(e)) return {};
    if (e.scriptFileHardIndicator) return {};
    if (!e.actorSigned) return {};
    if (e.certRevoked || e.signedAfterCertExpiry) return {};
    if (isAbusedSigner(e).ok) return {};

    if (!e.actorCertThumbprint.isEmpty() &&
        strongTrustThumbprints().contains(e.actorCertThumbprint.toUpper()))
        return { true, u("证书指纹在强可信白名单") };

    QString pathLower = e.actorPath.toLower();
    pathLower.replace(QLatin1Char('/'), QLatin1Char('\\'));
    if (publisherMatches(e.actorPublisher, strongPublishers()) && containsDir(systemDirs(), pathLower))
        return { true, u("微软签名且位于系统目录") };

    return {};
}

TrustDecision TrustPolicy::isHealthySigned(const bulwark::SecurityEvent& e) {
    if (!e.actorSigned) return {};
    if (e.signatureMismatch || e.certRevoked || e.signedAfterCertExpiry) return {};
    if (e.hasThreatIndicator) return {};
    if (hasDangerousCommandLineOrSelfTarget(e)) return {};
    if (isAbnormalChain(e)) return {};
    if (isAbusedSigner(e).ok) return {};

    if (e.certNotAfterUtc.has_value()) {
        const qint64 secs = nowUtc().secsTo(*e.certNotAfterUtc);
        if (e.isFirstSeen && secs > 0 && secs <= static_cast<qint64>(186) * 24 * 3600) return {};
        if (secs < 0 && e.isFirstSeen) {
            QString pathLower = e.actorPath.toLower();
            pathLower.replace(QLatin1Char('/'), QLatin1Char('\\'));
            if (!containsDir(trustedDirs(), pathLower)) return {};
        }
    }

    const QString reason = e.actorPublisher.isEmpty()
        ? u("有效数字签名(健康),直接放行")
        : (u("有效数字签名:") + e.actorPublisher + u("(健康),直接放行"));
    return { true, reason };
}

TrustDecision TrustPolicy::isBenignSigner(const bulwark::SecurityEvent& e) {
    if (!e.actorSigned) return {};
    if (e.certRevoked || e.signedAfterCertExpiry) return {};
    if (isAbusedSigner(e).ok) return {};

    const QString pub = matchedPublisher(e.actorPublisher, benignPublishers());
    if (!pub.isEmpty())
        return { true, u("合法签名发行商:") + pub };

    QString pathLower = e.actorPath.toLower();
    pathLower.replace(QLatin1Char('/'), QLatin1Char('\\'));
    if (containsDir(trustedDirs(), pathLower))
        return { true, u("合法签名且位于标准安装目录") };

    return {};
}

TrustDecision TrustPolicy::isTrustedVendorApp(const bulwark::SecurityEvent& e) {
    // 必须持有健康签名(未失配 / 未吊销 / 未过期后签名),防止同名恶意程序冒用白名单。
    if (!e.actorSigned || e.signatureMismatch || e.certRevoked || e.signedAfterCertExpiry)
        return {};
    if (isAbusedSigner(e).ok) return {};
    // 脚本宿主与代理执行程序联网全凭参数,微软签名替它背不了书:让它们照常走检测与规则。
    static const QSet<QString> proxyHosts = {
        "msxsl.exe", "installutil.exe", "regasm.exe", "regsvcs.exe", "odbcconf.exe", "ieexec.exe",
    };
    const QString name = fileNameLower(e.actorPath);
    if (isLolBinOrScriptHost(e.actorPath) || scriptHostsSet().contains(name) || proxyHosts.contains(name))
        return {};

    if (const auto app =
            TrustedSoftwareCatalog::instance().match(e.actorPath, e.actorPublisher)) {
        return { true,
                 u("软件信任库:") + app->name + u("(") + app->vendor + u(")·签名健康，可跳过低置信时序分析") };
    }

    if (name.isEmpty() || !trustedVendorApps().contains(name))
        return {};
    const QString pub = matchedPublisher(e.actorPublisher, benignPublishers());
    if (!pub.isEmpty())
        return { true, u("已知良性厂商应用(") + name + u(")·签名健康(") + pub + u(")，可跳过低置信时序分析") };
    return {};
}

bool TrustPolicy::isProcessCreationBroker(const QString& creatorPath) {
    static const QSet<QString> brokers = {
        "svchost.exe", "services.exe", "wininit.exe", "winlogon.exe", "smss.exe", "csrss.exe", "lsass.exe",
        "wmiprvse.exe", "taskhostw.exe", "taskeng.exe", "dllhost.exe", "sihost.exe", "runtimebroker.exe",
        "werfault.exe", "wermgr.exe", "consent.exe",
    };
    QString pathLower = creatorPath.toLower();
    pathLower.replace(QLatin1Char('/'), QLatin1Char('\\'));
    return brokers.contains(fileNameLower(pathLower)) && containsDir(systemDirs(), pathLower);
}

bool TrustPolicy::isMicrosoftSystemImage(const bulwark::SecurityEvent& e) {
    if (!e.actorSigned || e.signatureMismatch || e.certRevoked || e.signedAfterCertExpiry) return false;
    if (isAbusedSigner(e).ok) return false;
    QString pathLower = e.actorPath.toLower();
    pathLower.replace(QLatin1Char('/'), QLatin1Char('\\'));
    return publisherMatches(e.actorPublisher, strongPublishers()) && containsDir(systemDirs(), pathLower);
}

TrustDecision TrustPolicy::isTrustedOsComponent(const bulwark::SecurityEvent& e) {
    if (e.hasThreatIndicator) return {};
    if (isLolBinOrScriptHost(e.actorPath)) return {};
    const TrustDecision t = isStronglyTrusted(e);
    if (!t.ok) return {};
    return { true, u("强可信系统组件(") + t.reason + u("),敏感操作豁免") };
}

TrustDecision TrustPolicy::isTrusted(const bulwark::SecurityEvent& e) {
    return isStronglyTrusted(e);
}

TrustDecision TrustPolicy::rejectsWholeProcessTrust(const QString& path, bool isDirectory) {
    QString lower = path.trimmed().toLower();
    lower.replace(QLatin1Char('/'), QLatin1Char('\\'));
    if (lower.isEmpty()) return {};
    if (isDirectory) {
        QString dir = lower;
        while (dir.endsWith(QLatin1Char('*')) || dir.endsWith(QLatin1Char('\\')))
            dir.chop(1);
        dir += QLatin1Char('\\');
        if (dir.size() <= 3 || startsAfterDrive(dir, QStringLiteral("\\windows\\")))
            return { true, u("不允许信任整个盘符或 Windows 系统目录:其中的脚本宿主 / LOLBin 会因此跳过全部检测") };
        return {};
    }
    const QString name = fileNameLower(lower);
    if (lolBinsAndHosts().contains(name) || scriptHostsSet().contains(name))
        return { true, u("不允许整体信任脚本宿主 / LOLBin(") + name
                       + u("):它的行为完全由参数决定,整体加白会让经它发起的攻击全部跳过检测。"
                           "请改为删除误伤的那条规则,或为具体命令添加例外") };
    return {};
}

TrustDecision TrustPolicy::rejectsAllowRule(const bulwark::DefenseRule& r) {
    if (r.action != VerdictAction::Allow || !r.actorHashes.isEmpty())
        return {};
    if (!isWildcardOnly(r.targetPattern.trimmed()))
        return {};

    QString actor = (r.actorPath.trimmed().isEmpty() ? r.actorPattern : r.actorPath).trimmed().toLower();
    actor.replace(QLatin1Char('/'), QLatin1Char('\\'));
    if (isWildcardOnly(actor))
        return { true, u("放行规则既不限定程序也不限定目标,等于关掉这一类防护;"
                         "确需如此,请在设置里关闭对应的防护维度") };

    if (actor.endsWith(QLatin1String("\\*")) || actor.endsWith(QLatin1Char('\\'))) {
        // 通配写法(*\Windows\…、?:\…)不带真实盘符,rejectsWholeProcessTrust 认不出,这里先按卷内路径判一次。
        QString rel = (actor.size() >= 2 && actor.at(1) == QLatin1Char(':')) ? actor.mid(2) : actor;
        while (rel.startsWith(QLatin1Char('*')))
            rel.remove(0, 1);
        while (rel.endsWith(QLatin1Char('*')) || rel.endsWith(QLatin1Char('\\')))
            rel.chop(1);
        if (isWildcardOnly(rel) || (rel + QLatin1Char('\\')).startsWith(QLatin1String("\\windows\\")))
            return { true, u("不允许放行整个盘符或 Windows 系统目录下所有程序的整类行为:"
                             "其中的脚本宿主 / LOLBin 会因此跳过检测") };
        return rejectsWholeProcessTrust(actor, true);
    }

    const QString name = fileNameLower(actor);
    if (name.contains(QLatin1Char('*')) || name.contains(QLatin1Char('?')))
        return { true, u("文件名带通配的放行规则必须限定目标,否则任何改成匹配名字的程序都会被放过") };
    return rejectsWholeProcessTrust(actor, false);
}

}
