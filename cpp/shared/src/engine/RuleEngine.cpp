#include "bulwark/engine/RuleEngine.h"
#include "bulwark/engine/CommandDeobfuscator.h"
#include "bulwark/engine/EngineCommon.h"
#include "bulwark/engine/ThreatDetector.h"
#include "bulwark/engine/TrustPolicy.h"
#include "bulwark/engine/DgaDomainAnalyzer.h"
#include "bulwark/engine/AttackAnnotator.h"
#include "bulwark/engine/DefaultRules.h"
#include "bulwark/engine/SelfProtection.h"
#include <QSet>
#include <QStringList>
#include <algorithm>

namespace bulwark::engine {

using detail::u;
using detail::fileNameLower;

namespace {
const QSet<QString>& selfImageNames() {
    static const QSet<QString> s = {
        "bulwark_service.exe", "bulwark_ui.exe",
    };
    return s;
}

QStringList tokenizeCommandLine(const QString& cmd) {
    QStringList out;
    QString cur;
    bool inQuotes = false;
    bool started = false;
    for (int i = 0; i < cmd.size(); ++i) {
        const QChar c = cmd.at(i);
        if (c == QLatin1Char('"')) {
            if (inQuotes && i + 1 < cmd.size() && cmd.at(i + 1) == QLatin1Char('"')) {
                cur += QLatin1Char('"');
                ++i;
            } else {
                inQuotes = !inQuotes;
            }
            started = true;
            continue;
        }
        if (!inQuotes && c.isSpace()) {
            if (started) { out << cur; cur.clear(); started = false; }
            continue;
        }
        cur += c;
        started = true;
    }
    if (started) out << cur;
    return out;
}

QString normalizePathToken(const QString& token) {
    QString t = token.trimmed().toLower();
    t.replace(QLatin1Char('/'), QLatin1Char('\\'));
    return t;
}

bool isInlineCodeSwitch(const QString& tokenLower) {
    static const QSet<QString> s = {
        QStringLiteral("-command"),   QStringLiteral("/command"),
        QStringLiteral("-c"),         QStringLiteral("/c:"),
        QStringLiteral("-encodedcommand"), QStringLiteral("-encoded"),
        QStringLiteral("-enc"),       QStringLiteral("-e"),
        QStringLiteral("-ec"),        QStringLiteral("-encodedarguments"),
    };
    return s.contains(tokenLower);
}

bool hasCommandChaining(const QString& token) {
    static const char* kBad[] = { ";", "&", "|", "`", "$(", "%0a", "\n", "\r" };
    for (const char* b : kBad)
        if (token.contains(QLatin1String(b))) return true;
    return false;
}
}

void RuleEngine::addSelfDirectory(const QString& dir) {
    if (dir.trimmed().isEmpty()) return;
    QString norm = dir.trimmed().toLower();
    norm.replace(QLatin1Char('/'), QLatin1Char('\\'));
    if (!norm.endsWith(QLatin1Char('\\'))) norm += QLatin1Char('\\');
    QMutexLocker locker(&selfDirLock_);
    selfDirectories_.insert(norm);
}

bool RuleEngine::matchesSelf(const QString& path) const {
    if (path.isEmpty()) return false;

    const QString name = fileNameLower(path);
    if (name.isEmpty() || !selfImageNames().contains(name)) return false;

    QMutexLocker locker(&selfDirLock_);
    if (selfDirectories_.isEmpty()) return false;
    QString pathLower = path.toLower();
    pathLower.replace(QLatin1Char('/'), QLatin1Char('\\'));
    for (const QString& d : selfDirectories_)
        if (pathLower.startsWith(d)) return true;
    return false;
}

bool RuleEngine::isSelfComponent(const SecurityEvent& e) const {
    if (matchesSelf(e.actorPath)) return true;
    if (!matchesSelf(e.parentPath)) return false;
    QString actor = e.actorPath.toLower();
    actor.replace(QLatin1Char('/'), QLatin1Char('\\'));
    if (actor.isEmpty()) return false;
    QString sysRoot = qEnvironmentVariable("SystemRoot", QStringLiteral("C:\\Windows")).toLower();
    sysRoot.replace(QLatin1Char('/'), QLatin1Char('\\'));
    if (!sysRoot.endsWith(QLatin1Char('\\'))) sysRoot += QLatin1Char('\\');
    if (actor.startsWith(sysRoot)) return true;
    QMutexLocker locker(&selfDirLock_);
    for (const QString& d : selfDirectories_)
        if (actor.startsWith(d)) return true;
    return false;
}

bool RuleEngine::isSanctionedMaintenanceActor(const SecurityEvent& e) const {
    return isSanctionedScriptInvocation(e.actorPath, e.commandLine, false);
}

bool RuleEngine::isSanctionedScriptInvocation(const QString& actorPath, const QString& commandLine,
                                              bool includeInstallScript) const {
    const QString actorName = fileNameLower(actorPath);
    if (actorName != QLatin1String("powershell.exe") && actorName != QLatin1String("cmd.exe"))
        return false;
    QString actorLower = actorPath.toLower();
    actorLower.replace(QLatin1Char('/'), QLatin1Char('\\'));
    QString sysRoot = qEnvironmentVariable("SystemRoot", QStringLiteral("C:\\Windows")).toLower();
    sysRoot.replace(QLatin1Char('/'), QLatin1Char('\\'));
    if (!sysRoot.endsWith(QLatin1Char('\\'))) sysRoot += QLatin1Char('\\');
    if (!actorLower.startsWith(sysRoot)) return false;

    const QString& cmd = commandLine;
    if (cmd.isEmpty()) return false;

    QSet<QString> selfDirs;
    {
        QMutexLocker locker(&selfDirLock_);
        if (selfDirectories_.isEmpty()) return false;
        selfDirs = selfDirectories_;
    }

    static const QSet<QString> kScripts = {
        QStringLiteral("bulwark.ps1"),
        QStringLiteral("uninstall.ps1"),
    };
    static const QSet<QString> kScriptsWithInstall = {
        QStringLiteral("bulwark.ps1"),
        QStringLiteral("uninstall.ps1"),
        QStringLiteral("install.ps1"),
    };
    const QSet<QString>& scripts = includeInstallScript ? kScriptsWithInstall : kScripts;

    const QStringList tokens = tokenizeCommandLine(cmd);
    if (tokens.size() < 2) return false;

    bool sanctioned = false;
    for (int i = 0; i < tokens.size(); ++i) {
        const QString tokenLower = tokens.at(i).toLower();
        if (isInlineCodeSwitch(tokenLower)) return false;
        if (hasCommandChaining(tokens.at(i))) return false;

        const QString norm = normalizePathToken(tokens.at(i));
        const int slash = norm.lastIndexOf(QLatin1Char('\\'));
        if (slash < 0) continue;
        if (!scripts.contains(norm.mid(slash + 1))) continue;

        // -File 必须紧邻在前(PowerShell 允许参数名缩写,故按前缀认 -f/-fi/-fil/-file)。
        if (i == 0) continue;
        const QString prev = tokens.at(i - 1).toLower();
        if (!prev.startsWith(QLatin1Char('-')) || prev.size() < 2
            || !QStringLiteral("-file").startsWith(prev)) {
            continue;
        }

        bool underSelfDir = false;
        for (const QString& d : selfDirs)
            if (norm.startsWith(d)) { underSelfDir = true; break; }
        if (underSelfDir)
            sanctioned = true;
    }
    return sanctioned;
}

bool RuleEngine::isUserTrustedScriptHost(const QString& actorPath, const QString& commandLine) const {
    const QString actorName = fileNameLower(actorPath);
    const bool isPowershell = (actorName == QLatin1String("powershell.exe"));
    const bool isCmd = (actorName == QLatin1String("cmd.exe"));
    if (!isPowershell && !isCmd) return false;
    QString actorLower = actorPath.toLower();
    actorLower.replace(QLatin1Char('/'), QLatin1Char('\\'));
    QString sysRoot = qEnvironmentVariable("SystemRoot", QStringLiteral("C:\\Windows")).toLower();
    sysRoot.replace(QLatin1Char('/'), QLatin1Char('\\'));
    if (!sysRoot.endsWith(QLatin1Char('\\'))) sysRoot += QLatin1Char('\\');
    if (!actorLower.startsWith(sysRoot)) return false;
    if (commandLine.isEmpty()) return false;

    const QStringList tokens = tokenizeCommandLine(commandLine);
    if (tokens.size() < 2) return false;

    if (isCmd) {
        static const QSet<QString> kBenignSwitch = {
            QStringLiteral("/d"), QStringLiteral("/q"), QStringLiteral("/s"),
            QStringLiteral("/a"), QStringLiteral("/u"),
        };
        int cIdx = -1;
        for (int i = 1; i < tokens.size(); ++i) {
            const QString t = tokens.at(i).toLower();
            if (hasCommandChaining(tokens.at(i)) || tokens.at(i).contains(QLatin1Char('^'))) return false;
            if (t == QLatin1String("/c") || t == QLatin1String("/k")) { cIdx = i; break; }
            if (kBenignSwitch.contains(t) || t.startsWith(QLatin1String("/e:")) || t.startsWith(QLatin1String("/f:"))
                || t.startsWith(QLatin1String("/v:")) || t.startsWith(QLatin1String("/t:")))
                continue;
            return false;
        }
        if (cIdx < 0 || cIdx + 1 >= tokens.size()) return false;
        for (int i = cIdx + 1; i < tokens.size(); ++i)
            if (hasCommandChaining(tokens.at(i)) || tokens.at(i).contains(QLatin1Char('^'))) return false;
        const QString norm = normalizePathToken(tokens.at(cIdx + 1));
        if (norm.size() < 6 || norm.at(1) != QLatin1Char(':') || norm.at(2) != QLatin1Char('\\')
            || !(norm.endsWith(QLatin1String(".bat")) || norm.endsWith(QLatin1String(".cmd"))))
            return false;
        return userTrustNoteForPath(tokens.at(cIdx + 1)).has_value();
    }

    bool trusted = false;
    for (int i = 0; i < tokens.size(); ++i) {
        const QString tokenLower = tokens.at(i).toLower();
        if (isInlineCodeSwitch(tokenLower)) return false;
        if (hasCommandChaining(tokens.at(i))) return false;

        const QString norm = normalizePathToken(tokens.at(i));
        if (norm.size() < 4 || norm.at(1) != QLatin1Char(':') || norm.at(2) != QLatin1Char('\\')
            || !norm.endsWith(QLatin1String(".ps1"))) {
            continue;
        }
        if (i == 0) continue;
        const QString prev = tokens.at(i - 1).toLower();
        if (!prev.startsWith(QLatin1Char('-')) || prev.size() < 2
            || !QStringLiteral("-file").startsWith(prev)) {
            continue;
        }
        if (userTrustNoteForPath(tokens.at(i)).has_value())
            trusted = true;
    }
    return trusted;
}

bool RuleEngine::isSanctionedMaintenanceDescendant(const SecurityEvent& e) const {
    static const QSet<QString> kTools = {
        QStringLiteral("sc.exe"), QStringLiteral("fltmc.exe"), QStringLiteral("net.exe"),
        QStringLiteral("net1.exe"), QStringLiteral("taskkill.exe"),
    };
    if (!kTools.contains(fileNameLower(e.actorPath))) return false;
    QString actorLower = e.actorPath.toLower();
    actorLower.replace(QLatin1Char('/'), QLatin1Char('\\'));
    QString sysRoot = qEnvironmentVariable("SystemRoot", QStringLiteral("C:\\Windows")).toLower();
    sysRoot.replace(QLatin1Char('/'), QLatin1Char('\\'));
    if (!sysRoot.endsWith(QLatin1Char('\\'))) sysRoot += QLatin1Char('\\');
    if (!actorLower.startsWith(sysRoot)) return false;

    // 命令行里不得夹带串接:`sc stop BulwarkService & sc stop WinDefend` 这种复合命令,
    // 豁免了前半句就等于放过后半句。
    if (hasCommandChaining(e.commandLine)) return false;

    if (e.productSignedAncestor) return true;

    if (e.chainContext.isEmpty() || e.parentPid <= 0) return false;

    constexpr int kMaxHops = 3;
    QSet<int> visited;
    int pid = e.parentPid;
    for (int hop = 0; hop < kMaxHops && pid > 0 && !visited.contains(pid); ++hop) {
        visited.insert(pid);
        bool found = false;
        int next = 0;
        for (const bulwark::ChainEventInfo& c : e.chainContext) {
            if (c.actorPid != pid) continue;
            found = true;
            if (c.parentPid > 0) next = c.parentPid;
            if (c.commandLine.isEmpty()) continue;
            if (isSanctionedScriptInvocation(c.actorPath, c.commandLine, true))
                return true;
            if (isUserTrustedScriptHost(c.actorPath, c.commandLine))
                return true;
        }
        if (!found) return false;
        pid = next;
    }
    return false;
}

std::optional<QString> RuleEngine::userTrustNoteForPath(const QString& path) const {
    QString p = path.trimmed();
    if (p.isEmpty()) return std::nullopt;
    p.replace(QLatin1Char('/'), QLatin1Char('\\'));

    // 占位符路径:内核源在解析不出映像时会填 "PID 1234"(见 Worker::blacklistExec 的同名护栏)。
    // 这种事件无法判定主体身份 —— 宁可不豁免,绝不能因为一个占位符把真实的恶意处置放过去。
    if (p.startsWith(QLatin1String("PID "), Qt::CaseInsensitive)) return std::nullopt;

    const QDateTime now = nowUtc();
    QReadLocker locker(&rulesLock_);
    for (const DefenseRule& r : trustEntries_) {
        if (!r.enabled || r.isExpired(now))
            continue;
        const bool hitFile = !r.actorPath.isEmpty() && r.actorPath.compare(p, Qt::CaseInsensitive) == 0;
        const bool hitDir  = !r.actorPattern.isEmpty() && DefenseRule::wildcardMatch(r.actorPattern, p);
        if (hitFile || hitDir)
            return r.note.isEmpty() ? QStringLiteral("用户信任") : r.note;
    }
    return std::nullopt;
}

std::optional<QString> RuleEngine::trustNoteForPath(const QString& path) const {
    QString p = path.trimmed();
    if (p.isEmpty()) return std::nullopt;
    p.replace(QLatin1Char('/'), QLatin1Char('\\'));

    if (p.startsWith(QLatin1String("PID "), Qt::CaseInsensitive)) return std::nullopt;

    if (matchesSelf(p)) return QStringLiteral("本软件自身组件");

    return userTrustNoteForPath(p);
}

bool RuleEngine::targetIsTrustEligible(EventType t) {
    switch (t) {
        case EventType::ImageLoad:
        case EventType::FileWrite:
        case EventType::FileDelete:
            return true;
        default:
            return false;
    }
}

std::optional<QString> RuleEngine::trustNoteForEvent(const SecurityEvent& e) const {
    if (const std::optional<QString> actorNote = matchedUserTrust(e))
        return actorNote;

    if (!targetIsTrustEligible(e.type))
        return std::nullopt;

    const QString t = e.target.trimmed();
    if (t.isEmpty())
        return std::nullopt;
    if (t.contains(QLatin1Char('[')))
        return std::nullopt;

    return userTrustNoteForPath(t);
}

std::optional<QString> RuleEngine::matchedUserTrust(const SecurityEvent& e) const {
    QReadLocker locker(&rulesLock_);
    for (const DefenseRule& r : trustEntries_) {
        if (r.matches(e))
            return r.note.isEmpty() ? QStringLiteral("用户信任") : r.note;
    }
    return std::nullopt;
}

int RuleEngine::ruleTier(const DefenseRule& r) {
    const bool exactActor = !r.actorPath.isEmpty() || !r.actorHashes.isEmpty();
    if (exactActor) return 2;
    if (r.hardOverride) return 1;
    return 0;
}

int RuleEngine::rulePriority(VerdictAction a) {
    switch (a) {
        case VerdictAction::Block: return 2;
        case VerdictAction::Ask:   return 1;
        default:                   return 0;
    }
}

static bool devToolExemptionApplies(EventType t) {
    return t != EventType::RemoteThread && t != EventType::ProcessTerminate;
}

static bool contentInspectionRuleShouldBeIgnored(const SecurityEvent& e, const DefenseRule& r) {
    const bool healthyIdentity = e.actorSigned && !e.signatureMismatch
                              && !e.certRevoked && !e.signedAfterCertExpiry;
    if (!detail::isContentInspectionProcess(e.actorPath, healthyIdentity))
        return false;

    const bool noSubject = r.actorPath.isEmpty() && r.actorPattern.isEmpty()
                        && r.actorHashes.isEmpty();
    const bool commandOnly = noSubject && !r.commandLinePattern.isEmpty()
                          && r.targetPattern.isEmpty() && r.parentPattern.isEmpty();
    if (commandOnly)
        return true;

    if (e.type != EventType::FileWrite || r.action != VerdictAction::Block || !noSubject
        || r.targetPattern.isEmpty() || !r.commandLinePattern.isEmpty()
        || !r.parentPattern.isEmpty()) {
        return false;
    }

    const QString target = e.target.toLower();
    static const char* kSourceExt[] = {
        ".ps1", ".psm1", ".py", ".bat", ".cmd", ".js", ".jse",
        ".vbs", ".vbe", ".wsf", ".hta"
    };
    for (const char* ext : kSourceExt)
        if (target.endsWith(QLatin1String(ext)))
            return true;
    return false;
}

// 规则比的是命令行原文,p^o^w^e^r^s^h^e^l^l、i`e`x 这类写法会让 .cmd() 模式整条失配;
// 还原出的文本供 DefenseRule::matchesCommandLine 多比对一遍(仅 Block/Ask)。
// 签名健康的内容检查工具(rg / code / findstr …)的命令行是待检查的内容,不还原。
static void deobfuscateCommandLine(SecurityEvent& e) {
    e.normalizedCommandLine.clear();
    e.decodedCommandBlocks.clear();
    e.commandDeobfuscationLayers.clear();
    e.commandDeobfuscationReported = false;
    if (e.commandLine.isEmpty())
        return;
    const bool healthyIdentity = e.actorSigned && !e.signatureMismatch
                              && !e.certRevoked && !e.signedAfterCertExpiry;
    if (detail::isContentInspectionProcess(e.actorPath, healthyIdentity))
        return;
    const CommandDeobfuscator::Result d = CommandDeobfuscator::run(e.commandLine);
    e.normalizedCommandLine = d.normalized;
    e.decodedCommandBlocks = d.decodedBlocks;
    e.commandDeobfuscationLayers = d.layers;
}

static void flagProductTampering(SecurityEvent& e) {
    if (!SelfProtection::enabled.load(std::memory_order_relaxed) || e.commandLine.isEmpty())
        return;
    const bool healthyIdentity = e.actorSigned && !e.signatureMismatch
                              && !e.certRevoked && !e.signedAfterCertExpiry;
    if (detail::isContentInspectionProcess(e.actorPath, healthyIdentity))
        return;
    if (!SelfProtection::commandTargetsProduct(e.commandLine))
        return;
    e.hasThreatIndicator = true;
    e.riskScore = qMin(100, e.riskScore + 45);
    e.addEvidence(QStringLiteral("SelfProtection"), EvidenceKind::HardIndicator,
                  u("命令行试图停止/删除/结束本产品(磐垒)自身组件(服务·进程·驱动,自保护告警,T1562.001)"),
                  45);
}

static void addMonitorSignal(SecurityEvent& e, const char* source, int score, const QStringList& reasons,
                             bool hard) {
    if (score <= 0)
        return;
    e.riskScore = qMin(100, e.riskScore + score);
    bool first = true;
    for (const QString& r : reasons) {
        e.addEvidence(QLatin1String(source), hard ? EvidenceKind::HardIndicator : EvidenceKind::SoftSignal, r,
                      first ? score : 0);
        first = false;
    }
    if (hard)
        e.hasThreatIndicator = true;
}

namespace {

// 与 DefenseRule::wildcardMatch 逐字符相同的大小写折叠:索引键若用别的折叠方式,
// certutıl.exe(无点 ı,通配匹配时折成 I)这类写法会被索引提前筛掉,规则就漏了。
QString foldedKey(QStringView s) {
    QString out(s.size(), Qt::Uninitialized);
    for (qsizetype i = 0; i < s.size(); ++i) {
        const char16_t c = s.at(i).unicode();
        out[i] = c < 0x80 ? QChar((c >= u'a' && c <= u'z') ? static_cast<char16_t>(c - 0x20) : c)
                          : QChar(c).toUpper();
    }
    return out;
}

QString imageKeyOfPath(const QString& path) {
    const qsizetype slash = path.lastIndexOf(QLatin1Char('\\'));
    return foldedKey(QStringView(path).mid(slash + 1));
}

// 主体条件能否确定映像名:只有以「\名字」结尾、名字里没有通配的模式才行。命中它的路径
// 必然以「\名字」结尾,所以按事件主体路径最后一段查表不会漏掉它。其余一律放进 anyActor。
std::optional<QString> actorImageKeyOf(const DefenseRule& r) {
    if (!r.actorHashes.isEmpty() || !r.actorPath.isEmpty() || r.actorPattern.isEmpty())
        return std::nullopt;
    const QString& p = r.actorPattern;
    const qsizetype slash = p.lastIndexOf(QLatin1Char('\\'));
    const QStringView name = QStringView(p).mid(slash + 1);
    if (name.isEmpty() || name.contains(QLatin1Char('*')) || name.contains(QLatin1Char('?')))
        return std::nullopt;
    return foldedKey(name);
}

}

void RuleEngine::rebuildIndexLocked() {
    byType_.clear();
    typeAgnostic_ = RuleBucket{};
    trustEntries_.clear();
    for (auto it = rules_.constBegin(); it != rules_.constEnd(); ++it)
        indexInsertLocked(it.value());
}

void RuleEngine::indexInsertLocked(const DefenseRule& r) {
    RuleBucket& bucket = r.type.has_value() ? byType_[static_cast<int>(*r.type)] : typeAgnostic_;
    if (const std::optional<QString> key = actorImageKeyOf(r))
        bucket.byActorImage[*key].append(r);
    else
        bucket.anyActor.append(r);
    if (r.action == VerdictAction::Allow && r.isTrustEntry())
        trustEntries_.append(r);
}

void RuleEngine::collectMatches(const RuleBucket& bucket, const QString& actorImageKey, const SecurityEvent& e,
                                QVector<DefenseRule>& out) {
    for (const DefenseRule& r : bucket.anyActor)
        if (r.matches(e) && !contentInspectionRuleShouldBeIgnored(e, r))
            out.append(r);
    const auto it = bucket.byActorImage.constFind(actorImageKey);
    if (it == bucket.byActorImage.constEnd())
        return;
    for (const DefenseRule& r : it.value())
        if (r.matches(e) && !contentInspectionRuleShouldBeIgnored(e, r))
            out.append(r);
}

static bool isFilenameOnlyActorPattern(const QString& pattern) {
    if (pattern.isEmpty()) return false;
    // 取最后一个路径分隔符之后的部分;之前的部分必须只由通配构成才算「不限定位置」。
    const int slash = pattern.lastIndexOf(QLatin1Char('\\'));
    const QString head = slash < 0 ? QString() : pattern.left(slash);
    const QString tail = slash < 0 ? pattern : pattern.mid(slash + 1);
    if (!(head.isEmpty() || head == QStringLiteral("*"))) return false;
    if (tail.isEmpty() || tail.contains(QLatin1Char('*')) || tail.contains(QLatin1Char('?')))
        return false;
    return true;
}

bool RuleEngine::isUnsafeAllowRule(const DefenseRule& r, QString* whyOut) {
    if (r.action != VerdictAction::Allow) return false;
    if (r.requireUnsigned && r.requireSigned) {
        if (whyOut) *whyOut = u("同时要求已签名与未签名,永不命中(配置矛盾)");
        return true;
    }
    if (r.requireTargetUnsigned && r.requireTargetSigned) {
        if (whyOut) *whyOut = u("同时要求目标文件已签名与未签名,永不命中(配置矛盾)");
        return true;
    }
    if (!r.actorHashes.isEmpty()) return false;
    if (!r.actorPath.isEmpty()) return false;
    if (r.requireSigned) return false;
    if (isFilenameOnlyActorPattern(r.actorPattern)) {
        if (whyOut)
            *whyOut = u("Allow 规则的主体通配只写了文件名(") + r.actorPattern +
                      u("),等于放行任何位置的同名程序;请锚定路径或加 requireSigned");
        return true;
    }
    return false;
}

void RuleEngine::loadRules(const QVector<DefenseRule>& rules) {
    QHash<QUuid, DefenseRule> fresh;
    int rejected = 0;
    for (const DefenseRule& r : rules) {
        QString why;
        if (isUnsafeAllowRule(r, &why)) {
            ++rejected;
            qWarning("[RuleEngine] 拒绝加载不安全的 Allow 规则:%s | note=%s",
                     qUtf8Printable(why), qUtf8Printable(r.note));
            continue;
        }
        fresh.insert(r.id, r);
    }
    if (rejected > 0)
        qWarning("[RuleEngine] 共拒绝 %d 条不安全的 Allow 规则(见上方逐条说明)。", rejected);
    QWriteLocker locker(&rulesLock_);
    rules_ = std::move(fresh);
    rebuildIndexLocked();
}

QVector<DefenseRule> RuleEngine::getRules() const {
    const QDateTime now = nowUtc();
    QReadLocker locker(&rulesLock_);
    QVector<DefenseRule> out;
    out.reserve(rules_.size());
    for (auto it = rules_.constBegin(); it != rules_.constEnd(); ++it)
        if (!it.value().isExpired(now)) out.append(it.value());
    return out;
}

int RuleEngine::pruneExpired() {
    const QDateTime now = nowUtc();
    QWriteLocker locker(&rulesLock_);
    int removed = 0;
    for (auto it = rules_.begin(); it != rules_.end(); ) {
        if (it.value().isExpired(now)) { it = rules_.erase(it); ++removed; }
        else ++it;
    }
    if (removed > 0) rebuildIndexLocked();
    return removed;
}

void RuleEngine::addRule(const DefenseRule& rule) {
    {
        QString why;
        if (isUnsafeAllowRule(rule, &why)) {
            qWarning("[RuleEngine] 拒绝新增不安全的 Allow 规则:%s | note=%s",
                     qUtf8Printable(why), qUtf8Printable(rule.note));
            return;
        }
    }
    QWriteLocker locker(&rulesLock_);
    const bool replacing = rules_.contains(rule.id);
    rules_.insert(rule.id, rule);
    if (replacing) rebuildIndexLocked();
    else indexInsertLocked(rule);
}

bool RuleEngine::removeRule(const QUuid& id) {
    QWriteLocker locker(&rulesLock_);
    const bool removed = static_cast<bool>(rules_.remove(id));
    if (removed) rebuildIndexLocked();
    return removed;
}

void RuleEngine::appendDecisionEvidence(SecurityEvent& e, const Verdict& v) {
    QString action;
    switch (v.action) {
        case VerdictAction::Block: action = u("阻止"); break;
        case VerdictAction::Ask:   action = u("询问用户"); break;
        default:                   action = u("放行"); break;
    }
    QString source;
    switch (v.source) {
        case VerdictSource::Rule:          source = u("命中规则"); break;
        case VerdictSource::Heuristic:     source = u("行为研判"); break;
        case VerdictSource::TrustedSigner: source = u("可信放行"); break;
        case VerdictSource::UserPrompt:    source = u("用户裁决"); break;
        case VerdictSource::Timeout:       source = u("超时按默认策略"); break;
        case VerdictSource::Ai:            source = u("大模型裁决"); break;
        case VerdictSource::SharedIntel:   source = u("共享情报裁决"); break;
        default:                           source = u("默认策略"); break;
    }
    e.addEvidence(QStringLiteral("RuleEngine"), EvidenceKind::Decision,
        u("最终裁决:") + action + u("(依据:") + source + u(";风险分 ") +
        QString::number(e.riskScore) + u(")"), 0, false);
}

void RuleEngine::addCanaryFile(const QString& path) {
    QString p = path.trimmed().toLower();
    if (p.isEmpty()) return;
    p.replace(QLatin1Char('/'), QLatin1Char('\\'));
    QMutexLocker locker(&canaryLock_);
    canaryPaths_.insert(p);
}

bool RuleEngine::isCanaryTarget(const SecurityEvent& e) const {
    if (e.actorPid <= 0) return false;
    if (e.type != EventType::FileWrite && e.type != EventType::FileDelete) return false;
    QString target = e.target.toLower();
    target.replace(QLatin1Char('/'), QLatin1Char('\\'));
    if (target.isEmpty()) return false;
    QMutexLocker locker(&canaryLock_);
    return canaryPaths_.contains(target);
}

Verdict RuleEngine::evaluate(SecurityEvent& e) {
    const Verdict verdict = evaluateInternal(e);
    appendDecisionEvidence(e, verdict);
    AttackAnnotator::annotate(e);
    return verdict;
}

DefenseRule RuleEngine::createRuleFrom(SecurityEvent& e, VerdictAction action,
                                       std::optional<QDateTime> expiresUtc, bool sessionOnly) {
    DefenseRule rule;
    rule.actorPath = e.actorPath;
    rule.type = e.type;
    rule.targetPattern = e.target.isEmpty() ? QString() : e.target;
    rule.action = action;
    rule.expiresUtc = expiresUtc;
    rule.sessionOnly = sessionOnly;
    addRule(rule);
    return rule;
}

Verdict RuleEngine::evaluateInternal(SecurityEvent& e) {
    if (isSelfComponent(e)) {
        e.addEvidence(QStringLiteral("RuleEngine"), EvidenceKind::Trust, u("本软件自身组件,无条件放行"), 0, false);
        return Verdict::forEvent(e, VerdictAction::Allow, VerdictSource::TrustedSigner);
    }
    if (isSanctionedMaintenanceActor(e)) {
        e.addEvidence(QStringLiteral("RuleEngine"), EvidenceKind::Trust,
                      u("本软件自身的维护脚本(安装目录内),无条件放行"), 0, false);
        return Verdict::forEvent(e, VerdictAction::Allow, VerdictSource::TrustedSigner);
    }
    if (SelfProtection::enabled.load(std::memory_order_relaxed)
        && SelfProtection::commandTargetsProduct(e.commandLine)
        && isSanctionedMaintenanceDescendant(e)) {
        e.addEvidence(QStringLiteral("RuleEngine"), EvidenceKind::Trust,
                      u("本产品维护脚本派生的子进程(停止/卸载自身组件),放行"), 0, false);
        return Verdict::forEvent(e, VerdictAction::Allow, VerdictSource::TrustedSigner);
    }
    if (const std::optional<QString> trustNote = trustNoteForEvent(e)) {
        e.userTrusted = true;
        e.addEvidence(QStringLiteral("RuleEngine"), EvidenceKind::Trust,
                      u("用户信任放行,已跳过全部检测:") + *trustNote, 0, false);
        return Verdict::forEvent(e, VerdictAction::Allow, VerdictSource::Rule);
    }

    {
        const TrustDecision sec = TrustPolicy::isTrustedSecurityProduct(e);
        if (sec.ok) {
            e.addEvidence(QStringLiteral("TrustPolicy"), EvidenceKind::Trust, sec.reason, 0, false);
            return Verdict::forEvent(e, VerdictAction::Allow, VerdictSource::TrustedSigner);
        }
    }

    if (e.type == EventType::NetworkConnect || e.type == EventType::DnsQuery) {
        const TrustDecision app = TrustPolicy::isTrustedVendorApp(e);
        if (app.ok) {
            e.userTrusted = true;
            e.addEvidence(QStringLiteral("TrustPolicy"), EvidenceKind::Trust,
                          app.reason + u("(仅外联/DNS 维度)"), 0, false);
            return Verdict::forEvent(e, VerdictAction::Allow, VerdictSource::TrustedSigner);
        }
    }

    deobfuscateCommandLine(e);
    ThreatDetector::analyze(e);
    flagProductTampering(e);

    if (isCanaryTarget(e)) {
        e.hasThreatIndicator = true;
        e.riskScore = 100;
        e.addEvidence(QStringLiteral("RansomwareBehaviorMonitor"), EvidenceKind::HardIndicator,
                      u("触碰蜜罐诱饵文件(几乎可确认勒索/批量加密)"), 100);
        return Verdict::forEvent(e, VerdictAction::Block, VerdictSource::Heuristic);
    }

    if (e.type == EventType::FileWrite || e.type == EventType::FileDelete) {
        // 签名健康的主体即使触发也按误报抑制:对它只数数量,不去读它动过的文件。
        const bool trustedActor =
            e.actorSigned
            && ((!e.signatureMismatch && !e.certRevoked && !e.signedAfterCertExpiry)
                || TrustPolicy::isStronglyTrusted(e).ok);
        const RansomwareBehaviorMonitor::Result rm = ransomware_.observe(e, !trustedActor);
        if (rm.score > 0) {
            addMonitorSignal(e, "RansomwareBehaviorMonitor", rm.score, rm.reasons, false);
            if (trustedActor) {
                e.addEvidence(QStringLiteral("RansomwareBehaviorMonitor"), EvidenceKind::Trust,
                              u("主体签名健康,勒索行为特征按误报抑制(未触蜜罐诱饵)"), 0, false);
            } else {
                e.hasThreatIndicator = true;
                e.ransomwareContainmentRequired = rm.containmentRequired;
                if (rm.hardSignal || e.riskScore >= ThreatDetector::HighRisk)
                    return Verdict::forEvent(e, VerdictAction::Block, VerdictSource::Heuristic);
                e.addEvidence(QStringLiteral("RansomwareBehaviorMonitor"), EvidenceKind::Corroboration,
                              u("勒索行为达到临时收容阈值:先停止后续破坏,再由用户或策略裁决"), 0, false);
                return Verdict::forEvent(e, VerdictAction::Ask, VerdictSource::Heuristic);
            }
        }
    }

    if (e.type == EventType::NetworkConnect) {
        const NetworkBehaviorMonitor::Result nr = network_.observe(e);
        addMonitorSignal(e, "BeaconDetector", nr.beacon.score, nr.beacon.reasons, false);
        addMonitorSignal(e, "EgressRateMonitor", nr.fanout.score, nr.fanout.reasons, false);
    } else if (e.type == EventType::DnsQuery) {
        const ScoreResult d = DgaDomainAnalyzer::analyze(e.target);
        addMonitorSignal(e, "DgaDomainAnalyzer", d.score, d.reasons, false);
    }

    if (e.type == EventType::FileWrite || e.type == EventType::NetworkConnect
        || e.type == EventType::ProcessCreate) {
        const DownloaderBehaviorMonitor::Result dl = downloader_.observe(e);
        addMonitorSignal(e, "DownloaderBehaviorMonitor", dl.score, dl.reasons, dl.hardSignal);
    }

    if (e.type == EventType::ProcessCreate) {
        const CommandBurstMonitor::Result cb = bursts_.observe(e);
        addMonitorSignal(e, "KillChainAnalyzer", cb.discovery.score, cb.discovery.reasons, cb.discovery.hardSignal);
        addMonitorSignal(e, "KillChainAnalyzer", cb.serviceStop.score, cb.serviceStop.reasons,
                         cb.serviceStop.hardSignal);
    }

    if (enableBaseline) {
        const BaselineAnalyzer::Result bl = baseline_.observe(e);
        if (bl.deviation)
            addMonitorSignal(e, "BaselineAnalyzer", bl.score, bl.reasons, false);
    }

    {
        QVector<DefenseRule> matches;
        {
            const QString actorImageKey = imageKeyOfPath(e.actorPath);
            QReadLocker locker(&rulesLock_);
            const auto typed = byType_.constFind(static_cast<int>(e.type));
            if (typed != byType_.constEnd())
                collectMatches(typed.value(), actorImageKey, e, matches);
            collectMatches(typeAgnostic_, actorImageKey, e, matches);
        }
        // 内置放行规则只为降误报而设,不能替有硬指标的事件背书;用户自己的放行规则不受影响。
        if (!matches.isEmpty() && e.hasThreatIndicator) {
            const QString builtIn = DefaultRules::builtInTag();
            matches.erase(std::remove_if(matches.begin(), matches.end(),
                                         [&builtIn](const DefenseRule& r) {
                                             return r.action == VerdictAction::Allow
                                                 && r.note.startsWith(builtIn);
                                         }),
                          matches.end());
        }
        if (!matches.isEmpty()) {
            if (e.type == EventType::RemoteThread && !e.actorPath.isEmpty() && !e.target.isEmpty()
                && e.actorPath.compare(e.target, Qt::CaseInsensitive) == 0) {
                matches.erase(std::remove_if(matches.begin(), matches.end(),
                                             [](const DefenseRule& r) {
                                                 return r.note.contains(QStringLiteral("注入"));
                                             }),
                              matches.end());
            }
        }
        if (!matches.isEmpty()) {
            std::sort(matches.begin(), matches.end(), [](const DefenseRule& a, const DefenseRule& b) {
                const int ta = ruleTier(a), tb = ruleTier(b);
                if (ta != tb) return ta > tb;
                const int sa = specificity(a), sb = specificity(b);
                if (sa != sb) return sa > sb;
                const int pa = rulePriority(a.action), pb = rulePriority(b.action);
                if (pa != pb) return pa > pb;
                if (a.createdUtc != b.createdUtc) return a.createdUtc > b.createdUtc;
                return a.id < b.id;
            });
            const DefenseRule hit = matches.first();

            if (hit.exemptTrustedOsComponent) {
                const TrustDecision os = TrustPolicy::isTrustedOsComponent(e);
                if (os.ok) {
                    e.addEvidence(QStringLiteral("TrustPolicy"), EvidenceKind::Trust, os.reason);
                    return Verdict::forEvent(e, VerdictAction::Allow, VerdictSource::TrustedSigner);
                }
            }
            // 规则不让签名程序免问时,签名的开发工具也不免。
            if (hit.action == VerdictAction::Ask && !hit.disableDevToolAutoAllow
                && !hit.disableSignedAutoAllow
                && devToolExemptionApplies(e.type)
                && e.actorSigned && !e.signatureMismatch && !e.certRevoked
                && !e.signedAfterCertExpiry && !e.hasThreatIndicator && e.riskScore < 60
                && DefaultRules::isDevTool(e.actorPath)) {
                e.addEvidence(QStringLiteral("RuleEngine"), EvidenceKind::Trust,
                              u("健康签名开发工具的低风险行为自动放行"));
                return Verdict::forEvent(e, VerdictAction::Allow, VerdictSource::TrustedSigner);
            }
            e.matchedRuleNote = hit.note;
            e.matchedRuleIdentifiesSubject = hit.identifiesSubject();
            e.matchedRuleDisablesSignedAutoAllow = hit.disableSignedAutoAllow;
            e.matchedRuleUsageOnly = hit.actorPath.isEmpty() && hit.actorPattern.isEmpty()
                                  && hit.actorHashes.isEmpty()
                                  && (!hit.commandLinePattern.isEmpty() || !hit.parentPattern.isEmpty());
            const QString actionName = hit.action == VerdictAction::Block ? QStringLiteral("Block")
                                     : hit.action == VerdictAction::Ask ? QStringLiteral("Ask")
                                     : QStringLiteral("Allow");
            // 规则靠还原后的文本命中时要说清这一点:否则界面上显示的命令行与命中的
            // 判据对不上,一条真命中会被用户当成误报。只在原文确实不命中时才记。
            if (!hit.commandLinePattern.isEmpty()
                && !DefenseRule::wildcardMatch(hit.commandLinePattern, e.commandLine))
                reportCommandDeobfuscation(e, u("该规则命中的是还原后的命令行"));
            e.addEvidence(QStringLiteral("RuleEngine"), EvidenceKind::Rule,
                u("命中规则:") + (hit.note.isEmpty() ? actionName : hit.note), 0, false);
            // 询问规则只表达「至少要问」:不命中规则时会被拦下的事件,命中询问规则后不能反而只问。
            if (hit.action == VerdictAction::Ask && e.hasThreatIndicator
                && e.riskScore >= ThreatDetector::HighRisk) {
                e.addEvidence(QStringLiteral("RuleEngine"), EvidenceKind::Corroboration,
                              u("规则判询问,但行为硬指标已达高危线,按阻止处理"), 0, false);
                return Verdict::forEvent(e, VerdictAction::Block, VerdictSource::Heuristic);
            }
            return Verdict::forEvent(e, hit.action, VerdictSource::Rule);
        }
    }

    if (trustSignedActors) {
        const TrustDecision t = TrustPolicy::isStronglyTrusted(e);
        if (t.ok) {
            e.addEvidence(QStringLiteral("TrustPolicy"), EvidenceKind::Trust, t.reason);
            return Verdict::forEvent(e, VerdictAction::Allow, VerdictSource::TrustedSigner);
        }
        const TrustDecision h = TrustPolicy::isHealthySigned(e);
        if (h.ok) {
            e.addEvidence(QStringLiteral("TrustPolicy"), EvidenceKind::Trust, h.reason);
            return Verdict::forEvent(e, VerdictAction::Allow, VerdictSource::TrustedSigner);
        }
    }

    if (e.hasThreatIndicator) {
        return e.riskScore >= ThreatDetector::HighRisk
            ? Verdict::forEvent(e, VerdictAction::Block, VerdictSource::Heuristic)
            : Verdict::forEvent(e, VerdictAction::Ask, VerdictSource::Heuristic);
    }

    // 只有弱信号时永不拦截。
    if (e.type == EventType::NetworkConnect && !e.actorSigned
        && ThreatDetector::isSuspiciousDropDir(e.actorPath)) {
        const bool beacon = std::any_of(e.evidenceChain.cbegin(), e.evidenceChain.cend(), [](const Evidence& ev) {
            return ev.source == QLatin1String("BeaconDetector") && ev.scoreDelta > 0;
        });
        if (beacon) {
            e.addEvidence(QStringLiteral("RuleEngine"), EvidenceKind::SoftSignal,
                          u("未签名程序从用户可写目录发出短周期规整外联,转询问"), 0);
            return Verdict::forEvent(e, VerdictAction::Ask, VerdictSource::Heuristic);
        }
    }
    // 单个分析器自己就能把分数叠满(超大的未签名安装包:未签名 + 体积 + 目录),
    // 要两个以上互相独立的分析器同时举证才问。
    if (!e.actorSigned && e.riskScore >= ThreatDetector::HighRisk) {
        QSet<QString> sources;
        for (const Evidence& ev : e.evidenceChain)
            if (ev.kind == EvidenceKind::SoftSignal && ev.scoreDelta > 0)
                sources.insert(ev.source);
        if (sources.size() >= 2) {
            e.addEvidence(QStringLiteral("RuleEngine"), EvidenceKind::SoftSignal,
                          u("%1 个独立分析器的弱信号互证并达到高危线(未签名、无硬指标),转询问")
                              .arg(sources.size()),
                          0);
            return Verdict::forEvent(e, VerdictAction::Ask, VerdictSource::Heuristic);
        }
    }

    if (e.actorSigned) {
        const TrustDecision bn = TrustPolicy::isBenignSigner(e);
        if (bn.ok)
            e.addEvidence(QStringLiteral("TrustPolicy"), EvidenceKind::Trust, bn.reason);
    }

    return Verdict::forEvent(e, VerdictAction::Allow, VerdictSource::DefaultPolicy);
}

}
