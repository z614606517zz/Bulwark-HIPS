#include "bulwark/models/DefenseRule.h"
#include "bulwark/models/SecurityEvent.h"
#include "bulwark/json/JsonSupport.h"
#include "bulwark/Clock.h"
#include "bulwark/engine/NetworkEndpoint.h"
#include <QJsonArray>

namespace bulwark {
using namespace bulwark::json;

QString DefenseRule::trustNoteTag() {
    return QStringLiteral("[\u4fe1\u4efb]");
}

namespace {

QString parentDirectoryOf(const QString& path) {
    QString p = path.trimmed();
    p.replace(QLatin1Char('/'), QLatin1Char('\\'));
    const qsizetype slash = p.lastIndexOf(QLatin1Char('\\'));
    return slash > 0 ? p.left(slash) : QString();
}

bool sameParentDirectory(const QString& a, const QString& b) {
    const QString dir = parentDirectoryOf(a);
    return !dir.isEmpty() && dir.compare(parentDirectoryOf(b), Qt::CaseInsensitive) == 0;
}

}

bool DefenseRule::matches(const SecurityEvent& e) const {
    if (!enabled) return false;
    if (expiresUtc.has_value() && *expiresUtc <= nowUtc()) return false;

    if (type.has_value() && *type != e.type) return false;

    const bool judgeModule = (e.type == EventType::ImageLoad && e.actorPid > 0);
    const bool sigPresent = judgeModule ? e.targetSigned : e.actorSigned;
    const bool sigUnhealthy = judgeModule
                                  ? e.targetSignatureMismatch
                                  : (e.signatureMismatch || e.certRevoked ||
                                     e.signedAfterCertExpiry);

    if (requireUnsigned && sigPresent) return false;
    if (requireSigned && (!sigPresent || sigUnhealthy)) return false;

    // 注册表方向过滤:规则可只对「设值」或只对「删值/删键」生效。
    // 事件方向为 Unknown(ETW / 用户态行为源未提供)时不参与过滤,避免误杀。
    // 整棵恢复一次写下任意值,对只认「设值」的规则按设值算。只认恢复的规则必须真看到恢复:
    // 它的目标往往是整棵子树,沿用 Unknown 放行会让每条来源不明的注册表事件都命中。
    if (requireRegOp.has_value()) {
        const RegistryOperation op = e.registryOp;
        if (*requireRegOp == RegistryOperation::RestoreKey) {
            if (op != RegistryOperation::RestoreKey)
                return false;
        } else if (op != RegistryOperation::Unknown && *requireRegOp != op
                   && !(*requireRegOp == RegistryOperation::SetValue
                        && op == RegistryOperation::RestoreKey)) {
            return false;
        }
    }

    // REG_DWORD 值过滤:区分「设 0 加固」与「设 1 削弱」。
    // 值不可得(旧驱动 / 非 REG_DWORD)时不参与过滤,避免漏检。
    if (requireRegDword.has_value() && e.hasRegistryDword
        && *requireRegDword != e.registryDwordValue)
        return false;

    if (requireTargetUnsigned && e.targetSigned) return false;
    if (requireTargetSigned && (!e.targetSigned || e.targetSignatureMismatch)) return false;

    if (requireHostSigned &&
        (!e.actorSigned || e.signatureMismatch || e.certRevoked || e.signedAfterCertExpiry))
        return false;

    if (requireTargetBesideActor && !sameParentDirectory(e.target, e.actorPath))
        return false;

    if (exemptRemovableTarget && e.targetOnRemovableMedia)
        return false;

    if (!actorHashes.isEmpty()) {
        if (e.actorHash.isEmpty()) return false;
        const QString h = e.actorHash.toUpper();
        bool found = false;
        for (const QString& x : actorHashes) {
            if (x.toUpper() == h) { found = true; break; }
        }
        if (!found) return false;
    }

    if (!actorPath.isEmpty() &&
        actorPath.compare(e.actorPath, Qt::CaseInsensitive) != 0)
        return false;

    if (!actorPattern.isEmpty() && !wildcardMatch(actorPattern, e.actorPath))
        return false;

    if (!commandLinePattern.isEmpty() && !matchesCommandLine(e))
        return false;

    if (!parentPattern.isEmpty() && !wildcardMatch(parentPattern, e.parentPath))
        return false;

    if (type.has_value() && *type == EventType::RemoteThread
        && targetPattern.isEmpty() && e.isMemoryCarrierFinding())
        return false;

    if (!targetPattern.isEmpty()) {
        bool matchTarget = wildcardMatch(targetPattern, e.target);
        if (!matchTarget && e.type == EventType::NetworkConnect) {
            const auto expected = engine::NetworkEndpoint::parse(targetPattern);
            const auto actual = engine::NetworkEndpoint::parse(e.target);
            if (expected && actual && expected->address == actual->address
                && (expected->port == 0 || expected->port == actual->port)) matchTarget = true;
        }
        const bool allowActorFallback = (e.type == EventType::ProcessCreate);
        const bool matchActor = allowActorFallback && !e.actorPath.isEmpty() &&
                                wildcardMatch(targetPattern, e.actorPath);
        if (!matchTarget && !matchActor) return false;
    }

    return true;
}

bool DefenseRule::matchesCommandLine(const SecurityEvent& e) const {
    if (wildcardMatch(commandLinePattern, e.commandLine))
        return true;

    // 还原后的文本只用来扩大拦截 / 询问面,放行规则永远只看原文:否则攻击者可以把命令行写成
    // 还原后正好命中某条放行规则的形状,而规则排序先看 tier 与 specificity(见 RuleEngine::ruleTier / rulePriority),
    // 命中的放行规则可能盖掉 Block 规则。反方向最坏是误报,由 fp-* 回归哨兵与语料兜住。
    if (action == VerdictAction::Allow)
        return false;

    if (!e.normalizedCommandLine.isEmpty()
        && wildcardMatch(commandLinePattern, e.normalizedCommandLine))
        return true;

    // 规整形态:模式里的空格是字面量,`sc  stop X`、`sc<Tab>stop X`、`"sc" stop X` 不规整就对不上 `*sc stop *`。
    // 两份都比:模式本身带引号的(`*.creationtime = '*`)要靠保留引号的那一份。
    for (const QString& form : e.canonicalCommandLines)
        if (wildcardMatch(commandLinePattern, form))
            return true;

    for (const QString& block : e.decodedCommandBlocks)
        if (wildcardMatch(commandLinePattern, block))
            return true;

    return false;
}

int DefenseRule::specificityScore() const {
    int s = 0;
    if (!actorPath.isEmpty()) s += 3;
    if (!actorPattern.isEmpty()) s += 2;
    if (!commandLinePattern.isEmpty()) s += 2;
    if (!parentPattern.isEmpty()) s += 2;
    if (!targetPattern.isEmpty()) s += 1;
    if (type.has_value()) s += 1;
    if (requireUnsigned) s += 1;
    if (requireSigned) s += 1;
    if (requireTargetUnsigned) s += 1;
    if (requireTargetSigned) s += 1;
    if (requireHostSigned) s += 1;
    if (requireTargetBesideActor) s += 1;
    if (requireRegOp.has_value()) s += 1;
    if (!actorHashes.isEmpty()) s += 4;
    return s;
}

bool DefenseRule::identifiesSubject() const {
    if (!actorHashes.isEmpty())
        return true;
    if (!actorPath.trimmed().isEmpty())
        return true;
    const QString p = actorPattern.trimmed();
    if (!p.isEmpty() && !p.contains(QLatin1Char('*')) && !p.contains(QLatin1Char('?')))
        return true;
    return false;
}

DefenseRule DefenseRule::createTrust(const QString& actorPath, const QString& note) {
    DefenseRule r;
    r.actorPath = actorPath.trimmed();
    r.type = std::nullopt;
    r.action = VerdictAction::Allow;
    const QString n = note.trimmed();
    r.note = n.isEmpty() ? (trustNoteTag() + QStringLiteral(" \u6587\u4ef6\u4fe1\u4efb\u4e2d\u5fc3"))
                         : (trustNoteTag() + QStringLiteral(" ") + n);
    return r;
}

DefenseRule DefenseRule::createTrustDirectory(const QString& dirPath, const QString& note) {
    DefenseRule r;
    QString d = dirPath.trimmed();
    while (d.endsWith(QLatin1Char('\\')) || d.endsWith(QLatin1Char('/'))) d.chop(1);
    r.actorPattern = d + QStringLiteral("\\*");
    r.type = std::nullopt;
    r.action = VerdictAction::Allow;
    const QString n = note.trimmed();
    r.note = n.isEmpty() ? (trustNoteTag() + QStringLiteral(" \u76ee\u5f55\u4fe1\u4efb: ") + d)
                         : (trustNoteTag() + QStringLiteral(" ") + n);
    return r;
}

namespace {

inline char16_t foldUpper(char16_t c)
{
    if (c < 0x80)
        return (c >= u'a' && c <= u'z') ? static_cast<char16_t>(c - 0x20) : c;
    return QChar(c).toUpper().unicode();
}

}

bool DefenseRule::wildcardMatch(const QString& pattern, const QString& input) {
    if (pattern.isEmpty()) return true;
    const qsizetype pl = pattern.size();
    const qsizetype sl = input.size();
    const char16_t* pd = reinterpret_cast<const char16_t*>(pattern.constData());
    const char16_t* sd = reinterpret_cast<const char16_t*>(input.constData());
    qsizetype p = 0, s = 0, star = -1, mark = 0;
    while (s < sl) {
        if (p < pl && (pd[p] == u'?' || foldUpper(pd[p]) == foldUpper(sd[s]))) {
            ++p; ++s;
        } else if (p < pl && pd[p] == u'*') {
            star = p++; mark = s;
        } else if (star != -1) {
            p = star + 1; s = ++mark;
        } else {
            return false;
        }
    }
    while (p < pl && pd[p] == u'*') ++p;
    return p == pl;
}

QJsonObject DefenseRule::toJson() const {
    QJsonObject o;
    o["id"] = guidToString(id);
    o["actorPath"] = actorPath;
    o["actorPattern"] = actorPattern;
    o["type"] = type.has_value() ? QJsonValue(static_cast<int>(*type))
                                 : QJsonValue(QJsonValue::Null);
    o["targetPattern"] = targetPattern;
    o["commandLinePattern"] = commandLinePattern;
    o["parentPattern"] = parentPattern;
    o["requireUnsigned"] = requireUnsigned;
    o["requireSigned"] = requireSigned;
    o["requireTargetUnsigned"] = requireTargetUnsigned;
    o["requireTargetSigned"] = requireTargetSigned;
    if (requireRegOp.has_value())
        o["requireRegOp"] = registryOperationToString(*requireRegOp);
    if (requireRegDword.has_value())
        o["requireRegDword"] = static_cast<double>(*requireRegDword);
    o["exemptTrustedOsComponent"] = exemptTrustedOsComponent;
    o["hardOverride"] = hardOverride;
    if (disableDevToolAutoAllow) o["disableDevToolAutoAllow"] = true;
    if (requireHostSigned) o["requireHostSigned"] = true;
    if (requireTargetBesideActor) o["requireTargetBesideActor"] = true;
    if (exemptRemovableTarget) o["exemptRemovableTarget"] = true;
    if (disableSignedAutoAllow) o["disableSignedAutoAllow"] = true;
    QJsonArray hashes;
    for (const QString& h : actorHashes) hashes.append(h);
    o["actorHashes"] = hashes;
    o["action"] = static_cast<int>(action);
    o["note"] = note;
    o["createdUtc"] = dateTimeToIso(createdUtc);
    o["expiresUtc"] = optDateToJson(expiresUtc);
    o["sessionOnly"] = sessionOnly;
    o["enabled"] = enabled;
    return o;
}

DefenseRule DefenseRule::fromJson(const QJsonObject& o) {
    DefenseRule r;
    bool invalidEnum = false;
    const QUuid parsedId = guidFromString(getStr(o, "id"));
    if (!parsedId.isNull()) r.id = parsedId;
    r.actorPath = getStr(o, "actorPath");
    r.actorPattern = getStr(o, "actorPattern");
    const QJsonValue tv = o.value(QLatin1String("type"));
    if (tv.isDouble()) {
        const int rawType = tv.toInt(-1);
        if (rawType >= static_cast<int>(EventType::ProcessCreate)
            && rawType <= static_cast<int>(EventType::RemoteShareAccess))
            r.type = static_cast<EventType>(rawType);
        else
            invalidEnum = true;
    } else {
        r.type = std::nullopt;
    }
    r.targetPattern = getStr(o, "targetPattern");
    r.commandLinePattern = getStr(o, "commandLinePattern");
    r.parentPattern = getStr(o, "parentPattern");
    r.requireUnsigned = getBool(o, "requireUnsigned");
    r.requireSigned = getBool(o, "requireSigned");
    r.requireTargetUnsigned = getBool(o, "requireTargetUnsigned");
    r.requireTargetSigned = getBool(o, "requireTargetSigned");
    {
        const RegistryOperation op = registryOperationFromString(getStr(o, "requireRegOp"));
        if (op != RegistryOperation::Unknown)
            r.requireRegOp = op;
    }
    if (o.contains(QLatin1String("requireRegDword")))
        r.requireRegDword = static_cast<quint32>(o.value(QLatin1String("requireRegDword")).toDouble());
    r.requireHostSigned = getBool(o, "requireHostSigned");
    r.requireTargetBesideActor = getBool(o, "requireTargetBesideActor");
    r.exemptRemovableTarget = getBool(o, "exemptRemovableTarget");
    r.exemptTrustedOsComponent = getBool(o, "exemptTrustedOsComponent");
    r.hardOverride = getBool(o, "hardOverride");
    r.disableDevToolAutoAllow = getBool(o, "disableDevToolAutoAllow");
    r.disableSignedAutoAllow = getBool(o, "disableSignedAutoAllow");
    r.actorHashes.clear();
    const QJsonArray hashes = o.value(QLatin1String("actorHashes")).toArray();
    for (const QJsonValue& v : hashes) {
        const QString h = v.toString();
        if (!h.isEmpty()) r.actorHashes.insert(h);
    }
    const int rawAction = getInt(o, "action", static_cast<int>(VerdictAction::Ask));
    if (rawAction >= static_cast<int>(VerdictAction::Allow)
        && rawAction <= static_cast<int>(VerdictAction::Ask)) {
        r.action = static_cast<VerdictAction>(rawAction);
    } else {
        r.action = VerdictAction::Ask;
        invalidEnum = true;
    }
    r.note = getStr(o, "note");
    const QDateTime c = dateTimeFromIso(getStr(o, "createdUtc"));
    if (c.isValid()) r.createdUtc = c;
    r.expiresUtc = optDateFromJson(o.value(QLatin1String("expiresUtc")));
    r.sessionOnly = getBool(o, "sessionOnly");
    r.enabled = getBool(o, "enabled", true) && !invalidEnum;
    return r;
}

}
