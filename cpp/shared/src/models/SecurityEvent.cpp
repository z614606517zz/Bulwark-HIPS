#include "bulwark/models/SecurityEvent.h"
#include "bulwark/json/JsonSupport.h"
#include <QJsonArray>
#include <QSet>
#include <utility>

namespace bulwark {
using namespace bulwark::json;

void SecurityEvent::addEvidence(const QString& source, EvidenceKind kind,
                                const QString& description, int scoreDelta,
                                bool alsoReason, EvidenceSubject subject) {
    Evidence e;
    e.timestampUtc = nowUtc();
    e.source = source;
    e.kind = kind;
    e.description = description;
    e.scoreDelta = scoreDelta;
    e.subject = subject;
    evidenceChain.push_back(e);
    if (alsoReason && !description.isEmpty() && !riskReasons.contains(description))
        riskReasons << description;
}

bool SecurityEvent::addSnippet(const ThreatSnippet& s) {
    if (s.isEmpty() || threatSnippets.size() >= ThreatSnippet::kMaxSnippets)
        return false;
    for (const ThreatSnippet& have : threatSnippets)
        if (have.sameAs(s))
            return false;
    threatSnippets.push_back(s);
    return true;
}

bool SecurityEvent::isMemoryCarrierFinding() const {
    return memoryInjection && userModeObserved
           && target.startsWith(QLatin1String("PID "), Qt::CaseInsensitive);
}

QString SecurityEvent::processInstanceKey() const {
    QString key = QString::number(actorPid);
    if (actorCreationFileTime.has_value())
        return key + QLatin1Char('@') + QString::number(*actorCreationFileTime);

    QString path = actorPath.trimmed().toLower();
    path.replace(QLatin1Char('/'), QLatin1Char('\\'));
    return key + QLatin1Char('|') + path;
}

namespace {

struct HardEvidenceGroup {
    QSet<QString> sources;
    QSet<QString> techniques;
};

int independentHardEvidenceGroups(const QVector<Evidence>& evidence, bool actorOnly) {
    QVector<HardEvidenceGroup> groups;
    for (const Evidence& ev : evidence) {
        if (ev.kind != EvidenceKind::HardIndicator)
            continue;
        if (actorOnly && ev.subject != EvidenceSubject::Actor)
            continue;

        const QString source = ev.source.trimmed().isEmpty()
            ? QStringLiteral("(unknown)") : ev.source.trimmed();
        const QString technique = ev.technique.trimmed().toUpper();
        QVector<int> hits;
        for (int i = 0; i < groups.size(); ++i) {
            if (groups.at(i).sources.contains(source)
                || (!technique.isEmpty() && groups.at(i).techniques.contains(technique))) {
                hits.append(i);
            }
        }

        if (hits.isEmpty()) {
            HardEvidenceGroup g;
            g.sources.insert(source);
            if (!technique.isEmpty()) g.techniques.insert(technique);
            groups.append(std::move(g));
            continue;
        }

        const int base = hits.first();
        groups[base].sources.insert(source);
        if (!technique.isEmpty()) groups[base].techniques.insert(technique);
        for (int h = hits.size() - 1; h >= 1; --h) {
            const int idx = hits.at(h);
            groups[base].sources.unite(groups.at(idx).sources);
            groups[base].techniques.unite(groups.at(idx).techniques);
            groups.removeAt(idx);
        }
    }
    return groups.size();
}

}

bool SecurityEvent::hasActorHardIndicator() const {
    for (const Evidence& ev : evidenceChain) {
        if (ev.kind == EvidenceKind::HardIndicator && ev.subject == EvidenceSubject::Actor)
            return true;
    }
    return false;
}

int SecurityEvent::actorHardEvidenceSourceCount() const {
    return independentHardEvidenceGroups(evidenceChain, true);
}

int SecurityEvent::hardEvidenceGroupCount() const {
    return independentHardEvidenceGroups(evidenceChain, false);
}

QString SecurityEvent::originLabel() const {
    switch (originKind) {
        case ProcessOriginKind::Service: {
            if (originService.isEmpty())
                return QString::fromUtf8("服务");
            QString s = QString::fromUtf8("服务:") + originService;
            if (!originServiceDisplay.isEmpty()
                && originServiceDisplay.compare(originService, Qt::CaseInsensitive) != 0)
                s += QStringLiteral(" (") + originServiceDisplay + QLatin1Char(')');
            return s;
        }
        case ProcessOriginKind::ScheduledTask:
            return originTask.isEmpty() ? QString::fromUtf8("计划任务")
                                        : QString::fromUtf8("计划任务:") + originTask;
        case ProcessOriginKind::WmiProvider:    return QString::fromUtf8("WMI 提供者宿主派生");
        case ProcessOriginKind::LogonAutostart: return QString::fromUtf8("登录自启动");
        case ProcessOriginKind::SystemBoot:     return QString::fromUtf8("系统启动");
        case ProcessOriginKind::Interactive:    return QString::fromUtf8("交互式启动");
        case ProcessOriginKind::Unknown:        break;
    }
    return QString();
}

QJsonObject SecurityEvent::toJson() const {
    QJsonObject o;
    o["id"] = guidToString(id);
    o["timestampUtc"] = dateTimeToIso(timestampUtc);
    o["type"] = static_cast<int>(type);

    o["actorPid"] = actorPid;
    o["actorPath"] = actorPath;
    o["actorHash"] = actorHash;
    o["actorSigned"] = actorSigned;
    o["signatureMismatch"] = signatureMismatch;
    o["signatureTampered"] = signatureTampered;
    o["actorFileSize"] = actorFileSize;
    o["actorPublisher"] = actorPublisher;
    o["actorCertThumbprint"] = actorCertThumbprint;
    o["certNotAfterUtc"] = optDateToJson(certNotAfterUtc);
    o["signingTimeUtc"] = optDateToJson(signingTimeUtc);
    o["certRevoked"] = certRevoked;
    o["signedAfterCertExpiry"] = signedAfterCertExpiry;
    o["isFirstSeen"] = isFirstSeen;

    o["originatorPid"] = originatorPid;
    o["originatorPath"] = originatorPath;
    o["parentPid"] = parentPid;
    o["parentPath"] = parentPath;
    if (creatorPid > 0) o["creatorPid"] = creatorPid;
    if (spoofedParentPid > 0) {
        o["spoofedParentPid"] = spoofedParentPid;
        o["spoofedParentPath"] = spoofedParentPath;
    }
    if (actorImageMissing) o["actorImageMissing"] = true;
    if (actorImageFlags != 0) o["actorImageFlags"] = actorImageFlags;
    if (originKind != ProcessOriginKind::Unknown) o["originKind"] = static_cast<int>(originKind);
    if (!originService.isEmpty())        o["originService"] = originService;
    if (!originServiceDisplay.isEmpty()) o["originServiceDisplay"] = originServiceDisplay;
    if (!originTask.isEmpty())           o["originTask"] = originTask;
    if (!originDetail.isEmpty())         o["originDetail"] = originDetail;
    o["commandLine"] = commandLine;
    o["target"] = target;
    o["detail"] = detail;
    if (registryOp != RegistryOperation::Unknown)
        o["registryOp"] = registryOperationToString(registryOp);
    if (hasRegistryDword) {
        o["hasRegistryDword"] = true;
        o["registryDwordValue"] = static_cast<double>(registryDwordValue);
    }
    if (!correlationId.isEmpty()) o["correlationId"] = correlationId;
    o["targetSigned"] = targetSigned;
    o["targetSignatureMismatch"] = targetSignatureMismatch;

    o["riskScore"] = riskScore;
    o["riskReasons"] = strListToJson(riskReasons);

    QJsonArray ev;
    for (const Evidence& e : evidenceChain) ev.append(e.toJson());
    o["evidenceChain"] = ev;

    o["techniques"] = strListToJson(techniques);
    o["hasThreatIndicator"] = hasThreatIndicator;
    o["matchedRuleNote"] = matchedRuleNote;
    o["userModeObserved"] = userModeObserved;
    o["kernelBlocked"] = kernelBlocked;
    o["memoryInjection"] = memoryInjection;
    if (fileCreatedNew) o["fileCreatedNew"] = true;
    if (isInstaller) o["isInstaller"] = true;
    o["fileDescription"] = fileDescription;
    if (!originalFileName.isEmpty()) o["originalFileName"] = originalFileName;
    if (yaraLevel != YaraNone) {
        o["yaraLevel"] = yaraLevel;
        o["yaraRule"] = yaraRule;
        o["yaraAuthor"] = yaraAuthor;
        o["yaraMatchCount"] = yaraMatchCount;
    }
    if (!threatSnippets.isEmpty()) {
        QJsonArray sn;
        for (const ThreatSnippet& s : threatSnippets) sn.append(s.toJson());
        o["threatSnippets"] = sn;
    }

    QJsonArray chain;
    for (const ChainEventInfo& c : chainContext) chain.append(c.toJson());
    o["chainContext"] = chain;
    return o;
}

SecurityEvent SecurityEvent::fromJson(const QJsonObject& o) {
    SecurityEvent e;
    const QUuid parsedId = guidFromString(getStr(o, "id"));
    if (!parsedId.isNull()) e.id = parsedId;
    const QDateTime ts = dateTimeFromIso(getStr(o, "timestampUtc"));
    if (ts.isValid()) e.timestampUtc = ts;
    e.type = static_cast<EventType>(getInt(o, "type"));

    e.actorPid = getInt(o, "actorPid");
    e.actorPath = getStr(o, "actorPath");
    e.actorHash = getStr(o, "actorHash");
    e.actorSigned = getBool(o, "actorSigned");
    e.signatureMismatch = getBool(o, "signatureMismatch");
    e.signatureTampered = getBool(o, "signatureTampered");
    e.actorFileSize = getI64(o, "actorFileSize");
    e.actorPublisher = getStr(o, "actorPublisher");
    e.actorCertThumbprint = getStr(o, "actorCertThumbprint");
    e.certNotAfterUtc = optDateFromJson(o.value(QLatin1String("certNotAfterUtc")));
    e.signingTimeUtc = optDateFromJson(o.value(QLatin1String("signingTimeUtc")));
    e.certRevoked = getBool(o, "certRevoked");
    e.signedAfterCertExpiry = getBool(o, "signedAfterCertExpiry");
    e.isFirstSeen = getBool(o, "isFirstSeen");

    e.originatorPid = getInt(o, "originatorPid");
    e.originatorPath = getStr(o, "originatorPath");
    e.parentPid = getInt(o, "parentPid");
    e.parentPath = getStr(o, "parentPath");
    e.creatorPid = getInt(o, "creatorPid");
    e.spoofedParentPid = getInt(o, "spoofedParentPid");
    e.spoofedParentPath = getStr(o, "spoofedParentPath");
    e.actorImageMissing = getBool(o, "actorImageMissing");
    e.actorImageFlags = getInt(o, "actorImageFlags");
    e.originKind = static_cast<ProcessOriginKind>(getInt(o, "originKind", 0));
    e.originService = getStr(o, "originService");
    e.originServiceDisplay = getStr(o, "originServiceDisplay");
    e.originTask = getStr(o, "originTask");
    e.originDetail = getStr(o, "originDetail");
    e.commandLine = getStr(o, "commandLine");
    e.target = getStr(o, "target");
    e.detail = getStr(o, "detail");
    e.registryOp = registryOperationFromString(getStr(o, "registryOp"));
    e.hasRegistryDword = getBool(o, "hasRegistryDword");
    if (e.hasRegistryDword)
        e.registryDwordValue = static_cast<quint32>(o.value(QLatin1String("registryDwordValue")).toDouble());
    e.correlationId = getStr(o, "correlationId");
    e.targetSigned = getBool(o, "targetSigned");
    e.targetSignatureMismatch = getBool(o, "targetSignatureMismatch");

    e.riskScore = getInt(o, "riskScore");
    e.riskReasons = getStrList(o, "riskReasons");

    const QJsonArray ev = o.value(QLatin1String("evidenceChain")).toArray();
    e.evidenceChain.reserve(ev.size());
    for (const QJsonValue& v : ev) e.evidenceChain.push_back(Evidence::fromJson(v.toObject()));

    e.techniques = getStrList(o, "techniques");
    e.hasThreatIndicator = getBool(o, "hasThreatIndicator");
    e.matchedRuleNote = getStr(o, "matchedRuleNote");
    e.userModeObserved = getBool(o, "userModeObserved");
    e.kernelBlocked = getBool(o, "kernelBlocked");
    e.memoryInjection = getBool(o, "memoryInjection");
    e.fileCreatedNew = getBool(o, "fileCreatedNew");
    e.isInstaller = getBool(o, "isInstaller");
    e.fileDescription = getStr(o, "fileDescription");
    e.originalFileName = getStr(o, "originalFileName");
    e.yaraLevel = qBound(static_cast<int>(YaraNone), getInt(o, "yaraLevel"), static_cast<int>(YaraMalicious));
    e.yaraRule = getStr(o, "yaraRule");
    e.yaraAuthor = getStr(o, "yaraAuthor");
    e.yaraMatchCount = getInt(o, "yaraMatchCount");
    for (const QJsonValue& v : o.value(QLatin1String("threatSnippets")).toArray())
        e.addSnippet(ThreatSnippet::fromJson(v.toObject()));

    const QJsonArray chain = o.value(QLatin1String("chainContext")).toArray();
    e.chainContext.reserve(chain.size());
    for (const QJsonValue& v : chain) e.chainContext.push_back(ChainEventInfo::fromJson(v.toObject()));
    return e;
}

}
