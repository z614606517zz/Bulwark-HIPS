#include "bulwark/ipc/Payloads.h"
#include "bulwark/json/JsonSupport.h"

#include <QJsonArray>

namespace bulwark::ipc {

QJsonObject HelloPayload::toJson() const {
    QJsonObject o;
    o["processId"] = processId;
    o["role"] = role;
    return o;
}

HelloPayload HelloPayload::fromJson(const QJsonObject& o) {
    using namespace bulwark::json;
    HelloPayload h;
    h.processId = getInt(o, "processId");
    h.role = o.contains(QLatin1String("role")) ? getStr(o, "role") : QStringLiteral("ui");
    return h;
}

QJsonObject PromptResponsePayload::toJson() const {
    using namespace bulwark::json;
    QJsonObject o;
    o["eventId"] = guidToString(eventId);
    o["action"] = static_cast<int>(action);
    o["remember"] = remember;
    o["scope"] = static_cast<int>(scope);
    if (autoTimeout)
        o["autoTimeout"] = true;   // 仅为真时才写:线上形态与加入该字段之前逐字一致
    return o;
}

PromptResponsePayload PromptResponsePayload::fromJson(const QJsonObject& o) {
    using namespace bulwark::json;
    PromptResponsePayload p;
    p.eventId = guidFromString(getStr(o, "eventId"));
    p.action = static_cast<VerdictAction>(getInt(o, "action", 0));
    p.remember = getBool(o, "remember");
    p.scope = static_cast<RememberScope>(getInt(o, "scope", 0));
    p.autoTimeout = getBool(o, "autoTimeout");
    return p;
}

QJsonObject BlockNotificationPayload::toJson() const {
    QJsonObject o = event.toJson();
    o["enforcement"] = static_cast<int>(enforcement);
    if (timeoutBlock)
        o["timeoutBlock"] = true;
    if (execBlocked)
        o["execBlocked"] = true;
    return o;
}

BlockNotificationPayload BlockNotificationPayload::fromJson(const QJsonObject& o) {
    using namespace bulwark::json;
    BlockNotificationPayload p;
    p.event = bulwark::SecurityEvent::fromJson(o);
    p.enforcement = static_cast<bulwark::EnforcementOutcome>(
        getInt(o, "enforcement", static_cast<int>(bulwark::EnforcementOutcome::NotApplicable)));
    p.timeoutBlock = getBool(o, "timeoutBlock");
    p.execBlocked = getBool(o, "execBlocked");
    return p;
}

QJsonObject EventLogPayload::toJson() const {
    QJsonObject o;
    o["event"] = event.toJson();
    o["action"] = static_cast<int>(action);
    o["source"] = static_cast<int>(source);
    o["enforcement"] = static_cast<int>(enforcement);
    return o;
}

EventLogPayload EventLogPayload::fromJson(const QJsonObject& o) {
    using namespace bulwark::json;
    EventLogPayload p;
    p.event = bulwark::SecurityEvent::fromJson(o.value(QLatin1String("event")).toObject());
    p.action = static_cast<VerdictAction>(getInt(o, "action", 0));
    p.source = static_cast<VerdictSource>(getInt(o, "source", static_cast<int>(VerdictSource::DefaultPolicy)));
    p.enforcement = static_cast<bulwark::EnforcementOutcome>(
        getInt(o, "enforcement", static_cast<int>(bulwark::EnforcementOutcome::NotApplicable)));
    return p;
}

QJsonObject EventHistoryResponsePayload::toJson() const {
    QJsonArray arr;
    for (const EventLogPayload& e : events) arr.append(e.toJson());
    QJsonObject o;
    o["events"] = arr;
    return o;
}

EventHistoryResponsePayload EventHistoryResponsePayload::fromJson(const QJsonObject& o) {
    EventHistoryResponsePayload p;
    const QJsonArray arr = o.value(QLatin1String("events")).toArray();
    p.events.reserve(arr.size());
    for (const QJsonValue& v : arr)
        if (v.isObject()) p.events.append(EventLogPayload::fromJson(v.toObject()));
    return p;
}

QJsonObject RemediationSkippedItem::toJson() const {
    QJsonObject o;
    o["target"] = target;
    o["reason"] = reason;
    o["isFile"] = isFile;
    if (!kind.isEmpty()) o["kind"] = kind;
    if (!location.isEmpty()) o["location"] = location;
    if (!name.isEmpty()) o["name"] = name;
    if (forceable) o["forceable"] = true;
    return o;
}

RemediationSkippedItem RemediationSkippedItem::fromJson(const QJsonObject& o) {
    using namespace bulwark::json;
    RemediationSkippedItem s;
    s.target = getStr(o, "target");
    s.reason = getStr(o, "reason");
    s.isFile = getBool(o, "isFile");
    s.kind = getStr(o, "kind");
    s.location = getStr(o, "location");
    s.name = getStr(o, "name");
    s.forceable = getBool(o, "forceable");
    return s;
}

namespace {
QJsonArray rulesToArray(const QList<bulwark::DefenseRule>& rules) {
    QJsonArray arr;
    for (const auto& r : rules) arr.append(r.toJson());
    return arr;
}
QList<bulwark::DefenseRule> rulesFromArray(const QJsonArray& arr) {
    QList<bulwark::DefenseRule> out;
    out.reserve(arr.size());
    for (const auto& v : arr)
        if (v.isObject()) out.append(bulwark::DefenseRule::fromJson(v.toObject()));
    return out;
}
}

QJsonObject RulesResponsePayload::toJson() const {
    QJsonObject o; o["rules"] = rulesToArray(rules); return o;
}
RulesResponsePayload RulesResponsePayload::fromJson(const QJsonObject& o) {
    RulesResponsePayload p;
    p.rules = rulesFromArray(o.value(QLatin1String("rules")).toArray());
    return p;
}

QJsonObject DeleteRulePayload::toJson() const {
    using namespace bulwark::json; QJsonObject o; o["ruleId"] = guidToString(ruleId); return o;
}
DeleteRulePayload DeleteRulePayload::fromJson(const QJsonObject& o) {
    using namespace bulwark::json; DeleteRulePayload p; p.ruleId = guidFromString(getStr(o, "ruleId")); return p;
}

QJsonObject AddRulePayload::toJson() const {
    QJsonObject o;
    o["actorPath"] = actorPath;
    o["type"] = type.has_value() ? QJsonValue(static_cast<int>(*type)) : QJsonValue(QJsonValue::Null);
    o["targetPattern"] = targetPattern;
    o["action"] = static_cast<int>(action);
    return o;
}
AddRulePayload AddRulePayload::fromJson(const QJsonObject& o) {
    using namespace bulwark::json;
    AddRulePayload p;
    p.actorPath = getStr(o, "actorPath");
    const QJsonValue tv = o.value(QLatin1String("type"));
    if (tv.isDouble()) p.type = static_cast<bulwark::EventType>(tv.toInt());
    p.targetPattern = getStr(o, "targetPattern");
    // 越界值不能直接 static_cast 成枚举(下游 switch 会落到未定义分支);
    // 未知值按 Ask 处理,宁可多问一次也不默认放行。
    const int act = getInt(o, "action", static_cast<int>(bulwark::VerdictAction::Ask));
    p.action = (act >= static_cast<int>(bulwark::VerdictAction::Allow) && act <= static_cast<int>(bulwark::VerdictAction::Ask))
                   ? static_cast<bulwark::VerdictAction>(act)
                   : bulwark::VerdictAction::Ask;
    return p;
}

bulwark::DefenseRule AddRulePayload::toRule() const {
    bulwark::DefenseRule rule;
    const QString actor = actorPath.trimmed();
    if (!actor.isEmpty()) {
        const bool hasWild = actor.contains(QLatin1Char('*')) || actor.contains(QLatin1Char('?'));
        const bool rooted  = actor.contains(QStringLiteral(":\\")) || actor.startsWith(QStringLiteral("\\\\"));
        if (hasWild)      rule.actorPattern = actor;
        else if (rooted)  rule.actorPath = actor;
        else              rule.actorPattern = QStringLiteral("*\\") + actor;
    }
    rule.type = type;
    rule.targetPattern = targetPattern.trimmed();
    rule.action = action;
    return rule;
}

QJsonObject TrustListResponsePayload::toJson() const {
    QJsonObject o; o["entries"] = rulesToArray(entries); return o;
}
TrustListResponsePayload TrustListResponsePayload::fromJson(const QJsonObject& o) {
    TrustListResponsePayload p;
    p.entries = rulesFromArray(o.value(QLatin1String("entries")).toArray());
    return p;
}

QJsonObject AddTrustPayload::toJson() const {
    using namespace bulwark::json;
    QJsonObject o;
    o["actorPath"] = actorPath;
    o["note"] = note;
    o["isDirectory"] = isDirectory;
    o["sessionOnly"] = sessionOnly;
    o["expiresUtc"] = optDateToJson(expiresUtc);
    return o;
}
AddTrustPayload AddTrustPayload::fromJson(const QJsonObject& o) {
    using namespace bulwark::json;
    AddTrustPayload p;
    p.actorPath = getStr(o, "actorPath");
    p.note = getStr(o, "note");
    p.isDirectory = getBool(o, "isDirectory");
    p.sessionOnly = getBool(o, "sessionOnly");
    p.expiresUtc = optDateFromJson(o.value(QLatin1String("expiresUtc")));
    return p;
}

QJsonObject RemoveTrustPayload::toJson() const {
    using namespace bulwark::json; QJsonObject o; o["ruleId"] = guidToString(ruleId); return o;
}
RemoveTrustPayload RemoveTrustPayload::fromJson(const QJsonObject& o) {
    using namespace bulwark::json; RemoveTrustPayload p; p.ruleId = guidFromString(getStr(o, "ruleId")); return p;
}

QJsonObject QuarantineItemPayload::toJson() const {
    using namespace bulwark::json;
    QJsonObject o;
    o["id"] = guidToString(id);
    o["originalPath"] = originalPath;
    o["fileName"] = fileName;
    o["quarantinedUtc"] = dateTimeToIso(quarantinedUtc);
    o["size"] = static_cast<double>(size);
    o["sha256"] = sha256;
    o["reason"] = reason;
    o["actorPid"] = actorPid;
    if (!originalRemoved) o["originalRemoved"] = false;
    if (deleteOnRebootScheduled) o["deleteOnRebootScheduled"] = true;
    return o;
}
QuarantineItemPayload QuarantineItemPayload::fromJson(const QJsonObject& o) {
    using namespace bulwark::json;
    QuarantineItemPayload p;
    p.id = guidFromString(getStr(o, "id"));
    p.originalPath = getStr(o, "originalPath");
    p.fileName = getStr(o, "fileName");
    p.quarantinedUtc = dateTimeFromIso(getStr(o, "quarantinedUtc"));
    p.size = getI64(o, "size");
    p.sha256 = getStr(o, "sha256");
    p.reason = getStr(o, "reason");
    p.actorPid = getInt(o, "actorPid");
    p.originalRemoved = getBool(o, "originalRemoved", true);
    p.deleteOnRebootScheduled = getBool(o, "deleteOnRebootScheduled");
    return p;
}

QJsonObject QuarantineListResponsePayload::toJson() const {
    QJsonArray arr;
    for (const auto& i : items) arr.append(i.toJson());
    QJsonObject o; o["items"] = arr; return o;
}
QuarantineListResponsePayload QuarantineListResponsePayload::fromJson(const QJsonObject& o) {
    QuarantineListResponsePayload p;
    for (const auto& v : o.value(QLatin1String("items")).toArray())
        if (v.isObject()) p.items.append(QuarantineItemPayload::fromJson(v.toObject()));
    return p;
}

QJsonObject QuarantineActionPayload::toJson() const {
    using namespace bulwark::json; QJsonObject o; o["id"] = guidToString(id); return o;
}
QuarantineActionPayload QuarantineActionPayload::fromJson(const QJsonObject& o) {
    using namespace bulwark::json; QuarantineActionPayload p; p.id = guidFromString(getStr(o, "id")); return p;
}

QJsonObject QuarantineActionResultPayload::toJson() const {
    using namespace bulwark::json;
    QJsonObject o; o["id"] = guidToString(id); o["success"] = success; o["message"] = message; return o;
}
QuarantineActionResultPayload QuarantineActionResultPayload::fromJson(const QJsonObject& o) {
    using namespace bulwark::json;
    QuarantineActionResultPayload p;
    p.id = guidFromString(getStr(o, "id"));
    p.success = getBool(o, "success");
    p.message = getStr(o, "message");
    return p;
}

QJsonObject ManualQuarantinePayload::toJson() const {
    using namespace bulwark::json;
    QJsonObject o; o["requestId"] = guidToString(requestId); o["path"] = path;
    if (force) o["force"] = true;
    if (!kind.isEmpty()) o["kind"] = kind;
    if (!location.isEmpty()) o["location"] = location;
    if (!name.isEmpty()) o["name"] = name;
    return o;
}
ManualQuarantinePayload ManualQuarantinePayload::fromJson(const QJsonObject& o) {
    using namespace bulwark::json;
    ManualQuarantinePayload p;
    p.requestId = guidFromString(getStr(o, "requestId"));
    p.path = getStr(o, "path");
    p.force = getBool(o, "force");
    p.kind = getStr(o, "kind");
    p.location = getStr(o, "location");
    p.name = getStr(o, "name");
    return p;
}

QJsonObject ManualQuarantineResultPayload::toJson() const {
    using namespace bulwark::json;
    QJsonObject o; o["requestId"] = guidToString(requestId); o["success"] = success; o["message"] = message; return o;
}
ManualQuarantineResultPayload ManualQuarantineResultPayload::fromJson(const QJsonObject& o) {
    using namespace bulwark::json;
    ManualQuarantineResultPayload p;
    p.requestId = guidFromString(getStr(o, "requestId"));
    p.success = getBool(o, "success");
    p.message = getStr(o, "message");
    return p;
}

QJsonObject PersistenceListResponsePayload::toJson() const {
    using namespace bulwark::json;
    QJsonArray arr;
    for (const auto& e : entries) arr.append(e.toJson());
    QJsonObject o;
    o["scannedUtc"] = dateTimeToIso(scannedUtc);
    o["entries"] = arr;
    o["message"] = message;
    return o;
}
PersistenceListResponsePayload PersistenceListResponsePayload::fromJson(const QJsonObject& o) {
    using namespace bulwark::json;
    PersistenceListResponsePayload p;
    p.scannedUtc = dateTimeFromIso(getStr(o, "scannedUtc"));
    for (const auto& v : o.value(QLatin1String("entries")).toArray())
        if (v.isObject()) p.entries.append(bulwark::PersistenceEntry::fromJson(v.toObject()));
    p.message = getStr(o, "message");
    return p;
}

QJsonObject PersistenceCleanupRequestPayload::toJson() const {
    using namespace bulwark::json;
    QJsonObject o;
    o["requestId"] = guidToString(requestId);
    o["entry"] = entry.toJson();
    return o;
}
PersistenceCleanupRequestPayload PersistenceCleanupRequestPayload::fromJson(const QJsonObject& o) {
    using namespace bulwark::json;
    PersistenceCleanupRequestPayload p;
    p.requestId = guidFromString(getStr(o, "requestId"));
    p.entry = bulwark::PersistenceEntry::fromJson(o.value(QLatin1String("entry")).toObject());
    return p;
}

QJsonObject PersistenceCleanupResultPayload::toJson() const {
    using namespace bulwark::json;
    QJsonArray skippedArr;
    for (const auto& s : skipped) skippedArr.append(s.toJson());
    QJsonObject o;
    o["requestId"] = guidToString(requestId);
    o["success"] = success;
    o["entryId"] = entryId;
    o["message"] = message;
    o["quarantinedFiles"] = strListToJson(quarantinedFiles);
    o["removedRegistryValues"] = strListToJson(removedRegistryValues);
    o["skipped"] = skippedArr;
    return o;
}
PersistenceCleanupResultPayload PersistenceCleanupResultPayload::fromJson(const QJsonObject& o) {
    using namespace bulwark::json;
    PersistenceCleanupResultPayload p;
    p.requestId = guidFromString(getStr(o, "requestId"));
    p.success = o.value(QLatin1String("success")).toBool();
    p.entryId = getStr(o, "entryId");
    p.message = getStr(o, "message");
    p.quarantinedFiles = getStrList(o, "quarantinedFiles");
    p.removedRegistryValues = getStrList(o, "removedRegistryValues");
    for (const auto& v : o.value(QLatin1String("skipped")).toArray())
        if (v.isObject()) p.skipped.append(RemediationSkippedItem::fromJson(v.toObject()));
    return p;
}

QJsonObject RemediationReportPayload::toJson() const {
    using namespace bulwark::json;
    QJsonObject o;
    o["timestampUtc"] = dateTimeToIso(timestampUtc);
    o["actorPath"] = actorPath;
    o["actorPid"] = actorPid;
    o["reason"] = reason;
    o["actorQuarantined"] = actorQuarantined;
    o["quarantinedFiles"] = strListToJson(quarantinedFiles);
    o["removedRegistryValues"] = strListToJson(removedRegistryValues);
    QJsonArray sk;
    for (const auto& s : skipped) sk.append(s.toJson());
    o["skipped"] = sk;
    return o;
}
RemediationReportPayload RemediationReportPayload::fromJson(const QJsonObject& o) {
    using namespace bulwark::json;
    RemediationReportPayload p;
    p.timestampUtc = dateTimeFromIso(getStr(o, "timestampUtc"));
    p.actorPath = getStr(o, "actorPath");
    p.actorPid = getInt(o, "actorPid");
    p.reason = getStr(o, "reason");
    p.actorQuarantined = getBool(o, "actorQuarantined");
    p.quarantinedFiles = getStrList(o, "quarantinedFiles");
    p.removedRegistryValues = getStrList(o, "removedRegistryValues");
    for (const auto& v : o.value(QLatin1String("skipped")).toArray())
        if (v.isObject()) p.skipped.append(RemediationSkippedItem::fromJson(v.toObject()));
    return p;
}

QJsonObject IntelRefreshRequestPayload::toJson() const {
    using namespace bulwark::json;
    QJsonObject o; o["requestId"] = guidToString(requestId); o["previewOnly"] = previewOnly; return o;
}
IntelRefreshRequestPayload IntelRefreshRequestPayload::fromJson(const QJsonObject& o) {
    using namespace bulwark::json;
    IntelRefreshRequestPayload p;
    p.requestId = guidFromString(getStr(o, "requestId"));
    p.previewOnly = getBool(o, "previewOnly");
    return p;
}

QJsonObject IntelRefreshResultPayload::toJson() const {
    using namespace bulwark::json;
    QJsonObject o;
    o["requestId"] = guidToString(requestId);
    o["success"] = success;
    o["iocCount"] = iocCount;
    o["rulesApplied"] = rulesApplied;
    o["generatedRules"] = rulesToArray(generatedRules);
    o["threatContext"] = strListToJson(threatContext);
    o["message"] = message;
    return o;
}
IntelRefreshResultPayload IntelRefreshResultPayload::fromJson(const QJsonObject& o) {
    using namespace bulwark::json;
    IntelRefreshResultPayload p;
    p.requestId = guidFromString(getStr(o, "requestId"));
    p.success = getBool(o, "success");
    p.iocCount = getInt(o, "iocCount");
    p.rulesApplied = getInt(o, "rulesApplied");
    p.generatedRules = rulesFromArray(o.value(QLatin1String("generatedRules")).toArray());
    p.threatContext = getStrList(o, "threatContext");
    p.message = getStr(o, "message");
    return p;
}

QJsonObject IntelApplyRequestPayload::toJson() const {
    using namespace bulwark::json;
    QJsonObject o; o["requestId"] = guidToString(requestId); o["rules"] = rulesToArray(rules); return o;
}
IntelApplyRequestPayload IntelApplyRequestPayload::fromJson(const QJsonObject& o) {
    using namespace bulwark::json;
    IntelApplyRequestPayload p;
    p.requestId = guidFromString(getStr(o, "requestId"));
    p.rules = rulesFromArray(o.value(QLatin1String("rules")).toArray());
    return p;
}

namespace {
QJsonArray intListToArray(const QList<int>& list) {
    QJsonArray arr;
    for (int v : list) arr.append(v);
    return arr;
}
QList<int> intListFromArray(const QJsonArray& arr) {
    QList<int> out;
    out.reserve(arr.size());
    for (const QJsonValue& v : arr)
        if (v.isDouble()) out.append(v.toInt());
    return out;
}
}

QJsonObject TimelineRequestPayload::toJson() const {
    using namespace bulwark::json;
    QJsonObject o;
    o["requestId"] = guidToString(requestId);
    if (fromUtc.isValid()) o["fromUtc"] = dateTimeToIso(fromUtc);
    if (toUtc.isValid())   o["toUtc"] = dateTimeToIso(toUtc);
    if (!types.isEmpty())   o["types"] = intListToArray(types);
    if (!actions.isEmpty()) o["actions"] = intListToArray(actions);
    o["minRiskScore"] = minRiskScore;
    o["pid"] = pid;
    o["includeProcessTree"] = includeProcessTree;
    o["text"] = text;
    o["limit"] = limit;
    return o;
}
TimelineRequestPayload TimelineRequestPayload::fromJson(const QJsonObject& o) {
    using namespace bulwark::json;
    TimelineRequestPayload p;
    p.requestId = guidFromString(getStr(o, "requestId"));
    p.fromUtc = dateTimeFromIso(getStr(o, "fromUtc"));
    p.toUtc = dateTimeFromIso(getStr(o, "toUtc"));
    p.types = intListFromArray(o.value(QLatin1String("types")).toArray());
    p.actions = intListFromArray(o.value(QLatin1String("actions")).toArray());
    p.minRiskScore = getInt(o, "minRiskScore");
    p.pid = getInt(o, "pid");
    p.includeProcessTree = getBool(o, "includeProcessTree");
    p.text = getStr(o, "text");
    p.limit = getInt(o, "limit", 500);
    return p;
}

QJsonObject TimelineResponsePayload::toJson() const {
    using namespace bulwark::json;
    QJsonArray arr;
    for (const EventLogPayload& e : events) arr.append(e.toJson());
    QJsonObject o;
    o["requestId"] = guidToString(requestId);
    o["events"] = arr;
    o["scanned"] = scanned;
    o["matched"] = matched;
    o["truncated"] = truncated;
    if (earliestUtc.isValid()) o["earliestUtc"] = dateTimeToIso(earliestUtc);
    o["message"] = message;
    return o;
}
TimelineResponsePayload TimelineResponsePayload::fromJson(const QJsonObject& o) {
    using namespace bulwark::json;
    TimelineResponsePayload p;
    p.requestId = guidFromString(getStr(o, "requestId"));
    const QJsonArray arr = o.value(QLatin1String("events")).toArray();
    p.events.reserve(arr.size());
    for (const QJsonValue& v : arr)
        if (v.isObject()) p.events.append(EventLogPayload::fromJson(v.toObject()));
    p.scanned = getInt(o, "scanned");
    p.matched = getInt(o, "matched");
    p.truncated = getBool(o, "truncated");
    p.earliestUtc = dateTimeFromIso(getStr(o, "earliestUtc"));
    p.message = getStr(o, "message");
    return p;
}

QJsonObject AttackGraphRequestPayload::toJson() const {
    using namespace bulwark::json;
    QJsonObject o;
    o["requestId"] = guidToString(requestId);
    o["seedEventId"] = guidToString(seedEventId);
    o["rootPid"] = rootPid;
    o["windowSeconds"] = windowSeconds;
    return o;
}
AttackGraphRequestPayload AttackGraphRequestPayload::fromJson(const QJsonObject& o) {
    using namespace bulwark::json;
    AttackGraphRequestPayload p;
    p.requestId = guidFromString(getStr(o, "requestId"));
    p.seedEventId = guidFromString(getStr(o, "seedEventId"));
    p.rootPid = getInt(o, "rootPid");
    p.windowSeconds = getInt(o, "windowSeconds", 3600);
    return p;
}

QJsonObject AttackGraphResponsePayload::toJson() const {
    using namespace bulwark::json;
    QJsonObject o;
    o["requestId"] = guidToString(requestId);
    o["success"] = success;
    o["message"] = message;
    o["graph"] = graph.toJson();
    return o;
}
AttackGraphResponsePayload AttackGraphResponsePayload::fromJson(const QJsonObject& o) {
    using namespace bulwark::json;
    AttackGraphResponsePayload p;
    p.requestId = guidFromString(getStr(o, "requestId"));
    p.success = getBool(o, "success");
    p.message = getStr(o, "message");
    p.graph = bulwark::AttackGraph::fromJson(o.value(QLatin1String("graph")).toObject());
    return p;
}

QJsonObject ProcessListRequestPayload::toJson() const {
    using namespace bulwark::json;
    QJsonObject o;
    o["requestId"] = guidToString(requestId);
    o["includeCommandLine"] = includeCommandLine;
    o["resolveOrigin"] = resolveOrigin;
    return o;
}
ProcessListRequestPayload ProcessListRequestPayload::fromJson(const QJsonObject& o) {
    using namespace bulwark::json;
    ProcessListRequestPayload p;
    p.requestId = guidFromString(getStr(o, "requestId"));
    p.includeCommandLine = getBool(o, "includeCommandLine", true);
    p.resolveOrigin = getBool(o, "resolveOrigin", true);
    return p;
}

QJsonObject ProcessListResponsePayload::toJson() const {
    using namespace bulwark::json;
    QJsonArray arr;
    for (const bulwark::ProcessEntry& e : processes) arr.append(e.toJson());
    QJsonObject o;
    o["requestId"] = guidToString(requestId);
    o["snapshotUtc"] = dateTimeToIso(snapshotUtc);
    o["processes"] = arr;
    o["message"] = message;
    return o;
}
ProcessListResponsePayload ProcessListResponsePayload::fromJson(const QJsonObject& o) {
    using namespace bulwark::json;
    ProcessListResponsePayload p;
    p.requestId = guidFromString(getStr(o, "requestId"));
    p.snapshotUtc = dateTimeFromIso(getStr(o, "snapshotUtc"));
    for (const QJsonValue& v : o.value(QLatin1String("processes")).toArray())
        if (v.isObject()) p.processes.append(bulwark::ProcessEntry::fromJson(v.toObject()));
    p.message = getStr(o, "message");
    return p;
}

QJsonObject ProcessActionRequestPayload::toJson() const {
    using namespace bulwark::json;
    QJsonObject o;
    o["requestId"] = guidToString(requestId);
    o["kind"] = static_cast<int>(kind);
    o["pid"] = pid;
    if (creationFileTime != 0) o["creationFileTime"] = QString::number(creationFileTime);
    o["imagePath"] = imagePath;
    return o;
}
ProcessActionRequestPayload ProcessActionRequestPayload::fromJson(const QJsonObject& o) {
    using namespace bulwark::json;
    ProcessActionRequestPayload p;
    p.requestId = guidFromString(getStr(o, "requestId"));
    p.kind = static_cast<ProcessActionKind>(getInt(o, "kind", 0));
    p.pid = getInt(o, "pid");
    p.creationFileTime = getStr(o, "creationFileTime").toULongLong();
    p.imagePath = getStr(o, "imagePath");
    return p;
}

QJsonObject ProcessActionResultPayload::toJson() const {
    using namespace bulwark::json;
    QJsonObject o;
    o["requestId"] = guidToString(requestId);
    o["kind"] = static_cast<int>(kind);
    o["pid"] = pid;
    o["success"] = success;
    o["message"] = message;
    if (!sha256.isEmpty()) o["sha256"] = sha256;
    return o;
}
ProcessActionResultPayload ProcessActionResultPayload::fromJson(const QJsonObject& o) {
    using namespace bulwark::json;
    ProcessActionResultPayload p;
    p.requestId = guidFromString(getStr(o, "requestId"));
    p.kind = static_cast<ProcessActionKind>(getInt(o, "kind", 0));
    p.pid = getInt(o, "pid");
    p.success = getBool(o, "success");
    p.message = getStr(o, "message");
    p.sha256 = getStr(o, "sha256");
    return p;
}

QJsonObject PromptWithdrawPayload::toJson() const {
    using namespace bulwark::json;
    QJsonObject o;
    o["eventId"] = guidToString(eventId);
    o["action"] = action;
    o["by"] = by;
    o["reason"] = reason;
    o["actorPath"] = actorPath;
    return o;
}

PromptWithdrawPayload PromptWithdrawPayload::fromJson(const QJsonObject& o) {
    using namespace bulwark::json;
    PromptWithdrawPayload p;
    p.eventId = guidFromString(getStr(o, "eventId"));
    p.action = getStr(o, "action");
    p.by = getStr(o, "by");
    p.reason = getStr(o, "reason");
    p.actorPath = getStr(o, "actorPath");
    return p;
}

QJsonObject HardeningItemPayload::toJson() const {
    QJsonObject o;
    o["id"] = id;
    o["group"] = group;
    o["title"] = title;
    o["current"] = current;
    o["recommended"] = recommended;
    o["cost"] = cost;
    o["note"] = note;
    o["severity"] = severity;
    o["satisfied"] = satisfied;
    o["actionable"] = actionable;
    o["revertible"] = revertible;
    o["needsReboot"] = needsReboot;
    return o;
}

HardeningItemPayload HardeningItemPayload::fromJson(const QJsonObject& o) {
    using namespace bulwark::json;
    HardeningItemPayload p;
    p.id = getStr(o, "id");
    p.group = getStr(o, "group");
    p.title = getStr(o, "title");
    p.current = getStr(o, "current");
    p.recommended = getStr(o, "recommended");
    p.cost = getStr(o, "cost");
    p.note = getStr(o, "note");
    p.severity = getStr(o, "severity");
    p.satisfied = getBool(o, "satisfied");
    p.actionable = getBool(o, "actionable");
    p.revertible = getBool(o, "revertible");
    p.needsReboot = getBool(o, "needsReboot");
    return p;
}

QJsonObject HijackAlertPayload::toJson() const {
    using namespace bulwark::json;
    QJsonObject o;
    o["id"] = id;
    o["surface"] = surface;
    o["title"] = title;
    o["location"] = location;
    o["oldValue"] = oldValue;
    o["newValue"] = newValue;
    o["detail"] = detail;
    o["state"] = state;
    o["whenUtc"] = dateTimeToIso(whenUtc);
    o["restorable"] = restorable;
    o["preexisting"] = preexisting;
    return o;
}

HijackAlertPayload HijackAlertPayload::fromJson(const QJsonObject& o) {
    using namespace bulwark::json;
    HijackAlertPayload p;
    p.id = getStr(o, "id");
    p.surface = getStr(o, "surface");
    p.title = getStr(o, "title");
    p.location = getStr(o, "location");
    p.oldValue = getStr(o, "oldValue");
    p.newValue = getStr(o, "newValue");
    p.detail = getStr(o, "detail");
    p.state = getStr(o, "state");
    if (p.state.isEmpty())
        p.state = QStringLiteral("pending");
    p.whenUtc = dateTimeFromIso(getStr(o, "whenUtc"));
    p.restorable = getBool(o, "restorable", true);
    p.preexisting = getBool(o, "preexisting");
    return p;
}

QJsonObject HardeningStatusResponsePayload::toJson() const {
    using namespace bulwark::json;
    QJsonArray its;
    for (const auto& i : items) its.append(i.toJson());
    QJsonArray als;
    for (const auto& a : alerts) als.append(a.toJson());
    QJsonObject o;
    o["scannedUtc"] = dateTimeToIso(scannedUtc);
    o["items"] = its;
    o["alerts"] = als;
    o["actionsEnabled"] = actionsEnabled;
    o["hijackGuardActive"] = hijackGuardActive;
    o["message"] = message;
    return o;
}

HardeningStatusResponsePayload HardeningStatusResponsePayload::fromJson(const QJsonObject& o) {
    using namespace bulwark::json;
    HardeningStatusResponsePayload p;
    p.scannedUtc = dateTimeFromIso(getStr(o, "scannedUtc"));
    for (const auto& v : o.value(QLatin1String("items")).toArray())
        if (v.isObject()) p.items.append(HardeningItemPayload::fromJson(v.toObject()));
    for (const auto& v : o.value(QLatin1String("alerts")).toArray())
        if (v.isObject()) p.alerts.append(HijackAlertPayload::fromJson(v.toObject()));
    p.actionsEnabled = getBool(o, "actionsEnabled", true);
    p.hijackGuardActive = getBool(o, "hijackGuardActive");
    p.message = getStr(o, "message");
    return p;
}

QJsonObject HardeningActionRequestPayload::toJson() const {
    using namespace bulwark::json;
    QJsonObject o;
    o["requestId"] = guidToString(requestId);
    o["action"] = action;
    o["id"] = id;
    return o;
}

HardeningActionRequestPayload HardeningActionRequestPayload::fromJson(const QJsonObject& o) {
    using namespace bulwark::json;
    HardeningActionRequestPayload p;
    p.requestId = guidFromString(getStr(o, "requestId"));
    p.action = getStr(o, "action");
    p.id = getStr(o, "id");
    return p;
}

QJsonObject HardeningActionResultPayload::toJson() const {
    using namespace bulwark::json;
    QJsonObject o;
    o["requestId"] = guidToString(requestId);
    o["action"] = action;
    o["id"] = id;
    o["ok"] = ok;
    o["needsReboot"] = needsReboot;
    o["message"] = message;
    return o;
}

HardeningActionResultPayload HardeningActionResultPayload::fromJson(const QJsonObject& o) {
    using namespace bulwark::json;
    HardeningActionResultPayload p;
    p.requestId = guidFromString(getStr(o, "requestId"));
    p.action = getStr(o, "action");
    p.id = getStr(o, "id");
    p.ok = getBool(o, "ok");
    p.needsReboot = getBool(o, "needsReboot");
    p.message = getStr(o, "message");
    return p;
}

QJsonObject NetTrafficSubscribePayload::toJson() const {
    QJsonObject o;
    o["on"] = on;
    if (!focusPids.isEmpty()) {
        QJsonArray arr;
        for (int pid : focusPids) arr.append(pid);
        o["focusPids"] = arr;
    }
    return o;
}

NetTrafficSubscribePayload NetTrafficSubscribePayload::fromJson(const QJsonObject& o) {
    using namespace bulwark::json;
    NetTrafficSubscribePayload p;
    p.on = getBool(o, "on", true);
    for (const auto& v : o.value(QLatin1String("focusPids")).toArray()) {
        const int pid = v.toInt(0);
        if (pid > 0 && !p.focusPids.contains(pid) && p.focusPids.size() < 16)
            p.focusPids.append(pid);
    }
    return p;
}

QJsonObject NetTrafficConnPayload::toJson() const {
    QJsonObject o;
    o["proto"] = proto;
    o["remoteIp"] = remoteIp;
    o["remotePort"] = remotePort;
    o["localPort"] = localPort;
    if (!domain.isEmpty()) o["domain"] = domain;
    o["scope"] = scope;
    if (!proxyName.isEmpty()) o["proxyName"] = proxyName;
    o["upBps"] = static_cast<double>(upBps);
    o["downBps"] = static_cast<double>(downBps);
    o["upTotal"] = static_cast<double>(upTotal);
    o["downTotal"] = static_cast<double>(downTotal);
    o["ageSecs"] = static_cast<double>(ageSecs);
    o["idleSecs"] = static_cast<double>(idleSecs);
    o["established"] = established;
    return o;
}

NetTrafficConnPayload NetTrafficConnPayload::fromJson(const QJsonObject& o) {
    using namespace bulwark::json;
    NetTrafficConnPayload p;
    p.proto = getStr(o, "proto");
    p.remoteIp = getStr(o, "remoteIp");
    p.remotePort = getInt(o, "remotePort");
    p.localPort = getInt(o, "localPort");
    p.domain = getStr(o, "domain");
    p.scope = getStr(o, "scope");
    p.proxyName = getStr(o, "proxyName");
    p.upBps = getI64(o, "upBps");
    p.downBps = getI64(o, "downBps");
    p.upTotal = getI64(o, "upTotal");
    p.downTotal = getI64(o, "downTotal");
    p.ageSecs = getI64(o, "ageSecs");
    p.idleSecs = o.contains(QLatin1String("idleSecs")) ? getI64(o, "idleSecs") : -1;
    p.established = getBool(o, "established");
    return p;
}

QJsonObject NetTrafficRowPayload::toJson() const {
    using namespace bulwark::json;
    QJsonObject o;
    o["pid"] = pid;
    o["name"] = name;
    o["path"] = path;
    o["upBps"] = static_cast<double>(upBps);
    o["downBps"] = static_cast<double>(downBps);
    o["upTotal"] = static_cast<double>(upTotal);
    o["downTotal"] = static_cast<double>(downTotal);
    o["tcpConns"] = tcpConns;
    o["remotes"] = strListToJson(remotes);
    o["critical"] = critical;
    o["protectedSelf"] = protectedSelf;
    if (!proxyName.isEmpty()) {
        o["proxyName"] = proxyName;
        o["proxyConns"] = proxyConns;
        o["proxyUpBps"] = static_cast<double>(proxyUpBps);
        o["proxyDownBps"] = static_cast<double>(proxyDownBps);
    }
    return o;
}

NetTrafficRowPayload NetTrafficRowPayload::fromJson(const QJsonObject& o) {
    using namespace bulwark::json;
    NetTrafficRowPayload p;
    p.pid = getInt(o, "pid");
    p.name = getStr(o, "name");
    p.path = getStr(o, "path");
    p.upBps = getI64(o, "upBps");
    p.downBps = getI64(o, "downBps");
    p.upTotal = getI64(o, "upTotal");
    p.downTotal = getI64(o, "downTotal");
    p.tcpConns = getInt(o, "tcpConns");
    p.remotes = getStrList(o, "remotes");
    p.critical = getBool(o, "critical");
    p.protectedSelf = getBool(o, "protectedSelf");
    p.proxyName = getStr(o, "proxyName");
    p.proxyConns = getInt(o, "proxyConns");
    p.proxyUpBps = getI64(o, "proxyUpBps");
    p.proxyDownBps = getI64(o, "proxyDownBps");
    return p;
}

QJsonObject NetTrafficSnapshotPayload::toJson() const {
    using namespace bulwark::json;
    QJsonArray arr;
    for (const auto& r : rows) arr.append(r.toJson());
    QJsonObject o;
    o["atUtc"] = dateTimeToIso(atUtc);
    o["totalUpBps"] = static_cast<double>(totalUpBps);
    o["totalDownBps"] = static_cast<double>(totalDownBps);
    o["sessionUpBytes"] = static_cast<double>(sessionUpBytes);
    o["sessionDownBytes"] = static_cast<double>(sessionDownBytes);
    o["perProcessAvailable"] = perProcessAvailable;
    o["message"] = message;
    o["rows"] = arr;
    if (!connections.isEmpty()) {
        QJsonObject byPid;
        for (auto it = connections.constBegin(); it != connections.constEnd(); ++it) {
            QJsonArray list;
            for (const auto& c : it.value()) list.append(c.toJson());
            byPid[QString::number(it.key())] = list;
        }
        o["connections"] = byPid;
    }
    return o;
}

NetTrafficSnapshotPayload NetTrafficSnapshotPayload::fromJson(const QJsonObject& o) {
    using namespace bulwark::json;
    NetTrafficSnapshotPayload p;
    p.atUtc = dateTimeFromIso(getStr(o, "atUtc"));
    p.totalUpBps = getI64(o, "totalUpBps");
    p.totalDownBps = getI64(o, "totalDownBps");
    p.sessionUpBytes = getI64(o, "sessionUpBytes");
    p.sessionDownBytes = getI64(o, "sessionDownBytes");
    p.perProcessAvailable = getBool(o, "perProcessAvailable", true);
    p.message = getStr(o, "message");
    for (const auto& v : o.value(QLatin1String("rows")).toArray())
        if (v.isObject()) p.rows.append(NetTrafficRowPayload::fromJson(v.toObject()));
    const QJsonObject byPid = o.value(QLatin1String("connections")).toObject();
    for (auto it = byPid.constBegin(); it != byPid.constEnd(); ++it) {
        bool ok = false;
        const int pid = it.key().toInt(&ok);
        if (!ok || pid <= 0)
            continue;
        QList<NetTrafficConnPayload> list;
        for (const auto& v : it.value().toArray())
            if (v.isObject()) list.append(NetTrafficConnPayload::fromJson(v.toObject()));
        p.connections.insert(pid, list);
    }
    return p;
}

QJsonObject SystemBoostRequestPayload::toJson() const {
    using namespace bulwark::json;
    QJsonObject o;
    o["requestId"] = guidToString(requestId);
    return o;
}
SystemBoostRequestPayload SystemBoostRequestPayload::fromJson(const QJsonObject& o) {
    using namespace bulwark::json;
    SystemBoostRequestPayload p;
    p.requestId = guidFromString(getStr(o, "requestId"));
    return p;
}

QJsonObject SystemBoostResultPayload::toJson() const {
    using namespace bulwark::json;
    QJsonObject o;
    o["requestId"] = guidToString(requestId);
    o["success"] = success;
    o["processesTrimmed"] = processesTrimmed;
    o["processesTotal"] = processesTotal;
    o["freedBytes"] = static_cast<double>(freedBytes);
    o["inUseBefore"] = static_cast<double>(inUseBefore);
    o["inUseAfter"] = static_cast<double>(inUseAfter);
    o["totalPhysical"] = static_cast<double>(totalPhysical);
    o["loadBefore"] = loadBefore;
    o["loadAfter"] = loadAfter;
    o["message"] = message;
    return o;
}
SystemBoostResultPayload SystemBoostResultPayload::fromJson(const QJsonObject& o) {
    using namespace bulwark::json;
    SystemBoostResultPayload p;
    p.requestId = guidFromString(getStr(o, "requestId"));
    p.success = getBool(o, "success");
    p.processesTrimmed = getInt(o, "processesTrimmed");
    p.processesTotal = getInt(o, "processesTotal");
    p.freedBytes = getI64(o, "freedBytes");
    p.inUseBefore = getI64(o, "inUseBefore");
    p.inUseAfter = getI64(o, "inUseAfter");
    p.totalPhysical = getI64(o, "totalPhysical");
    p.loadBefore = getInt(o, "loadBefore");
    p.loadAfter = getInt(o, "loadAfter");
    p.message = getStr(o, "message");
    return p;
}

}
