#include "bulwark/models/Evidence.h"
#include "bulwark/json/JsonSupport.h"

namespace bulwark {
using namespace bulwark::json;

QJsonObject Evidence::toJson() const {
    QJsonObject o;
    o["timestampUtc"] = dateTimeToIso(timestampUtc);
    o["source"] = source;
    o["kind"] = evidenceKindToString(kind);
    o["description"] = description;
    o["scoreDelta"] = scoreDelta;
    if (!technique.isEmpty()) o["technique"] = technique;
    if (!techniqueName.isEmpty()) o["techniqueName"] = techniqueName;
    if (subject == EvidenceSubject::Target) o["subject"] = QStringLiteral("Target");
    return o;
}

Evidence Evidence::fromJson(const QJsonObject& o) {
    Evidence e;
    e.timestampUtc = dateTimeFromIso(getStr(o, "timestampUtc"));
    e.source = getStr(o, "source");
    e.kind = evidenceKindFromString(getStr(o, "kind"));
    e.description = getStr(o, "description");
    e.scoreDelta = getInt(o, "scoreDelta");
    e.technique = getStr(o, "technique");
    e.techniqueName = getStr(o, "techniqueName");
    e.subject = getStr(o, "subject") == QLatin1String("Target") ? EvidenceSubject::Target
                                                               : EvidenceSubject::Actor;
    return e;
}

}
