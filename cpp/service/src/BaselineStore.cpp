#include "bulwark/service/BaselineStore.h"
#include "bulwark/service/Logger.h"
#include "bulwark/service/AtomicFile.h"
#include "bulwark/json/JsonSupport.h"

#include <QDir>
#include <QFile>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>

namespace bulwark::service {
using namespace bulwark::json;
using bulwark::engine::BaselineSnapshot;
using bulwark::engine::BaselineProgram;

namespace {
QJsonObject programToJson(const BaselineProgram& p) {
    QJsonObject o;
    o["key"] = p.key;
    o["firstSeenUtc"] = dateTimeToIso(p.firstSeenUtc);
    o["lastSeenUtc"] = dateTimeToIso(p.lastSeenUtc);
    o["childObs"] = p.childObs;
    o["hostObs"] = p.hostObs;
    o["writeObs"] = p.writeObs;
    o["children"] = strListToJson(p.children);
    o["hosts"] = strListToJson(p.hosts);
    o["writeDirs"] = strListToJson(p.writeDirs);
    return o;
}
BaselineProgram programFromJson(const QJsonObject& o) {
    BaselineProgram p;
    p.key = getStr(o, "key");
    p.firstSeenUtc = dateTimeFromIso(getStr(o, "firstSeenUtc"));
    p.lastSeenUtc = dateTimeFromIso(getStr(o, "lastSeenUtc"));
    p.childObs = getInt(o, "childObs");
    p.hostObs = getInt(o, "hostObs");
    p.writeObs = getInt(o, "writeObs");
    p.children = getStrList(o, "children");
    p.hosts = getStrList(o, "hosts");
    p.writeDirs = getStrList(o, "writeDirs");
    return p;
}
}

BaselineStore::BaselineStore() {
    path_ = QDir(programDataDir()).filePath(QStringLiteral("baseline.json"));
}

std::optional<BaselineSnapshot> BaselineStore::load() {
    QMutexLocker lk(&io_);
    QFile f(path_);
    if (!f.exists() || !f.open(QIODevice::ReadOnly)) return std::nullopt;
    const QByteArray data = f.readAll();
    f.close();
    QJsonParseError err{};
    const QJsonDocument doc = QJsonDocument::fromJson(data, &err);
    if (err.error != QJsonParseError::NoError || !doc.isObject()) return std::nullopt;

    BaselineSnapshot snap;
    const QJsonArray progs = doc.object().value(QLatin1String("programs")).toArray();
    for (const QJsonValue& v : progs)
        if (v.isObject()) snap.programs.append(programFromJson(v.toObject()));
    return snap;
}

void BaselineStore::save(const BaselineSnapshot& snapshot) {
    QMutexLocker lk(&io_);
    QJsonArray progs;
    for (const BaselineProgram& p : snapshot.programs) progs.append(programToJson(p));
    QJsonObject root;
    root["programs"] = progs;
    const QByteArray bytes = QJsonDocument(root).toJson(QJsonDocument::Compact);

    if (!writeFileAtomically(path_, bytes, QStringLiteral("行为基线")))
        Logger(QStringLiteral("bulwark.service.BaselineStore"))
            .warning(QStringLiteral("行为基线落盘失败,内存态仍有效:%1").arg(path_));
}

}
