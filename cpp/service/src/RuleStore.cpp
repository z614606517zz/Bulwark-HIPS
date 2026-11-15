#include "bulwark/service/RuleStore.h"
#include "bulwark/service/AtomicFile.h"
#include "bulwark/service/Logger.h"

#include <QDir>
#include <QFile>
#include <QDateTime>
#include <QJsonDocument>
#include <QJsonArray>
#include <QJsonObject>

namespace bulwark::service {

RuleStore::RuleStore() {
    path_ = QDir(programDataDir()).filePath(QStringLiteral("rules.json"));
}

QVector<bulwark::DefenseRule> RuleStore::load() {
    QMutexLocker lk(&io_);
    QVector<bulwark::DefenseRule> out;
    QFile f(path_);
    if (!f.exists() || !f.open(QIODevice::ReadOnly)) return out;
    const QByteArray data = f.readAll();
    f.close();
    QJsonParseError err{};
    const QJsonDocument doc = QJsonDocument::fromJson(data, &err);
    if (err.error != QJsonParseError::NoError || !doc.isArray()) return out;

    const QDateTime now = QDateTime::currentDateTimeUtc();
    const QJsonArray arr = doc.array();
    out.reserve(arr.size());
    for (const QJsonValue& v : arr) {
        if (!v.isObject()) continue;
        const bulwark::DefenseRule r = bulwark::DefenseRule::fromJson(v.toObject());
        if (!r.isExpired(now)) out.append(r);
    }
    return out;
}

void RuleStore::save(const QVector<bulwark::DefenseRule>& rules) {
    QMutexLocker lk(&io_);
    const QDateTime now = QDateTime::currentDateTimeUtc();
    QJsonArray arr;
    for (const bulwark::DefenseRule& r : rules) {
        if (r.sessionOnly || r.isExpired(now)) continue;
        arr.append(r.toJson());
    }
    // 原子落盘(规则库含用户的加白项)。写入失败不崩溃,内存规则仍生效,但必须记错误日志。
    if (!writeFileAtomically(path_, QJsonDocument(arr).toJson(QJsonDocument::Indented),
                             QStringLiteral("规则库"))) {
        Logger(QStringLiteral("bulwark.service.RuleStore"))
            .error(QStringLiteral("规则库落盘失败,本次规则/信任项变更仅在内存中生效,重启后将丢失:%1")
                       .arg(path_));
    }
}

}
