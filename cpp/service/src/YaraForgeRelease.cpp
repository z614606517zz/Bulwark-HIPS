#include "bulwark/service/YaraForgeRelease.h"

#include "bulwark/json/JsonSupport.h"

#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QRegularExpression>
#include <QUrl>

namespace bulwark::service::yara {

std::optional<ReleaseAsset> parseLatestRelease(const QByteArray& json, const QString& package,
                                               const QString& allowedPrefix, QString* error) {
    using namespace bulwark::json;
    const auto fail = [error](const QString& why) -> std::optional<ReleaseAsset> {
        if (error) *error = why;
        return std::nullopt;
    };

    QJsonParseError err{};
    const QJsonDocument doc = QJsonDocument::fromJson(json, &err);
    if (err.error != QJsonParseError::NoError || !doc.isObject())
        return fail(QStringLiteral("发布信息不是有效的 JSON"));
    const QJsonObject root = doc.object();
    if (getBool(root, "draft") || getBool(root, "prerelease"))
        return fail(QStringLiteral("最新发布是草稿或预发布版本"));

    ReleaseAsset asset;
    asset.tag = getStr(root, "tag_name").trimmed();
    asset.publishedUtc = dateTimeFromIso(getStr(root, "published_at"));
    static const QRegularExpression safeTag(QStringLiteral("^[A-Za-z0-9._-]{1,64}$"));
    if (!safeTag.match(asset.tag).hasMatch())
        return fail(QStringLiteral("发布标签缺失或格式异常"));

    const QString wanted = QStringLiteral("yara-forge-rules-%1.zip").arg(package.trimmed().toLower());
    for (const QJsonValue& v : root.value(QLatin1String("assets")).toArray()) {
        const QJsonObject a = v.toObject();
        if (getStr(a, "name") != wanted)
            continue;
        asset.name = wanted;
        asset.url = getStr(a, "browser_download_url");
        asset.size = getI64(a, "size");
        const QString digest = getStr(a, "digest").trimmed().toLower();
        if (digest.startsWith(QLatin1String("sha256:"))) {
            const QString hex = digest.mid(7);
            static const QRegularExpression sha(QStringLiteral("^[0-9a-f]{64}$"));
            if (!sha.match(hex).hasMatch())
                return fail(QStringLiteral("发布页给出的 SHA-256 摘要格式异常"));
            asset.sha256 = hex;
        }
        const QUrl url(asset.url);
        if (!url.isValid() || url.scheme() != QLatin1String("https") || allowedPrefix.isEmpty()
            || !asset.url.startsWith(allowedPrefix))
            return fail(QStringLiteral("下载地址不在允许的范围内:%1").arg(asset.url));
        if (asset.size <= 0)
            return fail(QStringLiteral("发布页没有给出规则包大小"));
        return asset;
    }
    return fail(QStringLiteral("最新发布 %1 里没有 %2").arg(asset.tag, wanted));
}

std::optional<CompileReport> parseCompileReport(const QByteArray& json) {
    using namespace bulwark::json;
    QJsonParseError err{};
    const QJsonDocument doc = QJsonDocument::fromJson(json, &err);
    if (err.error != QJsonParseError::NoError || !doc.isObject())
        return std::nullopt;
    const QJsonObject o = doc.object();
    if (!o.value(QLatin1String("ok")).isBool())
        return std::nullopt;

    CompileReport r;
    r.ok = getBool(o, "ok");
    r.error = getStr(o, "error");
    r.engine = getStr(o, "engine");
    r.sourceName = getStr(o, "sourceName");
    r.sourceBytes = getI64(o, "sourceBytes");
    r.packageName = getStr(o, "packageName");
    r.packageCreated = getStr(o, "packageCreated");
    r.packageDeclaredRules = getInt(o, "packageDeclaredRules");
    r.rulesFound = getInt(o, "rulesFound");
    r.rulesCompiled = getInt(o, "rulesCompiled");
    r.rulesSkipped = getInt(o, "rulesSkipped");
    r.compileMs = getI64(o, "compileMs");
    r.outputBytes = getI64(o, "outputBytes");
    for (const QJsonValue& v : o.value(QLatin1String("sources")).toArray())
        if (v.isObject()) r.sources.append(bulwark::ipc::YaraRuleSourcePayload::fromJson(v.toObject()));
    for (const QJsonValue& v : o.value(QLatin1String("skipped")).toArray())
        if (v.isObject()) r.skipped.append(bulwark::ipc::YaraSkippedRulePayload::fromJson(v.toObject()));
    r.hardening = getStrList(o, "hardening");
    return r;
}

bool plausibleRuleCount(int compiled, int previous) {
    if (compiled < 50)
        return false;
    return previous <= 0 || compiled * 2 >= previous;
}

}
