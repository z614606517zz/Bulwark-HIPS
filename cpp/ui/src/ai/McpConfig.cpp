#include "ai/McpConfig.h"

#include <QByteArray>
#include <QCryptographicHash>
#include <QJsonArray>
#include <QJsonDocument>
#include <QSettings>
#include <QHostAddress>
#include <QUrl>
#include <QUuid>
#include <cstring>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <wincrypt.h>
#endif

namespace {

QString u(const char* s) { return QString::fromUtf8(s); }

constexpr const char* kSettingsKey = "ai/mcpServers";
constexpr const char* kProtectedPrefix = "dpapi:";

QByteArray protectSettings(const QByteArray& plain)
{
#ifdef _WIN32
    if (plain.isEmpty())
        return QByteArray(kProtectedPrefix);
    QByteArray mutablePlain = plain;
    QByteArray entropy("Bulwark.McpConfig.v1");
    DATA_BLOB input{static_cast<DWORD>(mutablePlain.size()),
                    reinterpret_cast<BYTE*>(mutablePlain.data())};
    DATA_BLOB extra{static_cast<DWORD>(entropy.size()),
                    reinterpret_cast<BYTE*>(entropy.data())};
    DATA_BLOB output{};
    if (!::CryptProtectData(&input, L"Bulwark MCP configuration", &extra, nullptr, nullptr,
                            CRYPTPROTECT_UI_FORBIDDEN, &output)) {
        ::SecureZeroMemory(mutablePlain.data(), static_cast<SIZE_T>(mutablePlain.size()));
        return {};
    }
    const QByteArray encoded(reinterpret_cast<const char*>(output.pbData),
                             static_cast<int>(output.cbData));
    ::LocalFree(output.pbData);
    ::SecureZeroMemory(mutablePlain.data(), static_cast<SIZE_T>(mutablePlain.size()));
    return QByteArray(kProtectedPrefix) + encoded.toBase64();
#else
    return plain;
#endif
}

QByteArray unprotectSettings(const QByteArray& stored)
{
#ifdef _WIN32
    if (!stored.startsWith(kProtectedPrefix))
        return stored; // 旧版明文仅用于一次迁移；下次保存会转成 DPAPI。
    const QByteArray cipher = QByteArray::fromBase64(stored.mid(strlen(kProtectedPrefix)),
                                                      QByteArray::AbortOnBase64DecodingErrors);
    if (cipher.isEmpty())
        return {};
    QByteArray mutableCipher = cipher;
    QByteArray entropy("Bulwark.McpConfig.v1");
    DATA_BLOB input{static_cast<DWORD>(mutableCipher.size()),
                    reinterpret_cast<BYTE*>(mutableCipher.data())};
    DATA_BLOB extra{static_cast<DWORD>(entropy.size()),
                    reinterpret_cast<BYTE*>(entropy.data())};
    DATA_BLOB output{};
    if (!::CryptUnprotectData(&input, nullptr, &extra, nullptr, nullptr,
                              CRYPTPROTECT_UI_FORBIDDEN, &output))
        return {};
    QByteArray plain(reinterpret_cast<const char*>(output.pbData),
                     static_cast<int>(output.cbData));
    ::SecureZeroMemory(output.pbData, output.cbData);
    ::LocalFree(output.pbData);
    return plain;
#else
    return stored;
#endif
}

QJsonArray toArray(const QStringList& l)
{
    QJsonArray a;
    for (const QString& s : l)
        a.append(s);
    return a;
}

QStringList fromArray(const QJsonValue& v)
{
    QStringList out;
    for (const QJsonValue& x : v.toArray())
        if (x.isString())
            out << x.toString();
    return out;
}

QString displayArg(const QString& a)
{
    if (!a.isEmpty() && !a.contains(QLatin1Char(' ')) && !a.contains(QLatin1Char('\t')) &&
        !a.contains(QLatin1Char('"')))
        return a;
    QString q = a;
    q.replace(QLatin1Char('"'), QStringLiteral("\\\""));
    return QLatin1Char('"') + q + QLatin1Char('"');
}

QStringList pairs(const QJsonValue& v, const QString& sep)
{
    QStringList out;
    const QJsonObject o = v.toObject();
    for (auto it = o.begin(); it != o.end(); ++it) {
        const QJsonValue val = it.value();
        QString s;
        if (val.isString())
            s = val.toString();
        else if (val.isDouble())
            s = QString::number(val.toDouble(), 'g', 17);
        else if (val.isBool())
            s = val.toBool() ? QStringLiteral("true") : QStringLiteral("false");
        else
            continue;
        out << it.key() + sep + s;
    }
    return out;
}

bool looksLikeServer(const QJsonObject& o)
{
    return o.contains(QLatin1String("command")) || o.contains(QLatin1String("url")) ||
           o.contains(QLatin1String("serverUrl")) || o.contains(QLatin1String("httpUrl"));
}

}

QString McpServerConfig::validationError() const
{
    if (name.trimmed().isEmpty())
        return u("请填写名称");
    if (isStdio()) {
        if (command.trimmed().isEmpty())
            return u("请填写要运行的命令");
        return QString();
    }
    const QUrl parsed(url.trimmed(), QUrl::StrictMode);
    if (url.trimmed().isEmpty())
        return u("请填写 MCP 端点 URL");
    if (!parsed.isValid() || parsed.host().isEmpty() ||
        (parsed.scheme() != QLatin1String("https") && parsed.scheme() != QLatin1String("http")))
        return u("URL 必须是 https:// 开头的完整地址(本机回环可用 http://)");
    if (parsed.scheme() == QLatin1String("http")) {
        const QString host = parsed.host().toLower();
        QHostAddress address;
        const bool loopback = host == QLatin1String("localhost")
            || (address.setAddress(host) && address.isLoopback());
        if (!loopback)
            return u("远程 MCP 端点必须使用 HTTPS,否则令牌和事件数据会明文传输");
    }
    for (const QString& h : headers) {
        if (h.trimmed().isEmpty())
            continue;
        const int colon = h.indexOf(QLatin1Char(':'));
        if (colon <= 0)
            return u("请求头「%1」格式不对,应为 名称: 值").arg(h.trimmed());
    }
    return QString();
}

QString McpServerConfig::summary() const
{
    if (!isStdio())
        return url.trimmed();
    QStringList parts{displayArg(command.trimmed())};
    for (const QString& a : args)
        parts << displayArg(a);
    return parts.join(QLatin1Char(' '));
}

QString McpServerConfig::fingerprint() const
{
    QJsonObject o = toJson();
    o.remove(QStringLiteral("name"));
    o.remove(QStringLiteral("enabled"));
    o.remove(QStringLiteral("autoApprove"));
    return QString::fromLatin1(
        QCryptographicHash::hash(QJsonDocument(o).toJson(QJsonDocument::Compact), QCryptographicHash::Sha256)
            .toHex());
}

QJsonObject McpServerConfig::toJson() const
{
    QJsonObject o{
        {QStringLiteral("id"), id},
        {QStringLiteral("name"), name},
        {QStringLiteral("enabled"), enabled},
        {QStringLiteral("transport"), isStdio() ? QStringLiteral("stdio") : QStringLiteral("http")},
        {QStringLiteral("autoApprove"), autoApprove},
    };
    if (isStdio()) {
        o[QStringLiteral("command")] = command;
        o[QStringLiteral("args")] = toArray(args);
        o[QStringLiteral("env")] = toArray(env);
        o[QStringLiteral("cwd")] = cwd;
    } else {
        o[QStringLiteral("url")] = url;
        o[QStringLiteral("headers")] = toArray(headers);
    }
    return o;
}

McpServerConfig McpServerConfig::fromJson(const QJsonObject& o)
{
    McpServerConfig c;
    c.id = o.value(QStringLiteral("id")).toString();
    c.name = o.value(QStringLiteral("name")).toString();
    c.enabled = o.value(QStringLiteral("enabled")).toBool(true);
    c.transport = o.value(QStringLiteral("transport")).toString() == QLatin1String("http") ? Transport::Http
                                                                                            : Transport::Stdio;
    c.autoApprove = o.value(QStringLiteral("autoApprove")).toBool(false);
    c.command = o.value(QStringLiteral("command")).toString();
    c.args = fromArray(o.value(QStringLiteral("args")));
    c.env = fromArray(o.value(QStringLiteral("env")));
    c.cwd = o.value(QStringLiteral("cwd")).toString();
    c.url = o.value(QStringLiteral("url")).toString();
    c.headers = fromArray(o.value(QStringLiteral("headers")));
    if (c.id.isEmpty())
        c.id = QUuid::createUuid().toString(QUuid::WithoutBraces);
    return c;
}

QList<McpServerConfig> mcpcfg::load()
{
    const QByteArray stored = QSettings().value(QLatin1String(kSettingsKey)).toString().toUtf8();
    const QByteArray raw = unprotectSettings(stored);
    QList<McpServerConfig> out;
    for (const QJsonValue& v : QJsonDocument::fromJson(raw).array())
        if (v.isObject())
            out << McpServerConfig::fromJson(v.toObject());
    return out;
}

void mcpcfg::save(const QList<McpServerConfig>& servers)
{
    QJsonArray a;
    for (const McpServerConfig& c : servers)
        a.append(c.toJson());
    QSettings s;
    const QByteArray raw = QJsonDocument(a).toJson(QJsonDocument::Compact);
    const QByteArray protectedValue = protectSettings(raw);
    if (protectedValue.isEmpty() && !raw.isEmpty())
        return; // DPAPI 失败时绝不退回明文保存凭据。
    s.setValue(QLatin1String(kSettingsKey), QString::fromLatin1(protectedValue));
    s.sync();
}

QList<McpServerConfig> mcpcfg::parseImport(const QString& json, QString* error)
{
    const auto fail = [error](const QString& msg) {
        if (error)
            *error = msg;
        return QList<McpServerConfig>{};
    };
    QJsonParseError pe{};
    const QJsonDocument doc = QJsonDocument::fromJson(json.trimmed().toUtf8(), &pe);
    if (pe.error != QJsonParseError::NoError || !doc.isObject())
        return fail(u("不是有效的 JSON 对象(%1)").arg(pe.errorString()));
    const QJsonObject root = doc.object();

    QJsonObject table;
    if (root.value(QStringLiteral("mcpServers")).isObject())
        table = root.value(QStringLiteral("mcpServers")).toObject();
    else if (root.value(QStringLiteral("servers")).isObject())
        table = root.value(QStringLiteral("servers")).toObject();
    else if (looksLikeServer(root))
        table.insert(root.value(QStringLiteral("name")).toString(u("MCP 服务器")), root);
    else
        table = root;

    QList<McpServerConfig> out;
    QStringList skipped;
    for (auto it = table.begin(); it != table.end(); ++it) {
        if (!it.value().isObject())
            continue;
        const QJsonObject o = it.value().toObject();
        if (!looksLikeServer(o))
            continue;
        McpServerConfig c;
        c.id = QUuid::createUuid().toString(QUuid::WithoutBraces);
        c.name = it.key().trimmed();
        c.enabled = !o.value(QStringLiteral("disabled")).toBool(false);
        const QString type = o.value(QStringLiteral("type")).toString().toLower();
        if (o.contains(QLatin1String("command"))) {
            c.transport = McpServerConfig::Transport::Stdio;
            c.command = o.value(QStringLiteral("command")).toString().trimmed();
            c.args = fromArray(o.value(QStringLiteral("args")));
            c.env = pairs(o.value(QStringLiteral("env")), QStringLiteral("="));
            c.cwd = o.value(QStringLiteral("cwd")).toString();
        } else {
            if (type == QLatin1String("sse")) {
                skipped << c.name + u("(旧式 SSE 传输,不支持)");
                continue;
            }
            c.transport = McpServerConfig::Transport::Http;
            for (const char* k : {"url", "serverUrl", "httpUrl"})
                if (c.url.isEmpty())
                    c.url = o.value(QLatin1String(k)).toString().trimmed();
            c.headers = pairs(o.value(QStringLiteral("headers")), QStringLiteral(": "));
        }
        const QString why = c.validationError();
        if (!why.isEmpty()) {
            skipped << (c.name.isEmpty() ? u("(未命名)") : c.name) + u("(") + why + u(")");
            continue;
        }
        out << c;
    }
    if (error)
        *error = skipped.isEmpty() ? QString() : u("已跳过:") + skipped.join(u("、"));
    if (out.isEmpty() && skipped.isEmpty())
        return fail(u("没有找到服务器配置。需要形如 {\"mcpServers\": {\"名称\": {\"command\": …}}} 的内容"));
    return out;
}
