#include "ai/McpManager.h"

#include "design/Confirm.h"

#include <QApplication>
#include <QJsonDocument>
#include <QNetworkAccessManager>
#include <QPointer>
#include <QSet>
#include <QTimer>

#include <algorithm>
#include <memory>

namespace {

QString u(const char* s) { return QString::fromUtf8(s); }

constexpr int kIdleMs = 5 * 60 * 1000;
constexpr int kMaxTools = 64;
constexpr int kMaxDescription = 1000;

QString functionName(int serverIndex, const QString& tool, QSet<QString>& used)
{
    QString clean;
    for (const QChar c : tool) {
        const ushort x = c.unicode();
        const bool ok = (x >= '0' && x <= '9') || (x >= 'a' && x <= 'z') || (x >= 'A' && x <= 'Z') || x == '_' ||
                        x == '-';
        clean += ok ? c : QLatin1Char('_');
    }
    const QString prefix = QStringLiteral("s%1_").arg(serverIndex);
    QString name = (prefix + clean).left(64);
    for (int n = 2; used.contains(name); ++n) {
        const QString tail = QStringLiteral("_%1").arg(n);
        name = (prefix + clean).left(64 - tail.size()) + tail;
    }
    used.insert(name);
    return name;
}

QString toolNames(const QList<McpClient::Tool>& tools)
{
    QStringList names;
    for (const McpClient::Tool& t : tools)
        names << t.name;
    if (names.size() > 6)
        return names.mid(0, 6).join(u("、")) + u(" 等");
    return names.join(u("、"));
}

QString okText(const McpClient* c)
{
    const int n = int(c->tools().size());
    QString t = u("连接正常 · %1 个工具").arg(n);
    if (n > 0)
        t += u(":") + toolNames(c->tools());
    if (!c->protocolVersion().isEmpty())
        t += u(" · 协议 ") + c->protocolVersion();
    return t;
}

}

McpManager::McpManager(QObject* parent)
    : QObject(parent), m_net(new QNetworkAccessManager(this)), m_servers(mcpcfg::load()), m_idle(new QTimer(this))
{
    m_idle->setSingleShot(true);
    m_idle->setInterval(kIdleMs);
    connect(m_idle, &QTimer::timeout, this, &McpManager::stopAll);
}

McpManager::~McpManager()
{
    qDeleteAll(m_clients);
    m_clients.clear();
}

bool McpManager::hasEnabledServers() const
{
    for (const McpServerConfig& c : m_servers)
        if (c.enabled)
            return true;
    return false;
}

void McpManager::setServers(const QList<McpServerConfig>& servers)
{
    m_servers = servers;
    mcpcfg::save(m_servers);
    QHash<QString, const McpServerConfig*> byId;
    for (const McpServerConfig& c : std::as_const(m_servers))
        byId.insert(c.id, &c);
    for (auto it = m_clients.begin(); it != m_clients.end();) {
        const McpServerConfig* now = byId.value(it.key());
        McpClient* client = it.value();
        if (now && now->enabled && now->fingerprint() == client->config().fingerprint()) {
            client->updateConfig(*now);
            ++it;
            continue;
        }
        client->stop();
        client->deleteLater();
        it = m_clients.erase(it);
    }
    for (auto it = m_status.begin(); it != m_status.end();) {
        const McpServerConfig* now = byId.value(it.key());
        if (!now || !now->enabled || !m_clients.contains(it.key()))
            it = m_status.erase(it);
        else
            ++it;
    }
    emit serversChanged();
}

McpClient* McpManager::clientFor(const McpServerConfig& cfg)
{
    McpClient* c = m_clients.value(cfg.id);
    if (c && c->config().fingerprint() != cfg.fingerprint()) {
        c->stop();
        c->deleteLater();
        c = nullptr;
    }
    if (!c) {
        c = new McpClient(cfg, m_net, this);
        m_clients.insert(cfg.id, c);
    }
    return c;
}

void McpManager::setStatus(const QString& id, Status::Kind kind, const QString& text)
{
    m_status.insert(id, Status{kind, text});
    emit statusChanged(id);
}

void McpManager::touch()
{
    m_idle->start();
}

void McpManager::stopAll()
{
    for (McpClient* c : std::as_const(m_clients)) {
        c->stop();
        c->deleteLater();
    }
    m_clients.clear();
}

void McpManager::collectTools(ToolsFn onDone)
{
    touch();
    QList<McpServerConfig> enabled;
    for (const McpServerConfig& c : std::as_const(m_servers))
        if (c.enabled)
            enabled << c;
    if (enabled.isEmpty()) {
        onDone({}, {});
        return;
    }
    struct Gather {
        int remaining = 0;
        QStringList problems;
        ToolsFn onDone;
    };
    auto g = std::make_shared<Gather>();
    g->remaining = int(enabled.size());
    g->onDone = std::move(onDone);

    const auto finish = [this, g, enabled] {
        QList<ToolRef> out;
        QSet<QString> used;
        int index = 0;
        for (const McpServerConfig& cfg : enabled) {
            ++index;
            McpClient* c = m_clients.value(cfg.id);
            if (!c || !c->isReady())
                continue;
            for (const McpClient::Tool& t : c->tools()) {
                if (out.size() >= kMaxTools) {
                    g->problems << u("工具总数超过 %1 个,其余未提供给大模型").arg(kMaxTools);
                    break;
                }
                ToolRef r;
                r.fnName = functionName(index, t.name, used);
                r.serverId = cfg.id;
                r.serverName = cfg.name;
                r.toolName = t.name;
                QString desc = t.description.trimmed();
                if (!t.title.isEmpty())
                    desc = t.title + (desc.isEmpty() ? QString() : u(":") + desc);
                r.description = (u("[MCP 服务器「%1」的工具 %2] ").arg(cfg.name, t.name) + desc).left(kMaxDescription);
                r.inputSchema = t.inputSchema;
                if (r.inputSchema.value(QStringLiteral("type")).toString() != QLatin1String("object"))
                    r.inputSchema = QJsonObject{{QStringLiteral("type"), QStringLiteral("object")},
                                                {QStringLiteral("properties"), QJsonObject{}}};
                r.autoApprove = cfg.autoApprove;
                out << r;
            }
        }
        g->onDone(out, g->problems);
    };

    for (const McpServerConfig& cfg : enabled) {
        McpClient* c = clientFor(cfg);
        const bool already = c->isReady();
        if (!already)
            setStatus(cfg.id, Status::Kind::Busy, u("正在连接…"));
        c->start([this, g, finish, id = cfg.id, name = cfg.name, client = QPointer<McpClient>(c)](bool ok,
                                                                                                  const QString& err) {
            if (ok && client)
                setStatus(id, Status::Kind::Ok, okText(client));
            else if (!ok) {
                setStatus(id, Status::Kind::Error, u("连接失败:") + err);
                g->problems << name + u(":") + err;
            }
            if (--g->remaining == 0)
                finish();
        });
    }
}

void McpManager::callTool(const ToolRef& tool, const QJsonObject& args, McpClient::CallFn onDone)
{
    touch();
    McpClient* c = m_clients.value(tool.serverId);
    if (!c) {
        onDone(false, u("MCP 服务器「%1」已断开").arg(tool.serverName));
        return;
    }
    c->callTool(tool.toolName, args, [this, onDone](bool ok, const QString& text) {
        touch();
        onDone(ok, text);
    });
}

bool McpManager::approve(const ToolRef& tool, const QJsonObject& args, const QString& purpose)
{
    if (tool.autoApprove)
        return true;
    QString shown = QString::fromUtf8(QJsonDocument(args).toJson(QJsonDocument::Indented)).trimmed();
    if (shown.size() > 1500)
        shown = shown.left(1500) + u("\n…(已截断)");
    ui::ConfirmSpec c;
    c.risk = ui::Risk::Caution;
    c.title = u("允许 AI 调用 MCP 工具");
    c.summary = u("「%1」时,大模型要调用 MCP 服务器「%2」的工具「%3」。").arg(purpose, tool.serverName, tool.toolName);
    c.consequences << u("下面的参数是大模型生成的,会原样发给这台 MCP 服务器")
                   << u("工具返回的内容会发给「大模型接入」里配置的接口")
                   << u("工具能做什么(读写文件、访问网络……)取决于这台服务器本身")
                   << u("拒绝后 AI 会在没有这个结果的情况下继续生成");
    c.subjectLabel = u("参数");
    c.subject = shown.isEmpty() ? u("(无参数)") : shown;
    c.confirmText = u("允许这一次");
    c.cancelText = u("拒绝");
    return ui::confirm(QApplication::activeWindow(), c);
}

void McpManager::test(const McpServerConfig& cfg, TestFn onDone)
{
    const bool known = std::any_of(m_servers.cbegin(), m_servers.cend(),
                                   [&cfg](const McpServerConfig& s) { return s.id == cfg.id; });
    if (known)
        setStatus(cfg.id, Status::Kind::Busy, u("正在测试连接…"));
    auto* c = new McpClient(cfg, m_net, this);
    c->start([this, c, cfg, known, onDone](bool ok, const QString& err) {
        const QString msg = ok ? okText(c) : u("连接失败:") + err;
        if (known)
            setStatus(cfg.id, ok ? Status::Kind::Ok : Status::Kind::Error, msg);
        c->stop();
        c->deleteLater();
        if (onDone)
            onDone(ok, msg);
    });
}
