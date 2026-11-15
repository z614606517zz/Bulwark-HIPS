#pragma once
#include "ai/McpClient.h"
#include "ai/McpConfig.h"

#include <QHash>
#include <QJsonObject>
#include <QList>
#include <QObject>
#include <QStringList>

#include <functional>

class QNetworkAccessManager;
class QTimer;

class McpManager : public QObject
{
    Q_OBJECT
public:
    struct ToolRef {
        QString fnName;
        QString serverId;
        QString serverName;
        QString toolName;
        QString description;
        QJsonObject inputSchema;
        bool autoApprove = false;
    };
    struct Status {
        enum class Kind { Unknown, Busy, Ok, Error };
        Kind kind = Kind::Unknown;
        QString text;
    };
    using ToolsFn = std::function<void(const QList<ToolRef>& tools, const QStringList& problems)>;
    using TestFn = std::function<void(bool ok, const QString& message)>;

    explicit McpManager(QObject* parent = nullptr);
    ~McpManager() override;

    QList<McpServerConfig> servers() const { return m_servers; }
    void setServers(const QList<McpServerConfig>& servers);
    bool hasEnabledServers() const;
    Status status(const QString& id) const { return m_status.value(id); }

    void collectTools(ToolsFn onDone);
    void callTool(const ToolRef& tool, const QJsonObject& args, McpClient::CallFn onDone);
    bool approve(const ToolRef& tool, const QJsonObject& args, const QString& purpose);

    void test(const McpServerConfig& cfg, TestFn onDone);

signals:
    void serversChanged();
    void statusChanged(const QString& id);

private:
    McpClient* clientFor(const McpServerConfig& cfg);
    void setStatus(const QString& id, Status::Kind kind, const QString& text);
    void touch();
    void stopAll();

    QNetworkAccessManager* m_net = nullptr;
    QList<McpServerConfig> m_servers;
    QHash<QString, McpClient*> m_clients;
    QHash<QString, Status> m_status;
    QTimer* m_idle = nullptr;
};
