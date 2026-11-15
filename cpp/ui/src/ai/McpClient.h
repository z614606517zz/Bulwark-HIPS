#pragma once
#include "ai/McpConfig.h"

#include <QHash>
#include <QJsonObject>
#include <QJsonValue>
#include <QList>
#include <QObject>
#include <QStringList>

#include <functional>

class QNetworkAccessManager;
class QProcess;
class QTimer;

class McpClient : public QObject
{
    Q_OBJECT
public:
    struct HeaderParam {
        QByteArray header;
        QStringList path;
    };
    struct Tool {
        QString name;
        QString title;
        QString description;
        QJsonObject inputSchema;
        QList<HeaderParam> headerParams;
    };
    using ReadyFn = std::function<void(bool ok, const QString& error)>;
    using CallFn = std::function<void(bool ok, const QString& text)>;

    static constexpr const char* kModernVersion = "2026-07-28";
    static constexpr const char* kLegacyVersion = "2025-11-25";

    McpClient(const McpServerConfig& cfg, QNetworkAccessManager* net, QObject* parent = nullptr);
    ~McpClient() override;

    const McpServerConfig& config() const { return m_cfg; }
    void updateConfig(const McpServerConfig& cfg) { m_cfg = cfg; }
    bool isReady() const { return m_state == State::Ready; }
    QString protocolVersion() const { return m_version; }
    const QList<Tool>& tools() const { return m_tools; }

    void start(ReadyFn onReady);
    void callTool(const QString& name, const QJsonObject& args, CallFn onDone);
    void stop();

private:
    enum class State { Idle, Starting, Ready };
    enum class Era { Unknown, Modern, Legacy };
    struct Reply {
        bool delivered = false;
        QString transportError;
        int http = 0;
        bool isError = false;
        int code = 0;
        QString message;
        QJsonValue data;
        QJsonObject result;
    };
    using ReplyFn = std::function<void(const Reply&)>;
    struct Pending {
        ReplyFn fn;
        QTimer* timer = nullptr;
    };

    void request(const QString& method, QJsonObject params, int timeoutMs, ReplyFn onReply,
                 const Tool* tool = nullptr);
    void notify(const QString& method, const QJsonObject& params = {});
    QJsonObject withMeta(QJsonObject params) const;

    void probe();
    void initializeLegacy();
    void listTools(const QString& cursor, int page);
    void finishStart(bool ok, const QString& error);

    bool launch(QString* error);
    void onStdout();
    void handleLine(const QByteArray& line);
    void onProcessFinished();
    void writeMessage(const QJsonObject& msg);
    void detachProcess(bool immediate);
    void dropPending();
    void failAllPending(const QString& why);
    QString stderrTail() const;

    void httpPost(const QJsonObject& msg, int timeoutMs, ReplyFn onReply, const Tool* tool);

    McpServerConfig m_cfg;
    QNetworkAccessManager* m_net = nullptr;
    State m_state = State::Idle;
    Era m_era = Era::Unknown;
    QString m_version;
    QString m_sessionId;
    QList<Tool> m_tools;
    QList<ReadyFn> m_waiting;
    qint64 m_nextId = 1;
    bool m_retriedLegacy = false;

    QProcess* m_proc = nullptr;
    void* m_job = nullptr;
    QByteArray m_outBuf;
    QByteArray m_errTail;
    QHash<qint64, Pending> m_pending;
    QHash<QObject*, ReplyFn> m_inflight;
};
