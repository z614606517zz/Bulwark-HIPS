#pragma once
#include <QHash>
#include <QList>
#include <QObject>
#include <QString>
#include <functional>
#include <memory>

class QJsonArray;

#include "bulwark/ipc/Payloads.h"
#include "bulwark/models/Enums.h"
#include "bulwark/models/SecurityEvent.h"

class QNetworkAccessManager;
class McpManager;

struct AiSuggestedRule {
    bulwark::ipc::AddRulePayload payload;
    QString note;
};

enum class AiExplainContext { Prompt, Blocked, Alerted, Traffic };

struct AiExplanation {
    enum class Advice { Unknown, Block, Allow, Caution };

    bool ok = false;
    QString error;
    Advice advice = Advice::Unknown;
    QString confidence;
    QString summary;
    qint64 elapsedMs = 0;
    int tokens = 0;
    bool cached = false;
    bool cachedSimilar = false;
    qint64 cachedAgeMs = 0;
    qint64 entryId = 0;
};

struct AiCallRecord {
    enum class Kind {
        ExplainPrompt,
        ExplainBlocked,
        ExplainAlerted,
        Rules,
        Test,
        ExplainTraffic,
    };
    enum class Outcome { Ok, Failed, Cached, Skipped };

    qint64 seq = 0;
    qint64 atMs = 0;
    Kind kind = Kind::ExplainPrompt;
    Outcome outcome = Outcome::Ok;
    QString model;
    QString host;
    QString subject;
    QString result;
    QString advice;
    QString confidence;
    int tokens = 0;
    qint64 elapsedMs = 0;
    qint64 entryId = 0;
    bool cachedSimilar = false;
};

class AiScanner : public QObject
{
    Q_OBJECT
public:
    explicit AiScanner(QObject* parent = nullptr);

    void setConfig(const QString& baseUrl, const QString& apiKey, const QString& model);
    bool isConfigured() const;
    bool configKnown() const { return m_configKnown; }

    void setCreditGuard(bool enabled, qint64 monthlyBudget);
    qint64 creditUsedThisMonth() const { return m_creditUsed; }
    qint64 creditBudget() const { return m_creditBudget; }
    bool creditGuardEnabled() const { return m_creditGuard; }

    QString modelName() const { return m_model; }
    QString endpointHost() const;

    void testConnection(const QString& baseUrl, const QString& apiKey, const QString& model, QObject* receiver,
                        std::function<void(bool ok, const QString& message)> onDone);

    void generateRules(const QString& request);

    bool promptExplainEnabled() const { return m_explainEnabled; }
    void setPromptExplainEnabled(bool on);

    bool blockExplainEnabled() const { return m_blockExplainEnabled; }
    void setBlockExplainEnabled(bool on);

    void explainEvent(const bulwark::SecurityEvent& e, QObject* receiver,
                      std::function<void(const AiExplanation&)> onDone,
                      AiExplainContext context = AiExplainContext::Prompt);

    McpManager* mcp() const { return m_mcp; }

    const QList<AiCallRecord>& callLog() const { return m_callLog; }
    void clearCallLog();

    struct ExplainEntry {
        qint64 id = 0;
        qint64 atMs = 0;
        QString summary;
        AiExplanation::Advice advice = AiExplanation::Advice::Unknown;
        QString confidence;
        bool namesActor = false;
    };
    QList<ExplainEntry> explainEntries();
    bool forgetExplainEntry(qint64 id);
    int clearExplainCache();
    static QString explainCacheFilePath();
    static QString creditFilePath();

signals:
    void rulesSuggested(const QList<AiSuggestedRule>& rules);
    void creditExhausted(qint64 used, qint64 budget);
    void callLogged(const AiCallRecord& record);
    void callLogCleared();
    void explainCacheChanged();
    void creditUsageChanged(qint64 used, qint64 budget);

private:
    QString endpoint() const;
    void postChat(const QString& systemPrompt, const QString& userPrompt,
                  std::function<void(bool ok, const QString& content, int tokens)> onDone,
                  int timeoutMs = 60000, const QString& toolPurpose = QString());
    struct ChatLoop;
    void chatRound(const std::shared_ptr<ChatLoop>& loop);
    void runToolCalls(const std::shared_ptr<ChatLoop>& loop, const QJsonArray& calls, int index);

    void loadCredit();
    void saveCredit() const;
    bool creditBlocked();
    void addCreditUsage(int tokens);

    void logCall(AiCallRecord r);

    QNetworkAccessManager* m_net = nullptr;
    McpManager* m_mcp = nullptr;
    QString m_base;
    QString m_key;
    QString m_model;

    bool    m_creditGuard = false;
    qint64  m_creditBudget = 0;
    qint64  m_creditUsed = 0;
    QString m_creditMonth;

    void ensureExplainCacheLoaded();
    // 每周一次的清理:删掉存过一周的条目并记下清理时刻。读取路径本来就不会用过期条目,
    // 所以这件事管的是「别把陈旧解读一直留在盘上」和文件体积,不是正确性。
    void sweepExplainCache(qint64 nowMs, bool force = false);
    void saveExplainCache() const;

    struct CachedExplanation {
        AiExplanation result;
        qint64 atMs = 0;
        qint64 id = 0;
        QString exactKey;
        bool namesActor = false;
    };
    struct ExplainWaiter {
        QString exactKey;
        QString subject;
        std::function<void(const AiExplanation&)> deliver;
    };
    bool m_explainEnabled = true;
    bool m_explainCacheLoaded = false;
    qint64 m_explainSweptAtMs = 0;
    qint64 m_explainNextId = 1;
    QHash<QString, CachedExplanation> m_explainCache;
    QHash<QString, QList<ExplainWaiter>> m_explainWaiting;
    QList<qint64> m_explainStarts;
    bool m_blockExplainEnabled = true;
    bool m_configKnown = false;
    QList<qint64> m_explainBlockedStarts;

    QList<AiCallRecord> m_callLog;
    qint64 m_callSeq = 0;
};
