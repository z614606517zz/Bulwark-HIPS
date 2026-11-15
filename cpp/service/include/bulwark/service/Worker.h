#pragma once
#include <QObject>
#include <QHash>
#include <QList>
#include <QUuid>
#include <QQueue>
#include <QSet>
#include <QMutex>
#include <QWaitCondition>
#include <QDateTime>
#include <QTimer>
#include <QPair>
#include <QString>
#include <QThreadPool>
#include <memory>
#include <thread>
#include <vector>
#include <atomic>
#include <functional>
#include <optional>
#include "bulwark/models/SecurityEvent.h"
#include "bulwark/models/Enums.h"
#include "bulwark/models/RuntimeSettings.h"
#include "bulwark/ipc/Payloads.h"
#include "bulwark/engine/RuleEngine.h"
#include "bulwark/engine/ProcessChainTracker.h"
#include "bulwark/service/Logger.h"
#include "bulwark/service/YaraScanner.h"

namespace bulwark::service {

class IpcServer;
class EventSource;
class RuleStore;
class AuditLog;
class FirstSeenStore;
class QuarantineManager;
class ThreatRemediator;
class AlertExporter;
struct RemediationReport;
class EventHistoryStore;
class UserModeProcessContainment;
class SystemHardening;
class DurableExecBlockAuthorization;

class Worker : public QObject {
    Q_OBJECT
public:
    Worker(bulwark::engine::RuleEngine* engine, IpcServer* ipc, EventSource* source,
           RuleStore* ruleStore, AuditLog* audit, FirstSeenStore* firstSeen,
           QuarantineManager* quarantine,
           const bulwark::RuntimeSettings* settings, QObject* parent = nullptr);
    ~Worker();

    void setEventHistory(EventHistoryStore* history) { eventHistory_ = history; }

    void publishProtectionEnabled(bool enabled) { sweepProtectionEnabled_.store(enabled); }

    // 已在执行前被拒绝的事件(AMSI 送检):只上报与记录,不再处置。
    void reportPreBlockedEvent(const bulwark::SecurityEvent& e);

    void setProtectionSuspended(bool on) { protectionSuspended_.store(on); }
    bool protectionSuspended() const { return protectionSuspended_.load(); }

    void setAlertExporter(AlertExporter* exporter) { alertExporter_ = exporter; }

    void setTaintRuleInjector(std::function<int(const QVector<bulwark::DefenseRule>&)> fn) {
        injectTaintRules_ = std::move(fn);
    }


    void setContainment(UserModeProcessContainment* c) { containment_ = c; }

    // 进程启动的 YARA 扫描。必须在 Worker 析构前 stop 掉扫描器:判恶意的回调会投递到本对象。
    void setYaraScanner(YaraScanner* scanner);

    void setHardening(SystemHardening* h, bool denyExecute, bool regHarden,
                      bool regDenyWrite = false) {
        hardening_ = h;
        denyExecuteEnabled_ = denyExecute;
        regHardenEnabled_ = regHarden;
        regDenyWriteEnabled_ = regDenyWrite;
    }
    void setFreezeOnDetect(bool on) { freezeOnDetect_ = on; }

    void startMaliciousSweep();

    void startPreexistingAudit(int delaySeconds = 25);

    static void setSelfExemptDirs(const QStringList& dirs);

    static void setProductSignerThumbprint(const QString& thumbprint) { s_productSignerThumbprint = thumbprint.trimmed().toUpper(); }

    std::pair<bool, QString> forceQuarantine(const QString& path);

    std::pair<bool, QString> forceHandle(const bulwark::ipc::ManualQuarantinePayload& req);

    bulwark::ipc::PersistenceCleanupResultPayload cleanupPersistence(
        const bulwark::ipc::PersistenceCleanupRequestPayload& req);

    void reconcileKernelBlocksAfterTrust();

    void purgeTaintRulesAfterTrust();

private slots:
    void onEvent(const bulwark::SecurityEvent& e);
    void onPromptResponse(const QUuid& eventId, bulwark::VerdictAction action,
                          bool remember, bulwark::RememberScope scope);
    void onPromptAutoTimeout(const QUuid& eventId);
    void onPromptTimeoutTick();

private:
    void processEvent(const bulwark::SecurityEvent& e);
    void enrich(bulwark::SecurityEvent& e);
    void seedAncestryChain(bulwark::SecurityEvent& e);
    bool hasProductSignedAncestor(const bulwark::SecurityEvent& e) const;
    inline static QString s_productSignerThumbprint;
    bulwark::EnforcementOutcome enforceBlock(const bulwark::SecurityEvent& e,
                                            bool persistentBlacklist = true,
                                            bool* execBlockedOut = nullptr);
    bool killMalicious(int pid);
    void rememberTerminated(int pid, const QString& imagePath, quint64 creationFileTime = 0);
    // creationFileTime 与记录双方都非 0 时按实例精确比对(PID 已被复用也认得出);否则退回 PID + 映像。
    bool wasTerminatedByUs(int pid, const QString& imagePath,
                           QDateTime* killedAtUtc = nullptr,
                           quint64 creationFileTime = 0) const;
    bool blacklistExec(const DurableExecBlockAuthorization& authorization);
    bool denyExecuteRevocable(const QString& imagePath, const QString& why);
    bool abortIfTrustedNow(const bulwark::SecurityEvent& e, const QString& stage);
    void maybeQuarantineOnBlock(const bulwark::SecurityEvent& e);
    void applyRegHardening(const RemediationReport& report);
    bool remediateIfMalicious(const bulwark::SecurityEvent& e, const bulwark::Verdict& v);
    static bool isDeterministicMaliciousBlock(const bulwark::SecurityEvent& e, const bulwark::Verdict& v);
    void maybeHandleLaunchingParent(const bulwark::SecurityEvent& e);
    void remediateOnUserBlock(const bulwark::SecurityEvent& e);
    void publishRemediation(const bulwark::SecurityEvent& e, const RemediationReport& report,
                            const QString& reason, bulwark::VerdictSource source);

    void taintDroppedFiles(const bulwark::SecurityEvent& e, bulwark::VerdictAction grade,
                           const QString& why);
public:
    static QString taintRuleTag();
    static bool isTaintRuleNote(const QString& note);

private:
    void dropTaintRulesMatching(const bulwark::SecurityEvent& e);
    int evictOldTaintRules(int incoming);
    QThreadPool taintPool_;

    void sweepLoop();
    void handleSweptMalicious(const bulwark::SecurityEvent& e, bulwark::VerdictSource source);
    void seedMaliciousHashesFromRules();
    static bool isSweepExemptPath(const QString& path);
    static QStringList s_sweepExemptDirs;
    static QMutex s_sweepExemptMx;

    void preexistingAuditLoop(int delaySeconds);
    void evaluatePreexisting(const bulwark::SecurityEvent& e);
    QSet<QString> preexistingSeen_;
    void enqueuePrompt(const bulwark::SecurityEvent& e, bool freezeWhilePending);
    void applySilentMode(const bulwark::SecurityEvent& e, bulwark::VerdictAction& action,
                         bulwark::VerdictSource& source);

    void detectSideloadedTamperedModule(bulwark::SecurityEvent& e);
    struct SideloadScan {
        QString tamperedPath;
        QString unsignedPath;
        QString unsignedWhy;
    };
    QHash<QString, SideloadScan> tamperScanCache_;

    void scanScriptFileBody(bulwark::SecurityEvent& e);
    void applyYaraVerdict(bulwark::SecurityEvent& e);
    void onYaraMalicious(const QString& sha256, const YaraScanner::Verdict& verdict,
                         const QVector<YaraScanner::Target>& targets);
    YaraScanner* yara_ = nullptr;
    struct ScriptBodyScan {
        int score = 0;
        bool hard = false;
        QStringList hits;
        QStringList reasons;
        QVector<bulwark::ThreatSnippet> snippets;
    };
    QHash<QString, ScriptBodyScan> scriptBodyCache_;

    QString originalFileNameCached(const QString& path);
    QHash<QString, QString> originalNameCache_;

    void attributeSpoofedParent(bulwark::SecurityEvent& e);

    void recordEvent(const bulwark::SecurityEvent& e, bulwark::VerdictAction action,
                     bulwark::VerdictSource source,
                     bulwark::EnforcementOutcome enforcement =
                         bulwark::EnforcementOutcome::NotApplicable);
    void writeAudit(const bulwark::SecurityEvent& e, bulwark::VerdictAction action,
                    bulwark::VerdictSource source,
                    bulwark::EnforcementOutcome enforcement =
                        bulwark::EnforcementOutcome::NotApplicable,
                    std::optional<bulwark::VerdictAction> rawAction = std::nullopt,
                    std::optional<bulwark::VerdictSource> rawSource = std::nullopt);
    QString describe(const bulwark::SecurityEvent& e, bulwark::VerdictAction action) const;
    bool isDimensionEnabled(bulwark::EventType type) const;

    bulwark::engine::RuleEngine* engine_;
    IpcServer* ipc_;
    EventSource* source_ = nullptr;
    RuleStore* ruleStore_;
    AuditLog* audit_;
    FirstSeenStore* firstSeen_;
    QuarantineManager* quarantine_ = nullptr;
    UserModeProcessContainment* containment_ = nullptr;
    bool freezeOnDetect_ = true;
    SystemHardening* hardening_ = nullptr;
    bool denyExecuteEnabled_ = false;
    bool regHardenEnabled_ = false;
    bool regDenyWriteEnabled_ = false;
    std::unique_ptr<ThreatRemediator> remediator_;
    EventHistoryStore* eventHistory_ = nullptr;
    AlertExporter* alertExporter_ = nullptr;
    std::function<int(const QVector<bulwark::DefenseRule>&)> injectTaintRules_;
    const bulwark::RuntimeSettings* settings_ = nullptr;
    bulwark::engine::ProcessChainTracker chain_;

    static constexpr int kKilledMemoryTtlSecs = 1800;
    static constexpr int kKilledMemoryMax = 256;
    static constexpr qint64 kQueuedBeforeExitGraceSecs = 10;
    struct KilledProcess {
        QString imagePath;
        quint64 creationFileTime = 0;  // 0:结束前没取到实例身份
        QDateTime killedAtUtc;
    };
    QHash<int, KilledProcess> killedByUs_;

    struct PendingPrompt {
        bulwark::SecurityEvent event;
        QDateTime deadlineUtc;
    };
    QHash<QUuid, PendingPrompt> pending_;
    QTimer* promptTimer_ = nullptr;

    static constexpr int kDecidedPromptMemory = 512;
    QSet<QUuid> decidedPrompts_;
    QQueue<QUuid> decidedPromptsOrder_;
    void rememberPromptDecided(const QUuid& id);
    void resolvePromptByDefault(const bulwark::SecurityEvent& e, const QString& why,
                                bool fromTimeout);

    Logger log_{QStringLiteral("Worker")};

    struct AllowBurst {
        qint64  firstMs = 0;
        quint32 folded  = 0;
    };
    static constexpr qint64 kAllowFoldWindowMs = 60000;
    static constexpr int    kAllowFoldMaxKeys  = 512;
    QHash<QString, AllowBurst> allowBursts_;
    bool shouldLogAllow(const bulwark::SecurityEvent& e, bulwark::VerdictAction action,
                        QString* summaryOut);

    // 同源同目标的自我保护事件折叠:窗口内只进事件列表一条(任务管理器反复结束
    // 本产品进程时会刷几百条),审计与文本日志照记,汇总以折叠摘要输出。
    struct SelfProtectBurst {
        qint64  firstMs = 0;
        quint32 folded  = 0;
    };
    static constexpr qint64 kSelfProtectFoldWindowMs = 60000;
    // 可信系统工具(任务管理器等)的自保事件是常态背景噪音(预开危险句柄),
    // 窗口放长到 30 分钟,事件列表基本只留一条折叠记录。
    static constexpr qint64 kSelfProtectSystemToolFoldWindowMs = 30 * 60 * 1000;
    QHash<QString, SelfProtectBurst> selfProtectBursts_;
    bool shouldRecordEvent(const bulwark::SecurityEvent& e, QString* foldSummaryOut);


    std::thread sweepWorker_;
    std::atomic<bool> sweepRunning_{false};
    std::thread preexistingWorker_;
    std::atomic<bool> preexistingRunning_{false};
    std::atomic<bool> sweepProtectionEnabled_{true};
    std::atomic<bool> protectionSuspended_{false};
    QMutex maliciousHashMx_;
    QSet<QString> confirmedMaliciousHashes_;
};

}
