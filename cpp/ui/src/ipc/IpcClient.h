#pragma once
#include <QByteArray>
#include <QList>
#include <QObject>
#include <QString>
#include <QUuid>

#include "ai/AiScanner.h"
#include "bulwark/ipc/IpcMessage.h"
#include "bulwark/ipc/Payloads.h"
#include "bulwark/models/DefenseRule.h"
#include "bulwark/models/Enums.h"
#include "bulwark/models/RuntimeSettings.h"
#include "bulwark/models/SecurityEvent.h"

class QLocalSocket;
class QTimer;
class AiScanner;

class IpcClient : public QObject
{
    Q_OBJECT
public:
    explicit IpcClient(QObject* parent = nullptr);
    ~IpcClient() override;

    void start();
    bool isConnected() const;

    void sendVerdict(const QUuid& eventId, bulwark::VerdictAction action, bool remember,
                     bulwark::RememberScope scope, bool autoTimeout = false);

    void requestRules();
    void addRule(const bulwark::ipc::AddRulePayload& p);
    void deleteRule(const QUuid& ruleId);
    void requestSettings();
    void updateSettings(const bulwark::RuntimeSettings& s);

    bool haveSettings() const { return m_haveSettings; }
    const bulwark::RuntimeSettings& lastSettings() const { return m_lastSettings; }
    void requestTrust();
    void addTrust(const QString& actorPath, const QString& note, bool isDirectory = false,
                  bulwark::RememberScope scope = bulwark::RememberScope::Permanent);
    void removeTrust(const QUuid& ruleId);
    void requestQuarantine();
    void quarantineRestore(const QUuid& id);
    void quarantineDelete(const QUuid& id);
    void requestHardeningStatus();
    QUuid hardeningAction(const QString& action, const QString& id);
    void requestPersistence();
    void requestPersistenceCleanup(const bulwark::PersistenceEntry& entry);
    void requestEventHistory();
    void clearEventHistory();
    void requestTimeline(const bulwark::ipc::TimelineRequestPayload& p);
    QUuid requestAttackGraph(const QUuid& seedEventId, int rootPid = 0, int windowSeconds = 3600);
    QUuid requestProcesses(bool includeCommandLine = true, bool resolveOrigin = true);
    void processAction(const bulwark::ipc::ProcessActionRequestPayload& p);
    QUuid requestSystemBoost();
    void setNetTrafficSubscribed(bool on, const QList<int>& focusPids = {});
    
    void manualQuarantine(const QString& path);
    QUuid forceHandle(const bulwark::ipc::RemediationSkippedItem& item);
    void aiGenerateRules(const QString& request);

    AiScanner* aiScanner() const { return m_ai; }

signals:
    void connectionChanged(bool connected);
    void promptReceived(const bulwark::SecurityEvent& event);
    void blockNotification(const bulwark::SecurityEvent& event,
                           bulwark::EnforcementOutcome enforcement,
                           bool timeoutBlock, bool execBlocked);
    void logReceived(const QString& line);
    void eventLogReceived(const bulwark::ipc::EventLogPayload& entry);
    void eventHistoryReceived(const QList<bulwark::ipc::EventLogPayload>& events);
    void remediationReport(const bulwark::ipc::RemediationReportPayload& report);
    void manualQuarantineResult(const bulwark::ipc::ManualQuarantineResultPayload& result);
    void rulesReceived(const QList<bulwark::DefenseRule>& rules);
    void trustReceived(const QList<bulwark::DefenseRule>& entries);
    void settingsReceived(const bulwark::RuntimeSettings& settings);
    void quarantineReceived(const QList<bulwark::ipc::QuarantineItemPayload>& items);
    void quarantineActionResult(const bulwark::ipc::QuarantineActionResultPayload& r);
    void hardeningStatusReceived(const bulwark::ipc::HardeningStatusResponsePayload& payload);
    void hardeningActionResult(const bulwark::ipc::HardeningActionResultPayload& result);
    void hijackAlertReceived(const bulwark::ipc::HijackAlertPayload& alert);
    void persistenceReceived(const bulwark::ipc::PersistenceListResponsePayload& payload);
    void persistenceCleanupDone(const bulwark::ipc::PersistenceCleanupResultPayload& payload);
    void timelineReceived(const bulwark::ipc::TimelineResponsePayload& payload);
    void attackGraphReceived(const bulwark::ipc::AttackGraphResponsePayload& payload);
    void processListReceived(const bulwark::ipc::ProcessListResponsePayload& payload);
    void processActionResult(const bulwark::ipc::ProcessActionResultPayload& result);
    void systemBoostReceived(const bulwark::ipc::SystemBoostResultPayload& result);
    void netTrafficReceived(const bulwark::ipc::NetTrafficSnapshotPayload& snapshot);
    void aiRulesSuggested(const QList<AiSuggestedRule>& rules);

private slots:
    void tryConnect();
    void onConnected();
    void onDisconnected();
    void onReadyRead();

private:
    void send(const bulwark::ipc::IpcMessage& msg);
    void dispatch(const QString& line);

    QLocalSocket* m_sock = nullptr;
    QTimer* m_reconnect = nullptr;
    QByteArray m_buf;
    bool m_connected = false;
    AiScanner* m_ai = nullptr;
    bulwark::RuntimeSettings m_lastSettings;
    bool m_haveSettings = false;
};
