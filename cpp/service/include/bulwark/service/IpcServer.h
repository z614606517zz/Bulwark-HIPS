#pragma once
#include <QObject>
#include <QHash>
#include <QSet>
#include <QByteArray>
#include <QUuid>
#include <QList>
#include <QPointer>
#include <QLocalSocket>
#include <functional>
#include <utility>

#include "bulwark/ipc/IpcMessage.h"
#include "bulwark/ipc/Payloads.h"
#include "bulwark/models/Enums.h"
#include "bulwark/models/SecurityEvent.h"
#include "bulwark/models/DefenseRule.h"
#include "bulwark/models/RuntimeSettings.h"

class QLocalServer;

namespace bulwark::service {

class IpcServer : public QObject {
    Q_OBJECT
public:
    explicit IpcServer(QObject* parent = nullptr);
    bool start();
    bool start(const QString& pipeName);
    void stop();
    int clientCount() const { return buffers_.size(); }
    quint64 rejectedConnectionCount() const { return rejectedConnections_; }

    std::function<QList<bulwark::DefenseRule>()>              rulesRequested;
    std::function<void(const QUuid&)>                        ruleDeleteRequested;
    std::function<void(const bulwark::ipc::AddRulePayload&)>  ruleAddRequested;
    std::function<bulwark::RuntimeSettings()>                 settingsRequested;
    std::function<void(const bulwark::RuntimeSettings&)>      settingsUpdated;
    std::function<QList<bulwark::DefenseRule>()>              trustListRequested;
    std::function<void(const bulwark::ipc::AddTrustPayload&)> trustAddRequested;
    std::function<void(const QUuid&)>                        trustRemoveRequested;
    std::function<bulwark::ipc::QuarantineListResponsePayload()>              quarantineListRequested;
    std::function<bulwark::ipc::QuarantineActionResultPayload(const QUuid&)>  quarantineRestoreRequested;
    std::function<bulwark::ipc::QuarantineActionResultPayload(const QUuid&)>  quarantineDeleteRequested;
    std::function<std::pair<bool, QString>(const bulwark::ipc::ManualQuarantinePayload&)> manualQuarantineRequested;
    std::function<bulwark::ipc::PersistenceListResponsePayload()> persistenceListRequested;
    std::function<bulwark::ipc::PersistenceCleanupResultPayload(
        const bulwark::ipc::PersistenceCleanupRequestPayload&)> persistenceCleanupRequested;
    std::function<bulwark::ipc::EventHistoryResponsePayload()>     eventHistoryRequested;
    std::function<void()>                                         eventHistoryClearRequested;
    std::function<void(const bulwark::ipc::TimelineRequestPayload&)>    timelineRequested;
    std::function<void(const bulwark::ipc::AttackGraphRequestPayload&)> attackGraphRequested;
    std::function<void(const bulwark::ipc::ProcessListRequestPayload&)> processListRequested;
    std::function<bulwark::ipc::ProcessActionResultPayload(
        const bulwark::ipc::ProcessActionRequestPayload&)>              processActionRequested;
    std::function<void(const bulwark::ipc::SystemBoostRequestPayload&)> systemBoostRequested;
    std::function<bulwark::ipc::IntelRefreshResultPayload(const bulwark::ipc::IntelRefreshRequestPayload&)> intelRefreshRequested;
    std::function<bulwark::ipc::IntelRefreshResultPayload(const bulwark::ipc::IntelApplyRequestPayload&)>   intelApplyRequested;
    std::function<bulwark::ipc::HardeningStatusResponsePayload()> hardeningStatusRequested;
    std::function<bulwark::ipc::HardeningActionResultPayload(
        const bulwark::ipc::HardeningActionRequestPayload&)>      hardeningActionRequested;
    std::function<void(int)>                                 uiProcessConnected;
    std::function<void(bool anySubscriber)>                  netTrafficSubscriptionChanged;

    void sendPrompt(const bulwark::SecurityEvent& e);
    void sendBlock(const bulwark::SecurityEvent& e,
                   bulwark::EnforcementOutcome enforcement =
                       bulwark::EnforcementOutcome::NotApplicable,
                   bool timeoutBlock = false, bool execBlocked = false);
    void sendHijackAlert(const bulwark::ipc::HijackAlertPayload& p);
    void sendNetTraffic(const bulwark::ipc::NetTrafficSnapshotPayload& p,
                        const QHash<int, QList<bulwark::ipc::NetTrafficConnPayload>>& connections = {});
    bool hasNetTrafficSubscribers() const { return !trafficSubscribers_.isEmpty(); }
    void sendLog(const QString& line);
    void sendEventLog(const bulwark::SecurityEvent& e,
                      bulwark::VerdictAction action, bulwark::VerdictSource source,
                      bulwark::EnforcementOutcome enforcement =
                          bulwark::EnforcementOutcome::NotApplicable);
    void sendRemediationReport(const bulwark::ipc::RemediationReportPayload& report);
    void sendTimeline(const bulwark::ipc::TimelineResponsePayload& payload);
    void sendAttackGraph(const bulwark::ipc::AttackGraphResponsePayload& payload);
    void sendProcessList(const bulwark::ipc::ProcessListResponsePayload& payload);
    void sendSystemBoost(const bulwark::ipc::SystemBoostResultPayload& payload);

    void sendRules(QLocalSocket* only = nullptr);
    void sendSettings(QLocalSocket* only = nullptr);
    void sendTrustList(QLocalSocket* only = nullptr);
    void sendQuarantineList(QLocalSocket* only = nullptr);

signals:
    void helloReceived(int processId, const QString& role);
    void promptResponse(const QUuid& eventId, bulwark::VerdictAction action,
                        bool remember, bulwark::RememberScope scope);
    void promptAutoTimeout(const QUuid& eventId);
    void clientCountChanged(int count);

private slots:
    void onNewConnection();
    void onReadyRead();
    void onDisconnected();

private:
    void broadcast(const bulwark::ipc::IpcMessage& msg);
    void sendTo(QLocalSocket* sock, const bulwark::ipc::IpcMessage& msg);
    void deliver(QLocalSocket* only, const bulwark::ipc::IpcMessage& msg);

    QUuid registerAsync(QLocalSocket* sock, const QUuid& clientRequestId);
    QLocalSocket* takeAsyncRoute(const QUuid& serverRequestId, QUuid* clientRequestId);
    template <class P>
    void replyAsync(bulwark::ipc::IpcMessageType type, P payload);

    void handleLine(QLocalSocket* sock, const QString& line);

    static constexpr int kMaxFrameBytes = 4 * 1024 * 1024;

    QLocalServer* server_ = nullptr;
    QHash<QLocalSocket*, QByteArray> buffers_;
    QHash<QLocalSocket*, quint32> clientPids_;
    QSet<QLocalSocket*> trafficSubscribers_;
    QHash<QLocalSocket*, QList<int>> trafficFocus_;
    void setTrafficSubscribed(QLocalSocket* sock, bool on, const QList<int>& focusPids = {});
    struct AsyncRoute {
        QPointer<QLocalSocket> sock;
        QUuid clientRequestId;
    };
    QHash<QUuid, AsyncRoute> asyncRoutes_;
    quint64 rejectedConnections_ = 0;
};

}
