#pragma once
#include "bulwark/service/EventSource.h"
#include "bulwark/service/BulwarkOptions.h"
#include "bulwark/service/Logger.h"
#include "bulwark/service/RemoteThreadDeduplicator.h"
#include "bulwark/service/EventSourceRoutingPolicy.h"

#include <QPointer>
#include <QSet>
#include <QStringList>
#include <QVector>

#include <functional>
#include <optional>

class QTimer;
class QByteArray;

namespace bulwark::service {

class DriverEventSource;
class UserModeBehaviorSource;
class UserModeExecBlock;
class UserModeNetworkBlock;

class EventSourceCoordinator : public EventSource {
    Q_OBJECT
public:
    EventSourceCoordinator(EventSource* base, UserModeBehaviorSource* behavior,
                           const BulwarkOptions& options, QObject* parent = nullptr);
    ~EventSourceCoordinator() override;

    void start() override;
    void stop() override;
    bool isAvailable() const override;
    bool wantsVerdict() const override;
    void submitVerdict(const bulwark::SecurityEvent& e, bulwark::VerdictAction action) override;

    using KernelStateHandler = std::function<void(bool connected, const QString& detail)>;
    void setKernelStateChanged(KernelStateHandler fn) { stateChanged_ = std::move(fn); }

    void addAuxSource(EventSource* s);
    void setEventDecorator(std::function<void(bulwark::SecurityEvent&)> fn) { decorator_=std::move(fn); }

    void setKernelEnabled(bool on);
    void configureBehaviorMonitor(bool enabled, bool canaryEnabled);

    void setSuspended(bool on);
    bool isSuspended() const { return suspended_; }

    void setKernelWantedOnResume(bool on);
    void setMemoryProtectionEnabled(bool on) override;
    void applyRansomGuard(bool enabled, const QStringList& dirs,
                          const QStringList& writers) override;
    void applyReadGuard(bool enabled, const QStringList& entries,
                        const QStringList& readers) override;
    QStringList ransomGuardDirs() const { return guardDirs_; }
    void addProtectedUiPid(int pid);
    void removeProtectedUiPid(int pid);

    bool addBlockedIp(const QString& ip, quint16 port = 0);
    int unblockIp(const QString& ip, quint16 port = 0);
    int clearUserModeIpBlocks();
    QStringList userModeBlockedIpList() const;
    bool blockModuleLoad(const QString& modulePath) override;
    bool blockExecPath(const QString& imagePath) override;
    bool clearExecBlock() override;
    bool clearModuleNoLoad() override;
    bool clearBannedProcesses() override;
    QStringList persistedExecBlockList() const override;
    QStringList persistedModuleNoLoadList() const override;

    int suspendUserModeLock(const QString& absPath);
    bool hardenRegistryKey(const QString& keyOrValue) override;

    bool readLockedFile(const QString& path, QByteArray& out);
    bool forceDeleteFile(const QString& path);
    bool killProcess(int pid) override;
    bool banProcess(int pid) override;

    bool kernelConnected() const;
    bool kernelAttachFailed() const { return attachFailed_; }
    bool kernelProtocolMismatch() const;
    QStringList kernelMissingCapabilities() const;

    struct ProtectionCapability {
        QString dimension;
        bool inForce = false;
        QString provider;
        QString limit;
    };
    QVector<ProtectionCapability> protectionCapabilities() const;

    void setHardeningState(bool registryRollbackActive, bool crossRebootExecDeny);

    void setIpcAuthBoundary(bool checked, bool intact, const QString& note);
    QString ipcAuthBoundaryNote() const;

    QString kernelOutboundEnforcementNote() const;

    QString protectionTier() const;
    QString protectionSummary() const;

private slots:
    void onBaseEvent(const bulwark::SecurityEvent& e);
    void onDriverEvent(const bulwark::SecurityEvent& e);
    void onBehaviorEvent(const bulwark::SecurityEvent& e);
    void onKernelRetry();

private:
    void notifyKernelState(bool connected, const QString& detail);
    void emitObserved(const bulwark::SecurityEvent& e);
    std::function<void(bulwark::SecurityEvent&)> decorator_;

    int pushConfiguredIpBlocks();
    void setFallbackEnforcement(bool active);

    void applyKernelEnabled(bool on);

    bool regRollbackActive_ = false;
    bool crossRebootDenyOn_ = false;

    bool ipcBoundaryChecked_ = false;
    bool ipcBoundaryIntact_ = false;
    QString ipcBoundaryNote_;

    EventSource* base_ = nullptr;
    UserModeBehaviorSource* behavior_ = nullptr;
    QVector<QPointer<EventSource>> aux_;
    DriverEventSource* driver_ = nullptr;
    UserModeExecBlock* execBlock_ = nullptr;
    UserModeNetworkBlock* netBlock_ = nullptr;
    QSet<QString> runtimeBlockedEndpoints_;
    const BulwarkOptions& options_;
    QTimer* kernelRetry_ = nullptr;
    QSet<int> protectedPids_;
    KernelStateHandler stateChanged_;
    std::optional<bool> notifiedConnected_;
    bool kernelEnabled_ = false;
    bool attachFailed_ = false;
    bool started_ = false;
    bool suspended_ = false;
    bool kernelWantedBeforeSuspend_ = false;
    bool memProtEnabled_ = true;
    bool guardEnabled_ = true;
    QStringList guardDirs_;
    QStringList guardWriters_;
    bool readGuardEnabled_ = true;
    QStringList readGuardEntries_;
    QStringList readGuardReaders_;
    RemoteThreadDeduplicator remoteThreadDedup_;
    RemoteThreadDeduplicator imageLoadDedup_;
    RemoteThreadDeduplicator observedIoDedup_;
    Logger log_{QStringLiteral("bulwark.service.Coordinator")};
};

}
