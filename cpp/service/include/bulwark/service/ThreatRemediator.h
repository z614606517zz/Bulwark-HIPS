#pragma once
#include <QString>
#include <QStringList>
#include <QList>
#include <utility>

#include "bulwark/models/SecurityEvent.h"
#include "bulwark/models/ChainEventInfo.h"
#include "bulwark/models/PersistenceEntry.h"
#include "bulwark/ipc/Payloads.h"
#include "bulwark/service/Logger.h"
#include "bulwark/service/QuarantineManager.h"

namespace bulwark::service {

struct RemediationReport {
    QStringList quarantinedFiles;
    QStringList removedRegistryValues;
    QList<bulwark::ipc::RemediationSkippedItem> skipped;
    QStringList hardenedRegTargets;
    int totalActions() const { return quarantinedFiles.size() + removedRegistryValues.size(); }
};

class ThreatRemediator {
public:
    ThreatRemediator(QuarantineManager& quarantine, Logger logger);

    RemediationReport remediate(const bulwark::SecurityEvent& malicious,
                                const QList<bulwark::ChainEventInfo>& footprint);
    std::pair<bool, QString> forceQuarantine(const QString& path);
    RemediationReport cleanupPersistenceEntry(const bulwark::PersistenceEntry& entry);

    bool undoBlockedWrite(const bulwark::SecurityEvent& e, RemediationReport& report);

    static bool isInUserDropZone(const QString& path, QString* reason = nullptr);

    // 指向 path 的服务、自启动项、映像劫持与计划任务能否按「指向恶意文件」清掉。被利用的系统程序
    // (svchost、explorer……)和系统 / 安装目录里签名有效的程序不算:指向它们的持久化属于系统与正常软件。
    static bool isPersistenceRemovalTarget(const QString& path);

    static void setOwnCanaryFiles(const QStringList& paths);

    static QString forceProtectedReason(const QString& path);

    // 不看签名与落地区强制隔离(可还原),做不出金库副本时直接删除(不可还原);禁区判定与结束占用进程由调用方负责。
    std::pair<bool, QString> forceRemoveFile(const QString& path);

    std::pair<bool, QString> forceRemovePersistence(const QString& kind, const QString& location,
                                                    const QString& name, RemediationReport& report);

private:
    void removeAutostartPersistence(const QStringList& maliciousFiles, RemediationReport& report);
    void removeIfeoPersistence(const QStringList& maliciousFiles, RemediationReport& report);
    void removeServicePersistence(const QStringList& maliciousFiles, RemediationReport& report);
    void removeScheduledTaskPersistence(const QStringList& maliciousFiles, RemediationReport& report);

    void tryQuarantinePayload(const bulwark::PersistenceEntry& entry, RemediationReport& report);
    void removeRunValue(const bulwark::PersistenceEntry& entry, RemediationReport& report);
    void removeIfeoDebugger(const bulwark::PersistenceEntry& entry, RemediationReport& report);
    void resetWinlogonValue(const bulwark::PersistenceEntry& entry, RemediationReport& report);
    void clearAppInitDlls(const bulwark::PersistenceEntry& entry, RemediationReport& report);
    void quarantineStartupFile(const bulwark::PersistenceEntry& entry, RemediationReport& report);
    void deleteScheduledTask(const bulwark::PersistenceEntry& entry, RemediationReport& report);
    void disableService(const bulwark::PersistenceEntry& entry, RemediationReport& report);

    QuarantineManager& quarantine_;
    Logger log_;
};

}
