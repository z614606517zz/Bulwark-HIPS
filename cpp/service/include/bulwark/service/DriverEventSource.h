#pragma once
#include <memory>
#include <QString>
#include <QStringList>
#include "bulwark/service/EventSource.h"
#include "bulwark/service/BulwarkOptions.h"

class QTimer;
class QByteArray;

namespace bulwark::service {

class DriverEventSource : public EventSource {
    Q_OBJECT
public:
    explicit DriverEventSource(const BulwarkOptions& options, QObject* parent = nullptr);
    ~DriverEventSource() override;

    void start() override;
    void stop() override;
    bool isAvailable() const override;

    bool wantsVerdict() const override { return false; }
    void submitVerdict(const bulwark::SecurityEvent& e, bulwark::VerdictAction action) override;

    void addProtectedPid(int pid);
    void addBlockedIp(const QString& ip, quint16 port = 0);
    void setMemoryProtectionEnabled(bool on) override;
    void applyRansomGuard(bool enabled, const QStringList& dirs, const QStringList& writers) override;
    void applyReadGuard(bool enabled, const QStringList& entries, const QStringList& readers) override;
    bool blockModuleLoad(const QString& modulePath) override;
    bool blockExecPath(const QString& imagePath) override;
    bool clearExecBlock() override;
    bool clearModuleNoLoad() override;
    bool clearBannedProcesses() override;
    QStringList persistedExecBlockList() const override;
    QStringList persistedModuleNoLoadList() const override;
    bool hardenRegistryKey(const QString& keyOrValue) override;

    bool readLockedFile(const QString& path, QByteArray& out);
    bool forceDeleteFile(const QString& path);
    bool killProcess(int pid);
    bool banProcess(int pid) override;

    bool isConnected() const;
    bool protocolMismatch() const;

    QStringList missingCapabilities() const;

    struct WfpStats {
        bool    available     = false;
        bool    registered    = false;
        quint32 layerCount    = 0;
        quint64 classifyCalls = 0;
        quint64 rightsCleared = 0;
        quint64 bannedBlocks  = 0;
        quint64 ipBlocks      = 0;
        quint32 bringUpAttempts = 0;
        quint32 lastStage       = 0;
        qint32  lastStatus      = 0;
        bool    bfeSubscribed   = false;
        qint32  lastLayer       = -1;
    };

    // 阶段号 -> 可读名,必须与 Protocol.h 的 BLW_WFP_STAGE_* 保持一一对应。
    static QString wfpStageName(quint32 stage);
    WfpStats queryWfpStats() const;

    // 把 queryWfpStats 的结果折成一句日志结论;判读阈值只在这里实现,调用方不要各写一套。
    // 返回空串 = 没有可报告的问题。
    static QString describeWfpHealth(const WfpStats& s);

private:
    void drain();
    // final=false 时只在本周期出现丢失时告警;final=true 时无论有无丢失都输出累计值。
    void reportDeliveryStats(bool final);

    struct Impl;
    std::unique_ptr<Impl> d_;
    QTimer* drainTimer_ = nullptr;
    QTimer* statsTimer_ = nullptr;
};

}
