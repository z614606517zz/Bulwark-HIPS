#pragma once
#include "bulwark/service/Logger.h"
#include "bulwark/models/SecurityEvent.h"

#include <QHash>
#include <QObject>
#include <QString>

#include <functional>

class QTimer;

namespace bulwark::service {

class ResourceAbuseMonitor : public QObject {
    Q_OBJECT
public:
    explicit ResourceAbuseMonitor(QObject* parent = nullptr);
    ~ResourceAbuseMonitor() override;

    using AuditSink = std::function<void(const QString& kind, const QString& detail)>;
    void setAuditSink(AuditSink fn) { audit_ = std::move(fn); }

    using ContainHandler = std::function<bool(int pid, const QString& why)>;
    void setContainHandler(ContainHandler fn) { contain_ = std::move(fn); }

    using SelfDegradedHandler = std::function<void(const QStringList& reasons)>;
    void setSelfDegradedHandler(SelfDegradedHandler fn) { selfDegraded_ = std::move(fn); }

    void start();
    void stop();

    void onObservedEvent(const bulwark::SecurityEvent& e);

private slots:
    void onSelfCheckTick();
    void onDecayTick();

private:
    struct Counter {
        qint64 windowStartMs = 0;
        int    count = 0;
        qint64 lastAlertMs = 0;
    };

    void bump(QHash<QString, Counter>& table, const QString& key, int threshold,
              const QString& kind, const QString& what, int pid, const QString& actorPath);

    static constexpr qint64 kWindowMs = 10 * 1000;
    static constexpr qint64 kAlertCooldownMs = 60 * 1000;
    static constexpr int kChildSpawnThreshold = 80;
    static constexpr int kSameImageThreshold  = 120;
    static constexpr int kRemoteThreadThreshold = 200;
    static constexpr int kContainMultiplier = 3;
    static constexpr int kSelfCheckMs = 30 * 1000;
    static constexpr int kMaxKeys = 2048;

    QHash<QString, Counter> childSpawn_;
    QHash<QString, Counter> sameImage_;
    QHash<QString, Counter> remoteThread_;

    QTimer* selfCheckTimer_ = nullptr;
    QTimer* decayTimer_ = nullptr;
    AuditSink audit_;
    ContainHandler contain_;
    SelfDegradedHandler selfDegraded_;
    bool started_ = false;
    bool selfDegradedReported_ = false;

    Logger log_{QStringLiteral("bulwark.service.ResourceGuard")};
};

}
