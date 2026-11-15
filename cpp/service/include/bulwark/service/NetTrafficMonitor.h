#pragma once
#include "bulwark/ipc/Payloads.h"
#include "bulwark/service/Logger.h"

#include <QHash>
#include <QList>
#include <QObject>
#include <QSet>
#include <QString>
#include <QTimer>

#include <functional>
#include <memory>

namespace bulwark::service {

class NetTrafficMonitor : public QObject {
    Q_OBJECT
public:
    using ConnMap = QHash<int, QList<bulwark::ipc::NetTrafficConnPayload>>;

    explicit NetTrafficMonitor(QObject* parent = nullptr);
    ~NetTrafficMonitor() override;

    void setSelfComponentProbe(std::function<bool(int pid, const QString& imagePath)> fn) {
        selfProbe_ = std::move(fn);
    }

    bool start();
    void stop();
    bool isRunning() const { return timer_ && timer_->isActive(); }

signals:
    void snapshotReady(const bulwark::ipc::NetTrafficSnapshotPayload& snapshot, const ConnMap& connections);

private:
    struct Impl;

    struct ProcInfo {
        QString name;
        QString path;
        quint64 createTime = 0;
        bool critical = false;
        bool self = false;
        qint64 verifiedMs = 0;
        qint64 lastSeenMs = 0;
        quint64 upTotal = 0;
        quint64 downTotal = 0;
    };

    void sample();
    ProcInfo& procOf(quint32 pid, qint64 nowMs);

    std::unique_ptr<Impl> d_;
    QTimer* timer_ = nullptr;
    std::function<bool(int, const QString&)> selfProbe_;

    QHash<quint32, ProcInfo> procs_;
    QHash<quint64, QPair<quint64, quint64>> prevIf_;
    qint64 lastSampleMs_ = 0;
    quint64 sessionUp_ = 0;
    quint64 sessionDown_ = 0;
    int samples_ = 0;
    bool etwOk_ = false;
    QString etwError_;
    Logger log_{QStringLiteral("bulwark.service.NetTraffic")};
};

}
