#pragma once
#include <QHash>
#include <QMutex>
#include <QObject>
#include <QString>
#include <atomic>
#include <functional>
#include <thread>
#include <vector>

#include "bulwark/models/SecurityEvent.h"
#include "bulwark/service/Logger.h"

namespace bulwark::service {

class AmsiBridge : public QObject {
    Q_OBJECT
public:
    explicit AmsiBridge(QObject* parent = nullptr);
    ~AmsiBridge() override;

    bool start();
    void stop();
    bool isRunning() const { return running_.load(); }

    void setEnabled(bool on) { enabled_.store(on); }

    void setTrustProbe(std::function<bool(const QString& hostImagePath)> probe) {
        trustProbe_ = std::move(probe);
    }

    void setReporter(std::function<void(const bulwark::SecurityEvent&, bool blocked)> r) {
        reporter_ = std::move(r);
    }

    quint64 scanCount()    const { return scans_.load(); }
    quint64 blockCount()   const { return blocks_.load(); }
    quint64 rejectCount()  const { return rejects_.load(); }

private:
    void serveLoop(void* firstPipe);
    void* createInstance(bool firstInstance);
    void serveOne(void* pipe);

    bool isOwnDescendant(unsigned long pid);
    bool beginClientRequest(unsigned long pid);
    void endClientRequest(unsigned long pid);

    static constexpr int kWorkers = 4;
    struct ClientBudget {
        qint64 windowStartMs = 0;
        int requests = 0;
        int active = 0;
    };

    std::vector<std::thread> workers_;
    std::atomic<bool>     running_{false};
    std::atomic<bool>     enabled_{true};
    std::atomic<quint64>  scans_{0}, blocks_{0}, rejects_{0}, overBudget_{0};
    QMutex                 clientBudgetMutex_;
    QHash<quint32, ClientBudget> clientBudgets_;
    void*                 stopEvent_ = nullptr;
    void*                 firstPipe_ = nullptr;

    std::function<bool(const QString&)> trustProbe_;
    std::function<void(const bulwark::SecurityEvent&, bool)> reporter_;

    Logger log_{QStringLiteral("bulwark.service.Amsi")};
};

}
