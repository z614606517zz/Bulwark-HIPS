#pragma once
#include "bulwark/service/BulwarkOptions.h"
#include "bulwark/service/Logger.h"
#include "bulwark/models/DefenseRule.h"

#include <QString>
#include <QVector>

#include <atomic>
#include <condition_variable>
#include <functional>
#include <mutex>
#include <thread>

namespace bulwark::service::reputation {

struct ThreatFoxIoc {
    QString ioc;
    QString iocType;
    QString malware;
    QString threatType;
    int confidence = 0;
};

class ThreatFoxFeedClient {
public:
    explicit ThreatFoxFeedClient(const ThreatFoxFeedOptions& opt);
    bool isEnabled() const;
    QVector<ThreatFoxIoc> fetchRecent();

private:
    QVector<ThreatFoxIoc> parse(const QString& json) const;
    ThreatFoxFeedOptions opt_;
    QString authKey_;
};

QVector<bulwark::DefenseRule> generateIntelRules(const QVector<ThreatFoxIoc>& iocs,
                                                 const ThreatFoxFeedOptions& opt);

class IntelFeedService {
public:
    using RulesReadyCallback = std::function<void(const QVector<bulwark::DefenseRule>&)>;

    explicit IntelFeedService(const ThreatFoxFeedOptions& opt);
    ~IntelFeedService();
    IntelFeedService(const IntelFeedService&) = delete;
    IntelFeedService& operator=(const IntelFeedService&) = delete;

    bool isEnabled() const;
    void setRulesReady(RulesReadyCallback cb) { onRulesReady_ = std::move(cb); }
    void start();
    void stop();

private:
    void loop();
    bool sleepInterruptible(int seconds);

    ThreatFoxFeedClient client_;
    ThreatFoxFeedOptions opt_;
    RulesReadyCallback onRulesReady_;
    std::atomic<bool> running_{false};
    std::thread worker_;
    std::mutex mx_;
    std::condition_variable cv_;
    Logger log_{QStringLiteral("ThreatFox")};
};

}
