#include "bulwark/engine/NetworkBehaviorMonitor.h"
#include "bulwark/Clock.h"
#include "bulwark/engine/NetworkEndpoint.h"
#include <QMutexLocker>
#include <cmath>

namespace bulwark::engine {

using detail::u;

namespace {

constexpr int kSamples = 12;
constexpr int kMinIntervals = 5;
constexpr qint64 kMinPeriodMs = 5 * 1000;
constexpr qint64 kMaxPeriodMs = 15 * 60 * 1000;
constexpr double kMaxJitter = 0.10;

constexpr qint64 kFanoutWindowMs = 60 * 1000;
constexpr int kFanoutThreshold = 60;
constexpr qint64 kFanoutCooldownMs = 10 * 60 * 1000;

constexpr int kMaxKeys = 4096;

QString remoteHostOf(const QString& endpoint) {
    const auto parsed = NetworkEndpoint::parse(endpoint);
    return parsed ? parsed->host() : endpoint;
}

}

NetworkBehaviorMonitor::Result NetworkBehaviorMonitor::observe(const SecurityEvent& e) {
    Result r;
    if (e.type != EventType::NetworkConnect || e.actorSigned || e.actorPath.isEmpty() || e.target.isEmpty())
        return r;
    const QDateTime when = e.timestampUtc.isValid() ? e.timestampUtc : nowUtc();
    const qint64 nowMs = when.toMSecsSinceEpoch();
    const QString actor = e.actorPath.toLower();

    QMutexLocker locker(&gate_);
    evict(nowMs);

    Series& s = series_[actor + QLatin1Char('|') + e.target];
    s.times.append(nowMs);
    if (s.times.size() > kSamples)
        s.times.remove(0, s.times.size() - kSamples);
    if (s.times.size() > kMinIntervals) {
        QVector<double> gaps;
        for (int i = 1; i < s.times.size(); ++i)
            gaps.append(static_cast<double>(s.times.at(i) - s.times.at(i - 1)));
        double mean = 0;
        for (const double g : gaps) mean += g;
        mean /= gaps.size();
        double var = 0;
        for (const double g : gaps) var += (g - mean) * (g - mean);
        const double cv = mean > 0 ? std::sqrt(var / gaps.size()) / mean : 1.0;
        if (mean >= kMinPeriodMs && mean <= kMaxPeriodMs && cv < kMaxJitter) {
            r.beacon.score = 40;
            r.beacon.reasons << u("未签名程序以约 %1 秒为周期规整连接 %2(疑似 C2 心跳,T1071)")
                                    .arg(qRound(mean / 1000.0)).arg(e.target);
        }
    }

    Fanout& f = fanout_[actor];
    f.lastSeenMs.insert(remoteHostOf(e.target), nowMs);
    for (auto it = f.lastSeenMs.begin(); it != f.lastSeenMs.end();) {
        if (nowMs - it.value() > kFanoutWindowMs) it = f.lastSeenMs.erase(it);
        else ++it;
    }
    if (f.lastSeenMs.size() >= kFanoutThreshold && nowMs - f.reportedMs > kFanoutCooldownMs) {
        f.reportedMs = nowMs;
        r.fanout.score = 30;
        r.fanout.reasons << u("未签名程序 1 分钟内连接 %1 个不同地址(扫描 / 蠕虫传播,T1046)")
                                .arg(f.lastSeenMs.size());
    }
    return r;
}

void NetworkBehaviorMonitor::evict(qint64 nowMs) {
    if (series_.size() > kMaxKeys) {
        for (auto it = series_.begin(); it != series_.end();) {
            if (it->times.isEmpty() || nowMs - it->times.last() > kMaxPeriodMs * 2) it = series_.erase(it);
            else ++it;
        }
        if (series_.size() > kMaxKeys)
            series_.clear();
    }
    if (fanout_.size() > kMaxKeys)
        fanout_.clear();
}

}
