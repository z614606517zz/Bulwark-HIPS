#pragma once

#include <QHash>
#include <QString>
#include <QtGlobal>

#include <chrono>
#include <condition_variable>
#include <functional>
#include <memory>
#include <mutex>
#include <thread>
#include <utility>

namespace bulwark::service::monitoring {

class RevocationGate {
public:
    enum class Verdict { Unknown, Good, Revoked };

    struct Outcome {
        Verdict verdict = Verdict::Unknown;
        bool    unreachable = true;
    };

    struct Config {
        qint64 revokedTtlMs      = 7LL * 24 * 3600 * 1000;
        qint64 goodTtlMs         = 6LL * 3600 * 1000;
        qint64 unknownTtlMs      = 5LL * 60 * 1000;
        int    breakerThreshold  = 3;
        qint64 breakerCooldownMs = 10LL * 60 * 1000;
        int    cacheCapacity     = 4096;
    };

    enum class Notice { BreakerOpened, BreakerReopened, BreakerClosed };

    using Clock      = std::function<qint64()>;
    using Check      = std::function<Outcome()>;
    using LateHook   = std::function<void(const QString&)>;
    using NoticeHook = std::function<void(Notice)>;

    explicit RevocationGate(Config cfg = Config(), Clock clock = Clock())
        : d_(std::make_shared<Impl>())
    {
        d_->cfg = cfg;
        d_->clock = clock ? std::move(clock) : Clock(&RevocationGate::steadyMs);
    }

    Verdict query(const QString& key, Check check, int budgetMs)
    {
        if (key.isEmpty() || !check)
            return Verdict::Unknown;
        const std::shared_ptr<Impl> d = d_;
        std::unique_lock<std::mutex> lk(d->mx);
        const qint64 now = d->clock();

        auto hit = d->cache.find(key);
        if (hit != d->cache.end()) {
            if (hit->expiresAt > now)
                return hit->verdict;
            d->cache.erase(hit);
        }
        if (d->openUntil != 0 && now < d->openUntil)
            return Verdict::Unknown;
        if (d->busy)
            return Verdict::Unknown;
        d->busy = true;
        const quint64 ticket = ++d->seq;
        d->tickets.insert(ticket, Ticket());
        try {
            std::thread([d, key, check = std::move(check), ticket] { runLane(d, key, check, ticket); }).detach();
        } catch (...) {
            d->busy = false;
            d->tickets.remove(ticket);
            return Verdict::Unknown;
        }
        if (budgetMs <= 0) {
            d->tickets[ticket].waiterGone = true;
            return Verdict::Unknown;
        }
        d->cv.wait_for(lk, std::chrono::milliseconds(budgetMs), [&] {
            const auto t = d->tickets.constFind(ticket);
            return t == d->tickets.constEnd() || t->done;
        });
        auto t = d->tickets.find(ticket);
        if (t == d->tickets.end())
            return Verdict::Unknown;
        if (t->done) {
            const Verdict v = t->verdict;
            d->tickets.erase(t);
            return v;
        }
        t->waiterGone = true;
        t->timedOut = true;
        const int tr = registerFailureLocked(*d, d->clock());
        const NoticeHook hook = d->notice;
        lk.unlock();
        if (tr != 0 && hook) {
            try { hook(tr == 1 ? Notice::BreakerOpened : Notice::BreakerReopened); } catch (...) {}
        }
        return Verdict::Unknown;
    }

    bool isKnownRevoked(const QString& key) const
    {
        if (key.isEmpty())
            return false;
        std::lock_guard<std::mutex> lk(d_->mx);
        const auto it = d_->cache.constFind(key);
        return it != d_->cache.constEnd() && it->verdict == Verdict::Revoked && it->expiresAt > d_->clock();
    }

    Verdict peek(const QString& key) const
    {
        std::lock_guard<std::mutex> lk(d_->mx);
        const auto it = d_->cache.constFind(key);
        if (it == d_->cache.constEnd() || it->expiresAt <= d_->clock())
            return Verdict::Unknown;
        return it->verdict;
    }

    bool breakerOpen() const
    {
        std::lock_guard<std::mutex> lk(d_->mx);
        return d_->openUntil != 0 && d_->clock() < d_->openUntil;
    }
    int consecutiveFailures() const
    {
        std::lock_guard<std::mutex> lk(d_->mx);
        return d_->failures;
    }
    bool laneBusy() const
    {
        std::lock_guard<std::mutex> lk(d_->mx);
        return d_->busy;
    }
    bool waitIdle(int timeoutMs) const
    {
        std::unique_lock<std::mutex> lk(d_->mx);
        return d_->cv.wait_for(lk, std::chrono::milliseconds(timeoutMs),
                               [this] { return !d_->busy && d_->hooksPending == 0; });
    }
    void setLateHook(LateHook hook)
    {
        std::lock_guard<std::mutex> lk(d_->mx);
        d_->late = std::move(hook);
    }
    void setNoticeHook(NoticeHook hook)
    {
        std::lock_guard<std::mutex> lk(d_->mx);
        d_->notice = std::move(hook);
    }

private:
    struct Entry {
        Verdict verdict = Verdict::Unknown;
        qint64  expiresAt = 0;
    };
    struct Ticket {
        bool    done = false;
        bool    waiterGone = false;
        bool    timedOut = false;
        Verdict verdict = Verdict::Unknown;
    };
    struct Impl {
        mutable std::mutex mx;
        std::condition_variable cv;
        Clock  clock;
        Config cfg;
        QHash<QString, Entry> cache;
        QHash<quint64, Ticket> tickets;   // 不能叫 slots(Qt 宏)
        quint64 seq = 0;
        bool    busy = false;
        int     hooksPending = 0;
        int     failures = 0;
        qint64  openUntil = 0;
        LateHook late;
        NoticeHook notice;
    };

    static qint64 steadyMs()
    {
        return std::chrono::duration_cast<std::chrono::milliseconds>(
                   std::chrono::steady_clock::now().time_since_epoch()).count();
    }

    static int registerFailureLocked(Impl& d, qint64 now)
    {
        ++d.failures;
        if (d.failures < d.cfg.breakerThreshold)
            return 0;
        const bool wasClosed = (d.openUntil == 0);
        d.openUntil = now + d.cfg.breakerCooldownMs;
        return wasClosed ? 1 : 2;
    }

    static void storeLocked(Impl& d, const QString& key, Verdict v, qint64 now)
    {
        if (d.cache.size() >= d.cfg.cacheCapacity) {
            for (auto it = d.cache.begin(); it != d.cache.end();) {
                if (it->expiresAt <= now) it = d.cache.erase(it); else ++it;
            }
            if (d.cache.size() >= d.cfg.cacheCapacity) {
                for (auto it = d.cache.begin(); it != d.cache.end();) {
                    if (it->verdict != Verdict::Revoked) it = d.cache.erase(it); else ++it;
                }
                if (d.cache.size() >= d.cfg.cacheCapacity)
                    d.cache.clear();
            }
        }
        const qint64 ttl = (v == Verdict::Revoked) ? d.cfg.revokedTtlMs
                         : (v == Verdict::Good)    ? d.cfg.goodTtlMs
                                                   : d.cfg.unknownTtlMs;
        d.cache.insert(key, Entry{v, now + ttl});
    }

    static void runLane(std::shared_ptr<Impl> d, QString key, Check check, quint64 ticket)
    {
        Outcome out;
        try {
            out = check();
        } catch (...) {
            out = Outcome();
        }
        LateHook late;
        NoticeHook noticeHook;
        bool fireLate = false;
        int tr = 0;
        {
            std::lock_guard<std::mutex> lk(d->mx);
            const qint64 now = d->clock();
            storeLocked(*d, key, out.verdict, now);
            auto t = d->tickets.find(ticket);
            const bool have = (t != d->tickets.end());
            const bool timedOut = have && t->timedOut;
            noticeHook = d->notice;
            if (out.unreachable) {
                if (!timedOut)
                    tr = registerFailureLocked(*d, now);
            } else if (!timedOut) {
                if (d->openUntil != 0)
                    tr = 3;
                d->failures = 0;
                d->openUntil = 0;
            }
            if (have) {
                if (t->waiterGone) {
                    d->tickets.erase(t);
                    if (out.verdict == Verdict::Revoked) {
                        late = d->late;
                        fireLate = true;
                    }
                } else {
                    t->done = true;
                    t->verdict = out.verdict;
                }
            }
            d->busy = false;
            if (tr != 0 && noticeHook) ++d->hooksPending;
            if (fireLate && late) ++d->hooksPending;
        }
        d->cv.notify_all();
        if (tr != 0 && noticeHook) {
            try {
                noticeHook(tr == 1 ? Notice::BreakerOpened
                         : tr == 2 ? Notice::BreakerReopened
                                   : Notice::BreakerClosed);
            } catch (...) {}
            finishHook(*d);
        }
        if (fireLate && late) {
            try { late(key); } catch (...) {}
            finishHook(*d);
        }
    }

    static void finishHook(Impl& d)
    {
        {
            std::lock_guard<std::mutex> lk(d.mx);
            --d.hooksPending;
        }
        d.cv.notify_all();
    }

    std::shared_ptr<Impl> d_;
};

}
