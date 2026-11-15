#pragma once

#include <QHash>
#include <QString>
#include <QVector>

#include <algorithm>

namespace bulwark::service {

enum class RemoteThreadSource {
    Base,
    Driver,
};

class RemoteThreadDeduplicator final {
public:
    [[nodiscard]] bool shouldSuppress(const QString& key,
                                      RemoteThreadSource source,
                                      qint64 nowMs)
    {
        if (key.isEmpty())
            return false;

        prune(nowMs);
        auto found = pending_.find(key);
        if (found != pending_.end()) {
            QVector<Pending>& entries = found.value();
            for (qsizetype i = 0; i < entries.size(); ++i) {
                if (entries.at(i).source != source) {
                    entries.removeAt(i);
                    if (entries.isEmpty())
                        pending_.erase(found);
                    return true;
                }
            }
        }

        if (!pending_.contains(key) && pending_.size() >= kMaxKeys)
            pending_.erase(pending_.begin());
        QVector<Pending>& entries = pending_[key];
        if (entries.size() >= kMaxPerKey)
            entries.removeFirst();
        entries.push_back(Pending{source, nowMs});
        return false;
    }

private:
    struct Pending {
        RemoteThreadSource source;
        qint64 atMs;
    };

    void prune(qint64 nowMs)
    {
        for (auto it = pending_.begin(); it != pending_.end();) {
            QVector<Pending>& entries = it.value();
            entries.erase(std::remove_if(entries.begin(), entries.end(), [nowMs](const Pending& p) {
                              return nowMs < p.atMs || nowMs - p.atMs > kWindowMs;
                          }),
                          entries.end());
            if (entries.isEmpty())
                it = pending_.erase(it);
            else
                ++it;
        }
    }

    static constexpr qint64 kWindowMs = 3000;
    static constexpr qsizetype kMaxKeys = 1024;
    static constexpr qsizetype kMaxPerKey = 32;
    QHash<QString, QVector<Pending>> pending_;
};

}
