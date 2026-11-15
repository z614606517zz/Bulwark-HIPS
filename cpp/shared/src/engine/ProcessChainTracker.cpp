#include "bulwark/engine/ProcessChainTracker.h"

#include <QFileInfo>
#include <algorithm>

namespace bulwark::engine {

ProcessChainTracker::ProcessChainTracker(int maxEventsPerPid, int maxPids, int retentionSeconds)
    : maxEventsPerPid_(std::max(4, maxEventsPerPid)),
      maxPids_(std::max(64, maxPids)),
      retentionSecs_(std::max(1, retentionSeconds)) {
    executableWriteExt_ = {
        QStringLiteral(".exe"), QStringLiteral(".dll"), QStringLiteral(".sys"),
        QStringLiteral(".scr"), QStringLiteral(".com"), QStringLiteral(".ocx"),
        QStringLiteral(".cpl"), QStringLiteral(".drv"), QStringLiteral(".ps1"),
        QStringLiteral(".vbs"), QStringLiteral(".js"),  QStringLiteral(".jse"),
        QStringLiteral(".wsf"), QStringLiteral(".hta"), QStringLiteral(".bat"),
        QStringLiteral(".cmd"), QStringLiteral(".jar")
    };
}

QString ProcessChainTracker::normalizePath(const QString& path) {
    QString p = path.trimmed();
    p.replace(QLatin1Char('/'), QLatin1Char('\\'));
    while (p.endsWith(QLatin1Char('\\')))
        p.chop(1);
    return p.toLower();
}

void ProcessChainTracker::record(const bulwark::SecurityEvent& e) {
    if (e.actorPid <= 0)
        return;
    const bulwark::ChainEventInfo info = bulwark::ChainEventInfo::from(e);

    QMutexLocker lock(&gate_);

    if (e.type == bulwark::EventType::ProcessCreate) {
        bool reused = false;
        const auto knownCreation = creationByPid_.constFind(e.actorPid);
        if (knownCreation != creationByPid_.constEnd() && e.actorCreationFileTime.has_value()
            && knownCreation.value() != *e.actorCreationFileTime) {
            reused = true;
        } else {
            const QString knownPath = lastKnownPathLocked(e.actorPid);
            if (!isPlaceholderPath(e.actorPath) && !knownPath.isEmpty()
                && knownPath.compare(e.actorPath.trimmed(), Qt::CaseInsensitive) != 0) {
                reused = true;
            }
        }
        if (reused)
            removePid(e.actorPid, true);
        if (e.actorCreationFileTime.has_value())
            creationByPid_[e.actorPid] = *e.actorCreationFileTime;
    }

    if (e.parentPid > 0)
        parent_[e.actorPid] = e.parentPid;

    auto it = byPid_.find(e.actorPid);
    if (it == byPid_.end()) {
        it = byPid_.insert(e.actorPid, QVector<bulwark::ChainEventInfo>());
        firstSeen_[e.actorPid] = nowUtc();
    }
    it.value().append(info);
    const qsizetype over = it.value().size() - static_cast<qsizetype>(maxEventsPerPid_);
    if (over > 0)
        it.value().remove(0, over);

    if (e.type == bulwark::EventType::FileWrite && !e.target.isEmpty()) {
        const QString ext = QStringLiteral(".") + QFileInfo(e.target).suffix().toLower();
        if (ext.size() > 1 && executableWriteExt_.contains(ext)) {
            ExeWrite w;
            w.when = nowUtc();
            w.writerPid = e.actorPid;
            w.writerPath = isPlaceholderPath(e.actorPath) ? lastKnownPathLocked(e.actorPid)
                                                          : e.actorPath.trimmed();
            w.originalPath = e.target.trimmed();
            recentExeWrites_[normalizePath(e.target)] = w;
        }
    }

    evictIfNeeded();
}

bool ProcessChainTracker::wasRecentlyWritten(const QString& path, int withinSeconds) const {
    if (path.isEmpty())
        return false;
    const QString key = normalizePath(path);
    QMutexLocker lock(&gate_);
    const auto it = recentExeWrites_.constFind(key);
    if (it == recentExeWrites_.constEnd())
        return false;
    return it.value().when.secsTo(nowUtc()) <= withinSeconds;
}

bool ProcessChainTracker::isPlaceholderPath(const QString& p) {
    const QString t = p.trimmed();
    return t.isEmpty() || t.startsWith(QLatin1String("PID "), Qt::CaseInsensitive);
}

QString ProcessChainTracker::lastKnownPathLocked(int pid) const {
    const auto it = byPid_.constFind(pid);
    if (it == byPid_.constEnd())
        return {};
    const QVector<bulwark::ChainEventInfo>& events = it.value();
    for (auto rit = events.crbegin(); rit != events.crend(); ++rit)
        if (!isPlaceholderPath(rit->actorPath))
            return rit->actorPath.trimmed();
    return {};
}

ProcessChainTracker::Writer ProcessChainTracker::lastWriterOf(const QString& path,
                                                              int withinSeconds) const {
    Writer w;
    if (path.trimmed().isEmpty())
        return w;
    const QString key = normalizePath(path);
    QMutexLocker lock(&gate_);
    const auto it = recentExeWrites_.constFind(key);
    if (it == recentExeWrites_.constEnd())
        return w;
    if (it.value().when.secsTo(nowUtc()) > withinSeconds)
        return w;
    w.pid = it.value().writerPid;
    w.path = it.value().writerPath;
    return w;
}

QVector<QString> ProcessChainTracker::filesWrittenBy(int rootPid, const QString& rootImagePath,
                                                     bool includeDescendants) const {
    QVector<QString> out;
    if (rootPid <= 0)
        return out;

    QMutexLocker lock(&gate_);

    const QString expected = rootImagePath.trimmed();
    if (!isPlaceholderPath(expected)) {
        const QString known = lastKnownPathLocked(rootPid);
        if (!known.isEmpty() && known.compare(expected, Qt::CaseInsensitive) != 0)
            return out;
    }

    QSet<int> pids;
    pids.insert(rootPid);
    if (includeDescendants) {
        bool grew = true;
        int guard = 0;
        while (grew && guard++ < 64) {
            grew = false;
            for (auto kv = parent_.constBegin(); kv != parent_.constEnd(); ++kv) {
                if (pids.contains(kv.value()) && !pids.contains(kv.key())) {
                    pids.insert(kv.key());
                    grew = true;
                }
            }
        }
    }

    QSet<QString> seen;
    auto add = [&](const QString& p) {
        const QString t = p.trimmed();
        if (t.isEmpty())
            return;
        const QString k = normalizePath(t);
        if (seen.contains(k))
            return;
        seen.insert(k);
        out.append(t);
    };

    for (int pid : pids) {
        const auto lit = byPid_.constFind(pid);
        if (lit == byPid_.constEnd())
            continue;
        for (const bulwark::ChainEventInfo& c : lit.value()) {
            if (c.type != bulwark::EventType::FileWrite)
                continue;
            if (pid == rootPid && !isPlaceholderPath(expected) && !isPlaceholderPath(c.actorPath)
                && c.actorPath.trimmed().compare(expected, Qt::CaseInsensitive) != 0)
                continue;
            add(c.target);
        }
    }

    for (auto kv = recentExeWrites_.constBegin(); kv != recentExeWrites_.constEnd(); ++kv) {
        const ExeWrite& w = kv.value();
        if (!pids.contains(w.writerPid))
            continue;
        if (!w.writerPath.isEmpty()) {
            const QString known = w.writerPid == rootPid && !isPlaceholderPath(expected)
                                      ? expected
                                      : lastKnownPathLocked(w.writerPid);
            if (!known.isEmpty() && known.compare(w.writerPath, Qt::CaseInsensitive) != 0)
                continue;
        }
        add(w.originalPath.isEmpty() ? kv.key() : w.originalPath);
    }
    return out;
}

QVector<bulwark::ChainEventInfo> ProcessChainTracker::buildContext(const bulwark::SecurityEvent& e,
                                                                   int maxEvents) const {
    maxEvents = std::max(1, maxEvents);

    QMutexLocker lock(&gate_);

    QSet<int> pids;
    if (e.actorPid > 0) pids.insert(e.actorPid);
    if (e.parentPid > 0) pids.insert(e.parentPid);

    int cur = e.actorPid > 0 ? e.actorPid : e.parentPid;
    int depth = 0;
    QSet<int> visited;
    while (cur > 0 && depth < 16 && !visited.contains(cur)) {
        visited.insert(cur);
        const auto pit = parent_.constFind(cur);
        if (pit != parent_.constEnd() && pit.value() > 0) {
            pids.insert(pit.value());
            cur = pit.value();
        } else {
            break;
        }
        ++depth;
    }

    if (e.actorPid > 0) {
        for (auto kv = parent_.constBegin(); kv != parent_.constEnd(); ++kv)
            if (kv.value() == e.actorPid)
                pids.insert(kv.key());
    }

    QVector<bulwark::ChainEventInfo> merged;
    for (int pid : pids) {
        const auto lit = byPid_.constFind(pid);
        if (lit != byPid_.constEnd())
            merged += lit.value();
    }

    if (!e.chainContext.isEmpty())
        merged += e.chainContext;

    merged.append(bulwark::ChainEventInfo::from(e));

    QVector<bulwark::ChainEventInfo> unique;
    unique.reserve(merged.size());
    QSet<QString> seen;
    for (const bulwark::ChainEventInfo& c : merged) {
        const QString key = QString::number(c.actorPid) + QLatin1Char('|')
                          + QString::number(static_cast<int>(c.type)) + QLatin1Char('|')
                          + c.target + QLatin1Char('|')
                          + QString::number(c.timestampUtc.toMSecsSinceEpoch());
        if (!seen.contains(key)) {
            seen.insert(key);
            unique.append(c);
        }
    }
    std::stable_sort(unique.begin(), unique.end(),
                     [](const bulwark::ChainEventInfo& a, const bulwark::ChainEventInfo& b) {
                         return a.timestampUtc < b.timestampUtc;
                     });
    if (unique.size() > static_cast<qsizetype>(maxEvents))
        unique = unique.mid(unique.size() - maxEvents);
    return unique;
}

QVector<bulwark::ChainEventInfo> ProcessChainTracker::collectTreeEvents(int rootPid) const {
    QVector<bulwark::ChainEventInfo> result;
    if (rootPid <= 0)
        return result;

    QMutexLocker lock(&gate_);

    QSet<int> pids;
    pids.insert(rootPid);
    bool grew = true;
    int guard = 0;
    while (grew && guard++ < 64) {
        grew = false;
        for (auto kv = parent_.constBegin(); kv != parent_.constEnd(); ++kv) {
            if (pids.contains(kv.value()) && !pids.contains(kv.key())) {
                pids.insert(kv.key());
                grew = true;
            }
        }
    }

    for (int pid : pids) {
        const auto lit = byPid_.constFind(pid);
        if (lit != byPid_.constEnd())
            result += lit.value();
    }

    std::stable_sort(result.begin(), result.end(),
                     [](const bulwark::ChainEventInfo& a, const bulwark::ChainEventInfo& b) {
                         return a.timestampUtc < b.timestampUtc;
                     });
    return result;
}

QString ProcessChainTracker::lastKnownPath(int pid) const {
    if (pid <= 0)
        return {};
    QMutexLocker lock(&gate_);
    const auto it = byPid_.constFind(pid);
    if (it == byPid_.constEnd())
        return {};
    const QVector<bulwark::ChainEventInfo>& events = it.value();
    for (auto rit = events.crbegin(); rit != events.crend(); ++rit) {
        const QString& p = rit->actorPath;
        if (!p.isEmpty() && !p.startsWith(QLatin1String("PID "), Qt::CaseInsensitive))
            return p;
    }
    return {};
}

void ProcessChainTracker::forget(int pid) {
    QMutexLocker lock(&gate_);
    removePid(pid, true);
}

int ProcessChainTracker::trackedProcessCount() const {
    QMutexLocker lock(&gate_);
    return static_cast<int>(byPid_.size());
}

void ProcessChainTracker::removePid(int pid, bool purgeRelations) {
    byPid_.remove(pid);
    firstSeen_.remove(pid);
    creationByPid_.remove(pid);

    if (!purgeRelations) {
        parent_.remove(pid);
        return;
    }

    for (auto it = parent_.begin(); it != parent_.end(); ) {
        if (it.key() == pid || it.value() == pid) it = parent_.erase(it);
        else ++it;
    }
    for (auto it = recentExeWrites_.begin(); it != recentExeWrites_.end(); ) {
        if (it.value().writerPid == pid) it = recentExeWrites_.erase(it);
        else ++it;
    }
}

void ProcessChainTracker::evictIfNeeded() {
    const QDateTime now = nowUtc();

    {
        QVector<int> expired;
        for (auto kv = firstSeen_.constBegin(); kv != firstSeen_.constEnd(); ++kv)
            if (kv.value().secsTo(now) > retentionSecs_)
                expired.append(kv.key());
        for (int pid : expired)
            removePid(pid);
    }

    if (byPid_.size() > static_cast<qsizetype>(maxPids_)) {
        QVector<QPair<QDateTime, int>> ages;
        ages.reserve(firstSeen_.size());
        for (auto kv = firstSeen_.constBegin(); kv != firstSeen_.constEnd(); ++kv)
            ages.append(qMakePair(kv.value(), kv.key()));
        std::stable_sort(ages.begin(), ages.end(),
                         [](const QPair<QDateTime, int>& a, const QPair<QDateTime, int>& b) {
                             return a.first < b.first;
                         });
        const qsizetype drop = byPid_.size() - static_cast<qsizetype>(maxPids_);
        for (qsizetype i = 0; i < drop && i < ages.size(); ++i)
            removePid(ages[i].second);
    }

    if (!recentExeWrites_.isEmpty()) {
        QVector<QString> stale;
        for (auto kv = recentExeWrites_.constBegin(); kv != recentExeWrites_.constEnd(); ++kv)
            if (kv.value().when.secsTo(now) > retentionSecs_)
                stale.append(kv.key());
        for (const QString& k : stale)
            recentExeWrites_.remove(k);

        if (recentExeWrites_.size() > static_cast<qsizetype>(maxPids_)) {
            QVector<QPair<QDateTime, QString>> ages;
            ages.reserve(recentExeWrites_.size());
            for (auto kv = recentExeWrites_.constBegin(); kv != recentExeWrites_.constEnd(); ++kv)
                ages.append(qMakePair(kv.value().when, kv.key()));
            std::stable_sort(ages.begin(), ages.end(),
                             [](const QPair<QDateTime, QString>& a, const QPair<QDateTime, QString>& b) {
                                 return a.first < b.first;
                             });
            const qsizetype drop = recentExeWrites_.size() - static_cast<qsizetype>(maxPids_);
            for (qsizetype i = 0; i < drop && i < ages.size(); ++i)
                recentExeWrites_.remove(ages[i].second);
        }
    }
}

}
