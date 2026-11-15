#include "bulwark/engine/BaselineAnalyzer.h"
#include "bulwark/engine/EngineCommon.h"
#include "bulwark/Clock.h"
#include <QMutexLocker>

namespace bulwark::engine {

using detail::u;
using detail::fileNameLower;

namespace {

constexpr int kDimChild = 0;
constexpr int kDimHost = 1;
constexpr int kDimWriteDir = 2;

constexpr int kMinObservations = 12;
// 浏览器、包管理器、同步盘在某一维上本来就是「什么都做」,这一维不再报偏离。
constexpr int kPromiscuous = 60;
constexpr int kMaxSetSize = 256;
constexpr int kMaxProfiles = 8192;

QString writeDirOf(const QString& path) {
    QString p = path.toLower();
    p.replace(QLatin1Char('/'), QLatin1Char('\\'));
    const qsizetype slash = p.lastIndexOf(QLatin1Char('\\'));
    return slash > 0 ? p.left(slash) : QString();
}

QString hostOf(const QString& endpoint) {
    const qsizetype colon = endpoint.lastIndexOf(QLatin1Char(':'));
    return colon > 0 ? endpoint.left(colon) : endpoint;
}

}

BaselineAnalyzer::Result BaselineAnalyzer::observe(const SecurityEvent& e) {
    Result r;
    const QDateTime now = e.timestampUtc.isValid() ? e.timestampUtc : nowUtc();
    switch (e.type) {
    case EventType::ProcessCreate:
        if (!e.parentPath.isEmpty() && !e.actorPath.isEmpty())
            return observeDimension(e.parentPath.toLower(), kDimChild, fileNameLower(e.actorPath), now);
        break;
    case EventType::NetworkConnect:
        if (!e.actorPath.isEmpty() && !e.target.isEmpty())
            return observeDimension(e.actorPath.toLower(), kDimHost, hostOf(e.target), now);
        break;
    case EventType::FileWrite: {
        const QString dir = writeDirOf(e.target);
        if (!e.actorPath.isEmpty() && !dir.isEmpty())
            return observeDimension(e.actorPath.toLower(), kDimWriteDir, dir, now);
        break;
    }
    default:
        break;
    }
    return r;
}

BaselineAnalyzer::Result BaselineAnalyzer::observeDimension(const QString& program, int dim,
                                                            const QString& value, const QDateTime& now) {
    Result r;
    if (value.isEmpty())
        return r;
    QMutexLocker locker(&gate_);
    evictIfNeeded();
    Profile& p = profiles_[program];
    if (!p.firstSeenUtc.isValid())
        p.firstSeenUtc = now;
    p.lastSeenUtc = now;

    QSet<QString>& seen = p.values[dim];
    const bool known = seen.contains(value);
    const bool established = p.obs[dim] >= kMinObservations && seen.size() < kPromiscuous;
    ++p.obs[dim];
    if (!known && seen.size() < kMaxSetSize)
        seen.insert(value);
    if (known || !established)
        return r;

    r.deviation = true;
    switch (dim) {
    case kDimChild:
        r.score = 15;
        r.reasons << u("偏离自身历史基线:首次派生 ") + value;
        break;
    case kDimHost:
        r.score = 10;
        r.reasons << u("偏离自身历史基线:首次连接 ") + value;
        break;
    default:
        r.score = 10;
        r.reasons << u("偏离自身历史基线:首次写入目录 ") + value;
        break;
    }
    return r;
}

void BaselineAnalyzer::evictIfNeeded() {
    if (profiles_.size() < kMaxProfiles)
        return;
    QDateTime oldest;
    QString victim;
    for (auto it = profiles_.cbegin(); it != profiles_.cend(); ++it) {
        if (victim.isEmpty() || it->lastSeenUtc < oldest) {
            oldest = it->lastSeenUtc;
            victim = it.key();
        }
    }
    profiles_.remove(victim);
}

BaselineSnapshot BaselineAnalyzer::exportSnapshot() {
    QMutexLocker locker(&gate_);
    BaselineSnapshot snap;
    snap.programs.reserve(profiles_.size());
    for (auto it = profiles_.cbegin(); it != profiles_.cend(); ++it) {
        BaselineProgram bp;
        bp.key = it.key();
        bp.firstSeenUtc = it->firstSeenUtc;
        bp.lastSeenUtc = it->lastSeenUtc;
        bp.childObs = it->obs[kDimChild];
        bp.hostObs = it->obs[kDimHost];
        bp.writeObs = it->obs[kDimWriteDir];
        bp.children = QStringList(it->values[kDimChild].cbegin(), it->values[kDimChild].cend());
        bp.hosts = QStringList(it->values[kDimHost].cbegin(), it->values[kDimHost].cend());
        bp.writeDirs = QStringList(it->values[kDimWriteDir].cbegin(), it->values[kDimWriteDir].cend());
        snap.programs.append(bp);
    }
    return snap;
}

void BaselineAnalyzer::importSnapshot(const BaselineSnapshot& snapshot) {
    QMutexLocker locker(&gate_);
    profiles_.clear();
    for (const BaselineProgram& bp : snapshot.programs) {
        if (bp.key.isEmpty())
            continue;
        Profile p;
        p.firstSeenUtc = bp.firstSeenUtc;
        p.lastSeenUtc = bp.lastSeenUtc;
        p.obs[kDimChild] = bp.childObs;
        p.obs[kDimHost] = bp.hostObs;
        p.obs[kDimWriteDir] = bp.writeObs;
        p.values[kDimChild] = QSet<QString>(bp.children.cbegin(), bp.children.cend());
        p.values[kDimHost] = QSet<QString>(bp.hosts.cbegin(), bp.hosts.cend());
        p.values[kDimWriteDir] = QSet<QString>(bp.writeDirs.cbegin(), bp.writeDirs.cend());
        profiles_.insert(bp.key, p);
        if (profiles_.size() >= kMaxProfiles)
            break;
    }
}

}
