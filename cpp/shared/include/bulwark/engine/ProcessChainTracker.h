#pragma once
#include <QHash>
#include <QVector>
#include <QSet>
#include <QString>
#include <QDateTime>
#include <QMutex>

#include "bulwark/models/ChainEventInfo.h"
#include "bulwark/models/SecurityEvent.h"

namespace bulwark::engine {

class ProcessChainTracker {
public:
    explicit ProcessChainTracker(int maxEventsPerPid = 64, int maxPids = 4096,
                                 int retentionSeconds = 30 * 60);

    void record(const bulwark::SecurityEvent& e);

    bool wasRecentlyWritten(const QString& path, int withinSeconds) const;

    struct Writer {
        int pid = 0;
        QString path;
        bool isValid() const { return pid > 0; }
    };

    Writer lastWriterOf(const QString& path, int withinSeconds) const;

    QVector<QString> filesWrittenBy(int rootPid, const QString& rootImagePath = QString(),
                                    bool includeDescendants = true) const;

    QVector<bulwark::ChainEventInfo> buildContext(const bulwark::SecurityEvent& e, int maxEvents = 12) const;

    QVector<bulwark::ChainEventInfo> collectTreeEvents(int rootPid) const;

    QString lastKnownPath(int pid) const;

    void forget(int pid);

    int trackedProcessCount() const;

private:
    void evictIfNeeded();      // 需在持锁状态调用:过期 + 容量淘汰
    void removePid(int pid, bool purgeRelations = false);
    QString lastKnownPathLocked(int pid) const;
    static bool isPlaceholderPath(const QString& p);
    static QString normalizePath(const QString& path);

    mutable QMutex gate_;
    QHash<int, QVector<bulwark::ChainEventInfo>> byPid_;
    QHash<int, int> parent_;
    QHash<int, QDateTime> firstSeen_;
    QHash<int, quint64> creationByPid_;
    struct ExeWrite {
        QDateTime when;
        int writerPid = 0;
        QString writerPath;
        QString originalPath;
    };
    QHash<QString, ExeWrite> recentExeWrites_;
    QSet<QString> executableWriteExt_;
    int maxEventsPerPid_;
    int maxPids_;
    qint64 retentionSecs_;
};

}
