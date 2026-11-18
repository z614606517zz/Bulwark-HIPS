#pragma once
#include "bulwark/models/SecurityEvent.h"
#include <QHash>
#include <QMutex>
#include <optional>

namespace bulwark::service {
inline constexpr quint32 remoteMutationAccess = 0xd0046U; // write, append, delete-child, delete, write-DAC, write-owner
class NativeAuditPolicy {
public:
    // Accepts only explicitly supported provider/event pairs; never renders message text.
    static std::optional<bulwark::SecurityEvent> parse(const QString& xml);
};
class RemoteShareTracker {
public:
    bool record(const bulwark::SecurityEvent& access);
    void annotate(bulwark::SecurityEvent& io);
private:
    struct Access { bulwark::SecurityEvent event; };
    struct Burst { QHash<QString,qint64> files; qint64 alerted = -1; qint64 last = 0; };
    QHash<QString,QVector<Access>> paths_;
    QHash<QString,Burst> bursts_;
    QMutex mutex_;
    void prune(qint64 now);
};
}
