#pragma once
#include "bulwark/models/SecurityEvent.h"
#include <QHash>
#include <QMutex>

namespace bulwark::engine {
class CrossEventMonitor {
public:
    struct Result { int score = 0; bool containment = false; QString reason; };
    Result observe(const SecurityEvent& event);
    Result damage(const SecurityEvent& event, const QStringList& confirmedPaths);
private:
    struct State {
        qint64 last = 0;
        QHash<QString, qint64> damaged;
        QHash<QString, qint64> secrets;
        qint64 archived = -1;
    };
    QHash<QString, State> states_;
    QMutex mutex_;
    static QStringList groups(const SecurityEvent& e, bool restart);
    void prune(qint64 now);
};
}
