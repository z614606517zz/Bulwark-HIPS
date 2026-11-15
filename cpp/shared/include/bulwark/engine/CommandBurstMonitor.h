#pragma once
#include <QHash>
#include <QMutex>
#include <QString>
#include "bulwark/engine/EngineCommon.h"
#include "bulwark/models/SecurityEvent.h"

namespace bulwark::engine {

// 单条侦察命令、单次停服务都是日常运维;同一个父进程在一分钟内成批地做,才像攻击链里的
// 侦察阶段或勒索加密前的清场。按父进程聚合进程创建事件的命令行。
class CommandBurstMonitor {
public:
    struct Result {
        ScoreResult discovery;
        ScoreResult serviceStop;
    };

    Result observe(const SecurityEvent& e);

private:
    struct Burst {
        QHash<QString, qint64> discovery;
        QHash<QString, qint64> stops;
        qint64 discoveryReportedMs = 0;
        qint64 stopReportedMs = 0;
        qint64 stopHardReportedMs = 0;
        qint64 lastMs = 0;
    };

    void evict(qint64 nowMs);

    QHash<QString, Burst> byParent_;
    QMutex gate_;
};

}
