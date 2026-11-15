#pragma once
#include <QDateTime>
#include <QHash>
#include <QMutex>
#include <QSet>
#include <QString>
#include <QVector>
#include "bulwark/engine/EngineCommon.h"
#include "bulwark/models/SecurityEvent.h"

namespace bulwark::engine {

// 周期外联(C2 心跳)与外联扇出(扫描 / 蠕虫)。只看未签名主体,只给软信号:
// 签名软件的心跳、同步、P2P 本来就规整或扇出很大。周期一旦成形,之后每一拍都报,
// 是否询问由引擎结合主体位置决定。
class NetworkBehaviorMonitor {
public:
    struct Result {
        ScoreResult beacon;
        ScoreResult fanout;
    };

    Result observe(const SecurityEvent& e);

private:
    struct Series {
        QVector<qint64> times;
    };
    struct Fanout {
        QHash<QString, qint64> lastSeenMs;
        qint64 reportedMs = 0;
    };

    void evict(qint64 nowMs);

    QHash<QString, Series> series_;
    QHash<QString, Fanout> fanout_;
    QMutex gate_;
};

}
