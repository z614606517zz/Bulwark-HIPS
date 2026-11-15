#pragma once
#include "bulwark/service/Logger.h"
#include "bulwark/service/monitoring/ProcessInspector.h"

#include <QHash>
#include <QList>
#include <QMutex>
#include <QObject>
#include <QString>
#include <QStringList>
#include <QVector>

#include <functional>

class QTimer;

namespace bulwark::service {

class UserModeProcessContainment : public QObject {
    Q_OBJECT
public:
    explicit UserModeProcessContainment(int maxEntries = 64, int frozenTtlMs = 120000,
                                        QObject* parent = nullptr);
    ~UserModeProcessContainment() override;

    using KernelKillFn = std::function<bool(int pid)>;
    void setKernelKill(KernelKillFn fn);

    // 不可撤销,只能用在即将结束该进程的路径上;onlyWhenTerminating 必须为 true,否则拒绝并记录。
    bool cutOffChildren(int pid, bool onlyWhenTerminating, const QString& why);
    bool isChildrenCutOff(int pid) const;

    bool freeze(int pid, const QString& imagePath, const QString& why, bool autoThaw = true);
    // 加白、用户放行或判定误报时必须调用。
    bool thaw(int pid, const QString& why);
    int thawByPathNeedle(const QString& needle, const QString& why);
    int thawAll(const QString& why);
    bool isFrozen(int pid) const;
    QList<int> frozenPids() const;
    qint64 frozenForMs(int pid) const;

    struct LadderStep {
        QString name;
        bool attempted = false;
        bool ok = false;
        QString detail;
    };
    struct LadderResult {
        bool imageLocked = false;
        bool frozen = false;
        bool childrenCutOff = false;
        bool userModeKilled = false;
        bool kernelKilled = false;
        bool confirmedGone = false;
        int  killedInTree = 0;
        QVector<LadderStep> steps;
        // 一行摘要;必须区分「已结束」与「已收容但仍在运行」,后者不能说成已拦截。
        QString summary() const;
    };
    LadderResult disposeOf(int pid, const QString& imagePath, const QString& imagePathNeedle,
                           const QString& why);

    QStringList describeState() const;

private:
    struct Entry {
        void*   job = nullptr;
        void*   imageLock = nullptr;
        bool    frozen = false;
        bool    autoThaw = true;
        qint64  frozenAtMs = 0;
        QString imagePath;
    };

    bool refuseTarget(int pid, const QString& imagePath, QString* why) const;
    bool lockImageEphemeral(int pid, const QString& imagePath);
    void releaseImageLockLocked(Entry& entry);
    void onTtlTick();

    mutable QMutex mx_;
    QHash<int, Entry> entries_;
    KernelKillFn kernelKill_;
    QTimer* ttl_ = nullptr;
    const int maxEntries_;
    const int frozenTtlMs_;
    Logger log_{QStringLiteral("bulwark.service.Containment")};
};

}
