#pragma once
#include "bulwark/service/EventSource.h"
#include "bulwark/service/Logger.h"

#include <QByteArray>
#include <QHash>
#include <QQueue>
#include <QSet>
#include <QString>

class QTimer;

namespace bulwark::service {

class FilelessGuard : public EventSource {
    Q_OBJECT
public:
    explicit FilelessGuard(QObject* parent = nullptr);
    ~FilelessGuard() override;

    void start() override;
    void stop() override;
    bool isAvailable() const override { return available_; }

    void addSelfPid(int pid) { selfPids_.insert(pid); }

    void onObservedEvent(const bulwark::SecurityEvent& e);

    int scanProcess(int pid);

private slots:
    void onSweepTick();
    void onTargetedTick();

private:
    struct Finding {
        QString  what;
        QString  detail;
        int      score = 0;
        bool     hard = false;
        QString  technique;
    };
    struct FnBaseline {
        QString    module;
        QString    fn;
        quintptr   rva = 0;
        QByteArray bytes;
        QString    technique;
        QString    label;
        QString    consequence;
    };

    void captureBaselines();
    QVector<Finding> scanUnbackedMemory(void* process, bool jitHost) const;
    QVector<Finding> scanHookPatches(void* process) const;
    QVector<Finding> scanThreadExecution(void* process, int pid) const;
    QHash<int, bulwark::SecurityEvent> contextRequests_;
    void emitFinding(int pid, const QString& imagePath, const Finding& f);
    int scanProcessImpl(int pid, bool urgent);
    static bool looksLikeKnownBypassStub(const QByteArray& bytes);

    static constexpr int kPrologueBytes   = 16;
    static constexpr int kSweepIntervalMs = 30 * 1000;
    static constexpr int kTargetedTickMs  = 1500;
    static constexpr int kProcPerSweep    = 24;
    static constexpr int kMaxRegions      = 8192;
    static constexpr quint64 kMinRwxBytes = 8 * 1024;
    static constexpr quint64 kMinRxBytes  = 64 * 1024;
    static constexpr int kTargetedQueueMax = 16;
    static constexpr int kCooldownMs      = 60 * 1000;
    static constexpr int kUrgentCooldownMs = 5 * 1000;

    QVector<FnBaseline> baselines_;
    QTimer* sweepTimer_ = nullptr;
    QTimer* targetedTimer_ = nullptr;
    QQueue<int> targeted_;
    QQueue<int> urgentTargeted_;
    QHash<int, qint64> lastScanMs_;
    QHash<int, qint64> lastUrgentScanMs_;
    QSet<QString> reported_;
    QSet<int> selfPids_;
    int  sweepCursor_ = 0;
    bool available_ = false;
    bool started_ = false;
    qint64 openFailures_ = 0;

    Logger log_{QStringLiteral("bulwark.service.Fileless")};
};

}
