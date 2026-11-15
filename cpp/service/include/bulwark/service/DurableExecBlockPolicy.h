#pragma once

#include "bulwark/models/SecurityEvent.h"
#include "bulwark/service/monitoring/ProcessInspector.h"

#include <functional>
#include <optional>
#include <QStringList>

namespace bulwark::service {

enum class DurableExecBlockDecision {
    Allowed,
    NotRequested,
    WrongEventType,
    InvalidPid,
    PidAbsent,
    ObservedIdentityUnavailable,
    CurrentIdentityUnavailable,
    PidMismatch,
    CreationTimeMismatch,
    ImageUnavailable,
    ImageMismatch,
};

QString durableExecBlockDecisionName(DurableExecBlockDecision decision);

enum class DurableExecBlockOrigin {
    Enforcement,
    LaunchingParent,
    MaliciousSweep,
};

class DurableExecBlockAuthorization {
public:
    DurableExecBlockAuthorization(const DurableExecBlockAuthorization&) = default;
    DurableExecBlockAuthorization(DurableExecBlockAuthorization&&) noexcept = default;
    DurableExecBlockAuthorization& operator=(const DurableExecBlockAuthorization&) = default;
    DurableExecBlockAuthorization& operator=(DurableExecBlockAuthorization&&) noexcept = default;

    int pid() const { return pid_; }
    quint64 creationFileTime() const { return creationFileTime_; }
    const QString& imagePath() const { return imagePath_; }
    DurableExecBlockOrigin origin() const { return origin_; }

private:
    friend class DurableExecBlockPolicy;
    DurableExecBlockAuthorization(int pid, quint64 creationFileTime, QString imagePath,
                                  DurableExecBlockOrigin origin)
        : pid_(pid), creationFileTime_(creationFileTime), imagePath_(std::move(imagePath)),
          origin_(origin) {}

    int pid_ = 0;
    quint64 creationFileTime_ = 0;
    QString imagePath_;
    DurableExecBlockOrigin origin_ = DurableExecBlockOrigin::Enforcement;
};

struct DurableExecBlockEvaluation {
    DurableExecBlockDecision decision = DurableExecBlockDecision::NotRequested;
    std::optional<DurableExecBlockAuthorization> authorization;
};

enum class DurableExecBlockEffectOrder {
    PersistThenContain,
    ContainThenPersist,
};

struct DurableExecBlockExecution {
    DurableExecBlockEvaluation evaluation;
    bool persistenceAttempted = false;
    bool persistenceSucceeded = false;
    bool containmentAttempted = false;
    bool containmentSucceeded = false;
};

struct AuthoritativePolicyReplayPlan {
    QStringList keep;
    QStringList drop;
};

class DurableExecBlockPolicy {
public:
    using PersistFn = std::function<bool(const DurableExecBlockAuthorization&)>;
    using ContainFn = std::function<bool(int)>;

    static DurableExecBlockEvaluation evaluate(
        bool requested,
        const bulwark::SecurityEvent& event,
        const std::optional<monitoring::ProcessInspector::ProcessInstance>& current,
        DurableExecBlockOrigin origin = DurableExecBlockOrigin::Enforcement);

    static AuthoritativePolicyReplayPlan planAuthoritativeReplay(
        const QStringList& authoritativeEntries,
        const QStringList& trustedNeedles);

    static QString normalizeImagePath(const QString& path);

private:
    friend class WorkerDurableExecBlockSeam;
    static DurableExecBlockExecution execute(
        bool requested,
        const bulwark::SecurityEvent& event,
        const std::optional<monitoring::ProcessInspector::ProcessInstance>& current,
        DurableExecBlockOrigin origin,
        int containmentPid,
        DurableExecBlockEffectOrder order,
        const PersistFn& persist,
        const ContainFn& contain);
};

}
