#include "bulwark/service/DurableExecBlockPolicy.h"

#include <QDir>

namespace bulwark::service {

QString durableExecBlockDecisionName(DurableExecBlockDecision decision)
{
    switch (decision) {
    case DurableExecBlockDecision::Allowed:                    return QStringLiteral("Allowed");
    case DurableExecBlockDecision::NotRequested:               return QStringLiteral("NotRequested");
    case DurableExecBlockDecision::WrongEventType:             return QStringLiteral("WrongEventType");
    case DurableExecBlockDecision::InvalidPid:                 return QStringLiteral("InvalidPid");
    case DurableExecBlockDecision::PidAbsent:                  return QStringLiteral("PidAbsent");
    case DurableExecBlockDecision::ObservedIdentityUnavailable:return QStringLiteral("ObservedIdentityUnavailable");
    case DurableExecBlockDecision::CurrentIdentityUnavailable: return QStringLiteral("CurrentIdentityUnavailable");
    case DurableExecBlockDecision::PidMismatch:                return QStringLiteral("PidMismatch");
    case DurableExecBlockDecision::CreationTimeMismatch:       return QStringLiteral("CreationTimeMismatch");
    case DurableExecBlockDecision::ImageUnavailable:           return QStringLiteral("ImageUnavailable");
    case DurableExecBlockDecision::ImageMismatch:              return QStringLiteral("ImageMismatch");
    }
    return QStringLiteral("Unknown");
}

QString DurableExecBlockPolicy::normalizeImagePath(const QString& path)
{
    QString normalized = QDir::fromNativeSeparators(path.trimmed());
    normalized = QDir::cleanPath(normalized);
    normalized.replace(QLatin1Char('/'), QLatin1Char('\\'));
    while (normalized.size() > 3 && normalized.endsWith(QLatin1Char('\\')))
        normalized.chop(1);
    return normalized;
}

DurableExecBlockEvaluation DurableExecBlockPolicy::evaluate(
    bool requested,
    const bulwark::SecurityEvent& event,
    const std::optional<monitoring::ProcessInspector::ProcessInstance>& current,
    DurableExecBlockOrigin origin)
{
    DurableExecBlockEvaluation result;
    if (!requested) {
        result.decision = DurableExecBlockDecision::NotRequested;
        return result;
    }
    if (event.type != bulwark::EventType::ProcessCreate) {
        result.decision = DurableExecBlockDecision::WrongEventType;
        return result;
    }
    if (event.actorPid <= 4) {
        result.decision = DurableExecBlockDecision::InvalidPid;
        return result;
    }
    if (!event.actorCreationFileTime.has_value() || *event.actorCreationFileTime == 0) {
        result.decision = DurableExecBlockDecision::ObservedIdentityUnavailable;
        return result;
    }
    if (!current.has_value()) {
        result.decision = DurableExecBlockDecision::PidAbsent;
        return result;
    }
    if (!current->isUsable()) {
        result.decision = DurableExecBlockDecision::CurrentIdentityUnavailable;
        return result;
    }
    if (current->pid != event.actorPid) {
        result.decision = DurableExecBlockDecision::PidMismatch;
        return result;
    }
    if (current->creationFileTime != *event.actorCreationFileTime) {
        result.decision = DurableExecBlockDecision::CreationTimeMismatch;
        return result;
    }

    const QString observedPath = normalizeImagePath(event.actorPath);
    const QString currentPath = normalizeImagePath(current->imagePath);
    if (observedPath.isEmpty() || currentPath.isEmpty()) {
        result.decision = DurableExecBlockDecision::ImageUnavailable;
        return result;
    }
    if (observedPath.compare(currentPath, Qt::CaseInsensitive) != 0) {
        result.decision = DurableExecBlockDecision::ImageMismatch;
        return result;
    }

    result.decision = DurableExecBlockDecision::Allowed;
    result.authorization = DurableExecBlockAuthorization(
        event.actorPid, *event.actorCreationFileTime, currentPath, origin);
    return result;
}

DurableExecBlockExecution DurableExecBlockPolicy::execute(
    bool requested,
    const bulwark::SecurityEvent& event,
    const std::optional<monitoring::ProcessInspector::ProcessInstance>& current,
    DurableExecBlockOrigin origin,
    int containmentPid,
    DurableExecBlockEffectOrder order,
    const PersistFn& persist,
    const ContainFn& contain)
{
    DurableExecBlockExecution result;
    result.evaluation = evaluate(requested, event, current, origin);

    const auto persistIfAuthorized = [&] {
        if (!result.evaluation.authorization.has_value())
            return;
        result.persistenceAttempted = true;
        result.persistenceSucceeded = persist(*result.evaluation.authorization);
    };
    const auto containNow = [&] {
        result.containmentAttempted = true;
        result.containmentSucceeded = contain(containmentPid);
    };

    if (order == DurableExecBlockEffectOrder::ContainThenPersist) {
        containNow();
        persistIfAuthorized();
    } else {
        persistIfAuthorized();
        containNow();
    }
    return result;
}

AuthoritativePolicyReplayPlan DurableExecBlockPolicy::planAuthoritativeReplay(
    const QStringList& authoritativeEntries,
    const QStringList& trustedNeedles)
{
    AuthoritativePolicyReplayPlan plan;
    for (const QString& entry : authoritativeEntries) {
        bool wouldBlockTrusted = false;
        if (!entry.isEmpty()) {
            for (const QString& trusted : trustedNeedles) {
                if (trusted.contains(entry, Qt::CaseInsensitive)) {
                    wouldBlockTrusted = true;
                    break;
                }
            }
        }
        (wouldBlockTrusted ? plan.drop : plan.keep) << entry;
    }
    return plan;
}

}
