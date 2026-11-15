#pragma once
#include <QHash>
#include <QSet>
#include <QVector>
#include <QUuid>
#include <QString>
#include <QDateTime>
#include <QReadWriteLock>
#include <QMutex>
#include <optional>
#include "bulwark/models/SecurityEvent.h"
#include "bulwark/models/Verdict.h"
#include "bulwark/models/DefenseRule.h"
#include "bulwark/engine/EngineCommon.h"
#include "bulwark/engine/BaselineAnalyzer.h"
#include "bulwark/engine/CommandBurstMonitor.h"
#include "bulwark/engine/DownloaderBehaviorMonitor.h"
#include "bulwark/engine/NetworkBehaviorMonitor.h"
#include "bulwark/engine/RansomwareBehaviorMonitor.h"

namespace bulwark::engine {

inline int specificity(const DefenseRule& r) { return r.specificityScore(); }

class RuleEngine {
public:
    RuleEngine() = default;

    bool enableBaseline = true;
    bool trustSignedActors = true;

    void addSelfDirectory(const QString& dir);
    bool matchesSelf(const QString& path) const;
    bool isSelfComponent(const SecurityEvent& e) const;

    bool isSanctionedMaintenanceActor(const SecurityEvent& e) const;

    bool isSanctionedMaintenanceDescendant(const SecurityEvent& e) const;

    static int ruleTier(const DefenseRule& r);
    static int rulePriority(VerdictAction a);

    static bool isUnsafeAllowRule(const DefenseRule& r, QString* whyOut = nullptr);

    void loadRules(const QVector<DefenseRule>& rules);
    QVector<DefenseRule> getRules() const;
    int pruneExpired();
    void addRule(const DefenseRule& rule);
    bool removeRule(const QUuid& id);

    Verdict evaluate(SecurityEvent& e);

    DefenseRule createRuleFrom(SecurityEvent& e, VerdictAction action,
                               std::optional<QDateTime> expiresUtc = std::nullopt,
                               bool sessionOnly = false);

    void addCanaryFile(const QString& path);
    bool isCanaryTarget(const SecurityEvent& e) const;
    void setFileStateProbe(RansomwareBehaviorMonitor::FileStateProbe probe) {
        ransomware_.setFileStateProbe(std::move(probe));
    }
    void setContentProbe(RansomwareBehaviorMonitor::ContentProbe probe) {
        ransomware_.setContentProbe(std::move(probe));
    }

    BaselineSnapshot exportBaseline() { return baseline_.exportSnapshot(); }
    void importBaseline(const BaselineSnapshot& snapshot) { baseline_.importSnapshot(snapshot); }

    std::optional<QString> trustNoteForPath(const QString& path) const;

    std::optional<QString> trustNoteForEvent(const SecurityEvent& e) const;

private:
    Verdict evaluateInternal(SecurityEvent& e);
    void appendDecisionEvidence(SecurityEvent& e, const Verdict& v);

    bool isSanctionedScriptInvocation(const QString& actorPath, const QString& commandLine,
                                      bool includeInstallScript) const;

    bool isUserTrustedScriptHost(const QString& actorPath, const QString& commandLine) const;

    std::optional<QString> matchedUserTrust(const SecurityEvent& e) const;

    std::optional<QString> userTrustNoteForPath(const QString& path) const;

    static bool targetIsTrustEligible(EventType t);

    // 绝大多数规则锚定主体映像名(*\powershell.exe):按映像名再分一层,只把可能命中的规则拿来匹配。
    struct RuleBucket {
        QVector<DefenseRule> anyActor;
        QHash<QString, QVector<DefenseRule>> byActorImage;
    };

    void rebuildIndexLocked();
    void indexInsertLocked(const DefenseRule& r);
    static void collectMatches(const RuleBucket& bucket, const QString& actorImageKey, const SecurityEvent& e,
                               QVector<DefenseRule>& out);

    QHash<QUuid, DefenseRule> rules_;
    QHash<int, RuleBucket> byType_;
    RuleBucket typeAgnostic_;
    QVector<DefenseRule> trustEntries_;
    mutable QReadWriteLock rulesLock_;
    QSet<QString> selfDirectories_;
    mutable QMutex selfDirLock_;
    QSet<QString> canaryPaths_;
    mutable QMutex canaryLock_;

    RansomwareBehaviorMonitor ransomware_;
    DownloaderBehaviorMonitor downloader_;
    CommandBurstMonitor bursts_;
    NetworkBehaviorMonitor network_;
    BaselineAnalyzer baseline_;
};

}
