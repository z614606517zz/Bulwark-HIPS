#pragma once
#include <QString>
#include <QStringList>
#include <QList>
#include <QDateTime>
#include <QUuid>
#include <QJsonObject>
#include "bulwark/models/Enums.h"

namespace bulwark {

enum class AttackNodeKind {
    Process = 0,
    File,
    Registry,
    Network,
    Domain,
    Module,
    Service,
    ScheduledTask,
};

QString attackNodeKindToString(AttackNodeKind k);
AttackNodeKind attackNodeKindFromString(const QString& s);

struct AttackGraphNode {
    QString id;
    AttackNodeKind kind = AttackNodeKind::Process;
    QString label;
    QString detail;
    int pid = 0;
    int parentPid = 0;
    QString path;
    QString commandLine;
    bool signedActor = false;
    QString publisher;
    int riskScore = 0;
    bool blocked = false;
    bool isSeed = false;
    bool isRoot = false;
    int depth = 0;
    ProcessOriginKind originKind = ProcessOriginKind::Unknown;
    QString originLabel;
    int eventCount = 0;
    QDateTime firstSeenUtc;
    QDateTime lastSeenUtc;

    QJsonObject toJson() const;
    static AttackGraphNode fromJson(const QJsonObject& o);
};

struct AttackGraphEdge {
    QUuid eventId;
    QString fromId;
    QString toId;
    EventType type = EventType::ProcessCreate;
    QString label;
    QString detail;
    QDateTime timestampUtc;
    int riskScore = 0;
    VerdictAction action = VerdictAction::Allow;
    EnforcementOutcome enforcement = EnforcementOutcome::NotApplicable;
    bool hasThreatIndicator = false;
    QStringList techniques;
    bool inferred = false;

    QJsonObject toJson() const;
    static AttackGraphEdge fromJson(const QJsonObject& o);
};

struct AttackGraph {
    QUuid seedEventId;
    int rootPid = 0;
    QString rootLabel;
    QList<AttackGraphNode> nodes;
    QList<AttackGraphEdge> edges;
    QStringList techniques;
    QDateTime firstUtc;
    QDateTime lastUtc;
    int maxRiskScore = 0;
    int eventCount = 0;
    bool truncated = false;
    QString summary;

    bool isEmpty() const { return nodes.isEmpty(); }

    QJsonObject toJson() const;
    static AttackGraph fromJson(const QJsonObject& o);
};

}
