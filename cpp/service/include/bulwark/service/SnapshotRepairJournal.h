#pragma once

#include "bulwark/service/RepairDriverSession.h"

#include <QJsonObject>
#include <QStringList>

#include <optional>

namespace bulwark::service {

enum class SnapshotRepairPhase {
    Prepared,
    DeleteCapabilityProved,
    ExecBlockDeleteIntent,
    ExecBlockRemovedVerified,
    RestoreIntent,
    Restored,
    Committed,
    Aborted,
};

QString snapshotRepairPhaseName(SnapshotRepairPhase phase);
std::optional<SnapshotRepairPhase> snapshotRepairPhaseFromName(const QString& name);

struct SnapshotRepairJournalData {
    int schemaVersion = 1;
    QString nonce;
    QString target;
    QString sentinel;
    QStringList canonicalPreimage;
    QString nonTargetDigest;
    QJsonObject componentIdentities;
    QString appsettingsSha256;
    QJsonObject timestamps;
    QVector<RepairCommandResult> commandResults;
    SnapshotRepairPhase phase = SnapshotRepairPhase::Prepared;
    bool consumed = false;
};

class SnapshotRepairJournal {
public:
    SnapshotRepairJournal() = default;
    explicit SnapshotRepairJournal(QString path) : path_(std::move(path)) {}

    static QString productionDirectory();
    static QString normalizeEntry(const QString& value);
    static QStringList canonicalize(const QStringList& values);
    static QString digest(const QStringList& canonicalValues);
    static QString nonTargetDigest(const QStringList& canonicalValues);

    static std::optional<SnapshotRepairJournal> create(
        const QString& directory, const QStringList& preimage,
        const QJsonObject& componentIdentities, const QString& appsettingsSha256,
        QString* error = nullptr);
    static std::optional<SnapshotRepairJournal> load(const QString& path,
                                                     QString* error = nullptr);

    bool save(QString* error = nullptr) const;
    const QString& path() const { return path_; }
    SnapshotRepairJournalData& data() { return data_; }
    const SnapshotRepairJournalData& data() const { return data_; }

private:
    QString path_;
    SnapshotRepairJournalData data_;
};

class SnapshotRepairPolicyReader {
public:
    virtual ~SnapshotRepairPolicyReader() = default;
    virtual bool read(QStringList* entries, QString* error) = 0;
};

class SnapshotRepairCoordinator {
public:
    static bool execute(RepairDriverSession& session, SnapshotRepairPolicyReader& reader,
                        SnapshotRepairJournal& journal, int deadlineMs,
                        QString* error = nullptr);
    static bool recover(RepairDriverSession& session, SnapshotRepairPolicyReader& reader,
                        SnapshotRepairJournal& journal, int deadlineMs,
                        QString* error = nullptr);
};

int runSnapshotRepairProduction();
int restoreLatestSnapshotRepairProduction();
bool recoverPendingSnapshotRepairsProduction(QString* error = nullptr);

}
