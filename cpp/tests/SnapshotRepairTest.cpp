#include "bulwark/service/RepairDriverSession.h"
#include "bulwark/service/SnapshotRepairJournal.h"

#include <QCoreApplication>
#include <QCryptographicHash>
#include <QFile>
#include <QJsonDocument>
#include <QTemporaryDir>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include "Protocol.h"

#include <cstdio>
#include <cstring>
#include <memory>

namespace {

using namespace bulwark::service;

int gChecks = 0;
int gFailed = 0;

void check(bool condition, const char* name) {
    ++gChecks;
    if (condition) return;
    ++gFailed;
    std::fprintf(stderr, "FAIL: %s\n", name);
}

struct FakeState {
    QStringList persisted;
    QStringList inMemory;
    int delayedDeleteReads = 0;
    bool mutateNonTargetAfterDelete = false;
};

class FakeReader final : public SnapshotRepairPolicyReader {
public:
    explicit FakeReader(FakeState& state) : state_(state) {}
    bool read(QStringList* entries, QString*) override {
        if (state_.delayedDeleteReads > 0) {
            --state_.delayedDeleteReads;
        } else {
            state_.persisted = state_.inMemory;
        }
        *entries = state_.persisted;
        return true;
    }
private:
    FakeState& state_;
};

class FakeTransport final : public RepairDriverTransport {
public:
    explicit FakeTransport(FakeState& state) : state_(state) {}
    bool connect(QString*) override { connected = true; return true; }
    bool send(quint32 command, const QString& path, QByteArray* output,
              QString* error) override {
        commands.append(qMakePair(command, path));
        if (command == BLW_CMD_HANDSHAKE) {
            if (!output || output->size() < static_cast<int>(sizeof(BLW_HANDSHAKE_REPLY))) {
                if (error) *error = QStringLiteral("missing handshake output");
                return false;
            }
            BLW_HANDSHAKE_REPLY reply{};
            reply.ProtocolVersion = BLW_PROTOCOL_VERSION;
            reply.EventMessageSize = sizeof(BLW_EVENT_MESSAGE);
            reply.ConfigMessageSize = sizeof(BLW_CONFIG_MESSAGE);
            reply.VerdictReplySize = sizeof(BLW_VERDICT_REPLY);
            std::memcpy(output->data(), &reply, sizeof(reply));
            output->resize(sizeof(reply));
            return true;
        }
        if (command == BLW_CMD_DEL_EXECBLOCK
            && path == RepairDriverSession::sentinelNeedle()) return true;
        if (command == BLW_CMD_DEL_EXECBLOCK
            && path == RepairDriverSession::targetNeedle()) {
            state_.inMemory.removeOne(path);
            if (state_.mutateNonTargetAfterDelete && !state_.inMemory.isEmpty())
                state_.inMemory[0] += QStringLiteral("-FOREIGN");
            state_.delayedDeleteReads = 3;
            return true;
        }
        if (command == BLW_CMD_ADD_EXECBLOCK
            && path == RepairDriverSession::targetNeedle()) {
            if (!state_.inMemory.contains(path)) state_.inMemory.append(path);
            state_.delayedDeleteReads = 0;
            state_.persisted = state_.inMemory;
            return true;
        }
        if (error) *error = QStringLiteral("unexpected command");
        return false;
    }

    bool connected = false;
    QVector<QPair<quint32, QString>> commands;
private:
    FakeState& state_;
};

struct Fixture {
    QTemporaryDir dir;
    FakeState state;
    FakeReader reader;
    FakeTransport* transport = nullptr;
    std::unique_ptr<RepairDriverSession> session;
    std::optional<SnapshotRepairJournal> journal;

    Fixture() : reader(state) {
        state.persisted = { QStringLiteral("\\OTHER\\BLOCKED.EXE"),
                            RepairDriverSession::targetNeedle() };
        state.inMemory = state.persisted;
        auto fake = std::make_unique<FakeTransport>(state);
        transport = fake.get();
        session = std::make_unique<RepairDriverSession>(std::move(fake));
        journal = SnapshotRepairJournal::create(dir.path(), state.persisted,
                                                 QJsonObject{}, QStringLiteral("ABC"));
    }
};

void testSuccessfulDelayedDelete() {
    Fixture fixture;
    check(fixture.journal.has_value(), "journal created for exact preimage");
    QString error;
    const bool ok = SnapshotRepairCoordinator::execute(
        *fixture.session, fixture.reader, *fixture.journal, 4000, &error);
    check(ok, "exact repair commits after delayed persistence");
    check(fixture.journal->data().phase == SnapshotRepairPhase::Committed
              && fixture.journal->data().consumed,
          "committed journal is consumed");
    check(!fixture.state.persisted.contains(RepairDriverSession::targetNeedle()),
          "committed postimage removes only fixed target");
    check(fixture.state.persisted.contains(QStringLiteral("\\OTHER\\BLOCKED.EXE")),
          "committed postimage retains non-target entry");
    check(fixture.transport->commands.size() == 3
              && fixture.transport->commands[0].first == BLW_CMD_HANDSHAKE
              && fixture.transport->commands[1].first == BLW_CMD_DEL_EXECBLOCK
              && fixture.transport->commands[1].second == RepairDriverSession::sentinelNeedle()
              && fixture.transport->commands[2].first == BLW_CMD_DEL_EXECBLOCK
              && fixture.transport->commands[2].second == RepairDriverSession::targetNeedle(),
          "normal transaction uses handshake and two fixed exact deletes only");
}

void testInitialStateRejections() {
    QTemporaryDir dir;
    QString error;
    check(!SnapshotRepairJournal::create(
               dir.path(), { RepairDriverSession::targetNeedle(),
                             RepairDriverSession::targetNeedle() }, {}, {}, &error),
          "duplicate target is rejected");
    check(!SnapshotRepairJournal::create(
               dir.path(), { QStringLiteral("\\OTHER.EXE") }, {}, {}, &error),
          "absent target is rejected");
    check(!SnapshotRepairJournal::create(
               dir.path(), { RepairDriverSession::targetNeedle(),
                             RepairDriverSession::sentinelNeedle() }, {}, {}, &error),
          "present sentinel is rejected before target mutation");
}

void testUncertainDeleteRecoveryAlwaysAdds() {
    Fixture fixture;
    fixture.journal->data().phase = SnapshotRepairPhase::ExecBlockDeleteIntent;
    fixture.journal->data().consumed = false;
    fixture.journal->save();
    fixture.state.persisted = fixture.journal->data().canonicalPreimage;
    fixture.state.inMemory = { QStringLiteral("\\OTHER\\BLOCKED.EXE") };
    QString error;
    const bool ok = SnapshotRepairCoordinator::recover(
        *fixture.session, fixture.reader, *fixture.journal, 2000, &error);
    check(ok, "uncertain delete intent recovers from stale pre-debounce registry state");
    check(fixture.transport->commands.size() == 2
              && fixture.transport->commands[0].first == BLW_CMD_HANDSHAKE
              && fixture.transport->commands[1].first == BLW_CMD_ADD_EXECBLOCK
              && fixture.transport->commands[1].second == RepairDriverSession::targetNeedle(),
          "uncertain recovery unconditionally sends exact fixed-target ADD");
    check(fixture.journal->data().phase == SnapshotRepairPhase::Restored
              && fixture.journal->data().consumed,
          "recovery marks RESTORED only after exact preimage readback");
}

void testEveryJournalPhase() {
    for (SnapshotRepairPhase phase : { SnapshotRepairPhase::Prepared,
            SnapshotRepairPhase::DeleteCapabilityProved, SnapshotRepairPhase::Aborted,
            SnapshotRepairPhase::ExecBlockDeleteIntent,
            SnapshotRepairPhase::ExecBlockRemovedVerified,
            SnapshotRepairPhase::RestoreIntent, SnapshotRepairPhase::Restored }) {
        Fixture fixture;
        fixture.journal->data().phase = phase;
        fixture.journal->data().consumed = false;
        fixture.journal->save();
        if (phase == SnapshotRepairPhase::ExecBlockRemovedVerified
            || phase == SnapshotRepairPhase::RestoreIntent) {
            fixture.state.persisted = { QStringLiteral("\\OTHER\\BLOCKED.EXE") };
            fixture.state.inMemory = fixture.state.persisted;
        }
        QString error;
        check(SnapshotRepairCoordinator::recover(
                  *fixture.session, fixture.reader, *fixture.journal, 2000, &error),
              "every unconsumed non-committed phase reaches a verified closed state");
    }

    Fixture committed;
    committed.journal->data().phase = SnapshotRepairPhase::Committed;
    committed.journal->data().consumed = false;
    committed.journal->save();
    committed.state.persisted = { QStringLiteral("\\OTHER\\BLOCKED.EXE") };
    committed.state.inMemory = committed.state.persisted;
    QString error;
    check(SnapshotRepairCoordinator::recover(
              *committed.session, committed.reader, *committed.journal, 2000, &error)
              && committed.journal->data().phase == SnapshotRepairPhase::Committed
              && committed.journal->data().consumed,
          "unconsumed COMMITTED phase requires exact committed postimage before startup");
}

void testJournalAndDigestRejections() {
    Fixture fixture;
    fixture.journal->data().consumed = true;
    fixture.journal->save();
    QString error;
    check(!SnapshotRepairCoordinator::recover(
               *fixture.session, fixture.reader, *fixture.journal, 1000, &error),
          "consumed or replayed journal is rejected");

    const QString malformed = fixture.dir.filePath(QStringLiteral("bad.json"));
    QFile bad(malformed);
    bad.open(QIODevice::WriteOnly);
    bad.write("{not-json");
    bad.close();
    check(!SnapshotRepairJournal::load(malformed, &error),
          "malformed journal is rejected");

    Fixture foreign;
    QFile source(foreign.journal->path());
    source.open(QIODevice::ReadOnly);
    QJsonObject envelope = QJsonDocument::fromJson(source.readAll()).object();
    source.close();
    QJsonObject payload = envelope.value(QStringLiteral("payload")).toObject();
    payload[QStringLiteral("target")] = QStringLiteral("\\FOREIGN.EXE");
    envelope[QStringLiteral("payload")] = payload;
    envelope[QStringLiteral("payloadSha256")] = QString::fromLatin1(
        QCryptographicHash::hash(QJsonDocument(payload).toJson(QJsonDocument::Compact),
                                 QCryptographicHash::Sha256).toHex().toUpper());
    const QString foreignPath = foreign.dir.filePath(payload.value(QStringLiteral("nonce")).toString()
                                                     + QStringLiteral(".json"));
    QFile foreignFile(foreignPath);
    foreignFile.open(QIODevice::WriteOnly | QIODevice::Truncate);
    foreignFile.write(QJsonDocument(envelope).toJson());
    foreignFile.close();
    check(!SnapshotRepairJournal::load(foreignPath, &error),
          "foreign fixed-target substitution is rejected even with matching envelope hash");

    Fixture changed;
    changed.state.mutateNonTargetAfterDelete = true;
    check(!SnapshotRepairCoordinator::execute(
               *changed.session, changed.reader, *changed.journal, 1200, &error)
              && !changed.journal->data().consumed,
          "non-target mutation fails closed and cannot authorize normal startup");
}

void testCanonicalization() {
    const QStringList values = SnapshotRepairJournal::canonicalize({
        QStringLiteral("  \\other\\blocked.exe  "),
        QStringLiteral("/新建文件夹 (3)/cpp/build_pkg/tests/release/bulwark_snapshot.exe/") });
    check(values.count(RepairDriverSession::targetNeedle()) == 1,
          "registry entries normalize slash, case, whitespace, and trailing separators");
    check(SnapshotRepairJournal::nonTargetDigest(values)
              == SnapshotRepairJournal::digest({ QStringLiteral("\\OTHER\\BLOCKED.EXE") }),
          "non-target digest excludes only the exact fixed target");
}

}

int main(int argc, char** argv) {
    QCoreApplication app(argc, argv);
    testSuccessfulDelayedDelete();
    testInitialStateRejections();
    testUncertainDeleteRecoveryAlwaysAdds();
    testEveryJournalPhase();
    testJournalAndDigestRejections();
    testCanonicalization();
    std::printf("%d checks, %d failed\n", gChecks, gFailed);
    return gFailed == 0 ? 0 : 1;
}
