#include "bulwark/service/SnapshotRepairJournal.h"

#include <QCoreApplication>
#include <QCryptographicHash>
#include <QDateTime>
#include <QDir>
#include <QDirIterator>
#include <QElapsedTimer>
#include <QFile>
#include <QFileInfo>
#include <QJsonArray>
#include <QJsonDocument>
#include <QSaveFile>
#include <QThread>
#include <QUuid>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <aclapi.h>
#include <sddl.h>

#include <algorithm>
#include <cstdio>

namespace bulwark::service {
namespace {

QString nowUtc() {
    return QDateTime::currentDateTimeUtc().toString(Qt::ISODateWithMs);
}

QString sha256Bytes(const QByteArray& bytes) {
    return QString::fromLatin1(QCryptographicHash::hash(bytes, QCryptographicHash::Sha256)
                                   .toHex().toUpper());
}

QString fileSha256(const QString& path) {
    QFile file(path);
    if (!file.open(QIODevice::ReadOnly)) return {};
    QCryptographicHash hash(QCryptographicHash::Sha256);
    if (!hash.addData(&file)) return {};
    return QString::fromLatin1(hash.result().toHex().toUpper());
}

QJsonArray stringsToJson(const QStringList& values) {
    QJsonArray result;
    for (const QString& value : values) result.append(value);
    return result;
}

QStringList stringsFromJson(const QJsonValue& value, bool* ok) {
    QStringList result;
    if (!value.isArray()) { *ok = false; return result; }
    for (const QJsonValue& item : value.toArray()) {
        if (!item.isString()) { *ok = false; return {}; }
        result.append(item.toString());
    }
    return result;
}

QJsonObject payloadFor(const SnapshotRepairJournalData& data) {
    QJsonObject payload;
    payload[QStringLiteral("schemaVersion")] = data.schemaVersion;
    payload[QStringLiteral("nonce")] = data.nonce;
    payload[QStringLiteral("target")] = data.target;
    payload[QStringLiteral("sentinel")] = data.sentinel;
    payload[QStringLiteral("canonicalPreimage")] = stringsToJson(data.canonicalPreimage);
    payload[QStringLiteral("nonTargetDigest")] = data.nonTargetDigest;
    payload[QStringLiteral("componentIdentities")] = data.componentIdentities;
    payload[QStringLiteral("appsettingsSha256")] = data.appsettingsSha256;
    payload[QStringLiteral("timestamps")] = data.timestamps;
    QJsonArray commands;
    for (const RepairCommandResult& result : data.commandResults)
        commands.append(result.toJson());
    payload[QStringLiteral("commandResults")] = commands;
    payload[QStringLiteral("phase")] = snapshotRepairPhaseName(data.phase);
    payload[QStringLiteral("consumed")] = data.consumed;
    return payload;
}

bool parsePayload(const QJsonObject& payload, SnapshotRepairJournalData* data,
                  QString* error) {
    const auto fail = [error](const QString& message) {
        if (error) *error = message;
        return false;
    };
    if (payload.value(QStringLiteral("schemaVersion")).toInt(-1) != 1)
        return fail(QStringLiteral("unsupported repair journal schema"));
    const QString nonce = payload.value(QStringLiteral("nonce")).toString();
    if (QUuid(nonce).isNull()) return fail(QStringLiteral("invalid repair journal nonce"));
    if (payload.value(QStringLiteral("target")).toString()
            != RepairDriverSession::targetNeedle()
        || payload.value(QStringLiteral("sentinel")).toString()
            != RepairDriverSession::sentinelNeedle()) {
        return fail(QStringLiteral("foreign repair journal target or sentinel"));
    }
    const auto phase = snapshotRepairPhaseFromName(
        payload.value(QStringLiteral("phase")).toString());
    if (!phase) return fail(QStringLiteral("invalid repair journal phase"));
    bool ok = true;
    const QStringList preimage = stringsFromJson(
        payload.value(QStringLiteral("canonicalPreimage")), &ok);
    if (!ok || preimage.isEmpty()) return fail(QStringLiteral("invalid repair preimage"));
    if (SnapshotRepairJournal::canonicalize(preimage) != preimage)
        return fail(QStringLiteral("repair preimage is not canonical"));
    if (preimage.count(RepairDriverSession::targetNeedle()) != 1)
        return fail(QStringLiteral("repair preimage does not contain exactly one target"));
    const QString expectedNonTarget = SnapshotRepairJournal::nonTargetDigest(preimage);
    if (payload.value(QStringLiteral("nonTargetDigest")).toString() != expectedNonTarget)
        return fail(QStringLiteral("repair non-target digest mismatch"));
    if (!payload.value(QStringLiteral("componentIdentities")).isObject()
        || !payload.value(QStringLiteral("timestamps")).isObject()
        || !payload.value(QStringLiteral("commandResults")).isArray()) {
        return fail(QStringLiteral("repair journal object shape is invalid"));
    }

    SnapshotRepairJournalData parsed;
    parsed.nonce = nonce;
    parsed.target = RepairDriverSession::targetNeedle();
    parsed.sentinel = RepairDriverSession::sentinelNeedle();
    parsed.canonicalPreimage = preimage;
    parsed.nonTargetDigest = expectedNonTarget;
    parsed.componentIdentities = payload.value(QStringLiteral("componentIdentities")).toObject();
    parsed.appsettingsSha256 = payload.value(QStringLiteral("appsettingsSha256")).toString();
    parsed.timestamps = payload.value(QStringLiteral("timestamps")).toObject();
    parsed.phase = *phase;
    parsed.consumed = payload.value(QStringLiteral("consumed")).toBool(false);
    for (const QJsonValue& value : payload.value(QStringLiteral("commandResults")).toArray()) {
        if (!value.isObject()) return fail(QStringLiteral("invalid repair command record"));
        const QJsonObject object = value.toObject();
        RepairCommandResult result;
        result.command = static_cast<quint32>(object.value(QStringLiteral("command")).toInteger());
        result.path = object.value(QStringLiteral("path")).toString();
        result.ok = object.value(QStringLiteral("ok")).toBool();
        result.error = object.value(QStringLiteral("error")).toString();
        parsed.commandResults.append(result);
    }
    *data = parsed;
    return true;
}

bool setRestrictedAcl(const QString& path, QString* error) {
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    if (!::ConvertStringSecurityDescriptorToSecurityDescriptorW(
            L"D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)", SDDL_REVISION_1,
            &descriptor, nullptr)) {
        if (error) *error = QStringLiteral("ConvertStringSecurityDescriptor failed: %1")
                                .arg(::GetLastError());
        return false;
    }
    PACL dacl = nullptr;
    BOOL present = FALSE, defaulted = FALSE;
    const BOOL got = ::GetSecurityDescriptorDacl(descriptor, &present, &dacl, &defaulted);
    DWORD status = ERROR_INVALID_SECURITY_DESCR;
    if (got && present) {
        status = ::SetNamedSecurityInfoW(
            const_cast<wchar_t*>(reinterpret_cast<const wchar_t*>(path.utf16())),
            SE_FILE_OBJECT, DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            nullptr, nullptr, dacl, nullptr);
    }
    ::LocalFree(descriptor);
    if (status != ERROR_SUCCESS) {
        if (error) *error = QStringLiteral("SetNamedSecurityInfo failed: %1").arg(status);
        return false;
    }
    return true;
}

bool sidIsSystemOrAdministrators(PSID sid) {
    BYTE systemBuffer[SECURITY_MAX_SID_SIZE] = {};
    BYTE adminBuffer[SECURITY_MAX_SID_SIZE] = {};
    DWORD systemSize = sizeof(systemBuffer), adminSize = sizeof(adminBuffer);
    if (!::CreateWellKnownSid(WinLocalSystemSid, nullptr, systemBuffer, &systemSize)
        || !::CreateWellKnownSid(WinBuiltinAdministratorsSid, nullptr,
                                 adminBuffer, &adminSize)) return false;
    return ::EqualSid(sid, systemBuffer) || ::EqualSid(sid, adminBuffer);
}

bool aclIsRestricted(const QString& path) {
    PACL dacl = nullptr;
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    const DWORD status = ::GetNamedSecurityInfoW(
        const_cast<wchar_t*>(reinterpret_cast<const wchar_t*>(path.utf16())),
        SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, nullptr, nullptr, &dacl, nullptr,
        &descriptor);
    if (status != ERROR_SUCCESS || !descriptor || !dacl) {
        if (descriptor) ::LocalFree(descriptor);
        return false;
    }
    const auto* control = reinterpret_cast<const SECURITY_DESCRIPTOR_RELATIVE*>(descriptor);
    bool ok = (control->Control & SE_DACL_PROTECTED) != 0 && dacl->AceCount == 2;
    for (DWORD i = 0; ok && i < dacl->AceCount; ++i) {
        void* raw = nullptr;
        if (!::GetAce(dacl, i, &raw)) { ok = false; break; }
        const auto* ace = static_cast<ACCESS_ALLOWED_ACE*>(raw);
        ok = ace->Header.AceType == ACCESS_ALLOWED_ACE_TYPE
          && (ace->Mask & FILE_ALL_ACCESS) == FILE_ALL_ACCESS
          && sidIsSystemOrAdministrators(const_cast<DWORD*>(&ace->SidStart));
    }
    ::LocalFree(descriptor);
    return ok;
}

class RegistryPolicyReader final : public SnapshotRepairPolicyReader {
public:
    bool read(QStringList* entries, QString* error) override {
        constexpr wchar_t key[] = L"SYSTEM\\CurrentControlSet\\Services\\Bulwark\\Policy";
        DWORD type = 0, bytes = 0;
        LSTATUS status = ::RegGetValueW(HKEY_LOCAL_MACHINE, key, L"FileExecBlock",
                                        RRF_RT_REG_MULTI_SZ, &type, nullptr, &bytes);
        if (status != ERROR_SUCCESS || type != REG_MULTI_SZ || bytes < 2 * sizeof(wchar_t)
            || bytes > 1024 * 1024) {
            if (error) *error = QStringLiteral("cannot read strict FileExecBlock preimage: %1")
                                    .arg(status);
            return false;
        }
        QVector<wchar_t> buffer(static_cast<int>(bytes / sizeof(wchar_t)) + 2, L'\0');
        status = ::RegGetValueW(HKEY_LOCAL_MACHINE, key, L"FileExecBlock",
                                RRF_RT_REG_MULTI_SZ, &type, buffer.data(), &bytes);
        if (status != ERROR_SUCCESS) {
            if (error) *error = QStringLiteral("FileExecBlock readback failed: %1").arg(status);
            return false;
        }
        QStringList result;
        const wchar_t* cursor = buffer.constData();
        const wchar_t* end = cursor + bytes / sizeof(wchar_t);
        while (cursor < end && *cursor) {
            const qsizetype remaining = end - cursor;
            qsizetype length = 0;
            while (length < remaining && cursor[length]) ++length;
            if (length == remaining) {
                if (error) *error = QStringLiteral("FileExecBlock is malformed REG_MULTI_SZ");
                return false;
            }
            result.append(QString::fromWCharArray(cursor, static_cast<int>(length)));
            cursor += length + 1;
        }
        *entries = result;
        return true;
    }
};

QStringList withoutTarget(const QStringList& preimage) {
    QStringList postimage = preimage;
    postimage.removeOne(RepairDriverSession::targetNeedle());
    return postimage;
}

bool readCanonical(SnapshotRepairPolicyReader& reader, QStringList* canonical,
                   QString* error) {
    QStringList values;
    if (!reader.read(&values, error)) return false;
    *canonical = SnapshotRepairJournal::canonicalize(values);
    return true;
}

bool waitStableExact(SnapshotRepairPolicyReader& reader, const QStringList& expected,
                     int timeoutMs, QString* error) {
    QElapsedTimer timer;
    timer.start();
    QStringList previous;
    bool havePrevious = false;
    while (timer.elapsed() <= timeoutMs) {
        QStringList current;
        QString readError;
        if (readCanonical(reader, &current, &readError)) {
            if (current == expected && havePrevious && current == previous)
                return true;
            previous = current;
            havePrevious = true;
        } else if (error) {
            *error = readError;
        }
        QThread::msleep(100);
    }
    if (error && error->isEmpty())
        *error = QStringLiteral("stable exact FileExecBlock readback timed out");
    return false;
}

void copyResults(const RepairDriverSession& session, SnapshotRepairJournal& journal) {
    journal.data().commandResults = session.commandResults();
}

bool transition(SnapshotRepairJournal& journal, SnapshotRepairPhase phase,
                bool consumed, QString* error) {
    journal.data().phase = phase;
    journal.data().consumed = consumed;
    journal.data().timestamps[snapshotRepairPhaseName(phase)] = nowUtc();
    return journal.save(error);
}

bool isElevated() {
    BOOL member = FALSE;
    SID_IDENTIFIER_AUTHORITY authority = SECURITY_NT_AUTHORITY;
    PSID admins = nullptr;
    if (!::AllocateAndInitializeSid(&authority, 2, SECURITY_BUILTIN_DOMAIN_RID,
                                    DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0,
                                    &admins)) return false;
    const BOOL ok = ::CheckTokenMembership(nullptr, admins, &member);
    ::FreeSid(admins);
    return ok && member;
}

bool serviceState(const wchar_t* name, DWORD expected) {
    SC_HANDLE manager = ::OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!manager) return false;
    SC_HANDLE service = ::OpenServiceW(manager, name, SERVICE_QUERY_STATUS);
    if (!service) { ::CloseServiceHandle(manager); return false; }
    SERVICE_STATUS_PROCESS status{};
    DWORD bytes = 0;
    const bool ok = ::QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO,
                                           reinterpret_cast<LPBYTE>(&status), sizeof(status),
                                           &bytes) && status.dwCurrentState == expected;
    ::CloseServiceHandle(service);
    ::CloseServiceHandle(manager);
    return ok;
}

QJsonObject productionIdentities() {
    const QString root = QStringLiteral("D:/新建文件夹 (3)");
    QJsonObject result;
    const auto add = [&result](const QString& name, const QString& path) {
        QFileInfo info(path);
        QJsonObject item;
        item[QStringLiteral("path")] = QDir::toNativeSeparators(path);
        item[QStringLiteral("size")] = info.exists() ? info.size() : -1;
        item[QStringLiteral("sha256")] = fileSha256(path);
        result[name] = item;
    };
    add(QStringLiteral("service"), QCoreApplication::applicationFilePath());
    add(QStringLiteral("driver"), QStringLiteral("C:/Windows/System32/drivers/Bulwark.sys"));
    add(QStringLiteral("snapshot"), root + QStringLiteral("/cpp/build_pkg/tests/Release/bulwark_snapshot.exe"));
    add(QStringLiteral("snapshotTool"), root + QStringLiteral("/cpp/tests/SnapshotTool.cpp"));
    add(QStringLiteral("corpus"), root + QStringLiteral("/cpp/tests/data/corpus.json"));
    add(QStringLiteral("golden"), root + QStringLiteral("/cpp/tests/data/golden.json"));
    return result;
}

bool productionPreconditions(QString* error) {
    const QString expected = QDir::cleanPath(
        QStringLiteral("D:/新建文件夹 (3)/cpp/dist/bulwark_service.exe"));
    if (QDir::cleanPath(QCoreApplication::applicationFilePath())
            .compare(expected, Qt::CaseInsensitive) != 0) {
        if (error) *error = QStringLiteral("repair must run from installed cpp\\dist service");
        return false;
    }
    if (!isElevated()) {
        if (error) *error = QStringLiteral("repair requires an elevated token");
        return false;
    }
    if (!serviceState(L"BulwarkService", SERVICE_STOPPED)) {
        if (error) *error = QStringLiteral("BulwarkService must be stopped");
        return false;
    }
    if (!serviceState(L"Bulwark", SERVICE_RUNNING)) {
        if (error) *error = QStringLiteral("Bulwark driver must remain running");
        return false;
    }
    const QString root = QStringLiteral("D:/新建文件夹 (3)");
    if (!QFileInfo(root + QStringLiteral("/cpp/build_pkg/tests/Release/bulwark_snapshot.exe")).isFile()) {
        if (error) *error = QStringLiteral("fixed snapshot target is absent");
        return false;
    }
    return true;
}

}

QString snapshotRepairPhaseName(SnapshotRepairPhase phase) {
    switch (phase) {
    case SnapshotRepairPhase::Prepared: return QStringLiteral("PREPARED");
    case SnapshotRepairPhase::DeleteCapabilityProved: return QStringLiteral("DELETE_CAPABILITY_PROVED");
    case SnapshotRepairPhase::ExecBlockDeleteIntent: return QStringLiteral("EXECBLOCK_DELETE_INTENT");
    case SnapshotRepairPhase::ExecBlockRemovedVerified: return QStringLiteral("EXECBLOCK_REMOVED_VERIFIED");
    case SnapshotRepairPhase::RestoreIntent: return QStringLiteral("RESTORE_INTENT");
    case SnapshotRepairPhase::Restored: return QStringLiteral("RESTORED");
    case SnapshotRepairPhase::Committed: return QStringLiteral("COMMITTED");
    case SnapshotRepairPhase::Aborted: return QStringLiteral("ABORTED");
    }
    return {};
}

std::optional<SnapshotRepairPhase> snapshotRepairPhaseFromName(const QString& name) {
    for (SnapshotRepairPhase phase : { SnapshotRepairPhase::Prepared,
            SnapshotRepairPhase::DeleteCapabilityProved,
            SnapshotRepairPhase::ExecBlockDeleteIntent,
            SnapshotRepairPhase::ExecBlockRemovedVerified,
            SnapshotRepairPhase::RestoreIntent, SnapshotRepairPhase::Restored,
            SnapshotRepairPhase::Committed, SnapshotRepairPhase::Aborted }) {
        if (snapshotRepairPhaseName(phase) == name) return phase;
    }
    return std::nullopt;
}

QString SnapshotRepairJournal::productionDirectory() {
    const QString base = qEnvironmentVariable("ProgramData", QStringLiteral("C:/ProgramData"));
    return QDir(base).filePath(QStringLiteral("Bulwark/maintenance/snapshot-full-regression"));
}

QString SnapshotRepairJournal::normalizeEntry(const QString& value) {
    QString result = value.trimmed();
    result.replace(QLatin1Char('/'), QLatin1Char('\\'));
    while (result.size() > 1 && result.endsWith(QLatin1Char('\\'))) result.chop(1);
    return result.toUpper();
}

QStringList SnapshotRepairJournal::canonicalize(const QStringList& values) {
    QStringList result;
    for (const QString& value : values) {
        const QString normalized = normalizeEntry(value);
        if (!normalized.isEmpty()) result.append(normalized);
    }
    std::sort(result.begin(), result.end(), [](const QString& left, const QString& right) {
        return left.compare(right, Qt::CaseSensitive) < 0;
    });
    return result;
}

QString SnapshotRepairJournal::digest(const QStringList& canonicalValues) {
    return sha256Bytes(canonicalValues.join(QChar(0x001f)).toUtf8());
}

QString SnapshotRepairJournal::nonTargetDigest(const QStringList& canonicalValues) {
    QStringList values;
    for (const QString& value : canonicalValues)
        if (value != RepairDriverSession::targetNeedle()) values.append(value);
    return digest(values);
}

std::optional<SnapshotRepairJournal> SnapshotRepairJournal::create(
    const QString& directory, const QStringList& preimage,
    const QJsonObject& componentIdentities, const QString& appsettingsSha256,
    QString* error) {
    const QStringList canonical = canonicalize(preimage);
    if (canonical.count(RepairDriverSession::targetNeedle()) != 1
        || canonical.contains(RepairDriverSession::sentinelNeedle())) {
        if (error) *error = QStringLiteral("repair requires exactly one target and no sentinel");
        return std::nullopt;
    }
    if (!QDir().mkpath(directory)) {
        if (error) *error = QStringLiteral("cannot create repair journal directory");
        return std::nullopt;
    }
    if (QDir::cleanPath(directory).compare(QDir::cleanPath(productionDirectory()),
                                           Qt::CaseInsensitive) == 0
        && !setRestrictedAcl(directory, error)) return std::nullopt;

    SnapshotRepairJournal journal;
    journal.data_.nonce = QUuid::createUuid().toString(QUuid::WithoutBraces);
    journal.path_ = QDir(directory).filePath(journal.data_.nonce + QStringLiteral(".json"));
    journal.data_.target = RepairDriverSession::targetNeedle();
    journal.data_.sentinel = RepairDriverSession::sentinelNeedle();
    journal.data_.canonicalPreimage = canonical;
    journal.data_.nonTargetDigest = nonTargetDigest(canonical);
    journal.data_.componentIdentities = componentIdentities;
    journal.data_.appsettingsSha256 = appsettingsSha256;
    journal.data_.timestamps[QStringLiteral("created")] = nowUtc();
    if (!journal.save(error)) return std::nullopt;
    return journal;
}

bool SnapshotRepairJournal::save(QString* error) const {
    if (path_.isEmpty()) {
        if (error) *error = QStringLiteral("repair journal path is empty");
        return false;
    }
    const QJsonObject payload = payloadFor(data_);
    const QByteArray payloadBytes = QJsonDocument(payload).toJson(QJsonDocument::Compact);
    QJsonObject envelope;
    envelope[QStringLiteral("payload")] = payload;
    envelope[QStringLiteral("payloadSha256")] = sha256Bytes(payloadBytes);
    const QByteArray bytes = QJsonDocument(envelope).toJson(QJsonDocument::Indented);
    QSaveFile file(path_);
    file.setDirectWriteFallback(false);
    if (!file.open(QIODevice::WriteOnly) || file.write(bytes) != bytes.size()
        || !file.commit()) {
        if (error) *error = QStringLiteral("QSaveFile journal commit failed");
        return false;
    }
    QString verifyError;
    const auto verified = load(path_, &verifyError);
    if (!verified || payloadFor(verified->data_) != payload) {
        if (error) *error = QStringLiteral("journal reopen verification failed: %1")
                                .arg(verifyError);
        return false;
    }
    if (QDir::cleanPath(QFileInfo(path_).absolutePath())
            .compare(QDir::cleanPath(productionDirectory()), Qt::CaseInsensitive) == 0
        && !setRestrictedAcl(path_, error)) return false;
    return true;
}

std::optional<SnapshotRepairJournal> SnapshotRepairJournal::load(const QString& path,
                                                                 QString* error) {
    QFile file(path);
    if (!file.open(QIODevice::ReadOnly)) {
        if (error) *error = QStringLiteral("cannot open repair journal");
        return std::nullopt;
    }
    QJsonParseError parseError{};
    const QJsonDocument document = QJsonDocument::fromJson(file.readAll(), &parseError);
    if (parseError.error != QJsonParseError::NoError || !document.isObject()) {
        if (error) *error = QStringLiteral("malformed repair journal");
        return std::nullopt;
    }
    const QJsonObject envelope = document.object();
    if (!envelope.value(QStringLiteral("payload")).isObject()) {
        if (error) *error = QStringLiteral("repair journal payload is absent");
        return std::nullopt;
    }
    const QJsonObject payload = envelope.value(QStringLiteral("payload")).toObject();
    const QByteArray payloadBytes = QJsonDocument(payload).toJson(QJsonDocument::Compact);
    if (envelope.value(QStringLiteral("payloadSha256")).toString() != sha256Bytes(payloadBytes)) {
        if (error) *error = QStringLiteral("repair journal SHA-256 mismatch");
        return std::nullopt;
    }
    SnapshotRepairJournal journal(path);
    if (!parsePayload(payload, &journal.data_, error)) return std::nullopt;
    if (QFileInfo(path).completeBaseName() != journal.data_.nonce) {
        if (error) *error = QStringLiteral("repair journal nonce/file-name mismatch");
        return std::nullopt;
    }
    return journal;
}

bool SnapshotRepairCoordinator::execute(
    RepairDriverSession& session, SnapshotRepairPolicyReader& reader,
    SnapshotRepairJournal& journal, int deadlineMs, QString* error) {
    QElapsedTimer deadline;
    deadline.start();
    const auto remaining = [&]() { return qMax(0, deadlineMs - static_cast<int>(deadline.elapsed())); };
    QString localError;
    if (!session.connect(&localError) || !session.handshake(&localError)) {
        copyResults(session, journal);
        journal.save(nullptr);
        if (error) *error = localError;
        return false;
    }
    copyResults(session, journal);
    if (!transition(journal, SnapshotRepairPhase::Prepared, false, &localError)) {
        if (error) *error = localError;
        return false;
    }
    if (!session.deleteSentinel(&localError)) {
        copyResults(session, journal);
        transition(journal, SnapshotRepairPhase::Aborted, true, nullptr);
        if (error) *error = localError;
        return false;
    }
    copyResults(session, journal);
    if (!waitStableExact(reader, journal.data().canonicalPreimage,
                         qMin(5000, remaining()), &localError)) {
        journal.save(nullptr);
        if (error) *error = localError;
        return false;
    }
    if (!transition(journal, SnapshotRepairPhase::DeleteCapabilityProved,
                    false, &localError)) {
        if (error) *error = localError;
        return false;
    }
    if (!transition(journal, SnapshotRepairPhase::ExecBlockDeleteIntent,
                    false, &localError)) {
        if (error) *error = localError;
        return false;
    }
    if (!session.deleteTarget(&localError)) {
        copyResults(session, journal);
        journal.save(nullptr);
        recover(session, reader, journal, remaining(), nullptr);
        if (error) *error = localError;
        return false;
    }
    copyResults(session, journal);
    journal.save(nullptr);
    const QStringList postimage = withoutTarget(journal.data().canonicalPreimage);
    if (!waitStableExact(reader, postimage, qMin(5000, remaining()), &localError)
        || SnapshotRepairJournal::nonTargetDigest(postimage) != journal.data().nonTargetDigest
        || !transition(journal, SnapshotRepairPhase::ExecBlockRemovedVerified,
                       false, &localError)
        || !transition(journal, SnapshotRepairPhase::Committed, true, &localError)) {
        recover(session, reader, journal, remaining(), nullptr);
        if (error) *error = localError;
        return false;
    }
    return true;
}

bool SnapshotRepairCoordinator::recover(
    RepairDriverSession& session, SnapshotRepairPolicyReader& reader,
    SnapshotRepairJournal& journal, int deadlineMs, QString* error) {
    if (journal.data().consumed) {
        if (error) *error = QStringLiteral("consumed/replayed repair journal rejected");
        return false;
    }
    QString localError;
    const auto phase = journal.data().phase;
    if (phase == SnapshotRepairPhase::Prepared
        || phase == SnapshotRepairPhase::DeleteCapabilityProved
        || phase == SnapshotRepairPhase::Aborted) {
        if (!waitStableExact(reader, journal.data().canonicalPreimage,
                             qMin(5000, deadlineMs), &localError)
            || !transition(journal, SnapshotRepairPhase::Aborted, true, &localError)) {
            if (error) *error = localError;
            return false;
        }
        return true;
    }
    if (phase == SnapshotRepairPhase::Committed) {
        const QStringList postimage = withoutTarget(journal.data().canonicalPreimage);
        if (!waitStableExact(reader, postimage, qMin(5000, deadlineMs), &localError)
            || !transition(journal, SnapshotRepairPhase::Committed, true, &localError)) {
            if (error) *error = localError;
            return false;
        }
        return true;
    }
    if (!transition(journal, SnapshotRepairPhase::RestoreIntent, false, &localError)) {
        if (error) *error = localError;
        return false;
    }
    if (!session.connect(&localError) || !session.handshake(&localError)
        || !session.restoreTarget(&localError)) {
        copyResults(session, journal);
        journal.save(nullptr);
        if (error) *error = localError;
        return false;
    }
    copyResults(session, journal);
    journal.save(nullptr);
    if (!waitStableExact(reader, journal.data().canonicalPreimage,
                         qMin(5000, deadlineMs), &localError)
        || !transition(journal, SnapshotRepairPhase::Restored, true, &localError)) {
        if (error) *error = localError;
        return false;
    }
    return true;
}

int runSnapshotRepairProduction() {
    QString error;
    if (!productionPreconditions(&error)) {
        fprintf(stderr, "%s\n", qPrintable(error));
        return 2;
    }
    if (!recoverPendingSnapshotRepairsProduction(&error)) {
        fprintf(stderr, "%s\n", qPrintable(error));
        return 2;
    }
    const QString directory = SnapshotRepairJournal::productionDirectory();
    if (QFileInfo::exists(directory) && !aclIsRestricted(directory)) {
        fprintf(stderr, "repair journal directory ACL is not restricted\n");
        return 2;
    }
    RegistryPolicyReader reader;
    QStringList preimage;
    if (!reader.read(&preimage, &error)) {
        fprintf(stderr, "%s\n", qPrintable(error));
        return 2;
    }
    const QString appsettings = QDir(QCoreApplication::applicationDirPath())
                                    .filePath(QStringLiteral("appsettings.json"));
    auto journal = SnapshotRepairJournal::create(directory, preimage,
                                                  productionIdentities(),
                                                  fileSha256(appsettings), &error);
    if (!journal) {
        fprintf(stderr, "%s\n", qPrintable(error));
        return 2;
    }
    auto session = RepairDriverSession::createProduction();
    if (!SnapshotRepairCoordinator::execute(*session, reader, *journal, 90000, &error)) {
        fprintf(stderr, "%s\n", qPrintable(error));
        return 2;
    }
    fprintf(stdout, "snapshot exact repair committed: %s\n", qPrintable(journal->path()));
    return 0;
}

int restoreLatestSnapshotRepairProduction() {
    QString error;
    if (!productionPreconditions(&error)) {
        fprintf(stderr, "%s\n", qPrintable(error));
        return 2;
    }
    QDir directory(SnapshotRepairJournal::productionDirectory());
    const QFileInfoList files = directory.entryInfoList({ QStringLiteral("*.json") },
                                                         QDir::Files, QDir::Time);
    for (const QFileInfo& file : files) {
        auto journal = SnapshotRepairJournal::load(file.absoluteFilePath(), &error);
        if (!journal || journal->data().phase != SnapshotRepairPhase::Committed
            || !journal->data().consumed) continue;
        journal->data().consumed = false;
        journal->data().phase = SnapshotRepairPhase::RestoreIntent;
        if (!journal->save(&error)) break;
        RegistryPolicyReader reader;
        auto session = RepairDriverSession::createProduction();
        if (SnapshotRepairCoordinator::recover(*session, reader, *journal, 90000, &error))
            return 0;
        break;
    }
    fprintf(stderr, "%s\n", qPrintable(error.isEmpty()
        ? QStringLiteral("no committed snapshot repair journal found") : error));
    return 2;
}

bool recoverPendingSnapshotRepairsProduction(QString* error) {
    const QString directoryPath = SnapshotRepairJournal::productionDirectory();
    QDir directory(directoryPath);
    if (!directory.exists()) return true;
    if (!aclIsRestricted(directoryPath)) {
        if (error) *error = QStringLiteral("repair journal directory ACL is not restricted");
        return false;
    }
    const QFileInfoList files = directory.entryInfoList({ QStringLiteral("*.json") },
                                                         QDir::Files, QDir::Name);
    for (const QFileInfo& file : files) {
        QString localError;
        auto journal = SnapshotRepairJournal::load(file.absoluteFilePath(), &localError);
        if (!journal) {
            if (error) *error = localError;
            return false;
        }
        if (journal->data().consumed) continue;
        RegistryPolicyReader reader;
        auto session = RepairDriverSession::createProduction();
        if (!SnapshotRepairCoordinator::recover(*session, reader, *journal, 90000,
                                                &localError)) {
            if (error) *error = localError;
            return false;
        }
    }
    return true;
}

}
