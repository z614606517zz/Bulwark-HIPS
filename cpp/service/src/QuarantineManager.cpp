#include "bulwark/service/QuarantineManager.h"
#include "bulwark/service/Logger.h"
#include "bulwark/service/AtomicFile.h"
#include "bulwark/service/OccupiedFileAccess.h"
#include "bulwark/json/JsonSupport.h"

#include <QCryptographicHash>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QJsonArray>
#include <QJsonDocument>
#include <QStorageInfo>
#include <QThread>

#include <algorithm>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

namespace bulwark::service {
namespace {

Logger& log() { static Logger l(QStringLiteral("QuarantineManager")); return l; }

bool isSafeRestoreTarget(const QString& rawPath) {
    const QString p = QDir::fromNativeSeparators(rawPath);
    if (p.size() < 4 || !p.at(0).isLetter() || p.at(1) != QLatin1Char(':') || p.at(2) != QLatin1Char('/'))
        return false;
    if (p.indexOf(QLatin1Char(':'), 2) >= 0)
        return false;
    const QStringList parts = p.split(QLatin1Char('/'), Qt::SkipEmptyParts);
    for (const QString& seg : parts)
        if (seg == QLatin1String("..") || seg == QLatin1String("."))
            return false;
    QString cur = parts.value(0);
    for (int i = 1; i < parts.size(); ++i) {
        cur += QLatin1Char('/') + parts.at(i);
        const DWORD attr = ::GetFileAttributesW(reinterpret_cast<LPCWSTR>(QDir::toNativeSeparators(cur).utf16()));
        if (attr == INVALID_FILE_ATTRIBUTES)
            break;
        if (attr & FILE_ATTRIBUTE_REPARSE_POINT)
            return false;
    }
    return true;
}

bool neutralizeCopy(const QString& src, const QString& dest, unsigned char key) {
    QFile in(src);
    if (!in.open(QIODevice::ReadOnly)) return false;
    QFile out(dest);
    if (!out.open(QIODevice::WriteOnly | QIODevice::Truncate)) return false;

    auto fail = [&out, &dest]() {
        out.close();
        QFile::remove(dest);
        return false;
    };

    constexpr qint64 kBuf = 1 << 16;
    QByteArray buf;
    buf.resize(kBuf);
    for (;;) {
        const qint64 n = in.read(buf.data(), kBuf);
        if (n < 0) return fail();
        if (n == 0) break;
        for (qint64 i = 0; i < n; ++i)
            buf[i] = static_cast<char>(static_cast<unsigned char>(buf[i]) ^ key);
        if (out.write(buf.constData(), n) != n) return fail();
    }
    if (!out.flush()) return fail();
    out.close();
    in.close();
    return true;
}

bool writeNeutralizedBuffer(const QByteArray& raw, const QString& dest, unsigned char key) {
    QFile out(dest);
    if (!out.open(QIODevice::WriteOnly | QIODevice::Truncate)) return false;
    auto fail = [&out, &dest]() {
        out.close();
        QFile::remove(dest);
        return false;
    };
    constexpr qint64 kBuf = 1 << 16;
    QByteArray buf;
    buf.resize(kBuf);
    const qint64 total = raw.size();
    qint64 pos = 0;
    while (pos < total) {
        const qint64 n = qMin<qint64>(kBuf, total - pos);
        for (qint64 i = 0; i < n; ++i)
            buf[i] = static_cast<char>(static_cast<unsigned char>(raw[static_cast<int>(pos + i)]) ^ key);
        if (out.write(buf.constData(), n) != n) return fail();
        pos += n;
    }
    if (!out.flush()) return fail();
    out.close();
    return true;
}

bool scheduleDeleteOnReboot(const QString& path) {
    return MoveFileExW(reinterpret_cast<const wchar_t*>(path.utf16()), nullptr,
                       MOVEFILE_DELAY_UNTIL_REBOOT) != FALSE;
}

}

QJsonObject QuarantineEntry::toJson() const {
    using namespace bulwark::json;
    QJsonObject o;
    o[QStringLiteral("id")] = guidToString(id);
    o[QStringLiteral("originalPath")] = originalPath;
    o[QStringLiteral("fileName")] = fileName;
    o[QStringLiteral("quarantinedUtc")] = dateTimeToIso(quarantinedUtc);
    o[QStringLiteral("size")] = static_cast<qint64>(size);
    o[QStringLiteral("sha256")] = sha256;
    o[QStringLiteral("reason")] = reason;
    o[QStringLiteral("actorPid")] = actorPid;
    // 正常成功项保持原有 JSON 形态；仅部分完成时写出额外状态，兼容旧索引。
    if (!originalRemoved)
        o[QStringLiteral("originalRemoved")] = false;
    if (deleteOnRebootScheduled)
        o[QStringLiteral("deleteOnRebootScheduled")] = true;
    return o;
}

QuarantineEntry QuarantineEntry::fromJson(const QJsonObject& o) {
    using namespace bulwark::json;
    QuarantineEntry e;
    const QUuid id = guidFromString(getStr(o, "id"));
    if (!id.isNull()) e.id = id;
    e.originalPath = getStr(o, "originalPath");
    e.fileName = getStr(o, "fileName");
    const QDateTime t = dateTimeFromIso(getStr(o, "quarantinedUtc"));
    if (t.isValid()) e.quarantinedUtc = t;
    e.size = getI64(o, "size");
    e.sha256 = getStr(o, "sha256");
    e.reason = getStr(o, "reason");
    e.actorPid = getInt(o, "actorPid");
    e.originalRemoved = getBool(o, "originalRemoved", true);
    e.deleteOnRebootScheduled = getBool(o, "deleteOnRebootScheduled");
    return e;
}

QuarantineManager::QuarantineManager() {
    dir_ = QDir(programDataDir()).filePath(QStringLiteral("quarantine"));
    QDir().mkpath(dir_);
    indexPath_ = QDir(dir_).filePath(QStringLiteral("index.json"));
}

QString QuarantineManager::storePathFor(const QUuid& id) const {
    return QDir(dir_).filePath(id.toString(QUuid::WithoutBraces).remove(QLatin1Char('-')));
}

QString QuarantineManager::tryComputeSha256(const QString& path) {
    QFile f(path);
    if (!f.open(QIODevice::ReadOnly)) return QString();
    QCryptographicHash h(QCryptographicHash::Sha256);
    if (!h.addData(&f)) return QString();
    return QString::fromLatin1(h.result().toHex());
}

}

namespace bulwark::service {

void QuarantineManager::ensureLoaded() {
    if (loaded_) return;

    QFile f(indexPath_);
    if (!f.exists()) {
        loaded_ = true;
        return;
    }
    if (!f.open(QIODevice::ReadOnly)) {
        log().error(QStringLiteral("隔离区索引存在但无法打开,本次不加载且【不会覆盖】索引文件:%1")
                        .arg(indexPath_));
        return;
    }
    const QByteArray raw = f.readAll();
    f.close();
    QJsonParseError err{};
    const QJsonDocument doc = QJsonDocument::fromJson(raw, &err);
    if (err.error != QJsonParseError::NoError || !doc.isArray()) {
        const QString bak = indexPath_ + QStringLiteral(".corrupt");
        QFile::remove(bak);
        QFile::copy(indexPath_, bak);
        log().error(QStringLiteral("隔离区索引解析失败(%1),已备份为 %2 后按空表继续")
                        .arg(err.errorString(), bak));
        loaded_ = true;
        return;
    }
    const QJsonArray arr = doc.array();
    entries_.clear();
    entries_.reserve(arr.size());
    for (const QJsonValue& v : arr)
        if (v.isObject()) entries_.append(QuarantineEntry::fromJson(v.toObject()));
    loaded_ = true;
}

bool QuarantineManager::saveIndex() {
    if (!loaded_) {
        log().error(QStringLiteral("隔离区索引尚未成功加载,跳过本次保存以免覆盖已有索引"));
        return false;
    }
    QJsonArray arr;
    for (const QuarantineEntry& e : entries_) arr.append(e.toJson());
    const QByteArray bytes = QJsonDocument(arr).toJson(QJsonDocument::Indented);
    const bool ok = writeFileAtomically(indexPath_, bytes, QStringLiteral("隔离区索引"));
    if (!ok)
        log().error(QStringLiteral("隔离区索引落盘失败,内存态仍有效:%1").arg(indexPath_));
    return ok;
}

std::optional<QuarantineEntry> QuarantineManager::quarantine(
    const QString& filePath, const QString& reason, int actorPid, const QString& sha256,
    bool waitForUnlock) {
    if (filePath.trimmed().isEmpty()) return std::nullopt;

    QMutexLocker lk(&io_);
    ensureLoaded();
    if (!loaded_) return std::nullopt;
    if (!QFileInfo::exists(filePath)) return std::nullopt;

    // 已有金库副本时不要重复复制；若原路径仍在，则重新尝试完成删除。
    for (QuarantineEntry& x : entries_) {
        if (x.originalPath.compare(filePath, Qt::CaseInsensitive) != 0
            || !QFileInfo::exists(storePathFor(x.id)))
            continue;
        if (!QFileInfo::exists(filePath)) {
            x.originalRemoved = true;
            x.deleteOnRebootScheduled = false;
            return x;
        }
        // 原路径可能已被另一个文件重新占用。只有内容哈希仍是同一份样本时才重试删除；
        // 否则继续创建独立条目，绝不能因路径相同误删后来出现的文件。
        const QString currentHash = tryComputeSha256(filePath);
        if (x.sha256.isEmpty() || currentHash.isEmpty()
            || x.sha256.compare(currentHash, Qt::CaseInsensitive) != 0)
            continue;
        QString removalNote;
        bool scheduled = false;
        x.originalRemoved = removeOriginal(filePath, waitForUnlock, &removalNote, &scheduled);
        x.deleteOnRebootScheduled = scheduled;
        saveIndex();
        if (!x.originalRemoved) {
            log().warning(QStringLiteral("隔离仅部分完成:金库副本已存在,但原路径仍未删除:%1 · %2")
                              .arg(filePath, removalNote));
        }
        return x;
    }

    const QFileInfo fi(filePath);
    constexpr qint64 kMaxSingleFileBytes = 512LL * 1024 * 1024;
    constexpr qint64 kMaxVaultBytes = 5LL * 1024 * 1024 * 1024;
    constexpr qint64 kMinFreeAfterBytes = 512LL * 1024 * 1024;
    if (fi.size() < 0 || fi.size() > kMaxSingleFileBytes) {
        log().warning(QStringLiteral("隔离已拒绝:单文件大小 %1 超过上限 %2:%3")
                          .arg(fi.size()).arg(kMaxSingleFileBytes).arg(filePath));
        return std::nullopt;
    }
    qint64 vaultBytes = 0;
    for (const QuarantineEntry& existing : entries_) {
        if (existing.size > 0 && vaultBytes <= kMaxVaultBytes - existing.size)
            vaultBytes += existing.size;
        else if (existing.size > 0)
            vaultBytes = kMaxVaultBytes;
    }
    if (vaultBytes > kMaxVaultBytes - fi.size()) {
        log().warning(QStringLiteral("隔离已拒绝:金库总量将超过 %1 字节上限").arg(kMaxVaultBytes));
        return std::nullopt;
    }
    const QStorageInfo storage(dir_);
    if (storage.isValid() && storage.isReady()
        && storage.bytesAvailable() < fi.size() + kMinFreeAfterBytes) {
        log().warning(QStringLiteral("隔离已拒绝:磁盘剩余空间不足,需为系统保留至少 %1 字节")
                          .arg(kMinFreeAfterBytes));
        return std::nullopt;
    }
    QuarantineEntry entry;
    entry.originalPath = filePath;
    entry.fileName = fi.fileName();
    entry.size = fi.size();
    entry.sha256 = sha256.trimmed().isEmpty() ? tryComputeSha256(filePath) : sha256;
    entry.reason = reason;
    entry.actorPid = actorPid;

    const QString dest = storePathFor(entry.id);
    bool vaulted = neutralizeCopy(filePath, dest, kXorKey);
    if (!vaulted && selfUnlock_ && selfUnlock_(filePath) > 0)
        vaulted = neutralizeCopy(filePath, dest, kXorKey);
    if (!vaulted) {
        QByteArray raw;
        QString why;
        if (occupied::readWithBackupSemantics(filePath, raw, why)) {
            vaulted = writeNeutralizedBuffer(raw, dest, kXorKey);
            if (vaulted)
                log().info(QStringLiteral("以备份特权读出了普通方式打不开的文件(DACL 拒绝),隔离继续:%1")
                               .arg(filePath));
        } else {
            log().debug(QStringLiteral("备份特权读取未成功(%1):%2").arg(why, filePath));
        }
    }
    if (!vaulted && kernelReader_) {
        QByteArray raw;
        if (kernelReader_(filePath, raw))
            vaulted = writeNeutralizedBuffer(raw, dest, kXorKey);
    }
    if (!vaulted) {
        const QString holders = occupied::describeHolders(filePath);
        log().warning(QStringLiteral("隔离失败:无法读出文件内容以制作可逆金库副本 —— %1。文件:%2")
                          .arg(holders.isEmpty()
                                   ? QStringLiteral("未能确定占用者(Restart Manager 未报告持有进程;"
                                                    "它只看得见可识别的那类句柄,不代表确实无人占用)")
                                   : QStringLiteral("占用者:") + holders)
                          .arg(filePath));
        return std::nullopt;
    }

    // 先把“仅有金库副本、原件尚未删除”的保守状态持久化，再触碰原件。
    // 这样第二次索引更新失败或进程崩溃时，仍有可恢复元数据，不会留下无索引孤儿。
    entry.originalRemoved = false;
    entry.deleteOnRebootScheduled = false;
    const int entryIndex = entries_.size();
    entries_.append(entry);
    if (!saveIndex()) {
        entries_.removeAt(entryIndex);
        if (!QFile::remove(dest))
            log().warning(QStringLiteral("隔离索引提交失败后无法清理金库临时副本:%1").arg(dest));
        return std::nullopt;
    }

    QString removalNote;
    bool scheduled = false;
    entry.originalRemoved = removeOriginal(filePath, waitForUnlock, &removalNote, &scheduled);
    entry.deleteOnRebootScheduled = scheduled;
    entries_[entryIndex] = entry;
    (void)saveIndex(); // 失败时磁盘上保留的是上面的保守状态，绝不会误报“已移走”。
    if (!entry.originalRemoved) {
        log().warning(QStringLiteral("隔离仅部分完成:已保存可还原副本,但原路径仍存在:%1 · %2")
                          .arg(filePath, removalNote));
    }
    return entry;
}

std::pair<bool, QString> QuarantineManager::forceDelete(const QString& filePath) {
    if (filePath.trimmed().isEmpty() || !QFileInfo::exists(filePath))
        return { false, QStringLiteral("文件不存在") };
    QMutexLocker lk(&io_);
    QString note;
    const bool deleted = removeOriginal(filePath, true, &note);
    return { deleted, note };
}

bool QuarantineManager::removeOriginal(const QString& filePath, bool waitForUnlock,
                                       QString* noteOut, bool* rebootDeleteScheduledOut) {
    if (rebootDeleteScheduledOut)
        *rebootDeleteScheduledOut = false;
    bool deleted = false;
    const int attempts = waitForUnlock ? 5 : 1;
    for (int attempt = 0; attempt < attempts; ++attempt) {
        if (attempt > 0) QThread::msleep(static_cast<unsigned long>(attempt) * 500);
        if (QFile::remove(filePath)) { deleted = true; break; }
    }
    if (!deleted && selfUnlock_ && selfUnlock_(filePath) > 0 && QFile::remove(filePath))
        deleted = true;
    if (!deleted) {
        QString why;
        if (occupied::deleteWithBackupSemantics(filePath, why)) {
            deleted = true;
            log().info(QStringLiteral("以备份特权删除了普通方式删不掉的文件(DACL 拒绝):%1")
                           .arg(filePath));
        } else {
            log().debug(QStringLiteral("备份特权删除未成功(%1):%2").arg(why, filePath));
        }
    }
    if (!deleted && kernelDeleter_ && kernelDeleter_(filePath))
        deleted = true;
    if (!deleted) {
        const QString holders = occupied::describeHolders(filePath);
        const bool scheduled = scheduleDeleteOnReboot(filePath);
        if (rebootDeleteScheduledOut)
            *rebootDeleteScheduledOut = scheduled;
        QString execNote;
        if (execDeny_) {
            const std::pair<bool, QString> r = execDeny_(filePath);
            execNote = r.first
                ? QStringLiteral("已对它加「拒绝执行」ACE,重启前也无法再被运行(在界面加白即可解除)")
                : QStringLiteral("【且重启前它仍然可以被双击运行】—— 未能加执行阻断:%1").arg(r.second);
        } else {
            execNote = QStringLiteral("【且重启前它仍然可以被双击运行】—— 未注入执行阻断委托");
        }
        const QString deleteNote = scheduled
            ? QStringLiteral("已计划在下次重启时删除")
            : QStringLiteral("计划在下次重启时删除也失败");
        log().warning(QStringLiteral("原文件删不掉,%1 —— %2。%3。文件:%4")
                          .arg(deleteNote,
                               holders.isEmpty() ? QStringLiteral("未能确定占用者")
                                                 : QStringLiteral("占用者:") + holders,
                               execNote,
                               filePath));
        if (noteOut)
            *noteOut = QStringLiteral("原文件删不掉,%1;%2").arg(deleteNote, execNote);
    } else if (noteOut) {
        *noteOut = QStringLiteral("原文件已删除");
    }
    return deleted;
}

bool QuarantineManager::isAlreadyQuarantined(const QString& filePath) {
    if (filePath.trimmed().isEmpty())
        return false;
    QMutexLocker lk(&io_);
    ensureLoaded();
    for (const QuarantineEntry& x : entries_)
        if (x.originalPath.compare(filePath, Qt::CaseInsensitive) == 0
            && QFileInfo::exists(storePathFor(x.id))
            && !QFileInfo::exists(filePath))
            return true;
    return false;
}

QList<QuarantineEntry> QuarantineManager::list() {
    QMutexLocker lk(&io_);
    ensureLoaded();
    QList<QuarantineEntry> out = entries_;
    std::sort(out.begin(), out.end(), [](const QuarantineEntry& a, const QuarantineEntry& b) {
        return a.quarantinedUtc > b.quarantinedUtc;
    });
    return out;
}

bool QuarantineManager::restore(const QUuid& id) {
    QMutexLocker lk(&io_);
    ensureLoaded();
    int idx = -1;
    for (int i = 0; i < entries_.size(); ++i)
        if (entries_[i].id == id) { idx = i; break; }
    if (idx < 0) return false;

    const QuarantineEntry entry = entries_[idx];
    const QString src = storePathFor(entry.id);
    if (!QFileInfo::exists(src)) return false;

    QString target = entry.originalPath;
    if (!isSafeRestoreTarget(target)) {
        log().warning(QStringLiteral("拒绝还原:原路径不安全(含 ..、非本地绝对路径或途经重解析点):%1").arg(target));
        return false;
    }
    const QString parent = QFileInfo(target).absolutePath();
    if (!parent.isEmpty()) QDir().mkpath(parent);
    if (!isSafeRestoreTarget(target)) {
        log().warning(QStringLiteral("拒绝还原:创建父目录后路径出现重解析点:%1").arg(target));
        return false;
    }
    if (QFileInfo::exists(target)) {
        const QString base = target + QStringLiteral(".restored");
        target = base;
        for (int n = 2; QFileInfo::exists(target); ++n) {
            if (n > 1000) return false;
            target = base + QString::number(n);
        }
    }

    if (!neutralizeCopy(src, target, kXorKey)) return false;
    if (!entry.sha256.trimmed().isEmpty()) {
        const QString restoredSha = tryComputeSha256(target);
        if (restoredSha.isEmpty()
            || restoredSha.compare(entry.sha256.trimmed(), Qt::CaseInsensitive) != 0) {
            QFile::remove(target);
            log().critical(QStringLiteral("拒绝还原:金库内容 SHA-256 与索引不一致,已删除解码副本:%1")
                               .arg(src));
            return false;
        }
    }
    if (!QFile::remove(src)) {
        const bool rolledBack = QFile::remove(target);
        log().warning(QStringLiteral("还原未提交:无法删除金库副本;新建的还原文件回滚%1:%2")
                          .arg(rolledBack ? QStringLiteral("成功") : QStringLiteral("失败"), target));
        return false;
    }
    entries_.removeAt(idx);
    saveIndex();
    return true;
}

bool QuarantineManager::purge(const QUuid& id) {
    QMutexLocker lk(&io_);
    ensureLoaded();
    int idx = -1;
    for (int i = 0; i < entries_.size(); ++i)
        if (entries_[i].id == id) { idx = i; break; }
    if (idx < 0) return false;

    const QString stored = storePathFor(entries_[idx].id);
    if (QFileInfo::exists(stored) && !QFile::remove(stored)) {
        log().warning(QStringLiteral("永久删除隔离条目失败:金库文件仍存在:%1").arg(stored));
        return false;
    }
    entries_.removeAt(idx);
    saveIndex();
    return true;
}

}
