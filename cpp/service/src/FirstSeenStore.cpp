#include "bulwark/service/FirstSeenStore.h"
#include "bulwark/service/Logger.h"

#include <QDir>
#include <QFile>
#include <QTextStream>

namespace bulwark::service {

namespace {
bool isSha256Hex(const QString& s) {
    if (s.size() != 64) return false;
    for (const QChar qc : s) {
        const char c = qc.toLatin1();
        const bool hex = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
        if (!hex) return false;
    }
    return true;
}
}

FirstSeenStore::FirstSeenStore() {
    path_ = QDir(programDataDir()).filePath(QStringLiteral("seen_hashes.txt"));
    load();
}

void FirstSeenStore::load() {
    QFile f(path_);
    if (!f.exists() || !f.open(QIODevice::ReadOnly | QIODevice::Text)) return;
    QTextStream in(&f);
    int skipped = 0;
    while (!in.atEnd()) {
        const QString h = in.readLine().trimmed().toUpper();
        if (h.isEmpty()) continue;
        if (!isSha256Hex(h)) { ++skipped; continue; }
        seen_.insert(h);
        if (seen_.size() >= kMaxEntries) break;
    }
    f.close();
    if (skipped > 0)
        Logger(QStringLiteral("bulwark.service.FirstSeenStore"))
            .warning(QStringLiteral("首见哈希文件中有 %1 行不是合法的 SHA-256,已忽略:%2")
                         .arg(skipped).arg(path_));
    if (seen_.size() >= kMaxEntries)
        compactLocked();
}

bool FirstSeenStore::markAndCheckFirstSeen(const QString& hash) {
    if (hash.isEmpty()) return false;
    const QString key = hash.toUpper();
    if (!isSha256Hex(key)) return false;

    QMutexLocker lk(&lock_);
    if (seen_.contains(key)) return false;
    seen_.insert(key);

    if (seen_.size() > kMaxEntries) {
        compactLocked();
        return true;
    }

    QFile f(path_);
    if (f.open(QIODevice::Append | QIODevice::WriteOnly | QIODevice::Text)) {
        f.write(key.toUtf8());
        f.write("\r\n");
        f.close();
    }
    return true;
}

void FirstSeenStore::compactLocked() {
    const int keep = kMaxEntries / 2;
    QSet<QString> trimmed;
    trimmed.reserve(keep);
    for (const QString& h : seen_) {
        if (trimmed.size() >= keep) break;
        trimmed.insert(h);
    }
    seen_.swap(trimmed);

    QFile f(path_);
    if (!f.open(QIODevice::WriteOnly | QIODevice::Truncate | QIODevice::Text)) {
        Logger(QStringLiteral("bulwark.service.FirstSeenStore"))
            .warning(QStringLiteral("首见哈希文件压实失败(仅内存已压实):%1").arg(path_));
        return;
    }
    QByteArray out;
    out.reserve(seen_.size() * 66);
    for (const QString& h : seen_) {
        out += h.toUtf8();
        out += "\r\n";
    }
    f.write(out);
    f.close();
    Logger(QStringLiteral("bulwark.service.FirstSeenStore"))
        .info(QStringLiteral("首见哈希已压实至 %1 条(上限 %2)").arg(seen_.size()).arg(kMaxEntries));
}

}
