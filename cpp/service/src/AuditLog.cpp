#include "bulwark/service/AuditLog.h"
#include "bulwark/service/Logger.h"

#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QDateTime>
#include <QJsonDocument>

namespace bulwark::service {

namespace {
constexpr qint64 kMaxFileBytes = 16LL * 1024 * 1024;
constexpr qint64 kMaxTotalBytes = 512LL * 1024 * 1024;
constexpr int kMaxAgeDays = 30;

void pruneOldAuditFiles(const QString& dir) {
    QDir d(dir);
    QFileInfoList files = d.entryInfoList({QStringLiteral("audit-*.jsonl")},
                                          QDir::Files, QDir::Time);
    qint64 kept = 0;
    const QDateTime cutoff = QDateTime::currentDateTime().addDays(-kMaxAgeDays);
    for (const QFileInfo& file : files) {
        const bool expired = file.lastModified() < cutoff;
        const bool overBudget = file.size() > 0 && kept > kMaxTotalBytes - file.size();
        if (expired || overBudget)
            QFile::remove(file.absoluteFilePath());
        else
            kept += file.size();
    }
}
}

AuditLog::AuditLog() {
    dir_ = QDir(programDataDir()).filePath(QStringLiteral("audit"));
    QDir().mkpath(dir_);
    pruneOldAuditFiles(dir_);
}

void AuditLog::writeRecord(const QJsonObject& record) {
    const QByteArray line = QJsonDocument(record).toJson(QJsonDocument::Compact) + "\r\n";

    QMutexLocker lk(&io_);
    const QString path = currentFilePath();
    QFile f(path);
    if (f.open(QIODevice::Append | QIODevice::WriteOnly)) {
        const qint64 written = f.write(line);
        f.close();
        if (written > 0)
            cachedBytes_ += written;
    }
}

QString AuditLog::currentFilePath() {
    const QString day = QDateTime::currentDateTime().toString(QStringLiteral("yyyyMMdd"));
    if (!cachedPath_.isEmpty() && day == cachedDay_ && cachedBytes_ < kMaxFileBytes)
        return cachedPath_;

    const QString baseName = QStringLiteral("audit-") + day;
    QString path = QDir(dir_).filePath(baseName + QStringLiteral(".jsonl"));
    int seq = 1;
    QFileInfo fi(path);
    while (fi.exists() && fi.size() >= kMaxFileBytes) {
        path = QDir(dir_).filePath(QStringLiteral("%1.%2.jsonl").arg(baseName).arg(seq++));
        fi.setFile(path);
    }

    cachedDay_ = day;
    cachedPath_ = path;
    cachedBytes_ = fi.exists() ? fi.size() : 0;
    return path;
}

}
