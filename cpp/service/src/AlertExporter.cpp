#include "bulwark/service/AlertExporter.h"
#include "bulwark/service/Logger.h"
#include "bulwark/engine/EcsAlertFormatter.h"

#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QDateTime>
#include <QJsonDocument>

namespace bulwark::service {

namespace {
constexpr qint64 kMaxFileBytes = 32LL * 1024 * 1024;
constexpr qint64 kMaxTotalBytes = 512LL * 1024 * 1024;
constexpr int kMaxAgeDays = 30;

void pruneOldAlertFiles(const QString& dir) {
    QDir d(dir);
    const QFileInfoList files = d.entryInfoList({QStringLiteral("alerts-*.jsonl")},
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

AlertExporter::AlertExporter(bool enabled) : enabled_(enabled) {
    dir_ = QDir(programDataDir()).filePath(QStringLiteral("alerts"));
    if (enabled_) {
        QDir().mkpath(dir_);
        pruneOldAlertFiles(dir_);
    }
}

void AlertExporter::exportAlert(const bulwark::SecurityEvent& e, const bulwark::Verdict& v) {
    if (!enabled_) return;

    const QJsonObject doc = bulwark::engine::EcsAlertFormatter::format(e, v);
    const QByteArray line = QJsonDocument(doc).toJson(QJsonDocument::Compact) + "\n";

    QMutexLocker lk(&io_);
    QFile f(currentFilePath());
    if (f.open(QIODevice::Append | QIODevice::WriteOnly)) {
        f.write(line);
        f.close();
    }
}

QString AlertExporter::currentFilePath() {
    const QString baseName = QStringLiteral("alerts-") +
        QDateTime::currentDateTime().toString(QStringLiteral("yyyyMMdd"));
    QString path = QDir(dir_).filePath(baseName + QStringLiteral(".jsonl"));
    int seq = 1;
    while (QFileInfo(path).exists() && QFileInfo(path).size() >= kMaxFileBytes)
        path = QDir(dir_).filePath(QStringLiteral("%1.%2.jsonl").arg(baseName).arg(seq++));
    return path;
}

}
