#pragma once
#include <QString>
#include <QByteArray>
#include <QList>
#include <QUuid>
#include <QDateTime>
#include <QMutex>
#include <QJsonObject>
#include <functional>
#include <optional>
#include <utility>

namespace bulwark::service {

struct QuarantineEntry {
    QUuid id = QUuid::createUuid();
    QString originalPath;
    QString fileName;
    QDateTime quarantinedUtc = QDateTime::currentDateTimeUtc();
    qint64 size = 0;
    QString sha256;
    QString reason;
    int actorPid = 0;
    // 复制进金库不等于完成隔离。只有原路径删除成功时才为 true。
    bool originalRemoved = true;
    bool deleteOnRebootScheduled = false;

    QJsonObject toJson() const;
    static QuarantineEntry fromJson(const QJsonObject& o);
};

class QuarantineManager {
public:
    QuarantineManager();

    std::optional<QuarantineEntry> quarantine(const QString& filePath, const QString& reason,
                                              int actorPid, const QString& sha256 = QString(),
                                              bool waitForUnlock = true);
    QList<QuarantineEntry> list();
    bool restore(const QUuid& id);
    bool purge(const QUuid& id);

    // 该原路径是否已完成隔离：金库副本仍在且原路径已不存在。仅有副本但原文件仍在时
    // 必须返回 false，让调用方继续尝试删除，不能把“复制成功”当成“已隔离”。
    bool isAlreadyQuarantined(const QString& filePath);

    // 不可还原地删除原文件,走与隔离相同的删除阶梯。只给「强制处理」在做不出金库副本时用,
    // 调用方负责护栏与二次确认。返回 (是否已从磁盘删掉, 未立即删掉时的说明)。
    std::pair<bool, QString> forceDelete(const QString& filePath);

    static QString tryComputeSha256(const QString& path);

    void setKernelAssist(std::function<bool(const QString&, QByteArray&)> reader,
                         std::function<bool(const QString&)> deleter) {
        kernelReader_ = std::move(reader);
        kernelDeleter_ = std::move(deleter);
    }

    void setSelfUnlock(std::function<int(const QString&)> fn) { selfUnlock_ = std::move(fn); }

    void setExecDenyFallback(std::function<std::pair<bool, QString>(const QString&)> fn) {
        execDeny_ = std::move(fn);
    }

private:
    QString storePathFor(const QUuid& id) const;
    void ensureLoaded();
    bool saveIndex();
    bool removeOriginal(const QString& filePath, bool waitForUnlock, QString* noteOut = nullptr,
                        bool* rebootDeleteScheduledOut = nullptr);

    static constexpr unsigned char kXorKey = 0x5A;
    QString dir_;
    QString indexPath_;
    QList<QuarantineEntry> entries_;
    bool loaded_ = false;
    QMutex io_;

    std::function<bool(const QString&, QByteArray&)> kernelReader_;
    std::function<bool(const QString&)> kernelDeleter_;
    std::function<int(const QString&)> selfUnlock_;
    std::function<std::pair<bool, QString>(const QString&)> execDeny_;
};

}
