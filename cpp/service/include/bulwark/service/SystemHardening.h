#pragma once
#include "bulwark/service/Logger.h"

#include <QHash>
#include <QMutex>
#include <QObject>
#include <QString>
#include <QStringList>
#include <QVector>

#include <functional>

namespace bulwark::service {

class SystemHardening : public QObject {
    Q_OBJECT
public:
    explicit SystemHardening(QObject* parent = nullptr);
    ~SystemHardening() override;

    using TrustProbeFn = std::function<bool(const QString& path)>;
    void setTrustProbe(TrustProbeFn fn);

    using RollbackJudgeFn =
        std::function<bool(const QString& valueName, const QString& data, QString* whyKeep)>;
    void setRollbackJudge(RollbackJudgeFn fn);

    struct Finding {
        QString id;
        QString title;
        bool    satisfied = false;
        QString current;
        QString recommended;
        QString cost;
        bool    needsReboot = false;
        bool    reversible = true;
    };
    QVector<Finding> inspect() const;

    bool applyRunAsPpl(bool apply);
    bool revertRunAsPpl(bool apply);

    bool applySelfServiceDacl(bool apply);

    bool denyExecute(const QString& path);
    bool undenyExecute(const QString& path);
    QStringList deniedExecuteThisRun() const;
    static bool isExclusiveRegistryKey(const QString& hiveAndKey);
    void watchKeyLive(const QString& hiveAndKey);
    bool hasDenyExecute(const QString& path) const;

    bool denyRegistryWrite(const QString& hiveAndKey, bool exclusiveKeyOnly);
    bool undenyRegistryWrite(const QString& hiveAndKey);

    void watchKey(const QString& hiveAndKey, const QStringList& onlyValues = QStringList());
    bool startWatching();
    void stopWatching();
    bool isWatching() const;
    struct RollbackRecord {
        QString keyPath;
        QString valueName;
        QString newData;
        QString restoredTo;
        QString whenUtcIso;
    };
    QVector<RollbackRecord> rollbacks() const;

signals:
    void rolledBack(const QString& keyPath, const QString& valueName, const QString& newData,
                    const QString& restoredTo);

private:
    struct Watched {
        QString hiveAndKey;
        QHash<QString, QString> snapshot;
        QHash<QString, quint32> snapType;
        QStringList onlyValues;
    };

    void watchLoop();
    bool reconcileKey(Watched& wk);

    mutable QMutex mx_;
    TrustProbeFn trustProbe_;
    RollbackJudgeFn rollbackJudge_;
    QHash<QString, qint64> lastRollbackNoteMs_;
    QStringList deniedExec_;
    QVector<Watched> watched_;
    QVector<RollbackRecord> rollbacks_;
    void* stopEvent_ = nullptr;
    void* thread_ = nullptr;
    bool watching_ = false;
    Logger log_{QStringLiteral("bulwark.service.Hardening")};
};

}
