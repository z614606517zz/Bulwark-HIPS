#pragma once
#include "bulwark/ipc/Payloads.h"
#include "bulwark/service/Logger.h"

#include <QHash>
#include <QList>
#include <QString>
#include <QStringList>
#include <QVector>

namespace bulwark::service {

class SystemHardening;

class HardeningCatalog {
public:
    struct Result {
        bool ok = false;
        bool needsReboot = false;
        QString message;
    };

    explicit HardeningCatalog(SystemHardening* legacy = nullptr, QString statePath = QString());

    QVector<ipc::HardeningItemPayload> inspect() const;
    Result apply(const QString& id);
    Result revert(const QString& id);

    static bool isKnown(const QString& id);

private:
    struct RegOp {
        QString hive;
        QString sub;
        QString name;
        bool existed = false;
        quint32 type = 0;
        QString data;
    };
    struct ItemState {
        QString appliedUtc;
        bool needsReboot = false;
        QList<RegOp> ops;
        QStringList created;
    };

    bool setTracked(const QString& hive, const QString& sub, const QString& name, quint32 type,
                    const QString& text, ItemState* st, QString* err);
    bool undo(const ItemState& st, QString* err);

    Result applyScriptAssoc();
    Result applyShowFileExt();
    Result applyLlmnr();

    void loadState();
    void saveState() const;

    SystemHardening* legacy_ = nullptr;
    QString statePath_;
    QHash<QString, ItemState> state_;
    Logger log_{QStringLiteral("bulwark.service.HardeningCatalog")};
};

}
