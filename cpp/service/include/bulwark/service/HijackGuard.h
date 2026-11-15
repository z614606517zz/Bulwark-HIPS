#pragma once
#include "bulwark/ipc/Payloads.h"
#include "bulwark/service/HijackPolicy.h"
#include "bulwark/service/Logger.h"

#include <QHash>
#include <QList>
#include <QMap>
#include <QObject>
#include <QString>
#include <QStringList>
#include <QTimer>
#include <QVector>

#include <functional>

namespace bulwark::service {

class HijackGuard : public QObject {
    Q_OBJECT
public:
    explicit HijackGuard(QObject* parent = nullptr);
    ~HijackGuard() override;

    void setActiveProbe(std::function<bool()> probe) { activeProbe_ = std::move(probe); }
    void setStatePath(const QString& path) { statePath_ = path; }

    bool start();
    void stop();
    bool isRunning() const;
    bool isActive() const;

    QList<ipc::HijackAlertPayload> alerts() const;
    int pendingCount() const;
    QVector<ipc::HardeningItemPayload> monitorItems() const;

    struct ActionResult {
        bool ok = false;
        QString message;
    };
    ActionResult restore(const QString& alertId);
    ActionResult accept(const QString& alertId);

    void scanNow();

signals:
    void alertRaised(const bulwark::ipc::HijackAlertPayload& alert);
    void alertResolved(const bulwark::ipc::HijackAlertPayload& alert);

private:
    struct Entry {
        QString sub;
        QString name;
        quint32 type = 0;
        QString data;
        bool supported = true;  // 能不能原样写回
    };
    struct Surface {
        QString key;
        QString kind;
        QString title;
        QString location;
        QString hive;
        QString rootSub;
        QMap<QString, Entry> entries;
    };
    struct AlertRec {
        QString surfaceKey;
        ipc::HijackAlertPayload p;
    };
    struct LnkInfo {
        qint64 mtimeMs = 0;
        qint64 size = 0;
        QString target;
        QString args;
        bool parsed = false;
        bool browser = false;
    };

    void onTick();
    void scan(bool includeShortcuts);
    void evaluate(const Surface& cur);

    QMap<QString, Surface> collectRegistrySurfaces() const;
    Surface readRegistrySurface(const Surface& like) const;
    void collectShortcutSurfaces(QMap<QString, Surface>* out);
    QStringList shortcutRoots(QList<int>* depths) const;
    Surface currentOf(const Surface& like);

    static bool sameEntries(const Surface& a, const Surface& b);
    static hijack::EntryData asData(const Surface& s);
    static hijack::Verdict judge(const Surface& oldS, const Surface& newS);
    ipc::HijackAlertPayload buildAlert(const Surface& oldS, const Surface& newS,
                                       const hijack::Verdict& v, bool preexisting) const;
    void raiseAlert(const Surface& oldS, const Surface& newS, const hijack::Verdict& v,
                    bool preexisting);
    void resolvePending(const QString& surfaceKey, const QString& state, bool keepPreexisting);
    AlertRec* findAlert(const QString& id);

    bool restoreRegistry(const Surface& base, QString* err);
    bool restoreShortcut(const Surface& base, QString* err);

    void loadState();
    void saveState();

    std::function<bool()> activeProbe_;
    QString statePath_;
    QTimer* timer_ = nullptr;
    int tick_ = 0;
    bool dirty_ = false;
    QMap<QString, Surface> baseline_;
    QList<AlertRec> alerts_;
    QHash<QString, LnkInfo> lnkCache_;
    QHash<QString, qint64> lastNotifyMs_;
    Logger log_{QStringLiteral("bulwark.service.Hijack")};
};

}
