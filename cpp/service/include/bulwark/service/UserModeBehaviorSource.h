#pragma once
#include "bulwark/service/EventSource.h"
#include "bulwark/service/Logger.h"

#include <QHash>
#include <QSet>
#include <QString>
#include <QStringList>

#include <functional>

class QFileSystemWatcher;
class QTimer;
namespace bulwark::engine { class RuleEngine; }

namespace bulwark::service {

class UserModeBehaviorSource : public EventSource {
    Q_OBJECT
public:
    explicit UserModeBehaviorSource(bulwark::engine::RuleEngine& engine, QObject* parent = nullptr);
    ~UserModeBehaviorSource() override;

    void start() override;
    void stop() override;

    void setEnabled(bool on) { enabled_ = on; }
    void setCanaryEnabled(bool on) { canaryEnabled_ = on; }

#ifdef BULWARK_ENABLE_SELFTEST
    bool setSelfTestCanaryRunId(const QString& runId);
#endif

    using CanarySink = std::function<void(const QString& canaryPath,
                                          const QString& correlationId)>;
    void setCanarySink(CanarySink fn) { canarySink_ = std::move(fn); }

    using AttributionActive = std::function<bool()>;
    using AttributionSeen = std::function<bool(const QString& pathLower, qint64 windowMs)>;
    void setAttributionProbe(AttributionSeen seen, AttributionActive active) {
        attributionSeen_ = std::move(seen);
        attributionActive_ = std::move(active);
    }

    static bool shouldDeferSynthetic(bool attributionActive) { return attributionActive; }
    static bool shouldEmitSyntheticAfterDefer(bool attributionSeenRecently) {
        return !attributionSeenRecently;
    }
    static constexpr int kSyntheticDeferMs = 1500;
    static constexpr qint64 kAttributionWindowMs = 5000;

private slots:
    void onDirectoryChanged(const QString& dir);
    void onFileChanged(const QString& path);
    void pollRegistry();

private:
    void startStartupWatchers();
    void deployCanaries();
    void snapshotStartup();
    void scanRegistryDelta(bool emitEvents);
    void emitAutorunFile(const QString& filePath, const QString& target);
    void emitAutorunReg(const QString& regPath, const QString& valueName,
                        const QString& valueData, const QString& target);

    bulwark::engine::RuleEngine& engine_;
    CanarySink canarySink_;
    AttributionSeen attributionSeen_;
    AttributionActive attributionActive_;
    bool enabled_ = true;
    bool canaryEnabled_ = true;
    bool started_ = false;

    QFileSystemWatcher* watcher_ = nullptr;
    QTimer* regTimer_ = nullptr;

    QStringList startupDirs_;
    QSet<QString> canaryFiles_;
    QHash<QString, QString> canaryCorrelationIds_;
#ifdef BULWARK_ENABLE_SELFTEST
    QString selfTestCanaryRunId_;
#endif
    QHash<QString, qint64> canaryLastEventMs_;
    qint64 canarySuppressed_ = 0;
    static constexpr qint64 kCanaryDebounceMs = 3000;
    QHash<QString, QSet<QString>> startupBaseline_;
    QHash<QString, QHash<QString, QString>> regBaseline_;

    Logger log_{QStringLiteral("bulwark.service.Behavior")};
};

}
