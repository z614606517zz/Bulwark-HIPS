#pragma once
#include <QVector>
#include <QMutex>
#include <memory>
#include "bulwark/service/EventSource.h"
#include "bulwark/service/BulwarkOptions.h"

class QTimer;

namespace bulwark::service {

class EtwProcessEventSource : public EventSource {
    Q_OBJECT
public:
    explicit EtwProcessEventSource(const EtwOptions& etw, QObject* parent = nullptr);
    ~EtwProcessEventSource() override;

    void setWatchLists(const QStringList& registryKeys, const QStringList& filePaths);

    void addAttributionPath(const QString& path, const QString& correlationId = QString());
    bool writeAttributionEnabled() const;

    bool wasAttributedRecently(const QString& pathLower, qint64 windowMs) const;

    // 出队间隔(毫秒),与内核源共用 Bulwark:EventDrainIntervalMs,两个源必须一起调。
    void setDrainIntervalMs(int ms);

    void start() override;
    void stop() override;
    bool isAvailable() const override;

private:
    void drain();

    static constexpr int kDefaultDrainMs = 20;

    struct Impl;
    std::unique_ptr<Impl> d_;
    QTimer* drainTimer_ = nullptr;
    bool available_ = false;
};

}
