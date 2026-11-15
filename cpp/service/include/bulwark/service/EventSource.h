 #pragma once
#include <QObject>
#include <QStringList>
#include "bulwark/models/SecurityEvent.h"

namespace bulwark::service {

class EventSource : public QObject {
    Q_OBJECT
public:
    explicit EventSource(QObject* parent = nullptr) : QObject(parent) {}
    ~EventSource() override = default;
    virtual void start() = 0;
    virtual void stop() = 0;
    virtual bool isAvailable() const { return true; }

    virtual bool wantsVerdict() const { return false; }
    virtual void submitVerdict(const bulwark::SecurityEvent&,
                               bulwark::VerdictAction) {}

    virtual bool blockModuleLoad(const QString&) { return false; }

    virtual bool blockExecPath(const QString&) { return false; }

    virtual bool hardenRegistryKey(const QString&) { return false; }

    virtual bool killProcess(int) { return false; }
    virtual bool banProcess(int) { return false; }

    virtual bool clearExecBlock() { return false; }
    virtual bool clearModuleNoLoad() { return false; }
    virtual bool clearBannedProcesses() { return false; }
    virtual QStringList persistedExecBlockList() const { return {}; }
    virtual QStringList persistedModuleNoLoadList() const { return {}; }

    virtual void setMemoryProtectionEnabled(bool) {}

    virtual void applyRansomGuard(bool, const QStringList&,
                                  const QStringList&) {}

    // 窃密防护:entries 为 "数据片段|读者;读者",readers 为对所有条目放行的全局读者。
    virtual void applyReadGuard(bool, const QStringList&,
                                const QStringList&) {}

signals:
    void eventProduced(const bulwark::SecurityEvent& e);
};

}
