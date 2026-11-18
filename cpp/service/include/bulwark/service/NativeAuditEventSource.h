#pragma once
#include "bulwark/service/EventSource.h"
#include "bulwark/service/NativeAuditPolicy.h"
#include "bulwark/service/Logger.h"
#include <QVector>
class QTimer;
namespace bulwark::service {
class NativeAuditEventSource : public EventSource {
    Q_OBJECT
public:
    NativeAuditEventSource(bool remoteShares, bool diskChanges, QObject* parent=nullptr);
    ~NativeAuditEventSource() override;
    void start() override;
    void stop() override;
    bool isAvailable() const override { return !subscriptions_.isEmpty(); }
    void annotate(bulwark::SecurityEvent& e) { tracker_.annotate(e); }
private:
    void subscribe(const wchar_t* channel,const wchar_t* query);
    void drain();
    struct Subscription { void* handle; void* signal; bool warned=false; };
    QVector<Subscription> subscriptions_;
    QTimer* timer_=nullptr;
    bool shares_=true,disks_=true;
    RemoteShareTracker tracker_;
    Logger log_{QStringLiteral("bulwark.service.NativeAudit")};
};
}
