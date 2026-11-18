#include "bulwark/service/NativeAuditEventSource.h"
#include <QTimer>
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <winevt.h>

namespace bulwark::service {
NativeAuditEventSource::NativeAuditEventSource(bool remoteShares,bool diskChanges,QObject* parent)
    : EventSource(parent),shares_(remoteShares),disks_(diskChanges) {
    timer_=new QTimer(this); timer_->setInterval(200);
    connect(timer_,&QTimer::timeout,this,&NativeAuditEventSource::drain);
}
NativeAuditEventSource::~NativeAuditEventSource() { stop(); }
void NativeAuditEventSource::subscribe(const wchar_t* channel,const wchar_t* query) {
    const HANDLE signal=::CreateEventW(nullptr,FALSE,FALSE,nullptr);
    if (!signal) return;
    const EVT_HANDLE subscription=::EvtSubscribe(nullptr,signal,channel,query,nullptr,nullptr,nullptr,EvtSubscribeToFutureEvents);
    if (!subscription) {
        log_.warning(QStringLiteral("事件日志订阅不可用：%1，错误 %2；未启用或修改任何审核策略")
            .arg(QString::fromWCharArray(channel)).arg(::GetLastError()));
        ::CloseHandle(signal); return;
    }
    subscriptions_.push_back({subscription,signal});
    log_.info(QStringLiteral("已订阅未来事件：%1（只读）").arg(QString::fromWCharArray(channel)));
}
void NativeAuditEventSource::start() {
    if (!subscriptions_.isEmpty()) return;
    if (shares_) {
        subscribe(L"Security",L"*[System[Provider[@Name='Microsoft-Windows-Security-Auditing'] and EventID=5145]]");
        log_.info(QStringLiteral("SMB 远端线索依赖系统已启用详细文件共享审核及 5145 事件；本程序不自动改变审核策略"));
    }
    if (disks_) {
        const wchar_t* query=L"*[System[Provider[@Name='Microsoft-Windows-BitLocker-API'] and (EventID=768 or EventID=769 or EventID=770 or EventID=771 or EventID=772 or EventID=773 or EventID=775 or EventID=776)]]";
        subscribe(L"Microsoft-Windows-BitLocker/BitLocker Management",query);
        subscribe(L"Microsoft-Windows-BitLocker-API/Management",query);
    }
    if (!subscriptions_.isEmpty()) timer_->start();
}
void NativeAuditEventSource::stop() {
    timer_->stop();
    for (const auto& item:subscriptions_) { ::EvtClose(item.handle); ::CloseHandle(item.signal); }
    subscriptions_.clear();
}
void NativeAuditEventSource::drain() {
    for (auto& item:subscriptions_) {
        EVT_HANDLE records[16]{}; DWORD returned=0;
        if (!::EvtNext(item.handle,16,records,0,0,&returned)) {
            const DWORD error=::GetLastError();
            if (error!=ERROR_NO_MORE_ITEMS && error!=ERROR_TIMEOUT && !item.warned) {
                log_.warning(QStringLiteral("事件日志读取失败：%1；本轮没有生成访问者归因").arg(error));
                item.warned=true;
            }
            continue;
        }
        item.warned=false;
        for (DWORD i=0;i<returned;++i) {
            DWORD bytes=0,properties=0;
            ::EvtRender(nullptr,records[i],EvtRenderEventXml,0,nullptr,&bytes,&properties);
            if (bytes>0 && bytes<=131072) {
                QByteArray buffer(static_cast<qsizetype>(bytes),Qt::Uninitialized);
                if (::EvtRender(nullptr,records[i],EvtRenderEventXml,bytes,buffer.data(),&bytes,&properties)) {
                    auto event=NativeAuditPolicy::parse(QString::fromWCharArray(reinterpret_cast<const wchar_t*>(buffer.constData())));
                    if (event) {
                        bool send=true;
                        if (event->type==bulwark::EventType::RemoteShareAccess) {
                            send=tracker_.record(*event);
                            if (send && (event->auditAccessMask&remoteMutationAccess))
                                event->detail+=QStringLiteral("；同一远端会话在 30 秒内请求修改至少 40 个不同文件，请核对是否为授权写入、删除或权限管理");
                        }
                        if (send) emit eventProduced(*event);
                    }
                }
            }
            ::EvtClose(records[i]);
        }
    }
}
}
