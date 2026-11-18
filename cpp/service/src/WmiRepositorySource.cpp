#include "bulwark/service/WmiRepositorySource.h"
#include "bulwark/service/WmiRepositoryPolicy.h"
#include <exception>
#include <stdexcept>
#include <QCryptographicHash>
#include <QElapsedTimer>
#include <QHash>
#include <QTimer>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <mutex>
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <wbemidl.h>

namespace bulwark::service {
struct WmiRepositorySource::Shared {
    std::atomic_bool stop{false},finished{false},available{false};
    std::mutex mutex;
    std::condition_variable wake;
    QVector<bulwark::SecurityEvent> events;
    QString health;
};
namespace {
template<class T> struct Com {
    T* p=nullptr;
    ~Com() { if (p) p->Release(); }
};
struct Bstr {
    BSTR p;
    explicit Bstr(const wchar_t* text):p(::SysAllocString(text)){}
    ~Bstr(){::SysFreeString(p);}
};
QString property(IWbemClassObject* object,const wchar_t* name) {
    VARIANT value; ::VariantInit(&value);
    QString out;
    if (SUCCEEDED(object->Get(name,0,&value,nullptr,nullptr)) && value.vt==VT_BSTR && value.bstrVal) {
        const UINT length=::SysStringLen(value.bstrVal);
        if (length>1024*1024) {
            ::VariantClear(&value);
            throw std::length_error("WMI field exceeds bounded snapshot size");
        }
        out=QString::fromWCharArray(value.bstrVal,static_cast<int>(length));
    }
    ::VariantClear(&value); return out;
}
using Item=WmiObjectFingerprint;
bool snapshot(IWbemServices* service,QHash<QString,Item>& values,const std::atomic_bool& stop) {
    QElapsedTimer timer; timer.start();
    for (const wchar_t* query:{L"SELECT * FROM __EventFilter",L"SELECT * FROM __EventConsumer",L"SELECT * FROM __FilterToConsumerBinding"}) {
        Com<IEnumWbemClassObject> results;
        Bstr language(L"WQL"),statement(query);
        if (FAILED(service->ExecQuery(language.p,statement.p,WBEM_FLAG_FORWARD_ONLY|WBEM_FLAG_RETURN_IMMEDIATELY,nullptr,&results.p))) return false;
        while (!stop.load() && timer.elapsed()<10000) {
            Com<IWbemClassObject> object; ULONG count=0;
            const HRESULT result=results.p->Next(250,1,&object.p,&count);
            if (result==WBEM_S_FALSE) break;
            if (result==WBEM_S_TIMEDOUT) continue;
            if (FAILED(result)||!count||!object.p) return false;
            if (values.size()>=4096) return false;
            const QString path=property(object.p,L"__RELPATH"),type=property(object.p,L"__CLASS");
            if (path.isEmpty()||path.size()>2048||type.isEmpty()) return false;
            QCryptographicHash hash(QCryptographicHash::Sha256);
            for (const wchar_t* name:{L"Name",L"Query",L"EventNamespace",L"Filter",L"Consumer",L"ExecutablePath",L"CommandLineTemplate",L"ScriptText",L"ScriptingEngine"}) {
                const QByteArray value=property(object.p,name).toUtf8();
                hash.addData(QByteArray::number(value.size())); hash.addData(QByteArrayLiteral(":")); hash.addData(value);
            }
            values.insert(path,{type,QString::fromLatin1(hash.result().toHex())});
        }
        if (stop.load()||timer.elapsed()>=10000) return false;
    }
    return true;
}
}
WmiRepositorySource::WmiRepositorySource(QObject* parent):EventSource(parent) {
    timer_=new QTimer(this); timer_->setInterval(250);
    connect(timer_,&QTimer::timeout,this,[this] {
        if (!state_) return;
        QVector<bulwark::SecurityEvent> events; QString health;
        {std::lock_guard lock(state_->mutex); events.swap(state_->events); health.swap(state_->health);}
        if (!health.isEmpty()) log_.info(health);
        for (const auto& e:events) emit eventProduced(e);
    });
}
WmiRepositorySource::~WmiRepositorySource(){stop();}
bool WmiRepositorySource::isAvailable()const{return state_&&state_->available.load();}
void WmiRepositorySource::start(){
    if(state_)return;
    state_=std::make_shared<Shared>(); thread_=std::thread(&WmiRepositorySource::run,state_); timer_->start();
}
void WmiRepositorySource::stop(){
    timer_->stop(); if(!state_)return;
    state_->stop.store(true);state_->wake.notify_all();
    if(thread_.joinable()){if(state_->finished.load())thread_.join();else thread_.detach();}
    state_.reset();
}
void WmiRepositorySource::run(const std::shared_ptr<Shared>& state){
    const HRESULT initialized=::CoInitializeEx(nullptr,COINIT_MULTITHREADED);
    if(FAILED(initialized)){state->finished=true;return;}
    try {
        Com<IWbemLocator> locator;Com<IWbemServices> service;
        Bstr space(L"ROOT\\subscription");
        const bool connected=SUCCEEDED(::CoCreateInstance(CLSID_WbemLocator,nullptr,CLSCTX_INPROC_SERVER,IID_IWbemLocator,reinterpret_cast<void**>(&locator.p)))
            && SUCCEEDED(locator.p->ConnectServer(space.p,nullptr,nullptr,nullptr,WBEM_FLAG_CONNECT_USE_MAX_WAIT,nullptr,nullptr,&service.p))
            && SUCCEEDED(::CoSetProxyBlanket(service.p,RPC_C_AUTHN_WINNT,RPC_C_AUTHZ_NONE,nullptr,RPC_C_AUTHN_LEVEL_CALL,RPC_C_IMP_LEVEL_IMPERSONATE,nullptr,EOAC_NONE));
        if(connected){
            WmiRepositoryPolicy policy;bool warned=false;
            while(!state->stop.load()){
                QHash<QString,Item> current;
                if(snapshot(service.p,current,state->stop)){
                    std::lock_guard lock(state->mutex);
                    if (state->events.isEmpty()) {
                        auto result=policy.update(current,true);
                        state->available=result.accepted;
                        if (result.baseline) state->health=QStringLiteral("WMI 永久订阅对象基线已建立：%1 个；只读轮询 filter、consumer、binding，不创建永久订阅").arg(current.size());
                        if (result.backlog) state->health=QStringLiteral("WMI 变更批次超过 64 个，剩余变更保留至下轮，不静默丢弃");
                        state->events=std::move(result.events);
                    }
                    warned=false;
                }else if(!state->stop.load()){
                    state->available=false;
                    if(!warned){std::lock_guard lock(state->mutex);state->health=QStringLiteral("WMI 对象快照未完整读取，保留上次基线，未推断删除或变更");warned=true;}
                }
                std::unique_lock lock(state->mutex);
                state->wake.wait_for(lock,std::chrono::seconds(5),[&]{return state->stop.load();});
            }
        }else{std::lock_guard lock(state->mutex);state->health=QStringLiteral("无法只读连接 WMI ROOT/subscription；对象轮询未生效");}
    }
    catch (...) {
        std::lock_guard lock(state->mutex);
        state->health=QStringLiteral("WMI 对象轮询发生异常，已停止该入口，未修改对象或基线");
    }
    ::CoUninitialize();state->available=false;state->finished=true;
}
}
