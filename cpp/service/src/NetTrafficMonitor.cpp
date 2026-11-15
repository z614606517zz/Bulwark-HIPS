#include "bulwark/service/NetTrafficMonitor.h"

#include "bulwark/service/monitoring/ProcessInspector.h"

#include <QDateTime>
#include <QFileInfo>
#include <QMutex>
#include <QMutexLocker>

#include <algorithm>
#include <atomic>
#include <cstdint>
#include <cstring>
#include <iterator>
#include <string>
#include <thread>
#include <utility>
#include <vector>

// winsock2.h 必须在 windows.h 之前包含(或先定义 WIN32_LEAN_AND_MEAN)。
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include <netioapi.h>
#include <krabs.hpp>

namespace bulwark::service {

namespace {

const wchar_t* const kKernelNetworkGuid = L"{7DD42A49-5329-4832-8DFD-43D979153A88}";
constexpr ULONGLONG kKeywordV4V6 = 0x30;
const wchar_t* const kDnsClientGuid = L"{1C95126E-7EEA-49A9-A3FE-A378B03DDB4D}";
constexpr USHORT kDnsQueryCompleted = 3008;
const wchar_t* const kSessionName = L"Bulwark-NetTraffic";

constexpr int kSampleMs = 1000;
constexpr int kMaxRows = 40;
constexpr int kMaxRemotes = 5;
constexpr int kMaxConnsPerPid = 200;
constexpr int kMaxConnStates = 6000;
constexpr qint64 kConnForgetMs = 60 * 1000;
constexpr qint64 kProcForgetMs = 120 * 1000;
constexpr qint64 kProcReverifyMs = 10 * 1000;
constexpr int kDnsMax = 4096;
constexpr qint64 kDnsTtlMs = 30 * 60 * 1000;
constexpr int kLocalAddrRefreshSamples = 10;

struct Endpoint {
    quint8 addr[16];
    quint16 port;
    quint8 v6;
    quint8 pad;
};
static_assert(sizeof(Endpoint) == 20, "Endpoint must have no hidden padding");

struct ConnKey {
    quint32 pid;
    quint8 udp;
    quint8 pad[3];
    Endpoint a;
    Endpoint b;
};
static_assert(sizeof(ConnKey) == 48, "ConnKey must have no hidden padding");

inline bool operator==(const ConnKey& x, const ConnKey& y) { return std::memcmp(&x, &y, sizeof(ConnKey)) == 0; }
inline size_t qHash(const ConnKey& k, size_t seed = 0) { return qHashBits(&k, sizeof(ConnKey), seed); }

inline quint16 swapPort(quint16 p) { return static_cast<quint16>((p << 8) | (p >> 8)); }

Endpoint ep4(quint32 addrNet, quint16 portHost) {
    Endpoint e;
    std::memset(&e, 0, sizeof e);
    std::memcpy(e.addr, &addrNet, 4);
    e.port = portHost;
    return e;
}

Endpoint ep6(const quint8* bytes, quint16 portHost) {
    static const quint8 mapped[12] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff};
    if (std::memcmp(bytes, mapped, 12) == 0) {
        quint32 a = 0;
        std::memcpy(&a, bytes + 12, 4);
        return ep4(a, portHost);
    }
    Endpoint e;
    std::memset(&e, 0, sizeof e);
    std::memcpy(e.addr, bytes, 16);
    e.port = portHost;
    e.v6 = 1;
    return e;
}

ConnKey makeKey(quint32 pid, bool udp, Endpoint x, Endpoint y) {
    ConnKey k;
    std::memset(&k, 0, sizeof k);
    k.pid = pid;
    k.udp = udp ? 1 : 0;
    if (std::memcmp(&x, &y, sizeof(Endpoint)) > 0)
        std::swap(x, y);
    k.a = x;
    k.b = y;
    return k;
}

bool isLoopback(const Endpoint& e) {
    if (!e.v6)
        return e.addr[0] == 127;
    for (int i = 0; i < 15; ++i)
        if (e.addr[i] != 0)
            return false;
    return e.addr[15] == 1;
}

bool isUnspecified(const Endpoint& e) {
    for (int i = 0; i < (e.v6 ? 16 : 4); ++i)
        if (e.addr[i] != 0)
            return false;
    return true;
}

bool isLan(const Endpoint& e) {
    const quint8* a = e.addr;
    if (!e.v6) {
        return a[0] == 10 || (a[0] == 172 && (a[1] & 0xF0) == 16) || (a[0] == 192 && a[1] == 168)
               || (a[0] == 169 && a[1] == 254) || (a[0] == 100 && (a[1] & 0xC0) == 64) || a[0] >= 224
               || a[0] == 0;
    }
    return (a[0] & 0xFE) == 0xFC
           || (a[0] == 0xFE && (a[1] & 0xC0) == 0x80)
           || a[0] == 0xFF;
}

QString ipText(const Endpoint& e) {
    if (!e.v6)
        return QStringLiteral("%1.%2.%3.%4").arg(e.addr[0]).arg(e.addr[1]).arg(e.addr[2]).arg(e.addr[3]);
    wchar_t buf[64] = {};
    IN6_ADDR addr;
    std::memcpy(&addr, e.addr, 16);
    if (!InetNtopW(AF_INET6, &addr, buf, 64))
        return QString();
    return QString::fromWCharArray(buf);
}

quint64 createTimeOf(quint32 pid) {
    HANDLE h = ::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!h)
        return 0;
    FILETIME c{}, e{}, k{}, u{};
    quint64 t = 0;
    if (::GetProcessTimes(h, &c, &e, &k, &u))
        t = (static_cast<quint64>(c.dwHighDateTime) << 32) | c.dwLowDateTime;
    ::CloseHandle(h);
    return t;
}

struct IfCounters {
    quint64 luid = 0;
    quint64 in = 0;
    quint64 out = 0;
};

std::vector<IfCounters> readInterfaces() {
    std::vector<IfCounters> hw, all;
    PMIB_IF_TABLE2 table = nullptr;
    if (::GetIfTable2(&table) != NO_ERROR || !table)
        return hw;
    for (ULONG i = 0; i < table->NumEntries; ++i) {
        const MIB_IF_ROW2& r = table->Table[i];
        if (r.Type == IF_TYPE_SOFTWARE_LOOPBACK || r.OperStatus != IfOperStatusUp)
            continue;
        IfCounters c;
        c.luid = r.InterfaceLuid.Value;
        c.in = r.InOctets;
        c.out = r.OutOctets;
        all.push_back(c);
        if (r.InterfaceAndOperStatusFlags.HardwareInterface)
            hw.push_back(c);
    }
    ::FreeMibTable(table);
    return hw.empty() ? all : hw;
}

QSet<QString> readLocalAddresses() {
    QSet<QString> out;
    PMIB_UNICASTIPADDRESS_TABLE t = nullptr;
    if (::GetUnicastIpAddressTable(AF_UNSPEC, &t) != NO_ERROR || !t)
        return out;
    for (ULONG i = 0; i < t->NumEntries; ++i) {
        const SOCKADDR_INET& a = t->Table[i].Address;
        if (a.si_family == AF_INET)
            out.insert(ipText(ep4(a.Ipv4.sin_addr.S_un.S_addr, 0)));
        else if (a.si_family == AF_INET6)
            out.insert(ipText(ep6(a.Ipv6.sin6_addr.u.Byte, 0)));
    }
    ::FreeMibTable(t);
    return out;
}

struct TcpRow {
    quint32 pid = 0;
    Endpoint local;
    Endpoint remote;
    bool listen = false;
    bool established = false;
};

template <class Row, class Fn>
void readTcpTable(ULONG af, Fn&& each) {
    ULONG size = 0;
    std::vector<BYTE> buf;
    for (int attempt = 0; attempt < 3; ++attempt) {
        buf.resize(size ? size + 16384 : 0);
        if (!buf.empty())
            size = static_cast<ULONG>(buf.size());
        const DWORD rc = ::GetExtendedTcpTable(buf.empty() ? nullptr : buf.data(), &size, FALSE, af,
                                               TCP_TABLE_OWNER_PID_ALL, 0);
        if (rc == NO_ERROR) {
            const DWORD n = *reinterpret_cast<const DWORD*>(buf.data());
            const Row* rows = reinterpret_cast<const Row*>(buf.data() + sizeof(DWORD));
            for (DWORD i = 0; i < n; ++i)
                each(rows[i]);
            return;
        }
        if (rc != ERROR_INSUFFICIENT_BUFFER)
            return;
    }
}

std::vector<TcpRow> readTcp() {
    std::vector<TcpRow> out;
    readTcpTable<MIB_TCPROW_OWNER_PID>(AF_INET, [&](const MIB_TCPROW_OWNER_PID& r) {
        if (r.dwState != MIB_TCP_STATE_ESTAB && r.dwState != MIB_TCP_STATE_LISTEN)
            return;
        TcpRow t;
        t.pid = r.dwOwningPid;
        t.local = ep4(r.dwLocalAddr, swapPort(static_cast<quint16>(r.dwLocalPort)));
        t.remote = ep4(r.dwRemoteAddr, swapPort(static_cast<quint16>(r.dwRemotePort)));
        t.listen = r.dwState == MIB_TCP_STATE_LISTEN;
        t.established = !t.listen;
        out.push_back(t);
    });
    readTcpTable<MIB_TCP6ROW_OWNER_PID>(AF_INET6, [&](const MIB_TCP6ROW_OWNER_PID& r) {
        if (r.dwState != MIB_TCP_STATE_ESTAB && r.dwState != MIB_TCP_STATE_LISTEN)
            return;
        TcpRow t;
        t.pid = r.dwOwningPid;
        t.local = ep6(r.ucLocalAddr, swapPort(static_cast<quint16>(r.dwLocalPort)));
        t.remote = ep6(r.ucRemoteAddr, swapPort(static_cast<quint16>(r.dwRemotePort)));
        t.listen = r.dwState == MIB_TCP_STATE_LISTEN;
        t.established = !t.listen;
        out.push_back(t);
    });
    return out;
}

// DNS 应答串里的一个片段 -> 地址;不是地址(「type: 5 xxx」之类的别名记录)返回 false。
bool parseDnsAddress(QString token, Endpoint* out) {
    token = token.trimmed();
    if (token.isEmpty() || token.startsWith(QLatin1String("type:"), Qt::CaseInsensitive))
        return false;
    const std::wstring w = token.toStdWString();
    IN_ADDR a4{};
    if (InetPtonW(AF_INET, w.c_str(), &a4) == 1) {
        *out = ep4(a4.S_un.S_addr, 0);
        return true;
    }
    IN6_ADDR a6{};
    if (InetPtonW(AF_INET6, w.c_str(), &a6) == 1) {
        *out = ep6(a6.u.Byte, 0);
        return true;
    }
    return false;
}

}

struct NetTrafficMonitor::Impl {
    // provider 必须比 trace 活得久:trace 按引用持有 provider。
    std::unique_ptr<krabs::user_trace> trace;
    std::unique_ptr<krabs::provider<>> provider;
    std::unique_ptr<krabs::provider<>> dnsProvider;
    std::thread worker;
    std::atomic<bool> running{false};

    struct Bytes {
        quint64 up = 0;
        quint64 down = 0;
    };

    QMutex mx;
    QHash<ConnKey, Bytes> counters;
    std::atomic<quint64> seen{0};
    std::atomic<quint64> counted{0};
    std::atomic<quint64> loopback{0};
    std::atomic<quint64> unparsed{0};
    std::atomic<quint64> dnsAnswers{0};

    std::atomic<bool> parseFailed{false};
    QString parseDiag;
    bool diagLogged = false;

    struct DnsEntry {
        QString name;
        qint64 atMs = 0;
    };
    QMutex dnsMx;
    QHash<QString, DnsEntry> dns;

    struct ConnState {
        quint32 pid = 0;
        bool udp = false;
        Endpoint remote{};
        Endpoint local{};
        QString scope;
        quint32 proxyPid = 0;
        qint64 firstSeenMs = 0;
        qint64 lastActiveMs = 0;
        quint64 upTotal = 0;
        quint64 downTotal = 0;
        qint64 upBps = 0;
        qint64 downBps = 0;
        bool established = false;
    };
    QHash<ConnKey, ConnState> conns;
    QSet<QString> localAddrs;

    quint32 selfPid = 0;
    Logger log{QStringLiteral("bulwark.service.NetTraffic")};

    void noteParseFailure(USHORT id, const krabs::parser& parser) {
        unparsed.fetch_add(1, std::memory_order_relaxed);
        if (parseFailed.exchange(true))
            return;
        QString names;
        try {
            for (const krabs::property& p : parser.properties())
                names += QStringLiteral("%1(in=%2,out=%3) ")
                             .arg(QString::fromStdWString(p.name()))
                             .arg(static_cast<int>(p.type()))
                             .arg(static_cast<int>(p.out_type()));
        } catch (...) {
        }
        QMutexLocker lk(&mx);
        parseDiag = QStringLiteral("Kernel-Network 事件 ID %1 的字段与预期(PID / size / daddr / saddr / dport / sport)对不上,实际属性:%2")
                        .arg(id)
                        .arg(names.isEmpty() ? QStringLiteral("(读不到)") : names.trimmed());
    }

    // 在 ETW 消费线程上运行,必须快且不抛异常。
    void onEvent(const EVENT_RECORD& record, const krabs::trace_context& ctx) {
        const USHORT id = record.EventHeader.EventDescriptor.Id;
        bool up = false, v6 = false, udp = false;
        switch (id) {
        case 10: up = true;  v6 = false; udp = false; break;
        case 11: up = false; v6 = false; udp = false; break;
        case 26: up = true;  v6 = true;  udp = false; break;
        case 27: up = false; v6 = true;  udp = false; break;
        case 42: up = true;  v6 = false; udp = true;  break;
        case 43: up = false; v6 = false; udp = true;  break;
        case 58: up = true;  v6 = true;  udp = true;  break;
        case 59: up = false; v6 = true;  udp = true;  break;
        default: return;                                       // 连接 / 断开 / 重传 / TCPCopy:不要
        }
        seen.fetch_add(1, std::memory_order_relaxed);
        krabs::schema schema(record, ctx.schema_locator);
        krabs::parser parser(schema);
        uint32_t pid = 0, size = 0;
        if (!parser.try_parse(L"PID", pid) || !parser.try_parse(L"size", size)) {
            noteParseFailure(id, parser);
            return;
        }
        if (pid == 0 || pid == selfPid || size == 0)
            return;
        uint16_t dport = 0, sport = 0;
        parser.try_parse(L"dport", dport);
        parser.try_parse(L"sport", sport);
        Endpoint d{}, s{};
        if (!v6) {
            uint32_t daddr = 0, saddr = 0;
            if (!parser.try_parse(L"daddr", daddr) || !parser.try_parse(L"saddr", saddr)) {
                noteParseFailure(id, parser);
                return;
            }
            d = ep4(daddr, swapPort(dport));
            s = ep4(saddr, swapPort(sport));
        } else {
            krabs::binary da, sa;
            const bool haveD = parser.try_parse(L"daddr", da) && da.bytes().size() == 16;
            const bool haveS = parser.try_parse(L"saddr", sa) && sa.bytes().size() == 16;
            if (!haveD || !haveS) {
                noteParseFailure(id, parser);
                return;
            }
            d = ep6(da.bytes().data(), swapPort(dport));
            s = ep6(sa.bytes().data(), swapPort(sport));
        }
        if (isLoopback(d) && isLoopback(s))
            loopback.fetch_add(1, std::memory_order_relaxed);
        counted.fetch_add(1, std::memory_order_relaxed);
        const ConnKey key = makeKey(pid, udp, d, s);
        QMutexLocker lk(&mx);
        Bytes& b = counters[key];
        (up ? b.up : b.down) += size;
    }

    void onDnsEvent(const EVENT_RECORD& record, const krabs::trace_context& ctx) {
        if (record.EventHeader.EventDescriptor.Id != kDnsQueryCompleted)
            return;
        krabs::schema schema(record, ctx.schema_locator);
        krabs::parser parser(schema);
        std::wstring name, results;
        uint32_t status = 1;
        if (!parser.try_parse(L"QueryName", name) || !parser.try_parse(L"QueryResults", results))
            return;
        parser.try_parse(L"QueryStatus", status);
        if (status != 0 || name.empty() || results.empty())
            return;
        const QString qname = QString::fromStdWString(name).trimmed().toLower();
        if (qname.isEmpty() || qname.size() > 253)
            return;
        const QStringList parts = QString::fromStdWString(results).split(QLatin1Char(';'), Qt::SkipEmptyParts);
        const qint64 now = static_cast<qint64>(::GetTickCount64());
        QMutexLocker lk(&dnsMx);
        for (const QString& part : parts) {
            Endpoint e{};
            if (!parseDnsAddress(part, &e) || isUnspecified(e) || isLoopback(e))
                continue;
            if (dns.size() >= kDnsMax && !dns.contains(ipText(e))) {
                for (auto it = dns.begin(); it != dns.end();)
                    it = (now - it->atMs > kDnsTtlMs) ? dns.erase(it) : std::next(it);
                if (dns.size() >= kDnsMax)
                    dns.clear();
            }
            dns.insert(ipText(e), DnsEntry{qname, now});
            dnsAnswers.fetch_add(1, std::memory_order_relaxed);
        }
    }
};

NetTrafficMonitor::NetTrafficMonitor(QObject* parent) : QObject(parent), d_(std::make_unique<Impl>()) {
    d_->selfPid = static_cast<quint32>(::GetCurrentProcessId());
}

NetTrafficMonitor::~NetTrafficMonitor() { stop(); }

bool NetTrafficMonitor::start() {
    if (timer_)
        return true;

    prevIf_.clear();
    for (const IfCounters& c : readInterfaces())
        prevIf_.insert(c.luid, qMakePair(c.in, c.out));
    sessionUp_ = sessionDown_ = 0;
    samples_ = 0;
    procs_.clear();
    d_->counters.clear();
    d_->conns.clear();
    d_->localAddrs = readLocalAddresses();
    {
        QMutexLocker lk(&d_->dnsMx);
        d_->dns.clear();
    }
    d_->seen = d_->counted = d_->loopback = d_->unparsed = d_->dnsAnswers = 0;
    d_->parseFailed = false;
    d_->parseDiag.clear();
    d_->diagLogged = false;
    lastSampleMs_ = static_cast<qint64>(::GetTickCount64());

    etwOk_ = false;
    etwError_.clear();
    try {
        d_->trace = std::make_unique<krabs::user_trace>(std::wstring(kSessionName));
        EVENT_TRACE_PROPERTIES props{};
        props.BufferSize = 64;
        props.MinimumBuffers = 8;
        props.MaximumBuffers = 32;
        props.FlushTimer = 1;
        props.LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
        d_->trace->set_trace_properties(&props);

        Impl* impl = d_.get();
        d_->provider = std::make_unique<krabs::provider<>>(krabs::guid(kKernelNetworkGuid));
        d_->provider->any(kKeywordV4V6);
        d_->provider->add_on_event_callback(
            [impl](const EVENT_RECORD& record, const krabs::trace_context& ctx) {
                try {
                    impl->onEvent(record, ctx);
                } catch (...) {
                }
            });
        d_->trace->enable(*d_->provider);

        try {
            d_->dnsProvider = std::make_unique<krabs::provider<>>(krabs::guid(kDnsClientGuid));
            d_->dnsProvider->add_on_event_callback(
                [impl](const EVENT_RECORD& record, const krabs::trace_context& ctx) {
                    try {
                        impl->onDnsEvent(record, ctx);
                    } catch (...) {
                    }
                });
            d_->trace->enable(*d_->dnsProvider);
        } catch (const std::exception& ex) {
            log_.warning(QStringLiteral("流量会话里的 DNS-Client 没启用,连接详情里不会有域名:%1").arg(QString::fromUtf8(ex.what())));
        }

        d_->trace->open();

        d_->running.store(true);
        d_->worker = std::thread([impl] {
            try {
                impl->trace->process();
            } catch (const std::exception& ex) {
                impl->log.warning(QStringLiteral("流量 ETW 处理线程结束:%1").arg(QString::fromUtf8(ex.what())));
            }
            impl->running.store(false);
        });
        etwOk_ = true;
    } catch (const std::exception& ex) {
        etwError_ = QString::fromUtf8(ex.what());
        d_->dnsProvider.reset();
        d_->provider.reset();
        d_->trace.reset();
        log_.warning(QStringLiteral("流量 ETW 会话没起来,降级为只显示连接与总速率:%1").arg(etwError_));
    }

    timer_ = new QTimer(this);
    timer_->setInterval(kSampleMs);
    connect(timer_, &QTimer::timeout, this, &NetTrafficMonitor::sample);
    timer_->start();
    if (etwOk_)
        log_.info(QStringLiteral("实时流量采样已启动(ETW 会话 Bulwark-NetTraffic:TCP/UDP × IPv4/IPv6 + DNS 应答;"
                                 "环回只认「连本机代理」的那部分)。"));
    else
        log_.info(QStringLiteral("实时流量采样已启动(降级:无逐进程速率)。"));
    return true;
}

void NetTrafficMonitor::stop() {
    if (!timer_)
        return;
    timer_->stop();
    timer_->deleteLater();
    timer_ = nullptr;
    const bool wasRunning = d_->running.exchange(false);
    if (d_->trace) {
        if (wasRunning) {
            try {
                const krabs::trace_stats st = d_->trace->query_stats();
                log_.info(QStringLiteral("实时流量采样停止:会话共处理 %1 条事件,丢失 %2 条;数据事件 %3 条,计入 %4"
                                         "(其中两端都是环回 %5),字段对不上 %6;DNS 应答地址 %7 条。")
                              .arg(static_cast<qulonglong>(st.eventsHandled))
                              .arg(st.eventsLost)
                              .arg(static_cast<qulonglong>(d_->seen.load()))
                              .arg(static_cast<qulonglong>(d_->counted.load()))
                              .arg(static_cast<qulonglong>(d_->loopback.load()))
                              .arg(static_cast<qulonglong>(d_->unparsed.load()))
                              .arg(static_cast<qulonglong>(d_->dnsAnswers.load())));
            } catch (...) {}
        }
        try { d_->trace->stop(); } catch (...) {}
    }
    if (d_->worker.joinable())
        d_->worker.join();
    d_->dnsProvider.reset();
    d_->provider.reset();
    d_->trace.reset();
    etwOk_ = false;
    procs_.clear();
    prevIf_.clear();
    d_->conns.clear();
}

NetTrafficMonitor::ProcInfo& NetTrafficMonitor::procOf(quint32 pid, qint64 nowMs) {
    auto it = procs_.find(pid);
    bool resolve = (it == procs_.end());
    if (!resolve && nowMs - it->verifiedMs > kProcReverifyMs) {
        const quint64 ct = createTimeOf(pid);
        if (ct != 0 && it->createTime != 0 && ct != it->createTime)
            resolve = true;
        else
            it->verifiedMs = nowMs;
    }
    if (resolve) {
        ProcInfo pi;
        pi.createTime = createTimeOf(pid);
        pi.path = monitoring::ProcessInspector::tryGetProcessImagePath(static_cast<int>(pid));
        if (!pi.path.isEmpty())
            pi.name = QFileInfo(pi.path).fileName();
        else
            pi.name = pid == 4 ? QStringLiteral("System") : QStringLiteral("PID %1").arg(pid);
        pi.critical = monitoring::ProcessInspector::isCriticalProcess(static_cast<int>(pid));
        pi.self = selfProbe_ ? selfProbe_(static_cast<int>(pid), pi.path) : false;
        pi.verifiedMs = nowMs;
        procs_.insert(pid, pi);
        it = procs_.find(pid);
    }
    it->lastSeenMs = nowMs;
    return it.value();
}

void NetTrafficMonitor::sample() {
    if (etwOk_ && !d_->running.load(std::memory_order_relaxed)) {
        log_.warning(QStringLiteral("流量 ETW worker 已意外结束,状态已降级并立即重建会话。"));
        stop();
        start();
        return;
    }
    const qint64 nowMs = static_cast<qint64>(::GetTickCount64());
    const double dt = std::clamp<double>((nowMs - lastSampleMs_) / 1000.0, 0.25, 10.0);
    lastSampleMs_ = nowMs;
    ++samples_;
    if (samples_ % kLocalAddrRefreshSamples == 0)
        d_->localAddrs = readLocalAddresses();

    ipc::NetTrafficSnapshotPayload snap;
    snap.atUtc = QDateTime::currentDateTimeUtc();

    {
        quint64 dIn = 0, dOut = 0;
        QHash<quint64, QPair<quint64, quint64>> cur;
        for (const IfCounters& c : readInterfaces()) {
            cur.insert(c.luid, qMakePair(c.in, c.out));
            const auto prev = prevIf_.constFind(c.luid);
            if (prev == prevIf_.constEnd())
                continue;
            if (c.in >= prev->first)
                dIn += c.in - prev->first;
            if (c.out >= prev->second)
                dOut += c.out - prev->second;
        }
        prevIf_ = cur;
        sessionDown_ += dIn;
        sessionUp_ += dOut;
        snap.totalDownBps = static_cast<qint64>(dIn / dt);
        snap.totalUpBps = static_cast<qint64>(dOut / dt);
        snap.sessionDownBytes = static_cast<qint64>(sessionDown_);
        snap.sessionUpBytes = static_cast<qint64>(sessionUp_);
    }

    QHash<ConnKey, Impl::Bytes> counters;
    {
        QMutexLocker lk(&d_->mx);
        counters.swap(d_->counters);
    }
    const std::vector<TcpRow> tcp = readTcp();
    QHash<QString, QString> dnsNames;
    {
        QMutexLocker lk(&d_->dnsMx);
        dnsNames.reserve(d_->dns.size());
        for (auto it = d_->dns.constBegin(); it != d_->dns.constEnd(); ++it)
            if (nowMs - it->atMs <= kDnsTtlMs)
                dnsNames.insert(it.key(), it->name);
    }

    QHash<quint16, quint32> listeners;
    QSet<quint32> egressPids;
    QHash<ConnKey, bool> established;
    for (const TcpRow& t : tcp) {
        if (t.listen) {
            if (isLoopback(t.local) || isUnspecified(t.local))
                listeners.insert(t.local.port, t.pid);
            continue;
        }
        if (t.pid == 0 || t.pid == d_->selfPid)
            continue;
        established.insert(makeKey(t.pid, false, t.local, t.remote), true);
        if (!isLoopback(t.remote) && !isUnspecified(t.remote))
            egressPids.insert(t.pid);
    }
    for (auto it = counters.constBegin(); it != counters.constEnd(); ++it)
        if (!(isLoopback(it.key().a) && isLoopback(it.key().b)))
            egressPids.insert(it.key().pid);

    QSet<ConnKey> keys;
    keys.reserve(counters.size() + established.size());
    for (auto it = counters.constBegin(); it != counters.constEnd(); ++it)
        keys.insert(it.key());
    for (auto it = established.constBegin(); it != established.constEnd(); ++it)
        keys.insert(it.key());

    struct PidAgg {
        quint64 up = 0, down = 0;
        quint64 proxyUp = 0, proxyDown = 0;
        int conns = 0;
        int proxyConns = 0;
        quint32 proxyPid = 0;
        bool any = false;
    };
    QHash<quint32, PidAgg> agg;

    for (const ConnKey& key : std::as_const(keys)) {
        if (key.pid == 0 || key.pid == d_->selfPid)
            continue;
        const Impl::Bytes bytes = counters.value(key);
        const bool isEstab = established.contains(key);

        Endpoint remote{}, local{};
        QString scope;
        quint32 proxyPid = 0;
        if (isLoopback(key.a) && isLoopback(key.b)) {
            if (key.udp)
                continue;
            const quint32 la = listeners.value(key.a.port, 0);
            const quint32 lb = listeners.value(key.b.port, 0);
            if (la != 0 && la != key.pid) {
                remote = key.a; local = key.b; proxyPid = la;
            } else if (lb != 0 && lb != key.pid) {
                remote = key.b; local = key.a; proxyPid = lb;
            } else {
                continue;
            }
            if (!egressPids.contains(proxyPid))
                continue;
            scope = QStringLiteral("proxy");
        } else {
            const bool aLocal = d_->localAddrs.contains(ipText(key.a)) || isLoopback(key.a);
            const bool bLocal = d_->localAddrs.contains(ipText(key.b)) || isLoopback(key.b);
            if (aLocal && !bLocal) {
                remote = key.b; local = key.a;
            } else if (bLocal && !aLocal) {
                remote = key.a; local = key.b;
            } else if (key.a.port <= key.b.port) {
                remote = key.a; local = key.b;
            } else {
                remote = key.b; local = key.a;
            }
            if (isUnspecified(remote))
                continue;
            scope = isLan(remote) ? QStringLiteral("lan") : QStringLiteral("public");
        }

        Impl::ConnState& st = d_->conns[key];
        if (st.firstSeenMs == 0) {
            st.pid = key.pid;
            st.udp = key.udp != 0;
            st.firstSeenMs = nowMs;
        }
        st.remote = remote;
        st.local = local;
        st.scope = scope;
        st.proxyPid = proxyPid;
        st.established = isEstab;
        st.upTotal += bytes.up;
        st.downTotal += bytes.down;
        st.upBps = static_cast<qint64>(bytes.up / dt);
        st.downBps = static_cast<qint64>(bytes.down / dt);
        if (bytes.up + bytes.down > 0)
            st.lastActiveMs = nowMs;

        PidAgg& g = agg[key.pid];
        g.any = true;
        if (proxyPid != 0) {
            g.proxyUp += bytes.up;
            g.proxyDown += bytes.down;
            if (isEstab)
                ++g.proxyConns;
            g.proxyPid = proxyPid;
        } else {
            g.up += bytes.up;
            g.down += bytes.down;
            if (isEstab && !key.udp)
                ++g.conns;
        }
    }

    for (auto it = d_->conns.begin(); it != d_->conns.end();) {
        if (!keys.contains(it.key())) {
            it->upBps = it->downBps = 0;
            it->established = false;
            const qint64 last = it->lastActiveMs ? it->lastActiveMs : it->firstSeenMs;
            if (nowMs - last > kConnForgetMs) {
                it = d_->conns.erase(it);
                continue;
            }
        }
        ++it;
    }
    if (d_->conns.size() > kMaxConnStates) {
        std::vector<std::pair<qint64, ConnKey>> idle;
        for (auto it = d_->conns.constBegin(); it != d_->conns.constEnd(); ++it)
            if (!it->established)
                idle.emplace_back(it->lastActiveMs ? it->lastActiveMs : it->firstSeenMs, it.key());
        std::sort(idle.begin(), idle.end(), [](const auto& x, const auto& y) { return x.first < y.first; });
        const size_t excess = static_cast<size_t>(d_->conns.size() - kMaxConnStates * 5 / 6);
        for (size_t i = 0; i < idle.size() && i < excess; ++i)
            d_->conns.remove(idle[i].second);
    }

    ConnMap details;
    {
        QHash<quint32, QList<const Impl::ConnState*>> byPid;
        for (auto it = d_->conns.constBegin(); it != d_->conns.constEnd(); ++it)
            byPid[it->pid].append(&it.value());
        for (auto it = byPid.begin(); it != byPid.end(); ++it) {
            QList<const Impl::ConnState*>& list = it.value();
            std::sort(list.begin(), list.end(), [](const Impl::ConnState* x, const Impl::ConnState* y) {
                const quint64 tx = x->upTotal + x->downTotal, ty = y->upTotal + y->downTotal;
                if (tx != ty) return tx > ty;
                if (x->established != y->established) return x->established;
                return x->firstSeenMs < y->firstSeenMs;
            });
            QList<ipc::NetTrafficConnPayload> out;
            out.reserve(std::min<qsizetype>(list.size(), kMaxConnsPerPid));
            for (const Impl::ConnState* st : std::as_const(list)) {
                if (out.size() >= kMaxConnsPerPid)
                    break;
                ipc::NetTrafficConnPayload c;
                c.proto = st->udp ? QStringLiteral("UDP") : QStringLiteral("TCP");
                c.remoteIp = ipText(st->remote);
                c.remotePort = st->remote.port;
                c.localPort = st->local.port;
                c.scope = st->scope;
                if (st->proxyPid != 0)
                    c.proxyName = procOf(st->proxyPid, nowMs).name;
                else
                    c.domain = dnsNames.value(c.remoteIp);
                c.upBps = st->upBps;
                c.downBps = st->downBps;
                c.upTotal = static_cast<qint64>(st->upTotal);
                c.downTotal = static_cast<qint64>(st->downTotal);
                c.ageSecs = (nowMs - st->firstSeenMs) / 1000;
                c.idleSecs = st->lastActiveMs ? (nowMs - st->lastActiveMs) / 1000 : -1;
                c.established = st->established;
                out << c;
            }
            details.insert(static_cast<int>(it.key()), out);
        }
    }

    QList<ipc::NetTrafficRowPayload> rows;
    rows.reserve(agg.size());
    for (auto it = agg.constBegin(); it != agg.constEnd(); ++it) {
        const quint32 pid = it.key();
        const PidAgg& g = it.value();
        ProcInfo& pi = procOf(pid, nowMs);
        pi.upTotal += g.up;
        pi.downTotal += g.down;

        ipc::NetTrafficRowPayload r;
        r.pid = static_cast<int>(pid);
        r.name = pi.name;
        r.path = pi.path;
        r.upBps = static_cast<qint64>(g.up / dt);
        r.downBps = static_cast<qint64>(g.down / dt);
        r.upTotal = static_cast<qint64>(pi.upTotal);
        r.downTotal = static_cast<qint64>(pi.downTotal);
        r.tcpConns = g.conns;
        r.critical = pi.critical;
        r.protectedSelf = pi.self;
        if (g.proxyPid != 0) {
            r.proxyName = procOf(g.proxyPid, nowMs).name;
            r.proxyConns = g.proxyConns;
            r.proxyUpBps = static_cast<qint64>(g.proxyUp / dt);
            r.proxyDownBps = static_cast<qint64>(g.proxyDown / dt);
        }
        for (const ipc::NetTrafficConnPayload& c : details.value(r.pid)) {
            if (r.remotes.size() >= kMaxRemotes)
                break;
            if (c.scope == QLatin1String("proxy"))
                continue;
            const QString ep = c.remoteIp.contains(QLatin1Char(':'))
                                   ? QStringLiteral("[%1]:%2").arg(c.remoteIp).arg(c.remotePort)
                                   : QStringLiteral("%1:%2").arg(c.remoteIp).arg(c.remotePort);
            const QString text = c.domain.isEmpty() ? ep : QStringLiteral("%1 (%2)").arg(c.domain, ep);
            if (!r.remotes.contains(text))
                r.remotes << text;
        }
        if (r.remotes.isEmpty() && !r.proxyName.isEmpty())
            r.remotes << QStringLiteral("经本机代理 %1").arg(r.proxyName);
        rows << r;
    }

    std::sort(rows.begin(), rows.end(),
              [](const ipc::NetTrafficRowPayload& a, const ipc::NetTrafficRowPayload& b) {
                  const qint64 ra = a.upBps + a.downBps + a.proxyUpBps + a.proxyDownBps;
                  const qint64 rb = b.upBps + b.downBps + b.proxyUpBps + b.proxyDownBps;
                  if (ra != rb) return ra > rb;
                  const int ca = a.tcpConns + a.proxyConns, cb = b.tcpConns + b.proxyConns;
                  if (ca != cb) return ca > cb;
                  const int cmp = QString::compare(a.name, b.name, Qt::CaseInsensitive);
                  return cmp != 0 ? cmp < 0 : a.pid < b.pid;
              });
    if (rows.size() > kMaxRows)
        rows.erase(rows.begin() + kMaxRows, rows.end());
    snap.rows = rows;

    for (auto it = procs_.begin(); it != procs_.end();) {
        if (nowMs - it->lastSeenMs > kProcForgetMs)
            it = procs_.erase(it);
        else
            ++it;
    }

    snap.perProcessAvailable = etwOk_;
    if (!etwOk_)
        snap.message = etwError_.isEmpty()
                           ? QStringLiteral("逐进程速率不可用:流量 ETW 会话没有运行。")
                           : QStringLiteral("逐进程速率不可用:%1").arg(etwError_);

    if (etwOk_ && samples_ == 8 && d_->seen.load() == 0 && sessionDown_ + sessionUp_ > 200 * 1024) {
        log_.warning(QStringLiteral("流量 ETW 会话已运行 8 秒,网卡累计有 %1 KB 流量,却没收到任何 Kernel-Network 数据事件 "
                                    "—— 逐进程速率将一直是 0。请检查是否有其它程序占用了同名会话或禁用了该提供程序。")
                         .arg((sessionDown_ + sessionUp_) / 1024));
    }
    if (etwOk_ && samples_ == 20) {
        log_.info(QStringLiteral("流量采样 20 秒自检:数据事件 %1 条(两端都是环回 %2),DNS 应答地址 %3 条,"
                                 "当前跟踪连接 %4 条,本机监听端口 %5 个。")
                      .arg(static_cast<qulonglong>(d_->seen.load()))
                      .arg(static_cast<qulonglong>(d_->loopback.load()))
                      .arg(static_cast<qulonglong>(d_->dnsAnswers.load()))
                      .arg(d_->conns.size())
                      .arg(listeners.size()));
    }
    if (d_->parseFailed.load() && !d_->diagLogged) {
        QString diag;
        {
            QMutexLocker lk(&d_->mx);
            diag = d_->parseDiag;
        }
        if (!diag.isEmpty()) {
            d_->diagLogged = true;
            log_.warning(diag);
        }
    }

    emit snapshotReady(snap, details);
}

}
