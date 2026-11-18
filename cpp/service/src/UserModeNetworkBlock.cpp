#include "bulwark/service/UserModeNetworkBlock.h"
#include "bulwark/service/IpBlockPolicy.h"

#include <QDateTime>
#include <algorithm>
#include <QDir>
#include <QFile>
#include <QMutexLocker>

// winsock2 必须在 windows.h 之前,否则 windows.h 会拉进旧的 winsock.h 造成重定义。
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <fwpmu.h>

namespace bulwark::service {

namespace {

QString nowIso() {
    return QDateTime::currentDateTimeUtc().toString(Qt::ISODateWithMs);
}


}

UserModeNetworkBlock::UserModeNetworkBlock(int maxEntries)
    : maxEntries_(maxEntries > 0 ? maxEntries : 256) {}

UserModeNetworkBlock::~UserModeNetworkBlock() {
    QMutexLocker lock(&mx_);
    if (engine_) {
        ::FwpmEngineClose0(engine_);
        engine_ = nullptr;
    }
}

void UserModeNetworkBlock::removeLegacyManifest() const {
    const QString p = QDir(programDataDir()).filePath(QStringLiteral("usermode_netblock.json"));
    if (!QFile::exists(p))
        return;
    if (QFile::remove(p)) {
        log_.info(QStringLiteral("已删除早期版本遗留的用户态网络封禁清单(%1)——"
                                 "本功能改为纯会话内生效,出站黑名单以 appsettings 的 "
                                 "BlockedRemoteEndpoints 为唯一权威。")
                      .arg(p));
    } else {
        log_.warning(QStringLiteral("早期版本遗留的用户态网络封禁清单删不掉(%1);它已不再被读取,"
                                    "留在盘上只会误导排查,建议手工删除。")
                         .arg(p));
    }
}

QString UserModeNetworkBlock::keyOf(const QString& ip, quint16 port) {
    auto endpoint = bulwark::engine::NetworkEndpoint::parse(ip);
    if (!endpoint) return {};
    if (port) endpoint->port = port;
    return endpoint->text();
}

bool UserModeNetworkBlock::isOpen() const {
    QMutexLocker lock(&mx_);
    return engine_ != nullptr;
}

bool UserModeNetworkBlock::open() {
    QMutexLocker lock(&mx_);
    if (engine_)
        return true;

    FWPM_SESSION0 session{};
    session.flags = FWPM_SESSION_FLAG_DYNAMIC;

    HANDLE h = nullptr;
    const DWORD rc = ::FwpmEngineOpen0(nullptr, RPC_C_AUTHN_WINNT, nullptr, &session, &h);
    if (rc != ERROR_SUCCESS) {
        log_.error(QStringLiteral("用户态网络封禁不可用:打开 WFP 引擎失败(rc=%1)。"
                                 "此后所有出站封禁请求都将如实返回失败,不会假装已拦截。")
                       .arg(rc));
        return false;
    }
    engine_ = h;
    log_.info(QStringLiteral("用户态网络封禁已就绪(WFP 动态会话;过滤器随本进程退出自动清除,"
                             "每次启动按当前配置重建)。"));
    removeLegacyManifest();
    return true;
}

bool UserModeNetworkBlock::addFilterLocked(Entry& e) {
    if (!engine_)
        return false;

    const auto endpoint = bulwark::engine::NetworkEndpoint::parse(e.ip);
    if (!endpoint) return false;
    const bool ipv6 = endpoint->address.protocol() == QAbstractSocket::IPv6Protocol;
    FWP_V6_ADDR_AND_MASK v6{};
    if (ipv6) {
        const auto bytes = endpoint->address.toIPv6Address();
        std::copy(bytes.c, bytes.c + 16, v6.addr);
        v6.prefixLength = 128;
    }

    FWPM_FILTER_CONDITION0 conds[2]{};
    UINT32 nConds = 0;

    conds[nConds].fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS;
    conds[nConds].matchType = FWP_MATCH_EQUAL;
    if (ipv6) {
        conds[nConds].conditionValue.type = FWP_V6_ADDR_MASK;
        conds[nConds].conditionValue.v6AddrMask = &v6;
    } else {
        conds[nConds].conditionValue.type = FWP_UINT32;
        conds[nConds].conditionValue.uint32 = endpoint->address.toIPv4Address();
    }
    ++nConds;

    if (e.port > 0) {
        conds[nConds].fieldKey = FWPM_CONDITION_IP_REMOTE_PORT;
        conds[nConds].matchType = FWP_MATCH_EQUAL;
        conds[nConds].conditionValue.type = FWP_UINT16;
        conds[nConds].conditionValue.uint16 = e.port;
        ++nConds;
    }

    const QString name = QStringLiteral("Bulwark egress block %1").arg(keyOf(e.ip, e.port));
    std::wstring wname(reinterpret_cast<const wchar_t*>(name.utf16()));

    FWPM_FILTER0 filter{};
    filter.displayData.name = const_cast<wchar_t*>(wname.c_str());
    filter.layerKey = ipv6 ? FWPM_LAYER_ALE_AUTH_CONNECT_V6 : FWPM_LAYER_ALE_AUTH_CONNECT_V4;
    filter.subLayerKey = FWPM_SUBLAYER_UNIVERSAL;
    filter.action.type = FWP_ACTION_BLOCK;
    filter.weight.type = FWP_EMPTY;
    filter.numFilterConditions = nConds;
    filter.filterCondition = conds;

    UINT64 id = 0;
    const DWORD rc = ::FwpmFilterAdd0(engine_, &filter, nullptr, &id);
    if (rc != ERROR_SUCCESS) {
        log_.warning(QStringLiteral("用户态网络封禁:下发过滤器失败(rc=%1),该地址此刻【未被拦截】:%2")
                         .arg(rc)
                         .arg(keyOf(e.ip, e.port)));
        return false;
    }
    e.filterId = id;
    return true;
}

bool UserModeNetworkBlock::deleteFilterLocked(Entry& e) {
    if (!engine_ || e.filterId == 0)
        return false;
    const DWORD rc = ::FwpmFilterDeleteById0(engine_, e.filterId);
    if (rc != ERROR_SUCCESS) {
        log_.warning(QStringLiteral("用户态网络封禁:删除过滤器失败(rc=%1,id=%2),该封禁可能仍在生效:%3")
                         .arg(rc)
                         .arg(e.filterId)
                         .arg(keyOf(e.ip, e.port)));
        return false;
    }
    e.filterId = 0;
    return true;
}

bool UserModeNetworkBlock::blockIp(const QString& ip, quint16 port) {
    const auto parsed = bulwark::engine::NetworkEndpoint::parse(ip);
    if (parsed && parsed->port) {
        if (port && port != parsed->port) return false;
        port = parsed->port;
    }
    const QString addr = parsed ? parsed->host() : QString();
    if (addr.isEmpty())
        return false;

    if (isUnsafeToBlanketBlockIp(addr)) {
        log_.warning(QStringLiteral("用户态网络封禁已拒绝(该地址不可整段封禁:私网/环回/公共解析器/"
                                    "共享 CDN 前端,或无效 IP):%1")
                         .arg(addr));
        return false;
    }

    QMutexLocker lock(&mx_);
    if (!engine_) {
        log_.warning(QStringLiteral("用户态网络封禁:WFP 引擎未就绪,该地址未被拦截:%1").arg(addr));
        return false;
    }

    const QString key = keyOf(addr, port);
    if (entries_.contains(key))
        return entries_[key].filterId != 0;

    if (entries_.size() >= maxEntries_) {
        log_.warning(QStringLiteral("用户态网络封禁名单已达上限 %1 条,拒绝新增:%2"
                                    "(绝不静默挤掉已有条目)")
                         .arg(maxEntries_)
                         .arg(key));
        return false;
    }

    Entry e;
    e.ip = addr;
    e.port = port;
    e.since = nowIso();
    const bool ok = addFilterLocked(e);
    if (!ok)
        return false;

    entries_.insert(key, e);
    log_.warning(QStringLiteral("用户态网络封禁已生效:%1 的出站连接此后被 WFP 在 connect 阶段拒绝"
                                "(调用方将收到 WSAEACCES)。")
                     .arg(key));
    return true;
}

int UserModeNetworkBlock::unblockIp(const QString& ip, quint16 port) {
    QMutexLocker lock(&mx_);
    const QString key = keyOf(ip, port);
    auto it = entries_.find(key);
    if (it == entries_.end())
        return 0;
    const bool ok = deleteFilterLocked(*it);
    if (ok)
        entries_.erase(it);
    log_.warning(QStringLiteral("用户态网络封禁%1:%2")
                     .arg(ok ? QStringLiteral("已解除") : QStringLiteral("解除失败,已保留记录供重试"),
                          key));
    return ok ? 1 : 0;
}

int UserModeNetworkBlock::clearAll() {
    QMutexLocker lock(&mx_);
    int n = 0;
    for (auto it = entries_.begin(); it != entries_.end();) {
        if (deleteFilterLocked(*it)) {
            it = entries_.erase(it);
            ++n;
        } else {
            ++it;
        }
    }
    if (n > 0)
        log_.warning(QStringLiteral("用户态网络封禁已删除 %1 条 WFP 过滤器;失败项保留供重试。")
                         .arg(n));
    return n;
}

QStringList UserModeNetworkBlock::blockedList() const {
    QMutexLocker lock(&mx_);
    QStringList out;
    for (auto it = entries_.constBegin(); it != entries_.constEnd(); ++it)
        out << keyOf(it.value().ip, it.value().port);
    return out;
}

}
