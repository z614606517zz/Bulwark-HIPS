#include "bulwark/service/IpcServer.h"
#include "bulwark/service/Logger.h"
#include "bulwark/service/IpcClientAuth.h"

#include "bulwark/ipc/IpcMessageType.h"
#include "bulwark/ipc/Payloads.h"
#include "bulwark/ipc/PipeNames.h"

#include <optional>
#include <stdexcept>

#include <QLocalServer>
#include <QLocalSocket>
#include <QDateTime>

namespace bulwark::service {
using namespace bulwark::ipc;

namespace {
Logger& log() { static Logger l(QStringLiteral("IpcServer")); return l; }
}

IpcServer::IpcServer(QObject* parent) : QObject(parent) {
    server_ = new QLocalServer(this);
    server_->setSocketOptions(QLocalServer::WorldAccessOption);
    connect(server_, &QLocalServer::newConnection, this, &IpcServer::onNewConnection);
}

bool IpcServer::start() {
    return start(controlPipe());
}

bool IpcServer::start(const QString& name) {
    QLocalServer::removeServer(name);
    if (!server_->listen(name)) {
        log().error(QStringLiteral("监听控制管道失败: %1 (%2)").arg(name, server_->errorString()));
        return false;
    }
    log().info(QStringLiteral("IPC 服务器已监听 %1").arg(name));
    return true;
}

void IpcServer::stop() {
    const QList<QLocalSocket*> socks = buffers_.keys();
    buffers_.clear();
    clientPids_.clear();
    asyncRoutes_.clear();
    {
        const bool hadSubscribers = !trafficSubscribers_.isEmpty();
        trafficSubscribers_.clear();
        trafficFocus_.clear();
        if (hadSubscribers && netTrafficSubscriptionChanged)
            netTrafficSubscriptionChanged(false);
    }
    for (QLocalSocket* sock : socks)
        if (sock) sock->disconnectFromServer();
    if (server_) server_->close();
}

void IpcServer::onNewConnection() {
    while (QLocalSocket* sock = server_->nextPendingConnection()) {
        const IpcClientAuth::Result auth = IpcClientAuth::authenticate(sock->socketDescriptor());
        if (!auth.ok) {
            log().warning(QStringLiteral("已拒绝未授权的控制管道连接:%1").arg(auth.reason));
            ++rejectedConnections_;
            sock->disconnectFromServer();
            sock->deleteLater();
            continue;
        }

        buffers_.insert(sock, QByteArray());
        clientPids_.insert(sock, auth.pid);
        connect(sock, &QLocalSocket::readyRead, this, &IpcServer::onReadyRead);
        connect(sock, &QLocalSocket::disconnected, this, &IpcServer::onDisconnected);
        log().info(QStringLiteral("UI 客户端已连接(%1,当前 %2)").arg(auth.reason).arg(buffers_.size()));
        emit clientCountChanged(buffers_.size());
    }
}

void IpcServer::onReadyRead() {
    auto* sock = qobject_cast<QLocalSocket*>(sender());
    if (!sock) return;
    {
        const auto it = buffers_.find(sock);
        if (it == buffers_.end()) return;
        it.value() += sock->readAll();
    }
    // handleLine 回发消息会 flush,可能同步跑到 onDisconnected 把本 sock 从 buffers_ 摘掉,
    // QHash 随之 rehash / 释放节点 —— 所以每轮都重新按 sock 定位缓冲,绝不跨 handleLine 持有引用。
    for (;;) {
        const auto it = buffers_.find(sock);
        if (it == buffers_.end()) return;   // 连接已在上一条消息处理过程中断开
        QByteArray& buf = it.value();
        const int nl = buf.indexOf('\n');
        if (nl < 0) {
            if (buf.size() > kMaxFrameBytes) {
                log().warning(QStringLiteral("控制管道客户端单帧超过 %1 字节仍无换行符,已断开该连接(疑似畸形或恶意客户端)")
                                  .arg(kMaxFrameBytes));
                buf.clear();
                sock->disconnectFromServer();
            }
            return;
        }
        const QByteArray lineBytes = buf.left(nl);
        buf.remove(0, nl + 1);
        const QString line = QString::fromUtf8(lineBytes).trimmed();
        if (!line.isEmpty()) handleLine(sock, line);
    }
}

void IpcServer::onDisconnected() {
    auto* sock = qobject_cast<QLocalSocket*>(sender());
    if (!sock) return;
    buffers_.remove(sock);
    clientPids_.remove(sock);
    setTrafficSubscribed(sock, false);
    for (auto it = asyncRoutes_.begin(); it != asyncRoutes_.end(); ) {
        if (it.value().sock.isNull() || it.value().sock == sock) it = asyncRoutes_.erase(it);
        else ++it;
    }
    sock->deleteLater();
    log().info(QStringLiteral("UI 客户端断开(当前 %1)").arg(buffers_.size()));
    emit clientCountChanged(buffers_.size());
}

void IpcServer::handleLine(QLocalSocket* sock, const QString& line) {
    const auto msg = IpcMessage::deserialize(line);
    if (!msg) return;

    try {
        switch (msg->type) {
            case IpcMessageType::Hello: {
                const HelloPayload h = HelloPayload::fromJson(msg->payloadObject());
                const quint32 realPid = clientPids_.value(sock, 0);
                if (realPid != 0 && h.processId > 0 && static_cast<quint32>(h.processId) != realPid) {
                    log().warning(
                        QStringLiteral("控制管道 Hello 自报 PID(%1)与认证得到的真实 PID(%2)不一致,"
                                       "按真实 PID 处理(自报值不参与授权)")
                            .arg(h.processId).arg(realPid));
                }
                const quint32 grantPid = realPid;
                emit helloReceived(static_cast<int>(grantPid), h.role);
                if (uiProcessConnected && grantPid > 0) uiProcessConnected(static_cast<int>(grantPid));
                break;
            }
            case IpcMessageType::PromptResponse: {
                const QJsonObject raw = msg->payloadObject();
                const int action = raw.value(QLatin1String("action")).toInt(-1);
                const int scope = raw.value(QLatin1String("scope")).toInt(-1);
                if (action < static_cast<int>(VerdictAction::Allow)
                    || action > static_cast<int>(VerdictAction::Ask)
                    || scope < static_cast<int>(RememberScope::Permanent)
                    || scope > static_cast<int>(RememberScope::OneDay)) {
                    log().warning(QStringLiteral("已拒绝枚举越界的 PromptResponse(action=%1,scope=%2)")
                                      .arg(action).arg(scope));
                    break;
                }
                const PromptResponsePayload p = PromptResponsePayload::fromJson(raw);
                if (p.eventId.isNull()) {
                    log().warning(QStringLiteral("已拒绝缺少 eventId 的 PromptResponse"));
                    break;
                }
                if (p.autoTimeout)
                    emit promptAutoTimeout(p.eventId);
                else
                    emit promptResponse(p.eventId, p.action, p.remember, p.scope);
                break;
            }
            case IpcMessageType::RulesRequest:
                sendRules(sock);
                break;
            case IpcMessageType::DeleteRule: {
                const auto p = DeleteRulePayload::fromJson(msg->payloadObject());
                if (ruleDeleteRequested) ruleDeleteRequested(p.ruleId);
                sendRules();
                break;
            }
            case IpcMessageType::AddRule: {
                const QJsonObject raw = msg->payloadObject();
                const QJsonValue type = raw.value(QLatin1String("type"));
                if (type.isDouble()) {
                    const int value = type.toInt(-1);
                    if (value < static_cast<int>(bulwark::EventType::ProcessCreate)
                        || value > static_cast<int>(bulwark::EventType::ScriptScan)) {
                        log().warning(QStringLiteral("已拒绝事件类型越界的 AddRule(type=%1)").arg(value));
                        break;
                    }
                }
                const auto p = AddRulePayload::fromJson(raw);
                if (ruleAddRequested) ruleAddRequested(p);
                sendRules();
                break;
            }

            case IpcMessageType::SettingsRequest:
                sendSettings(sock);
                break;
            case IpcMessageType::SettingsUpdate: {
                const auto s = bulwark::RuntimeSettings::fromJson(msg->payloadObject());
                if (settingsUpdated) settingsUpdated(s);
                sendSettings();
                break;
            }

            case IpcMessageType::TrustListRequest:
                sendTrustList(sock);
                break;
            case IpcMessageType::AddTrust: {
                const auto p = AddTrustPayload::fromJson(msg->payloadObject());
                if (trustAddRequested && !p.actorPath.trimmed().isEmpty()) trustAddRequested(p);
                sendTrustList();
                break;
            }
            case IpcMessageType::RemoveTrust: {
                const auto p = RemoveTrustPayload::fromJson(msg->payloadObject());
                if (trustRemoveRequested) trustRemoveRequested(p.ruleId);
                sendTrustList();
                break;
            }

            case IpcMessageType::QuarantineListRequest:
                sendQuarantineList(sock);
                break;
            case IpcMessageType::QuarantineRestore: {
                const auto p = QuarantineActionPayload::fromJson(msg->payloadObject());
                QuarantineActionResultPayload r = quarantineRestoreRequested
                    ? quarantineRestoreRequested(p.id)
                    : QuarantineActionResultPayload{p.id, false, QStringLiteral("服务未启用隔离区"), };
                sendTo(sock, IpcMessage::from(IpcMessageType::QuarantineActionResult, r));
                sendQuarantineList();
                break;
            }
            case IpcMessageType::QuarantineDelete: {
                const auto p = QuarantineActionPayload::fromJson(msg->payloadObject());
                QuarantineActionResultPayload r = quarantineDeleteRequested
                    ? quarantineDeleteRequested(p.id)
                    : QuarantineActionResultPayload{p.id, false, QStringLiteral("服务未启用隔离区"), };
                sendTo(sock, IpcMessage::from(IpcMessageType::QuarantineActionResult, r));
                sendQuarantineList();
                break;
            }
            case IpcMessageType::ManualQuarantineRequest: {
                const auto req = ManualQuarantinePayload::fromJson(msg->payloadObject());
                ManualQuarantineResultPayload resp;
                resp.requestId = req.requestId;
                if (manualQuarantineRequested) {
                    const auto [ok, message] = manualQuarantineRequested(req);
                    resp.success = ok;
                    resp.message = message;
                } else {
                    resp.success = false;
                    resp.message = QStringLiteral("当前环境不支持隔离");
                }
                sendTo(sock, IpcMessage::from(IpcMessageType::ManualQuarantineResponse, resp));
                break;
            }

            case IpcMessageType::NetTrafficSubscribe: {
                const auto req = NetTrafficSubscribePayload::fromJson(msg->payloadObject());
                setTrafficSubscribed(sock, req.on, req.focusPids);
                break;
            }

            case IpcMessageType::HardeningStatusRequest: {
                HardeningStatusResponsePayload payload;
                if (hardeningStatusRequested) {
                    payload = hardeningStatusRequested();
                } else {
                    payload.message = QStringLiteral("服务未启用系统加固");
                    payload.actionsEnabled = false;
                }
                sendTo(sock, IpcMessage::from(IpcMessageType::HardeningStatusResponse, payload));
                break;
            }

            case IpcMessageType::HardeningActionRequest: {
                const auto req = HardeningActionRequestPayload::fromJson(msg->payloadObject());
                HardeningActionResultPayload res;
                if (hardeningActionRequested) {
                    res = hardeningActionRequested(req);
                } else {
                    res.ok = false;
                    res.message = QStringLiteral("服务未启用系统加固");
                }
                res.requestId = req.requestId;
                res.action = req.action;
                res.id = req.id;
                sendTo(sock, IpcMessage::from(IpcMessageType::HardeningActionResponse, res));
                break;
            }

            case IpcMessageType::PersistenceCleanupRequest: {
                const auto req = PersistenceCleanupRequestPayload::fromJson(msg->payloadObject());
                PersistenceCleanupResultPayload res;
                if (persistenceCleanupRequested) {
                    res = persistenceCleanupRequested(req);
                } else {
                    res.success = false;
                    res.message = QStringLiteral("服务未启用自启动项清理");
                }
                res.requestId = req.requestId;
                res.entryId = req.entry.id;
                sendTo(sock, IpcMessage::from(IpcMessageType::PersistenceCleanupResponse, res));
                break;
            }

            case IpcMessageType::PersistenceListRequest: {
                PersistenceListResponsePayload payload = persistenceListRequested
                    ? persistenceListRequested()
                    : PersistenceListResponsePayload{QDateTime::currentDateTimeUtc(), {}, QStringLiteral("服务未启用持久化扫描")};
                sendTo(sock, IpcMessage::from(IpcMessageType::PersistenceListResponse, payload));
                break;
            }

            case IpcMessageType::EventHistoryRequest: {
                const EventHistoryResponsePayload payload =
                    eventHistoryRequested ? eventHistoryRequested() : EventHistoryResponsePayload{};
                sendTo(sock, IpcMessage::from(IpcMessageType::EventHistoryResponse, payload));
                break;
            }

            case IpcMessageType::EventHistoryClearRequest: {
                if (eventHistoryClearRequested) eventHistoryClearRequested();
                const EventHistoryResponsePayload payload =
                    eventHistoryRequested ? eventHistoryRequested() : EventHistoryResponsePayload{};
                broadcast(IpcMessage::from(IpcMessageType::EventHistoryResponse, payload));
                break;
            }

            case IpcMessageType::EventTimelineRequest: {
                auto req = TimelineRequestPayload::fromJson(msg->payloadObject());
                if (timelineRequested) {
                    req.requestId = registerAsync(sock, req.requestId);
                    timelineRequested(req);
                } else {
                    TimelineResponsePayload res;
                    res.requestId = req.requestId;
                    res.message = QStringLiteral("服务未启用事件时间线");
                    sendTo(sock, IpcMessage::from(IpcMessageType::EventTimelineResponse, res));
                }
                break;
            }

            case IpcMessageType::AttackGraphRequest: {
                auto req = AttackGraphRequestPayload::fromJson(msg->payloadObject());
                if (attackGraphRequested) {
                    req.requestId = registerAsync(sock, req.requestId);
                    attackGraphRequested(req);
                } else {
                    AttackGraphResponsePayload res;
                    res.requestId = req.requestId;
                    res.message = QStringLiteral("服务未启用攻击图");
                    sendTo(sock, IpcMessage::from(IpcMessageType::AttackGraphResponse, res));
                }
                break;
            }

            case IpcMessageType::ProcessListRequest: {
                auto req = ProcessListRequestPayload::fromJson(msg->payloadObject());
                if (processListRequested) {
                    req.requestId = registerAsync(sock, req.requestId);
                    processListRequested(req);
                } else {
                    ProcessListResponsePayload res;
                    res.requestId = req.requestId;
                    res.message = QStringLiteral("服务未启用进程管理");
                    sendTo(sock, IpcMessage::from(IpcMessageType::ProcessListResponse, res));
                }
                break;
            }
            case IpcMessageType::ProcessActionRequest: {
                const auto req = ProcessActionRequestPayload::fromJson(msg->payloadObject());
                ProcessActionResultPayload res;
                if (processActionRequested) {
                    res = processActionRequested(req);
                } else {
                    res.success = false;
                    res.message = QStringLiteral("服务未启用进程管理");
                }
                res.requestId = req.requestId;
                res.kind = req.kind;
                res.pid = req.pid;
                sendTo(sock, IpcMessage::from(IpcMessageType::ProcessActionResponse, res));
                break;
            }

            case IpcMessageType::SystemBoostRequest: {
                auto req = SystemBoostRequestPayload::fromJson(msg->payloadObject());
                if (systemBoostRequested) {
                    req.requestId = registerAsync(sock, req.requestId);
                    systemBoostRequested(req);
                } else {
                    SystemBoostResultPayload res;
                    res.requestId = req.requestId;
                    res.success = false;
                    res.message = QStringLiteral("服务未启用一键加速");
                    sendTo(sock, IpcMessage::from(IpcMessageType::SystemBoostResponse, res));
                }
                break;
            }

            case IpcMessageType::IntelRefreshRequest: {
                const auto req = IntelRefreshRequestPayload::fromJson(msg->payloadObject());
                IntelRefreshResultPayload result = intelRefreshRequested
                    ? intelRefreshRequested(req)
                    : IntelRefreshResultPayload{req.requestId, false, 0, 0, {}, {}, QStringLiteral("情报刷新未启用")};
                result.requestId = req.requestId;
                sendTo(sock, IpcMessage::from(IpcMessageType::IntelRefreshResponse, result));
                break;
            }
            case IpcMessageType::IntelApplyRequest: {
                const auto req = IntelApplyRequestPayload::fromJson(msg->payloadObject());
                IntelRefreshResultPayload result = intelApplyRequested
                    ? intelApplyRequested(req)
                    : IntelRefreshResultPayload{req.requestId, false, 0, 0, {}, {}, QStringLiteral("情报采纳未启用")};
                result.requestId = req.requestId;
                sendTo(sock, IpcMessage::from(IpcMessageType::IntelApplyResponse, result));
                break;
            }

            case IpcMessageType::YaraRulesStatusRequest: {
                YaraRulesStatusPayload payload;
                if (yaraStatusRequested)
                    payload = yaraStatusRequested();
                else
                    payload.message = QStringLiteral("服务未启用 YARA 规则库");
                sendTo(sock, IpcMessage::from(IpcMessageType::YaraRulesStatusResponse, payload));
                break;
            }
            case IpcMessageType::YaraRulesActionRequest: {
                const auto req = YaraRulesActionRequestPayload::fromJson(msg->payloadObject());
                YaraRulesActionResultPayload res;
                if (yaraActionRequested) {
                    res = yaraActionRequested(req);
                } else {
                    res.ok = false;
                    res.message = QStringLiteral("服务未启用 YARA 规则库");
                }
                res.requestId = req.requestId;
                res.action = req.action;
                sendTo(sock, IpcMessage::from(IpcMessageType::YaraRulesActionResponse, res));
                break;
            }

            default:
                break;
        }
    } catch (const std::exception& ex) {
        log().warning(QStringLiteral("处理 UI 消息出错(已忽略): %1").arg(QString::fromUtf8(ex.what())));
    } catch (...) {
        log().warning(QStringLiteral("处理 UI 消息出现未知异常(已忽略)。"));
    }
}

void IpcServer::broadcast(const IpcMessage& msg) {
    const QByteArray bytes = (msg.serialize() + QLatin1Char('\n')).toUtf8();
    // 先拷一份连接列表:flush 可能同步触发 onDisconnected 改动 buffers_,边遍历边改会让迭代器失效。
    const QList<QLocalSocket*> socks = buffers_.keys();
    for (QLocalSocket* sock : socks) {
        if (!buffers_.contains(sock) || sock->state() != QLocalSocket::ConnectedState)
            continue;
        sock->write(bytes);
        sock->flush();
    }
}

void IpcServer::sendTo(QLocalSocket* sock, const IpcMessage& msg) {
    if (!sock || !buffers_.contains(sock)) return;
    if (sock->state() != QLocalSocket::ConnectedState) return;
    sock->write((msg.serialize() + QLatin1Char('\n')).toUtf8());
    sock->flush();
}

void IpcServer::deliver(QLocalSocket* only, const IpcMessage& msg) {
    if (only) sendTo(only, msg);
    else broadcast(msg);
}

QUuid IpcServer::registerAsync(QLocalSocket* sock, const QUuid& clientRequestId) {
    constexpr qsizetype kMaxAsyncRoutes = 64;
    if (asyncRoutes_.size() >= kMaxAsyncRoutes) {
        log().warning(QStringLiteral("异步 IPC 请求已达上限 %1,断开超额客户端")
                          .arg(kMaxAsyncRoutes));
        if (sock)
            sock->disconnectFromServer();
        throw std::runtime_error("too many asynchronous IPC requests");
    }
    const QUuid serverId = QUuid::createUuid();
    asyncRoutes_.insert(serverId, AsyncRoute{ sock, clientRequestId });
    return serverId;
}

QLocalSocket* IpcServer::takeAsyncRoute(const QUuid& serverRequestId, QUuid* clientRequestId) {
    const auto it = asyncRoutes_.constFind(serverRequestId);
    if (it == asyncRoutes_.constEnd()) return nullptr;
    QLocalSocket* sock = it.value().sock.data();
    if (clientRequestId) *clientRequestId = it.value().clientRequestId;
    asyncRoutes_.erase(it);
    return sock;
}

template <class P>
void IpcServer::replyAsync(IpcMessageType type, P payload) {
    QUuid clientId;
    QLocalSocket* sock = takeAsyncRoute(payload.requestId, &clientId);
    if (!sock) {
        log().info(QStringLiteral("异步响应(类型 %1)的发起连接已不在,丢弃(不广播)")
                       .arg(static_cast<int>(type)));
        return;
    }
    payload.requestId = clientId;
    sendTo(sock, IpcMessage::from(type, payload));
}

void IpcServer::sendPrompt(const bulwark::SecurityEvent& e) {
    broadcast(IpcMessage::create(IpcMessageType::PromptRequest, e.toJson()));
}

void IpcServer::sendBlock(const bulwark::SecurityEvent& e,
                          bulwark::EnforcementOutcome enforcement,
                          bool timeoutBlock, bool execBlocked) {
    BlockNotificationPayload p;
    p.event = e;
    p.enforcement = enforcement;
    p.timeoutBlock = timeoutBlock;
    p.execBlocked = execBlocked;
    broadcast(IpcMessage::create(IpcMessageType::BlockNotification, p.toJson()));
}

void IpcServer::sendHijackAlert(const bulwark::ipc::HijackAlertPayload& p) {
    broadcast(IpcMessage::from(IpcMessageType::HijackAlertNotification, p));
}

void IpcServer::setTrafficSubscribed(QLocalSocket* sock, bool on, const QList<int>& focusPids) {
    if (!sock)
        return;
    const bool before = !trafficSubscribers_.isEmpty();
    if (on) {
        if (!buffers_.contains(sock))
            return;
        trafficSubscribers_.insert(sock);
        if (focusPids.isEmpty())
            trafficFocus_.remove(sock);
        else
            trafficFocus_.insert(sock, focusPids);
    } else {
        trafficSubscribers_.remove(sock);
        trafficFocus_.remove(sock);
    }
    const bool after = !trafficSubscribers_.isEmpty();
    if (before != after && netTrafficSubscriptionChanged)
        netTrafficSubscriptionChanged(after);
}

void IpcServer::sendNetTraffic(const bulwark::ipc::NetTrafficSnapshotPayload& p,
                               const QHash<int, QList<bulwark::ipc::NetTrafficConnPayload>>& connections) {
    if (trafficSubscribers_.isEmpty())
        return;
    std::optional<IpcMessage> plain;
    const QList<QLocalSocket*> subs = trafficSubscribers_.values();
    for (QLocalSocket* s : subs) {
        const QList<int> focus = trafficFocus_.value(s);
        if (focus.isEmpty()) {
            if (!plain)
                plain = IpcMessage::from(IpcMessageType::NetTrafficSnapshot, p);
            sendTo(s, *plain);
            continue;
        }
        bulwark::ipc::NetTrafficSnapshotPayload mine = p;
        for (int pid : focus)
            mine.connections.insert(pid, connections.value(pid));
        sendTo(s, IpcMessage::from(IpcMessageType::NetTrafficSnapshot, mine));
    }
}

void IpcServer::sendLog(const QString& line) {
    broadcast(IpcMessage::createRaw(IpcMessageType::LogEntry, line));
}

void IpcServer::sendEventLog(const bulwark::SecurityEvent& e,
                             bulwark::VerdictAction action, bulwark::VerdictSource source,
                             bulwark::EnforcementOutcome enforcement) {
    EventLogPayload p;
    p.event = e;
    p.action = action;
    p.source = source;
    p.enforcement = enforcement;
    broadcast(IpcMessage::from(IpcMessageType::EventLogEntry, p));
}

void IpcServer::sendRemediationReport(const RemediationReportPayload& report) {
    broadcast(IpcMessage::from(IpcMessageType::RemediationReport, report));
}

// 异步回推只回发起方。payload.requestId 必须是 handleLine 交给宿主的服务端 id(宿主原样回填)。
void IpcServer::sendTimeline(const TimelineResponsePayload& payload) {
    replyAsync(IpcMessageType::EventTimelineResponse, payload);
}

void IpcServer::sendAttackGraph(const AttackGraphResponsePayload& payload) {
    replyAsync(IpcMessageType::AttackGraphResponse, payload);
}

void IpcServer::sendProcessList(const ProcessListResponsePayload& payload) {
    replyAsync(IpcMessageType::ProcessListResponse, payload);
}

void IpcServer::sendSystemBoost(const SystemBoostResultPayload& payload) {
    replyAsync(IpcMessageType::SystemBoostResponse, payload);
}

void IpcServer::sendRules(QLocalSocket* only) {
    RulesResponsePayload payload;
    if (rulesRequested) payload.rules = rulesRequested();
    deliver(only, IpcMessage::from(IpcMessageType::RulesResponse, payload));
}

void IpcServer::sendSettings(QLocalSocket* only) {
    const bulwark::RuntimeSettings settings = settingsRequested ? settingsRequested() : bulwark::RuntimeSettings{};
    deliver(only, IpcMessage::from(IpcMessageType::SettingsResponse, settings));
}

void IpcServer::sendTrustList(QLocalSocket* only) {
    TrustListResponsePayload payload;
    if (trustListRequested) payload.entries = trustListRequested();
    deliver(only, IpcMessage::from(IpcMessageType::TrustListResponse, payload));
}

void IpcServer::sendQuarantineList(QLocalSocket* only) {
    const QuarantineListResponsePayload payload =
        quarantineListRequested ? quarantineListRequested() : QuarantineListResponsePayload{};
    deliver(only, IpcMessage::from(IpcMessageType::QuarantineListResponse, payload));
}

void IpcServer::sendYaraStatus(const YaraRulesStatusPayload& p) {
    broadcast(IpcMessage::from(IpcMessageType::YaraRulesStatusResponse, p));
}

}
