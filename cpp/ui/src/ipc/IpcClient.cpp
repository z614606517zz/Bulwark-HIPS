#include "ipc/IpcClient.h"

#include "bulwark/ipc/IpcMessageType.h"
#include "bulwark/ipc/PipeNames.h"

#include <QCoreApplication>
#include <QDateTime>
#include <QDir>
#include <QLocalSocket>
#include <QTimer>

#include <iterator>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

using namespace bulwark;
using namespace bulwark::ipc;

IpcClient::IpcClient(QObject* parent)
    : QObject(parent), m_ai(new AiScanner(this))
{
    connect(m_ai, &AiScanner::rulesSuggested, this,
            [this](const QList<AiSuggestedRule>& rules) { emit aiRulesSuggested(rules); });
}

IpcClient::~IpcClient() = default;

void IpcClient::start()
{
    if (m_sock)
        return;

    m_sock = new QLocalSocket(this);
    connect(m_sock, &QLocalSocket::connected, this, &IpcClient::onConnected);
    connect(m_sock, &QLocalSocket::disconnected, this, &IpcClient::onDisconnected);
    connect(m_sock, &QLocalSocket::errorOccurred, this,
            [this](QLocalSocket::LocalSocketError) { onDisconnected(); });
    connect(m_sock, &QLocalSocket::readyRead, this, &IpcClient::onReadyRead);

    m_reconnect = new QTimer(this);
    m_reconnect->setInterval(1000);
    m_reconnect->setSingleShot(true);
    connect(m_reconnect, &QTimer::timeout, this, &IpcClient::tryConnect);

    tryConnect();
}

bool IpcClient::isConnected() const
{
    return m_sock && m_sock->state() == QLocalSocket::ConnectedState;
}

void IpcClient::tryConnect()
{
    if (m_sock && m_sock->state() == QLocalSocket::UnconnectedState)
        m_sock->connectToServer(controlPipe());
}

namespace {
bool serverIsGenuine(qintptr fd)
{
    ULONG pid = 0;
    if (!::GetNamedPipeServerProcessId(reinterpret_cast<HANDLE>(fd), &pid) || pid == 0)
        return false;
    HANDLE h = ::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!h) return false;
    wchar_t buf[MAX_PATH * 2];
    DWORD len = static_cast<DWORD>(std::size(buf));
    const BOOL pathOk = ::QueryFullProcessImageNameW(h, 0, buf, &len);

    HANDLE token = nullptr;
    BYTE userBuffer[256] = {};
    DWORD userBytes = 0;
    const bool tokenOk = ::OpenProcessToken(h, TOKEN_QUERY, &token) != FALSE
        && ::GetTokenInformation(token, TokenUser, userBuffer, sizeof(userBuffer), &userBytes) != FALSE;
    if (token)
        ::CloseHandle(token);
    ::CloseHandle(h);
    if (!pathOk || !tokenOk)
        return false;

    BYTE systemSidBuffer[SECURITY_MAX_SID_SIZE] = {};
    DWORD systemSidBytes = sizeof(systemSidBuffer);
    if (!::CreateWellKnownSid(WinLocalSystemSid, nullptr, systemSidBuffer, &systemSidBytes))
        return false;
    const auto* tokenUser = reinterpret_cast<const TOKEN_USER*>(userBuffer);
    if (!::EqualSid(tokenUser->User.Sid, systemSidBuffer))
        return false;

    const QString server = QDir::cleanPath(QString::fromWCharArray(buf, static_cast<int>(len)));
    const QString expected = QDir::cleanPath(
        QDir(QCoreApplication::applicationDirPath()).filePath(QStringLiteral("bulwark_service.exe")));
    return server.compare(expected, Qt::CaseInsensitive) == 0;
}
}

void IpcClient::onConnected()
{
    if (!serverIsGenuine(m_sock->socketDescriptor())) {
        m_sock->abort();
        if (m_reconnect && !m_reconnect->isActive())
            m_reconnect->start();
        return;
    }
    if (!m_connected) {
        m_connected = true;
        emit connectionChanged(true);
    }
    HelloPayload hello;
    hello.processId = static_cast<int>(QCoreApplication::applicationPid());
    hello.role = QStringLiteral("ui");
    send(IpcMessage::from(IpcMessageType::Hello, hello));
}

void IpcClient::onDisconnected()
{
    const bool was = m_connected;
    m_connected = false;
    m_buf.clear();
    if (was)
        emit connectionChanged(false);
    if (m_reconnect && !m_reconnect->isActive())
        m_reconnect->start();
}

void IpcClient::onReadyRead()
{
    m_buf += m_sock->readAll();
    int nl;
    while ((nl = m_buf.indexOf('\n')) >= 0) {
        const QByteArray lineBytes = m_buf.left(nl);
        m_buf.remove(0, nl + 1);
        const QString line = QString::fromUtf8(lineBytes).trimmed();
        if (!line.isEmpty())
            dispatch(line);
    }
    constexpr qsizetype kMaxFrameBytes = 4 * 1024 * 1024;
    if (m_buf.size() > kMaxFrameBytes) {
        m_buf.clear();
        m_sock->abort();
        if (m_reconnect && !m_reconnect->isActive())
            m_reconnect->start();
    }
}

void IpcClient::dispatch(const QString& line)
{
    const auto msg = IpcMessage::deserialize(line);
    if (!msg)
        return;

    switch (msg->type) {
    case IpcMessageType::PromptRequest:
        emit promptReceived(msg->payloadAs<SecurityEvent>());
        break;
    case IpcMessageType::BlockNotification: {
        const auto p = msg->payloadAs<BlockNotificationPayload>();
        emit blockNotification(p.event, p.enforcement, p.timeoutBlock, p.execBlocked);
        break;
    }
    case IpcMessageType::LogEntry:
        emit logReceived(msg->payload);
        break;
    case IpcMessageType::EventLogEntry:
        emit eventLogReceived(msg->payloadAs<EventLogPayload>());
        break;
    case IpcMessageType::EventHistoryResponse:
        emit eventHistoryReceived(msg->payloadAs<EventHistoryResponsePayload>().events);
        break;
    case IpcMessageType::PromptWithdrawNotification:
        // 只有旧版服务会发:它的「AI 全权裁决」代答后要收回弹窗。本版不收回,弹窗只由用户或超时策略关闭。
        qWarning("ignored PromptWithdrawNotification from an older service");
        break;
    case IpcMessageType::RemediationReport:
        emit remediationReport(msg->payloadAs<RemediationReportPayload>());
        break;
    case IpcMessageType::ManualQuarantineResponse:
        emit manualQuarantineResult(msg->payloadAs<ManualQuarantineResultPayload>());
        break;
    case IpcMessageType::RulesResponse:
        emit rulesReceived(msg->payloadAs<RulesResponsePayload>().rules);
        break;
    case IpcMessageType::TrustListResponse:
        emit trustReceived(msg->payloadAs<TrustListResponsePayload>().entries);
        break;
    case IpcMessageType::SettingsResponse: {
        const auto s = msg->payloadAs<bulwark::RuntimeSettings>();
        m_ai->setConfig(s.aiBaseUrl, s.aiApiKey, s.aiModel);
        m_ai->setCreditGuard(s.aiCreditGuardEnabled, s.aiMonthlyCreditBudget);
        m_lastSettings = s;
        m_haveSettings = true;
        emit settingsReceived(s);
        break;
    }
    case IpcMessageType::QuarantineListResponse:
        emit quarantineReceived(msg->payloadAs<QuarantineListResponsePayload>().items);
        break;
    case IpcMessageType::QuarantineActionResult:
        emit quarantineActionResult(msg->payloadAs<QuarantineActionResultPayload>());
        break;
    case IpcMessageType::HardeningStatusResponse:
        emit hardeningStatusReceived(msg->payloadAs<HardeningStatusResponsePayload>());
        break;
    case IpcMessageType::HardeningActionResponse:
        emit hardeningActionResult(msg->payloadAs<HardeningActionResultPayload>());
        break;
    case IpcMessageType::HijackAlertNotification:
        emit hijackAlertReceived(msg->payloadAs<HijackAlertPayload>());
        break;
    case IpcMessageType::PersistenceListResponse:
        emit persistenceReceived(msg->payloadAs<PersistenceListResponsePayload>());
        break;
    case IpcMessageType::PersistenceCleanupResponse:
        emit persistenceCleanupDone(msg->payloadAs<PersistenceCleanupResultPayload>());
        break;
    case IpcMessageType::EventTimelineResponse:
        emit timelineReceived(msg->payloadAs<TimelineResponsePayload>());
        break;
    case IpcMessageType::AttackGraphResponse:
        emit attackGraphReceived(msg->payloadAs<AttackGraphResponsePayload>());
        break;
    case IpcMessageType::ProcessListResponse:
        emit processListReceived(msg->payloadAs<ProcessListResponsePayload>());
        break;
    case IpcMessageType::ProcessActionResponse:
        emit processActionResult(msg->payloadAs<ProcessActionResultPayload>());
        break;
    case IpcMessageType::SystemBoostResponse:
        emit systemBoostReceived(msg->payloadAs<SystemBoostResultPayload>());
        break;
    case IpcMessageType::YaraRulesStatusResponse:
        emit yaraStatusReceived(msg->payloadAs<YaraRulesStatusPayload>());
        break;
    case IpcMessageType::YaraRulesActionResponse:
        emit yaraActionResult(msg->payloadAs<YaraRulesActionResultPayload>());
        break;
    case IpcMessageType::NetTrafficSnapshot:
        emit netTrafficReceived(msg->payloadAs<NetTrafficSnapshotPayload>());
        break;
    case IpcMessageType::IntelRefreshResponse:
    case IpcMessageType::IntelApplyResponse:
        emit intelResult(msg->payloadAs<IntelRefreshResultPayload>());
        break;
    default:
        break;
    }
}

void IpcClient::sendVerdict(const QUuid& eventId, VerdictAction action, bool remember,
                            RememberScope scope, bool autoTimeout)
{
    PromptResponsePayload p;
    p.eventId = eventId;
    p.action = action;
    p.remember = remember;
    p.scope = scope;
    p.autoTimeout = autoTimeout;
    send(IpcMessage::from(IpcMessageType::PromptResponse, p));
}

void IpcClient::requestRules()
{
    send(IpcMessage::create(IpcMessageType::RulesRequest, {}));
}

void IpcClient::addRule(const AddRulePayload& p)
{
    send(IpcMessage::from(IpcMessageType::AddRule, p));
}

void IpcClient::deleteRule(const QUuid& ruleId)
{
    DeleteRulePayload p;
    p.ruleId = ruleId;
    send(IpcMessage::from(IpcMessageType::DeleteRule, p));
}

void IpcClient::requestSettings()
{
    send(IpcMessage::create(IpcMessageType::SettingsRequest, {}));
}

void IpcClient::updateSettings(const bulwark::RuntimeSettings& s)
{
    send(IpcMessage::create(IpcMessageType::SettingsUpdate, s.toJson()));
}

void IpcClient::requestTrust()
{
    send(IpcMessage::create(IpcMessageType::TrustListRequest, {}));
}

void IpcClient::addTrust(const QString& actorPath, const QString& note, bool isDirectory,
                         bulwark::RememberScope scope)
{
    AddTrustPayload p;
    p.actorPath = actorPath;
    p.note = note;
    p.isDirectory = isDirectory;
    const QDateTime now = QDateTime::currentDateTimeUtc();
    switch (scope) {
    case bulwark::RememberScope::Session:   p.sessionOnly = true; break;
    case bulwark::RememberScope::OneHour:   p.expiresUtc = now.addSecs(3600); break;
    case bulwark::RememberScope::OneDay:    p.expiresUtc = now.addSecs(86400); break;
    case bulwark::RememberScope::Permanent: break;
    }
    send(IpcMessage::from(IpcMessageType::AddTrust, p));
}

void IpcClient::removeTrust(const QUuid& ruleId)
{
    RemoveTrustPayload p;
    p.ruleId = ruleId;
    send(IpcMessage::from(IpcMessageType::RemoveTrust, p));
}

void IpcClient::requestQuarantine()
{
    send(IpcMessage::create(IpcMessageType::QuarantineListRequest, {}));
}

void IpcClient::quarantineRestore(const QUuid& id)
{
    QuarantineActionPayload p;
    p.id = id;
    send(IpcMessage::from(IpcMessageType::QuarantineRestore, p));
}

void IpcClient::quarantineDelete(const QUuid& id)
{
    QuarantineActionPayload p;
    p.id = id;
    send(IpcMessage::from(IpcMessageType::QuarantineDelete, p));
}

void IpcClient::requestPersistenceCleanup(const bulwark::PersistenceEntry& entry)
{
    PersistenceCleanupRequestPayload p;
    p.entry = entry;
    send(IpcMessage::from(IpcMessageType::PersistenceCleanupRequest, p));
}

void IpcClient::requestHardeningStatus()
{
    send(IpcMessage::create(IpcMessageType::HardeningStatusRequest, {}));
}

QUuid IpcClient::hardeningAction(const QString& action, const QString& id)
{
    HardeningActionRequestPayload p;
    p.action = action;
    p.id = id;
    send(IpcMessage::from(IpcMessageType::HardeningActionRequest, p));
    return p.requestId;
}

void IpcClient::requestPersistence()
{
    send(IpcMessage::create(IpcMessageType::PersistenceListRequest, {}));
}

void IpcClient::requestEventHistory()
{
    send(IpcMessage::create(IpcMessageType::EventHistoryRequest, {}));
}

void IpcClient::clearEventHistory()
{
    send(IpcMessage::create(IpcMessageType::EventHistoryClearRequest, {}));
}

void IpcClient::manualQuarantine(const QString& path)
{
    ManualQuarantinePayload p;
    p.path = path;
    send(IpcMessage::from(IpcMessageType::ManualQuarantineRequest, p));
}

QUuid IpcClient::forceHandle(const RemediationSkippedItem& item)
{
    ManualQuarantinePayload p;
    p.force = true;
    p.kind = item.kind.isEmpty() ? QStringLiteral("file") : item.kind;
    p.path = item.isFile ? item.target : QString();
    p.location = item.location;
    p.name = item.name;
    send(IpcMessage::from(IpcMessageType::ManualQuarantineRequest, p));
    return p.requestId;
}

void IpcClient::requestTimeline(const TimelineRequestPayload& p)
{
    send(IpcMessage::from(IpcMessageType::EventTimelineRequest, p));
}

QUuid IpcClient::requestAttackGraph(const QUuid& seedEventId, int rootPid, int windowSeconds)
{
    AttackGraphRequestPayload p;
    p.seedEventId = seedEventId;
    p.rootPid = rootPid;
    p.windowSeconds = windowSeconds;
    send(IpcMessage::from(IpcMessageType::AttackGraphRequest, p));
    return p.requestId;
}

QUuid IpcClient::requestProcesses(bool includeCommandLine, bool resolveOrigin)
{
    ProcessListRequestPayload p;
    p.includeCommandLine = includeCommandLine;
    p.resolveOrigin = resolveOrigin;
    send(IpcMessage::from(IpcMessageType::ProcessListRequest, p));
    return p.requestId;
}

void IpcClient::setNetTrafficSubscribed(bool on, const QList<int>& focusPids)
{
    NetTrafficSubscribePayload p;
    p.on = on;
    if (on)
        p.focusPids = focusPids;
    send(IpcMessage::from(IpcMessageType::NetTrafficSubscribe, p));
}

void IpcClient::processAction(const ProcessActionRequestPayload& p)
{
    send(IpcMessage::from(IpcMessageType::ProcessActionRequest, p));
}

QUuid IpcClient::requestSystemBoost()
{
    SystemBoostRequestPayload p;
    send(IpcMessage::from(IpcMessageType::SystemBoostRequest, p));
    return p.requestId;
}

void IpcClient::requestYaraStatus()
{
    send(IpcMessage::create(IpcMessageType::YaraRulesStatusRequest, {}));
}

QUuid IpcClient::yaraAction(const QString& action, bool enabled)
{
    YaraRulesActionRequestPayload p;
    p.action = action;
    p.enabled = enabled;
    send(IpcMessage::from(IpcMessageType::YaraRulesActionRequest, p));
    return p.requestId;
}

void IpcClient::intelRefresh(bool previewOnly)
{
    IntelRefreshRequestPayload p;
    p.previewOnly = previewOnly;
    send(IpcMessage::from(IpcMessageType::IntelRefreshRequest, p));
}

void IpcClient::intelApply(const QList<bulwark::DefenseRule>& rules)
{
    IntelApplyRequestPayload p;
    p.rules = rules;
    send(IpcMessage::from(IpcMessageType::IntelApplyRequest, p));
}

void IpcClient::aiGenerateRules(const QString& request)
{
    m_ai->generateRules(request);
}

void IpcClient::send(const IpcMessage& msg)
{
    if (!m_sock || m_sock->state() != QLocalSocket::ConnectedState)
        return;
    const QByteArray bytes = (msg.serialize() + QLatin1Char('\n')).toUtf8();
    m_sock->write(bytes);
    m_sock->flush();
}
