#include "ai/McpClient.h"

#include "bulwark/Version.h"

#include <QCoreApplication>
#include <QDir>
#include <QFileInfo>
#include <QJsonArray>
#include <QJsonDocument>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QNetworkRequest>
#include <QPointer>
#include <QProcess>
#include <QProcessEnvironment>
#include <QSet>
#include <QStandardPaths>
#include <QTimer>
#include <QUrl>

#include <memory>

#ifdef Q_OS_WIN
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#endif

namespace {

QString u(const char* s) { return QString::fromUtf8(s); }

constexpr int kProbeTimeoutMs = 20000;
constexpr int kHandshakeTimeoutMs = 30000;
constexpr int kCallTimeoutMs = 120000;
constexpr int kMaxToolPages = 20;
constexpr qsizetype kMaxLineBytes = 16 * 1024 * 1024;
constexpr qsizetype kMaxErrTail = 4096;

QHash<QString, int>& eraCache()
{
    static QHash<QString, int> c;
    return c;
}

bool isModernErrorCode(int code) { return code == -32020 || code == -32021 || code == -32022; }

QJsonObject clientInfo()
{
    return QJsonObject{{QStringLiteral("name"), QStringLiteral("bulwark")},
                       {QStringLiteral("title"), QStringLiteral("Bulwark")},
                       {QStringLiteral("version"), bulwark::version::current()}};
}

QStringList versionsIn(const QJsonValue& v)
{
    QStringList out;
    const QJsonObject o = v.toObject();
    for (const char* k : {"supportedVersions", "supported"})
        for (const QJsonValue& x : o.value(QLatin1String(k)).toArray())
            if (x.isString())
                out << x.toString();
    return out;
}

bool isToken(const QString& s)
{
    if (s.isEmpty())
        return false;
    for (const QChar c : s) {
        const ushort x = c.unicode();
        const bool alnum = (x >= '0' && x <= '9') || (x >= 'a' && x <= 'z') || (x >= 'A' && x <= 'Z');
        if (!alnum && !QStringLiteral("!#$%&'*+-.^_`|~").contains(c))
            return false;
    }
    return true;
}

QByteArray headerValue(const QString& v)
{
    bool plain = v == v.trimmed();
    for (const QChar c : v)
        if (!(c.unicode() == 0x09 || (c.unicode() >= 0x20 && c.unicode() <= 0x7E)))
            plain = false;
    if (v.startsWith(QLatin1String("=?base64?")) && v.endsWith(QLatin1String("?=")))
        plain = false;
    if (plain)
        return v.toLatin1();
    return "=?base64?" + v.toUtf8().toBase64() + "?=";
}

bool collectHeaderParams(const QJsonObject& schema, const QStringList& path, QList<McpClient::HeaderParam>& out,
                         QSet<QString>& seen, QString* why)
{
    const QJsonObject props = schema.value(QStringLiteral("properties")).toObject();
    for (auto it = props.begin(); it != props.end(); ++it) {
        const QJsonObject sub = it.value().toObject();
        const QStringList p = path + QStringList{it.key()};
        if (sub.contains(QLatin1String("x-mcp-header"))) {
            const QString name = sub.value(QStringLiteral("x-mcp-header")).toString();
            const QString type = sub.value(QStringLiteral("type")).toString();
            if (!isToken(name)) {
                *why = u("x-mcp-header「%1」不是合法的请求头名").arg(name);
                return false;
            }
            if (type != QLatin1String("string") && type != QLatin1String("integer") &&
                type != QLatin1String("boolean")) {
                *why = u("x-mcp-header 只能标在 string / integer / boolean 参数上(%1)").arg(p.join(QLatin1Char('.')));
                return false;
            }
            if (seen.contains(name.toLower())) {
                *why = u("x-mcp-header「%1」重复").arg(name);
                return false;
            }
            seen.insert(name.toLower());
            out.append({QByteArray("Mcp-Param-") + name.toLatin1(), p});
        }
        if (!collectHeaderParams(sub, p, out, seen, why))
            return false;
    }
    return true;
}

QString flattenToolResult(const QJsonObject& result)
{
    QStringList parts;
    for (const QJsonValue& v : result.value(QStringLiteral("content")).toArray()) {
        const QJsonObject b = v.toObject();
        const QString type = b.value(QStringLiteral("type")).toString();
        if (type == QLatin1String("text")) {
            parts << b.value(QStringLiteral("text")).toString();
        } else if (type == QLatin1String("image") || type == QLatin1String("audio")) {
            parts << u("[%1 内容,已省略]").arg(type);
        } else if (type == QLatin1String("resource")) {
            const QJsonObject r = b.value(QStringLiteral("resource")).toObject();
            if (r.contains(QLatin1String("text")))
                parts << r.value(QStringLiteral("text")).toString();
            else
                parts << u("[资源 %1,二进制内容已省略]").arg(r.value(QStringLiteral("uri")).toString());
        } else if (type == QLatin1String("resource_link")) {
            parts << u("[资源链接] %1 %2")
                         .arg(b.value(QStringLiteral("name")).toString(), b.value(QStringLiteral("uri")).toString());
        }
    }
    if (parts.isEmpty() && result.contains(QLatin1String("structuredContent")))
        parts << QString::fromUtf8(
            QJsonDocument::fromVariant(result.value(QStringLiteral("structuredContent")).toVariant())
                .toJson(QJsonDocument::Compact));
    return parts.join(QLatin1Char('\n'));
}

QString cmdQuote(const QString& a)
{
    QString q = a;
    q.replace(QLatin1Char('"'), QStringLiteral("\"\""));
    return QLatin1Char('"') + q + QLatin1Char('"');
}

QString httpFailure(QNetworkReply* reply)
{
    if (reply->property("bw.timedOut").toBool())
        return u("等待服务器响应超时");
    const int http = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
    if (http == 401 || http == 403)
        return u("服务器拒绝访问(HTTP %1),检查请求头里的令牌").arg(http);
    if (http == 404)
        return u("端点不存在(HTTP 404),检查 URL");
    if (http > 0)
        return u("服务器返回 HTTP %1").arg(http);
    return u("连不上服务器:") + reply->errorString();
}

}

McpClient::McpClient(const McpServerConfig& cfg, QNetworkAccessManager* net, QObject* parent)
    : QObject(parent), m_cfg(cfg), m_net(net)
{
}

McpClient::~McpClient()
{
    dropPending();
    const QList<QObject*> replies = m_inflight.keys();
    m_inflight.clear();
    for (QObject* r : replies) {
        r->disconnect(this);
        delete r;
    }
    detachProcess(true);
}

void McpClient::start(ReadyFn onReady)
{
    if (m_state == State::Ready) {
        onReady(true, QString());
        return;
    }
    m_waiting.append(std::move(onReady));
    if (m_state == State::Starting)
        return;
    m_state = State::Starting;
    m_tools.clear();
    m_sessionId.clear();
    m_retriedLegacy = false;
    m_era = static_cast<Era>(eraCache().value(m_cfg.fingerprint(), int(Era::Unknown)));

    if (m_cfg.isStdio()) {
        QString err;
        if (!launch(&err)) {
            finishStart(false, err);
            return;
        }
    }
    switch (m_era) {
    case Era::Modern:
        m_version = QString::fromLatin1(kModernVersion);
        listTools(QString(), 0);
        break;
    case Era::Legacy:
        initializeLegacy();
        break;
    case Era::Unknown:
        probe();
        break;
    }
}

void McpClient::finishStart(bool ok, const QString& error)
{
    m_state = ok ? State::Ready : State::Idle;
    if (!ok) {
        m_tools.clear();
        dropPending();
        detachProcess(false);
    }
    const QList<ReadyFn> waiting = std::exchange(m_waiting, {});
    for (const ReadyFn& fn : waiting)
        fn(ok, error);
}

void McpClient::stop()
{
    const bool wasStarting = m_state == State::Starting;
    m_state = State::Idle;
    m_tools.clear();
    failAllPending(u("连接已关闭"));
    detachProcess(false);
    if (wasStarting) {
        const QList<ReadyFn> waiting = std::exchange(m_waiting, {});
        for (const ReadyFn& fn : waiting)
            fn(false, u("连接已关闭"));
    }
}

void McpClient::probe()
{
    m_version = QString::fromLatin1(kModernVersion);
    request(QStringLiteral("server/discover"), {}, kProbeTimeoutMs, [this](const Reply& r) {
        if (m_state != State::Starting)
            return;
        if (r.delivered && !r.isError && versionsIn(r.result).contains(QLatin1String(kModernVersion))) {
            m_era = Era::Modern;
            eraCache().insert(m_cfg.fingerprint(), int(Era::Modern));
            listTools(QString(), 0);
            return;
        }
        if (r.delivered && r.isError && isModernErrorCode(r.code)) {
            // 现代服务器,但不认我们的版本(或请求本身被拒):规范要求此时不得退回 initialize。
            const QStringList vs = versionsIn(r.data);
            finishStart(false, r.code == -32022
                                   ? u("服务器只支持 MCP 协议 %1,本程序使用 %2")
                                         .arg(vs.isEmpty() ? u("(未说明)") : vs.join(u("、")),
                                              QString::fromLatin1(kModernVersion))
                                   : u("服务器拒绝了请求:") + r.message);
            return;
        }
        m_era = Era::Legacy;
        eraCache().insert(m_cfg.fingerprint(), int(Era::Legacy));
        initializeLegacy();
    });
}

void McpClient::initializeLegacy()
{
    m_version.clear();
    const QJsonObject params{{QStringLiteral("protocolVersion"), QString::fromLatin1(kLegacyVersion)},
                             {QStringLiteral("capabilities"), QJsonObject{}},
                             {QStringLiteral("clientInfo"), clientInfo()}};
    request(QStringLiteral("initialize"), params, kHandshakeTimeoutMs, [this](const Reply& r) {
        if (m_state != State::Starting)
            return;
        if (!r.delivered) {
            const bool oldSse = !m_cfg.isStdio() && (r.http == 404 || r.http == 405);
            finishStart(false, oldSse ? u("握手失败(HTTP %1):这个地址可能只支持已废弃的 HTTP+SSE 传输,"
                                          "本程序不支持;请换成服务器的 Streamable HTTP 端点")
                                            .arg(r.http)
                                      : u("握手失败:") + r.transportError);
            return;
        }
        if (r.isError) {
            if (r.http == 401 || r.http == 403)
                finishStart(false, u("服务器拒绝访问(HTTP %1),检查请求头里的令牌:").arg(r.http) + r.message);
            else
                finishStart(false, (r.http >= 400 ? u("握手失败(HTTP %1):").arg(r.http) : u("握手失败:")) + r.message);
            return;
        }
        m_version = r.result.value(QStringLiteral("protocolVersion")).toString(QString::fromLatin1(kLegacyVersion));
        notify(QStringLiteral("notifications/initialized"));
        listTools(QString(), 0);
    });
}

void McpClient::listTools(const QString& cursor, int page)
{
    QJsonObject params;
    if (!cursor.isEmpty())
        params[QStringLiteral("cursor")] = cursor;
    request(QStringLiteral("tools/list"), params, kHandshakeTimeoutMs, [this, page](const Reply& r) {
        if (m_state != State::Starting)
            return;
        if (!r.delivered) {
            finishStart(false, u("读取工具清单失败:") + r.transportError);
            return;
        }
        if (r.isError) {
            if (r.code == -32601) {
                finishStart(true, QString());
                return;
            }
            finishStart(false, u("读取工具清单失败:") + r.message);
            return;
        }
        const bool mirrorHeaders = !m_cfg.isStdio() && m_era == Era::Modern;
        for (const QJsonValue& v : r.result.value(QStringLiteral("tools")).toArray()) {
            const QJsonObject o = v.toObject();
            Tool t;
            t.name = o.value(QStringLiteral("name")).toString();
            if (t.name.isEmpty())
                continue;
            t.title = o.value(QStringLiteral("title")).toString();
            t.description = o.value(QStringLiteral("description")).toString();
            t.inputSchema = o.value(QStringLiteral("inputSchema")).toObject();
            if (mirrorHeaders) {
                QSet<QString> seen;
                QString why;
                if (!collectHeaderParams(t.inputSchema, {}, t.headerParams, seen, &why)) {
                    qWarning("MCP %s: 工具 %s 已排除:%s", qUtf8Printable(m_cfg.name), qUtf8Printable(t.name),
                             qUtf8Printable(why));
                    continue;
                }
            }
            m_tools.append(t);
        }
        const QString next = r.result.value(QStringLiteral("nextCursor")).toString();
        if (!next.isEmpty() && page + 1 < kMaxToolPages)
            listTools(next, page + 1);
        else
            finishStart(true, QString());
    });
}

void McpClient::callTool(const QString& name, const QJsonObject& args, CallFn onDone)
{
    const Tool* tool = nullptr;
    for (const Tool& t : std::as_const(m_tools))
        if (t.name == name)
            tool = &t;
    if (m_state != State::Ready || !tool) {
        onDone(false, m_state != State::Ready ? u("MCP 服务器未连接") : u("服务器没有名为「%1」的工具").arg(name));
        return;
    }
    const QJsonObject params{{QStringLiteral("name"), name}, {QStringLiteral("arguments"), args}};
    request(QStringLiteral("tools/call"), params, kCallTimeoutMs, [onDone](const Reply& r) {
        if (!r.delivered) {
            onDone(false, r.transportError);
            return;
        }
        if (r.isError) {
            onDone(false, u("服务器报错(%1):%2").arg(r.code).arg(r.message));
            return;
        }
        const QString rt = r.result.value(QStringLiteral("resultType")).toString(QStringLiteral("complete"));
        if (rt == QLatin1String("input_required")) {
            onDone(false, u("这个工具需要额外输入(采样、表单或目录),本程序不提供这些能力"));
            return;
        }
        if (rt != QLatin1String("complete")) {
            onDone(false, u("服务器返回了无法识别的结果类型「%1」").arg(rt));
            return;
        }
        const QString text = flattenToolResult(r.result);
        if (r.result.value(QStringLiteral("isError")).toBool())
            onDone(false, text.isEmpty() ? u("工具报告执行失败") : text);
        else
            onDone(true, text);
    }, tool);
}

QJsonObject McpClient::withMeta(QJsonObject params) const
{
    QJsonObject meta = params.value(QStringLiteral("_meta")).toObject();
    meta[QStringLiteral("io.modelcontextprotocol/protocolVersion")] = QString::fromLatin1(kModernVersion);
    meta[QStringLiteral("io.modelcontextprotocol/clientInfo")] = clientInfo();
    meta[QStringLiteral("io.modelcontextprotocol/clientCapabilities")] = QJsonObject{};
    params[QStringLiteral("_meta")] = meta;
    return params;
}

void McpClient::request(const QString& method, QJsonObject params, int timeoutMs, ReplyFn onReply, const Tool* tool)
{
    const qint64 id = m_nextId++;
    const QJsonObject msg{{QStringLiteral("jsonrpc"), QStringLiteral("2.0")},
                          {QStringLiteral("id"), id},
                          {QStringLiteral("method"), method},
                          {QStringLiteral("params"), m_era == Era::Legacy ? params : withMeta(params)}};
    if (!m_cfg.isStdio()) {
        httpPost(msg, timeoutMs, std::move(onReply), tool);
        return;
    }
    if (!m_proc || m_proc->state() != QProcess::Running) {
        QTimer::singleShot(0, this, [onReply] {
            Reply r;
            r.transportError = u("服务器进程未在运行");
            onReply(r);
        });
        return;
    }
    auto* timer = new QTimer(this);
    timer->setSingleShot(true);
    connect(timer, &QTimer::timeout, this, [this, id, timeoutMs] {
        const auto it = m_pending.find(id);
        if (it == m_pending.end())
            return;
        const Pending p = it.value();
        m_pending.erase(it);
        p.timer->deleteLater();
        notify(QStringLiteral("notifications/cancelled"),
               QJsonObject{{QStringLiteral("requestId"), id}, {QStringLiteral("reason"), QStringLiteral("timeout")}});
        Reply r;
        r.transportError = u("等待服务器响应超时(%1 秒)").arg(timeoutMs / 1000);
        p.fn(r);
    });
    timer->start(timeoutMs);
    m_pending.insert(id, Pending{std::move(onReply), timer});
    writeMessage(msg);
}

void McpClient::notify(const QString& method, const QJsonObject& params)
{
    const QJsonObject msg{{QStringLiteral("jsonrpc"), QStringLiteral("2.0")},
                          {QStringLiteral("method"), method},
                          {QStringLiteral("params"), params}};
    if (m_cfg.isStdio()) {
        if (m_proc && m_proc->state() == QProcess::Running)
            writeMessage(msg);
        return;
    }
    httpPost(msg, kHandshakeTimeoutMs, [](const Reply&) {}, nullptr);
}

void McpClient::dropPending()
{
    for (const Pending& p : std::as_const(m_pending))
        p.timer->deleteLater();
    m_pending.clear();
}

void McpClient::failAllPending(const QString& why)
{
    Reply r;
    r.transportError = why;
    const QHash<qint64, Pending> pending = std::exchange(m_pending, {});
    for (const Pending& p : pending) {
        p.timer->deleteLater();
        p.fn(r);
    }
    const QHash<QObject*, ReplyFn> inflight = std::exchange(m_inflight, {});
    for (auto it = inflight.begin(); it != inflight.end(); ++it) {
        it.value()(r);
        if (auto* reply = qobject_cast<QNetworkReply*>(it.key()))
            reply->abort();
    }
}

bool McpClient::launch(QString* error)
{
    detachProcess(true);
    m_outBuf.clear();
    m_errTail.clear();

    const QProcessEnvironment inherited = QProcessEnvironment::systemEnvironment();
    QProcessEnvironment env;
    for (const QString& name : {
             QStringLiteral("SystemRoot"), QStringLiteral("WINDIR"),
             QStringLiteral("COMSPEC"), QStringLiteral("PATH"), QStringLiteral("PATHEXT"),
             QStringLiteral("TEMP"), QStringLiteral("TMP"),
             QStringLiteral("USERPROFILE"), QStringLiteral("APPDATA"),
             QStringLiteral("LOCALAPPDATA"), QStringLiteral("PROGRAMDATA")}) {
        if (inherited.contains(name))
            env.insert(name, inherited.value(name));
    }
    for (const QString& kv : std::as_const(m_cfg.env)) {
        const int eq = kv.indexOf(QLatin1Char('='));
        if (eq > 0)
            env.insert(kv.left(eq).trimmed(), kv.mid(eq + 1));
    }
    const QString cwd = m_cfg.cwd.trimmed();
    if (!cwd.isEmpty() && !QFileInfo(cwd).isDir()) {
        *error = u("工作目录不存在:") + cwd;
        return false;
    }

    QString program = m_cfg.command.trimmed();
    if (!cwd.isEmpty() && QFileInfo(program).isRelative() &&
        (program.contains(QLatin1Char('/')) || program.contains(QLatin1Char('\\'))))
        program = QDir(cwd).absoluteFilePath(program);
    QString resolved;
    if (QFileInfo(program).isAbsolute()) {
        resolved = QStandardPaths::findExecutable(QFileInfo(program).fileName(), {QFileInfo(program).absolutePath()});
    } else {
        const QStringList paths = env.value(QStringLiteral("PATH")).split(QDir::listSeparator(), Qt::SkipEmptyParts);
        resolved = QStandardPaths::findExecutable(program, paths);
    }
    if (resolved.isEmpty()) {
        *error = u("找不到命令「%1」:确认它已安装并在 PATH 中(npx 来自 Node.js,uvx 来自 uv)").arg(m_cfg.command);
        return false;
    }

    auto* p = new QProcess(this);
    p->setProcessChannelMode(QProcess::SeparateChannels);
    p->setProcessEnvironment(env);
    if (!cwd.isEmpty())
        p->setWorkingDirectory(cwd);
    const QString suffix = QFileInfo(resolved).suffix().toLower();
    if (suffix == QLatin1String("cmd") || suffix == QLatin1String("bat")) {
        QString line = QStringLiteral("/d /s /c \"") + cmdQuote(QDir::toNativeSeparators(resolved));
        for (const QString& a : std::as_const(m_cfg.args))
            line += QLatin1Char(' ') + cmdQuote(a);
        line += QLatin1Char('"');
        p->setProgram(env.value(QStringLiteral("ComSpec"), QStringLiteral("cmd.exe")));
        p->setNativeArguments(line);
    } else {
        p->setProgram(resolved);
        p->setArguments(m_cfg.args);
    }
#ifdef Q_OS_WIN
    p->setCreateProcessArgumentsModifier(
        [](QProcess::CreateProcessArguments* a) { a->flags |= CREATE_NO_WINDOW; });
#endif
    connect(p, &QProcess::readyReadStandardOutput, this, &McpClient::onStdout);
    connect(p, &QProcess::readyReadStandardError, this, [this, p] {
        m_errTail += p->readAllStandardError();
        if (m_errTail.size() > kMaxErrTail)
            m_errTail = m_errTail.right(kMaxErrTail);
    });
    connect(p, &QProcess::finished, this, &McpClient::onProcessFinished);
    p->start();
    if (!p->waitForStarted(10000)) {
        *error = u("无法启动「%1」:%2").arg(QDir::toNativeSeparators(resolved), p->errorString());
        p->disconnect(this);
        delete p;
        return false;
    }
    m_proc = p;

#ifdef Q_OS_WIN
    if (HANDLE job = CreateJobObjectW(nullptr, nullptr)) {
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION info{};
        info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        SetInformationJobObject(job, JobObjectExtendedLimitInformation, &info, sizeof(info));
        if (HANDLE h = OpenProcess(PROCESS_SET_QUOTA | PROCESS_TERMINATE, FALSE, DWORD(p->processId()))) {
            if (AssignProcessToJobObject(job, h))
                m_job = job;
            CloseHandle(h);
        }
        if (!m_job)
            CloseHandle(job);
    }
#endif
    return true;
}

void McpClient::detachProcess(bool immediate)
{
    if (!m_proc)
        return;
    QProcess* p = m_proc;
    m_proc = nullptr;
    p->disconnect(this);
#ifdef Q_OS_WIN
    std::shared_ptr<void> job(m_job, [](void* h) {
        if (h)
            CloseHandle(static_cast<HANDLE>(h));
    });
#else
    std::shared_ptr<void> job;
#endif
    m_job = nullptr;
    if (immediate) {
        p->closeWriteChannel();
        job.reset();
        if (p->state() != QProcess::NotRunning) {
            p->kill();
            p->waitForFinished(500);
        }
        delete p;
        return;
    }
    p->setParent(QCoreApplication::instance());
    p->closeWriteChannel();
    QObject::connect(p, &QProcess::finished, p, [p, job]() mutable {
        job.reset();
        p->deleteLater();
    });
    QTimer::singleShot(2000, p, [p, job]() mutable {
        job.reset();
        if (p->state() != QProcess::NotRunning)
            p->kill();
    });
}

void McpClient::onStdout()
{
    if (!m_proc)
        return;
    m_outBuf += m_proc->readAllStandardOutput();
    qsizetype nl;
    while ((nl = m_outBuf.indexOf('\n')) >= 0) {
        const QByteArray line = m_outBuf.left(nl);
        m_outBuf.remove(0, nl + 1);
        handleLine(line);
        if (!m_proc)
            return;
    }
    if (m_outBuf.size() > kMaxLineBytes) {
        qWarning("MCP %s: 单行输出超过 16 MB,断开", qUtf8Printable(m_cfg.name));
        stop();
    }
}

void McpClient::handleLine(const QByteArray& raw)
{
    const QByteArray line = raw.trimmed();
    if (line.isEmpty())
        return;
    const QJsonObject msg = QJsonDocument::fromJson(line).object();
    if (msg.isEmpty())
        return; // 规范禁止往 stdout 写非 MCP 内容,但有的服务器会打横幅:忽略,不当成错误
    if (msg.contains(QLatin1String("method"))) {
        if (!msg.contains(QLatin1String("id")))
            return;
        QJsonObject resp{{QStringLiteral("jsonrpc"), QStringLiteral("2.0")}, {QStringLiteral("id"), msg.value(QStringLiteral("id"))}};
        if (msg.value(QStringLiteral("method")).toString() == QLatin1String("ping"))
            resp[QStringLiteral("result")] = QJsonObject{};
        else
            resp[QStringLiteral("error")] = QJsonObject{{QStringLiteral("code"), -32601},
                                                        {QStringLiteral("message"), QStringLiteral("Method not found")}};
        writeMessage(resp);
        return;
    }
    const QJsonValue idv = msg.value(QStringLiteral("id"));
    const qint64 id = idv.isString() ? idv.toString().toLongLong() : idv.toInteger(-1);
    const auto it = m_pending.find(id);
    if (it == m_pending.end())
        return;
    const Pending p = it.value();
    m_pending.erase(it);
    p.timer->deleteLater();
    Reply r;
    r.delivered = true;
    if (msg.contains(QLatin1String("error"))) {
        const QJsonObject e = msg.value(QStringLiteral("error")).toObject();
        r.isError = true;
        r.code = e.value(QStringLiteral("code")).toInt();
        r.message = e.value(QStringLiteral("message")).toString();
        r.data = e.value(QStringLiteral("data"));
    } else {
        r.result = msg.value(QStringLiteral("result")).toObject();
    }
    p.fn(r);
}

void McpClient::writeMessage(const QJsonObject& msg)
{
    if (m_proc)
        m_proc->write(QJsonDocument(msg).toJson(QJsonDocument::Compact) + '\n');
}

QString McpClient::stderrTail() const
{
    const QString t = QString::fromUtf8(m_errTail).trimmed();
    if (t.isEmpty())
        return QString();
    const QStringList lines = t.split(QLatin1Char('\n'));
    return lines.mid(qMax<qsizetype>(0, lines.size() - 3)).join(QLatin1Char(' ')).trimmed();
}

void McpClient::onProcessFinished()
{
    if (!m_proc)
        return;
    const int code = m_proc->exitCode();
    const bool crashed = m_proc->exitStatus() == QProcess::CrashExit;
    detachProcess(true);
    QString why = crashed ? u("服务器进程崩溃") : u("服务器进程已退出(代码 %1)").arg(code);
    if (const QString tail = stderrTail(); !tail.isEmpty())
        why += u(":") + tail;

    if (m_state == State::Starting && m_era == Era::Unknown && !m_retriedLegacy) {
        dropPending();
        m_retriedLegacy = true;
        m_era = Era::Legacy;
        eraCache().insert(m_cfg.fingerprint(), int(Era::Legacy));
        QString err;
        if (!launch(&err)) {
            finishStart(false, err);
            return;
        }
        initializeLegacy();
        return;
    }
    const bool wasStarting = m_state == State::Starting;
    m_state = State::Idle;
    m_tools.clear();
    failAllPending(why);
    if (wasStarting) {
        const QList<ReadyFn> waiting = std::exchange(m_waiting, {});
        for (const ReadyFn& fn : waiting)
            fn(false, why);
    }
}

void McpClient::httpPost(const QJsonObject& msg, int timeoutMs, ReplyFn onReply, const Tool* tool)
{
    const QString method = msg.value(QStringLiteral("method")).toString();
    const bool isNotification = !msg.contains(QLatin1String("id"));
    const QJsonValue id = msg.value(QStringLiteral("id"));

    QNetworkRequest req{QUrl(m_cfg.url.trimmed())};
    req.setHeader(QNetworkRequest::ContentTypeHeader, QStringLiteral("application/json"));
    req.setRawHeader("Accept", "application/json, text/event-stream");
    for (const QString& h : std::as_const(m_cfg.headers)) {
        const int colon = h.indexOf(QLatin1Char(':'));
        if (colon <= 0 || h.contains(QLatin1Char('\r')) || h.contains(QLatin1Char('\n')))
            continue;
        req.setRawHeader(h.left(colon).trimmed().toUtf8(), h.mid(colon + 1).trimmed().toUtf8());
    }
    if (m_era != Era::Legacy) {
        req.setRawHeader("MCP-Protocol-Version", kModernVersion);
        req.setRawHeader("Mcp-Method", method.toUtf8());
        const QJsonObject params = msg.value(QStringLiteral("params")).toObject();
        if (method == QLatin1String("tools/call")) {
            req.setRawHeader("Mcp-Name", headerValue(params.value(QStringLiteral("name")).toString()));
            if (tool) {
                const QJsonObject args = params.value(QStringLiteral("arguments")).toObject();
                for (const HeaderParam& hp : tool->headerParams) {
                    QJsonValue v = args;
                    for (const QString& k : hp.path)
                        v = v.toObject().value(k);
                    if (v.isString())
                        req.setRawHeader(hp.header, headerValue(v.toString()));
                    else if (v.isBool())
                        req.setRawHeader(hp.header, v.toBool() ? "true" : "false");
                    else if (v.isDouble() && v.toDouble() == double(qint64(v.toDouble())))
                        req.setRawHeader(hp.header, QByteArray::number(qint64(v.toDouble())));
                }
            }
        }
    } else {
        if (!m_version.isEmpty())
            req.setRawHeader("MCP-Protocol-Version", m_version.toLatin1());
        if (!m_sessionId.isEmpty())
            req.setRawHeader("Mcp-Session-Id", m_sessionId.toLatin1());
    }

    QNetworkReply* reply = m_net->post(req, QJsonDocument(msg).toJson(QJsonDocument::Compact));
    reply->setParent(this);

    struct Stream {
        QByteArray buf;
        qsizetype received = 0;
        bool delivered = false;
        bool tooLarge = false;
    };
    auto stream = std::make_shared<Stream>();
    auto once = std::make_shared<bool>(false);
    onReply = [once, inner = std::move(onReply)](const Reply& r) {
        if (*once)
            return;
        *once = true;
        inner(r);
    };
    m_inflight.insert(reply, onReply);
    connect(reply, &QObject::destroyed, this, [this, reply] { m_inflight.remove(reply); });

    auto* timer = new QTimer(reply);
    timer->setSingleShot(true);
    connect(timer, &QTimer::timeout, reply, [reply] {
        reply->setProperty("bw.timedOut", true);
        reply->abort();
    });
    timer->start(timeoutMs);

    const auto deliver = [stream, onReply, reply](const QJsonObject& m) {
        if (stream->delivered)
            return;
        stream->delivered = true;
        Reply r;
        r.delivered = true;
        r.http = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
        if (m.contains(QLatin1String("error"))) {
            const QJsonObject e = m.value(QStringLiteral("error")).toObject();
            r.isError = true;
            r.code = e.value(QStringLiteral("code")).toInt();
            r.message = e.value(QStringLiteral("message")).toString();
            r.data = e.value(QStringLiteral("data"));
        } else {
            r.result = m.value(QStringLiteral("result")).toObject();
        }
        onReply(r);
    };
    const auto isSse = [reply] {
        return reply->header(QNetworkRequest::ContentTypeHeader).toString().contains(QLatin1String("text/event-stream"),
                                                                                    Qt::CaseInsensitive);
    };
    const auto drainSse = [stream, id, deliver, reply](bool atEnd) {
        stream->buf.replace("\r\n", "\n");
        while (!stream->delivered) {
            qsizetype end = stream->buf.indexOf("\n\n");
            if (end < 0) {
                if (!atEnd || stream->buf.trimmed().isEmpty())
                    return;
                end = stream->buf.size();
            }
            const QByteArray event = stream->buf.left(end);
            stream->buf.remove(0, qMin(end + 2, stream->buf.size()));
            QByteArray data;
            for (const QByteArray& l : event.split('\n'))
                if (l.startsWith("data:"))
                    data += (l.size() > 5 && l.at(5) == ' ' ? l.mid(6) : l.mid(5)) + '\n';
            const QJsonObject m = QJsonDocument::fromJson(data).object();
            if (!m.contains(QLatin1String("method")) && m.value(QStringLiteral("id")) == id &&
                (m.contains(QLatin1String("result")) || m.contains(QLatin1String("error")))) {
                deliver(m);
                reply->abort();
            }
        }
    };

    connect(reply, &QNetworkReply::readyRead, this, [reply, stream, isSse, drainSse, isNotification] {
        if (stream->delivered)
            return;
        const QByteArray chunk = reply->readAll();
        stream->received += chunk.size();
        if (stream->received > kMaxLineBytes) {
            stream->tooLarge = true;
            reply->abort();
            return;
        }
        if (isNotification)
            return; // 通知响应体只计数并丢弃，不能无限留在 QNetworkReply 内。
        stream->buf += chunk;
        if (isSse())
            drainSse(false);
    });
    connect(reply, &QNetworkReply::finished, this,
            [this, reply, stream, isSse, drainSse, deliver, onReply, isNotification] {
        reply->deleteLater();
        if (m_era == Era::Legacy) {
            const QByteArray sid = reply->rawHeader("Mcp-Session-Id");
            if (!sid.isEmpty())
                m_sessionId = QString::fromLatin1(sid);
        }
        if (stream->delivered)
            return;
        const QByteArray tail = reply->readAll();
        stream->received += tail.size();
        if (stream->received > kMaxLineBytes)
            stream->tooLarge = true;
        if (!isNotification && !stream->tooLarge)
            stream->buf += tail;
        const int http = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
        if (stream->tooLarge) {
            Reply r;
            r.http = http;
            r.transportError = u("MCP 响应超过 16 MB 上限,已中止");
            onReply(r);
            return;
        }
        if (isNotification) {
            Reply r;
            r.delivered = http >= 200 && http < 300;
            r.http = http;
            onReply(r);
            return;
        }
        if (isSse()) {
            drainSse(true);
            if (stream->delivered)
                return;
        } else {
            const QJsonObject m = QJsonDocument::fromJson(stream->buf).object();
            if (m.contains(QLatin1String("result")) || m.contains(QLatin1String("error"))) {
                deliver(m);
                return;
            }
        }
        Reply r;
        r.http = http;
        r.transportError = reply->error() != QNetworkReply::NoError ? httpFailure(reply)
                                                                    : u("服务器的响应里没有对应的 JSON-RPC 结果");
        onReply(r);
    });
}
