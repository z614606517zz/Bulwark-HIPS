#include "bulwark/service/EventHistoryStore.h"
#include "bulwark/service/Logger.h"
#include "bulwark/service/AtomicFile.h"

#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QJsonDocument>
#include <QJsonObject>

#include <QJsonParseError>
#include <QSet>

#include <algorithm>
#include <condition_variable>
#include <deque>
#include <functional>
#include <mutex>
#include <optional>
#include <thread>

namespace bulwark::service {

using bulwark::ipc::EventLogPayload;

struct EventHistoryStore::Impl {
    static constexpr int kMaxRecords = 1000;
    static constexpr int kRecentRecords = 500;           // newest window is never priority-evicted
    static constexpr qint64 kMaxFileBytes = 24LL * 1024 * 1024;
    static constexpr size_t kQueueCapacity = 20000;
    static constexpr int kMaxBatch = 512;

    QString path;
    std::mutex mutex;
    std::condition_variable cv;
    std::deque<QString> queue;
    std::deque<EventLogPayload> buffer;
    std::thread worker;
    bool disposed = false;
    bool clearRequested = false;
    quint64 droppedRecords = 0;            // 因落盘队列满而丢弃的记录数(取证缺口,必须可见)

    Impl() {
        const QString dir = QDir(programDataDir()).filePath(QStringLiteral("history"));
        QDir().mkpath(dir);
        path = QDir(dir).filePath(QStringLiteral("events.jsonl"));
        load();
        worker = std::thread([this] { writeLoop(); });
    }

    ~Impl() {
        {
            std::lock_guard<std::mutex> lk(mutex);
            disposed = true;
        }
        cv.notify_all();
        if (worker.joinable()) worker.join();
    }

    void appendRetained(const EventLogPayload& payload) {
        buffer.push_back(payload);
        while (static_cast<int>(buffer.size()) > kMaxRecords) {
            const int recent = std::min(kRecentRecords, static_cast<int>(buffer.size()));
            const auto oldestEnd = buffer.end() - recent;
            const auto oldestWithAction = [this, oldestEnd](bulwark::VerdictAction action) {
                return std::find_if(buffer.begin(), oldestEnd,
                                    [action](const EventLogPayload& p) { return p.action == action; });
            };
            auto victim = oldestWithAction(bulwark::VerdictAction::Allow);
            if (victim == oldestEnd)
                victim = oldestWithAction(bulwark::VerdictAction::Ask);
            if (victim == oldestEnd)
                victim = buffer.begin();
            buffer.erase(victim);
        }
    }

    void load() {
        QFile f(path);
        if (!f.exists() || !f.open(QIODevice::ReadOnly)) return;
        const QByteArray raw = f.readAll();
        f.close();
        const QList<QByteArray> lines = raw.split('\n');
        for (const QByteArray& rawLine : lines) {
            const QByteArray line = rawLine.trimmed();
            if (line.isEmpty()) continue;
            QJsonParseError err{};
            const QJsonDocument doc = QJsonDocument::fromJson(line, &err);
            if (err.error == QJsonParseError::NoError && doc.isObject())
                appendRetained(EventLogPayload::fromJson(doc.object()));
        }
    }

    QString serialize(const EventLogPayload& p) const {
        return QString::fromUtf8(QJsonDocument(p.toJson()).toJson(QJsonDocument::Compact));
    }

    void add(const EventLogPayload& payload) {
        const QString line = serialize(payload);
        {
            std::lock_guard<std::mutex> lk(mutex);
            appendRetained(payload);
            if (queue.size() < kQueueCapacity) {
                queue.push_back(line);
            } else {
                ++droppedRecords;
                if (droppedRecords == 1 || droppedRecords % 1000 == 0) {
                    Logger(QStringLiteral("bulwark.service.EventHistory"))
                        .warning(QStringLiteral("事件历史落盘队列已满(容量 %1),累计丢弃 %2 条记录 —— "
                                                "取证时间线在此期间不完整")
                                     .arg(kQueueCapacity).arg(droppedRecords));
                }
            }
        }
        cv.notify_one();
    }

    QList<EventLogPayload> getRecent() {
        std::lock_guard<std::mutex> lk(mutex);
        QList<EventLogPayload> out;
        out.reserve(static_cast<int>(buffer.size()));
        for (const EventLogPayload& p : buffer) out.append(p);
        return out;
    }

    void clear() {
        {
            std::lock_guard<std::mutex> lk(mutex);
            buffer.clear();
            queue.clear();
            clearRequested = true;
        }
        cv.notify_one();
    }

    void writeLoop() {
        for (;;) {
            QByteArray batch;
            bool doClear = false;
            {
                std::unique_lock<std::mutex> lk(mutex);
                cv.wait(lk, [this] { return disposed || !queue.empty() || clearRequested; });
                if (clearRequested) { clearRequested = false; doClear = true; }
                int count = 0;
                while (count < kMaxBatch && !queue.empty()) {
                    batch += queue.front().toUtf8();
                    batch += '\n';
                    queue.pop_front();
                    ++count;
                }
                if (batch.isEmpty() && !doClear) {
                    if (disposed) return;
                    continue;
                }
            }
            if (doClear) {
                QFile f(path);
                if (f.open(QIODevice::WriteOnly | QIODevice::Truncate)) f.close();
            }
            if (!batch.isEmpty()) {
                QFile f(path);
                if (f.open(QIODevice::Append | QIODevice::WriteOnly)) {
                    f.write(batch);
                    f.close();
                }
            }
            compact();
        }
    }

    void compact() {
        if (QFileInfo(path).size() < kMaxFileBytes) return;
        QByteArray out;
        {
            std::lock_guard<std::mutex> lk(mutex);
            if (!queue.empty() || clearRequested)
                return;
            for (const EventLogPayload& p : buffer) {
                out += serialize(p).toUtf8();
                out += '\n';
            }
        }
        writeFileAtomically(path, out, QStringLiteral("事件历史压缩"));
    }
};

namespace {

constexpr int kMaxScanLines = 40000;   // 单次查询最多回看多少条(护栏:防病态大文件卡死)
constexpr int kHardLimit = 5000;

void scanBackwards(const QString& path, int maxLines,
                   const std::function<bool(const QByteArray& line)>& visit)
{
    QFile f(path);
    if (!f.exists() || !f.open(QIODevice::ReadOnly))
        return;
    const QByteArray raw = f.readAll();
    f.close();
    if (raw.isEmpty())
        return;

    int end = raw.size();
    int scanned = 0;
    while (end > 0 && scanned < maxLines) {
        int start = raw.lastIndexOf('\n', end - 1);
        const int from = start + 1;
        const QByteArray line = raw.mid(from, end - from).trimmed();
        end = start;
        if (line.isEmpty())
            continue;
        ++scanned;
        if (!visit(line))
            return;
    }
}

std::optional<bulwark::ipc::EventLogPayload> parseLine(const QByteArray& line)
{
    QJsonParseError err{};
    const QJsonDocument doc = QJsonDocument::fromJson(line, &err);
    if (err.error != QJsonParseError::NoError || !doc.isObject())
        return std::nullopt;
    return bulwark::ipc::EventLogPayload::fromJson(doc.object());
}

QDateTime earliestTimestamp(const QString& path)
{
    QFile f(path);
    if (!f.exists() || !f.open(QIODevice::ReadOnly))
        return QDateTime();
    const QByteArray line = f.readLine(64 * 1024).trimmed();
    f.close();
    if (const auto p = parseLine(line))
        return p->event.timestampUtc;
    return QDateTime();
}

bool belongsToProcess(const bulwark::ipc::EventLogPayload& p, int pid, bool includeTree)
{
    const bulwark::SecurityEvent& e = p.event;
    if (e.actorPid == pid)
        return true;
    if (!includeTree)
        return false;
    if (e.parentPid == pid || e.originatorPid == pid)
        return true;
    for (const bulwark::ChainEventInfo& c : e.chainContext)
        if (c.actorPid == pid)
            return true;
    return false;
}

bool matchesText(const bulwark::ipc::EventLogPayload& p, const QString& text)
{
    if (text.isEmpty())
        return true;
    const bulwark::SecurityEvent& e = p.event;
    const Qt::CaseSensitivity ci = Qt::CaseInsensitive;
    return e.actorPath.contains(text, ci) || e.target.contains(text, ci)
        || e.commandLine.contains(text, ci) || e.actorPublisher.contains(text, ci)
        || e.detail.contains(text, ci) || e.matchedRuleNote.contains(text, ci)
        || e.originService.contains(text, ci) || e.originTask.contains(text, ci);
}

}

EventHistoryStore::EventHistoryStore() : d_(std::make_unique<Impl>()) {}
EventHistoryStore::~EventHistoryStore() = default;

void EventHistoryStore::add(const bulwark::ipc::EventLogPayload& payload) { d_->add(payload); }
QList<bulwark::ipc::EventLogPayload> EventHistoryStore::getRecent() { return d_->getRecent(); }
void EventHistoryStore::clear() { d_->clear(); }

bulwark::ipc::TimelineResponsePayload
EventHistoryStore::query(const bulwark::ipc::TimelineRequestPayload& req)
{
    bulwark::ipc::TimelineResponsePayload res;
    res.requestId = req.requestId;
    res.earliestUtc = earliestTimestamp(d_->path);

    const int limit = std::clamp(req.limit <= 0 ? 500 : req.limit, 1, kHardLimit);
    const QSet<int> types(req.types.begin(), req.types.end());
    const QSet<int> actions(req.actions.begin(), req.actions.end());
    const QString text = req.text.trimmed();

    QList<bulwark::ipc::EventLogPayload> hits;
    int scanned = 0;
    int matched = 0;
    int belowWindow = 0;

    const QByteArray textNeedle = text.toUtf8().toLower();

    scanBackwards(d_->path, kMaxScanLines, [&](const QByteArray& line) {
        ++scanned;
        if (!textNeedle.isEmpty() && !line.toLower().contains(textNeedle))
            return true;
        const auto parsed = parseLine(line);
        if (!parsed)
            return true;
        const bulwark::SecurityEvent& e = parsed->event;

        if (req.fromUtc.isValid() && e.timestampUtc.isValid() && e.timestampUtc < req.fromUtc) {
            if (++belowWindow > 200)
                return false;
            return true;
        }
        belowWindow = 0;
        if (req.toUtc.isValid() && e.timestampUtc.isValid() && e.timestampUtc > req.toUtc)
            return true;
        if (!types.isEmpty() && !types.contains(static_cast<int>(e.type)))
            return true;
        if (!actions.isEmpty() && !actions.contains(static_cast<int>(parsed->action)))
            return true;
        if (e.riskScore < req.minRiskScore)
            return true;
        if (req.pid > 0 && !belongsToProcess(*parsed, req.pid, req.includeProcessTree))
            return true;
        if (!matchesText(*parsed, text))
            return true;

        ++matched;
        if (hits.size() < limit)
            hits.append(*parsed);
        else
            res.truncated = true;
        return true;
    });

    res.scanned = scanned;
    res.matched = matched;
    std::reverse(hits.begin(), hits.end());
    res.events = hits;
    res.message = res.truncated
        ? QStringLiteral("扫描 %1 条,命中 %2 条,已按上限返回最近 %3 条")
              .arg(scanned).arg(matched).arg(hits.size())
        : QStringLiteral("扫描 %1 条,命中 %2 条").arg(scanned).arg(matched);
    return res;
}

QList<bulwark::ipc::EventLogPayload>
EventHistoryStore::eventsInWindow(const QDateTime& fromUtc, const QDateTime& toUtc, int maxEvents)
{
    QList<bulwark::ipc::EventLogPayload> out;
    const int cap = std::clamp(maxEvents <= 0 ? 2000 : maxEvents, 1, kHardLimit);
    int belowWindow = 0;

    scanBackwards(d_->path, kMaxScanLines, [&](const QByteArray& line) {
        const auto parsed = parseLine(line);
        if (!parsed)
            return true;
        const QDateTime ts = parsed->event.timestampUtc;
        if (fromUtc.isValid() && ts.isValid() && ts < fromUtc)
            return ++belowWindow <= 200;
        belowWindow = 0;
        if (toUtc.isValid() && ts.isValid() && ts > toUtc)
            return true;
        out.append(*parsed);
        return out.size() < cap;
    });

    std::reverse(out.begin(), out.end());
    return out;
}

std::optional<bulwark::ipc::EventLogPayload> EventHistoryStore::findById(const QUuid& id)
{
    if (id.isNull())
        return std::nullopt;
    for (const bulwark::ipc::EventLogPayload& p : d_->getRecent())
        if (p.event.id == id)
            return p;

    std::optional<bulwark::ipc::EventLogPayload> found;
    scanBackwards(d_->path, kMaxScanLines, [&](const QByteArray& line) {
        if (!line.contains(id.toString(QUuid::WithoutBraces).toUtf8()))
            return true;
        const auto parsed = parseLine(line);
        if (parsed && parsed->event.id == id) {
            found = parsed;
            return false;
        }
        return true;
    });
    return found;
}

}
