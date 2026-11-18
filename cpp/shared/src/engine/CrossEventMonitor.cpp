#include "bulwark/engine/CrossEventMonitor.h"
#include "bulwark/engine/NetworkEndpoint.h"
#include "bulwark/engine/SensitivePaths.h"
#include <QMutexLocker>
#include <QRegularExpression>
#include <QSet>

namespace bulwark::engine {
namespace {
constexpr qint64 window = 30 * 60 * 1000;
void expire(QHash<QString, qint64>& paths, qint64 now) {
    for (auto it = paths.begin(); it != paths.end();) {
        if (now < it.value() || now - it.value() > window) it = paths.erase(it); else ++it;
    }
}
}
QStringList CrossEventMonitor::groups(const SecurityEvent& e, bool restart) {
    QStringList out;
    if (e.actorPid <= 4 || !e.actorCreationFileTime || e.actorPath.isEmpty()) return out;
    out << QStringLiteral("process|%1|%2|%3").arg(e.actorPid).arg(*e.actorCreationFileTime).arg(e.actorPath.toLower());
    QString parent = e.parentPath.toLower();
    parent.replace(QLatin1Char('/'), QLatin1Char('\\'));
    const QString parentName = parent.mid(parent.lastIndexOf(QLatin1Char('\\')) + 1);
    static const QSet<QString> brokers = { "explorer.exe", "services.exe", "svchost.exe", "wmiprvse.exe",
        "taskeng.exe", "taskhostw.exe", "wininit.exe", "userinit.exe", "csrss.exe", "sihost.exe", "runtimebroker.exe" };
    if (e.parentPid > 4 && e.parentCreationFileTime && !parent.isEmpty() && !brokers.contains(parentName))
        out << QStringLiteral("process|%1|%2|%3").arg(e.parentPid).arg(*e.parentCreationFileTime).arg(e.parentPath.toLower());
    // Restarts can only be joined when a verified OS user identity is present.
    if (restart && !e.actorUserSid.isEmpty())
        out << QStringLiteral("restart|") + e.actorUserSid + QLatin1Char('|') + e.actorPath.toLower();
    return out;
}
void CrossEventMonitor::prune(qint64 now) {
    for (auto it = states_.begin(); it != states_.end();) {
        if (now < it->last || now - it->last > window) it = states_.erase(it); else ++it;
    }
    // State and per-state file counts are bounded even under adversarial input.
    if (states_.size() >= 2048) states_.clear();
}
CrossEventMonitor::Result CrossEventMonitor::damage(const SecurityEvent& e, const QStringList& paths) {
    Result result;
    if (e.kernelBlocked || e.userTrusted || paths.isEmpty()) return result;
    const qint64 now = e.timestampUtc.toMSecsSinceEpoch();
    QMutexLocker lock(&mutex_);
    prune(now);
    for (const QString& key : groups(e, true)) {
        State& s = states_[key];
        s.last = now;
        expire(s.damaged, now);
        for (const QString& path : paths) {
            // Do not refresh old damage on every unrelated event.
            if (!s.damaged.contains(path) && s.damaged.size() < 512) s.damaged.insert(path, now);
        }
        if (s.damaged.size() >= 6) {
            result = { 55, true, QStringLiteral("30 分钟内同一进程实例、同一父进程实例或同用户同程序接力破坏 %1 个不同文件，要求可逆收容(T1486)").arg(s.damaged.size()) };
        }
    }
    return result;
}
CrossEventMonitor::Result CrossEventMonitor::observe(const SecurityEvent& e) {
    Result result;
    if (e.kernelBlocked || e.userTrusted) return result;
    if (e.type != EventType::FileRead && e.type != EventType::ProcessCreate && e.type != EventType::NetworkConnect)
        return result;
    const qint64 now = e.timestampUtc.toMSecsSinceEpoch();
    QMutexLocker lock(&mutex_);
    prune(now);
    static const QRegularExpression archive(QStringLiteral(R"((?:^|[\\\s"'])(?:7z(?:a|g)?|rar|winrar|tar)(?:\.exe)?(?:["']?\s+)(?:a\s|[^\r\n]*-c)|\bcompress-archive\b)"), QRegularExpression::CaseInsensitiveOption);
    for (const QString& key : groups(e, false)) {
        State& s = states_[key];
        s.last = now;
        expire(s.secrets, now);
        if (e.type == EventType::FileRead && isDeveloperCredential(e.target)) {
            if (s.secrets.size() < 64) s.secrets.insert(e.target.toLower(), now);
        } else if (e.type == EventType::ProcessCreate && !s.secrets.isEmpty()
                   && archive.match(e.commandLine).hasMatch()) {
            s.archived = now;
        } else if (e.type == EventType::NetworkConnect && !s.secrets.isEmpty()
                   && s.archived >= 0 && s.archived <= now && now - s.archived <= 10 * 60 * 1000) {
            const auto ep = NetworkEndpoint::parse(e.target);
            if (ep && ep->isPublicUnicast()) {
                result = { 50, true, QStringLiteral("关联到开发凭据读取、归档命令和后续连接 %1；可能外传，要求确认，尚未证明已上传秘密正文(T1005/T1560/T1041)").arg(ep->text()) };
            }
        }
    }
    return result;
}
}
