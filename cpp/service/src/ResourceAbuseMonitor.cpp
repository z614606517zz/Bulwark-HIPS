#include "bulwark/service/ResourceAbuseMonitor.h"
#include "bulwark/service/SelfHardening.h"

#include <QDateTime>
#include <QDir>
#include <QFileInfo>
#include <QTimer>

namespace bulwark::service {

namespace {

bool isTrustedDir(const QString& path) {
    QString p = QDir::cleanPath(path.trimmed());
    p.replace(QLatin1Char('/'), QLatin1Char('\\'));
    p = p.toLower();
    if (p.isEmpty())
        return false;

    QStringList roots;
    roots << qEnvironmentVariable("SystemRoot")
          << qEnvironmentVariable("ProgramFiles")
          << qEnvironmentVariable("ProgramFiles(x86)");
    QString programData = qEnvironmentVariable("ProgramData", QStringLiteral("C:/ProgramData"));
    roots << QDir(programData).filePath(QStringLiteral("Bulwark"));
    for (QString root : roots) {
        root = QDir::cleanPath(root.trimmed());
        root.replace(QLatin1Char('/'), QLatin1Char('\\'));
        root = root.toLower();
        if (!root.isEmpty() && p.startsWith(root + QLatin1Char('\\')))
            return true;
    }
    return false;
}

QString keyOf(const QString& path) {
    return path.trimmed().isEmpty() ? QStringLiteral("(unknown)") : path.toLower();
}

}

ResourceAbuseMonitor::ResourceAbuseMonitor(QObject* parent) : QObject(parent) {}

ResourceAbuseMonitor::~ResourceAbuseMonitor() { stop(); }

void ResourceAbuseMonitor::start() {
    if (started_)
        return;
    started_ = true;

    selfCheckTimer_ = new QTimer(this);
    selfCheckTimer_->setInterval(kSelfCheckMs);
    connect(selfCheckTimer_, &QTimer::timeout, this, &ResourceAbuseMonitor::onSelfCheckTick);
    selfCheckTimer_->start();

    decayTimer_ = new QTimer(this);
    decayTimer_->setInterval(static_cast<int>(kWindowMs * 3));
    connect(decayTimer_, &QTimer::timeout, this, &ResourceAbuseMonitor::onDecayTick);
    decayTimer_->start();

    log_.info(QStringLiteral(
        "资源攻击防护已启动:自身降权/饿死自检 %1 秒一次;系统侧速率聚合阈值 —— "
        "同一父进程 %2 子进程/10s、同一映像 %3 次启动/10s、同一主体 %4 远程线程/10s;"
        "达到阈值 %5 倍且主体不在可信目录时才做运行期收容(封禁+结束),"
        "绝不进入会留下跨重启禁运名单的裁决路径。")
            .arg(kSelfCheckMs / 1000).arg(kChildSpawnThreshold).arg(kSameImageThreshold)
            .arg(kRemoteThreadThreshold).arg(kContainMultiplier));

    QTimer::singleShot(3000, this, &ResourceAbuseMonitor::onSelfCheckTick);
}

void ResourceAbuseMonitor::stop() {
    if (selfCheckTimer_) { selfCheckTimer_->stop(); selfCheckTimer_->deleteLater(); selfCheckTimer_ = nullptr; }
    if (decayTimer_)     { decayTimer_->stop();     decayTimer_->deleteLater();     decayTimer_ = nullptr; }
    started_ = false;
}

void ResourceAbuseMonitor::onDecayTick() {
    const qint64 now = QDateTime::currentMSecsSinceEpoch();
    const auto prune = [now](QHash<QString, Counter>& t) {
        for (auto it = t.begin(); it != t.end();) {
            if (now - it.value().windowStartMs > kWindowMs * 3)
                it = t.erase(it);
            else
                ++it;
        }
    };
    prune(childSpawn_);
    prune(sameImage_);
    prune(remoteThread_);
}

void ResourceAbuseMonitor::onSelfCheckTick() {
    const bool ok = SelfHardening::selfCheck(true,
        [this](const QStringList& reasons) {
            if (selfDegradedReported_)
                return;   // 只报一次:状态不可自愈,重复无意义
            selfDegradedReported_ = true;

            for (const QString& r : reasons) {
                log_.critical(QStringLiteral("【自保护降级】%1").arg(r));
                if (audit_)
                    audit_(QStringLiteral("SelfProtectionDegraded"), r);
            }
            log_.critical(QStringLiteral(
                "【自保护降级】本服务进程的令牌/资源配额已被外部修改 —— 这意味着某个进程成功地对"
                "安全软件本体实施了降权或资源攻击。内核 ObCallbacks 本应剥离这类权限"
                "(PROCESS_QUERY_INFORMATION / SET_QUOTA),出现这种情况通常说明【内核驱动当时没有加载】。"
                "建议:确认 Bulwark 驱动处于 RUNNING,并重启本服务以恢复完整令牌。"));
            if (selfDegraded_)
                selfDegraded_(reasons);
        });

    if (ok)
        selfDegradedReported_ = false;
}

void ResourceAbuseMonitor::bump(QHash<QString, Counter>& table, const QString& key, int threshold,
                               const QString& kind, const QString& what, int pid,
                               const QString& actorPath) {
    if (table.size() > kMaxKeys)
        table.clear();

    const qint64 now = QDateTime::currentMSecsSinceEpoch();
    Counter& c = table[key];
    if (c.windowStartMs == 0 || now - c.windowStartMs > kWindowMs) {
        c.windowStartMs = now;
        c.count = 0;
    }
    ++c.count;

    if (c.count < threshold)
        return;
    if (now - c.lastAlertMs < kAlertCooldownMs)
        return;
    c.lastAlertMs = now;

    const QString detail =
        QStringLiteral("%1:%2 在 %3 秒内达到 %4 次(阈值 %5)。主体:%6")
            .arg(what, key).arg(kWindowMs / 1000).arg(c.count).arg(threshold)
            .arg(actorPath.isEmpty() ? QStringLiteral("(未知)") : actorPath);

    log_.warning(QStringLiteral("资源耗尽攻击嫌疑 —— %1").arg(detail));
    if (audit_)
        audit_(kind, detail);

    if (c.count < threshold * kContainMultiplier)
        return;
    if (isTrustedDir(actorPath)) {
        log_.info(QStringLiteral("资源耗尽:主体位于可信目录,只告警不收容(构建工具/系统维护任务"
                                 "的正常爆发式派生落在这里):%1").arg(actorPath));
        return;
    }
    if (pid <= 4 || !contain_)
        return;

    const QString why = QStringLiteral("资源耗尽攻击(%1,%2 次/%3 秒)")
                            .arg(what).arg(c.count).arg(kWindowMs / 1000);
    if (contain_(pid, why)) {
        log_.critical(QStringLiteral("资源耗尽攻击已收容:PID=%1 %2 —— %3")
                          .arg(pid).arg(actorPath, why));
        if (audit_)
            audit_(QStringLiteral("ResourceAbuseContained"),
                   QStringLiteral("PID=%1 %2 —— %3").arg(pid).arg(actorPath, why));
    }
}

void ResourceAbuseMonitor::onObservedEvent(const bulwark::SecurityEvent& e) {
    switch (e.type) {
    case bulwark::EventType::ProcessCreate:
        if (!e.parentPath.trimmed().isEmpty()) {
            bump(childSpawn_, keyOf(e.parentPath), kChildSpawnThreshold,
                 QStringLiteral("ResourceAbuseChildSpawnStorm"),
                 QStringLiteral("同一父进程高速派生子进程"), e.parentPid, e.parentPath);
        }
        bump(sameImage_, keyOf(e.actorPath), kSameImageThreshold,
             QStringLiteral("ResourceAbuseRelaunchStorm"),
             QStringLiteral("同一映像被高速反复启动"), e.actorPid, e.actorPath);
        break;

    case bulwark::EventType::RemoteThread:
        bump(remoteThread_, keyOf(e.actorPath), kRemoteThreadThreshold,
             QStringLiteral("ResourceAbuseThreadBomb"),
             QStringLiteral("同一主体高速创建远程线程"), e.actorPid, e.actorPath);
        break;

    default:
        break;
    }
}

}
