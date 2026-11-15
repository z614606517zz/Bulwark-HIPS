#include "bulwark/engine/CommandBurstMonitor.h"
#include "bulwark/engine/ThreatDetector.h"
#include "bulwark/Clock.h"
#include <QMutexLocker>
#include <QRegularExpression>
#include <QSet>

namespace bulwark::engine {

using detail::u;
using detail::fileNameLower;

namespace {

constexpr qint64 kWindowMs = 60 * 1000;
constexpr qint64 kCooldownMs = 10 * 60 * 1000;
constexpr int kDiscoveryThreshold = 5;
// 重置 Windows 更新组件、停数据库全家桶的运维脚本一次停四五个服务;勒索清场动辄几十个。
constexpr int kStopThreshold = 5;
constexpr int kStopHardThreshold = 8;
constexpr int kMaxParents = 1024;

// 词必须从命令边界开始:checklist 里的 klist、shipconfig 里的 ipconfig 都不算。
bool containsCommand(const QString& cmd, QLatin1String token) {
    for (qsizetype at = cmd.indexOf(token); at >= 0; at = cmd.indexOf(token, at + 1)) {
        if (at == 0)
            return true;
        const QChar before = cmd.at(at - 1);
        if (before.isSpace() || QStringView(u"\"'&|(;\\/").contains(before))
            return true;
    }
    return false;
}

QSet<QString> discoveryKeys(const QString& image, const QString& cmd) {
    QSet<QString> keys;
    static const QHash<QString, QString> byImage = {
        { "whoami.exe", "whoami" }, { "nltest.exe", "nltest" }, { "systeminfo.exe", "systeminfo" },
        { "ipconfig.exe", "ipconfig" }, { "arp.exe", "arp" }, { "netstat.exe", "netstat" },
        { "quser.exe", "quser" }, { "qwinsta.exe", "qwinsta" }, { "dsquery.exe", "dsquery" },
        { "nslookup.exe", "nslookup" }, { "klist.exe", "klist" }, { "setspn.exe", "setspn" },
        { "route.exe", "route" }, { "csvde.exe", "ldap-export" }, { "ldifde.exe", "ldap-export" },
    };
    if (const auto it = byImage.constFind(image); it != byImage.constEnd())
        keys.insert(it.value());

    // cmd /c "whoami & ipconfig /all & net user" 这类一次串起来的写法在同一条命令行里。
    // tasklist、sc query、reg query 在安装脚本里太常见,不计入。
    struct Token { const char* text; const char* key; };
    static const Token tokens[] = {
        { "whoami", "whoami" }, { "nltest", "nltest" }, { "systeminfo", "systeminfo" }, { "ipconfig", "ipconfig" },
        { "arp -a", "arp" }, { "netstat -a", "netstat" }, { "quser", "quser" }, { "query user", "quser" },
        { "qwinsta", "qwinsta" }, { "dsquery", "dsquery" }, { "nslookup", "nslookup" }, { "klist", "klist" },
        { "setspn", "setspn" }, { "route print", "route" }, { "net view", "net view" }, { "net share", "net share" },
        { "net accounts", "net accounts" }, { "net session", "net session" }, { "net time", "net time" },
        { "cmdkey /list", "cmdkey" }, { "get-aduser", "ad-user" }, { "get-adcomputer", "ad-computer" },
        { "get-adgroupmember", "ad-group" }, { "get-domain", "powerview" }, { "get-netdomain", "powerview" },
        { "securitycenter2", "av-enum" }, { "antivirusproduct", "av-enum" }, { "wmic computersystem", "wmic-inv" },
        { "wmic os ", "wmic-inv" }, { "wmic product", "wmic-inv" }, { "wmic qfe", "wmic-inv" },
        { "wmic useraccount", "wmic-inv" }, { "get-wmiobject win32_", "wmi-inv" }, { "get-ciminstance win32_", "wmi-inv" },
    };
    for (const Token& t : tokens)
        if (containsCommand(cmd, QLatin1String(t.text)))
            keys.insert(QLatin1String(t.key));
    // 建号、删号、改组成员不算侦察,另有规则。
    const bool accountChange = cmd.contains(QLatin1String("/add")) || cmd.contains(QLatin1String("/del"));
    if (!accountChange) {
        static const Token accountQueries[] = {
            { "net user", "net user" }, { "net1 user", "net user" }, { "net group", "net group" },
            { "net1 group", "net group" }, { "net localgroup", "net localgroup" }, { "net1 localgroup", "net localgroup" },
        };
        for (const Token& t : accountQueries)
            if (containsCommand(cmd, QLatin1String(t.text)))
                keys.insert(QLatin1String(t.key));
    }
    return keys;
}

QSet<QString> stoppedServices(const QString& cmd) {
    QSet<QString> out;
    static const QRegularExpression stopRe(
        QStringLiteral(R"((?:^|[\s"&|(\\])(?:net1?|sc)(?:\.exe)?"?\s+stop\s+"?([^\s"&|)]+))"));
    static const QRegularExpression psRe(
        QStringLiteral(R"(stop-service\s+(?:-name\s+)?['"]?([^\s'"&|;,)]+))"));
    static const QRegularExpression killRe(QStringLiteral(R"(/im\s+"?([^\s"&|)]+))"));
    for (const QRegularExpression* re : { &stopRe, &psRe }) {
        QRegularExpressionMatchIterator it = re->globalMatch(cmd);
        while (it.hasNext())
            out.insert(it.next().captured(1));
    }
    if (cmd.contains(QLatin1String("taskkill"))) {
        QRegularExpressionMatchIterator it = killRe.globalMatch(cmd);
        while (it.hasNext())
            out.insert(QLatin1String("kill:") + it.next().captured(1));
    }
    return out;
}

void prune(QHash<QString, qint64>& h, qint64 nowMs) {
    for (auto it = h.begin(); it != h.end();) {
        if (nowMs - it.value() > kWindowMs) it = h.erase(it);
        else ++it;
    }
}

}

CommandBurstMonitor::Result CommandBurstMonitor::observe(const SecurityEvent& e) {
    Result r;
    if (e.type != EventType::ProcessCreate || e.commandLine.isEmpty())
        return r;
    const QString cmd = e.commandLine.toLower();
    const QSet<QString> discovered = discoveryKeys(fileNameLower(e.actorPath), cmd);
    const QSet<QString> stopped = stoppedServices(cmd);
    if (discovered.isEmpty() && stopped.isEmpty())
        return r;

    const QDateTime when = e.timestampUtc.isValid() ? e.timestampUtc : nowUtc();
    const qint64 nowMs = when.toMSecsSinceEpoch();
    const QString parent = QString::number(e.parentPid) + QLatin1Char('|') + e.parentPath.toLower();

    QMutexLocker locker(&gate_);
    evict(nowMs);
    Burst& b = byParent_[parent];
    b.lastMs = nowMs;
    prune(b.discovery, nowMs);
    prune(b.stops, nowMs);
    for (const QString& k : discovered)
        b.discovery.insert(k, nowMs);
    for (const QString& k : stopped)
        b.stops.insert(k, nowMs);

    if (b.discovery.size() >= kDiscoveryThreshold && nowMs - b.discoveryReportedMs > kCooldownMs) {
        b.discoveryReportedMs = nowMs;
        // 运维脚本从资源管理器或管理工具里跑也会成批侦察;由投递目录里的程序发起才像攻击。
        r.discovery.hardSignal = ThreatDetector::isSuspiciousDropDir(e.parentPath);
        r.discovery.score = r.discovery.hardSignal ? 40 : 30;
        r.discovery.reasons << u("1 分钟内由同一父进程连续执行 %1 类侦察命令(账户 / 域 / 网络 / 进程 / 安全软件枚举,T1087/T1082/T1518)")
                                   .arg(b.discovery.size());
    }
    const int stops = static_cast<int>(b.stops.size());
    const bool hardStop = stops >= kStopHardThreshold
        || (stops >= kStopThreshold && ThreatDetector::isSuspiciousDropDir(e.parentPath));
    const bool reportHard = hardStop && nowMs - b.stopHardReportedMs > kCooldownMs;
    const bool reportSoft = !hardStop && stops >= kStopThreshold && nowMs - b.stopReportedMs > kCooldownMs;
    if (reportHard || reportSoft) {
        b.stopReportedMs = nowMs;
        if (reportHard)
            b.stopHardReportedMs = nowMs;
        r.serviceStop.hardSignal = reportHard;
        r.serviceStop.score = reportHard ? 50 : 30;
        r.serviceStop.reasons << u("1 分钟内由同一父进程停止 / 结束 %1 个服务或进程(勒索加密前清场,T1489)")
                                     .arg(stops);
    }
    return r;
}

void CommandBurstMonitor::evict(qint64 nowMs) {
    if (byParent_.size() <= kMaxParents)
        return;
    for (auto it = byParent_.begin(); it != byParent_.end();) {
        if (nowMs - it->lastMs > kWindowMs) it = byParent_.erase(it);
        else ++it;
    }
    if (byParent_.size() > kMaxParents)
        byParent_.clear();
}

}
