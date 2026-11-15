#include "bulwark/engine/DownloaderBehaviorMonitor.h"
#include "bulwark/engine/CommandLineAnalyzer.h"
#include "bulwark/engine/SystemPaths.h"
#include "bulwark/engine/ThreatDetector.h"
#include "bulwark/Clock.h"
#include <QMutexLocker>
#include <QSet>

namespace bulwark::engine {

using detail::u;
using detail::fileNameLower;

namespace {

// 落地到启动超过 5 分钟就不再关联:拖过窗口能规避,但窗口放宽会把「先下载、过一阵再手动运行」都算进来。
constexpr qint64 kDropWindowMs = 5 * 60 * 1000;
constexpr qint64 kNetworkWindowMs = 10 * 60 * 1000;
constexpr int kMaxEntries = 4096;

QString normalized(const QString& path) {
    QString p = path.trimmed().toLower();
    p.replace(QLatin1Char('/'), QLatin1Char('\\'));
    return p;
}

bool isProcessImage(const QString& pathLower) {
    static const char* exts[] = { ".exe", ".scr", ".com", ".pif" };
    for (const char* x : exts)
        if (pathLower.endsWith(QLatin1String(x)))
            return true;
    return false;
}

bool isScriptHostWriter(const QString& imageName) {
    static const QSet<QString> s = {
        "powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe",
        "regsvr32.exe", "certutil.exe", "bitsadmin.exe", "curl.exe", "wget.exe", "ftp.exe",
    };
    return s.contains(imageName);
}

bool isInstalledLocation(const QString& pathLower) {
    const QString rel = SystemPaths::systemVolumeRelative(pathLower);
    return rel.startsWith(QLatin1String("\\windows\\system32\\"))
        || rel.startsWith(QLatin1String("\\windows\\syswow64\\"))
        || rel.startsWith(QLatin1String("\\windows\\winsxs\\"))
        || rel.startsWith(QLatin1String("\\program files\\"))
        || rel.startsWith(QLatin1String("\\program files (x86)\\"));
}

// 安装引擎把自带的帮助程序解到 %TEMP% 下自己的临时目录再运行,是 Inno / NSIS / SFX 的常规流程。
bool isInstallerStagingDir(const QString& pathLower) {
    for (const char* tempRoot : { "\\appdata\\local\\temp\\", "\\windows\\temp\\" }) {
        const qsizetype at = pathLower.indexOf(QLatin1String(tempRoot));
        if (at < 0)
            continue;
        const qsizetype start = at + static_cast<qsizetype>(qstrlen(tempRoot));
        const qsizetype end = pathLower.indexOf(QLatin1Char('\\'), start);
        if (end < 0)
            return false;
        const QString dir = pathLower.mid(start, end - start);
        const bool tmpDir = dir.endsWith(QLatin1String(".tmp"));
        return (tmpDir && dir.startsWith(QLatin1String("is-")))
            || (tmpDir && (dir.startsWith(QLatin1String("ns")) || dir.startsWith(QLatin1String("~ns"))))
            || (tmpDir && dir.startsWith(QLatin1String("ixp")))
            || dir.startsWith(QLatin1String("7zs")) || dir.startsWith(QLatin1String("rar$ex"))
            || (dir.startsWith(QLatin1Char('{')) && dir.endsWith(QLatin1Char('}')));
    }
    return false;
}

}

DownloaderBehaviorMonitor::Result DownloaderBehaviorMonitor::observe(const SecurityEvent& e) {
    Result r;
    const QDateTime when = e.timestampUtc.isValid() ? e.timestampUtc : nowUtc();
    const qint64 nowMs = when.toMSecsSinceEpoch();

    QMutexLocker locker(&gate_);
    evict(nowMs);

    switch (e.type) {
    case EventType::NetworkConnect:
        // 脚本宿主只认命令行里的取远端:安装脚本经 -File 运行、在脚本里联网下载再解包运行太常见。
        if (e.actorPid > 0 && !isScriptHostWriter(fileNameLower(normalized(e.actorPath))))
            networkActive_.insert(e.processInstanceKey(), nowMs);
        return r;

    case EventType::FileWrite: {
        const QString target = normalized(e.target);
        if (target.isEmpty() || !isProcessImage(target))
            return r;
        const QString writer = normalized(e.actorPath);
        const QString writerName = fileNameLower(writer);
        const bool healthy = e.actorSigned && !e.signatureMismatch && !e.certRevoked && !e.signedAfterCertExpiry;
        Drop d;
        d.atMs = nowMs;
        d.writerPid = e.actorPid;
        d.writerInstance = e.processInstanceKey();
        d.writerPath = e.actorPath;
        d.writerIsScriptHost = isScriptHostWriter(writerName);
        d.writerTrusted = (healthy || isInstalledLocation(writer)) && !d.writerIsScriptHost;
        d.writerFetchedRemote = CommandLineAnalyzer::fetchesRemote(e.commandLine.toLower());
        d.inDropZone = ThreatDetector::isSuspiciousDropDir(target) && !isInstallerStagingDir(target);
        drops_.insert(target, d);
        if (!e.actorSigned && !isInstalledLocation(writer) && d.inDropZone) {
            r.score = 20;
            r.reasons << u("未签名程序向投递目录落地可执行体 ") + e.target + u("(下载器 / 释放器前半段,需与启动互证)");
        }
        return r;
    }

    case EventType::ProcessCreate:
        break;

    default:
        return r;
    }

    const QString image = normalized(e.actorPath);
    const auto it = drops_.constFind(image);
    if (it == drops_.constEnd())
        return r;
    const Drop drop = it.value();
    const qint64 ageSecs = (nowMs - drop.atMs) / 1000;
    const bool writerHadNet = networkActive_.contains(drop.writerInstance);
    const QString writerName = fileNameLower(drop.writerPath);

    if (drop.writerTrusted || e.actorSigned) {
        if (!e.actorSigned && drop.writerPid > 0 && drop.writerPid == e.parentPid) {
            r.score = 8;
            r.reasons << u("签名 / 已安装程序落地并启动未签名载荷(安装与更新常见,软信号)");
        }
        return r;
    }

    const bool inDropZone = drop.inDropZone
        || (ThreatDetector::isSuspiciousDropDir(image) && !isInstallerStagingDir(image));
    const bool downloaderShaped = writerHadNet || drop.writerFetchedRemote;
    // 脚本宿主解包即跑(Inno 经 cmd 拉起解包器)也落在投递目录,对它只认「取过远端」。
    const bool dropperShaped = inDropZone && !drop.writerIsScriptHost;

    if (!downloaderShaped && !dropperShaped) {
        r.score = drop.writerIsScriptHost ? 8 : 20;
        r.reasons << (drop.writerIsScriptHost
                          ? writerName + u(" 落地并启动未签名载荷(未见取远端,解包即跑也是这个形态,软信号)")
                          : u("未签名程序落地并启动另一未签名可执行体(写出即执行,需互证)"));
        return r;
    }

    r.hardSignal = true;
    if (drop.writerIsScriptHost) {
        r.score = inDropZone ? 80 : 75;
        r.reasons << writerName + u(" 取远端落地可执行体并立即启动(木马下载器,T1105/T1204)");
    } else if (downloaderShaped) {
        r.score = inDropZone ? 80 : 75;
        r.reasons << u("未签名程序联网后落地可执行体并立即启动(木马下载器,T1105/T1204)");
    } else {
        r.score = 65;
        r.reasons << u("未签名程序向投递目录落地可执行体并立即启动(木马释放器,T1105/T1204)");
    }
    r.reasons << u("载荷 %1 由 %2 落地,%3 秒后被启动").arg(e.actorPath, drop.writerPath).arg(ageSecs);
    return r;
}

void DownloaderBehaviorMonitor::evict(qint64 nowMs) {
    for (auto it = networkActive_.begin(); it != networkActive_.end();) {
        if (nowMs - it.value() > kNetworkWindowMs) it = networkActive_.erase(it);
        else ++it;
    }
    for (auto it = drops_.begin(); it != drops_.end();) {
        if (nowMs - it->atMs > kDropWindowMs) it = drops_.erase(it);
        else ++it;
    }
    if (networkActive_.size() > kMaxEntries) networkActive_.clear();
    if (drops_.size() > kMaxEntries) drops_.clear();
}

}
