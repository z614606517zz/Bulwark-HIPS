#include "bulwark/service/BulwarkOptions.h"
#include "bulwark/service/Logger.h"
#include "bulwark/service/SettingsStore.h"
#include "bulwark/service/RuleStore.h"
#include "bulwark/service/AuditLog.h"
#include "bulwark/service/FirstSeenStore.h"
#include "bulwark/service/QuarantineManager.h"
#include "bulwark/service/EventHistoryStore.h"
#include "bulwark/service/IpcServer.h"
#include "bulwark/service/IpcClientAuth.h"
#include "bulwark/service/InstallDirAclCheck.h"
#include "bulwark/service/AlertExporter.h"
#include "bulwark/service/BaselineStore.h"
#include "bulwark/service/EventSource.h"
#include "bulwark/service/EtwProcessEventSource.h"
#include "bulwark/service/DriverEventSource.h"
#include "bulwark/service/DriverControl.h"
#include "bulwark/service/UserModeBehaviorSource.h"
#include "bulwark/service/EventSourceCoordinator.h"
#include "bulwark/service/UserModeProcessContainment.h"
#include "bulwark/service/SystemHardening.h"
#include "bulwark/service/HardeningCatalog.h"
#include "bulwark/service/HijackGuard.h"
#include "bulwark/service/RegistryRollbackPolicy.h"
#include "bulwark/service/SelfHardening.h"
#include "bulwark/service/SensitiveDataGuardPolicy.h"
#include "bulwark/service/FileContentProbe.h"
#include "bulwark/service/BootSectorGuard.h"
#include "bulwark/service/FilelessGuard.h"
#include "bulwark/service/ResourceAbuseMonitor.h"
#include "bulwark/service/PersistenceScanner.h"
#include "bulwark/service/ForensicsService.h"
#include "bulwark/service/NetTrafficMonitor.h"
#include "bulwark/service/Worker.h"
#include "bulwark/service/RepairDriverSession.h"
#include "bulwark/service/SnapshotRepairJournal.h"

#include "bulwark/service/monitoring/ProcessInspector.h"
#include "bulwark/service/monitoring/RevocationGate.h"
#include "bulwark/service/monitoring/ProcessEnumerator.h"
#include "bulwark/service/monitoring/ProcessOriginResolver.h"
#include "bulwark/service/SystemBoost.h"
#include "bulwark/service/reputation/ThreatFoxFeed.h"
#include "bulwark/service/YaraRuleUpdater.h"
#include "bulwark/service/YaraScanner.h"
#include "bulwark/service/AmsiBridge.h"

#include "bulwark/engine/RuleEngine.h"
#include "bulwark/engine/DefaultRules.h"
#include "bulwark/engine/TrustPolicy.h"
#include "bulwark/engine/SelfProtection.h"
#include "bulwark/engine/TrustedSoftwareCatalog.h"
#include "bulwark/engine/ThreatDetector.h"
#include "bulwark/engine/SystemPaths.h"

#include <QCoreApplication>
#include <QDir>
#include <QFile>
#include <QTimer>
#include <thread>
#include <QFileInfo>
#include <QDateTime>
#include <QHash>
#include <QSet>
#include <QProcess>
#include <QStringList>
#include <QTextStream>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonParseError>
#include <QTemporaryDir>
#include <QElapsedTimer>
#include <QEventLoop>
#include <QLocalSocket>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <sddl.h>

#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <exception>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <vector>

using namespace bulwark::service;

namespace {

struct RansomGuardBaselineEntry {
    const char* path;
    bool directory;
};

const RansomGuardBaselineEntry kRansomGuardSystemBaseline[] = {
    { "\\Windows\\System32\\config\\SAM",      false },
    { "\\Windows\\System32\\config\\SECURITY", false },
    { "\\Windows\\System32\\config\\SYSTEM",   false },
    { "\\Windows\\System32\\config\\SOFTWARE", false },
    { "\\Windows\\System32\\config\\DEFAULT",  false },
    { "\\Windows\\Boot\\", true },
    { "\\Boot\\BCD", false },
    { "\\Recovery\\WindowsRE\\", true },
    { "\\Windows\\System32\\Recovery\\", true },
    { "\\Windows\\System32\\CodeIntegrity\\", true },
    { "\\Windows\\System32\\winevt\\Logs\\", true },
    { "\\System Volume Information\\", true },
};

// 给勒索行为监视器查文件创建时间。只取属性、不打开数据流,不会和正在写文件的进程争共享模式。
bulwark::engine::RansomwareBehaviorMonitor::FileState probeFileStateForRansomware(const QString& path)
{
    using FileState = bulwark::engine::RansomwareBehaviorMonitor::FileState;
    FileState state;

    QString native = QDir::toNativeSeparators(path.trimmed());
    QString local = native;
    if (local.startsWith(QLatin1String("\\\\?\\")))
        local = local.mid(4);
    // 只查本地盘。网络路径在服务器不可达时一次查询能卡数秒,会拖住整条事件队列。
    if (local.size() < 3 || local.at(1) != QLatin1Char(':') || local.at(2) != QLatin1Char('\\'))
        return state;
    const std::wstring root = local.left(3).toStdWString();
    if (::GetDriveTypeW(root.c_str()) == DRIVE_REMOTE)
        return state;

    if (!native.startsWith(QLatin1String("\\\\?\\")) && native.size() >= MAX_PATH - 12)
        native.prepend(QLatin1String("\\\\?\\"));
    const std::wstring wide = native.toStdWString();
    WIN32_FILE_ATTRIBUTE_DATA data{};
    if (!::GetFileAttributesExW(wide.c_str(), GetFileExInfoStandard, &data)) {
        const DWORD err = ::GetLastError();
        if (err == ERROR_FILE_NOT_FOUND || err == ERROR_PATH_NOT_FOUND)
            state.kind = FileState::Kind::Missing;
        return state;
    }
    if (data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
        state.kind = FileState::Kind::Missing;
        return state;
    }
    ULARGE_INTEGER created;
    created.LowPart = data.ftCreationTime.dwLowDateTime;
    created.HighPart = data.ftCreationTime.dwHighDateTime;
    if (created.QuadPart == 0)
        return state;
    constexpr qint64 kFileTimeToUnixMs = 11644473600000LL;
    state.kind = FileState::Kind::Present;
    state.createdUtc = QDateTime::fromMSecsSinceEpoch(
        static_cast<qint64>(created.QuadPart / 10000ULL) - kFileTimeToUnixMs, QTimeZone::UTC);
    return state;
}

QStringList discoverDefaultUserDataGuardDirs()
{
    QString systemDrive = qEnvironmentVariable("SystemDrive").trimmed();
    if (systemDrive.isEmpty())
        systemDrive = QStringLiteral("C:");
    const QDir usersRoot(QDir::cleanPath(systemDrive + QStringLiteral("/Users")));
    if (!usersRoot.exists())
        return {};

    const QSet<QString> excludedProfiles = {
        QStringLiteral("all users"), QStringLiteral("default"),
        QStringLiteral("default user"), QStringLiteral("defaultuser0"),
        QStringLiteral("public"), QStringLiteral("wdagutilityaccount"),
    };
    // 刻意不含 Desktop:桌面常被当作工作区和便携软件的存放处,写前拒绝在这里误拦太多
    // (便携程序写自己的缓存、开发工具写项目文件)。桌面仍由勒索行为监控与诱饵检测覆盖；
    // 需要写前拒绝的话,在界面上把桌面手动加进受保护目录。
    const QStringList protectedLeaves = {
        QStringLiteral("Documents"), QStringLiteral("Pictures"),
    };

    QStringList out;
    const auto addExisting = [&out](const QString& path) {
        const QFileInfo info(path);
        if (!info.exists() || !info.isDir())
            return;
        const QString canonical = info.canonicalFilePath();
        const QString resolved = canonical.isEmpty() ? info.absoluteFilePath() : canonical;
        if (!out.contains(resolved, Qt::CaseInsensitive))
            out << resolved;
    };

    const QFileInfoList profiles = usersRoot.entryInfoList(
        QDir::Dirs | QDir::NoDotAndDotDot | QDir::NoSymLinks,
        QDir::Name | QDir::IgnoreCase);
    for (const QFileInfo& profile : profiles) {
        if (excludedProfiles.contains(profile.fileName().toLower()))
            continue;
        const QDir profileDir(profile.absoluteFilePath());
        for (const QString& leaf : protectedLeaves)
            addExisting(profileDir.filePath(leaf));

        const QFileInfoList oneDrives = profileDir.entryInfoList(
            QStringList{QStringLiteral("OneDrive"), QStringLiteral("OneDrive - *")},
            QDir::Dirs | QDir::NoDotAndDotDot | QDir::NoSymLinks,
            QDir::Name | QDir::IgnoreCase);
        for (const QFileInfo& oneDrive : oneDrives) {
            const QDir oneDriveDir(oneDrive.absoluteFilePath());
            for (const QString& leaf : protectedLeaves)
                addExisting(oneDriveDir.filePath(leaf));
        }
    }
    return out;
}

QStringList composeRansomGuardDirs(const bulwark::service::BulwarkOptions& options,
                                   const QStringList& userDirs)
{
    QStringList out;
    const auto add = [&out](const QString& raw, bool isDirectory) {
        QString s = raw.trimmed();
        if (s.isEmpty())
            return;
        s.replace(QLatin1Char('/'), QLatin1Char('\\'));
        if (s.size() >= 2 && s.at(1) == QLatin1Char(':'))
            s = s.mid(2);
        if (s.isEmpty())
            return;
        if (!s.startsWith(QLatin1Char('\\')))
            s.prepend(QLatin1Char('\\'));
        if (isDirectory) {
            while (s.endsWith(QStringLiteral("\\*")))
                s.chop(1);
            if (!s.endsWith(QLatin1Char('\\')))
                s.append(QLatin1Char('\\'));
        } else {
            while (s.endsWith(QLatin1Char('\\')))
                s.chop(1);
        }
        if (!s.isEmpty() && !out.contains(s, Qt::CaseInsensitive))
            out << s;
    };

    if (options.RansomGuardSystemBaseline)
        for (const RansomGuardBaselineEntry& e : kRansomGuardSystemBaseline)
            add(QString::fromLatin1(e.path), e.directory);
    // 下面三个来源按契约全是目录，即使目录名含 '.' 也必须补边界反斜杠。
    for (const QString& d : options.RansomGuardDirectories)
        add(d, true);
    for (const QString& d : userDirs)
        add(d, true);
    if (options.RansomGuardUserFoldersByDefault) {
        constexpr int kDriverGuardDirCapacity = 64;
        for (const QString& d : discoverDefaultUserDataGuardDirs()) {
            if (out.size() >= kDriverGuardDirCapacity)
                break;
            add(d, true);
        }
    }
    return out;
}

// 去盘符的程序路径或目录(目录补结尾 '\'),不区分大小写去重后追加。
void appendDriveLessPath(QStringList& out, const QString& raw, bool isDir)
{
    QString s = raw.trimmed();
    if (s.isEmpty())
        return;
    s.replace(QLatin1Char('/'), QLatin1Char('\\'));
    if (s.size() >= 2 && s.at(1) == QLatin1Char(':'))
        s = s.mid(2);
    if (s.isEmpty())
        return;
    if (!s.startsWith(QLatin1Char('\\')))
        s.prepend(QLatin1Char('\\'));
    if (isDir && !s.endsWith(QLatin1Char('\\')))
        s.append(QLatin1Char('\\'));
    if (!out.contains(s, Qt::CaseInsensitive))
        out << s;
}

void appendConfiguredPaths(QStringList& out, const QStringList& configured)
{
    for (const QString& w : configured) {
        const QString t = w.trimmed();
        appendDriveLessPath(out, t, t.endsWith(QLatin1Char('\\')) || t.endsWith(QLatin1Char('/')));
    }
}

// 用户信任名单里的程序或目录。
void appendTrustedActors(QStringList& out, const QVector<bulwark::DefenseRule>& rules)
{
    for (const bulwark::DefenseRule& r : rules) {
        if (!r.isTrustEntry())
            continue;
        const bool isDir = r.actorPath.trimmed().isEmpty() && !r.actorPattern.trimmed().isEmpty();
        QString p = isDir ? r.actorPattern.trimmed() : r.actorPath.trimmed();
        if (isDir && p.endsWith(QStringLiteral("\\*")))
            p.chop(2);
        if (p.isEmpty())
            continue;
        appendDriveLessPath(out, p, isDir);
    }
}

QStringList composeRansomGuardWriters(const bulwark::service::BulwarkOptions& options,
                                      const QVector<bulwark::DefenseRule>& rules)
{
    QStringList out;
    appendConfiguredPaths(out, options.RansomGuardWriters);
    appendTrustedActors(out, rules);
    return out;
}

QStringList composeReadGuardEntries(const bulwark::service::BulwarkOptions& options)
{
    return bulwark::service::sensitive_data_guard::composeEntries(options.SensitiveDataGuardBuiltins,
                                                                  options.SensitiveDataGuardEntries);
}

// 全局读者(对所有条目放行):配置里的 SensitiveDataGuardReaders 加用户信任名单,与可信写入者同源。
// 内核从卷根比(\Program Files、\Windows 只认系统卷),所以只去盘符。
QStringList composeReadGuardReaders(const bulwark::service::BulwarkOptions& options,
                                    const QVector<bulwark::DefenseRule>& rules)
{
    QStringList out;
    appendConfiguredPaths(out, options.SensitiveDataGuardReaders);
    appendTrustedActors(out, rules);
    return out;
}

int runInspect(const QString& path) {
    using bulwark::service::monitoring::ProcessInspector;
    QString buf;
    QTextStream out(&buf);
    out << "=== ProcessInspector self-test ===\n";
    out << "target: " << path << "\n";
    if (!path.isEmpty()) {
        out << "isSigned: " << (ProcessInspector::isSigned(path) ? "true" : "false") << "\n";
        out << "signatureMismatch: " << (ProcessInspector::isSignatureMismatch(path) ? "true" : "false") << "\n";
        out << "hasEmbedded: " << (ProcessInspector::hasEmbeddedSignature(path) ? "true" : "false") << "\n";
        out << "publisher: " << ProcessInspector::tryGetPublisher(path) << "\n";
        out << "sha256: " << ProcessInspector::tryComputeSha256(path) << "\n";
        const ProcessInspector::CertInfo ci = ProcessInspector::getCertInfo(path);
        out << "cert.thumbprint: " << ci.thumbprint << "\n";
        out << "cert.notBefore: "
            << (ci.notBeforeUtc.isValid() ? ci.notBeforeUtc.toString(Qt::ISODate) : QStringLiteral("(none)")) << "\n";
        out << "cert.notAfter: "
            << (ci.notAfterUtc.isValid() ? ci.notAfterUtc.toString(Qt::ISODate) : QStringLiteral("(none)")) << "\n";
        out << "cert.signingTime: "
            << (ci.signingTimeUtc.isValid() ? ci.signingTimeUtc.toString(Qt::ISODate) : QStringLiteral("(none)")) << "\n";
        out << "cert.signedAfterExpiry: " << (ci.signedAfterCertExpiry ? "true" : "false") << "\n";
        out << "cert.revoked: " << (ci.revoked ? "true" : "false") << "\n";
    }
    const int selfPid = static_cast<int>(QCoreApplication::applicationPid());
    out << "--- self (pid " << selfPid << ") ---\n";
    out << "self.imagePath: " << ProcessInspector::tryGetProcessImagePath(selfPid) << "\n";
    out << "self.commandLine: " << ProcessInspector::tryGetCommandLine(selfPid) << "\n";
    out << "self.parentPid: " << ProcessInspector::tryGetParentPid(selfPid) << "\n";
    out.flush();

    const QString resultPath = QDir(QDir::tempPath()).filePath(QStringLiteral("bulwark_inspect_result.txt"));
    QFile rf(resultPath);
    if (rf.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
        rf.write(buf.toUtf8());
        rf.close();
    }
    QTextStream(stdout) << buf << "result written to: " << resultPath << "\n";
    return 0;
}

namespace {

struct LegacyCacheRemoval {
    QString path;
    bool removed = false;
};

// 旧版「AI 全权裁决」留在本机的缓存。本版不读它;启动时删掉,免得退回旧版时这些旧结论又被拿来替用户回答询问。
QList<LegacyCacheRemoval> removeLegacyAiVerdictCaches(const QString& dir) {
    QList<LegacyCacheRemoval> out;
    for (const QString& name : {QStringLiteral("ai-verdict-cache.json"), QStringLiteral("ai-verdict-share.json")}) {
        const QString path = QDir(dir).filePath(name);
        if (QFile::exists(path))
            out.append(LegacyCacheRemoval{path, QFile::remove(path)});
    }
    return out;
}

}

int runServiceRegressionSelfTest() {
    QTextStream out(stdout);
    out << "=== Service regression selftest ===\n";

    int pass = 0, total = 0;
    const auto check = [&](bool ok, const QString& what) {
        ++total;
        if (ok) ++pass;
        out << (ok ? "  PASS " : "  FAIL ") << what << "\n";
    };

    {
        QTemporaryDir dir;
        const QStringList names{QStringLiteral("ai-verdict-cache.json"), QStringLiteral("ai-verdict-share.json")};
        for (const QString& name : names) {
            QFile f(QDir(dir.path()).filePath(name));
            if (f.open(QIODevice::WriteOnly))
                f.write(R"({"version":1,"items":[{"key":"0123456789abcdef","action":"allow","votes":2}]})");
        }
        const QList<LegacyCacheRemoval> removed = removeLegacyAiVerdictCaches(dir.path());
        bool gone = dir.isValid() && removed.size() == names.size();
        for (const LegacyCacheRemoval& r : removed)
            gone = gone && r.removed && !QFile::exists(r.path);
        check(gone, QStringLiteral("启动时删掉旧版「AI 全权裁决」的缓存 ai-verdict-cache.json / ai-verdict-share.json"));
        check(removeLegacyAiVerdictCaches(dir.path()).isEmpty(),
              QStringLiteral("没有旧缓存时,启动清理什么也不做"));
    }
    {
        QJsonObject o;
        o[QStringLiteral("aiFullVerdictEnabled")] = true;
        check(!bulwark::RuntimeSettings::fromJson(o).toJson().contains(QStringLiteral("aiFullVerdictEnabled")),
              QStringLiteral("settings.json 里残留的 aiFullVerdictEnabled 被忽略,保存时不再写出"));
    }

    {
        using bulwark::engine::ThreatDetector;
        const bool tempIsDrop = ThreatDetector::isSuspiciousDropDir(
            QStringLiteral("C:\\Users\\u\\AppData\\Local\\Temp\\actor.exe"));
        const bool pfIsNotDrop = !ThreatDetector::isSuspiciousDropDir(
            QStringLiteral("C:\\Program Files\\Vendor App\\app.exe"));
        check(tempIsDrop && pfIsNotDrop,
              QStringLiteral("%TEMP% 算投递目录,Program Files 不算"));
    }

    {
        using bulwark::engine::RuleEngine;
        using bulwark::engine::SelfProtection;

        const auto hits = [](const char* cmd) {
            return SelfProtection::commandTargetsProduct(QString::fromUtf8(cmd));
        };
        check(hits("\"C:\\Windows\\system32\\sc.exe\" stop BulwarkService")
                  && hits("sc stop BulwarkService") && hits("net stop BulwarkService")
                  && hits("taskkill /F /IM bulwark_ui.exe")
                  && hits("powershell -c \"Stop-Process -Name bulwark_service -Force\"")
                  && hits("sc.exe delete Bulwark") && hits("sc.exe stop \"Bulwark\"")
                  && hits("fltmc unload Bulwark")
                  && hits("sc config BulwarkService start= disabled")
                  && hits("Get-Process bulwark* | Stop-Process"),
              QStringLiteral("自保护判据:停止/删除/禁用/结束本产品的各种写法都命中"));
        check(!hits("sc config BulwarkService start= auto")
                  && !hits("cmd /c echo stop > \"C:\\Program Files\\Bulwark\\x.txt\"")
                  && !hits("\"C:\\Program Files\\Bulwark\\bulwark_service.exe\" --service")
                  && !hits("sc stop Spooler") && !hits("taskkill /IM notepad.exe")
                  && !hits("notepad C:\\Program Files\\Bulwark\\bulwark_ui.exe.log")
                  && !hits("C:\\tools\\misc stop bulwark_ui") && !hits(""),
              QStringLiteral("自保护判据:无破坏性动词 / 动词不指向本产品 / 词内子串 -> 不命中"));

        const QDateTime pinned = QDateTime(QDate(2026, 6, 1), QTime(12, 0), QTimeZone::UTC);
        bulwark::setFixedNowUtcForTest(pinned);
        const QString kPsExe = QStringLiteral("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe");
        const QString kScExe = QStringLiteral("C:\\Windows\\System32\\sc.exe");
        const auto mkEvent = [&](const QString& exe, const QString& cmd, int pid, int ppid) {
            bulwark::SecurityEvent e;
            e.timestampUtc = pinned;
            e.type = bulwark::EventType::ProcessCreate;
            e.actorPid = pid;
            e.parentPid = ppid;
            e.actorPath = exe;
            e.actorSigned = true;
            e.actorPublisher = QStringLiteral("Microsoft Windows");
            e.actorFileSize = 65536;
            e.commandLine = cmd;
            return e;
        };
        const auto mkNode = [&](int pid, int ppid, const QString& exe, const QString& cmd) {
            bulwark::ChainEventInfo c;
            c.timestampUtc = pinned;
            c.type = bulwark::EventType::ProcessCreate;
            c.actorPid = pid;
            c.parentPid = ppid;
            c.actorPath = exe;
            c.commandLine = cmd;
            return c;
        };
        const QString kStop = QStringLiteral("\"C:\\Windows\\system32\\sc.exe\" stop BulwarkService");

        RuleEngine eng;
        eng.addSelfDirectory(QStringLiteral("C:\\Program Files\\Bulwark\\"));
        eng.loadRules(bulwark::engine::DefaultRules::build());

        {
            bulwark::SecurityEvent on = mkEvent(kScExe, kStop, 7001, 1000);
            const bulwark::Verdict von = eng.evaluate(on);
            SelfProtection::enabled.store(false);
            bulwark::SecurityEvent off = mkEvent(kScExe, kStop, 7002, 1000);
            const bulwark::Verdict voff = eng.evaluate(off);
            SelfProtection::enabled.store(true);
            check(von.action == bulwark::VerdictAction::Ask && on.hasThreatIndicator,
                  QStringLiteral("自保护告警:开 -> 询问 + 硬指标"));
            check(voff.action == bulwark::VerdictAction::Allow && !off.hasThreatIndicator,
                  QStringLiteral("自保护告警:开关关闭 -> 与改动前一致(放行、无硬指标)"));
        }

        {
            RuleEngine eng2;
            eng2.addSelfDirectory(QStringLiteral("C:\\Program Files\\Bulwark\\"));
            eng2.loadRules(bulwark::engine::DefaultRules::build());
            const QString trustedScript = QStringLiteral(
                "powershell.exe -NoProfile -File \"C:\\DevScripts\\stop-driver.ps1\"");
            const auto withChain = [&](const QString& scriptCmd) {
                bulwark::SecurityEvent e = mkEvent(kScExe, kStop, 7100, 7101);
                e.chainContext.append(mkNode(7101, 1000, kPsExe, scriptCmd));
                return e;
            };

            bulwark::SecurityEvent noTrust = withChain(trustedScript);
            const bulwark::Verdict v0 = eng2.evaluate(noTrust);
            check(v0.action == bulwark::VerdictAction::Ask,
                  QStringLiteral("脚本未加白 -> 子进程的『停止本产品』仍询问"));

            eng2.addRule(bulwark::DefenseRule::createTrustDirectory(
                QStringLiteral("C:\\DevScripts"), QStringLiteral("语料:开发脚本目录")));
            bulwark::SecurityEvent trusted = withChain(trustedScript);
            const bulwark::Verdict v1 = eng2.evaluate(trusted);
            check(v1.action == bulwark::VerdictAction::Allow && !trusted.hasThreatIndicator,
                  QStringLiteral("脚本所在文件夹已加白 -> 子进程放行"));

            bulwark::SecurityEvent other = withChain(QStringLiteral(
                "powershell.exe -NoProfile -File \"C:\\Other\\x.ps1\""));
            check(eng2.evaluate(other).action == bulwark::VerdictAction::Ask,
                  QStringLiteral("脚本不在已加白文件夹 -> 不豁免"));

            bulwark::SecurityEvent inl = withChain(QStringLiteral(
                "powershell.exe -Command \"x\" -File \"C:\\DevScripts\\stop-driver.ps1\""));
            check(eng2.evaluate(inl).action == bulwark::VerdictAction::Ask,
                  QStringLiteral("父进程带行内代码开关 -> 不豁免(不可被一句文本伪造)"));

            // 跳数:sc <- cmd <- cmd <- powershell(脚本)= 3 跳可达;再多一层 = 4 跳,不可达。
            bulwark::SecurityEvent hop3 = mkEvent(kScExe, kStop, 7200, 7201);
            hop3.chainContext.append(mkNode(7201, 7202, QStringLiteral("C:\\Windows\\System32\\cmd.exe"),
                                            QStringLiteral("cmd.exe /c x")));
            hop3.chainContext.append(mkNode(7202, 7203, QStringLiteral("C:\\Windows\\System32\\cmd.exe"),
                                            QStringLiteral("cmd.exe /c y")));
            hop3.chainContext.append(mkNode(7203, 1000, kPsExe, trustedScript));
            check(eng2.evaluate(hop3).action == bulwark::VerdictAction::Allow,
                  QStringLiteral("进程链 3 跳内找到受认可脚本 -> 放行"));
            bulwark::SecurityEvent hop4 = mkEvent(kScExe, kStop, 7300, 7301);
            hop4.chainContext.append(mkNode(7301, 7302, QStringLiteral("C:\\Windows\\System32\\cmd.exe"),
                                            QStringLiteral("cmd.exe /c x")));
            hop4.chainContext.append(mkNode(7302, 7303, QStringLiteral("C:\\Windows\\System32\\cmd.exe"),
                                            QStringLiteral("cmd.exe /c y")));
            hop4.chainContext.append(mkNode(7303, 7304, QStringLiteral("C:\\Windows\\System32\\cmd.exe"),
                                            QStringLiteral("cmd.exe /c z")));
            hop4.chainContext.append(mkNode(7304, 1000, kPsExe, trustedScript));
            check(eng2.evaluate(hop4).action == bulwark::VerdictAction::Ask,
                  QStringLiteral("进程链超过 3 跳 -> 不豁免(失败方向是多一次询问)"));

            const QString kCmdExe = QStringLiteral("C:\\Windows\\System32\\cmd.exe");
            const auto withBat = [&](const QString& cmdLine) {
                bulwark::SecurityEvent e = mkEvent(kScExe, kStop, 7500, 7501);
                e.chainContext.append(mkNode(7501, 1000, kCmdExe, cmdLine));
                return e;
            };
            const auto batAction = [&](const QString& cmdLine) {
                bulwark::SecurityEvent e = withBat(cmdLine);
                return eng2.evaluate(e).action;
            };
            check(batAction(QStringLiteral("cmd.exe /c \"C:\\DevScripts\\stop-driver.bat\""))
                      == bulwark::VerdictAction::Allow,
                  QStringLiteral("cmd /c 已加白文件夹里的 .bat -> 其子进程放行"));
            check(batAction(QStringLiteral("cmd.exe /d /c C:\\DevScripts\\stop-driver.cmd arg1"))
                      == bulwark::VerdictAction::Allow,
                  QStringLiteral("cmd /d /c 已加白文件夹里的 .cmd(带参数)-> 放行"));
            check(batAction(QStringLiteral("cmd.exe /c C:\\Other\\x.bat"))
                      == bulwark::VerdictAction::Ask,
                  QStringLiteral("cmd /c 不在已加白文件夹的 .bat -> 不豁免"));
            check(batAction(QStringLiteral("cmd.exe /c C:\\DevScripts\\a.bat & evil.exe"))
                      == bulwark::VerdictAction::Ask,
                  QStringLiteral("cmd /c 脚本后夹带串接(& evil.exe)-> 不豁免"));
            check(batAction(QStringLiteral("cmd.exe /c calc.exe C:\\DevScripts\\a.bat"))
                      == bulwark::VerdictAction::Ask,
                  QStringLiteral("cmd /c 后紧邻的不是脚本文件(脚本只是第二个参数)-> 不豁免"));
            check(batAction(QStringLiteral("cmd.exe /c echo C:\\DevScripts\\a.bat"))
                      == bulwark::VerdictAction::Ask,
                  QStringLiteral("cmd /c echo <脚本路径>(只是文本)-> 不豁免"));
        }

        {
            const QString kInnoTmp = QStringLiteral("C:\\Users\\u\\AppData\\Local\\Temp\\is-ABCDE.tmp\\Bulwark-Setup.tmp");
            bulwark::SecurityEvent spoof = mkEvent(kScExe, kStop, 7400, 7401);
            spoof.chainContext.append(mkNode(7401, 1000, kInnoTmp, QStringLiteral("\"") + kInnoTmp + QStringLiteral("\" /SL5")));
            check(eng.evaluate(spoof).action == bulwark::VerdictAction::Ask,
                  QStringLiteral("安装程序阶段:祖先只是 %TEMP%\\is-*.tmp 路径形态、没被现验为本产品签名 -> 仍询问(路径不是证据)"));
            bulwark::SecurityEvent verified = mkEvent(kScExe, kStop, 7402, 7403);
            verified.productSignedAncestor = true;
            const bulwark::Verdict vv = eng.evaluate(verified);
            check(vv.action == bulwark::VerdictAction::Allow && !verified.hasThreatIndicator,
                  QStringLiteral("安装程序阶段:祖先被现验为『带有效签名且证书与本服务相同』-> 放行,无硬指标"));
            bulwark::SecurityEvent chained = mkEvent(
                kScExe, kStop + QStringLiteral(" & sc stop WinDefend"), 7406, 7407);
            chained.productSignedAncestor = true;
            check(eng.evaluate(chained).action != bulwark::VerdictAction::Allow,
                  QStringLiteral("安装程序阶段:命令里夹带串接(& sc stop WinDefend)-> 不豁免"));
            const QString kFakeSc = QStringLiteral("C:\\Users\\u\\Downloads\\sc.exe");
            bulwark::SecurityEvent fakeOff = mkEvent(kFakeSc, kStop, 7408, 7409);
            bulwark::SecurityEvent fakeOn = mkEvent(kFakeSc, kStop, 7410, 7411);
            fakeOn.productSignedAncestor = true;
            check(eng.evaluate(fakeOn).action == eng.evaluate(fakeOff).action,
                  QStringLiteral("安装程序阶段:sc.exe 不在 %SystemRoot% 下 -> 标记不改变结论"));
            SelfProtection::enabled.store(false);
            bulwark::SecurityEvent offFlag = mkEvent(kScExe, kStop, 7412, 7413);
            offFlag.productSignedAncestor = true;
            const bulwark::VerdictAction offAct = eng.evaluate(offFlag).action;
            SelfProtection::enabled.store(true);
            check(offAct == bulwark::VerdictAction::Allow,
                  QStringLiteral("自保护告警关闭时:放行(微软签名 sc.exe,与引入该检测之前一致)"));
        }
        bulwark::setFixedNowUtcForTest(QDateTime());
    }

    {
        const BulwarkOptions def;
        check(def.Etw.KernelFileWriteAttribution && def.Etw.Enabled && def.Etw.KernelFile,
              QStringLiteral("写入归因默认开(且 ETW / Kernel-File 总开关为开,归因才真的会起来)"));
        check(def.Etw.PerProcessFilePerMinute == 240 && def.Etw.DedupWindowSeconds == 60
                  && def.Etw.RawChannelCapacity == 8192 && def.Etw.AttributionPathMax == 256,
              QStringLiteral("归因开启时的限流 / 去重窗口 / 通道容量 / 路径上限保持开启且数值未变"));
        check(UserModeBehaviorSource::shouldDeferSynthetic(true)
                  && !UserModeBehaviorSource::shouldDeferSynthetic(false),
              QStringLiteral("合成事件:归因开着才延迟,没开立即发(与改动前一致)"));
        check(!UserModeBehaviorSource::shouldEmitSyntheticAfterDefer(true)
                  && UserModeBehaviorSource::shouldEmitSyntheticAfterDefer(false),
              QStringLiteral("合成事件:ETW 已观测到写入则不再发,没观测到才兜底发出"));
        check(UserModeBehaviorSource::kSyntheticDeferMs > 0
                  && UserModeBehaviorSource::kAttributionWindowMs > UserModeBehaviorSource::kSyntheticDeferMs,
              QStringLiteral("合成事件延迟 > 0,且去重窗口大于延迟(ETW 事件早于合成事件到达也认得出)"));
    }

    {
        using Policy = RegistryRollbackPolicy;
        const QSet<QString> existing = {
            QStringLiteral("c:\\program files\\vendor\\app.exe"),
            QStringLiteral("c:\\program files\\vendor\\x.dll"),
            QStringLiteral("c:\\users\\u\\appdata\\local\\temp\\evil.exe"),
            QStringLiteral("c:\\users\\u\\appdata\\local\\temp\\evil.dll"),
            QStringLiteral("c:\\tools\\mine.exe"),
            QStringLiteral("c:\\windows\\system32\\userinit.exe"),
            QStringLiteral("c:\\windows\\explorer.exe"),
            QStringLiteral("c:\\windows\\system32\\rundll32.exe"),
            QStringLiteral("c:\\windows\\system32\\windowspowershell\\v1.0\\powershell.exe"),
            QStringLiteral("c:\\python312\\python.exe"),
            QStringLiteral("c:\\users\\u\\evil.py"),
            QStringLiteral("c:\\tools\\ok.py"),
        };
        const QSet<QString> signedFiles = {
            QStringLiteral("c:\\program files\\vendor\\app.exe"),
            QStringLiteral("c:\\program files\\vendor\\x.dll"),
            QStringLiteral("c:\\windows\\system32\\userinit.exe"),
            QStringLiteral("c:\\windows\\explorer.exe"),
            QStringLiteral("c:\\windows\\system32\\rundll32.exe"),
            QStringLiteral("c:\\windows\\system32\\windowspowershell\\v1.0\\powershell.exe"),
            QStringLiteral("c:\\python312\\python.exe"),
        };
        const QSet<QString> userTrusted = { QStringLiteral("c:\\tools\\mine.exe"), QStringLiteral("c:\\tools\\ok.py") };
        Policy::Deps d;
        d.expandEnv = [](const QString& s) {
            QString r = s;
            r.replace(QStringLiteral("%SystemRoot%"), QStringLiteral("C:\\Windows"), Qt::CaseInsensitive);
            return r;
        };
        d.exists = [&](const QString& p) { return existing.contains(p.toLower()); };
        d.isUserTrusted = [&](const QString& p) { return userTrusted.contains(p.toLower()); };
        d.isSigned = [&](const QString& p) { return signedFiles.contains(p.toLower()); };
        const auto dec = [&](const char* name, const char* data) {
            return Policy::judge(QString::fromUtf8(name), QString::fromUtf8(data), d);
        };
        using D = Policy::Decision;

        check(dec("App", "\"C:\\Program Files\\Vendor\\app.exe\" /silent") == D::KeepTrusted,
              QStringLiteral("回滚判定:带引号 + 参数的已签名程序 -> 保留(旧判据拿整串对白名单,永远命不中)"));
        check(dec("App", "C:\\Program Files\\Vendor\\app.exe /silent") == D::KeepTrusted,
              QStringLiteral("回滚判定:不带引号、路径含空格的已签名程序 -> 保留(按空格逐个试前缀)"));
        check(dec("Evil", "\"C:\\Users\\u\\AppData\\Local\\Temp\\evil.exe\"") == D::Rollback,
              QStringLiteral("回滚判定:Temp 下未签名、未加白 -> 回滚"));
        check(dec("Mine", "C:\\Tools\\mine.exe -x") == D::KeepTrusted,
              QStringLiteral("回滚判定:用户已加白的未签名程序 -> 保留"));
        check(dec("Gone", "\"C:\\Not\\There\\later.exe\"") == D::KeepUnjudgeable,
              QStringLiteral("回滚判定:目标文件不存在(安装器先写注册表后拷文件)-> 不判定、不回滚"));
        check(dec("Rd", "rundll32.exe C:\\Users\\u\\AppData\\Local\\Temp\\evil.dll,Run") == D::Rollback,
              QStringLiteral("回滚判定:rundll32 + Temp 下未签名 dll -> 回滚(宿主的微软签名不替载荷背书)"));
        check(dec("Rd", "rundll32.exe \"C:\\Program Files\\Vendor\\x.dll\",Entry") == D::KeepTrusted,
              QStringLiteral("回滚判定:rundll32 + 已签名 dll -> 保留"));
        check(dec("Ps", "powershell.exe -NoProfile -enc AAAA") == D::Rollback,
              QStringLiteral("回滚判定:powershell -enc 光杆调用(无任何受信载荷文件)-> 回滚,"
                             "即使 powershell.exe 不在 %SystemRoot% 根下、解析不出路径"));
        check(dec("Rd", "rundll32.exe C:\\Not\\There\\x.dll,Entry") == D::KeepUnjudgeable,
              QStringLiteral("回滚判定:宿主声明的载荷此刻不在磁盘上(先写注册表后拷文件)-> 不判定、不回滚"));
        check(dec("Shell", "explorer.exe") == D::KeepTrusted,
              QStringLiteral("回滚判定:Winlogon Shell 默认值 explorer.exe(按 %SystemRoot% 解析)-> 保留"));
        check(dec("Userinit", "C:\\Windows\\system32\\userinit.exe,") == D::KeepTrusted,
              QStringLiteral("回滚判定:Winlogon Userinit 默认值(尾逗号)-> 保留"));
        check(dec("Userinit", "C:\\Windows\\system32\\userinit.exe,C:\\Users\\u\\AppData\\Local\\Temp\\evil.exe")
                  == D::Rollback,
              QStringLiteral("回滚判定:Userinit 追加一项未签名程序 -> 逐项判,回滚"));
        check(dec("Shell", "%SystemRoot%\\explorer.exe") == D::KeepTrusted,
              QStringLiteral("回滚判定:环境变量先展开再解析"));
        check(dec("Py", "\"C:\\Python312\\python.exe\" C:\\Users\\u\\evil.py") == D::Rollback,
              QStringLiteral("回滚判定:有效签名的解释器 python.exe + 未签名脚本 -> 回滚(解释器的签名不替脚本背书)"));
        check(dec("Py", "\"C:\\Python312\\python.exe\" C:\\Tools\\ok.py") == D::KeepTrusted,
              QStringLiteral("回滚判定:解释器 + 用户已加白的脚本 -> 保留"));
        check(dec("Py", "\"C:\\Python312\\python.exe\" -c \"import x\"") == D::Rollback,
              QStringLiteral("回滚判定:解释器的光杆调用(命令行里没有任何脚本文件路径)-> 回滚"));
        check(dec("Userinit", "C:\\Windows\\system32\\userinit.exe,C:\\Not\\There\\later.exe") == D::Rollback,
              QStringLiteral("回滚判定:Userinit 列表追加一项此刻不存在的程序 -> 回滚(不被 userinit.exe 的签名整条背书)"));
        check(dec("Shell", "explorer.exe,C:\\Not\\There\\later.exe") == D::Rollback,
              QStringLiteral("回滚判定:Shell 列表追加一项此刻不存在的程序 -> 回滚"));
        check(!Policy::isScriptHostOrLolbin(QStringLiteral("C:\\Program Files\\Vendor\\app.exe"))
                  && Policy::isScriptHostOrLolbin(QStringLiteral("C:\\Windows\\System32\\RUNDLL32.EXE")),
              QStringLiteral("脚本宿主 / LOLBin 名单:大小写不敏感,普通程序不在其中"));

        const BulwarkOptions def;
        check(def.RegistryInstantRollbackEnabled && def.RegistryRollbackWinlogonEnabled
                  && !def.RegistryDenyWriteEnabled,
              QStringLiteral("③ 默认值:即时回滚开、Winlogon 开、跨重启注册表 DENY ACE 关"));
    }

    {
        using W = Worker;
        const BulwarkOptions def;
        check(!def.FileDenyExecuteEnabled && def.FileDenyExecuteConfirmedEnabled,
              QStringLiteral("跨重启执行阻断:宽口径默认关,隔离删除失败兜底默认开"));

        check(W::isTaintRuleNote(W::taintRuleTag() + QStringLiteral(" x.exe")),
              QStringLiteral("污点 note:带前缀 -> 是污点规则"));
        check(!W::isTaintRuleNote(QStringLiteral("用户规则 ") + W::taintRuleTag())
                  && !W::isTaintRuleNote(QString()),
              QStringLiteral("污点 note:前缀不在开头 / 空串 -> 不是污点规则"));
    }

    {
        using RG = monitoring::RevocationGate;
        using V = RG::Verdict;
        auto fakeNow = std::make_shared<std::atomic<qint64>>(1000);
        const auto fakeClock = [fakeNow] { return fakeNow->load(); };
        const auto answered = [](V v) { RG::Outcome o; o.verdict = v; o.unreachable = false; return o; };
        const auto unreachable = [] { return RG::Outcome(); };

        {
            RG gate(RG::Config(), fakeClock);
            int calls = 0;
            const auto chk = [&] { ++calls; return answered(V::Good); };
            check(gate.query(QStringLiteral("AA"), chk, 2000) == V::Good && calls == 1,
                  QStringLiteral("吊销闸:预算内问到 -> 返回结论"));
            check(gate.query(QStringLiteral("AA"), chk, 2000) == V::Good && calls == 1,
                  QStringLiteral("吊销闸:同一证书第二次直接命中缓存,不再联网"));
            fakeNow->fetch_add(6LL * 3600 * 1000 + 1);
            check(gate.query(QStringLiteral("AA"), chk, 2000) == V::Good && calls == 2,
                  QStringLiteral("吊销闸:Good 缓存 6 小时后过期,重新问一次"));
        }
        {
            RG gate(RG::Config(), fakeClock);
            int calls = 0;
            const auto bad = [&] { ++calls; return unreachable(); };
            check(gate.query(QStringLiteral("BB"), bad, 2000) == V::Unknown && calls == 1,
                  QStringLiteral("吊销闸:没问到 -> 按 Unknown(不阻止放行)"));
            check(gate.query(QStringLiteral("BB"), bad, 2000) == V::Unknown && calls == 1,
                  QStringLiteral("吊销闸:没问到的结果有 5 分钟负缓存,不会对同一证书反复撞网络"));
            fakeNow->fetch_add(5LL * 60 * 1000 + 1);
            gate.query(QStringLiteral("BB"), bad, 2000);
            check(calls == 2, QStringLiteral("吊销闸:负缓存 5 分钟后到期,允许再问"));

            RG g2(RG::Config(), fakeClock);
            const auto rev = [&] { return answered(V::Revoked); };
            check(g2.query(QStringLiteral("CC"), rev, 2000) == V::Revoked && g2.isKnownRevoked(QStringLiteral("CC")),
                  QStringLiteral("吊销闸:问到已吊销 -> 返回 Revoked,并进入『已知吊销』集合"));
            fakeNow->fetch_add(7LL * 24 * 3600 * 1000 - 1000);
            check(g2.isKnownRevoked(QStringLiteral("CC")),
                  QStringLiteral("吊销闸:Revoked 在 7 天内一直有效"));
            fakeNow->fetch_add(2000);
            check(!g2.isKnownRevoked(QStringLiteral("CC")),
                  QStringLiteral("吊销闸:Revoked 缓存 7 天后过期"));
        }
        {
            RG gate(RG::Config(), fakeClock);
            int calls = 0;
            bool healthy = false;
            const auto chk = [&] { ++calls; return healthy ? answered(V::Good) : unreachable(); };
            gate.query(QStringLiteral("K1"), chk, 2000);
            gate.query(QStringLiteral("K2"), chk, 2000);
            check(!gate.breakerOpen(), QStringLiteral("吊销闸:连续 2 次没问到,熔断尚未打开"));
            gate.query(QStringLiteral("K3"), chk, 2000);
            check(gate.breakerOpen() && calls == 3, QStringLiteral("吊销闸:连续 3 次没问到 -> 熔断打开"));
            gate.query(QStringLiteral("K4"), chk, 2000);
            check(calls == 3, QStringLiteral("吊销闸:熔断期间对新证书一律不联网(只剩本机缓存 CRL)"));
            fakeNow->fetch_add(10LL * 60 * 1000 + 1);
            check(!gate.breakerOpen(), QStringLiteral("吊销闸:冷却 10 分钟后进入半开"));
            gate.query(QStringLiteral("K5"), chk, 2000);
            check(calls == 4 && gate.breakerOpen(),
                  QStringLiteral("吊销闸:半开只放一个探测,探测失败则熔断重新打开"));
            fakeNow->fetch_add(10LL * 60 * 1000 + 1);
            healthy = true;
            check(gate.query(QStringLiteral("K6"), chk, 2000) == V::Good && calls == 5 && !gate.breakerOpen()
                      && gate.consecutiveFailures() == 0,
                  QStringLiteral("吊销闸:探测成功 -> 熔断解除、失败计数清零"));
        }
        {
            RG gate(RG::Config(), fakeClock);
            std::mutex gm;
            std::condition_variable gcv;
            bool release = false;
            std::atomic<int> started{0};
            std::atomic<int> otherCalls{0};
            QStringList lateKeys;
            std::mutex lateMx;
            gate.setLateHook([&](const QString& k) { std::lock_guard<std::mutex> lk(lateMx); lateKeys << k; });
            const auto slow = [&] {
                ++started;
                std::unique_lock<std::mutex> lk(gm);
                gcv.wait(lk, [&] { return release; });
                return answered(V::Revoked);
            };
            QElapsedTimer tm;
            tm.start();
            const V first = gate.query(QStringLiteral("S1"), slow, 30);
            const qint64 waited = tm.elapsed();
            check(first == V::Unknown && waited >= 20 && waited < 1500,
                  QStringLiteral("吊销闸:检查被挡住时,调用方只等预算(30ms)就放手,按 Unknown 放行"));
            check(gate.laneBusy() && gate.consecutiveFailures() == 1,
                  QStringLiteral("吊销闸:放手后车道仍在后台占用;这次等超时计 1 次失败"));
            tm.restart();
            const V second = gate.query(QStringLiteral("S2"), [&] { ++otherCalls; return answered(V::Good); }, 2000);
            check(second == V::Unknown && otherCalls == 0 && tm.elapsed() < 500,
                  QStringLiteral("吊销闸:车道忙时第二个请求不排队、立即按 Unknown 返回,且不执行它的检查"));
            check(started == 1, QStringLiteral("吊销闸:同一时刻只有一个在线检查在途"));
            { std::lock_guard<std::mutex> lk(gm); release = true; }
            gcv.notify_all();
            check(gate.waitIdle(5000), QStringLiteral("吊销闸:放开后车道线程收尾"));
            check(gate.peek(QStringLiteral("S1")) == V::Revoked && gate.isKnownRevoked(QStringLiteral("S1")),
                  QStringLiteral("吊销闸:晚到的结论已回填缓存(之后同一证书的查询直接命中)"));
            { std::lock_guard<std::mutex> lk(lateMx);
              check(lateKeys == QStringList{ QStringLiteral("S1") },
                    QStringLiteral("吊销闸:晚到的『已吊销』触发一次宿主回调(用于记 warning)")); }
            check(gate.query(QStringLiteral("S1"), slow, 30) == V::Revoked && started == 1,
                  QStringLiteral("吊销闸:晚到结论回填后,下一次查询直接拿到 Revoked,不再联网"));
        }
        {
            RG gate(RG::Config(), fakeClock);
            std::atomic<int> calls{0};
            const auto chk = [&] { ++calls; return answered(V::Good); };
            const V v = gate.query(QStringLiteral("P1"), chk, 0);
            check(v == V::Unknown, QStringLiteral("吊销闸:预算 0 -> 本次一定按 Unknown 返回(从不等)"));
            check(gate.waitIdle(5000) && gate.peek(QStringLiteral("P1")) == V::Good && gate.consecutiveFailures() == 0,
                  QStringLiteral("吊销闸:预算 0 时检查仍在后台跑完并回填缓存"));
        }
        {
            RG::Config cfg;
            cfg.cacheCapacity = 8;
            RG gate(cfg, fakeClock);
            const auto chk = [&] { return answered(V::Good); };
            for (int i = 0; i < 40; ++i)
                gate.query(QStringLiteral("CAP%1").arg(i), chk, 2000);
            check(gate.peek(QStringLiteral("CAP39")) == V::Good,
                  QStringLiteral("吊销闸:缓存满后仍能写入新结论(容量有界,不会无限增长)"));
        }

        const BulwarkOptions def;
        check(def.OnlineCertRevocationCheck && def.AbusedSignerThumbprints.isEmpty()
                  && def.AbusedSignerPublishers.isEmpty(),
              QStringLiteral("⑦ 默认值:OnlineCertRevocationCheck 开;AbusedSignerThumbprints / Publishers 保持空(不编造情报)"));
        check(monitoring::ProcessInspector::onlineRevocationBudgetMs == 800,
              QStringLiteral("⑦ 默认值:富化线程等在线吊销检查的预算 800ms(与 InlineReputationBudgetMs 默认值一致)"));
    }

    {
        using bulwark::promptTimeoutShouldBlock;
        check(promptTimeoutShouldBlock(false, true, true, 70),
              QStringLiteral("超时分档:分档开 + 硬指标 + 风险 70 -> 拦截(含边界 70)"));
        check(promptTimeoutShouldBlock(false, true, true, 95),
              QStringLiteral("超时分档:分档开 + 硬指标 + 风险 95 -> 拦截"));
        check(!promptTimeoutShouldBlock(false, true, true, 69),
              QStringLiteral("超时分档:风险 69(差 1 分)-> 仍按默认放行"));
        check(!promptTimeoutShouldBlock(false, true, false, 99),
              QStringLiteral("超时分档:没有硬指标,风险分再高也只按默认放行(分数单独不构成理由)"));
        check(!promptTimeoutShouldBlock(false, false, true, 99),
              QStringLiteral("超时分档:分档开关关 + 硬指标 + 风险 99 -> 按默认放行(关就是关)"));
        check(promptTimeoutShouldBlock(true, false, false, 0) && promptTimeoutShouldBlock(true, true, false, 10),
              QStringLiteral("超时分档:全局『默认拦截未知行为』开着 -> 任何超时都拦(既有语义不变)"));
        check(!promptTimeoutShouldBlock(false, true, false, 0),
              QStringLiteral("超时分档:默认放行 + 无硬指标 + 低分 -> 放行(绝大多数询问不受影响)"));
        check(bulwark::kPromptTimeoutBlockMinRisk == 70,
              QStringLiteral("超时分档:起点风险分固定为 70"));

        const bulwark::RuntimeSettings rs;
        check(rs.promptTimeoutBlockHighRisk && !rs.defaultBlock
                  && promptTimeoutShouldBlock(rs, true, 80) && !promptTimeoutShouldBlock(rs, false, 80),
              QStringLiteral("⑥ 默认值(RuntimeSettings):分档开、全局默认拦截关;按 RuntimeSettings 判与按四个布尔判一致"));
        const BulwarkOptions def;
        check(def.PromptTimeoutBlockHighRisk && def.DefaultAction == bulwark::VerdictAction::Allow
                  && def.PromptTimeoutSeconds == 30,
              QStringLiteral("⑥ 默认值(BulwarkOptions):分档开;DefaultAction 仍是 Allow、PromptTimeoutSeconds 仍是 30"));
    }

    {
        BulwarkOptions fromFile;
        const QString jsonPath =
            QDir(QCoreApplication::applicationDirPath()).filePath(QStringLiteral("appsettings.json"));
        if (QFileInfo::exists(jsonPath) && fromFile.loadFromFile(jsonPath)) {
            const BulwarkOptions def;
            check(fromFile.Etw.KernelFileWriteAttribution == def.Etw.KernelFileWriteAttribution
                      && fromFile.Etw.PerProcessFilePerMinute == def.Etw.PerProcessFilePerMinute
                      && fromFile.Etw.DedupWindowSeconds == def.Etw.DedupWindowSeconds
                      && fromFile.Etw.RawChannelCapacity == def.Etw.RawChannelCapacity
                      && def.Etw.KernelFileWriteAttribution && def.Etw.PerProcessFilePerMinute > 0
                      && def.Etw.DedupWindowSeconds > 0 && def.Etw.RawChannelCapacity > 0,
                  QStringLiteral("配置层 ①:Etw.KernelFileWriteAttribution=开,限流三项(每进程每分钟 / 去重窗口 / 通道容量)仍 >0,JSON 与结构体一致"));
            check(fromFile.RegistryInstantRollbackEnabled == def.RegistryInstantRollbackEnabled
                      && fromFile.RegistryRollbackWinlogonEnabled == def.RegistryRollbackWinlogonEnabled
                      && fromFile.RegistryDenyWriteEnabled == def.RegistryDenyWriteEnabled,
                  QStringLiteral("配置层 ③:RegistryInstantRollbackEnabled / RegistryRollbackWinlogonEnabled / RegistryDenyWriteEnabled,JSON 与结构体一致"));
            check(fromFile.FileDenyExecuteEnabled == def.FileDenyExecuteEnabled
                      && fromFile.FileDenyExecuteConfirmedEnabled == def.FileDenyExecuteConfirmedEnabled
                      && !fromFile.FileDenyExecuteEnabled,
                  QStringLiteral("配置层:FileDenyExecuteEnabled(宽)=关、FileDenyExecuteConfirmedEnabled(隔离失败兜底)=开,JSON 与结构体一致"));
            check(fromFile.SelfProtectionAlertEnabled == def.SelfProtectionAlertEnabled
                      && fromFile.InstallDirAclSelfCheckEnabled == def.InstallDirAclSelfCheckEnabled,
                  QStringLiteral("配置层 ⑤ ⑫c:SelfProtectionAlertEnabled / InstallDirAclSelfCheckEnabled,JSON 与结构体一致"));
            check(fromFile.PromptTimeoutBlockHighRisk == def.PromptTimeoutBlockHighRisk
                      && fromFile.DefaultAction == def.DefaultAction
                      && fromFile.PromptTimeoutSeconds == def.PromptTimeoutSeconds,
                  QStringLiteral("配置层 ⑥:PromptTimeoutBlockHighRisk=开,DefaultAction 仍 Allow、PromptTimeoutSeconds 仍 30,JSON 与结构体一致"));
            check(fromFile.OnlineCertRevocationCheck == def.OnlineCertRevocationCheck
                      && fromFile.AbusedSignerThumbprints.isEmpty() && fromFile.AbusedSignerPublishers.isEmpty(),
                  QStringLiteral("配置层 ⑦:OnlineCertRevocationCheck=开,AbusedSigner 两份名单保持空(不编造情报),JSON 与结构体一致"));
        } else {
            out << "  SKIP 配置层一致性:exe 旁没有可解析的 appsettings.json(" << jsonPath << ")\n";
        }
    }

    out << "\n=== " << pass << "/" << total << " passed ===\n";
    out.flush();
    return (pass == total) ? 0 : 2;
}

int runIpcSelfTest() {
    namespace bi = bulwark::ipc;
    QTextStream out(stdout);
    out << "=== IPC routing selftest (A5 unicast / A7 authenticated PID) ===\n";

    int pass = 0, total = 0;
    const auto check = [&](bool ok, const QString& what) {
        ++total;
        if (ok) ++pass;
        out << (ok ? "  PASS " : "  FAIL ") << what << "\n";
        out.flush();
    };

    const auto pumpUntil = [](const std::function<bool()>& done, int timeoutMs) {
        QElapsedTimer t;
        t.start();
        while (!done() && t.elapsed() < timeoutMs) {
            QEventLoop loop;
            QTimer::singleShot(10, &loop, &QEventLoop::quit);
            loop.exec();
        }
        return done();
    };
    const auto settle = [&pumpUntil](int ms) { pumpUntil([] { return false; }, ms); };

    {
        IpcClientAuth::Policy pol;
        pol.installDir = QDir::toNativeSeparators(QCoreApplication::applicationDirPath());
        pol.allowedImageNames << QFileInfo(QCoreApplication::applicationFilePath()).fileName();
        IpcClientAuth::configure(pol);
    }

    const auto sentinel = [](const char* tag) {
        return QString::fromLatin1(tag) + QUuid::createUuid().toString(QUuid::Id128);
    };
    const QByteArray kAiKey    = sentinel("SELFTEST-AIKEY-").toUtf8();
    const QByteArray kVtKey    = sentinel("SELFTEST-VTKEY-").toUtf8();
    const QByteArray kCmdline  = sentinel("SELFTEST-CMDLINE-").toUtf8();
    const QByteArray kTimeline = sentinel("SELFTEST-TIMELINE-").toUtf8();
    const QByteArray kStray    = sentinel("SELFTEST-STRAY-").toUtf8();

    IpcServer server;
    server.settingsRequested = [&] {
        bulwark::RuntimeSettings s;
        s.aiApiKey = QString::fromUtf8(kAiKey);
        return s;
    };
    server.rulesRequested = [] { return QList<bulwark::DefenseRule>{}; };
    int ruleAdds = 0;
    server.ruleAddRequested = [&](const bi::AddRulePayload&) { ++ruleAdds; };
    QList<bi::ProcessListRequestPayload> pendingProc;
    server.processListRequested = [&](const bi::ProcessListRequestPayload& r) { pendingProc << r; };
    QList<bi::TimelineRequestPayload> pendingTimeline;
    server.timelineRequested = [&](const bi::TimelineRequestPayload& r) { pendingTimeline << r; };
    server.quarantineRestoreRequested = [](const QUuid& id) {
        return bi::QuarantineActionResultPayload{ id, true, QStringLiteral("ok") };
    };
    server.quarantineListRequested = [] { return bi::QuarantineListResponsePayload{}; };
    QList<int> grantedPids;
    server.uiProcessConnected = [&](int pid) { grantedPids << pid; };

    const QString pipe = QStringLiteral("Bulwark.Control.selftest.%1.%2")
                             .arg(QCoreApplication::applicationPid())
                             .arg(QUuid::createUuid().toString(QUuid::Id128));
    if (!server.start(pipe)) {
        out << "FAIL: cannot listen on the test pipe " << pipe << "\n";
        return 1;
    }

    struct TestClient {
        QLocalSocket sock;
        QByteArray raw;
        QByteArray buf;
        QList<bi::IpcMessage> msgs;
    };
    TestClient a, b;
    for (TestClient* c : { &a, &b }) {
        QObject::connect(&c->sock, &QLocalSocket::readyRead, &c->sock, [c] {
            const QByteArray chunk = c->sock.readAll();
            c->raw += chunk;
            c->buf += chunk;
            int nl;
            while ((nl = c->buf.indexOf('\n')) >= 0) {
                const QString line = QString::fromUtf8(c->buf.left(nl)).trimmed();
                c->buf.remove(0, nl + 1);
                if (const auto m = bi::IpcMessage::deserialize(line)) c->msgs << *m;
            }
        });
    }
    const auto send = [](TestClient& c, const bi::IpcMessage& m) {
        c.sock.write((m.serialize() + QLatin1Char('\n')).toUtf8());
        c.sock.flush();
    };
    const auto count = [](const TestClient& c, bi::IpcMessageType t) {
        int n = 0;
        for (const bi::IpcMessage& m : c.msgs)
            if (m.type == t) ++n;
        return n;
    };
    const auto firstOf = [](const TestClient& c, bi::IpcMessageType t) {
        for (const bi::IpcMessage& m : c.msgs)
            if (m.type == t) return m;
        return bi::IpcMessage{};
    };
    const auto reset = [](TestClient& c) { c.raw.clear(); c.msgs.clear(); };
    const auto emptyReq = [](bi::IpcMessageType t) { return bi::IpcMessage::create(t, QJsonObject{}); };

    out << "\n-- setup --\n";
    a.sock.connectToServer(pipe);
    pumpUntil([&] { return server.clientCount() == 1; }, 5000);
    b.sock.connectToServer(pipe);
    pumpUntil([&] { return server.clientCount() == 2; }, 5000);
    check(server.clientCount() == 2,
          QStringLiteral("two in-process clients passed IpcClientAuth (connected %1, rejected %2)")
              .arg(server.clientCount()).arg(server.rejectedConnectionCount()));
    if (server.clientCount() != 2) {
        out << "\n=== aborted: clients could not connect; nothing else is meaningful ===\n";
        server.stop();
        return 2;
    }

    out << "\n-- Hello uses the authenticated PID (A7) --\n";
    {
        bi::HelloPayload h;
        h.processId = 4;
        send(a, bi::IpcMessage::from(bi::IpcMessageType::Hello, h));
        pumpUntil([&] { return !grantedPids.isEmpty(); }, 3000);
        const int self = static_cast<int>(QCoreApplication::applicationPid());
        check(grantedPids.size() == 1 && grantedPids.first() == self,
              QStringLiteral("host was handed the real PID %1, not the self-reported 4 (got %2)")
                  .arg(self)
                  .arg(grantedPids.isEmpty() ? QStringLiteral("nothing") : QString::number(grantedPids.first())));
    }

    out << "\n-- query responses are unicast (A5) --\n";
    reset(a); reset(b);
    send(a, emptyReq(bi::IpcMessageType::SettingsRequest));
    pumpUntil([&] { return count(a, bi::IpcMessageType::SettingsResponse) > 0; }, 3000);
    settle(300);
    check(count(a, bi::IpcMessageType::SettingsResponse) == 1 && a.raw.contains(kAiKey),
          QStringLiteral("requester receives its SettingsResponse (sentinel key visible to the test)"));
    check(count(b, bi::IpcMessageType::SettingsResponse) == 0,
          QStringLiteral("other client receives no SettingsResponse it did not ask for"));
    check(!b.raw.contains(kAiKey),
          QStringLiteral("other client's byte stream contains neither API key"));

    reset(a); reset(b);
    send(a, emptyReq(bi::IpcMessageType::RulesRequest));
    pumpUntil([&] { return count(a, bi::IpcMessageType::RulesResponse) > 0; }, 3000);
    settle(300);
    check(count(a, bi::IpcMessageType::RulesResponse) == 1 && count(b, bi::IpcMessageType::RulesResponse) == 0,
          QStringLiteral("RulesResponse goes to the requester only"));

    out << "\n-- async responses are routed to the requester; a copied requestId cannot hijack them --\n";
    reset(a); reset(b);
    {
        bi::ProcessListRequestPayload pr;
        const QUuid clientId = pr.requestId;
        send(a, bi::IpcMessage::from(bi::IpcMessageType::ProcessListRequest, pr));
        pumpUntil([&] { return pendingProc.size() == 1; }, 3000);
        send(b, bi::IpcMessage::from(bi::IpcMessageType::ProcessListRequest, pr));
        pumpUntil([&] { return pendingProc.size() == 2; }, 3000);
        check(pendingProc.size() == 2
                  && pendingProc[0].requestId != pendingProc[1].requestId
                  && pendingProc[0].requestId != clientId && pendingProc[1].requestId != clientId,
              QStringLiteral("host sees two distinct server-minted ids, never the client-chosen one"));
        if (pendingProc.size() == 2) {
            bi::ProcessListResponsePayload ra;
            ra.requestId = pendingProc[0].requestId;
            ra.message = QString::fromUtf8(kCmdline);
            server.sendProcessList(ra);
            bi::ProcessListResponsePayload rb;
            rb.requestId = pendingProc[1].requestId;
            rb.message = QStringLiteral("for-B");
            server.sendProcessList(rb);
        }
        pumpUntil([&] {
            return count(a, bi::IpcMessageType::ProcessListResponse) > 0
                && count(b, bi::IpcMessageType::ProcessListResponse) > 0;
        }, 3000);
        settle(300);
        check(count(a, bi::IpcMessageType::ProcessListResponse) == 1
                  && count(b, bi::IpcMessageType::ProcessListResponse) == 1,
              QStringLiteral("each requester receives exactly one ProcessListResponse"));
        check(a.raw.contains(kCmdline) && !b.raw.contains(kCmdline),
              QStringLiteral("A's process snapshot reaches A only, although B sent the same requestId"));
        const auto pa = firstOf(a, bi::IpcMessageType::ProcessListResponse).payloadAs<bi::ProcessListResponsePayload>();
        const auto pb = firstOf(b, bi::IpcMessageType::ProcessListResponse).payloadAs<bi::ProcessListResponsePayload>();
        check(pa.requestId == clientId && pb.requestId == clientId,
              QStringLiteral("each response carries the client's own requestId on the wire (UI filters unchanged)"));
    }

    out << "\n-- pushes still reach every client --\n";
    reset(a); reset(b);
    server.sendPrompt(bulwark::SecurityEvent{});
    server.sendSettings();
    pumpUntil([&] {
        return count(a, bi::IpcMessageType::PromptRequest) && count(b, bi::IpcMessageType::PromptRequest)
            && count(a, bi::IpcMessageType::SettingsResponse) && count(b, bi::IpcMessageType::SettingsResponse);
    }, 3000);
    check(count(a, bi::IpcMessageType::PromptRequest) == 1 && count(b, bi::IpcMessageType::PromptRequest) == 1,
          QStringLiteral("PromptRequest is broadcast to all clients"));
    check(count(a, bi::IpcMessageType::SettingsResponse) == 1 && count(b, bi::IpcMessageType::SettingsResponse) == 1,
          QStringLiteral("state-change settings push (sendSettings() with no target) is still broadcast"));

    out << "\n-- mutations: result to requester, fresh snapshot to everyone --\n";
    reset(a); reset(b);
    {
        bi::AddRulePayload ar;
        ar.actorPath = QStringLiteral("C:\\selftest\\never-exists.exe");
        send(a, bi::IpcMessage::from(bi::IpcMessageType::AddRule, ar));
    }
    pumpUntil([&] {
        return count(a, bi::IpcMessageType::RulesResponse) && count(b, bi::IpcMessageType::RulesResponse);
    }, 3000);
    check(ruleAdds == 1, QStringLiteral("AddRule reached the host"));
    check(count(a, bi::IpcMessageType::RulesResponse) == 1 && count(b, bi::IpcMessageType::RulesResponse) == 1,
          QStringLiteral("post-change rules snapshot is broadcast"));

    reset(a); reset(b);
    {
        bi::QuarantineActionPayload qa;
        qa.id = QUuid::createUuid();
        send(a, bi::IpcMessage::from(bi::IpcMessageType::QuarantineRestore, qa));
    }
    pumpUntil([&] {
        return count(a, bi::IpcMessageType::QuarantineActionResult)
            && count(a, bi::IpcMessageType::QuarantineListResponse)
            && count(b, bi::IpcMessageType::QuarantineListResponse);
    }, 3000);
    settle(300);
    check(count(a, bi::IpcMessageType::QuarantineActionResult) == 1
              && count(b, bi::IpcMessageType::QuarantineActionResult) == 0,
          QStringLiteral("QuarantineActionResult goes to the requester only"));
    check(count(a, bi::IpcMessageType::QuarantineListResponse) == 1
              && count(b, bi::IpcMessageType::QuarantineListResponse) == 1,
          QStringLiteral("post-change quarantine list is broadcast"));

    out << "\n-- orphaned or unrouted async responses are dropped, not broadcast --\n";
    reset(b);
    send(a, bi::IpcMessage::from(bi::IpcMessageType::EventTimelineRequest, bi::TimelineRequestPayload{}));
    pumpUntil([&] { return pendingTimeline.size() == 1; }, 3000);
    a.sock.abort();
    pumpUntil([&] { return server.clientCount() == 1; }, 3000);
    check(pendingTimeline.size() == 1 && server.clientCount() == 1,
          QStringLiteral("timeline request reached the host and the requester's disconnect was observed"));
    if (!pendingTimeline.isEmpty()) {
        bi::TimelineResponsePayload late;
        late.requestId = pendingTimeline[0].requestId;
        late.message = QString::fromUtf8(kTimeline);
        server.sendTimeline(late);
        server.sendTimeline(late);   // 重复回推同一个 id:路由已被取走,同样必须丢弃
    }
    {
        bi::ProcessListResponsePayload stray;
        stray.requestId = QUuid::createUuid();
        stray.message = QString::fromUtf8(kStray);
        server.sendProcessList(stray);
    }
    settle(400);
    check(count(b, bi::IpcMessageType::EventTimelineResponse) == 0 && !b.raw.contains(kTimeline),
          QStringLiteral("remaining client does not receive the departed requester's timeline"));
    check(count(b, bi::IpcMessageType::ProcessListResponse) == 0 && !b.raw.contains(kStray),
          QStringLiteral("a response with an unregistered requestId reaches nobody"));

    out << "\n-- prompt auto-timeout is not a user verdict (item 6) --\n";
    {
        int userVerdicts = 0, autoTimeouts = 0;
        QUuid lastAuto;
        QObject::connect(&server, &IpcServer::promptResponse, &server,
                         [&](const QUuid&, bulwark::VerdictAction, bool, bulwark::RememberScope) {
                             ++userVerdicts;
                         });
        QObject::connect(&server, &IpcServer::promptAutoTimeout, &server,
                         [&](const QUuid& id) { ++autoTimeouts; lastAuto = id; });
        reset(b);

        bi::PromptResponsePayload user;
        user.eventId = QUuid::createUuid();
        user.action = bulwark::VerdictAction::Block;
        user.remember = true;
        send(b, bi::IpcMessage::from(bi::IpcMessageType::PromptResponse, user));
        pumpUntil([&] { return userVerdicts == 1; }, 3000);
        check(userVerdicts == 1 && autoTimeouts == 0,
              QStringLiteral("a user verdict still arrives as promptResponse (behaviour unchanged)"));

        bi::PromptResponsePayload autoResp;
        autoResp.eventId = QUuid::createUuid();
        autoResp.action = bulwark::VerdictAction::Block;   // 即便带着 Block + 记住,也不能被当成用户裁决
        autoResp.remember = true;
        autoResp.autoTimeout = true;
        send(b, bi::IpcMessage::from(bi::IpcMessageType::PromptResponse, autoResp));
        pumpUntil([&] { return autoTimeouts == 1; }, 3000);
        settle(100);
        check(autoTimeouts == 1 && userVerdicts == 1 && lastAuto == autoResp.eventId,
              QStringLiteral("an autoTimeout response goes to promptAutoTimeout and is NOT delivered as a user verdict"));
    }

    // 一次读进来的多条消息里,处理到第 65 条时服务端因异步路由超限主动断开这个连接,
    // onDisconnected 同步把它的缓冲从 buffers_ 删掉。之后不能再碰那块缓冲,剩下的消息也不该再派发。
    out << "\n-- a connection dropped while its batch is being handled is not touched afterwards --\n";
    {
        TestClient c;
        c.sock.connectToServer(pipe);
        pumpUntil([&] { return server.clientCount() == 2; }, 5000);
        check(server.clientCount() == 2, QStringLiteral("third client connected for the batch test"));
        pendingTimeline.clear();
        QByteArray batch;
        for (int i = 0; i < 70; ++i)
            batch += (bi::IpcMessage::from(bi::IpcMessageType::EventTimelineRequest, bi::TimelineRequestPayload{})
                          .serialize() + QLatin1Char('\n')).toUtf8();
        c.sock.write(batch);
        c.sock.flush();
        pumpUntil([&] { return server.clientCount() == 1; }, 5000);
        settle(300);
        check(server.clientCount() == 1,
              QStringLiteral("server dropped the client that exceeded the async-request cap"));
        check(pendingTimeline.size() == 64,
              QStringLiteral("exactly 64 requests dispatched; nothing read from the dropped connection's buffer "
                             "afterwards (got %1)").arg(pendingTimeline.size()));
        reset(b);
        send(b, emptyReq(bi::IpcMessageType::SettingsRequest));
        pumpUntil([&] { return count(b, bi::IpcMessageType::SettingsResponse) > 0; }, 3000);
        check(count(b, bi::IpcMessageType::SettingsResponse) == 1,
              QStringLiteral("server still serves the remaining client"));
    }

    server.stop();
    settle(50);

    out << "\n-- install-dir ACL criterion (IPC auth precondition) --\n";
    {
        struct AceSpec { bool allow; const wchar_t* sid; DWORD mask; BYTE flags; };
        const auto grantsWrite = [](std::initializer_list<AceSpec> aces, QStringList* who = nullptr) {
            alignas(DWORD) BYTE buf[2048];
            PACL acl = reinterpret_cast<PACL>(buf);
            InitializeAcl(acl, sizeof(buf), ACL_REVISION);
            for (const AceSpec& a : aces) {
                PSID sid = nullptr;
                ConvertStringSidToSidW(a.sid, &sid);
                if (a.allow)
                    AddAccessAllowedAceEx(acl, ACL_REVISION, a.flags, a.mask, sid);
                else
                    AddAccessDeniedAceEx(acl, ACL_REVISION, a.flags, a.mask, sid);
                LocalFree(sid);
            }
            return InstallDirAclCheck::daclGrantsNonAdminWrite(acl, who);
        };
        constexpr DWORD kReadExec = FILE_GENERIC_READ | FILE_GENERIC_EXECUTE;
        constexpr DWORD kModify = FILE_GENERIC_READ | FILE_GENERIC_WRITE | FILE_GENERIC_EXECUTE | DELETE;
        constexpr DWORD kAllWrite = FILE_GENERIC_WRITE | DELETE | FILE_DELETE_CHILD | WRITE_DAC | WRITE_OWNER;
        const wchar_t* const kAdmins = L"S-1-5-32-544";
        const wchar_t* const kSystem = L"S-1-5-18";
        const wchar_t* const kUsers = L"S-1-5-32-545";
        const wchar_t* const kEveryone = L"S-1-1-0";
        const wchar_t* const kAuthUsers = L"S-1-5-11";

        check(!grantsWrite({ { true, kSystem, FILE_ALL_ACCESS, 0 }, { true, kAdmins, FILE_ALL_ACCESS, 0 },
                             { true, kUsers, kReadExec, 0 } }),
              QStringLiteral("Administrators/SYSTEM full control + Users read-execute -> not writable"));
        QStringList who;
        check(grantsWrite({ { true, kAdmins, FILE_ALL_ACCESS, 0 }, { true, kUsers, kModify, 0 } }, &who)
                  && who.contains(QStringLiteral("Users")),
              QStringLiteral("Users Modify -> writable (named in the report)"));
        check(grantsWrite({ { true, kEveryone, FILE_ALL_ACCESS, 0 } }),
              QStringLiteral("Everyone full control -> writable"));
        check(grantsWrite({ { true, kAuthUsers, kModify, 0 } }),
              QStringLiteral("Authenticated Users Modify -> writable (the cpp\\dist case)"));
        check(!grantsWrite({ { false, kAuthUsers, kAllWrite, 0 }, { true, kAuthUsers, kModify, 0 },
                             { true, kAdmins, FILE_ALL_ACCESS, 0 } }),
              QStringLiteral("deny write precedes allow Modify for the same group -> not writable"));
        check(grantsWrite({ { true, kAuthUsers, kModify, 0 }, { false, kAuthUsers, kAllWrite, 0 } }),
              QStringLiteral("allow Modify precedes deny -> still writable (stored order is honoured)"));
        check(!grantsWrite({ { true, kUsers, FILE_ALL_ACCESS, INHERIT_ONLY_ACE | OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE },
                             { true, kAdmins, FILE_ALL_ACCESS, 0 } }),
              QStringLiteral("inherit-only ACE does not apply to the object itself -> not writable"));
        check(grantsWrite({ { true, kUsers, kReadExec | FILE_ADD_FILE, 0 } }),
              QStringLiteral("Users may create files (FILE_ADD_FILE) -> writable (plant a same-name exe)"));
        {
            QStringList nw;
            check(InstallDirAclCheck::daclGrantsNonAdminWrite(nullptr, &nw) && !nw.isEmpty(),
                  QStringLiteral("NULL DACL = everyone full control -> writable"));
        }
        QTemporaryDir probe;
        if (probe.isValid()) {
            const InstallDirAclCheck::Report rep = InstallDirAclCheck::check(probe.path());
            const QString d = rep.detail();
            check(rep.checked && !rep.targets.isEmpty() && rep.targets.first().readable,
                  QStringLiteral("read-only DACL read of a real directory works (%1)")
                      .arg(rep.intact() ? QStringLiteral("not writable") : QStringLiteral("writable here")));
            Q_UNUSED(d);
        }
    }

    out << "\n-- prompt / block-notification payload round-trips (item 6 / F6) --\n";
    {
        bi::PromptResponsePayload autoResp;
        autoResp.eventId = QUuid::createUuid();
        autoResp.action = bulwark::VerdictAction::Block;
        autoResp.remember = true;
        autoResp.autoTimeout = true;

        const bi::PromptResponsePayload rtAuto = bi::PromptResponsePayload::fromJson(autoResp.toJson());
        bi::PromptResponsePayload plain;
        plain.eventId = QUuid::createUuid();
        check(rtAuto.autoTimeout && rtAuto.eventId == autoResp.eventId
                  && !plain.toJson().contains(QStringLiteral("autoTimeout"))
                  && !bi::PromptResponsePayload::fromJson(plain.toJson()).autoTimeout,
              QStringLiteral("PromptResponsePayload.autoTimeout round-trips; the key is only written when true (old servers see the old wire form)"));

        bi::BlockNotificationPayload bn;
        bn.enforcement = bulwark::EnforcementOutcome::Terminated;
        bn.timeoutBlock = true;
        bn.execBlocked = true;
        const bi::BlockNotificationPayload rtBn = bi::BlockNotificationPayload::fromJson(bn.toJson());
        bi::BlockNotificationPayload oldForm;
        oldForm.enforcement = bulwark::EnforcementOutcome::Terminated;
        const QJsonObject oldJson = oldForm.toJson();
        check(rtBn.timeoutBlock && rtBn.execBlocked && rtBn.enforcement == bulwark::EnforcementOutcome::Terminated
                  && !oldJson.contains(QStringLiteral("timeoutBlock")) && !oldJson.contains(QStringLiteral("execBlocked"))
                  && !bi::BlockNotificationPayload::fromJson(oldJson).timeoutBlock
                  && !bi::BlockNotificationPayload::fromJson(oldJson).execBlocked,
              QStringLiteral("BlockNotificationPayload timeoutBlock / execBlocked round-trip; absent keys read as false (no assumed success)"));

        bulwark::RuntimeSettings rs;
        rs.promptTimeoutBlockHighRisk = false;
        const bulwark::RuntimeSettings rtRs = bulwark::RuntimeSettings::fromJson(rs.toJson());
        const bulwark::RuntimeSettings missing = bulwark::RuntimeSettings::fromJson(QJsonObject{});
        check(!rtRs.promptTimeoutBlockHighRisk && missing.promptTimeoutBlockHighRisk,
              QStringLiteral("RuntimeSettings.promptTimeoutBlockHighRisk round-trips; a missing key falls back to the default (on)"));
    }

    out << "\n=== " << pass << "/" << total << " passed ===\n";
    out.flush();
    return (pass == total) ? 0 : 2;
}

void onTerminate() {
    QString detail = QStringLiteral("std::terminate called");
    if (auto ex = std::current_exception()) {
        try { std::rethrow_exception(ex); }
        catch (const std::exception& e) { detail = QString::fromUtf8(e.what()); }
        catch (...) { detail = QStringLiteral("unknown exception"); }
    }
    writeCrashLog(QStringLiteral("Terminate"), detail);
    std::abort();
}

}

namespace {
void setServiceStopAccepted(bool accept);
}

static int serviceRun(int argc, char** argv) {
    QCoreApplication app(argc, argv);
    QCoreApplication::setApplicationName(QStringLiteral("Bulwark Defense"));
    std::set_terminate(onTerminate);

    ::SetConsoleOutputCP(CP_UTF8);

    // 诊断自检(在任何服务初始化之前处理):只读取证并退出,绝不启动监控/处置。
    {
        const QStringList args = QCoreApplication::arguments();
#ifdef BULWARK_ENABLE_SELFTEST
        const QString repairFlag = QStringLiteral("--repair-full-regression-snapshot");
        const QString restoreFlag = QStringLiteral("--restore-full-regression-snapshot");
        const QString acknowledgement = QStringLiteral("--acknowledge-authorized-repair");
        if (args.contains(repairFlag)) {
            if (args.size() != 3 || !args.contains(acknowledgement)) {
                QTextStream(stderr) << "repair mode accepts only its flag and explicit acknowledgement\n";
                return 2;
            }
            return runSnapshotRepairProduction();
        }
        if (args.contains(restoreFlag)) {
            if (args.size() != 3 || !args.contains(acknowledgement)) {
                QTextStream(stderr) << "restore mode accepts only its flag and explicit acknowledgement\n";
                return 2;
            }
            return restoreLatestSnapshotRepairProduction();
        }
#endif
        const int idx = args.indexOf(QStringLiteral("--inspect"));
        if (idx >= 0)
            return runInspect(idx + 1 < args.size() ? args.at(idx + 1) : QString());
        if (args.contains(QStringLiteral("--regression-selftest")))
            return runServiceRegressionSelfTest();
        if (args.contains(QStringLiteral("--ipc-selftest")))
            return runIpcSelfTest();
    }

    {
        QString recoveryError;
        if (!recoverPendingSnapshotRepairsProduction(&recoveryError)) {
            QTextStream(stderr) << "snapshot repair recovery blocked normal startup: "
                                << recoveryError << "\n";
            return 2;
        }
    }

    startFileLog();
    Logger log(QStringLiteral("bulwark.service.Main"));
    log.info(QStringLiteral("Bulwark 服务启动中(C++/Qt 移植)。"));

    {
        const SelfHardening::Report hr = SelfHardening::hardenCurrentProcess(false);
        for (const QString& s : hr.applied)
            log.info(QStringLiteral("自保护加固 · 已生效:%1").arg(s));
        for (const QString& s : hr.skipped)
            log.warning(QStringLiteral("自保护加固 · 未生效:%1").arg(s));
    }

    BulwarkOptions options;
    const QString appsettings =
        QDir(QCoreApplication::applicationDirPath()).filePath(QStringLiteral("appsettings.json"));
    if (!options.loadFromFile(appsettings))
        log.warning(QStringLiteral("appsettings.json 解析失败,使用默认值: %1").arg(appsettings));

    if (options.ThreatFoxFeed.Enabled && options.ThreatFoxFeed.GenerateDomainRules
        && !options.ThreatFoxFeed.resolveAuthKey().isEmpty() && options.Etw.SuspiciousOnly) {
        options.Etw.SuspiciousOnly = false;
        log.warning(QStringLiteral("ThreatFox 域名规则已启用：Etw.SuspiciousOnly 自动关闭，"
                                   "DNS 事件将经过限流后送入规则引擎，否则普通域名 IOC 无法命中。"));
    }

    monitoring::ProcessInspector::onlineRevocationCheck = options.OnlineCertRevocationCheck;
    monitoring::ProcessInspector::onlineRevocationBudgetMs =
        qBound(0, options.InlineReputationBudgetMs, 3000);

    // 被盗用 / 被滥用的代码签名证书名单(见 TrustPolicy::isAbusedSigner)。
    // 必须在监控线程起来之前注入:名单在裁决热路径上只读无锁。
    bulwark::engine::TrustPolicy::setAbusedSigners(options.AbusedSignerThumbprints,
                                                  options.AbusedSignerPublishers);
    if (!options.AbusedSignerThumbprints.isEmpty() || !options.AbusedSignerPublishers.isEmpty()) {
        log.info(QStringLiteral("已加载被盗用证书名单:指纹 %1 条、签名主体 %2 条")
                     .arg(options.AbusedSignerThumbprints.size())
                     .arg(options.AbusedSignerPublishers.size()));
    }

    bulwark::engine::SelfProtection::enabled.store(options.SelfProtectionAlertEnabled);
    if (!options.SelfProtectionAlertEnabled)
        log.warning(QStringLiteral("自保护告警已关闭(Bulwark:SelfProtectionAlertEnabled=false):"
                                   "停止 / 删除 / 结束本产品自身组件的命令行将不再提示、不再留审计。"));

    {
        const QString selfThumb = monitoring::ProcessInspector::tryGetSignerThumbprint(
            QCoreApplication::applicationFilePath());
        Worker::setProductSignerThumbprint(selfThumb);
        if (selfThumb.isEmpty())
            log.info(QStringLiteral("本服务 exe 没有签名证书(开发 / 未签名构建):自保护告警里『祖先是本产品"
                                    "自己签名的安装程序』这条豁免不生效,升级安装时 Setup 停旧版本的 "
                                    "sc / fltmc / taskkill 会被询问一次。"));
        else
            log.info(QStringLiteral("本服务 exe 的签名证书指纹=%1:祖先进程若是带有效签名且证书相同的程序"
                                    "(本产品自己签名的 Setup / 卸载程序 / 界面),其『停止 / 删除本产品』"
                                    "命令按维护操作放行。").arg(selfThumb));
    }

    if (!options.Etw.KernelFileWriteAttribution)
        log.info(QStringLiteral("部署配置显式关闭了新装默认开启的 Etw.KernelFileWriteAttribution"
                                "(此机生效值=关):勒索诱饵被改写仍只能告警、无法结束写入进程。"));
    if (!options.RegistryInstantRollbackEnabled)
        log.info(QStringLiteral("部署配置显式关闭了新装默认开启的 RegistryInstantRollbackEnabled"
                                "(此机生效值=关):自启动项被改写后只能等 4 秒轮询发现,不会即时回滚。"));
    if (!options.OnlineCertRevocationCheck)
        log.info(QStringLiteral("部署配置显式关闭了新装默认开启的 OnlineCertRevocationCheck"
                                "(此机生效值=关):证书吊销校验只读本机缓存 CRL,不联网。"));

    bulwark::engine::TrustedSoftwareCatalog::instance().load();
    log.info(QStringLiteral("软件信任库已加载:%1 条(内置+用户)")
                 .arg(bulwark::engine::TrustedSoftwareCatalog::instance().apps().size()));

    SettingsStore settingsStore;
    RuleStore ruleStore;
    AuditLog audit;
    FirstSeenStore firstSeen;
    QuarantineManager quarantine;
    EventHistoryStore eventHistory;
    BaselineStore baselineStore;
    AlertExporter alertExporter(options.ExportEcsAlerts);

    bulwark::RuntimeSettings settings;
    settings.trustSignedActors = options.TrustSignedActors;
    settings.eventSource = options.EventSource;
    settings.defaultBlock = (options.DefaultAction == bulwark::VerdictAction::Block);
    settings.promptTimeoutBlockHighRisk = options.PromptTimeoutBlockHighRisk;
    const bool eventSourceDriver =
        options.EventSource.compare(QStringLiteral("Driver"), Qt::CaseInsensitive) == 0;
    if (const auto rs = settingsStore.load()) {
        settings = *rs;
        settings.eventSource = options.EventSource;
        log.info(QStringLiteral("已从 settings.json 载入运行时设置。"));
        if (!settings.kernelDriverEnabledAuthoritative) {
            const bool effective = settings.kernelDriverEnabled || eventSourceDriver;
            if (effective != settings.kernelDriverEnabled)
                log.info(QStringLiteral("设置迁移:「内核驱动」开关按此前实际生效的状态改为开启"
                                        "(EventSource=Driver 一直在加载驱动,开关此前显示为关)。"));
            settings.kernelDriverEnabled = effective;
            settings.kernelDriverEnabledAuthoritative = true;
            settingsStore.save(settings);
        }
    } else {
        settings.kernelDriverEnabled = eventSourceDriver;
        settings.kernelDriverEnabledAuthoritative = true;
    }

    {
        const QString optKey = options.Ai.resolveApiKey();
        int seeded = 0;
        if (settings.aiBaseUrl.trimmed().isEmpty() && !options.Ai.BaseUrl.trimmed().isEmpty()) {
            settings.aiBaseUrl = options.Ai.BaseUrl.trimmed();
            ++seeded;
        }
        if (settings.aiApiKey.trimmed().isEmpty() && !optKey.isEmpty()) {
            settings.aiApiKey = optKey;
            ++seeded;
        }
        if (settings.aiModel.trimmed().isEmpty() && !options.Ai.Model.trimmed().isEmpty()) {
            settings.aiModel = options.Ai.Model.trimmed();
            ++seeded;
        }
        if (seeded > 0) {
            log.info(QStringLiteral("大模型配置自 appsettings 补齐 %1 项(接口=%2 模型=%3 Key=%4)。")
                         .arg(seeded)
                         .arg(settings.aiBaseUrl.isEmpty() ? QStringLiteral("未配置") : settings.aiBaseUrl,
                              settings.aiModel.isEmpty() ? QStringLiteral("服务端默认") : settings.aiModel,
                              settings.aiApiKey.isEmpty() ? QStringLiteral("未配置") : QStringLiteral("已配置")));
        }
        for (const LegacyCacheRemoval& r : removeLegacyAiVerdictCaches(programDataDir())) {
            if (r.removed)
                log.info(QStringLiteral("已删除旧版「AI 全权裁决」的缓存 %1,本版不再读取它。").arg(r.path));
            else
                log.warning(QStringLiteral("旧版「AI 全权裁决」的缓存 %1 删除失败;本版不读取它,可以手动删除。").arg(r.path));
        }
    }

    bulwark::engine::RuleEngine engine;
    engine.trustSignedActors = settings.trustSignedActors;
    engine.enableBaseline = settings.behaviorBaselineEnabled;
    engine.setFileStateProbe(&probeFileStateForRansomware);
    {
        // 解压、覆盖安装也会成批改写 / 删除已有文件:读一眼改写后的文件开头,内容完好的不计入。
        // 探针自带线程和超时,随引擎一起存活。
        auto contentProbe = std::make_shared<bulwark::service::FileContentProbe>();
        engine.setContentProbe([contentProbe](const QString& path) { return contentProbe->sample(path); });
    }
    engine.addSelfDirectory(QCoreApplication::applicationDirPath());
    Worker::setSelfExemptDirs({
        QCoreApplication::applicationDirPath(),
        QDir(qEnvironmentVariable("ProgramData", QStringLiteral("C:\\ProgramData")))
            .filePath(QStringLiteral("Bulwark")),
    });
    QVector<bulwark::DefenseRule> rules = bulwark::engine::DefaultRules::build();
    const QString builtInTag = bulwark::engine::DefaultRules::builtInTag();
    QHash<QString, int> taintSubjectIndexes;
    int collapsedTaintRules = 0;
    int resolvedTaintActionConflicts = 0;
    const auto taintSubjectKey = [](const bulwark::DefenseRule& r) {
        const auto folded = [](const QString& s) { return s.trimmed().toCaseFolded(); };
        QStringList hashes = r.actorHashes.values();
        for (QString& hash : hashes)
            hash = folded(hash);
        hashes.removeDuplicates();
        hashes.sort(Qt::CaseSensitive);

        QJsonArray key;
        key.append(r.type.has_value() ? static_cast<int>(*r.type) : -1);
        key.append(folded(r.actorPath));
        key.append(folded(r.actorPattern));
        key.append(folded(r.targetPattern));
        key.append(folded(r.commandLinePattern));
        key.append(folded(r.parentPattern));
        QJsonArray hashKey;
        for (const QString& hash : hashes)
            hashKey.append(hash);
        key.append(hashKey);
        return QString::fromUtf8(QJsonDocument(key).toJson(QJsonDocument::Compact));
    };
    const auto preferIncomingTaintRule = [](const bulwark::DefenseRule& incoming,
                                            const bulwark::DefenseRule& current) {
        // 同 subject 的动作只保留一个：确定性 Block 不得被后来的关联 Ask 降级；反过来，
        // 新 Block 必须替换旧 Ask。异常的其它动作排在这两档之后。
        const auto actionRank = [](bulwark::VerdictAction action) {
            if (action == bulwark::VerdictAction::Block) return 2;
            if (action == bulwark::VerdictAction::Ask) return 1;
            return 0;
        };
        const int incomingRank = actionRank(incoming.action);
        const int currentRank = actionRank(current.action);
        if (incomingRank != currentRank)
            return incomingRank > currentRank;

        if (incoming.expiresUtc.has_value() != current.expiresUtc.has_value())
            return !incoming.expiresUtc.has_value();
        if (incoming.expiresUtc.has_value() && incoming.expiresUtc != current.expiresUtc)
            return *incoming.expiresUtc > *current.expiresUtc;
        return incoming.createdUtc >= current.createdUtc;
    };

    for (const bulwark::DefenseRule& r : ruleStore.load()) {
        if (r.note.startsWith(builtInTag))
            continue;
        if (r.isTrustEntry()) {
            const bool isDir = r.actorPath.isEmpty() && !r.actorPattern.isEmpty();
            const auto rej = bulwark::engine::TrustPolicy::rejectsWholeProcessTrust(
                isDir ? r.actorPattern : r.actorPath, isDir);
            if (rej.ok) {
                log.warning(QStringLiteral("丢弃已持久化的越权信任项 %1:%2")
                                .arg(isDir ? r.actorPattern : r.actorPath, rej.reason));
                continue;
            }
        }
        if (Worker::isTaintRuleNote(r.note)) {
            const QString key = taintSubjectKey(r);
            const auto found = taintSubjectIndexes.constFind(key);
            if (found != taintSubjectIndexes.constEnd()) {
                bulwark::DefenseRule& current = rules[*found];
                if (current.action != r.action)
                    ++resolvedTaintActionConflicts;
                if (preferIncomingTaintRule(r, current))
                    current = r;
                ++collapsedTaintRules;
                continue;
            }
            taintSubjectIndexes.insert(key, rules.size());
        }
        rules.append(r);
    }
    if (collapsedTaintRules > 0) {
        log.warning(QStringLiteral("启动规则归一化:仅在内存中合并旧释放物污点规则 %1 条"
                                   "(其中动作冲突 %2 条)，rules.json 未在启动时改写。")
                        .arg(collapsedTaintRules)
                        .arg(resolvedTaintActionConflicts));
    }

    {
        int seeded = 0;
        for (const QString& raw : options.TrustedDirectories) {
            const QString dir = raw.trimmed();
            if (dir.isEmpty())
                continue;
            const bulwark::DefenseRule tr = bulwark::DefenseRule::createTrustDirectory(
                dir, QStringLiteral("appsettings 预置信任目录"));
            bool dup = false;
            for (const bulwark::DefenseRule& r : rules)
                if (r.isTrustEntry() && !r.actorPattern.isEmpty()
                    && r.actorPattern.compare(tr.actorPattern, Qt::CaseInsensitive) == 0) {
                    dup = true;
                    break;
                }
            if (!dup) { rules.append(tr); ++seeded; }
        }
        if (seeded > 0)
            log.info(QStringLiteral("已从 appsettings 预置 %1 个信任目录(该目录下程序直接放行)。").arg(seeded));
    }
    engine.loadRules(rules);
    log.info(QStringLiteral("已加载 %1 条规则(内置 + 用户/信任/情报)。").arg(rules.size()));

    if (const auto snap = baselineStore.load()) {
        engine.importBaseline(*snap);
        log.info(QStringLiteral("已载入行为基线画像:%1 个程序。").arg(snap->programs.size()));
    } else {
        log.info(QStringLiteral("无历史行为基线画像(首次运行或文件缺失),从空画像开始学习。"));
    }

    std::function<int(const QVector<bulwark::DefenseRule>&)> applyIntelRules =
        [&engine, &ruleStore](const QVector<bulwark::DefenseRule>& newRules) -> int {
            const QString tag = ThreatFoxFeedOptions::ruleNoteTag();
            int removed = 0;
            for (const bulwark::DefenseRule& r : engine.getRules())
                if (r.note.startsWith(tag) && engine.removeRule(r.id))
                    ++removed;
            for (const bulwark::DefenseRule& r : newRules)
                engine.addRule(r);
            ruleStore.save(engine.getRules());
            return removed;
        };

    reputation::ThreatFoxFeedClient intelClient(options.ThreatFoxFeed);
    reputation::IntelFeedService intelFeed(options.ThreatFoxFeed);
    intelFeed.setRulesReady([applyIntelRules, &log](const QVector<bulwark::DefenseRule>& rules) {
        const int removed = applyIntelRules(rules);
        log.info(QStringLiteral("ThreatFox 情报刷新:清理旧规则 %1 条,注入新规则 %2 条。")
                     .arg(removed).arg(rules.size()));
    });

    {
        int added = 0;
        for (const QString& frag : bulwark::engine::DefaultRules::registryWatchFragments()) {
            if (frag.trimmed().isEmpty()) continue;
            if (options.ProtectedRegistryKeys.contains(frag, Qt::CaseInsensitive)) continue;
            options.ProtectedRegistryKeys.append(frag);
            ++added;
        }
        if (added > 0)
            log.info(QStringLiteral("内置规则库:并入 %1 个受关注注册表键片段(共 %2 条;仅上报、"
                                    "不拦截。不并入则段 2/段 3 的注册表规则结构性永不命中)。")
                         .arg(added).arg(options.ProtectedRegistryKeys.size()));
    }

    IpcServer ipc;

    {
        IpcClientAuth::Policy authPolicy;
        authPolicy.installDir = QCoreApplication::applicationDirPath();
        authPolicy.allowedImageNames = { QStringLiteral("bulwark_ui.exe") };
        authPolicy.requireElevatedAdministrator = true;
        authPolicy.enforceSignature = options.EnforceUiClientSignature;
        authPolicy.allowedThumbprints = options.UiClientAllowedThumbprints;
        authPolicy.allowedPublishers = options.UiClientAllowedPublishers;
        IpcClientAuth::configure(authPolicy);

        if (!authPolicy.enforceSignature) {
            const QString uiPath =
                QDir(QCoreApplication::applicationDirPath()).filePath(QStringLiteral("bulwark_ui.exe"));
            Logger authLog(QStringLiteral("IpcAuth"));
            if (!QFileInfo::exists(uiPath)) {
                authLog.warning(QStringLiteral(
                    "控制管道签名加固未启用,且安装目录下找不到 bulwark_ui.exe(%1),无法判断能否启用。"
                    "当前唯一边界是「映像在安装目录下且文件名为 bulwark_ui.exe」。").arg(uiPath));
            } else if (monitoring::ProcessInspector::isSigned(uiPath)) {
                const QString tp = monitoring::ProcessInspector::getCertInfo(uiPath).thumbprint.trimmed();
                authLog.warning(QStringLiteral(
                    "控制管道签名加固【可以启用但当前是关的】:本服务已能验通 %1 的数字签名。"
                    "建议在 appsettings.json 置 \"EnforceUiClientSignature\": true%2 —— "
                    "不启用时,有管理员权限的程序把安装目录里的 bulwark_ui.exe 换成自己的程序,"
                    "就能连上控制管道取得本产品的全部控制权(关防护 / 加白任意路径 / 结束任意进程树 / "
                    "还原隔离区)。抢在真界面发出 Hello 前注入它这条路,由内核驱动按映像身份剥权挡住,"
                    "待机时驱动不在,这条路仍开着。")
                        .arg(uiPath,
                             tp.isEmpty()
                                 ? QString()
                                 : QStringLiteral(",并可一并收窄 \"UiClientAllowedThumbprints\": [\"%1\"]").arg(tp)));
            } else {
                authLog.warning(QStringLiteral(
                    "控制管道签名加固未启用,且 %1 当前没有本服务可验通的数字签名,"
                    "所以现在【不能】启用(启用会导致 UI 连不上)。当前边界是「已提升的管理员进程,"
                    "且映像在安装目录下、文件名为 bulwark_ui.exe」:有管理员权限的程序替换掉安装目录里的"
                    "bulwark_ui.exe 就能连上控制管道。对发布的 bulwark_ui.exe 做代码签名并打开加固,"
                    "可关掉这条路径。抢在真界面发出 Hello 前注入它这条路,由内核驱动按映像身份剥权挡住,"
                    "待机时驱动不在,这条路仍开着。").arg(uiPath));
            }
        }
    }

    bool ipcBoundaryChecked = false;
    bool ipcBoundaryIntact = false;
    QString ipcBoundaryNote;
    if (options.InstallDirAclSelfCheckEnabled) {
        const InstallDirAclCheck::Report rep =
            InstallDirAclCheck::check(QCoreApplication::applicationDirPath());
        ipcBoundaryChecked = true;
        if (rep.anyWritable) {
            ipcBoundaryIntact = false;
            ipcBoundaryNote = QStringLiteral(
                "IPC 认证强制层当前不构成安全边界:安装目录 / 服务 exe 对非管理员可写(%1)。"
                "任何本地普通用户都可往该目录放一个同名 bulwark_ui.exe 通过认证,进而下发关闭防护、"
                "加白任意路径等指令。请把安装目录收回到仅 SYSTEM / Administrators 可写。")
                                .arg(rep.detail());
            log.critical(QStringLiteral("控制管道认证:%1").arg(ipcBoundaryNote));
        } else if (!rep.checked) {
            ipcBoundaryIntact = false;
            ipcBoundaryNote = QStringLiteral(
                "无法核对安装目录的写保护(%1),不能确认 IPC 认证强制层的前提成立。")
                                .arg(rep.detail());
            log.warning(QStringLiteral("控制管道认证:%1").arg(ipcBoundaryNote));
        } else if (rep.anyUnreadable) {
            ipcBoundaryIntact = false;
            ipcBoundaryNote = QStringLiteral(
                "安装目录写保护只核对了一部分(%1),不能确认 IPC 认证强制层的前提完全成立。")
                                .arg(rep.detail());
            log.warning(QStringLiteral("控制管道认证:%1").arg(ipcBoundaryNote));
        } else {
            ipcBoundaryIntact = true;
            log.info(QStringLiteral("控制管道认证:已核对 %1 个对象(安装目录与服务 / 界面 exe),"
                                    "均对非管理员不可写,强制认证层的前提成立。")
                         .arg(rep.targets.size()));
        }
    }

    EventSourceCoordinator* coordinatorPtr = nullptr;
    Worker* workerPtr = nullptr;

    auto uiPids = std::make_shared<QSet<int>>();

    struct UiWatch { void* handle = nullptr; QString imagePath; };
    auto uiWatch = std::make_shared<QHash<int, UiWatch>>();

    ipc.uiProcessConnected = [&coordinatorPtr, uiPids, uiWatch, &log](int pid) {
        if (pid > 0)
            uiPids->insert(pid);
        if (coordinatorPtr) {
            coordinatorPtr->addProtectedUiPid(pid);
            log.info(QStringLiteral("UI 已连接(PID %1),已登记内核自我保护名单。").arg(pid));
        }
#ifdef Q_OS_WIN
        if (pid > 0 && !uiWatch->contains(pid)) {
            const HANDLE h = ::OpenProcess(SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION,
                                           FALSE, static_cast<DWORD>(pid));
            if (h != nullptr) {
                UiWatch w;
                w.handle = h;
                wchar_t buf[1024] = {};
                DWORD n = 1024;
                if (::QueryFullProcessImageNameW(h, 0, buf, &n) && n > 0)
                    w.imagePath = QString::fromWCharArray(buf, static_cast<int>(n));
                uiWatch->insert(pid, w);
            }
        }
#endif
    };

#ifdef Q_OS_WIN
    {
        auto* uiTimer = new QTimer(&ipc);
        uiTimer->setInterval(5000);
        QObject::connect(uiTimer, &QTimer::timeout, &ipc,
                         [uiWatch, uiPids, coordinatorPtr, &audit, &log] {
            for (auto it = uiWatch->begin(); it != uiWatch->end();) {
                const HANDLE h = static_cast<HANDLE>(it.value().handle);
                if (h == nullptr) { it = uiWatch->erase(it); continue; }
                if (::WaitForSingleObject(h, 0) != WAIT_OBJECT_0) { ++it; continue; }

                DWORD code = 0;
                const bool gotCode = ::GetExitCodeProcess(h, &code) != 0;
                const int pid = it.key();
                const QString image = it.value().imagePath;
                ::CloseHandle(h);
                it = uiWatch->erase(it);
                uiPids->remove(pid);
                if (coordinatorPtr)
                    coordinatorPtr->removeProtectedUiPid(pid);

                if (gotCode && code == 0) {
                    log.info(QStringLiteral("界面看护:界面进程(PID %1)已正常退出(退出码 0)——"
                                            "这是用户自己退出 / 界面自愈重启前的那次退出,不重新拉起。")
                                 .arg(pid));
                    continue;
                }

                const QString detail =
                    QStringLiteral("界面进程 PID=%1 以退出码 %2 结束(非正常退出,典型为被 "
                                   "TerminateProcess 结束)。内核自我保护本应剥离外部进程对界面的 "
                                   "PROCESS_TERMINATE —— 能成功通常意味着【当时驱动未加载】。")
                        .arg(pid).arg(gotCode ? QString::number(code) : QStringLiteral("未知"));
                log.critical(QStringLiteral("界面看护:%1").arg(detail));

                QJsonObject o;
                o["timestampUtc"] = QDateTime::currentDateTimeUtc().toString(Qt::ISODateWithMs);
                o["type"] = QStringLiteral("UiProcessKilled");
                o["detail"] = detail;
                audit.writeRecord(o);

                log.warning(QStringLiteral("界面看护:未从 LocalSystem 服务重新拉起 UI，避免创建 "
                                           "Session 0/SYSTEM 幽灵界面。请由交互用户重新打开:%1")
                                .arg(image.isEmpty() ? QStringLiteral("(映像路径未知)") : image));
            }
        });
        uiTimer->start();
    }
#endif

    ipc.rulesRequested = [&engine] { return engine.getRules(); };
    ipc.ruleDeleteRequested = [&engine, &ruleStore](const QUuid& id) {
        if (engine.removeRule(id)) ruleStore.save(engine.getRules());
    };
    ipc.ruleAddRequested = [&engine, &ruleStore, &log](const bulwark::ipc::AddRulePayload& p) {
        const bulwark::DefenseRule rule = p.toRule();
        // 与 AddTrust 同理:界面上的提示可被任意控制管道客户端绕过,放行范围只能在这里把关。
        if (const auto rej = bulwark::engine::TrustPolicy::rejectsAllowRule(rule); rej.ok) {
            log.warning(QStringLiteral("已拒绝新增放行规则 %1:%2")
                            .arg(rule.actorPath.isEmpty() ? rule.actorPattern : rule.actorPath,
                                 rej.reason));
            return;
        }
        engine.addRule(rule);
        ruleStore.save(engine.getRules());
        log.info(QStringLiteral("已新增规则:%1 => %2")
                     .arg(rule.actorPath.isEmpty() ? rule.actorPattern : rule.actorPath,
                          bulwark::verdictActionToString(rule.action)));
    };

    ipc.settingsRequested = [&settings, &engine, &coordinatorPtr] {
        bulwark::RuntimeSettings snap = settings.clone();
        snap.trustSignedActors = engine.trustSignedActors;
        if (coordinatorPtr && coordinatorPtr->isSuspended()) {
            snap.kernelConnected = false;
            snap.kernelStatus = coordinatorPtr->protectionSummary();
            return snap;
        }

        if (coordinatorPtr && coordinatorPtr->kernelConnected()) {
            snap.kernelConnected = true;
            const QStringList missing = coordinatorPtr->kernelMissingCapabilities();
            if (missing.isEmpty()) {
                snap.kernelStatus =
                    QStringLiteral("内核驱动已连接 · 行为前拦截(进程/文件/注册表/自保/网络)");
            } else {
                snap.kernelStatus =
                    QStringLiteral("内核驱动已连接,但驱动版本偏旧 · 以下 %1 个维度未生效:%2 —— "
                                   "请用与本服务同源编译的 Bulwark.sys 替换后重新加载")
                        .arg(missing.size())
                        .arg(missing.join(QStringLiteral("、")));
            }
            const QString ipcNote = coordinatorPtr->ipcAuthBoundaryNote();
            if (!ipcNote.isEmpty())
                snap.kernelStatus += QStringLiteral(" · ⚠ ") + ipcNote;
            const QString outNote = coordinatorPtr->kernelOutboundEnforcementNote();
            if (!outNote.isEmpty())
                snap.kernelStatus += QStringLiteral(" · ⚠ ") + outNote;
        } else {
            snap.kernelConnected = false;
            const QString why = (coordinatorPtr && coordinatorPtr->kernelProtocolMismatch())
                ? QStringLiteral("内核驱动协议不一致(请用同源编译的 Bulwark.sys)")
                : ((coordinatorPtr && coordinatorPtr->kernelAttachFailed())
                       ? QStringLiteral("内核驱动不可用(后台重试中)")
                       : QStringLiteral("内核驱动未启用"));
            snap.kernelStatus = coordinatorPtr
                ? (why + QStringLiteral(" · ") + coordinatorPtr->protectionSummary())
                : why;
        }
        return snap;
    };
    std::function<void()> protectionLifetimeHook;
    ipc.settingsUpdated = [&settings, &engine, &settingsStore,
                           &coordinatorPtr, &workerPtr, &log, &options,
                           &protectionLifetimeHook](
                              const bulwark::RuntimeSettings& s) {
        bulwark::RuntimeSettings updated = s;
        updated.eventSource = settings.eventSource;
        updated.kernelDriverEnabledAuthoritative = settings.kernelDriverEnabledAuthoritative;
        settings = updated;
        if (workerPtr)
            workerPtr->publishProtectionEnabled(settings.protectionEnabled);
        engine.trustSignedActors = settings.trustSignedActors;
        engine.enableBaseline = settings.behaviorBaselineEnabled;
        settingsStore.save(settings);
        if (coordinatorPtr) {
            coordinatorPtr->setKernelEnabled(settings.kernelDriverEnabled);
            coordinatorPtr->configureBehaviorMonitor(settings.userModeBehaviorMonitor,
                                                     settings.ransomwareCanaryEnabled);
            coordinatorPtr->setMemoryProtectionEnabled(settings.memoryProtectionEnabled);
            coordinatorPtr->applyRansomGuard(
                settings.ransomGuardEnabled,
                composeRansomGuardDirs(options, settings.ransomGuardEnabled
                                                    ? settings.ransomGuardDirs
                                                    : QStringList{}),
                composeRansomGuardWriters(options, engine.getRules()));
            coordinatorPtr->applyReadGuard(options.SensitiveDataGuardEnabled,
                                           composeReadGuardEntries(options),
                                           composeReadGuardReaders(options, engine.getRules()));
        }
        log.info(QStringLiteral("设置已更新:总开关=%1 默认动作=%2 防护生命周期=%3")
                     .arg(settings.protectionEnabled ? QStringLiteral("开") : QStringLiteral("关"),
                          settings.defaultBlock ? QStringLiteral("Block") : QStringLiteral("Allow"),
                          settings.protectionFollowsUi ? QStringLiteral("随界面(退出即停止)")
                                                       : QStringLiteral("常驻")));
        if (protectionLifetimeHook)
            protectionLifetimeHook();
    };

    ipc.trustListRequested = [&engine] {
        QList<bulwark::DefenseRule> out;
        for (const auto& r : engine.getRules())
            if (r.isTrustEntry()) out.append(r);
        return out;
    };
    std::function<void()> trustAddedHook;
    std::function<void()> ransomGuardRefreshHook;
    ipc.trustAddRequested = [&engine, &ruleStore, &log, &trustAddedHook](const bulwark::ipc::AddTrustPayload& p) {
        const QString path = p.actorPath.trimmed();
        if (path.isEmpty()) return;
        // 服务端是信任写入的唯一闸门:UI 确认框可被任意 IPC 客户端绕过,必须在这里拒绝。
        if (const auto rej = bulwark::engine::TrustPolicy::rejectsWholeProcessTrust(path, p.isDirectory);
            rej.ok) {
            log.warning(QStringLiteral("已拒绝信任请求 %1:%2").arg(path, rej.reason));
            return;
        }
        const auto reconcile = [&trustAddedHook] { if (trustAddedHook) trustAddedHook(); };
        if (p.isDirectory) {
            bulwark::DefenseRule rule = bulwark::DefenseRule::createTrustDirectory(path, p.note);
            rule.sessionOnly = p.sessionOnly;
            rule.expiresUtc = p.expiresUtc;
            for (const auto& r : engine.getRules())
                if (r.isTrustEntry() && !r.actorPattern.isEmpty()
                    && r.actorPattern.compare(rule.actorPattern, Qt::CaseInsensitive) == 0) {
                    reconcile();
                    return;
                }
            engine.addRule(rule);
            ruleStore.save(engine.getRules());
            log.info(QStringLiteral("已加入文件夹信任:%1%2")
                         .arg(path, p.sessionOnly ? QStringLiteral("(仅会话)")
                                 : p.expiresUtc ? QStringLiteral("(有到期)")
                                                : QString()));
            reconcile();
        } else {
            for (const auto& r : engine.getRules())
                if (r.isTrustEntry() && r.actorPath.compare(path, Qt::CaseInsensitive) == 0) {
                    reconcile();
                    return;
                }
            bulwark::DefenseRule rule = bulwark::DefenseRule::createTrust(path, p.note);
            rule.sessionOnly = p.sessionOnly;
            rule.expiresUtc = p.expiresUtc;
            engine.addRule(rule);
            ruleStore.save(engine.getRules());
            log.info(QStringLiteral("已加入文件信任:%1%2")
                         .arg(path, p.sessionOnly ? QStringLiteral("(仅会话)")
                                 : p.expiresUtc ? QStringLiteral("(有到期)")
                                                : QString()));
            reconcile();
        }
    };
    ipc.trustRemoveRequested = [&engine, &ruleStore, &ransomGuardRefreshHook](const QUuid& id) {
        if (engine.removeRule(id)) {
            ruleStore.save(engine.getRules());
            if (ransomGuardRefreshHook)
                ransomGuardRefreshHook();
        }
    };

    ipc.quarantineListRequested = [&quarantine] {
        bulwark::ipc::QuarantineListResponsePayload payload;
        for (const auto& x : quarantine.list()) {
            bulwark::ipc::QuarantineItemPayload item;
            item.id = x.id; item.originalPath = x.originalPath; item.fileName = x.fileName;
            item.quarantinedUtc = x.quarantinedUtc; item.size = x.size; item.sha256 = x.sha256;
            item.reason = x.reason; item.actorPid = x.actorPid;
            item.originalRemoved = x.originalRemoved;
            item.deleteOnRebootScheduled = x.deleteOnRebootScheduled;
            payload.items.append(item);
        }
        return payload;
    };
    ipc.quarantineRestoreRequested = [&quarantine, &log](const QUuid& id) {
        const bool ok = quarantine.restore(id);
        if (ok) log.warning(QStringLiteral("用户从隔离区还原了条目 %1。").arg(id.toString(QUuid::WithoutBraces)));
        return bulwark::ipc::QuarantineActionResultPayload{
            id, ok, ok ? QStringLiteral("已还原到原始位置")
                       : QStringLiteral("还原失败(条目不存在或文件被占用)")};
    };
    ipc.quarantineDeleteRequested = [&quarantine, &log](const QUuid& id) {
        const bool ok = quarantine.purge(id);
        if (ok) log.info(QStringLiteral("用户永久删除了隔离条目 %1。").arg(id.toString(QUuid::WithoutBraces)));
        return bulwark::ipc::QuarantineActionResultPayload{
            id, ok, ok ? QStringLiteral("已永久删除") : QStringLiteral("删除失败(条目不存在)")};
    };

    // 持久化审计:UI 打开「自启动项」视图时只读枚举 7 类自启动持久化点,逐项启发式打分 +
    // ATT&CK 标注返回。纯只读——绝不修改任何自启动项(清理走既有规则/隔离流程)。
    struct PersistenceSnapshotState {
        QHash<QString, bulwark::PersistenceEntry> byId;
        QDateTime scannedUtc;
    };
    auto persistenceSnapshot = std::make_shared<PersistenceSnapshotState>();
    ipc.persistenceListRequested = [persistenceSnapshot] {
        auto payload = PersistenceScanner::scan();
        persistenceSnapshot->byId.clear();
        for (const auto& entry : payload.entries)
            if (!entry.id.trimmed().isEmpty())
                persistenceSnapshot->byId.insert(entry.id, entry);
        persistenceSnapshot->scannedUtc = payload.scannedUtc;
        return payload;
    };

    ipc.eventHistoryRequested = [&eventHistory] {
        bulwark::ipc::EventHistoryResponsePayload payload;
        payload.events = eventHistory.getRecent();
        return payload;
    };
    ipc.eventHistoryClearRequested = [&eventHistory] { eventHistory.clear(); };


    auto forensicsInflight = std::make_shared<std::atomic<int>>(0);

    ipc.timelineRequested = [&ipc, &eventHistory, forensicsInflight](
                                const bulwark::ipc::TimelineRequestPayload& req) {
        forensicsInflight->fetch_add(1);
        std::thread([&ipc, &eventHistory, req, forensicsInflight] {
            struct Guard {
                std::shared_ptr<std::atomic<int>> c;
                ~Guard() { c->fetch_sub(1); }
            } guard{ forensicsInflight };
            bulwark::ipc::TimelineResponsePayload res;
            try {
                res = ForensicsService::queryTimeline(eventHistory, req);
            } catch (...) {
                res.requestId = req.requestId;
                res.message = QStringLiteral("时间线查询失败(历史文件可能损坏)");
            }
            res.requestId = req.requestId;
            QMetaObject::invokeMethod(&ipc, [&ipc, res] { ipc.sendTimeline(res); },
                                      Qt::QueuedConnection);
        }).detach();
    };

    ipc.attackGraphRequested = [&ipc, &eventHistory, forensicsInflight](
                                   const bulwark::ipc::AttackGraphRequestPayload& req) {
        forensicsInflight->fetch_add(1);
        std::thread([&ipc, &eventHistory, req, forensicsInflight] {
            struct Guard {
                std::shared_ptr<std::atomic<int>> c;
                ~Guard() { c->fetch_sub(1); }
            } guard{ forensicsInflight };
            bulwark::ipc::AttackGraphResponsePayload res;
            try {
                res = ForensicsService::buildAttackGraph(eventHistory, req);
            } catch (...) {
                res.success = false;
                res.message = QStringLiteral("攻击图构建失败(历史文件可能损坏)");
            }
            res.requestId = req.requestId;
            QMetaObject::invokeMethod(&ipc, [&ipc, res] { ipc.sendAttackGraph(res); },
                                      Qt::QueuedConnection);
        }).detach();
    };

    const int ownPid = static_cast<int>(QCoreApplication::applicationPid());
    const QString appDir = QDir::toNativeSeparators(QCoreApplication::applicationDirPath()).toLower();
    auto isSelfComponent = [ownPid, uiPids, appDir](int pid, const QString& imagePath) {
        if (pid == ownPid || uiPids->contains(pid))
            return true;
        if (appDir.isEmpty() || imagePath.isEmpty())
            return false;
        const QString lower = QDir::toNativeSeparators(imagePath).toLower();
        const QString name = QFileInfo(lower).fileName();
        return lower.startsWith(appDir)
            && (name == QStringLiteral("bulwark_service.exe") || name == QStringLiteral("bulwark_ui.exe"));
    };

    // 进程快照:枚举 + 验签 + 溯源在后台线程(首次要对几百个映像验签,可能数秒),回到主线程
    // 才补「是否已加白 / 是否自身组件」—— 加白判定要碰引擎规则集,那必须在主线程做。
    ipc.processListRequested = [&ipc, &engine, forensicsInflight, isSelfComponent](
                                   const bulwark::ipc::ProcessListRequestPayload& req) {
        forensicsInflight->fetch_add(1);
        std::thread([&ipc, &engine, req, forensicsInflight, isSelfComponent] {
            struct Guard {
                std::shared_ptr<std::atomic<int>> c;
                ~Guard() { c->fetch_sub(1); }
            } guard{ forensicsInflight };
            bulwark::ipc::ProcessListResponsePayload res;
            res.requestId = req.requestId;
            try {
                monitoring::ProcessEnumerator::Options opt;
                opt.includeCommandLine = req.includeCommandLine;
                opt.resolveOrigin = req.resolveOrigin;
                res.processes = monitoring::ProcessEnumerator::snapshot(opt);
                res.message = QStringLiteral("共 %1 个进程").arg(res.processes.size());
            } catch (...) {
                res.message = QStringLiteral("进程枚举失败");
            }
            res.snapshotUtc = QDateTime::currentDateTimeUtc();
            QMetaObject::invokeMethod(&ipc, [&ipc, &engine, res, isSelfComponent]() mutable {
                for (bulwark::ProcessEntry& p : res.processes) {
                    p.isProtectedSelf = isSelfComponent(p.pid, p.imagePath);
                    if (!p.imagePath.isEmpty() && engine.trustNoteForPath(p.imagePath).has_value()) {
                        p.isTrusted = true;
                        p.riskScore = 0;
                        p.riskReasons = QStringList{ QStringLiteral("已在用户信任名单(该程序不再被检测)") };
                    }
                }
                ipc.sendProcessList(res);
            }, Qt::QueuedConnection);
        }).detach();
    };

    // 进程处置:全部由用户在 UI 显式点击触发。三道护栏,任一命中即如实拒绝(绝不静默成功):
    //   ① PID <= 4(Idle/System);② 本软件自身组件(自我保护);③ 关键系统进程(结束会 0xEF 蓝屏)。
    ipc.processActionRequested =
        [&engine, &ruleStore, &quarantine, &log, &trustAddedHook,
         isSelfComponent](
            const bulwark::ipc::ProcessActionRequestPayload& req)
        -> bulwark::ipc::ProcessActionResultPayload {
        using Kind = bulwark::ipc::ProcessActionKind;
        bulwark::ipc::ProcessActionResultPayload res;
        res.requestId = req.requestId;
        res.kind = req.kind;
        res.pid = req.pid;

        QString imagePath;
        bool imagePathFromServer = false;
        std::optional<monitoring::ProcessInspector::ProcessInstance> currentInstance;
        if (req.pid > 4)
            currentInstance = monitoring::ProcessInspector::tryGetProcessInstance(req.pid);
        if (!currentInstance.has_value() || !currentInstance->isUsable()
            || req.creationFileTime == 0
            || currentInstance->creationFileTime != req.creationFileTime
            || (!req.imagePath.trimmed().isEmpty()
                && currentInstance->imagePath.compare(req.imagePath.trimmed(), Qt::CaseInsensitive) != 0)) {
            res.message = QStringLiteral("进程实例已退出、PID 已复用或请求身份不完整,已拒绝处置");
            return res;
        }
        imagePath = currentInstance->imagePath;
        imagePathFromServer = true;

        if (req.kind == Kind::ComputeHash) {
            if (imagePath.isEmpty() || !QFileInfo::exists(imagePath)) {
                res.message = QStringLiteral("无法读取映像文件(路径未知或已不存在)");
                return res;
            }
            res.sha256 = monitoring::ProcessInspector::tryComputeSha256(imagePath);
            res.success = !res.sha256.isEmpty();
            res.message = res.success ? QStringLiteral("已计算 SHA-256")
                                      : QStringLiteral("计算失败(文件过大或被独占锁定)");
            return res;
        }

        if (req.kind == Kind::TrustImage) {
            if (req.pid <= 4 || !imagePathFromServer || imagePath.isEmpty()) {
                res.message = QStringLiteral("无法从当前进程实例解析映像路径,已拒绝加入信任名单");
                return res;
            }
            if (const auto rej = bulwark::engine::TrustPolicy::rejectsWholeProcessTrust(
                    imagePath, false);
                rej.ok) {
                res.message = QStringLiteral("该程序不能整体加入信任名单:%1").arg(rej.reason);
                log.warning(QStringLiteral("进程管理信任请求已拒绝(PID %1):%2 · %3")
                                .arg(req.pid).arg(imagePath, rej.reason));
                return res;
            }
            bool exists = false;
            for (const auto& r : engine.getRules())
                if (r.isTrustEntry() && r.actorPath.compare(imagePath, Qt::CaseInsensitive) == 0) {
                    exists = true;
                    break;
                }
            if (!exists) {
                engine.addRule(bulwark::DefenseRule::createTrust(
                    imagePath, QStringLiteral("从进程管理信任")));
                ruleStore.save(engine.getRules());
                log.info(QStringLiteral("已从进程管理加入文件信任:%1").arg(imagePath));
            }
            if (trustAddedHook) trustAddedHook();
            res.success = true;
            res.message = exists ? QStringLiteral("该程序已在信任名单中")
                                 : QStringLiteral("已加入信任名单(此后其全部行为直接放行)");
            return res;
        }

        if (req.pid <= 4) {
            res.message = QStringLiteral("PID 无效(系统空闲/内核进程不可处置)");
            return res;
        }
        if (isSelfComponent(req.pid, imagePath)) {
            res.message = QStringLiteral("自我保护:不允许从进程管理结束磐垒自身组件。"
                                         "如需停止防护,请在设置里关闭总开关,或走正常卸载流程。");
            log.warning(QStringLiteral("进程管理请求处置本软件组件(PID %1),已拒绝。").arg(req.pid));
            return res;
        }
        const bool critical = monitoring::ProcessInspector::isCriticalProcess(req.pid);
        if (critical && req.kind != Kind::Resume) {
            res.message = QStringLiteral("关键系统进程:结束或挂起会导致系统崩溃(0xEF),已拒绝。");
            return res;
        }

        switch (req.kind) {
        case Kind::Terminate:
            res.success = monitoring::ProcessInspector::tryTerminateProcess(req.pid);
            res.message = res.success
                ? QStringLiteral("已结束进程")
                : QStringLiteral("结束失败(进程已退出 / 受保护 / 权限不足)");
            break;
        case Kind::TerminateTree: {
            const int killed = monitoring::ProcessInspector::terminateProcessTree(req.pid);
            res.success = killed > 0;
            res.message = res.success ? QStringLiteral("已结束进程树,共 %1 个进程").arg(killed)
                                      : QStringLiteral("结束失败(进程已退出 / 受保护 / 权限不足)");
            break;
        }
        case Kind::Suspend:
            res.success = monitoring::ProcessInspector::trySuspend(req.pid);
            res.message = res.success ? QStringLiteral("已挂起(全部线程冻结)")
                                      : QStringLiteral("挂起失败(权限不足或进程已退出)");
            break;
        case Kind::Resume:
            res.success = monitoring::ProcessInspector::tryResume(req.pid);
            res.message = res.success ? QStringLiteral("已恢复运行")
                                      : QStringLiteral("恢复失败(权限不足或进程已退出)");
            break;
        case Kind::QuarantineImage: {
            if (!imagePathFromServer || !QFileInfo::exists(imagePath)) {
                res.message = QStringLiteral("无法定位映像文件,已放弃隔离(未做任何处置)");
                break;
            }
            const int killed = monitoring::ProcessInspector::terminateProcessTree(req.pid);
            const QString hash = QuarantineManager::tryComputeSha256(imagePath);
            const auto entry = quarantine.quarantine(
                imagePath, QStringLiteral("用户从进程管理手动隔离"), req.pid, hash);
            res.success = entry.has_value() && entry->originalRemoved;
            if (res.success) {
                log.warning(QStringLiteral("用户从进程管理隔离了映像:%1(同时结束 %2 个进程)")
                                .arg(imagePath).arg(killed));
                res.message = QStringLiteral("已结束 %1 个进程并把映像移入隔离区(可还原)").arg(killed);
            } else if (entry.has_value()) {
                res.message = entry->deleteOnRebootScheduled
                    ? QStringLiteral("已结束 %1 个进程并保存可还原副本,但原文件仍在;已计划重启删除")
                          .arg(killed)
                    : QStringLiteral("已结束 %1 个进程并保存可还原副本,但原文件删除和重启调度均失败")
                          .arg(killed);
                log.warning(QStringLiteral("进程管理隔离仅部分完成:%1 · %2")
                                .arg(imagePath, res.message));
            } else {
                res.message = killed > 0
                    ? QStringLiteral("已结束 %1 个进程,但隔离失败(文件被占用或权限不足)").arg(killed)
                    : QStringLiteral("隔离失败(文件被占用或权限不足),进程也未能结束");
            }
            break;
        }
        default:
            res.message = QStringLiteral("不支持的动作");
            break;
        }
        return res;
    };

    ipc.systemBoostRequested = [&ipc, ownPid, uiPids, forensicsInflight](
                                   const bulwark::ipc::SystemBoostRequestPayload& req) {
        QSet<int> skip = *uiPids;
        skip.insert(ownPid);
        forensicsInflight->fetch_add(1);
        const QUuid rid = req.requestId;
        std::thread([&ipc, rid, skip, forensicsInflight] {
            struct Guard {
                std::shared_ptr<std::atomic<int>> c;
                ~Guard() { c->fetch_sub(1); }
            } guard{ forensicsInflight };
            bulwark::ipc::SystemBoostResultPayload res;
            res.requestId = rid;
            try {
                const SystemBoostReport r =
                    SystemBoost::run([&skip](int pid) { return skip.contains(pid); });
                res.success = true;
                res.processesTrimmed = r.processesTrimmed;
                res.processesTotal = r.processesTotal;
                res.freedBytes = r.freedBytes;
                res.inUseBefore = r.inUseBefore;
                res.inUseAfter = r.inUseAfter;
                res.totalPhysical = r.totalPhysical;
                res.loadBefore = r.loadBefore;
                res.loadAfter = r.loadAfter;
                res.message = r.freedBytes > 0
                    ? QStringLiteral("已加速:修剪 %1 个进程,回收物理内存约 %2 MB")
                          .arg(r.processesTrimmed).arg(r.freedBytes / (1024 * 1024))
                    : QStringLiteral("已加速:修剪 %1 个进程;内存已较干净,本次无可回收")
                          .arg(r.processesTrimmed);
            } catch (...) {
                res.success = false;
                res.message = QStringLiteral("一键加速失败");
            }
            QMetaObject::invokeMethod(&ipc, [&ipc, res] { ipc.sendSystemBoost(res); },
                                      Qt::QueuedConnection);
        }).detach();
    };

    NetTrafficMonitor netTraffic;
    netTraffic.setSelfComponentProbe(isSelfComponent);
    QObject::connect(&netTraffic, &NetTrafficMonitor::snapshotReady, &ipc,
                     [&ipc](const bulwark::ipc::NetTrafficSnapshotPayload& snapshot,
                            const NetTrafficMonitor::ConnMap& connections) {
                         ipc.sendNetTraffic(snapshot, connections);
                     });
    ipc.netTrafficSubscriptionChanged = [&netTraffic, &log](bool anySubscriber) {
        if (anySubscriber) {
            log.info(QStringLiteral("实时流量悬浮窗已订阅,启动流量采样。"));
            netTraffic.start();
        } else {
            log.info(QStringLiteral("实时流量悬浮窗已全部退订(或界面断开),停止流量采样。"));
            netTraffic.stop();
        }
    };

    std::function<std::pair<bool, QString>(const bulwark::ipc::ManualQuarantinePayload&)> forceQuarantineHook;
    ipc.manualQuarantineRequested =
        [&forceQuarantineHook](const bulwark::ipc::ManualQuarantinePayload& req) -> std::pair<bool, QString> {
        if (!forceQuarantineHook) return { false, QStringLiteral("服务尚未就绪,请稍后重试") };
        return forceQuarantineHook(req);
    };

    // 情报采纳只认本服务最近一次预览生成的规则,并以服务端保存的那份为准。
    struct IntelPreviewState {
        QHash<QUuid, bulwark::DefenseRule> rules;
        QDateTime generatedUtc;
    };
    constexpr qint64 kIntelPreviewTtlSecs = 30 * 60;
    auto intelPreview = std::make_shared<IntelPreviewState>();

    ipc.intelRefreshRequested = [&intelClient, applyIntelRules, &options, &log, intelPreview](
        const bulwark::ipc::IntelRefreshRequestPayload& req) -> bulwark::ipc::IntelRefreshResultPayload {
        bulwark::ipc::IntelRefreshResultPayload res;
        res.requestId = req.requestId;
        if (!intelClient.isEnabled()) {
            res.success = false;
            res.message = QStringLiteral("ThreatFox 未启用或未配置 Auth-Key");
            return res;
        }
        const QVector<reputation::ThreatFoxIoc> iocs = intelClient.fetchRecent();
        res.iocCount = static_cast<int>(iocs.size());
        const QVector<bulwark::DefenseRule> gen = reputation::generateIntelRules(iocs, options.ThreatFoxFeed);
        res.generatedRules = gen;
        if (req.previewOnly) {
            intelPreview->rules.clear();
            for (const bulwark::DefenseRule& r : gen)
                intelPreview->rules.insert(r.id, r);
            intelPreview->generatedUtc = QDateTime::currentDateTimeUtc();
            res.success = !gen.isEmpty();
            res.message = QStringLiteral("预览:拉取 %1 条 IOC,生成 %2 条规则(未落地)")
                              .arg(iocs.size()).arg(gen.size());
            return res;
        }
        const int removed = applyIntelRules(gen);
        res.rulesApplied = static_cast<int>(gen.size());
        res.success = true;
        res.message = QStringLiteral("已刷新:清理旧 %1 条,注入 %2 条").arg(removed).arg(gen.size());
        log.info(res.message);
        return res;
    };

    ipc.intelApplyRequested = [applyIntelRules, &log, intelPreview](
        const bulwark::ipc::IntelApplyRequestPayload& req) -> bulwark::ipc::IntelRefreshResultPayload {
        bulwark::ipc::IntelRefreshResultPayload res;
        res.requestId = req.requestId;
        const bool fresh = intelPreview->generatedUtc.isValid()
            && intelPreview->generatedUtc.secsTo(QDateTime::currentDateTimeUtc()) <= kIntelPreviewTtlSecs;
        if (!fresh) {
            res.success = false;
            res.message = QStringLiteral("没有 %1 分钟内的情报预览可采纳,请先刷新情报")
                              .arg(kIntelPreviewTtlSecs / 60);
            return res;
        }
        // 客户端回传的规则只用来挑选(按 id),内容一概不信:否则任何控制管道客户端都能借这里
        // 写入带信任标记或硬覆盖的规则,绕过 AddTrust 的服务端闸门。
        QVector<bulwark::DefenseRule> accepted;
        QSet<QUuid> seen;
        int unbound = 0;
        for (const bulwark::DefenseRule& r : req.rules) {
            const auto it = intelPreview->rules.constFind(r.id);
            if (it == intelPreview->rules.constEnd()) {
                ++unbound;
                continue;
            }
            if (!seen.contains(r.id)) {
                seen.insert(r.id);
                accepted.append(it.value());
            }
        }
        if (unbound > 0)
            log.warning(QStringLiteral("情报采纳:%1 条规则不属于最近一次服务端预览,已忽略。").arg(unbound));
        if (accepted.isEmpty()) {
            res.success = false;
            res.message = QStringLiteral("所选规则都不在最近一次情报预览里,请重新刷新情报后再采纳");
            return res;
        }
        const int removed = applyIntelRules(accepted);
        res.rulesApplied = static_cast<int>(accepted.size());
        res.success = true;
        res.message = QStringLiteral("已采纳:清理旧 %1 条,注入 %2 条").arg(removed).arg(accepted.size());
        log.info(res.message);
        return res;
    };

    const QString yaracPath =
        QDir(QCoreApplication::applicationDirPath()).filePath(QStringLiteral("bulwark_yarac.exe"));
    YaraRuleUpdater yaraRules(options.YaraRules, programDataDir() + QStringLiteral("/yara"), yaracPath);
    YaraScanner yaraScanner(options.YaraRules, yaracPath);
    {
        // 优先用联网更新编出的规则;还没有时退回安装包内置的那份(打包时预编译)。
        const QString bundled =
            QDir(QCoreApplication::applicationDirPath()).filePath(QStringLiteral("rules/yara-forge-core.yarc"));
        const bulwark::ipc::YaraRulesStatusPayload st = yaraRules.status();
        if (!st.rulesPath.isEmpty() && QFileInfo::exists(st.rulesPath)) {
            yaraScanner.setRules(st.rulesPath, QStringLiteral("YARA Forge %1").arg(st.releaseTag));
        } else if (QFileInfo::exists(bundled)) {
            QFile report(QFileInfo(bundled).dir().filePath(QStringLiteral("yara-forge-core.json")));
            const QString created = report.open(QIODevice::ReadOnly)
                ? QJsonDocument::fromJson(report.readAll()).object().value(QStringLiteral("packageCreated"))
                      .toString().trimmed()
                : QString();
            yaraScanner.setRules(QDir::toNativeSeparators(bundled),
                                 created.isEmpty() ? QStringLiteral("安装包内置规则")
                                                   : QStringLiteral("安装包内置 · YARA Forge %1").arg(created));
        } else {
            yaraScanner.setRules(QString(), QString());
        }
    }
    yaraRules.setRulesInstalled(
        [&yaraScanner](const QString& path, const QString& label) { yaraScanner.setRules(path, label); });
    const auto withScanStatus = [&yaraScanner](bulwark::ipc::YaraRulesStatusPayload s) {
        s.scan = yaraScanner.status();
        s.usedForDetection = s.scan.enabled && !s.scan.rulesLabel.isEmpty();
        return s;
    };
    yaraRules.setStatusChanged([&ipc, withScanStatus](const bulwark::ipc::YaraRulesStatusPayload& s) {
        ipc.sendYaraStatus(withScanStatus(s));
    });
    yaraScanner.setChangedCallback([&ipc, &yaraRules, withScanStatus] {
        QMetaObject::invokeMethod(
            qApp, [&ipc, &yaraRules, withScanStatus] { ipc.sendYaraStatus(withScanStatus(yaraRules.status())); },
            Qt::QueuedConnection);
    });
    ipc.yaraStatusRequested = [&yaraRules, withScanStatus] { return withScanStatus(yaraRules.status()); };
    ipc.yaraActionRequested = [&yaraRules](const bulwark::ipc::YaraRulesActionRequestPayload& req) {
        return yaraRules.handleAction(req);
    };

    if (!ipc.start())
        log.warning(QStringLiteral("IPC 控制管道监听失败;UI 将无法连接。"));

    std::unique_ptr<EventSource> baseSource;
    EtwProcessEventSource* etwPtr = nullptr;
    {
        auto etwSource = std::make_unique<EtwProcessEventSource>(options.Etw);
        etwPtr = etwSource.get();
        const QStringList guardDirsForWatch =
            composeRansomGuardDirs(options, settings.ransomGuardEnabled ? settings.ransomGuardDirs
                                                                       : QStringList{});
        etwSource->setWatchLists(options.ProtectedRegistryKeys + options.RegistryHardBlocks,
                                 options.ProtectedPaths + options.FileHardBlocks +
                                     (settings.ransomGuardEnabled ? guardDirsForWatch
                                                                  : QStringList{}));
        etwSource->setDrainIntervalMs(options.EventDrainIntervalMs);
        baseSource = std::move(etwSource);
        log.info(QStringLiteral("基础事件源 = ETW(Kernel-Process + 可选 Kernel-Network/DNS-Client/Kernel-Registry,实时)。"));
    }

    auto behaviorSource = std::make_unique<UserModeBehaviorSource>(engine);
#ifdef BULWARK_ENABLE_SELFTEST
    const QString selfTestCanaryRunId = qEnvironmentVariable("BULWARK_SELFTEST_RUN_ID");
    if (!selfTestCanaryRunId.isEmpty())
        behaviorSource->setSelfTestCanaryRunId(selfTestCanaryRunId);
#endif
    if (etwPtr) {
        behaviorSource->setCanarySink(
            [etwPtr](const QString& canaryPath, const QString& correlationId) {
                etwPtr->addAttributionPath(canaryPath, correlationId);
            });
        behaviorSource->setAttributionProbe(
            [etwPtr](const QString& pathLower, qint64 windowMs) {
                return etwPtr->wasAttributedRecently(pathLower, windowMs);
            },
            [etwPtr]() { return etwPtr->writeAttributionEnabled(); });
        if (etwPtr->writeAttributionEnabled())
            log.info(QStringLiteral("勒索诱饵写入归因已配置(Etw.KernelFileWriteAttribution=true):"
                                   "诱饵被改写时可定位写入进程并结束其进程树;是否真正生效以随后"
                                   "『ETW 实时会话已启动』那一行里有无『FileWrite归因』为准。"));
        else
            log.info(QStringLiteral("勒索诱饵写入归因未配置(Etw.KernelFileWriteAttribution=false):"
                                   "诱饵被改写只能告警,无法定位写入进程、因而结束不了它 —— "
                                   "开启需额外订阅 Kernel-File 的 CREATE+WRITE(实测回调频率由约 "
                                   "12/s 升至约 3000/s)。"));
    }

    auto coordinator = std::make_unique<EventSourceCoordinator>(baseSource.get(), behaviorSource.get(), options);
    coordinatorPtr = coordinator.get();

    auto bootGuard = std::make_unique<BootSectorGuard>();
    auto fileless = std::make_unique<FilelessGuard>();
    auto resourceGuard = std::make_unique<ResourceAbuseMonitor>();

    fileless->addSelfPid(static_cast<int>(::GetCurrentProcessId()));
    coordinator->addAuxSource(bootGuard.get());
    coordinator->addAuxSource(fileless.get());

    QObject::connect(coordinator.get(), &EventSource::eventProduced,
                     fileless.get(), &FilelessGuard::onObservedEvent);
    QObject::connect(coordinator.get(), &EventSource::eventProduced,
                     resourceGuard.get(), &ResourceAbuseMonitor::onObservedEvent);

    resourceGuard->setAuditSink([&audit](const QString& kind, const QString& detail) {
        QJsonObject o;
        o["timestampUtc"] = QDateTime::currentDateTimeUtc().toString(Qt::ISODateWithMs);
        o["type"] = kind;
        o["detail"] = detail;
        audit.writeRecord(o);
    });
    resourceGuard->setContainHandler([coordinatorPtr, &log](int pid, const QString& why) -> bool {
        if (coordinatorPtr == nullptr)
            return false;
        const bool banned = coordinatorPtr->banProcess(pid);
        const bool killed = coordinatorPtr->killProcess(pid);
        log.warning(QStringLiteral("资源耗尽收容:PID=%1(%2)—— 内核封禁=%3,驱动级结束=%4。"
                                   "两者都是运行期手段,不写注册表、不留跨重启痕迹。")
                        .arg(pid).arg(why)
                        .arg(banned ? QStringLiteral("已受理") : QStringLiteral("不可用(无驱动)"))
                        .arg(killed ? QStringLiteral("已受理") : QStringLiteral("不可用(无驱动)")));
        return banned || killed;
    });

    resourceGuard->start();

    quarantine.setKernelAssist(
        [coordinatorPtr](const QString& p, QByteArray& out) {
            return coordinatorPtr ? coordinatorPtr->readLockedFile(p, out) : false;
        },
        [coordinatorPtr](const QString& p) {
            return coordinatorPtr ? coordinatorPtr->forceDeleteFile(p) : false;
        });

    quarantine.setSelfUnlock([coordinatorPtr](const QString& p) {
        return coordinatorPtr ? coordinatorPtr->suspendUserModeLock(p) : 0;
    });

    UserModeProcessContainment containment(options.UserModeContainmentMax,
                                          options.UserModeFreezeTtlMs);
    containment.setKernelKill([coordinatorPtr](int pid) {
        return coordinatorPtr ? coordinatorPtr->killProcess(pid) : false;
    });

    SystemHardening hardening;
    hardening.setTrustProbe([&engine](const QString& p) {
        return engine.trustNoteForPath(p).has_value();
    });

    quarantine.setExecDenyFallback(
        [&hardening, &options](const QString& p) -> std::pair<bool, QString> {
            if (!(options.FileDenyExecuteEnabled || options.FileDenyExecuteConfirmedEnabled)) {
                return { false,
                         QStringLiteral("FileDenyExecuteConfirmedEnabled=false 且 FileDenyExecuteEnabled=false"
                                        "(把前者置为 true 即可让删不掉的恶意文件在重启前也无法被执行;"
                                        "代价是文件上会留一条跨重启的拒绝执行 ACE,撤销入口是在界面加白"
                                        "或通知上的『撤销拦截』)") };
            }
            if (hardening.hasDenyExecute(p))
                return { true, QString() };
            if (hardening.denyExecute(p))
                return { true, QString() };
            return { false, QStringLiteral("施加拒绝执行 ACE 失败(该文件的 DACL 不可改写)") };
        });

    {
        const QVector<SystemHardening::Finding> findings = hardening.inspect();
        log.info(QStringLiteral("加固体检:%1 项").arg(findings.size()));
        for (const SystemHardening::Finding& f : findings) {
            log.info(QStringLiteral("  [%1] %2 —— %3")
                         .arg(f.satisfied ? QStringLiteral("已加固") : QStringLiteral("未加固"))
                         .arg(f.title)
                         .arg(f.current));
            if (!f.satisfied) {
                log.info(QStringLiteral("        建议:%1%2").arg(f.recommended)
                             .arg(f.needsReboot ? QStringLiteral("(需重启)") : QString()));
                log.info(QStringLiteral("        代价:%1").arg(f.cost));
            }
        }
        const auto satisfied = [&findings](const char* id) {
            for (const SystemHardening::Finding& f : findings) {
                if (f.id == QLatin1String(id))
                    return f.satisfied;
            }
            return true;   // 查不到就按「无需处理」,绝不在不确定时去改系统
        };
        if (options.ApplyLsaRunAsPpl) {
            if (satisfied("RunAsPPL")) {
                log.info(QStringLiteral("加固:ApplyLsaRunAsPpl=true,但 lsass 已处于 PPL 保护,跳过。"));
            } else {
                hardening.applyRunAsPpl(true);
            }
        }
        if (options.ApplySelfServiceDacl) {
            if (satisfied("SelfServiceDacl")) {
                log.info(QStringLiteral("加固:ApplySelfServiceDacl=true,但本服务 DACL 已足够紧"
                                        "(宽泛主体无停止/改配置/删除权限),跳过。"));
            } else {
                hardening.applySelfServiceDacl(true);
            }
        }
    }
    if (options.RegistryInstantRollbackEnabled) {
        hardening.setRollbackJudge(
            [&engine](const QString& valueName, const QString& data, QString* whyKeep) -> bool {
                RegistryRollbackPolicy::Deps d;
                d.expandEnv = [](const QString& s) {
                    wchar_t buf[4096] = {};
                    const DWORD n = ::ExpandEnvironmentStringsW(
                        reinterpret_cast<LPCWSTR>(s.utf16()), buf, 4096);
                    return (n == 0 || n > 4096) ? s : QString::fromWCharArray(buf);
                };
                d.exists = [](const QString& p) {
                    const QFileInfo fi(p);
                    return fi.exists() && fi.isFile();
                };
                d.isUserTrusted = [&engine](const QString& p) {
                    return engine.trustNoteForPath(p).has_value();
                };
                d.isSigned = [](const QString& p) { return monitoring::ProcessInspector::isSigned(p); };
                d.systemRoot = qEnvironmentVariable("SystemRoot", QStringLiteral("C:\\Windows"));
                QString why;
                const RegistryRollbackPolicy::Decision dec =
                    RegistryRollbackPolicy::judge(valueName, data, d, &why);
                if (dec == RegistryRollbackPolicy::Decision::Rollback)
                    return true;
                if (whyKeep) *whyKeep = why;
                return false;
            });
        for (const char* k : {
                 "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
                 "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
                 "HKLM\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run",
                 "HKLM\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
             }) {
            hardening.watchKey(QString::fromLatin1(k));
        }
        if (options.RegistryRollbackWinlogonEnabled) {
            hardening.watchKey(
                QStringLiteral("HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon"),
                { QStringLiteral("Shell"), QStringLiteral("Userinit") });
        } else {
            log.info(QStringLiteral("Winlogon Shell / Userinit 的即时回滚未启用"
                                    "(RegistryRollbackWinlogonEnabled=false)。"));
        }
        QObject::connect(
            &hardening, &SystemHardening::rolledBack, &hardening,
            [&audit, &ipc](const QString& keyPath, const QString& valueName, const QString& newData,
                           const QString& restoredTo) {
                QJsonObject o;
                o["timestampUtc"] = QDateTime::currentDateTimeUtc().toString(Qt::ISODateWithMs);
                o["type"] = QStringLiteral("RegistryRollback");
                o["keyPath"] = keyPath;
                o["valueName"] = valueName;
                o["newData"] = newData;
                o["restoredTo"] = restoredTo;
                const QString detail =
                    QStringLiteral("已撤回自启动项 %1\\%2:新值「%3」%4(未签名且未加白;"
                                   "若这是你自己装的程序,请在界面把它加白,下次不会再被撤回)")
                        .arg(keyPath, valueName, newData,
                             restoredTo.isEmpty() ? QStringLiteral("已删除")
                                                  : QStringLiteral("已还原为「%1」").arg(restoredTo));
                o["detail"] = detail;
                audit.writeRecord(o);
                ipc.sendLog(QStringLiteral("【注册表回滚】") + detail);
            });
        hardening.startWatching();
    } else {
        log.info(QStringLiteral("注册表即时监视 + 自动回滚未启用(RegistryInstantRollbackEnabled=false)"
                                "—— 自启动项的发现仍由用户态行为源的周期性比对负责,"
                                "那条路径存在「写进去、等我们下一轮才发现」的窗口。"));
    }
    HardeningCatalog hardeningCatalog(&hardening);
    HijackGuard hijackGuard;
    hijackGuard.setStatePath(programDataDir() + QStringLiteral("/hijack-state.json"));
    hijackGuard.setActiveProbe([&coordinatorPtr, &settings]() {
        if (coordinatorPtr && coordinatorPtr->isSuspended())
            return false;
        return settings.protectionEnabled && settings.registryProtection;
    });
    QObject::connect(&hijackGuard, &HijackGuard::alertRaised, &hijackGuard,
                     [&audit, &ipc, &log](const bulwark::ipc::HijackAlertPayload& a) {
                         QJsonObject o;
                         o["timestampUtc"] = QDateTime::currentDateTimeUtc().toString(Qt::ISODateWithMs);
                         o["type"] = QStringLiteral("HijackDetected");
                         o["surface"] = a.surface;
                         o["location"] = a.location;
                         o["oldValue"] = a.oldValue;
                         o["newValue"] = a.newValue;
                         o["detail"] = a.title + QStringLiteral(" —— ") + a.detail;
                         audit.writeRecord(o);
                         log.warning(QStringLiteral("劫持防护:%1(%2)。%3").arg(a.title, a.location, a.detail));
                         ipc.sendHijackAlert(a);
                         ipc.sendLog(QStringLiteral("【劫持防护】") + a.title);
                     });
    QObject::connect(&hijackGuard, &HijackGuard::alertResolved, &hijackGuard,
                     [&audit](const bulwark::ipc::HijackAlertPayload& a) {
                         QJsonObject o;
                         o["timestampUtc"] = QDateTime::currentDateTimeUtc().toString(Qt::ISODateWithMs);
                         o["type"] = QStringLiteral("HijackResolved");
                         o["surface"] = a.surface;
                         o["location"] = a.location;
                         o["state"] = a.state;
                         o["detail"] = a.title;
                         audit.writeRecord(o);
                     });
    if (options.HijackGuardEnabled) {
        if (hijackGuard.start())
            log.info(QStringLiteral("劫持防护已启动(系统代理 / PAC、浏览器企业策略、网卡 DNS、浏览器快捷方式;"
                                    "基线 %1)。").arg(programDataDir() + QStringLiteral("/hijack-state.json")));
        else
            log.warning(QStringLiteral("劫持防护没能启动(详见上面的日志)。"));
    } else {
        log.info(QStringLiteral("劫持防护未启用(HijackGuardEnabled=false)。"));
    }

    AmsiBridge amsiBridge;
    amsiBridge.setTrustProbe([&engine](const QString& hostImagePath) {
        return engine.trustNoteForPath(hostImagePath).has_value();
    });
    amsiBridge.setReporter([&workerPtr](const bulwark::SecurityEvent& e, bool) {
        if (workerPtr != nullptr)
            workerPtr->reportPreBlockedEvent(e);
    });
    if (options.AmsiProviderEnabled) {
        if (!amsiBridge.start()) {
            log.warning(QStringLiteral("脚本内容防护(AMSI)未能启动,该维度本次运行不可用。"));
        }
    } else {
        log.info(QStringLiteral("脚本内容防护(AMSI)未启用(AmsiProviderEnabled=false)。"));
    }

    ipc.hardeningStatusRequested = [&hardeningCatalog, &hijackGuard, &options]() {
        bulwark::ipc::HardeningStatusResponsePayload p;
        p.scannedUtc = QDateTime::currentDateTimeUtc();
        for (const auto& it : hardeningCatalog.inspect())
            p.items << it;
        for (const auto& it : hijackGuard.monitorItems())
            p.items << it;
        p.alerts = hijackGuard.alerts();
        p.actionsEnabled = options.HardeningUiActionsEnabled;
        p.hijackGuardActive = hijackGuard.isRunning() && hijackGuard.isActive();
        if (!options.HijackGuardEnabled)
            p.message = QStringLiteral("劫持防护未启用(部署配置 HijackGuardEnabled=false)。");
        else if (hijackGuard.isRunning() && !hijackGuard.isActive())
            p.message = QStringLiteral("劫持防护此刻暂停(实时防护或注册表防护已关闭 / 处于待机)。恢复后会补查期间的改动。");
        return p;
    };
    ipc.hardeningActionRequested = [&hardeningCatalog, &hijackGuard, &options, &audit, &log](
                                       const bulwark::ipc::HardeningActionRequestPayload& req) {
        bulwark::ipc::HardeningActionResultPayload res;
        const QString action = req.action.trimmed().toLower();
        const bool changesSystem = action != QLatin1String("accept");
        if (changesSystem && !options.HardeningUiActionsEnabled) {
            res.ok = false;
            res.message = QStringLiteral("部署配置不允许在界面上改系统状态(HardeningUiActionsEnabled=false)。");
            return res;
        }
        if (action == QLatin1String("apply") || action == QLatin1String("revert")) {
            if (!HardeningCatalog::isKnown(req.id)) {
                res.message = QStringLiteral("未知的加固项:%1").arg(req.id);
                return res;
            }
            const HardeningCatalog::Result r =
                action == QLatin1String("apply") ? hardeningCatalog.apply(req.id) : hardeningCatalog.revert(req.id);
            res.ok = r.ok;
            res.needsReboot = r.needsReboot;
            res.message = r.message;
        } else if (action == QLatin1String("restore") || action == QLatin1String("accept")) {
            const HijackGuard::ActionResult r =
                action == QLatin1String("restore") ? hijackGuard.restore(req.id) : hijackGuard.accept(req.id);
            res.ok = r.ok;
            res.message = r.message;
        } else {
            res.message = QStringLiteral("未知的动作:%1").arg(req.action);
            return res;
        }
        QJsonObject o;
        o["timestampUtc"] = QDateTime::currentDateTimeUtc().toString(Qt::ISODateWithMs);
        o["type"] = QStringLiteral("HardeningAction");
        o["action"] = action;
        o["id"] = req.id;
        o["ok"] = res.ok;
        o["detail"] = res.message;
        audit.writeRecord(o);
        log.info(QStringLiteral("系统加固页:%1 %2 -> %3:%4")
                     .arg(action, req.id, res.ok ? QStringLiteral("成功") : QStringLiteral("失败"), res.message));
        return res;
    };

    // 两条分支都要走到这里:能力表必须知道这两维的实况,哪怕结论是「都没生效」。
    if (coordinatorPtr)
        coordinatorPtr->setHardeningState(
            hardening.isWatching(),
            options.FileDenyExecuteEnabled || options.FileDenyExecuteConfirmedEnabled);
    if (coordinatorPtr)
        coordinatorPtr->setIpcAuthBoundary(ipcBoundaryChecked, ipcBoundaryIntact, ipcBoundaryNote);

    Worker worker(&engine, &ipc, coordinator.get(), &ruleStore, &audit, &firstSeen, &quarantine,
                  &settings);
    workerPtr = &worker;
    worker.publishProtectionEnabled(settings.protectionEnabled);
    worker.setEventHistory(&eventHistory);
    worker.setAlertExporter(&alertExporter);
    worker.setContainment(&containment);
    worker.setFreezeOnDetect(options.UserModeFreezeOnDetect);
    worker.setYaraScanner(&yaraScanner);

    if (coordinatorPtr) {
        QTimer::singleShot(60000, coordinatorPtr, [coordinatorPtr, &log]() {
            const QString note = coordinatorPtr->kernelOutboundEnforcementNote();
            if (note.isEmpty()) {
                log.info(QStringLiteral("出站拦截实测核对:内核 WFP classify 在跑,且多数连接的裁决"
                                        "可由本驱动改写 —— 「出站连接阻断」这一维有实测依据。"));
            } else {
                log.error(note);
            }
        });
    }
    worker.setHardening(&hardening, options.FileDenyExecuteEnabled,
                        options.RegistryInstantRollbackEnabled,
                        options.RegistryDenyWriteEnabled);
    ransomGuardRefreshHook = [&coordinator, &engine, &options, &settings] {
        coordinator->applyRansomGuard(
            settings.ransomGuardEnabled,
            composeRansomGuardDirs(options, settings.ransomGuardEnabled ? settings.ransomGuardDirs
                                                                       : QStringList{}),
            composeRansomGuardWriters(options, engine.getRules()));
        // 信任名单同时是窃密防护的全局读者,加白后要一起重推。
        coordinator->applyReadGuard(options.SensitiveDataGuardEnabled,
                                    composeReadGuardEntries(options),
                                    composeReadGuardReaders(options, engine.getRules()));
    };
    trustAddedHook = [&worker, &ransomGuardRefreshHook] {
        worker.purgeTaintRulesAfterTrust();
        worker.reconcileKernelBlocksAfterTrust();
        if (ransomGuardRefreshHook)
            ransomGuardRefreshHook();
    };
    forceQuarantineHook = [&worker](const bulwark::ipc::ManualQuarantinePayload& req) {
        return req.force ? worker.forceHandle(req) : worker.forceQuarantine(req.path);
    };
    ipc.persistenceCleanupRequested =
        [&worker, persistenceSnapshot](const bulwark::ipc::PersistenceCleanupRequestPayload& req) {
            bulwark::ipc::PersistenceCleanupResultPayload denied;
            denied.requestId = req.requestId;
            denied.entryId = req.entry.id;
            const bool fresh = persistenceSnapshot->scannedUtc.isValid()
                && persistenceSnapshot->scannedUtc.secsTo(QDateTime::currentDateTimeUtc()) <= 300;
            const auto it = persistenceSnapshot->byId.constFind(req.entry.id);
            if (!fresh || req.entry.id.trimmed().isEmpty()
                || it == persistenceSnapshot->byId.constEnd()) {
                denied.success = false;
                denied.message = QStringLiteral("清理请求未绑定到最近 5 分钟内的服务端扫描结果,请刷新后重试");
                return denied;
            }
            auto trustedReq = req;
            trustedReq.entry = it.value(); // location/category/name 全部取服务端快照，忽略客户端回传内容
            auto result = worker.cleanupPersistence(trustedReq);
            if (result.success)
                persistenceSnapshot->byId.remove(req.entry.id);
            return result;
        };
    worker.setTaintRuleInjector(
        [&engine, &ruleStore, &log](const QVector<bulwark::DefenseRule>& newRules) -> int {
            const auto existing = engine.getRules();
            auto duplicate = [&existing](const bulwark::DefenseRule& nr) {
                for (const bulwark::DefenseRule& r : existing)
                    if (r.type == nr.type && r.action == nr.action
                        && r.targetPattern == nr.targetPattern && r.actorHashes == nr.actorHashes
                        && r.actorPath.compare(nr.actorPath, Qt::CaseInsensitive) == 0
                        && r.commandLinePattern == nr.commandLinePattern)
                        return true;
                return false;
            };
            int added = 0;
            for (const bulwark::DefenseRule& r : newRules) {
                if (duplicate(r)) continue;
                engine.addRule(r);
                ++added;
            }
            if (added > 0) {
                ruleStore.save(engine.getRules());
                log.info(QStringLiteral("释放物污点规则:新增 %1 条主动拦截规则。").arg(added));
            }
            return added;
        });

    intelFeed.start();
    yaraRules.start();
    yaraScanner.start();
    const bool standbyAtStart = settings.protectionFollowsUi && ipc.clientCount() == 0;

    coordinator->configureBehaviorMonitor(settings.userModeBehaviorMonitor, settings.ransomwareCanaryEnabled);
    coordinator->setMemoryProtectionEnabled(settings.memoryProtectionEnabled);
    coordinator->applyRansomGuard(
        settings.ransomGuardEnabled,
        composeRansomGuardDirs(options, settings.ransomGuardEnabled ? settings.ransomGuardDirs
                                                                   : QStringList{}),
        composeRansomGuardWriters(options, engine.getRules()));
    coordinator->applyReadGuard(options.SensitiveDataGuardEnabled,
                                composeReadGuardEntries(options),
                                composeReadGuardReaders(options, engine.getRules()));
    if (standbyAtStart) {
        log.warning(QStringLiteral("「退出界面即停止防护」已开启且界面当前未运行 —— 本次启动直接进入待机:"
                                   "不启动 ETW 会话、不投放勒索诱饵、不加载内核驱动、不重放禁止执行名单。"
                                   "打开 bulwark_ui.exe 即会拉起全部防护;在此之前本机"
                                   "【不受本软件保护】。"));
    } else {
        coordinator->start();
    }

    const auto recordKernelState =
            [&audit, &ipc, &log, coordinatorPtr](bool connected, const QString& detail) {
                QJsonObject o;
                o["timestampUtc"] = QDateTime::currentDateTimeUtc().toString(Qt::ISODateWithMs);
                o["type"] = QStringLiteral("KernelProtectionState");
                o["connected"] = connected;
                o["protectionTier"] = connected ? QStringLiteral("Driver") : QStringLiteral("Wmi");
                if (coordinatorPtr)
                    o["protectionTierDetailed"] = coordinatorPtr->protectionTier();
                o["detail"] = detail;
                if (coordinatorPtr) {
                    QJsonArray caps;
                    for (const auto& c : coordinatorPtr->protectionCapabilities()) {
                        QJsonObject co;
                        co["dimension"] = c.dimension;
                        co["inForce"] = c.inForce;
                        co["provider"] = c.provider;
                        if (!c.limit.isEmpty())
                            co["limit"] = c.limit;
                        caps.append(co);
                    }
                    o["capabilities"] = caps;
                }
                audit.writeRecord(o);

                if (connected) log.info(detail); else log.warning(detail);
                if (coordinatorPtr)
                    log.warning(coordinatorPtr->protectionSummary());

                ipc.sendLog(detail);
                ipc.sendSettings();
            };
    if (coordinatorPtr)
        coordinatorPtr->setKernelStateChanged(recordKernelState);

    const bool kernelInitial = settings.kernelDriverEnabled;
    if (standbyAtStart) {
        coordinator->setSuspended(true);
        coordinator->setKernelWantedOnResume(kernelInitial);
        recordKernelState(false,
                          QStringLiteral("启动即待机(「退出界面即停止防护」已开启,界面未运行)· "
                                         "内核驱动未加载,本软件此刻不提供任何防护"));
    } else if (kernelInitial) {
        coordinator->setKernelEnabled(true);
    } else {
        recordKernelState(false, QStringLiteral("按设置运行于用户态观测(「内核驱动」开关已关闭)"
                                               "· 无行为前拦截"));
    }

    if (!coordinator->isAvailable() && !standbyAtStart)
        log.warning(QStringLiteral("基础事件源(ETW)不可用(通常因未以管理员身份运行);"
                                   "无实时进程事件,IPC/规则 / 用户态行为监控仍照常工作。"));

    worker.reconcileKernelBlocksAfterTrust();

    worker.startMaliciousSweep();

    worker.startPreexistingAudit();

    constexpr int kStandByGraceMs = 8000;

    auto standByTimer = new QTimer(&ipc);
    standByTimer->setSingleShot(true);
    standByTimer->setInterval(kStandByGraceMs);

    auto applyProtectionLifetime =
        [&settings, &ipc, coordinatorPtr, workerPtr, &audit, &log, standByTimer, &amsiBridge](bool immediate) {
            if (!coordinatorPtr || !workerPtr)
                return;
            const bool uiOnline = ipc.clientCount() > 0;
            const bool want = settings.protectionEnabled
                && (!settings.protectionFollowsUi || uiOnline);
            const bool isSuspended = coordinatorPtr->isSuspended();
            if (want == !isSuspended) {
                standByTimer->stop();
                amsiBridge.setEnabled(want);
                setServiceStopAccepted(!want);
                return;
            }
            if (want) {
                standByTimer->stop();
            } else if (!immediate) {
                if (!standByTimer->isActive())
                    standByTimer->start();
                return;
            }

            if (!want)
                workerPtr->setProtectionSuspended(true);
            coordinatorPtr->setSuspended(!want);
            setServiceStopAccepted(!want);
            // 待机时脚本内容也不再送检拦截:「不提供任何防护」要对 AMSI 同样成立。
            amsiBridge.setEnabled(want);
            if (want) {
                workerPtr->setProtectionSuspended(false);
                workerPtr->reconcileKernelBlocksAfterTrust();
                workerPtr->startPreexistingAudit(5);
            }

            const QString detail = want
                ? QStringLiteral("防护已恢复")
                : (!settings.protectionEnabled
                       ? QStringLiteral("实时防护总开关已关闭 —— 内核驱动已卸载、事件源已停、用户态拦截已放开")
                       : QStringLiteral("界面已退出 —— 防护已停止(内核驱动已卸载、事件源已停、"
                                        "用户态拦截已放开)"));
            log.warning(QStringLiteral("【防护生命周期】%1").arg(detail));
            {
                QJsonObject o;
                o["timestampUtc"] = QDateTime::currentDateTimeUtc().toString(Qt::ISODateWithMs);
                o["type"] = QStringLiteral("ProtectionLifetime");
                o["protectionActive"] = want;
                o["uiOnline"] = uiOnline;
                o["reason"] = detail;
                o["protectionTierDetailed"] = coordinatorPtr->protectionTier();
                audit.writeRecord(o);
            }
            ipc.sendLog(QStringLiteral("【防护生命周期】") + detail);
            ipc.sendSettings();
        };
    protectionLifetimeHook = [applyProtectionLifetime] { applyProtectionLifetime(true); };

    QObject::connect(standByTimer, &QTimer::timeout, &ipc,
                     [applyProtectionLifetime] { applyProtectionLifetime(true); });

    QObject::connect(&ipc, &IpcServer::clientCountChanged, &ipc, [applyProtectionLifetime, &ipc](int n) {
        QTimer::singleShot(0, &ipc, [applyProtectionLifetime, n] { applyProtectionLifetime(n > 0); });
    });

    applyProtectionLifetime(true);

    QTimer baselineSaveTimer;
    baselineSaveTimer.setInterval(5 * 60 * 1000);
    QObject::connect(&baselineSaveTimer, &QTimer::timeout, [&engine, &baselineStore] {
        baselineStore.save(engine.exportBaseline());
    });
    baselineSaveTimer.start();

    log.info(QStringLiteral("Bulwark 服务已就绪。"));

    const int rc = app.exec();

    baselineSaveTimer.stop();
    baselineStore.save(engine.exportBaseline());
    log.info(QStringLiteral("行为基线画像已落盘。"));

    // 先停止接收新请求，再等所有捕获栈对象引用的后台任务退出；不得超时后继续析构。
    ipc.stop();
    int waitTicks = 0;
    while (forensicsInflight->load() > 0) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        if (++waitTicks % 100 == 0)
            log.warning(QStringLiteral("停机仍在等待 %1 个后台任务安全退出。")
                            .arg(forensicsInflight->load()));
    }

    amsiBridge.stop();
    amsiBridge.setTrustProbe(nullptr);
    amsiBridge.setReporter(nullptr);

    intelFeed.stop();
    yaraRules.stop();
    yaraScanner.stop();
    yaraRules.setRulesInstalled(nullptr);
    yaraScanner.setChangedCallback(nullptr);
    yaraScanner.setMaliciousCallback(nullptr);
    ipc.yaraStatusRequested = nullptr;
    ipc.yaraActionRequested = nullptr;
    coordinator->stop();

    ipc.hardeningStatusRequested = nullptr;
    ipc.hardeningActionRequested = nullptr;
    hijackGuard.stop();
    quarantine.setExecDenyFallback(nullptr);
    quarantine.setSelfUnlock(nullptr);
    quarantine.setKernelAssist(nullptr, nullptr);

    log.info(QStringLiteral("Bulwark 服务退出。"));
    stopFileLog();
    return rc;
}


namespace {

const wchar_t* kSvcName = L"BulwarkService";
const wchar_t* kSvcDisplay = L"\u78D0\u5792\u4E3B\u52A8\u9632\u5FA1\u670D\u52A1";

const wchar_t kSvcDependencies[] = L"FltMgr\0";

SERVICE_STATUS_HANDLE g_statusHandle = nullptr;
SERVICE_STATUS g_status = {};
int g_svcArgc = 0;
char** g_svcArgv = nullptr;

std::atomic<bool> g_stopRequested{false};
std::atomic<bool> g_stopAccepted{true};

void reportStatus(DWORD state, DWORD waitHint = 0, DWORD win32ExitCode = NO_ERROR) {
    g_status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    g_status.dwCurrentState = state;
    g_status.dwControlsAccepted =
        (state == SERVICE_START_PENDING)
            ? 0
            : (SERVICE_ACCEPT_SHUTDOWN | (g_stopAccepted.load() ? SERVICE_ACCEPT_STOP : 0));
    g_status.dwWin32ExitCode = win32ExitCode;
    g_status.dwWaitHint = waitHint;
    static DWORD checkPoint = 1;
    g_status.dwCheckPoint =
        (state == SERVICE_RUNNING || state == SERVICE_STOPPED) ? 0 : checkPoint++;
    if (g_statusHandle) ::SetServiceStatus(g_statusHandle, &g_status);
}

// 防护生效时不接受 SCM 的停止请求:脚本里一句 sc stop / net stop 就能先把本产品停掉再动手。
// 要停服务(升级、卸载)先在界面里关掉实时防护,或退出界面进入待机;关机照常收到 SHUTDOWN。
void setServiceStopAccepted(bool accept) {
    if (g_stopAccepted.exchange(accept) == accept)
        return;
    if (g_statusHandle && g_status.dwCurrentState == SERVICE_RUNNING)
        reportStatus(SERVICE_RUNNING);
}

void WINAPI serviceCtrlHandler(DWORD ctrl) {
    if (ctrl == SERVICE_CONTROL_STOP || ctrl == SERVICE_CONTROL_SHUTDOWN) {
        g_stopRequested.store(true);
        reportStatus(SERVICE_STOP_PENDING, 8000);
        if (auto* a = QCoreApplication::instance())
            QMetaObject::invokeMethod(a, "quit", Qt::QueuedConnection);
    }
}

void WINAPI serviceMain(DWORD, LPWSTR*) {
    g_statusHandle = ::RegisterServiceCtrlHandlerW(kSvcName, serviceCtrlHandler);
    if (!g_statusHandle) return;
    reportStatus(SERVICE_START_PENDING, 8000);
    reportStatus(SERVICE_RUNNING);

    int rc = 1;
    try {
        rc = serviceRun(g_svcArgc, g_svcArgv);
    } catch (const std::exception& ex) {
        std::fprintf(stderr, "serviceRun 异常终止:%s\n", ex.what());
        rc = 1;
    } catch (...) {
        std::fprintf(stderr, "serviceRun 未知异常终止\n");
        rc = 1;
    }

    const bool userAsked = g_stopRequested.load();
    reportStatus(SERVICE_STOPPED, 0, userAsked ? NO_ERROR : ERROR_PROCESS_ABORTED);
}

bool applyFailureActions(SC_HANDLE svc) {
    // 先把「非崩溃失败也算失败」这个开关打上 —— 它独立于下面的动作表,且下面命中
    // "配置已一致"时会提前返回,所以必须放在前面,否则老服务永远补不上这个开关。
    {
        SERVICE_FAILURE_ACTIONS_FLAG flag = {};
        flag.fFailureActionsOnNonCrashFailures = TRUE;
        ::ChangeServiceConfig2W(svc, SERVICE_CONFIG_FAILURE_ACTIONS_FLAG, &flag);
    }

    SC_ACTION actions[3] = {};
    actions[0].Type = SC_ACTION_RESTART; actions[0].Delay = 5000;
    actions[1].Type = SC_ACTION_RESTART; actions[1].Delay = 5000;
    actions[2].Type = SC_ACTION_RESTART; actions[2].Delay = 60000;

    SERVICE_FAILURE_ACTIONSW fa = {};
    fa.dwResetPeriod = 86400;
    fa.lpRebootMsg = nullptr;      // 绝不重启系统
    fa.lpCommand = nullptr;
    fa.cActions = 3;
    fa.lpsaActions = actions;

    std::vector<char> buf(4096);
    DWORD needed = 0;
    if (::QueryServiceConfig2W(svc, SERVICE_CONFIG_FAILURE_ACTIONS,
                               reinterpret_cast<LPBYTE>(buf.data()),
                               static_cast<DWORD>(buf.size()), &needed)) {
        const auto* cur = reinterpret_cast<const SERVICE_FAILURE_ACTIONSW*>(buf.data());
        bool same = cur->dwResetPeriod == fa.dwResetPeriod && cur->cActions == fa.cActions
                    && cur->lpsaActions != nullptr;
        for (DWORD i = 0; same && i < fa.cActions; ++i)
            same = cur->lpsaActions[i].Type == actions[i].Type
                   && cur->lpsaActions[i].Delay == actions[i].Delay;
        if (same) return true;
    }
    return ::ChangeServiceConfig2W(svc, SERVICE_CONFIG_FAILURE_ACTIONS, &fa) != FALSE;
}

int installService() {
    wchar_t exe[MAX_PATH] = {};
    ::GetModuleFileNameW(nullptr, exe, MAX_PATH);
    const std::wstring bin = L"\"" + std::wstring(exe) + L"\" --service";
    SC_HANDLE scm = ::OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CREATE_SERVICE);
    if (!scm) { std::fprintf(stderr, "OpenSCManager failed (%lu). 需管理员权限。\n", ::GetLastError()); return 1; }
    int rc = 0;
    SC_HANDLE svc = ::CreateServiceW(scm, kSvcName, kSvcDisplay, SERVICE_ALL_ACCESS,
                                     SERVICE_WIN32_OWN_PROCESS, SERVICE_AUTO_START, SERVICE_ERROR_NORMAL,
                                     bin.c_str(), nullptr, nullptr, kSvcDependencies, nullptr, nullptr);
    if (!svc) {
        const DWORD e = ::GetLastError();
        if (e == ERROR_SERVICE_EXISTS) std::printf("BulwarkService 已存在。\n");
        else { std::fprintf(stderr, "CreateService failed (%lu).\n", e); rc = 1; }
    } else {
        const bool fa = applyFailureActions(svc);
        std::printf("BulwarkService 已安装(自动启动%s)。用 `sc start BulwarkService` 启动。\n",
                    fa ? " + 异常终止自动恢复" : "");
        if (!fa)
            std::fprintf(stderr, "提示:配置失败自动恢复未成功(错误 %lu),"
                                 "服务异常终止后需手动启动。\n", ::GetLastError());
        ::CloseServiceHandle(svc);
    }
    ::CloseServiceHandle(scm);
    return rc;
}

int uninstallService() {
    SC_HANDLE scm = ::OpenSCManagerW(nullptr, nullptr,
                                      SC_MANAGER_CONNECT | SC_MANAGER_CREATE_SERVICE);
    if (!scm) { std::fprintf(stderr, "OpenSCManager failed (%lu). 需管理员权限。\n", ::GetLastError()); return 1; }

    int rc = 0;
    SC_HANDLE svc = ::OpenServiceW(scm, kSvcName, SERVICE_STOP | DELETE);
    if (!svc) {
        std::fprintf(stderr, "OpenService failed (%lu)(可能未安装)。\n", ::GetLastError());
        rc = 1;
    } else {
        SERVICE_STATUS st = {};
        if (!::ControlService(svc, SERVICE_CONTROL_STOP, &st)
            && ::GetLastError() == ERROR_INVALID_SERVICE_CONTROL) {
            std::fprintf(stderr, "防护生效中,服务拒绝停止。请先在界面里关闭实时防护"
                                 "(或退出界面进入待机)后再卸载。\n");
            ::CloseServiceHandle(svc);
            ::CloseServiceHandle(scm);
            return 1;
        }
        if (::DeleteService(svc)) std::printf("BulwarkService 已卸载。\n");
        else { std::fprintf(stderr, "DeleteService failed (%lu).\n", ::GetLastError()); rc = 1; }
        ::CloseServiceHandle(svc);
    }
    ::CloseServiceHandle(scm);
    return rc;
}

int prepareReplace() {
    // 先停服务再卸驱动:服务在线(防护生效)时驱动拒绝外部卸载,服务自己也拒绝停止。
    bool serviceStopped = false;
    SC_HANDLE scm = ::OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (scm) {
        SC_HANDLE svc = ::OpenServiceW(scm, kSvcName, SERVICE_STOP | SERVICE_QUERY_STATUS);
        if (!svc) {
            serviceStopped = (::GetLastError() == ERROR_SERVICE_DOES_NOT_EXIST);
        } else {
            SERVICE_STATUS st = {};
            if (!::QueryServiceStatus(svc, &st))
                st.dwCurrentState = 0;
            if (st.dwCurrentState != SERVICE_STOPPED
                && !::ControlService(svc, SERVICE_CONTROL_STOP, &st)
                && ::GetLastError() == ERROR_INVALID_SERVICE_CONTROL) {
                std::fprintf(stderr, "prepare-replace: 防护生效中,服务拒绝停止。请先在界面里关闭实时防护"
                                     "(或退出界面进入待机)后再升级。\n");
            }
            for (int i = 0; i < 40; ++i) {
                if (!::QueryServiceStatus(svc, &st)) break;
                if (st.dwCurrentState == SERVICE_STOPPED) break;
                ::Sleep(200);
            }
            serviceStopped = st.dwCurrentState == SERVICE_STOPPED;
            std::printf("prepare-replace: 用户态服务 %s\n",
                        serviceStopped ? "已停止" : "未能停止");
            ::CloseServiceHandle(svc);
        }
        ::CloseServiceHandle(scm);
    }

    bool driverStopped = !DriverControl::isRunning();
    if (serviceStopped && !driverStopped) {
        std::printf("prepare-replace: 卸载内核驱动…\n");
        (void)DriverControl::tryStop();
        ::Sleep(500);
        driverStopped = !DriverControl::isRunning();
    }
    if (!driverStopped)
        std::fprintf(stderr, "prepare-replace: 内核驱动仍在运行,拒绝继续覆盖。\n");

    if (!driverStopped || !serviceStopped) {
        std::fprintf(stderr, "prepare-replace: 未安全停止全部组件,安装程序不得覆盖文件。\n");
        return 1;
    }
    std::printf("prepare-replace: 完成(安装程序可继续覆盖文件)。\n");
    return 0;
}

QStringList g_bootstrapNotes;

void note(const QString& s) {
    g_bootstrapNotes << s;
    std::printf("%s\n", s.toLocal8Bit().constData());
}

QString dataDir() {
    QString dir = qEnvironmentVariable("BULWARK_DATA_DIR").trimmed();
    if (dir.isEmpty()) {
        QString base = qEnvironmentVariable("ProgramData");
        if (base.isEmpty()) base = QStringLiteral("C:/ProgramData");
        dir = base + QStringLiteral("/Bulwark");
    }
    return dir;
}

bool testSigningOn() {
    QProcess p;
    p.setProcessChannelMode(QProcess::MergedChannels);
    p.start(QStringLiteral("bcdedit.exe"), { QStringLiteral("/enum"), QStringLiteral("{current}") });
    if (!p.waitForStarted(5000) || !p.waitForFinished(10000))
        return true;
    const QString out = QString::fromLocal8Bit(p.readAll());
    for (const QString& line : out.split(QLatin1Char('\n'))) {
        if (line.contains(QStringLiteral("testsigning"), Qt::CaseInsensitive))
            return line.contains(QStringLiteral("Yes"), Qt::CaseInsensitive)
                || line.contains(QString::fromUtf8("\xE6\x98\xAF"));
    }
    return false;
}

void stageDriverBinary() {
    const QString sysRoot = qEnvironmentVariable("SystemRoot", QStringLiteral("C:\\Windows"));
    const QString dst = QDir(sysRoot).filePath(QStringLiteral("System32/drivers/Bulwark.sys"));
    if (QFileInfo::exists(dst))
        return;
    const QString src = QDir(QCoreApplication::applicationDirPath()).filePath(QStringLiteral("Bulwark.sys"));
    if (!QFileInfo::exists(src)) {
        note(QString::fromUtf8("驱动文件 Bulwark.sys 不在程序目录,内核前拦截不可用(将以 ETW 用户态观测运行)。"));
        return;
    }
    if (QFile::copy(src, dst))
        note(QString::fromUtf8("已部署内核驱动到 %1。").arg(QDir::toNativeSeparators(dst)));
    else
        note(QString::fromUtf8("复制 Bulwark.sys 到 System32\\drivers 失败(需管理员权限)。"));
}

bool ensureServiceRunning() {
    wchar_t exe[MAX_PATH] = {};
    ::GetModuleFileNameW(nullptr, exe, MAX_PATH);
    const std::wstring bin = L"\"" + std::wstring(exe) + L"\" --service";

    SC_HANDLE scm = ::OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT | SC_MANAGER_CREATE_SERVICE);
    if (!scm) {
        note(QString::fromUtf8("打开服务管理器失败(错误 %1)——请以管理员身份运行。").arg(::GetLastError()));
        return false;
    }

    SC_HANDLE svc = ::OpenServiceW(scm, kSvcName, SERVICE_QUERY_CONFIG | SERVICE_CHANGE_CONFIG
                                                      | SERVICE_QUERY_STATUS | SERVICE_START);
    if (!svc) {
        svc = ::CreateServiceW(scm, kSvcName, kSvcDisplay, SERVICE_ALL_ACCESS,
                               SERVICE_WIN32_OWN_PROCESS, SERVICE_AUTO_START, SERVICE_ERROR_NORMAL,
                               bin.c_str(), nullptr, nullptr, kSvcDependencies, nullptr, nullptr);
        if (!svc) {
            note(QString::fromUtf8("注册服务失败(错误 %1)。").arg(::GetLastError()));
            ::CloseServiceHandle(scm);
            return false;
        }
        note(QString::fromUtf8("已注册后台服务(开机自动启动)。"));
        if (!applyFailureActions(svc))
            note(QString::fromUtf8("配置「异常终止后自动恢复」失败(错误 %1)——服务若被打死需手动启动。")
                     .arg(::GetLastError()));
    } else {
        std::vector<char> buf(8192);
        DWORD needed = 0;
        auto* cfg = reinterpret_cast<QUERY_SERVICE_CONFIGW*>(buf.data());
        if (::QueryServiceConfigW(svc, cfg, static_cast<DWORD>(buf.size()), &needed)) {
            const bool pathStale = cfg->lpBinaryPathName == nullptr
                                   || ::_wcsicmp(cfg->lpBinaryPathName, bin.c_str()) != 0;
            const bool notAuto = cfg->dwStartType != SERVICE_AUTO_START;
            const bool depsMissing = cfg->lpDependencies == nullptr
                                     || cfg->lpDependencies[0] == L'\0';
            if (pathStale || notAuto || depsMissing) {
                if (::ChangeServiceConfigW(svc, SERVICE_NO_CHANGE, SERVICE_AUTO_START, SERVICE_NO_CHANGE,
                                           pathStale ? bin.c_str() : nullptr,
                                           nullptr, nullptr,
                                           depsMissing ? kSvcDependencies : nullptr,
                                           nullptr, nullptr, nullptr)) {
                    QStringList fixed;
                    if (pathStale)   fixed << QString::fromUtf8("程序路径");
                    if (notAuto)     fixed << QString::fromUtf8("开机自启");
                    if (depsMissing) fixed << QString::fromUtf8("FltMgr 依赖");
                    note(QString::fromUtf8("已修正服务配置(%1)。").arg(fixed.join(QStringLiteral(" / "))));
                } else {
                    note(QString::fromUtf8("修正服务配置失败(错误 %1)——可能被内核自保护挡住,"
                                           "如需改动请先在界面里关闭内核驱动。")
                             .arg(::GetLastError()));
                }
            }
        }
        if (!applyFailureActions(svc))
            note(QString::fromUtf8("配置「异常终止后自动恢复」失败(错误 %1)——"
                                   "可能被内核自保护挡住,可先关闭内核驱动后重试。")
                     .arg(::GetLastError()));
    }

    if (!::StartServiceW(svc, 0, nullptr)) {
        const DWORD e = ::GetLastError();
        if (e != ERROR_SERVICE_ALREADY_RUNNING) {
            note(QString::fromUtf8("启动服务失败(错误 %1)。").arg(e));
            ::CloseServiceHandle(svc);
            ::CloseServiceHandle(scm);
            return false;
        }
    }

    bool running = false;
    for (int i = 0; i < 80; ++i) {
        SERVICE_STATUS_PROCESS st = {};
        DWORD n = 0;
        if (::QueryServiceStatusEx(svc, SC_STATUS_PROCESS_INFO, reinterpret_cast<LPBYTE>(&st),
                                   sizeof(st), &n)) {
            if (st.dwCurrentState == SERVICE_RUNNING) { running = true; break; }
            if (st.dwCurrentState == SERVICE_STOPPED) break;
        }
        ::Sleep(500);
    }
    ::CloseServiceHandle(svc);
    ::CloseServiceHandle(scm);

    if (running) note(QString::fromUtf8("后台服务已运行。"));
    else         note(QString::fromUtf8("后台服务未能进入运行状态,详见 service.log。"));
    return running;
}

int runBootstrap(int argc, char** argv) {
    QCoreApplication app(argc, argv);
    QCoreApplication::setApplicationName(QStringLiteral("Bulwark Bootstrap"));

    stageDriverBinary();

    if (DriverControl::isRunning()) {
        note(QString::fromUtf8("内核驱动已加载。"));
    } else if (DriverControl::ensureLoaded()) {
        note(QString::fromUtf8("内核驱动已加载(行为前拦截已启用)。"));
    } else if (!testSigningOn()) {
        note(QString::fromUtf8("内核驱动加载失败:系统未开启测试签名模式。"
                               "以管理员运行 `bcdedit /set testsigning on` 后重启即可;"
                               "在此之前防护以 ETW 用户态观测运行。"));
    } else {
        note(QString::fromUtf8("内核驱动加载失败,防护将以 ETW 用户态观测运行。"));
    }

    const bool ok = ensureServiceRunning();

    const QString dir = dataDir();
    QDir().mkpath(dir);
    QFile f(QDir(dir).filePath(QStringLiteral("bootstrap-status.txt")));
    if (f.open(QIODevice::WriteOnly | QIODevice::Truncate))
        f.write(g_bootstrapNotes.join(QLatin1Char('\n')).toUtf8());

    return ok ? 0 : 1;
}

}

int main(int argc, char** argv) {
    for (int i = 1; i < argc; ++i) {
        const std::string a = argv[i];
        if (a == "--install") return installService();
        if (a == "--uninstall") return uninstallService();
        if (a == "--prepare-replace") return prepareReplace();
        if (a == "--bootstrap") return runBootstrap(argc, argv);
        if (a == "--service") {
            g_svcArgc = argc;
            g_svcArgv = argv;
            SERVICE_TABLE_ENTRYW table[] = {
                { const_cast<LPWSTR>(kSvcName), serviceMain },
                { nullptr, nullptr },
            };
            if (!::StartServiceCtrlDispatcherW(table)) {
                std::fprintf(stderr, "--service 只能由 SCM 启动(StartServiceCtrlDispatcher failed %lu)。\n",
                             ::GetLastError());
                return 1;
            }
            return 0;
        }
    }
    return serviceRun(argc, argv);
}
