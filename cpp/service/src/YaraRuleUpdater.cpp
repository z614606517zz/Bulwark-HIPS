#include "bulwark/service/YaraRuleUpdater.h"

#include "bulwark/service/AtomicFile.h"
#include "bulwark/service/YaraForgeRelease.h"
#include "bulwark/service/YaraHelperProcess.h"
#include "bulwark/service/reputation/HttpTransport.h"

#include <QCoreApplication>
#include <QCryptographicHash>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QJsonDocument>
#include <QJsonObject>
#include <QRegularExpression>

#include <algorithm>
#include <chrono>
#include <string>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

namespace bulwark::service {
namespace {

using bulwark::ipc::YaraRulesActionRequestPayload;
using bulwark::ipc::YaraRulesActionResultPayload;
using bulwark::ipc::YaraRulesStatusPayload;

QString u(const char* s) { return QString::fromUtf8(s); }

constexpr int kMaxSkippedKept = 300;
constexpr qint64 kRetryAfterFailureSecs = 2 * 3600;
constexpr qint64 kMaxIdleWaitSecs = 6 * 3600;
constexpr qint64 kCompilerPollSecs = 60;
constexpr int kReleaseInfoMaxBytes = 1024 * 1024;

QString noCompilerMessage() { return u("辅助程序 bulwark_yarac.exe 不在安装目录,没有下载。"); }

// 上次检查只是因为辅助程序不在才失败、而它现在已经在了:这是部署顺序问题,不是网络或规则包的问题,
// 不该再按失败退避等满两小时。改写成就绪状态并返回 true,调用方据此安排尽快检查。
bool forgiveMissingCompiler(YaraRulesStatusPayload& s) {
    if (!s.compilerAvailable || !s.lastCheckFailed || s.message != noCompilerMessage())
        return false;
    s.lastCheckFailed = false;
    s.message = s.autoUpdate ? u("辅助程序已就位,稍后自动检查并下载规则。")
                             : u("辅助程序已就位,可以立即更新规则。");
    return true;
}

std::wstring native(const QString& path) { return QDir::toNativeSeparators(path).toStdWString(); }

QString megabytes(qint64 bytes) {
    return QString::number(static_cast<double>(bytes) / 1024.0 / 1024.0, 'f', 1) + QStringLiteral(" MB");
}

// 随包辅助程序链接的引擎。为空(构建时没有 YARA-X 包)时不核对。
QString bundledEngine() {
    const QString v = QStringLiteral(BULWARK_YARAX_VERSION).trimmed();
    return v.isEmpty() ? QString() : QStringLiteral("YARA-X ") + v;
}

void clearRuleFields(YaraRulesStatusPayload& s) {
    s.releaseTag.clear();
    s.releasePublishedUtc = QDateTime();
    s.packageSha256.clear();
    s.packageBytes = 0;
    s.rulesFound = 0;
    s.rulesCompiled = 0;
    s.rulesSkipped = 0;
    s.compiledBytes = 0;
    s.compileMs = 0;
    s.rulesPath.clear();
    s.sources.clear();
    s.skipped.clear();
}

}

YaraRuleUpdater::YaraRuleUpdater(const YaraRulesOptions& opt, const QString& dataDir,
                                 const QString& compilerPath)
    : opt_(opt), dataDir_(dataDir), compilerPath_(compilerPath) {
    static const QRegularExpression packageName(QStringLiteral("^[a-z]{1,16}$"));
    opt_.Package = opt_.Package.trimmed().toLower();
    if (!packageName.match(opt_.Package).hasMatch())
        opt_.Package = QStringLiteral("core");
    opt_.CheckIntervalHours = std::clamp(opt_.CheckIntervalHours, 1, 24 * 30);
    opt_.MaxDownloadMB = std::clamp(opt_.MaxDownloadMB, 1, 256);
    opt_.DownloadTimeoutSeconds = std::clamp(opt_.DownloadTimeoutSeconds, 10, 600);
    opt_.CompileTimeoutSeconds = std::clamp(opt_.CompileTimeoutSeconds, 30, 3600);
    opt_.InitialDelaySeconds = std::clamp(opt_.InitialDelaySeconds, 0, 3600);
    stopEvent_ = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    QDir().mkpath(dataDir_);
    loadState();
}

YaraRuleUpdater::~YaraRuleUpdater() {
    stop();
    if (stopEvent_)
        CloseHandle(static_cast<HANDLE>(stopEvent_));
}

void YaraRuleUpdater::setStatusChanged(StatusCallback cb) {
    std::lock_guard<std::mutex> lk(mx_);
    onStatus_ = std::move(cb);
}

void YaraRuleUpdater::setRulesInstalled(RulesCallback cb) {
    std::lock_guard<std::mutex> lk(mx_);
    onRulesInstalled_ = std::move(cb);
}

QString YaraRuleUpdater::rulesPath() const {
    return QDir(dataDir_).filePath(QStringLiteral("rules/yara-forge-%1.yarc").arg(opt_.Package));
}

void YaraRuleUpdater::loadState() {
    std::lock_guard<std::mutex> lk(mx_);
    YaraRulesStatusPayload s;
    bool userSet = false;
    QFile f(QDir(dataDir_).filePath(QStringLiteral("state.json")));
    if (f.open(QIODevice::ReadOnly)) {
        const QJsonObject root = QJsonDocument::fromJson(f.readAll()).object();
        s = YaraRulesStatusPayload::fromJson(root.value(QLatin1String("status")).toObject());
        const QJsonValue autoUpdate = root.value(QLatin1String("autoUpdate"));
        if (autoUpdate.isBool()) {
            userSet = true;
            s.autoUpdate = autoUpdate.toBool();
        }
    }
    if (!userSet)
        s.autoUpdate = opt_.AutoUpdate;

    // 运行期事实每次启动重新核对,不信落盘值。
    const QString storedPackage = s.package;
    s.featureEnabled = opt_.Enabled;
    s.compilerAvailable = QFileInfo::exists(compilerPath_);
    s.usedForDetection = false;
    s.stage = QStringLiteral("idle");
    s.stageDetail.clear();
    s.package = opt_.Package;
    s.dataDir = QDir::toNativeSeparators(dataDir_);
    s.checkIntervalHours = opt_.CheckIntervalHours;
    s.scan = {};
    const QString engine = bundledEngine();
    const bool engineChanged = !engine.isEmpty() && s.rulesCompiled > 0 && s.engine != engine;
    if (storedPackage != opt_.Package || !QFileInfo::exists(rulesPath()) || engineChanged) {
        clearRuleFields(s);
        if (engineChanged) {
            // 升级换了引擎:旧规则扫描进程载不了,启动后尽快重新下载编译,而不是等满一个周期。
            s.lastCheckUtc = QDateTime();
            s.lastCheckFailed = false;
            s.message = u("辅助程序换成了 %1,之前的规则需要重新下载编译。").arg(engine);
        }
    } else {
        s.rulesPath = QDir::toNativeSeparators(rulesPath());
    }
    if (s.engine.isEmpty() || engineChanged)
        s.engine = engine.isEmpty() ? QStringLiteral("YARA-X") : engine;
    checkSoon_ = forgiveMissingCompiler(s);

    state_ = s;
    autoUpdateUserSet_ = userSet;
    refreshNextCheckLocked();
}

bool YaraRuleUpdater::noticeCompilerLocked() {
    if (state_.compilerAvailable || !QFileInfo::exists(compilerPath_))
        return false;
    state_.compilerAvailable = true;
    if (forgiveMissingCompiler(state_))
        checkSoon_ = true;
    return true;
}

void YaraRuleUpdater::saveStateLocked() const {
    YaraRulesStatusPayload s = state_;
    s.stage = QStringLiteral("idle");
    s.stageDetail.clear();
    QJsonObject root;
    root[QStringLiteral("status")] = s.toJson();
    if (autoUpdateUserSet_)
        root[QStringLiteral("autoUpdate")] = state_.autoUpdate;
    writeFileAtomically(QDir(dataDir_).filePath(QStringLiteral("state.json")),
                        QJsonDocument(root).toJson(QJsonDocument::Indented), QStringLiteral("yara state"));
}

void YaraRuleUpdater::refreshNextCheckLocked() {
    if (!state_.featureEnabled || !state_.autoUpdate) {
        state_.nextCheckUtc = QDateTime();
        return;
    }
    const QDateTime now = QDateTime::currentDateTimeUtc();
    QDateTime next = now;
    if (state_.lastCheckUtc.isValid() && !checkSoon_)
        next = state_.lastCheckUtc.addSecs(state_.lastCheckFailed
                                               ? std::min<qint64>(kRetryAfterFailureSecs,
                                                                  opt_.CheckIntervalHours * 3600LL)
                                               : opt_.CheckIntervalHours * 3600LL);
    if (notBeforeUtc_.isValid() && next < notBeforeUtc_)
        next = notBeforeUtc_;
    state_.nextCheckUtc = next;
}

bulwark::ipc::YaraRulesStatusPayload YaraRuleUpdater::status() const {
    std::lock_guard<std::mutex> lk(mx_);
    return state_;
}

void YaraRuleUpdater::publish() {
    StatusCallback cb;
    YaraRulesStatusPayload s;
    {
        std::lock_guard<std::mutex> lk(mx_);
        cb = onStatus_;
        s = state_;
    }
    if (!cb || !qApp)
        return;
    QMetaObject::invokeMethod(qApp, [cb, s] { cb(s); }, Qt::QueuedConnection);
}

void YaraRuleUpdater::setStage(const QString& stage, const QString& detail) {
    {
        std::lock_guard<std::mutex> lk(mx_);
        state_.stage = stage;
        state_.stageDetail = detail;
    }
    publish();
}

void YaraRuleUpdater::finish(bool failed, const QString& message) {
    {
        std::lock_guard<std::mutex> lk(mx_);
        state_.stage = QStringLiteral("idle");
        state_.stageDetail.clear();
        state_.lastCheckUtc = QDateTime::currentDateTimeUtc();
        state_.lastCheckFailed = failed;
        state_.message = message;
        refreshNextCheckLocked();
        saveStateLocked();
    }
    if (failed)
        log_.warning(u("YARA 规则更新失败:") + message);
    else
        log_.info(u("YARA 规则更新:") + message);
    publish();
}

void YaraRuleUpdater::start() {
    bool autoUpdate = false;
    {
        std::lock_guard<std::mutex> lk(mx_);
        if (!state_.featureEnabled) {
            log_.info(u("YARA 规则联网更新已在部署配置中关闭(YaraRules.Enabled=false),后台不启动。"));
            return;
        }
        notBeforeUtc_ = QDateTime::currentDateTimeUtc().addSecs(opt_.InitialDelaySeconds);
        refreshNextCheckLocked();
        autoUpdate = state_.autoUpdate;
    }
    if (running_.exchange(true))
        return;
    ResetEvent(static_cast<HANDLE>(stopEvent_));
    worker_ = std::thread([this] { loop(); });
    log_.info(u("YARA 规则更新后台已启动(规则包 %1,%2)。")
                  .arg(opt_.Package, autoUpdate ? u("每 %1 小时自动检查").arg(opt_.CheckIntervalHours)
                                                : u("自动更新已关闭")));
}

void YaraRuleUpdater::stop() {
    if (!running_.exchange(false))
        return;
    SetEvent(static_cast<HANDLE>(stopEvent_));
    {
        std::lock_guard<std::mutex> lk(mx_);
        cv_.notify_all();
    }
    if (worker_.joinable())
        worker_.join();
}

void YaraRuleUpdater::loop() {
    while (running_.load()) {
        bool compilerArrived = false;
        {
            std::unique_lock<std::mutex> lk(mx_);
            compilerArrived = noticeCompilerLocked();
            if (!compilerArrived && !updateRequested_) {
                refreshNextCheckLocked();
                const QDateTime now = QDateTime::currentDateTimeUtc();
                if (!state_.nextCheckUtc.isValid() || now < state_.nextCheckUtc) {
                    qint64 waitSecs = kMaxIdleWaitSecs;
                    if (state_.nextCheckUtc.isValid())
                        waitSecs = std::clamp<qint64>(now.secsTo(state_.nextCheckUtc), 1, kMaxIdleWaitSecs);
                    // 辅助程序不在时每分钟看一眼:装进来之后不必等服务重启,也不必等失败退避。
                    if (!state_.compilerAvailable)
                        waitSecs = std::min(waitSecs, kCompilerPollSecs);
                    cv_.wait_for(lk, std::chrono::seconds(waitSecs),
                                 [this] { return !running_.load() || updateRequested_; });
                    continue;
                }
            }
            if (!compilerArrived)
                updateRequested_ = false;
        }
        if (compilerArrived) {
            log_.info(u("YARA 规则更新:辅助程序 bulwark_yarac.exe 已就位。"));
            publish();
            continue;
        }
        if (running_.load())
            runOnce();
    }
}

void YaraRuleUpdater::runOnce() {
    bool compilerAvailable = false;
    {
        std::lock_guard<std::mutex> lk(mx_);
        checkSoon_ = false;
        state_.compilerAvailable = QFileInfo::exists(compilerPath_);
        compilerAvailable = state_.compilerAvailable;
    }
    if (!compilerAvailable) {
        finish(true, noCompilerMessage());
        return;
    }

    setStage(QStringLiteral("checking"), u("查询 YARA Forge 最新发布"));
    const QStringList apiHeaders{QStringLiteral("Accept: application/vnd.github+json"),
                                 QStringLiteral("X-GitHub-Api-Version: 2022-11-28")};
    const auto info = reputation::HttpTransport::getBytes(opt_.ReleaseApiUrl, apiHeaders,
                                                          opt_.DownloadTimeoutSeconds, kReleaseInfoMaxBytes);
    if (!running_.load()) {
        finish(true, u("服务正在停止,本次检查已取消。"));
        return;
    }
    if (info.first != 200) {
        finish(true, info.first == 0 ? u("连不上 GitHub(网络不通、被代理或防火墙拦截),沿用现有规则。")
                                     : u("GitHub 返回 HTTP %1,沿用现有规则。").arg(info.first));
        return;
    }
    QString error;
    const std::optional<yara::ReleaseAsset> asset =
        yara::parseLatestRelease(info.second, opt_.Package, opt_.DownloadUrlPrefix, &error);
    if (!asset) {
        finish(true, u("发布信息不可用:") + error);
        return;
    }

    int previousCompiled = 0;
    bool upToDate = false;
    {
        std::lock_guard<std::mutex> lk(mx_);
        previousCompiled = state_.rulesCompiled;
        upToDate = asset->tag == state_.releaseTag && state_.rulesCompiled > 0
                && QFileInfo::exists(rulesPath());
    }
    if (upToDate) {
        finish(false, u("已是最新:YARA Forge %1。").arg(asset->tag));
        return;
    }
    const qint64 maxBytes = static_cast<qint64>(opt_.MaxDownloadMB) * 1024 * 1024;
    if (asset->size > maxBytes) {
        finish(true, u("规则包 %1 有 %2,超过上限 %3 MB,没有下载。")
                         .arg(asset->name, megabytes(asset->size))
                         .arg(opt_.MaxDownloadMB));
        return;
    }

    const QString staging = QDir(dataDir_).filePath(QStringLiteral("staging"));
    QDir(staging).removeRecursively();
    QDir().mkpath(staging);
    const QString zipPath = QDir(staging).filePath(asset->name);
    const QString outPath = QDir(staging).filePath(QStringLiteral("rules.yarc"));
    const QString reportPath = QDir(staging).filePath(QStringLiteral("report.json"));
    const auto cleanup = [staging] { QDir(staging).removeRecursively(); };

    setStage(QStringLiteral("downloading"), u("下载 %1(%2)").arg(asset->name, megabytes(asset->size)));
    QString sha256;
    if (!download(*asset, zipPath, &sha256, &error)) {
        cleanup();
        finish(true, error);
        return;
    }

    setStage(QStringLiteral("compiling"), u("编译 YARA Forge %1 的 %2 规则包").arg(asset->tag, opt_.Package));
    yara::CompileReport report;
    if (!compile(zipPath, outPath, reportPath, &report, &error)) {
        cleanup();
        finish(true, error);
        return;
    }
    if (!yara::plausibleRuleCount(report.rulesCompiled, previousCompiled)) {
        cleanup();
        finish(true, u("新规则包只编出 %1 条(上一版 %2 条),数量异常,沿用现有规则。")
                         .arg(report.rulesCompiled)
                         .arg(previousCompiled));
        return;
    }

    setStage(QStringLiteral("installing"), u("替换规则文件"));
    if (!install(outPath, &error)) {
        cleanup();
        finish(true, error);
        return;
    }
    cleanup();

    {
        std::lock_guard<std::mutex> lk(mx_);
        state_.package = opt_.Package;
        state_.releaseTag = asset->tag;
        state_.releasePublishedUtc = asset->publishedUtc;
        state_.packageSha256 = sha256;
        state_.packageBytes = asset->size;
        state_.engine = report.engine.isEmpty() ? QStringLiteral("YARA-X") : report.engine;
        state_.rulesFound = report.rulesFound;
        state_.rulesCompiled = report.rulesCompiled;
        state_.rulesSkipped = report.rulesSkipped;
        state_.compiledBytes = report.outputBytes;
        state_.compileMs = report.compileMs;
        state_.sources = report.sources;
        state_.skipped = report.skipped.mid(0, kMaxSkippedKept);
        state_.rulesPath = QDir::toNativeSeparators(rulesPath());
        state_.lastSuccessUtc = QDateTime::currentDateTimeUtc();
    }
    QString message = u("已更新到 YARA Forge %1:编译 %2 条规则,跳过 %3 条。")
                          .arg(asset->tag)
                          .arg(report.rulesCompiled)
                          .arg(report.rulesSkipped);
    if (asset->sha256.isEmpty())
        message += u(" 发布页没有给出摘要,本次未做哈希校验。");
    finish(false, message);

    RulesCallback installed;
    {
        std::lock_guard<std::mutex> lk(mx_);
        installed = onRulesInstalled_;
    }
    if (installed)
        installed(QDir::toNativeSeparators(rulesPath()), u("YARA Forge %1").arg(asset->tag));
}

bool YaraRuleUpdater::download(const yara::ReleaseAsset& asset, const QString& zipPath, QString* sha256,
                               QString* error) {
    const auto res = reputation::HttpTransport::getBytes(asset.url, {}, opt_.DownloadTimeoutSeconds,
                                                         static_cast<int>(asset.size) + 1);
    if (res.first != 200) {
        *error = res.first == 0 ? u("规则包下载失败(网络中断、超时或超过大小上限)。")
                                : u("规则包下载失败:HTTP %1。").arg(res.first);
        return false;
    }
    if (res.second.size() != asset.size) {
        *error = u("规则包大小不符:发布页写 %1 字节,实际收到 %2 字节。").arg(asset.size).arg(res.second.size());
        return false;
    }
    *sha256 = QString::fromLatin1(QCryptographicHash::hash(res.second, QCryptographicHash::Sha256).toHex());
    if (!asset.sha256.isEmpty() && *sha256 != asset.sha256) {
        *error = u("规则包 SHA-256 与发布页不符,已丢弃(期望 %1,实际 %2)。").arg(asset.sha256, *sha256);
        return false;
    }
    QFile f(zipPath);
    if (!f.open(QIODevice::WriteOnly | QIODevice::Truncate) || f.write(res.second) != res.second.size()) {
        *error = u("规则包写盘失败:%1").arg(QDir::toNativeSeparators(zipPath));
        return false;
    }
    f.close();
    return true;
}

bool YaraRuleUpdater::compile(const QString& zipPath, const QString& outPath, const QString& reportPath,
                              yara::CompileReport* report, QString* error) {
    const yarahelper::ExitResult child = yarahelper::runToExit(
        compilerPath_,
        {QStringLiteral("--zip"), QDir::toNativeSeparators(zipPath), QStringLiteral("--out"),
         QDir::toNativeSeparators(outPath), QStringLiteral("--report"), QDir::toNativeSeparators(reportPath)},
        opt_.CompileTimeoutSeconds, opt_.CompilerMemoryLimitMB, stopEvent_);
    if (!child.started) {
        *error = u("编译程序没能启动(错误 %1)。").arg(child.error);
        return false;
    }
    if (child.cancelled) {
        *error = u("服务正在停止,编译已中止。");
        return false;
    }
    if (child.timedOut) {
        *error = u("编译超过 %1 秒被终止,沿用现有规则。").arg(opt_.CompileTimeoutSeconds);
        return false;
    }

    std::optional<yara::CompileReport> parsed;
    QFile f(reportPath);
    if (f.open(QIODevice::ReadOnly))
        parsed = yara::parseCompileReport(f.readAll());
    f.close();
    if (!parsed) {
        *error = u("编译程序异常退出(退出码 0x%1),没有留下报告。")
                     .arg(static_cast<qulonglong>(child.exitCode), 8, 16, QLatin1Char('0'));
        return false;
    }
    const QString kept = QDir(dataDir_).filePath(QStringLiteral("last-compile-report.json"));
    QFile::remove(kept);
    QFile::copy(reportPath, kept);

    *report = *parsed;
    if (child.exitCode != 0 || !parsed->ok) {
        *error = u("编译失败:") + (parsed->error.isEmpty() ? u("退出码 %1").arg(child.exitCode) : parsed->error);
        return false;
    }
    if (!QFileInfo::exists(outPath)) {
        *error = u("编译程序报告成功,但没有写出规则文件。");
        return false;
    }
    return true;
}

bool YaraRuleUpdater::install(const QString& stagedPath, QString* error) {
    const QString target = rulesPath();
    QDir().mkpath(QFileInfo(target).absolutePath());
    const QString previous = QDir(QFileInfo(target).absolutePath())
                                 .filePath(QStringLiteral("yara-forge-%1.prev.yarc").arg(opt_.Package));
    const std::wstring t = native(target);
    const std::wstring p = native(previous);
    const std::wstring s = native(stagedPath);
    const bool hadOld = QFileInfo::exists(target);
    if (hadOld && !MoveFileExW(t.c_str(), p.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
        *error = u("旧规则文件挪不开(错误 %1),没有替换。").arg(GetLastError());
        return false;
    }
    if (!MoveFileExW(s.c_str(), t.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
        const DWORD e = GetLastError();
        if (hadOld)
            MoveFileExW(p.c_str(), t.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH);
        *error = u("新规则文件放不进去(错误 %1),已恢复旧规则。").arg(e);
        return false;
    }
    return true;
}

YaraRulesActionResultPayload YaraRuleUpdater::handleAction(const YaraRulesActionRequestPayload& req) {
    YaraRulesActionResultPayload res;
    res.requestId = req.requestId;
    res.action = req.action;

    if (req.action == QLatin1String("update")) {
        std::lock_guard<std::mutex> lk(mx_);
        noticeCompilerLocked();
        if (!state_.featureEnabled)
            res.message = u("部署配置关闭了 YARA 规则联网更新(appsettings.json 里的 YaraRules.Enabled)。");
        else if (!state_.compilerAvailable)
            res.message = u("辅助程序 bulwark_yarac.exe 不在安装目录,没法更新。");
        else if (!running_.load())
            res.message = u("规则更新后台没有运行。");
        else if (state_.stage != QLatin1String("idle") || updateRequested_)
            res.message = u("上一次更新还没结束。");
        else {
            updateRequested_ = true;
            cv_.notify_all();
            res.ok = true;
            res.message = u("已开始检查更新。");
        }
        return res;
    }

    if (req.action == QLatin1String("auto")) {
        {
            std::lock_guard<std::mutex> lk(mx_);
            if (!state_.featureEnabled) {
                res.message = u("部署配置关闭了 YARA 规则联网更新(appsettings.json 里的 YaraRules.Enabled)。");
                return res;
            }
            state_.autoUpdate = req.enabled;
            autoUpdateUserSet_ = true;
            refreshNextCheckLocked();
            saveStateLocked();
            cv_.notify_all();
        }
        res.ok = true;
        res.message = req.enabled ? u("已开启自动更新:每 %1 小时检查一次。").arg(opt_.CheckIntervalHours)
                                  : u("已关闭自动更新:只在点「立即更新」时联网。");
        log_.info(res.message);
        publish();
        return res;
    }

    res.message = u("不支持的动作:%1").arg(req.action);
    return res;
}

}
