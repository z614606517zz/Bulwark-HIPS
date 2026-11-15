#include "bulwark/service/YaraScanner.h"

#include <QDateTime>
#include <QDir>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>

#include <algorithm>

namespace bulwark::service {
namespace {

using bulwark::ipc::YaraScanHitPayload;
using bulwark::ipc::YaraScanStatusPayload;
using yarahelper::LineChannel;

QString u(const char* s) { return QString::fromUtf8(s); }

constexpr int kQueueMax = 256;
constexpr int kTargetsPerHashMax = 16;
constexpr int kCacheMax = 20000;
constexpr int kRecentHitsMax = 50;
constexpr int kRulesKept = 16;
constexpr int kReadyTimeoutMs = 120 * 1000;
constexpr int kReadSlackMs = 30 * 1000;
constexpr int kIdleStopSecs = 600;
constexpr int kCrashWindowSecs = 600;
constexpr int kCrashLimit = 5;
constexpr int kPauseAfterStartFailureSecs = 600;
constexpr int kPauseAfterCrashLoopSecs = 1800;

// 名单写法:规则名(不分大小写),或以 * 结尾的前缀。单独一个 * 不算 —— 不允许一句话把全部规则判成恶意。
void compilePatterns(const QStringList& in, QSet<QString>* exact, QStringList* prefixes) {
    for (QString p : in) {
        p = p.trimmed().toLower();
        if (p.endsWith(QLatin1Char('*'))) {
            p.chop(1);
            if (!p.isEmpty())
                prefixes->append(p);
        } else if (!p.isEmpty()) {
            exact->insert(p);
        }
    }
}

bool matchesPattern(const QString& rule, const QSet<QString>& exact, const QStringList& prefixes) {
    const QString r = rule.toLower();
    if (exact.contains(r))
        return true;
    return std::any_of(prefixes.cbegin(), prefixes.cend(), [&r](const QString& p) { return r.startsWith(p); });
}

QString describeFailure(const QString& error) {
    if (error == QLatin1String("too-large"))
        return u("文件超过扫描大小上限");
    if (error == QLatin1String("timeout"))
        return u("扫描超时");
    if (error == QLatin1String("read"))
        return u("读文件中途失败");
    if (error.startsWith(QLatin1String("open ")))
        return u("打不开文件(错误 %1)").arg(error.mid(5));
    return error.isEmpty() ? u("扫描失败") : error;
}

QString levelKey(YaraScanner::Level level) {
    return level == YaraScanner::Level::Malicious ? QStringLiteral("malicious") : QStringLiteral("suspicious");
}

}

YaraScanner::YaraScanner(const YaraRulesOptions& opt, const QString& helperPath)
    : opt_(opt), helperPath_(helperPath) {
    opt_.ScanMaxFileMB = std::clamp(opt_.ScanMaxFileMB, 1, 256);
    opt_.ScanTimeoutSeconds = std::clamp(opt_.ScanTimeoutSeconds, 1, 120);
    opt_.ScannerMemoryLimitMB = std::clamp(std::max(opt_.ScannerMemoryLimitMB, opt_.ScanMaxFileMB * 2 + 512), 512, 8192);
    compilePatterns(opt_.MaliciousRules, &maliciousExact_, &maliciousPrefixes_);
    compilePatterns(opt_.IgnoredRules, &ignoredExact_, &ignoredPrefixes_);
    stats_.enabled = opt_.ScanProcesses;
    stats_.verifiedRulePatterns = static_cast<int>(maliciousExact_.size() + maliciousPrefixes_.size());
    stats_.state = opt_.ScanProcesses ? QStringLiteral("no-rules") : QStringLiteral("off");
}

YaraScanner::~YaraScanner() { stop(); }

void YaraScanner::setMaliciousCallback(MaliciousCallback cb) {
    std::lock_guard<std::mutex> lk(mx_);
    onMalicious_ = std::move(cb);
}

void YaraScanner::setChangedCallback(ChangedCallback cb) {
    std::lock_guard<std::mutex> lk(mx_);
    onChanged_ = std::move(cb);
}

void YaraScanner::setRules(const QString& path, const QString& label) {
    {
        std::lock_guard<std::mutex> lk(mx_);
        rulesPath_ = path;
        rulesLabel_ = path.isEmpty() ? QString() : label;
        ++generation_;
        cache_.clear();
        cacheOrder_.clear();
        pausedUntil_ = {};
        crashes_.clear();
        stats_.rulesLabel = rulesLabel_;
        stats_.rulesLoaded = 0;
        if (path.isEmpty()) {
            pending_.clear();
            queue_.clear();
        }
        if (opt_.ScanProcesses) {
            stats_.state = path.isEmpty() ? QStringLiteral("no-rules") : QStringLiteral("idle");
            stats_.detail.clear();
        }
        stats_.pendingScans = static_cast<int>(queue_.size());
    }
    cv_.notify_all();
    if (opt_.ScanProcesses)
        log_.info(path.isEmpty() ? u("YARA 进程扫描:暂无可用规则。")
                                 : u("YARA 进程扫描改用 %1(%2),扫描缓存已清空。").arg(label, path));
    notifyChanged();
}

void YaraScanner::start() {
    if (!opt_.ScanProcesses) {
        log_.info(u("YARA 进程启动扫描已在部署配置中关闭(YaraRules.ScanProcesses=false)。"));
        return;
    }
    if (running_.exchange(true))
        return;
    worker_ = std::thread([this] {
        try {
            loop();
        } catch (...) {
            // 后台线程绝不因异常带崩服务。
        }
    });
    log_.info(u("YARA 进程启动扫描已启动:单个文件上限 %1 MB,超时 %2 秒,已验证家族规则 %3 条。")
                  .arg(opt_.ScanMaxFileMB)
                  .arg(opt_.ScanTimeoutSeconds)
                  .arg(maliciousExact_.size() + maliciousPrefixes_.size()));
}

void YaraScanner::stop() {
    if (!running_.exchange(false))
        return;
    {
        std::lock_guard<std::mutex> lk(mx_);
        cv_.notify_all();
    }
    if (worker_.joinable())
        worker_.join();
}

std::optional<YaraScanner::Verdict> YaraScanner::lookup(const QString& sha256) const {
    const QString key = sha256.toLower();
    std::lock_guard<std::mutex> lk(mx_);
    const auto it = cache_.constFind(key);
    if (it == cache_.constEnd())
        return std::nullopt;
    return it.value();
}

void YaraScanner::submit(const Target& in) {
    if (!opt_.ScanProcesses || in.path.isEmpty())
        return;
    Target t = in;
    t.sha256 = t.sha256.toLower();
    if (t.sha256.size() != 64)
        return;
    {
        std::lock_guard<std::mutex> lk(mx_);
        if (!running_.load() || rulesPath_.isEmpty() || Clock::now() < pausedUntil_)
            return;
        if (cache_.contains(t.sha256))
            return;
        const auto it = pending_.find(t.sha256);
        if (it != pending_.end()) {
            const bool known = std::any_of(it->cbegin(), it->cend(), [&t](const Target& x) {
                return x.pid == t.pid && x.creationFileTime == t.creationFileTime;
            });
            if (!known && it->size() < kTargetsPerHashMax)
                it->append(t);
            return;
        }
        if (static_cast<int>(queue_.size()) >= kQueueMax)
            return;
        pending_.insert(t.sha256, QVector<Target>{t});
        queue_.push_back(t.sha256);
        stats_.pendingScans = static_cast<int>(queue_.size());
    }
    cv_.notify_all();
}

bulwark::ipc::YaraScanStatusPayload YaraScanner::status() const {
    std::lock_guard<std::mutex> lk(mx_);
    YaraScanStatusPayload s = stats_;
    s.pendingScans = static_cast<int>(queue_.size());
    return s;
}

void YaraScanner::loop() {
    while (running_.load()) {
        QString hash;
        QString path;
        QString rulesPath;
        quint64 generation = 0;
        {
            std::unique_lock<std::mutex> lk(mx_);
            for (;;) {
                if (!running_.load())
                    break;
                const Clock::time_point now = Clock::now();
                const bool paused = now < pausedUntil_;
                if (!paused && !queue_.empty() && !rulesPath_.isEmpty())
                    break;
                // 没活干时:换了规则或闲置太久就先把辅助进程停掉,省下它占的内存,下次有活再起。
                if (helper_.running()
                    && (helperGeneration_ != generation_ || now - lastActivity_ >= std::chrono::seconds(kIdleStopSecs))) {
                    lk.unlock();
                    helper_.stop(true);
                    lk.lock();
                    if (stats_.state == QLatin1String("ready"))
                        stats_.state = QStringLiteral("idle");
                    continue;
                }
                if (paused)
                    cv_.wait_until(lk, pausedUntil_);
                else if (helper_.running())
                    cv_.wait_until(lk, lastActivity_ + std::chrono::seconds(kIdleStopSecs));
                else
                    cv_.wait(lk);
            }
            if (!running_.load())
                break;
            hash = queue_.front();
            queue_.pop_front();
            stats_.pendingScans = static_cast<int>(queue_.size());
            const auto it = pending_.constFind(hash);
            if (it != pending_.constEnd() && !it->isEmpty())
                path = it->first().path;
            else
                pending_.remove(hash);
            generation = generation_;
            rulesPath = rulesPath_;
        }
        if (path.isEmpty())
            continue;

        if (!ensureHelper(generation, rulesPath)) {
            {
                std::lock_guard<std::mutex> lk(mx_);
                pending_.clear();
                queue_.clear();
                stats_.pendingScans = 0;
                if (running_.load())
                    pausedUntil_ = Clock::now() + std::chrono::seconds(kPauseAfterStartFailureSecs);
            }
            notifyChanged();
            continue;
        }

        const quint64 id = nextRequestId_++;
        QByteArray reply;
        QString failure;
        bool cancelled = false;
        if (!helper_.writeLine(QByteArray::number(id) + '\t' + QDir::toNativeSeparators(path).toUtf8())) {
            helper_.stop(false);
            failure = u("扫描辅助进程没有响应");
            noteCrash();
        } else {
            QByteArray line;
            const LineChannel::Read r =
                helper_.readLine(&line, opt_.ScanTimeoutSeconds * 1000 + kReadSlackMs, running_);
            if (r == LineChannel::Read::Line
                && QJsonDocument::fromJson(line).object().value(QLatin1String("id")).toInteger()
                       == static_cast<qint64>(id)) {
                reply = line;
            } else if (r == LineChannel::Read::Cancelled) {
                cancelled = true;
            } else {
                helper_.stop(false);
                if (r == LineChannel::Read::TimedOut) {
                    failure = u("扫描超过 %1 秒没有结果,已结束扫描进程").arg(opt_.ScanTimeoutSeconds + kReadSlackMs / 1000);
                } else {
                    failure = u("扫描辅助进程在处理这个文件时退出");
                    noteCrash();
                }
            }
        }
        if (cancelled)
            break;
        lastActivity_ = Clock::now();
        finishScan(hash, path, generation, reply, failure);
    }
    helper_.stop(true);
}

bool YaraScanner::ensureHelper(quint64 generation, const QString& rulesPath) {
    if (helper_.running() && helperGeneration_ == generation)
        return true;
    helper_.stop(true);
    setState(QStringLiteral("starting"), u("载入规则"));
    const QStringList args{QStringLiteral("--serve"),
                           QStringLiteral("--rules"),
                           QDir::toNativeSeparators(rulesPath),
                           QStringLiteral("--timeout"),
                           QString::number(opt_.ScanTimeoutSeconds),
                           QStringLiteral("--max-bytes"),
                           QString::number(static_cast<qint64>(opt_.ScanMaxFileMB) * 1024 * 1024)};
    QString error;
    if (!helper_.start(helperPath_, args, opt_.ScannerMemoryLimitMB, &error)) {
        setState(QStringLiteral("error"), u("扫描辅助进程没能启动(%1)").arg(error));
        log_.warning(u("YARA 扫描辅助进程没能启动:%1").arg(error));
        return false;
    }
    QByteArray line;
    const LineChannel::Read r = helper_.readLine(&line, kReadyTimeoutMs, running_);
    if (r != LineChannel::Read::Line) {
        helper_.stop(false);
        if (r != LineChannel::Read::Cancelled) {
            const QString why = r == LineChannel::Read::TimedOut
                ? u("载入规则超过 %1 秒").arg(kReadyTimeoutMs / 1000)
                : u("扫描辅助进程启动后立即退出");
            setState(QStringLiteral("error"), why);
            log_.warning(u("YARA 扫描辅助进程:") + why);
        }
        return false;
    }
    const QJsonObject o = QJsonDocument::fromJson(line).object();
    if (!o.value(QLatin1String("ready")).toBool()) {
        helper_.stop(false);
        const QString why = u("规则载入失败:%1").arg(o.value(QLatin1String("error")).toString());
        setState(QStringLiteral("error"), why);
        log_.warning(u("YARA 扫描:") + why);
        return false;
    }
    helperGeneration_ = generation;
    lastActivity_ = Clock::now();
    const int rules = o.value(QLatin1String("rules")).toInt();
    QStringList hardening;
    for (const QJsonValue& v : o.value(QLatin1String("hardening")).toArray())
        hardening << v.toString();
    {
        std::lock_guard<std::mutex> lk(mx_);
        stats_.rulesLoaded = rules;
        stats_.state = QStringLiteral("ready");
        stats_.detail = o.value(QLatin1String("engine")).toString();
    }
    log_.info(u("YARA 扫描进程已就绪:%1 条规则,%2,加固项 %3。")
                  .arg(rules)
                  .arg(o.value(QLatin1String("engine")).toString(), hardening.join(QStringLiteral(", "))));
    notifyChanged();
    return true;
}

void YaraScanner::finishScan(const QString& hash, const QString& path, quint64 generation,
                             const QByteArray& reply, const QString& failure) {
    Verdict v;
    QString reported;
    QString error = failure;
    if (error.isEmpty()) {
        const QJsonObject o = QJsonDocument::fromJson(reply).object();
        reported = o.value(QLatin1String("sha256")).toString().toLower();
        if (o.value(QLatin1String("ok")).toBool())
            v = classify(o);
        else
            error = describeFailure(o.value(QLatin1String("error")).toString());
    }
    if (!error.isEmpty()) {
        v = Verdict{};
        v.error = error;
    }

    QVector<Target> targets;
    QString subject = hash;
    MaliciousCallback onMalicious;
    bool hit = false;
    {
        std::lock_guard<std::mutex> lk(mx_);
        if (generation != generation_) {
            // 扫描期间换了规则:结论作废,按新规则重扫(等它的进程还挂在 pending_ 上)。
            if (pending_.contains(hash)) {
                queue_.push_front(hash);
                stats_.pendingScans = static_cast<int>(queue_.size());
            }
            return;
        }
        targets = pending_.take(hash);

        const auto remember = [this](const QString& key, const Verdict& verdict) {
            if (!cache_.contains(key)) {
                cacheOrder_.push_back(key);
                while (static_cast<int>(cacheOrder_.size()) > kCacheMax) {
                    cache_.remove(cacheOrder_.front());
                    cacheOrder_.pop_front();
                }
            }
            cache_.insert(key, verdict);
        };
        if (v.scanned && reported.size() == 64 && reported != hash) {
            // 磁盘上的文件已经不是进程启动时那份:结论记在实际扫到的内容名下;
            // 启动时那份这次没法下结论,也不处置等它的进程 —— 它们跑的是旧内容。
            Verdict stale;
            stale.error = u("文件在扫描前已被替换");
            remember(hash, stale);
            remember(reported, v);
            subject = reported;
            targets.clear();
        } else {
            remember(hash, v);
        }

        if (v.scanned)
            ++stats_.scannedFiles;
        else
            ++stats_.failedScans;
        if (v.scanned && v.level != Level::Clean) {
            if (v.level == Level::Malicious)
                ++stats_.maliciousFiles;
            else
                ++stats_.suspiciousFiles;
            YaraScanHitPayload h;
            h.timeUtc = QDateTime::currentDateTimeUtc();
            h.path = path;
            h.sha256 = subject;
            h.rule = v.rule;
            h.author = v.author;
            h.level = levelKey(v.level);
            h.matchCount = v.matchCount;
            stats_.recentHits.prepend(h);
            while (stats_.recentHits.size() > kRecentHitsMax)
                stats_.recentHits.removeLast();
            hit = true;
        }
        if (v.scanned && v.level == Level::Malicious)
            onMalicious = onMalicious_;
    }

    if (!v.scanned)
        log_.info(u("YARA 未能扫描 %1:%2").arg(path, v.error));
    if (hit) {
        log_.warning(u("YARA %1:%2 命中 %3%4,共 %5 条规则")
                         .arg(v.level == Level::Malicious ? u("判恶意") : u("判可疑"), path, v.rule,
                              v.author.isEmpty() ? QString() : u("(作者 %1)").arg(v.author))
                         .arg(v.matchCount));
        notifyChanged();
    }
    if (onMalicious)
        onMalicious(subject, v, targets);
}

YaraScanner::Verdict YaraScanner::classify(const QJsonObject& reply) const {
    Verdict v;
    v.scanned = true;
    const QJsonArray matches = reply.value(QLatin1String("matches")).toArray();
    int counted = 0;
    int ignored = 0;
    for (const QJsonValue& mv : matches) {
        const QJsonObject m = mv.toObject();
        const QString rule = m.value(QLatin1String("rule")).toString();
        if (rule.isEmpty())
            continue;
        if (matchesPattern(rule, ignoredExact_, ignoredPrefixes_)) {
            ++ignored;
            continue;
        }
        ++counted;
        if (v.rules.size() < kRulesKept)
            v.rules << rule;
        const Level level = matchesPattern(rule, maliciousExact_, maliciousPrefixes_) ? Level::Malicious
                                                                                      : Level::Suspicious;
        if (level > v.level) {
            v.level = level;
            v.rule = rule;
            v.author = m.value(QLatin1String("author")).toString();
            v.description = m.value(QLatin1String("description")).toString();
        }
    }
    // 回复只带前若干条命中,total 是全部条数。
    const int total = reply.value(QLatin1String("total")).toInt(counted + ignored);
    v.matchCount = v.level == Level::Clean ? 0 : std::max(counted, total - ignored);
    return v;
}

void YaraScanner::setState(const QString& state, const QString& detail) {
    {
        std::lock_guard<std::mutex> lk(mx_);
        stats_.state = state;
        stats_.detail = detail;
    }
    notifyChanged();
}

void YaraScanner::noteCrash() {
    const Clock::time_point now = Clock::now();
    bool paused = false;
    {
        std::lock_guard<std::mutex> lk(mx_);
        crashes_.push_back(now);
        while (!crashes_.empty() && now - crashes_.front() > std::chrono::seconds(kCrashWindowSecs))
            crashes_.pop_front();
        if (static_cast<int>(crashes_.size()) >= kCrashLimit) {
            crashes_.clear();
            pending_.clear();
            queue_.clear();
            stats_.pendingScans = 0;
            pausedUntil_ = now + std::chrono::seconds(kPauseAfterCrashLoopSecs);
            stats_.state = QStringLiteral("paused");
            stats_.detail = u("扫描进程 %1 分钟内异常退出 %2 次,暂停 %3 分钟")
                                .arg(kCrashWindowSecs / 60)
                                .arg(kCrashLimit)
                                .arg(kPauseAfterCrashLoopSecs / 60);
            paused = true;
        }
    }
    if (paused) {
        log_.warning(u("YARA 扫描进程反复异常退出,暂停扫描 %1 分钟。").arg(kPauseAfterCrashLoopSecs / 60));
        notifyChanged();
    }
}

void YaraScanner::notifyChanged() {
    ChangedCallback cb;
    {
        std::lock_guard<std::mutex> lk(mx_);
        cb = onChanged_;
    }
    if (cb)
        cb();
}

}
