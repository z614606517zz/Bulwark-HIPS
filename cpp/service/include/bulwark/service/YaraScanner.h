#pragma once

#include "bulwark/ipc/Payloads.h"
#include "bulwark/service/BulwarkOptions.h"
#include "bulwark/service/Logger.h"
#include "bulwark/service/YaraHelperProcess.h"

#include <QHash>
#include <QSet>
#include <QString>
#include <QStringList>
#include <QVector>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <deque>
#include <functional>
#include <mutex>
#include <optional>
#include <thread>

namespace bulwark::service {

// 进程启动时对主体程序文件做 YARA 扫描。
//
// 结果按 SHA-256 缓存;没扫过的文件排进后台队列,调用方(Worker::enrich)从不等待。
// 扫描在 bulwark_yarac.exe --serve 子进程里做:它崩溃、卡死或被畸形文件拖垮都只影响自己,
// 这边按时限结束它,把那个文件记成「没扫成」(规则换代前不再重试),再起一个接着扫后面的。
//
// 判级:命中 YaraRules.MaliciousRules 里的规则判恶意,其余命中一律判可疑。
// 换规则时缓存整体作废。
class YaraScanner {
public:
    enum class Level { Clean = 0, Suspicious = 1, Malicious = 2 };

    struct Verdict {
        bool scanned = false;   // false:没扫成(过大 / 打不开 / 超时 / 辅助进程崩溃),见 error
        Level level = Level::Clean;
        QString rule;           // 代表规则:恶意优先,其次第一条命中
        QString author;
        QString description;
        int matchCount = 0;
        QStringList rules;
        QString error;
    };

    // 等结果的进程。creationFileTime 用来在结果回来时认出「还是不是同一个进程」。
    struct Target {
        QString sha256;         // 小写
        QString path;
        int pid = 0;
        quint64 creationFileTime = 0;
        QString commandLine;
        int parentPid = 0;
        QString parentPath;
    };

    // 判为恶意时在扫描线程上回调。targets 是扫描期间以这个哈希启动、仍在等结果的进程。
    using MaliciousCallback =
        std::function<void(const QString& sha256, const Verdict& verdict, const QVector<Target>& targets)>;
    // 状态值得推给界面时(命中、辅助进程起停、换规则)在扫描线程上回调。
    using ChangedCallback = std::function<void()>;

    YaraScanner(const YaraRulesOptions& opt, const QString& helperPath);
    ~YaraScanner();
    YaraScanner(const YaraScanner&) = delete;
    YaraScanner& operator=(const YaraScanner&) = delete;

    void setMaliciousCallback(MaliciousCallback cb);
    void setChangedCallback(ChangedCallback cb);
    // 换规则(任意线程)。path 为空表示暂无可用规则。
    void setRules(const QString& path, const QString& label);
    void start();
    void stop();

    std::optional<Verdict> lookup(const QString& sha256) const;
    void submit(const Target& t);
    bulwark::ipc::YaraScanStatusPayload status() const;

private:
    using Clock = std::chrono::steady_clock;

    void loop();
    bool ensureHelper(quint64 generation, const QString& rulesPath);
    void finishScan(const QString& hash, const QString& path, quint64 generation, const QByteArray& reply,
                    const QString& failure);
    Verdict classify(const QJsonObject& reply) const;
    void setState(const QString& state, const QString& detail);
    void noteCrash();
    void notifyChanged();

    YaraRulesOptions opt_;
    QString helperPath_;
    QSet<QString> maliciousExact_;
    QStringList maliciousPrefixes_;
    QSet<QString> ignoredExact_;
    QStringList ignoredPrefixes_;

    mutable std::mutex mx_;
    std::condition_variable cv_;
    QString rulesPath_;
    QString rulesLabel_;
    quint64 generation_ = 0;
    QHash<QString, Verdict> cache_;
    std::deque<QString> cacheOrder_;
    QHash<QString, QVector<Target>> pending_;
    std::deque<QString> queue_;
    Clock::time_point pausedUntil_{};
    std::deque<Clock::time_point> crashes_;
    bulwark::ipc::YaraScanStatusPayload stats_;
    MaliciousCallback onMalicious_;
    ChangedCallback onChanged_;

    std::atomic<bool> running_{false};
    std::thread worker_;

    // 只在扫描线程上用。
    yarahelper::LineChannel helper_;
    quint64 helperGeneration_ = 0;
    quint64 nextRequestId_ = 1;
    Clock::time_point lastActivity_{};

    Logger log_{QStringLiteral("bulwark.service.YaraScan")};
};

}
