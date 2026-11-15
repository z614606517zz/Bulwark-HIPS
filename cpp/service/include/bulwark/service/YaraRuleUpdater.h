#pragma once

#include "bulwark/ipc/Payloads.h"
#include "bulwark/service/BulwarkOptions.h"
#include "bulwark/service/Logger.h"

#include <QDateTime>
#include <QString>

#include <atomic>
#include <condition_variable>
#include <functional>
#include <mutex>
#include <thread>

namespace bulwark::service {

namespace yara {
struct ReleaseAsset;
struct CompileReport;
}

// YARA Forge 规则包的自动下载与编译。
//
// 后台线程按周期查 GitHub 上的最新发布,有新版就限量下载、按发布页给出的 SHA-256 校验,
// 再交给 bulwark_yarac.exe(独立子进程,放进限内存 / 限进程数的 Job)解压编译;
// 编译结果条数可信才替换,旧规则留一份 .prev。任何一步失败都沿用现有规则。
// 换上新规则后经 setRulesInstalled 通知扫描端(YaraScanner)重新载入。
class YaraRuleUpdater {
public:
    using StatusCallback = std::function<void(const bulwark::ipc::YaraRulesStatusPayload&)>;
    // path:新规则文件;label:给界面看的版本说明。在更新线程上回调。
    using RulesCallback = std::function<void(const QString& path, const QString& label)>;

    YaraRuleUpdater(const YaraRulesOptions& opt, const QString& dataDir, const QString& compilerPath);
    ~YaraRuleUpdater();
    YaraRuleUpdater(const YaraRuleUpdater&) = delete;
    YaraRuleUpdater& operator=(const YaraRuleUpdater&) = delete;

    // 状态每次变化时在主线程回调一次。
    void setStatusChanged(StatusCallback cb);
    void setRulesInstalled(RulesCallback cb);
    void start();
    void stop();

    bulwark::ipc::YaraRulesStatusPayload status() const;
    bulwark::ipc::YaraRulesActionResultPayload handleAction(
        const bulwark::ipc::YaraRulesActionRequestPayload& req);

private:
    void loop();
    void runOnce();
    bool download(const yara::ReleaseAsset& asset, const QString& zipPath, QString* sha256,
                  QString* error);
    bool compile(const QString& zipPath, const QString& outPath, const QString& reportPath,
                 yara::CompileReport* report, QString* error);
    bool install(const QString& stagedPath, QString* error);

    void setStage(const QString& stage, const QString& detail = QString());
    void finish(bool failed, const QString& message);
    void publish();
    void loadState();
    void saveStateLocked() const;
    void refreshNextCheckLocked();
    // 辅助程序是后放进安装目录的:记下它已就位,返回是否刚刚发现。
    bool noticeCompilerLocked();

    QString rulesPath() const;

    YaraRulesOptions opt_;
    QString dataDir_;
    QString compilerPath_;

    mutable std::mutex mx_;
    std::condition_variable cv_;
    bulwark::ipc::YaraRulesStatusPayload state_;
    bool autoUpdateUserSet_ = false;
    bool updateRequested_ = false;
    // 不按上次失败的退避等:上次只是因为辅助程序不在才失败,而它已经就位。下一次检查开始时清掉。
    bool checkSoon_ = false;
    QDateTime notBeforeUtc_;
    StatusCallback onStatus_;
    RulesCallback onRulesInstalled_;

    std::atomic<bool> running_{false};
    void* stopEvent_ = nullptr;
    std::thread worker_;
    Logger log_{QStringLiteral("bulwark.service.Yara")};
};

}
