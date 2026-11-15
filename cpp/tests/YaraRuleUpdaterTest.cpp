// YARA 规则更新的排期。辅助程序 bulwark_yarac.exe 晚于一次失败的检查才放进安装目录时,
// 不该再按失败退避等满两小时;其他失败照常退避,不会因此反复去请求 GitHub。
// 只测载入状态、排期与「立即更新」的受理,不启动后台线程,不联网,不起辅助程序。

#include "bulwark/service/YaraRuleUpdater.h"

#include <QCoreApplication>
#include <QDir>
#include <QFile>
#include <QJsonDocument>
#include <QJsonObject>
#include <QTemporaryDir>

#include <cstdio>

using bulwark::ipc::YaraRulesActionRequestPayload;
using bulwark::ipc::YaraRulesStatusPayload;
using bulwark::service::YaraRuleUpdater;
using bulwark::service::YaraRulesOptions;

namespace {

int g_failed = 0;

void check(bool ok, const char* what)
{
    std::printf("%s %s\n", ok ? "ok  " : "FAIL", what);
    if (!ok)
        ++g_failed;
}

QString noCompilerMessage() { return QString::fromUtf8("辅助程序 bulwark_yarac.exe 不在安装目录,没有下载。"); }

void writeState(const QString& dir, const QString& message, const QDateTime& lastCheck)
{
    YaraRulesStatusPayload s;
    s.featureEnabled = true;
    s.autoUpdate = true;
    s.package = QStringLiteral("core");
    s.lastCheckUtc = lastCheck;
    s.lastCheckFailed = true;
    s.message = message;
    QJsonObject root;
    root[QStringLiteral("status")] = s.toJson();
    QFile f(QDir(dir).filePath(QStringLiteral("state.json")));
    if (f.open(QIODevice::WriteOnly | QIODevice::Truncate))
        f.write(QJsonDocument(root).toJson());
}

void touch(const QString& path)
{
    QFile f(path);
    if (f.open(QIODevice::WriteOnly | QIODevice::Truncate))
        f.write("MZ");
}

bool near(const QDateTime& a, const QDateTime& b) { return a.isValid() && b.isValid() && qAbs(a.secsTo(b)) <= 2; }

}

int main(int argc, char** argv)
{
    QCoreApplication app(argc, argv);
    YaraRulesOptions opt;
    const QDateTime lastCheck = QDateTime::currentDateTimeUtc().addSecs(-600);
    const QDateTime backoffEnd = lastCheck.addSecs(2 * 3600);

    // 上次只是因为辅助程序不在才失败,现在它在了:不再标记失败,马上可以检查。
    {
        QTemporaryDir data, bin;
        const QString helper = QDir(bin.path()).filePath(QStringLiteral("bulwark_yarac.exe"));
        touch(helper);
        writeState(data.path(), noCompilerMessage(), lastCheck);
        YaraRuleUpdater up(opt, data.path(), helper);
        const YaraRulesStatusPayload s = up.status();
        check(s.compilerAvailable, "helper arrived: compilerAvailable");
        check(!s.lastCheckFailed && s.message != noCompilerMessage(), "helper arrived: failure forgiven");
        check(s.nextCheckUtc.isValid() && s.nextCheckUtc <= QDateTime::currentDateTimeUtc().addSecs(2),
              "helper arrived: next check is due now, not after the 2h backoff");
    }

    // 辅助程序仍然不在:照常退避两小时。
    {
        QTemporaryDir data, bin;
        writeState(data.path(), noCompilerMessage(), lastCheck);
        YaraRuleUpdater up(opt, data.path(), QDir(bin.path()).filePath(QStringLiteral("bulwark_yarac.exe")));
        const YaraRulesStatusPayload s = up.status();
        check(!s.compilerAvailable, "helper still missing: compilerAvailable=false");
        check(s.lastCheckFailed && s.message == noCompilerMessage(), "helper still missing: failure kept");
        check(near(s.nextCheckUtc, backoffEnd), "helper still missing: next check after the 2h backoff");
    }

    // 别的原因失败(网络):辅助程序在也照常退避。
    {
        QTemporaryDir data, bin;
        const QString helper = QDir(bin.path()).filePath(QStringLiteral("bulwark_yarac.exe"));
        touch(helper);
        const QString network = QString::fromUtf8("查询 YARA Forge 最新发布失败:连接超时。");
        writeState(data.path(), network, lastCheck);
        YaraRuleUpdater up(opt, data.path(), helper);
        const YaraRulesStatusPayload s = up.status();
        check(s.lastCheckFailed && s.message == network, "network failure: failure kept");
        check(near(s.nextCheckUtc, backoffEnd), "network failure: next check after the 2h backoff");
    }

    // 服务运行中辅助程序才放进来:「立即更新」先重新核对,不再回「辅助程序不在」。
    {
        QTemporaryDir data, bin;
        const QString helper = QDir(bin.path()).filePath(QStringLiteral("bulwark_yarac.exe"));
        writeState(data.path(), noCompilerMessage(), lastCheck);
        YaraRuleUpdater up(opt, data.path(), helper);
        check(!up.status().compilerAvailable, "late helper: missing at load");
        touch(helper);
        YaraRulesActionRequestPayload req;
        req.action = QStringLiteral("update");
        const auto res = up.handleAction(req);
        check(up.status().compilerAvailable, "late helper: update re-checks the helper");
        check(!res.message.contains(QString::fromUtf8("不在安装目录")), "late helper: update not refused as missing");
        check(!up.status().lastCheckFailed, "late helper: failure forgiven");
    }

    if (g_failed == 0)
        std::printf("all passed\n");
    else
        std::printf("%d failed\n", g_failed);
    return g_failed == 0 ? 0 : 1;
}
