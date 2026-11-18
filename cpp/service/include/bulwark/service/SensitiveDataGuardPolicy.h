#pragma once

#include <QRegularExpression>
#include <QString>
#include <QStringList>

namespace bulwark::service::sensitive_data_guard {

// 内核窃密防护(ReadGuard)条目 "数据片段|读者;读者",格式与匹配语义见驱动 Protocol.h。
//   data    敏感数据路径片段,去盘符,出现在目标路径任意位置即命中。
//   readers 指定读者,从「安装根」(\Program Files[ (x86)] 或某用户 \AppData\Local、\AppData\Roaming)
//           之后比,以 '\' 结尾按目录前缀、否则按整段相等。
// 读者要卡在程序目录而不是整个厂商目录:数据目录和程序目录同在一个厂商目录下时(Vivaldi、按用户安装的
// Chromium 内核浏览器),读者写成厂商目录就等于允许数据目录里的任何程序读。tdata 就在程序目录里的
// Telegram 只能写精确 exe。
struct Builtin {
    const char* data;
    const char* readers;
};

inline constexpr Builtin kBuiltins[] = {
    // 浏览器:登录库、Cookie、保存的密码、扩展钱包
    { "\\Google\\Chrome\\User Data\\",               "\\Google\\Chrome\\Application\\;\\Google\\Update\\" },
    { "\\Microsoft\\Edge\\User Data\\",              "\\Microsoft\\Edge\\Application\\;\\Microsoft\\EdgeUpdate\\" },
    { "\\BraveSoftware\\Brave-Browser\\User Data\\", "\\BraveSoftware\\Brave-Browser\\Application\\;\\BraveSoftware\\Update\\" },
    { "\\Vivaldi\\User Data\\",                      "\\Vivaldi\\Application\\" },
    { "\\Opera Software\\Opera Stable\\",            "\\Programs\\Opera\\;\\Opera\\" },
    { "\\Opera Software\\Opera GX Stable\\",         "\\Programs\\Opera GX\\;\\Opera GX\\" },
    { "\\Yandex\\YandexBrowser\\User Data\\",        "\\Yandex\\YandexBrowser\\Application\\" },
    { "\\360se6\\User Data\\",                       "\\360\\360se6\\Application\\;\\360se6\\Application\\" },
    { "\\360Chrome\\Chrome\\User Data\\",            "\\360Chrome\\Chrome\\Application\\" },
    { "\\Tencent\\QQBrowser\\User Data\\",           "\\Tencent\\QQBrowser\\" },
    // 开发者版、Nightly 与正式版共用 Firefox\Profiles;Betterbird 共用 Thunderbird\Profiles。
    { "\\Mozilla\\Firefox\\Profiles\\",              "\\Mozilla Firefox\\;\\Firefox Developer Edition\\;\\Firefox Nightly\\" },
    // 邮件与即时通讯会话
    { "\\Thunderbird\\Profiles\\",                   "\\Mozilla Thunderbird\\;\\Betterbird\\" },
    { "\\Telegram Desktop\\tdata\\",                 "\\Telegram Desktop\\Telegram.exe" },
    // 加密货币钱包
    { "\\Exodus\\exodus.wallet\\",                   "\\exodus\\" },
    { "\\Electrum\\wallets\\",                       "\\Electrum\\" },
    { "\\Bitcoin\\wallets\\",                        "\\Bitcoin\\" },
    { "\\Bitcoin\\wallet.dat",                       "\\Bitcoin\\" },
    // Developer/cloud credentials. '$' anchors the filename, excluding public keys.
    { "\\.ssh\\identity$", "\\Git\\usr\\bin\\ssh.exe;\\OpenSSH\\ssh.exe" },
    { "\\GitHub CLI\\hosts.yml$", "\\GitHub CLI\\gh.exe" },
    { "\\.ssh\\id_rsa$", "\\Git\\usr\\bin\\ssh.exe;\\OpenSSH\\ssh.exe" },
    { "\\.ssh\\id_ed25519$", "\\Git\\usr\\bin\\ssh.exe;\\OpenSSH\\ssh.exe" },
    { "\\.ssh\\id_ecdsa$", "\\Git\\usr\\bin\\ssh.exe;\\OpenSSH\\ssh.exe" },
    { "\\.ssh\\id_dsa$", "\\Git\\usr\\bin\\ssh.exe;\\OpenSSH\\ssh.exe" },
    { "\\.aws\\credentials$", "\\Amazon\\AWSCLIV2\\aws.exe" },
    { "\\.azure\\accessTokens.json$", "\\Microsoft SDKs\\Azure\\CLI2\\python.exe" },
    { "\\.azure\\msal_token_cache.json$", "\\Microsoft SDKs\\Azure\\CLI2\\python.exe" },
    { "\\.azure\\msal_token_cache.bin$", "\\Microsoft SDKs\\Azure\\CLI2\\python.exe" },
    { "\\gcloud\\application_default_credentials.json$", "\\Google\\Cloud SDK\\google-cloud-sdk\\" },
    { "\\gcloud\\credentials.db$", "\\Google\\Cloud SDK\\google-cloud-sdk\\" },
    { "\\.kube\\config$", "\\Kubernetes\\kubectl.exe" },
    { "\\.docker\\config.json$", "\\Docker\\Docker\\resources\\bin\\docker.exe" },
    { "\\.npmrc$", "\\nodejs\\node.exe" },
    { "\\.pypirc$", "" },
    { "\\.git-credentials$", "\\Git\\mingw64\\bin\\git.exe;\\Git\\mingw64\\libexec\\git-core\\" },
    { "\\gh\\hosts.yml$", "\\GitHub CLI\\gh.exe" },
    // FTP 站点凭据
    { "\\FileZilla\\sitemanager.xml",                "\\FileZilla FTP Client\\" },
    { "\\FileZilla\\recentservers.xml",              "\\FileZilla FTP Client\\" },
};

inline QString driveLess(QString s)
{
    s = s.trimmed();
    s.replace(QLatin1Char('/'), QLatin1Char('\\'));
    if (s.size() >= 2 && s.at(1) == QLatin1Char(':'))
        s = s.mid(2);
    if (!s.isEmpty() && !s.startsWith(QLatin1Char('\\')))
        s.prepend(QLatin1Char('\\'));
    return s;
}

// 读者若写成完整路径(C:\Program Files\X\、C:\Users\me\AppData\Local\X\),换算成「安装根之后」的形式。
inline QString readerFragment(const QString& raw)
{
    static const QRegularExpression kInstallRoot(
        QStringLiteral(R"(^\\(?:Program Files(?: \(x86\))?|Users\\[^\\]+\\AppData\\(?:Local|Roaming))(?=\\))"),
        QRegularExpression::CaseInsensitiveOption);
    QString s = driveLess(raw);
    s.remove(kInstallRoot);
    return s == QStringLiteral("\\") ? QString() : s;
}

// 驱动对短于 4 个字符的数据片段直接拒收(那样几乎所有路径都算敏感数据),这里先滤掉。
inline QString makeEntry(const QString& data, const QString& readers)
{
    const QString d = driveLess(data);
    if (d.size() < 4 || d.contains(QLatin1Char('|')) || d.contains(QLatin1Char(';')))
        return {};
    QStringList rs;
    for (const QString& r : readers.split(QLatin1Char(';'), Qt::SkipEmptyParts)) {
        const QString n = readerFragment(r);
        if (!n.isEmpty() && !rs.contains(n, Qt::CaseInsensitive))
            rs << n;
    }
    return rs.isEmpty() ? d : d + QLatin1Char('|') + rs.join(QLatin1Char(';'));
}

// 自定义条目写法同内核格式 "数据片段|读者;读者",读者可省略。
inline QStringList composeEntries(bool builtins, const QStringList& extra)
{
    QStringList out;
    const auto add = [&out](const QString& entry) {
        if (!entry.isEmpty() && !out.contains(entry, Qt::CaseInsensitive))
            out << entry;
    };
    if (builtins)
        for (const Builtin& b : kBuiltins)
            add(makeEntry(QString::fromLatin1(b.data), QString::fromLatin1(b.readers)));
    for (const QString& e : extra) {
        const int bar = e.indexOf(QLatin1Char('|'));
        add(makeEntry(bar < 0 ? e : e.left(bar), bar < 0 ? QString() : e.mid(bar + 1)));
    }
    return out;
}

}
