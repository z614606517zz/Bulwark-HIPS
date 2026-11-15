#pragma once
#include <QString>
#include <QStringList>

namespace bulwark::engine {

struct ScoreResult {
    int score = 0;
    QStringList reasons;
    bool hardSignal = false;
};

namespace detail {

inline QString u(const char* s) { return QString::fromUtf8(s); }
inline QString u(const QString& s) { return s; }

inline QString fileNameLower(const QString& path) {
    if (path.isEmpty()) return QString();
    QString p = path;
    p.replace(QLatin1Char('/'), QLatin1Char('\\'));
    while (p.size() > 1 && p.endsWith(QLatin1Char('\\'))) p.chop(1);
    const int slash = p.lastIndexOf(QLatin1Char('\\'));
    const QString name = (slash >= 0) ? p.mid(slash + 1) : p;
    return name.toLower();
}

inline bool isContentInspectionProcess(const QString& path, bool trustedIdentity) {
    // 名字本身绝不是白名单：未签名样本改名为 rg.exe 的成本为零。只有取证层已确认主体
    // 签名健康时，才把这些参数解释为“待检查内容”。用户显式信任仍由更早的信任通道处理。
    if (!trustedIdentity)
        return false;
    const QString n = fileNameLower(path);
    return n == QLatin1String("rg.exe") || n == QLatin1String("ripgrep.exe")
        || n == QLatin1String("grep.exe") || n == QLatin1String("findstr.exe")
        || n == QLatin1String("code.exe") || n == QLatin1String("kiro.exe")
        || n == QLatin1String("trae cn.exe") || n == QLatin1String("devenv.exe")
        || n == QLatin1String("notepad++.exe");
}

// Chromium 系浏览器在 Windows 上经 cmd.exe /d /c 启动扩展的原生消息宿主,并把标准输入输出
// 重定向到 \\.\pipe\chrome.nativeMessaging.* 管道(密码管理器、企业 SSO 扩展都走这条)。
// 夹带串接、管道符、变量展开或多余重定向时不认,防止借这个形态伪装。
inline bool isBrowserNativeMessagingLaunch(const QString& actorPath, const QString& parentPath,
                                           const QString& commandLine) {
    if (fileNameLower(actorPath) != QLatin1String("cmd.exe"))
        return false;
    static const QStringList kChromiumBrowsers = {
        QStringLiteral("chrome.exe"),  QStringLiteral("msedge.exe"), QStringLiteral("brave.exe"),
        QStringLiteral("vivaldi.exe"), QStringLiteral("opera.exe"),  QStringLiteral("chromium.exe"),
    };
    if (!kChromiumBrowsers.contains(fileNameLower(parentPath)))
        return false;
    const QString c = commandLine.toLower();
    if (!c.contains(QLatin1String("chrome-extension://"))
        || !c.contains(QLatin1String("\\\\.\\pipe\\chrome.nativemessaging.")))
        return false;
    if (c.count(QLatin1Char('<')) != 1 || c.count(QLatin1Char('>')) != 1)
        return false;
    static const QString kChaining = QStringLiteral("&|^%`");
    for (const QChar ch : kChaining)
        if (c.contains(ch))
            return false;
    return true;
}

}
}
