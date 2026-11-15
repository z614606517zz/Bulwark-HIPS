#pragma once
#include <QString>
#include <QStringList>
#include <QVector>

namespace bulwark::engine {

struct CommandLineAnalyzer {
    struct Hit {
        const char* id = "";
        QString source;
        int score = 0;
        bool hard = false;
        QString reason;
        QString token;   // 第一组里实际命中的词,用于在正文里定位代码段
    };

    // text 必须已转小写。actorName 为主体映像名(小写),用于只对特定程序成立的信号。
    static QVector<Hit> scan(const QString& lowerText, const QString& actorName);

    // 脚本正文:只对特定程序成立的信号,以正文里提到该程序为前提。
    static QVector<Hit> scanScript(const QString& lowerText);

    // 混淆写法本身只是弱信号:7-Zip、Inno 的正常命令行也会用到引号和转义。
    static int obfuscationScore(const QString& rawText, QStringList* reasons);

    static bool isScriptHost(const QString& actorName);

    // 以下判定的参数都必须已转小写。
    // -WindowStyle Hidden 及其任意缩写;Get-ChildItem 的 -Hidden 开关不算。
    static bool hasHiddenWindowFlag(const QString& lowerText);
    // -EncodedCommand 及其缩写,且后面跟的是 Base64 载荷;Out-File -Enc utf8 这类编码名不算。
    static bool hasEncodedCommandArgument(const QString& lowerText);
    static bool hasIpLiteralUrl(const QString& lowerText);
    static bool fetchesRemote(const QString& lowerText);
    // net user <名字以 $ 结尾> ... /add:在账户列表里隐身的后门账户。
    static bool createsHiddenAccount(const QString& lowerText);
};

}
