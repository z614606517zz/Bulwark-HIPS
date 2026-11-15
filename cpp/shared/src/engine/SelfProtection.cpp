#include "bulwark/engine/SelfProtection.h"
#include <QRegularExpression>

namespace bulwark::engine {

namespace {

QString flatten(const QString& commandLine) {
    QString s = commandLine.toLower();
    s.replace(QLatin1Char('"'), QLatin1Char(' '));
    s.replace(QLatin1Char('\''), QLatin1Char(' '));
    s.replace(QLatin1Char('`'), QLatin1Char(' '));
    s = s.simplified();
    static const QRegularExpression exeTail(QStringLiteral("\\.exe(?=\\s|$)"));
    s.remove(exeTail);
    return s;
}

}

bool SelfProtection::commandTargetsProduct(const QString& commandLine) {
    if (commandLine.isEmpty()) return false;
    if (!commandLine.contains(QLatin1String("bulwark"), Qt::CaseInsensitive)) return false;
    const QString s = flatten(commandLine);

    static const QString kB = QStringLiteral("(?:^|[\\s\\\\/;&|(])");

    static const QRegularExpression kKill(
        kB + QStringLiteral("(?:taskkill|stop-process|spps|stop-service|spsv|remove-service)(?=\\s|$)"));
    static const QRegularExpression kSc(
        kB + QStringLiteral("sc(?: \\\\\\\\\\S+)? (stop|delete|config)(?=\\s|$)"));
    static const QRegularExpression kNetStop(kB + QStringLiteral("net1? stop(?=\\s|$)"));
    static const QRegularExpression kFltUnload(kB + QStringLiteral("fltmc unload(?=\\s|$)"));
    static const QRegularExpression kSetService(kB + QStringLiteral("set-service(?=\\s|$)"));
    static const QRegularExpression kDisabled(QStringLiteral("(?:^|[\\s=])disabled(?=\\s|$)"));
    static const QRegularExpression kWmic(kB + QStringLiteral("wmic(?=\\s)"));
    static const QRegularExpression kWmicAct(
        QStringLiteral("(?:^|\\s)(?:call terminate|call stopservice|delete)(?=\\s|$)"));

    bool verb = kKill.match(s).hasMatch() || kNetStop.match(s).hasMatch() || kFltUnload.match(s).hasMatch();
    if (!verb) {
        const QRegularExpressionMatch m = kSc.match(s);
        if (m.hasMatch()) {
            verb = m.captured(1) != QLatin1String("config") || kDisabled.match(s).hasMatch();
        }
    }
    if (!verb && kSetService.match(s).hasMatch() && kDisabled.match(s).hasMatch()) verb = true;
    if (!verb && kWmic.match(s).hasMatch() && kWmicAct.match(s).hasMatch()) verb = true;
    if (!verb) return false;

    if (s.contains(QLatin1String("bulwark_service")) || s.contains(QLatin1String("bulwark_ui"))
        || s.contains(QLatin1String("bulwarkservice")))
        return true;

    static const QRegularExpression kDriverName(
        kB + QStringLiteral("(?:stop|delete|config|unload|stop-service|remove-service|stop-process|spps|spsv|taskkill)"
                            "(?:\\s+[-/]\\w+)*\\s+bulwark(?=\\s|$)"));
    if (kDriverName.match(s).hasMatch()) return true;

    static const QRegularExpression kWildcard(QStringLiteral("(?:^|[\\s\\\\/-])bulwark[_a-z]*\\*"));
    return kWildcard.match(s).hasMatch();
}

}
