#include "bulwark/engine/ScriptAnalyzer.h"
#include "bulwark/engine/CommandLineAnalyzer.h"
#include "bulwark/engine/EngineCommon.h"
#include <QFileInfo>
#include <QRegularExpression>

namespace bulwark::engine {

using detail::u;

namespace {

QStringList splitCommandLine(const QString& cmd) {
    QStringList out;
    QString cur;
    bool quoted = false;
    for (const QChar c : cmd) {
        if (c == QLatin1Char('"')) {
            quoted = !quoted;
            continue;
        }
        if (c.isSpace() && !quoted) {
            if (!cur.isEmpty()) {
                out << cur;
                cur.clear();
            }
            continue;
        }
        cur += c;
    }
    if (!cur.isEmpty())
        out << cur;
    return out;
}

bool hasScriptExtension(const QString& token) {
    static const QStringList exts = {
        QStringLiteral(".ps1"), QStringLiteral(".psm1"), QStringLiteral(".vbs"), QStringLiteral(".vbe"),
        QStringLiteral(".js"), QStringLiteral(".jse"), QStringLiteral(".wsf"), QStringLiteral(".wsh"),
        QStringLiteral(".bat"), QStringLiteral(".cmd"), QStringLiteral(".hta"),
    };
    for (const QString& x : exts)
        if (token.endsWith(x, Qt::CaseInsensitive))
            return true;
    return false;
}

int lineIndexOf(const QString& content, qsizetype pos) {
    return static_cast<int>(content.left(pos).count(QLatin1Char('\n')));
}

ThreatSnippet snippetAround(const QString& content, qsizetype pos, qsizetype length, const QString& title) {
    ThreatSnippet sn;
    sn.title = title.left(ThreatSnippet::kMaxTitleChars);
    const QStringList lines = content.split(QLatin1Char('\n'));
    const int hitLine = lineIndexOf(content, pos);
    const int first = qMax(0, hitLine - 2);
    const int last = qMin(static_cast<int>(lines.size()) - 1, first + ThreatSnippet::kMaxLines - 1);
    const qsizetype hitLineStart = content.lastIndexOf(QLatin1Char('\n'), pos > 0 ? pos - 1 : 0) + 1;
    for (int i = first; i <= last; ++i) {
        const bool isHit = (i == hitLine);
        bool cut = false;
        sn.lines.append(snippet::makeLine(i + 1, lines.at(i), isHit, isHit ? pos - hitLineStart : -1,
                                          isHit ? length : 0, ThreatSnippet::kMaxLineChars, &cut));
        sn.truncated = sn.truncated || cut;
    }
    sn.truncated = sn.truncated || first > 0 || last + 1 < lines.size();
    sn.totalChars = static_cast<int>(content.size());
    return sn;
}

}

ScriptType ScriptAnalyzer::scriptTypeFromPath(const QString& path) {
    const QString suffix = QFileInfo(path).suffix().toLower();
    if (suffix == QLatin1String("ps1") || suffix == QLatin1String("psm1")) return ScriptType::PowerShell;
    if (suffix == QLatin1String("vbs") || suffix == QLatin1String("vbe")) return ScriptType::Vbscript;
    if (suffix == QLatin1String("js") || suffix == QLatin1String("jse")) return ScriptType::Javascript;
    if (suffix == QLatin1String("wsf") || suffix == QLatin1String("wsh")) return ScriptType::Vbscript;
    if (suffix == QLatin1String("bat") || suffix == QLatin1String("cmd")) return ScriptType::Batch;
    if (suffix == QLatin1String("hta")) return ScriptType::Hta;
    return ScriptType::Unknown;
}

ScriptType ScriptAnalyzer::scriptTypeForHost(const QString& hostImageName) {
    const QString n = hostImageName.toLower();
    if (n.contains(QLatin1String("powershell")) || n.contains(QLatin1String("pwsh"))) return ScriptType::PowerShell;
    if (n.contains(QLatin1String("vbscript"))) return ScriptType::Vbscript;
    if (n.contains(QLatin1String("jscript")) || n.contains(QLatin1String("javascript"))) return ScriptType::Javascript;
    return ScriptType::Unknown;
}

QString ScriptAnalyzer::extractScriptFilePath(const QString& commandLine) {
    const QStringList tokens = splitCommandLine(commandLine);
    if (tokens.size() < 2)
        return QString();
    const QString host = detail::fileNameLower(tokens.first());
    for (int i = 1; i < tokens.size(); ++i) {
        const QString t = tokens.at(i);
        const QString lower = t.toLower();
        if (host.startsWith(QLatin1String("powershell")) || host.startsWith(QLatin1String("pwsh"))) {
            if ((lower == QLatin1String("-file") || lower == QLatin1String("-f")) && i + 1 < tokens.size())
                return tokens.at(i + 1);
            // -Command / -EncodedCommand 之后是内联代码,不是脚本文件。
            if (lower.startsWith(QLatin1String("-c")) || lower.startsWith(QLatin1String("-e")))
                return QString();
        }
        if (lower.startsWith(QLatin1String("http:")) || lower.startsWith(QLatin1String("https:")))
            return QString();
        if (lower.startsWith(QLatin1Char('/')) || lower.startsWith(QLatin1Char('-')))
            continue;
        if (hasScriptExtension(t))
            return t;
        // cmd /c 之后第一个参数若不是脚本,就是在跑别的程序。
        if (host == QLatin1String("cmd.exe"))
            return QString();
    }
    return QString();
}

ThreatSnippet ScriptAnalyzer::snippetForContent(const QString& content, const QString& title) {
    return snippet::fromText(title, content);
}

ScriptAnalyzer::Result ScriptAnalyzer::analyze(const QString& content, ScriptType type,
                                               const QString& snippetTitle) {
    Result r;
    if (content.trimmed().isEmpty())
        return r;
    const QString lower = content.toLower();

    QString firstHitToken;
    for (const CommandLineAnalyzer::Hit& h : CommandLineAnalyzer::scanScript(lower)) {
        r.score += h.score;
        r.hardSignal = r.hardSignal || h.hard;
        r.hits << QLatin1String(h.id);
        r.reasons << h.reason;
        if (firstHitToken.isEmpty() && h.hard)
            firstHitToken = h.token;
    }

    const auto add = [&r](const char* id, int score, bool hard, const char* reason) {
        r.score += score;
        r.hardSignal = r.hardSignal || hard;
        r.hits << QLatin1String(id);
        r.reasons << u(reason);
    };

    if (type == ScriptType::Vbscript || type == ScriptType::Javascript || type == ScriptType::Hta
        || type == ScriptType::Unknown) {
        const bool fetch = lower.contains(QLatin1String("xmlhttp")) || lower.contains(QLatin1String("winhttprequest"));
        const bool stream = lower.contains(QLatin1String("adodb.stream"));
        const bool save = lower.contains(QLatin1String("savetofile"));
        const bool run = lower.contains(QLatin1String(".run")) || lower.contains(QLatin1String("shellexecute"))
                         || lower.contains(QLatin1String(".exec("));
        if (fetch && stream && save && run)
            add("script-dropper", 60, true, "脚本下载文件、落地后运行(脚本投递器,T1105/T1059)");
        else if (fetch && run)
            add("script-fetch-run", 20, false, "脚本既联网又启动程序(T1059)");
        if (lower.count(QLatin1String("fromcharcode")) >= 10)
            add("script-charcode", 20, false, "大量 fromCharCode 拼接代码(T1027)");
        if (lower.count(QLatin1String("chr(")) >= 30)
            add("script-chr", 20, false, "大量 Chr() 拼接代码(T1027)");
        if (lower.contains(QLatin1String("eval(")) && lower.contains(QLatin1String("unescape(")))
            add("script-eval-unescape", 15, false, "解码后 eval 执行(T1027)");
    }

    static const QRegularExpression peRe(QStringLiteral("TV[qopr][A-Za-z0-9+/]{200,}"));
    if (peRe.match(content).hasMatch())
        add("embedded-pe", 40, true, "脚本内嵌 Base64 编码的可执行体(T1027.009)");

    QStringList obfReasons;
    const int obf = CommandLineAnalyzer::obfuscationScore(content.left(16 * 1024), &obfReasons);
    if (obf > 0) {
        r.score += obf;
        r.hits << QStringLiteral("obfuscation");
        r.reasons += obfReasons;
    }

    r.score = qMin(100, r.score);
    if (!r.hits.isEmpty()) {
        const qsizetype at = firstHitToken.isEmpty() ? -1 : lower.indexOf(firstHitToken);
        r.snippets << (at >= 0 ? snippetAround(content, at, firstHitToken.size(), snippetTitle)
                               : snippetForContent(content, snippetTitle));
    }
    return r;
}

}
