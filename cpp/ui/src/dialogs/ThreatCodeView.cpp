#include "dialogs/ThreatCodeView.h"
#include "design/Components.h"
#include "widgets/CodeBlock.h"
#include "widgets/WrapLabel.h"

#include <QDir>
#include <QHBoxLayout>
#include <QRegularExpression>
#include <QSet>
#include <QVBoxLayout>

namespace {

QString u(const char* s) { return QString::fromUtf8(s); }

bool commandLineMatters(const bulwark::SecurityEvent& e)
{
    if (e.type == bulwark::EventType::ProcessCreate)
        return true;
    static const QSet<QString> kCommandLineSources = {
        QStringLiteral("CommandObfuscationAnalyzer"), QStringLiteral("ScriptAnalyzer"),
        QStringLiteral("ScriptFileAnalyzer"),         QStringLiteral("LolbinAnalyzer"),
        QStringLiteral("CredentialAccessAnalyzer"),   QStringLiteral("DefenseEvasionAnalyzer"),
        QStringLiteral("PersistenceAnalyzer"),        QStringLiteral("RemoteControlAnalyzer"),
    };
    for (const bulwark::Evidence& ev : e.evidenceChain)
        if (kCommandLineSources.contains(ev.source))
            return true;
    return false;
}

bool hasArguments(const QString& commandLine, const QString& actorPath)
{
    const QString cmd = commandLine.trimmed();
    if (cmd.isEmpty())
        return false;
    const bool quoted = cmd.startsWith(QLatin1Char('"'));
    const QString body = quoted ? cmd.mid(1) : cmd;

    const QString ap = QDir::fromNativeSeparators(actorPath.trimmed()).toLower();
    if (!ap.isEmpty() && QDir::fromNativeSeparators(body).toLower().startsWith(ap)) {
        QString rest = body.mid(ap.size());
        if (quoted && rest.startsWith(QLatin1Char('"')))
            rest = rest.mid(1);
        return !rest.trimmed().isEmpty();
    }
    qsizetype end;
    if (quoted) {
        end = cmd.indexOf(QLatin1Char('"'), 1);
        if (end < 0)
            return false;
        ++end;
    } else {
        static const QRegularExpression ws(QStringLiteral("\\s"));
        end = cmd.indexOf(ws);
        if (end < 0)
            return false;
    }
    return !cmd.mid(end).trimmed().isEmpty();
}

QString headerOf(const bulwark::ThreatSnippet& s, bool fromCommandLine)
{
    QString t = fromCommandLine ? s.title : u("命中代码 · ") + s.title;
    int lo = 0, hi = 0;
    for (const bulwark::SnippetLine& l : s.lines) {
        if (l.number <= 0)
            continue;
        lo = lo == 0 ? l.number : qMin(lo, l.number);
        hi = qMax(hi, l.number);
    }
    if (lo > 0)
        t += lo == hi ? u(" · 第 %1 行").arg(lo) : u(" · 第 %1–%2 行").arg(lo).arg(hi);
    if (s.wrap && s.totalChars > 0)
        t += u(" · 共 %1 字符").arg(s.totalChars);
    if (s.truncated)
        t += u(" · 已截取");
    return t;
}

}

namespace threatcode {

QVector<bulwark::ThreatSnippet> snippetsFor(const bulwark::SecurityEvent& e, bool commandLineFallback)
{
    QVector<bulwark::ThreatSnippet> out;
    for (const bulwark::ThreatSnippet& s : e.threatSnippets)
        if (!s.isEmpty())
            out.push_back(s);
    if (!out.isEmpty() || !commandLineFallback)
        return out;

    if (!commandLineMatters(e) || !hasArguments(e.commandLine, e.actorPath))
        return out;
    const bulwark::ThreatSnippet s = bulwark::snippet::fromText(u("命令行"), e.commandLine);
    if (!s.isEmpty())
        out.push_back(s);
    return out;
}

QWidget* build(const bulwark::SecurityEvent& e, const QColor& accent, const Options& opt)
{
    const QVector<bulwark::ThreatSnippet> all = snippetsFor(e, opt.commandLineFallback);
    if (all.isEmpty())
        return nullptr;
    const bool fromCommandLine = e.threatSnippets.isEmpty();

    auto* box = new HeightForWidthBox;
    auto* v = new QVBoxLayout(box);
    v->setContentsMargins(0, 0, 0, 0);
    v->setSpacing(6);

    const int shown = qMin<int>(all.size(), qMax(1, opt.maxSnippets));
    for (int i = 0; i < shown; ++i) {
        const bulwark::ThreatSnippet& s = all.at(i);

        auto* head = new QWidget;
        auto* h = new QHBoxLayout(head);
        h->setContentsMargins(0, 0, 0, 0);
        h->setSpacing(6);
        h->addWidget(ui::elided(headerOf(s, fromCommandLine), "caption"), 1, Qt::AlignVCenter);
        const QString copyText = fromCommandLine ? bulwark::snippet::sanitize(e.commandLine)
                                                 : s.plainText();
        h->addWidget(ui::copyButton([copyText] { return copyText; }, u("复制代码")), 0, Qt::AlignVCenter);
        v->addWidget(head);

        v->addWidget(new CodeBlock(s, accent, opt.maxRows));
    }

    if (all.size() > shown) {
        const QString hint = opt.moreHint.isEmpty()
            ? u("另有 %1 段命中代码,见拦截记录详情").arg(all.size() - shown)
            : opt.moreHint.arg(all.size() - shown);
        auto* more = new WrapLabel(hint);
        more->setProperty("role", "muted");
        v->addWidget(more);
    }
    return box;
}

}
