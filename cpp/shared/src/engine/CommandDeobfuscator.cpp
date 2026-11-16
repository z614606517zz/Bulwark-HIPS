#include "bulwark/engine/CommandDeobfuscator.h"
#include "bulwark/engine/EngineCommon.h"
#include "bulwark/models/SecurityEvent.h"
#include <QByteArray>
#include <QLatin1String>
#include <QRegularExpression>
#include <QStringConverter>

namespace bulwark::engine {
using detail::u;

namespace {

inline bool isAsciiAlnum(QChar c) {
    const ushort x = c.unicode();
    return (x >= '0' && x <= '9') || (x >= 'A' && x <= 'Z') || (x >= 'a' && x <= 'z');
}

inline bool isQuote(QChar c) { return c == u'\'' || c == u'"'; }

// cmd 的 ^ 转义:^X 就是字面 X,^^ 是一个 ^,行尾单个 ^ 被吃掉。
// 判据是「^ 紧跟任意非空白字符」:标点同样会被转义(regsvr32 /i^:http^:^/^/host/a.sct)。
// 正常命令行里的 ^ 也会被还原(findstr 的正则锚点、echo a^&b),但去掉几个 ^ 造不出规则要求的多 token 串,不构成误报面。
int caretEscapeHits(const QString& s) {
    int hits = 0;
    for (qsizetype i = 0; i + 1 < s.size(); ++i)
        if (s.at(i) == u'^' && !s.at(i + 1).isSpace())
            ++hits;
    return hits;
}

QString stripCaret(const QString& s) {
    QString out;
    out.reserve(s.size());
    for (qsizetype i = 0; i < s.size(); ++i) {
        if (s.at(i) != u'^') { out += s.at(i); continue; }
        if (i + 1 >= s.size()) break;
        out += s.at(++i);
    }
    return out;
}

// PowerShell 的 ` 转义。`n `r `t `0 是真正的换行 / 回车 / 制表 / 空字符,按空白还原;
// 其余 `X 是字面 X,那才是 i`e`x、Invoke-Expre`ssion 这类混淆。
int backtickEscapeHits(const QString& s) {
    int hits = 0;
    for (qsizetype i = 0; i + 1 < s.size(); ++i)
        if (s.at(i) == u'`' && !s.at(i + 1).isSpace())
            ++hits;
    return hits;
}

QString normalizeBacktick(const QString& s) {
    QString out;
    out.reserve(s.size());
    for (qsizetype i = 0; i < s.size(); ++i) {
        if (s.at(i) != u'`') { out += s.at(i); continue; }
        if (i + 1 >= s.size()) break;
        const QChar n = s.at(++i);
        const QChar l = n.toLower();
        if (l == u'n' || l == u'r' || l == u't' || l == u'0')
            out += QLatin1Char(' ');
        else
            out += n;
    }
    return out;
}

// [char]105 + [char]101 + [char]120 -> 'i'+'e'+'x'
// 只认可打印 ASCII(32~126),超出范围的还原出来是控制字符或非 ASCII,对模式匹配没有意义。
// 换成带引号的单字符,交给下面的 + 拼接合并。
QString substituteCharCodes(const QString& s, bool* fired) {
    static const QRegularExpression re(
        QStringLiteral("\\[char\\]\\s*(0x[0-9a-fA-F]{1,2}|\\d{1,3})"),
        QRegularExpression::CaseInsensitiveOption);

    QString out;
    qsizetype last = 0;
    int n = 0;
    auto it = re.globalMatch(s);
    while (it.hasNext() && n < 256) {
        const QRegularExpressionMatch m = it.next();
        const QString num = m.captured(1);
        bool okNum = false;
        const uint v = num.startsWith(QLatin1String("0x"), Qt::CaseInsensitive)
                           ? num.mid(2).toUInt(&okNum, 16)
                           : num.toUInt(&okNum, 10);
        if (!okNum || v < 32 || v > 126)
            continue;
        out += s.mid(last, m.capturedStart(0) - last);
        out += QLatin1Char('\'');
        out += QChar(static_cast<ushort>(v));
        out += QLatin1Char('\'');
        last = m.capturedEnd(0);
        ++n;
    }
    if (n == 0)
        return s;
    out += s.mid(last);
    *fired = true;
    return out;
}

// -f 格式化重排:('{1}{0}' -f 'ex','i') -> 'iex'
// 只处理模板里全是 {N} 占位符、实参全是引号字面量的形态;模板混了普通字符或实参是表达式就整条放弃。
QString applyFormatOperator(const QString& s, bool* fired) {
    static const QRegularExpression head(
        QStringLiteral("(['\"])((?:\\{\\d{1,2}\\})+)\\1\\s*-f\\s*"),
        QRegularExpression::CaseInsensitiveOption);

    QString cur = s;
    for (int round = 0; round < 8; ++round) {
        const QRegularExpressionMatch m = head.match(cur);
        if (!m.hasMatch())
            break;

        QStringList args;
        qsizetype p = m.capturedEnd(0);
        bool ok = true;
        while (args.size() < 16) {
            while (p < cur.size() && cur.at(p).isSpace()) ++p;
            if (p >= cur.size() || !isQuote(cur.at(p))) { ok = !args.isEmpty(); break; }
            const QChar q = cur.at(p++);
            QString lit;
            bool closed = false;
            while (p < cur.size()) {
                if (cur.at(p) == q) { closed = true; ++p; break; }
                lit += cur.at(p++);
            }
            if (!closed) { ok = false; break; }
            args << lit;
            const qsizetype save = p;
            while (p < cur.size() && cur.at(p).isSpace()) ++p;
            if (p < cur.size() && cur.at(p) == u',') { ++p; continue; }
            p = save;
            break;
        }
        if (!ok || args.isEmpty())
            break;

        const QString tmpl = m.captured(2);
        QString built;
        bool resolved = true;
        qsizetype i = 0;
        while (i < tmpl.size()) {
            if (tmpl.at(i) != u'{') { resolved = false; break; }
            const qsizetype close = tmpl.indexOf(u'}', i);
            if (close < 0) { resolved = false; break; }
            bool okIdx = false;
            const int idx = tmpl.mid(i + 1, close - i - 1).toInt(&okIdx);
            if (!okIdx || idx < 0 || idx >= args.size()) { resolved = false; break; }
            built += args.at(idx);
            i = close + 1;
        }
        if (!resolved)
            break;

        const QString quote = m.captured(1);
        cur.replace(m.capturedStart(0), p - m.capturedStart(0), quote + built + quote);
        *fired = true;
    }
    return cur;
}

// 字符串拼接与词内引号,两者是同一类混淆:引号在词内被解释器吃掉。
//   "pow"+"ershell" -> "powershell"
//   'ie'+'x'        -> 'iex'
//   w"h"oami        -> whoami
//   i''ex           -> iex
// 只动词内引号(两侧都是字母数字)与相邻字面量之间的 +,不动分隔参数的引号,
// 因此 "C:\Program Files\x.exe" -a 这类正常命令行原样返回。
QString collapseConcat(const QString& s, bool* fired) {
    static const QRegularExpression plus(
        QStringLiteral("(['\"])([^'\"\\r\\n]*)\\1\\s*\\+\\s*(['\"])([^'\"\\r\\n]*)\\3"));

    QString cur = s;
    for (int round = 0; round < 32; ++round) {
        const QRegularExpressionMatch m = plus.match(cur);
        if (!m.hasMatch())
            break;
        cur.replace(m.capturedStart(0), m.capturedLength(0),
                    m.captured(1) + m.captured(2) + m.captured(4) + m.captured(1));
        *fired = true;
    }

    QString out;
    out.reserve(cur.size());
    for (qsizetype i = 0; i < cur.size(); ++i) {
        const QChar c = cur.at(i);
        if (!isQuote(c)) { out += c; continue; }
        const QChar prev = out.isEmpty() ? QChar() : out.back();
        // 空字面量插入:i''ex / i""ex
        if (i + 1 < cur.size() && cur.at(i + 1) == c) {
            const QChar after = (i + 2 < cur.size()) ? cur.at(i + 2) : QChar();
            if (isAsciiAlnum(prev) || isAsciiAlnum(after)) { ++i; *fired = true; continue; }
        }
        const QChar next = (i + 1 < cur.size()) ? cur.at(i + 1) : QChar();
        if (isAsciiAlnum(prev) && isAsciiAlnum(next)) { *fired = true; continue; }
        out += c;
    }
    return out;
}

// 收尾:把包着单个 token 的引号去掉,让 'iex' 还原成 iex —— 规则模式要求 iex( 这样
// 的 token 连续,留着引号等于没还原。只在前面确实改过东西时才跑。
QString unquoteTokens(const QString& s) {
    static const QRegularExpression re(
        QStringLiteral("(['\"])([A-Za-z0-9_.:+@/\\\\-]{1,96})\\1"));
    QString cur = s;
    cur.replace(re, QStringLiteral("\\2"));
    return cur;
}

QString collapseWhitespace(const QString& s) {
    QString out;
    out.reserve(s.size());
    bool pendingSpace = false;
    for (const QChar c : s) {
        if (c.isSpace()) { pendingSpace = true; continue; }
        if (pendingSpace && !out.isEmpty())
            out += QLatin1Char(' ');
        pendingSpace = false;
        out += c;
    }
    return out;
}

// 规整会不会改动这一串:有引号,或者有连续空白 / 空格以外的空白字符。
// 两样都没有的命令行在这里就返回,不分配也不跑正则。
bool hasCanonicalWork(const QString& s) {
    bool prevSpace = false;
    for (const QChar c : s) {
        if (isQuote(c))
            return true;
        if (!c.isSpace()) { prevSpace = false; continue; }
        if (prevSpace || c != u' ')
            return true;
        prevSpace = true;
    }
    return false;
}

bool hasQuoteChar(const QString& s) {
    for (const QChar c : s)
        if (isQuote(c))
            return true;
    return false;
}

// 原文的规整形态(见 Result::canonicalForms)。只删引号、只合并空白,不会长出原文没有的字符。
// 与原文去掉首尾空白后一致、或与 normalized 一致的不留:那种差别不值得让每条规则多比对一遍。
// unquoteTokens 的字符集里没有空白,先压空白再去引号与反过来做结果相同。
QStringList canonicalFormsOf(const QString& s, const QString& normalized) {
    QStringList out;
    if (s.size() > CommandDeobfuscator::kMaxCanonicalInputChars || !hasCanonicalWork(s))
        return out;
    const QString spaced = collapseWhitespace(s);
    if (spaced.isEmpty())
        return out;
    if (spaced != normalized && spaced != s.trimmed())
        out << spaced;
    if (hasQuoteChar(spaced)) {
        const QString bare = unquoteTokens(spaced);
        if (bare != spaced && bare != normalized)
            out << bare;
    }
    return out;
}

// Base64 正文解码。两种入口:PowerShell 的 -EncodedCommand / -enc / -e,以及行内的
// [Convert]::FromBase64String('...')。解不出可读文本就丢弃:任意二进制进了匹配面只会制造随机命中。
QString decodeBase64Payload(const QString& b64) {
    const auto dec = QByteArray::fromBase64Encoding(
        b64.toLatin1(), QByteArray::Base64Encoding | QByteArray::AbortOnBase64DecodingErrors);
    if (!dec)
        return QString();
    const QByteArray& b = dec.decoded;
    if (b.size() < 8)
        return QString();

    // UTF-16LE 判据:偶数长度,且奇数位字节绝大多数是 0(ASCII 文本的 UTF-16LE 形态)。
    int oddTotal = 0, oddZero = 0;
    for (qsizetype i = 1; i < b.size() && i < 256; i += 2) {
        ++oddTotal;
        if (b.at(i) == '\0') ++oddZero;
    }
    QString text;
    if (b.size() % 2 == 0 && oddTotal > 0 && oddZero * 4 >= oddTotal * 3) {
        text = QString::fromUtf16(reinterpret_cast<const char16_t*>(b.constData()), b.size() / 2);
    } else {
        // 必须用解码器显式取错误标志,不能用 QString::fromUtf8:它把非法字节序列替换成 U+FFFD,
        // 而 U+FFFD 在 QChar::isPrint() 下算可打印,纯二进制会借此混过下面的可读性检查。
        QStringDecoder decoder(QStringDecoder::Utf8);
        text = decoder(b);
        if (decoder.hasError())
            return QString();
    }
    // UTF-16LE 分支同样可能解出替换字符(非法代理对),一并挡掉。
    if (text.contains(QChar(0xFFFD)))
        return QString();

    const qsizetype sampled = qMin<qsizetype>(text.size(), 512);
    if (sampled == 0)
        return QString();
    int printable = 0;
    for (qsizetype i = 0; i < sampled; ++i) {
        const QChar c = text.at(i);
        if (c.isPrint() || c == u'\n' || c == u'\r' || c == u'\t')
            ++printable;
    }
    if (printable * 10 < sampled * 9)
        return QString();

    if (text.size() > CommandDeobfuscator::kMaxDecodedChars)
        text.truncate(CommandDeobfuscator::kMaxDecodedChars);
    return text;
}

void collectDecodedBlocks(const QString& s, QStringList* out) {
    static const QRegularExpression res[] = {
        QRegularExpression(
            // 正文外面允许有一个引号:-enc "<b64>" 是很自然的写法,PowerShell 照常执行。
            QStringLiteral("-(?:encodedcommand|encodedarguments|encoded|enc|ec|e)\\s+['\"]?"
                           "([A-Za-z0-9+/=]{16,})"),
            QRegularExpression::CaseInsensitiveOption),
        QRegularExpression(
            QStringLiteral("frombase64string\\s*\\(\\s*['\"]([A-Za-z0-9+/=]{16,})['\"]"),
            QRegularExpression::CaseInsensitiveOption),
    };

    for (const QRegularExpression& re : res) {
        auto it = re.globalMatch(s);
        while (it.hasNext()) {
            if (out->size() >= CommandDeobfuscator::kMaxDecodedBlocks)
                return;
            const QString b64 = it.next().captured(1);
            if (b64.size() < CommandDeobfuscator::kMinBase64Chars)
                continue;
            const QString text = decodeBase64Payload(b64);
            if (text.trimmed().isEmpty() || out->contains(text))
                continue;
            out->append(text);
        }
    }
}

}

CommandDeobfuscator::Result CommandDeobfuscator::run(const QString& commandLine) {
    Result r;
    if (commandLine.trimmed().isEmpty())
        return r;
    if (commandLine.size() > kMaxInputChars) {
        r.canonicalForms = canonicalFormsOf(commandLine, QString());
        return r;
    }

    bool caretL = false, tickL = false, charL = false, fmtL = false, concatL = false;

    QString cur = commandLine;
    for (int pass = 0; pass < kMaxPasses; ++pass) {
        bool fired = false;

        if (caretEscapeHits(cur) > 0) {
            const QString t = stripCaret(cur);
            if (t != cur) { cur = t; caretL = fired = true; }
        }
        if (backtickEscapeHits(cur) > 0) {
            const QString t = normalizeBacktick(cur);
            if (t != cur) { cur = t; tickL = fired = true; }
        }
        {
            bool f = false;
            const QString t = substituteCharCodes(cur, &f);
            if (f && t != cur) { cur = t; charL = fired = true; }
        }
        {
            bool f = false;
            const QString t = applyFormatOperator(cur, &f);
            if (f && t != cur) { cur = t; fmtL = fired = true; }
        }
        {
            bool f = false;
            const QString t = collapseConcat(cur, &f);
            if (f && t != cur) { cur = t; concatL = fired = true; }
        }

        if (!fired)
            break;
    }

    // 去引号之前的那一版要单独留一份:FromBase64String('<b64>') 的提取要求字面量带引号,
    // 而 unquoteTokens 会把引号去掉;少了这一份,同时被转义混淆过的命令行里就提取不出行内 Base64。
    QString preUnquote;
    if (caretL || tickL || charL || fmtL || concatL) {
        preUnquote = cur;
        cur = collapseWhitespace(unquoteTokens(cur));
        if (cur.size() > kMaxOutputChars)
            cur.truncate(kMaxOutputChars);
        if (cur != commandLine && !cur.trimmed().isEmpty())
            r.normalized = cur;
    }

    // 规整形态永远从原文算,与上面有没有做还原无关;和 normalized 是同一串时不重复留。
    r.canonicalForms = canonicalFormsOf(commandLine, r.normalized);

    // 还原 / 规整后的文本里才会露出 -enc <b64> 这种形态(原文可能写成 -e^n^c,或者给正文加了引号
    // 写成 -enc "<b64>"),所以几份都扫。
    collectDecodedBlocks(commandLine, &r.decodedBlocks);
    if (!preUnquote.isEmpty())
        collectDecodedBlocks(preUnquote, &r.decodedBlocks);
    if (!r.normalized.isEmpty())
        collectDecodedBlocks(r.normalized, &r.decodedBlocks);
    for (const QString& form : r.canonicalForms)
        collectDecodedBlocks(form, &r.decodedBlocks);

    if (caretL)   r.layers << u("cmd ^ 转义");
    if (tickL)    r.layers << u("PowerShell ` 转义");
    if (charL)    r.layers << u("[char] 字符码拼接");
    if (fmtL)     r.layers << u("-f 格式化重排");
    if (concatL)  r.layers << u("字符串拼接 / 词内引号");
    if (!r.decodedBlocks.isEmpty()) r.layers << u("Base64 解码");

    return r;
}

QString CommandDeobfuscator::tidied(const QString& commandLine) {
    if (commandLine.size() > kMaxCanonicalInputChars || !hasCanonicalWork(commandLine))
        return commandLine;
    const QString spaced = collapseWhitespace(commandLine);
    if (spaced.isEmpty())
        return commandLine;
    return hasQuoteChar(spaced) ? unquoteTokens(spaced) : spaced;
}

void reportCommandCanonicalization(SecurityEvent& e, const QString& matchedForm) {
    if (matchedForm.isEmpty())
        return;
    e.addEvidence(QStringLiteral("CommandDeobfuscator"), EvidenceKind::Info,
                  u("该规则命中的是规整后的命令行(比对时把连续空白当作一个空格、把包着单个参数的引号当作没有)"),
                  0);
    e.addSnippet(snippet::fromText(u("规整后的命令行"), matchedForm));
}

void reportCommandDeobfuscation(SecurityEvent& e, const QString& why) {
    if (e.commandDeobfuscationReported || e.commandDeobfuscationLayers.isEmpty())
        return;
    e.commandDeobfuscationReported = true;

    // 刻意不写"原文经 X 混淆":layers 里混着转义还原与 Base64 解码两类东西,
    // 说成"经 Base64 解码混淆"是错的。只陈述用了哪些还原手法。
    e.addEvidence(QStringLiteral("CommandDeobfuscator"), EvidenceKind::Info,
                  why + u("(还原手法:") + e.commandDeobfuscationLayers.join(QStringLiteral("、"))
                      + u(")"),
                  0);

    // 界面上必须能看到还原后的那一串:否则用户看到的命令行与命中的判据对不上,
    // 一条真命中会被当成误报。
    const QString shown = !e.normalizedCommandLine.isEmpty()
                              ? e.normalizedCommandLine
                              : (e.decodedCommandBlocks.isEmpty() ? QString()
                                                                  : e.decodedCommandBlocks.at(0));
    if (!shown.isEmpty())
        e.addSnippet(snippet::fromText(u("还原后的命令行"), shown));
}

}
