#include "dialogs/YaraView.h"
#include "design/Components.h"
#include "design/FlowLayout.h"
#include "design/GlowCard.h"
#include "design/Motion.h"
#include "design/Sticker.h"
#include "design/Theme.h"
#include "dialogs/EventFormat.h"
#include "dialogs/ToastWindow.h"
#include "widgets/ElidingLabel.h"

#include "bulwark/models/SecurityEvent.h"

#include <QEvent>
#include <QFileInfo>
#include <QHBoxLayout>
#include <QLabel>
#include <QLinearGradient>
#include <QPainter>
#include <QPainterPath>
#include <QRegularExpression>
#include <QVBoxLayout>
#include <QtMath>

#include <cmath>
#include <initializer_list>
#include <iterator>
#include <utility>

using bulwark::SecurityEvent;
using evtfmt::u;

namespace yaraview {
namespace {

// 深色屏幕上的级别色:恶意 = 红,可疑 = 黄(亮一档,压得住深底)。
QColor levelOnScreen(bool verified)
{
    const bool m = theme::mecha();
    if (verified)
        return m ? QColor(0xFF, 0x4A, 0x4A) : QColor(0xFF, 0x9C, 0x9C);
    return m ? QColor(0xFF, 0xCF, 0x33) : QColor(0xFF, 0xE2, 0x7A);
}

QColor levelColor(bool verified) { return verified ? theme::danger() : theme::warning(); }

// 扫描屏:深色小屏上一页文件,命中那一行高亮,一道扫描线在页面上来回扫(动画关闭时停在命中行)。
class ScanTile final : public QWidget
{
public:
    ScanTile(int size, bool verified) : m_verified(verified)
    {
        setFixedSize(size, size);
        setAttribute(Qt::WA_TransparentForMouseEvents);
        m_ticker = new motion::Ticker(this, [this](qint64 now) {
            m_beam = 0.5 - 0.5 * std::cos(qreal(now) / 1700.0 * 2.0 * M_PI);
            update();
        }, 33);
    }

protected:
    void showEvent(QShowEvent* e) override
    {
        QWidget::showEvent(e);
        m_ticker->setActive(true);
    }
    void hideEvent(QHideEvent* e) override
    {
        QWidget::hideEvent(e);
        m_ticker->setActive(false);
    }
    void paintEvent(QPaintEvent*) override
    {
        QPainter p(this);
        p.setRenderHint(QPainter::Antialiasing, true);
        const theme::Palette& P = theme::pal();
        const bool m = theme::mecha();
        const QColor lit = levelOnScreen(m_verified);
        const QRectF body = sticker::panel(p, QRectF(rect()), P.screen, m ? 8.0 : 14.0, true);

        const qreal s = body.width();
        const QRectF doc(body.center().x() - s * 0.23, body.top() + s * 0.16, s * 0.46, s * 0.64);
        const qreal fold = doc.width() * 0.32;
        QPainterPath page;
        page.moveTo(doc.left(), doc.top());
        page.lineTo(doc.right() - fold, doc.top());
        page.lineTo(doc.right(), doc.top() + fold);
        page.lineTo(doc.right(), doc.bottom());
        page.lineTo(doc.left(), doc.bottom());
        page.closeSubpath();
        p.fillPath(page, m ? QColor(0xF3, 0xEE, 0xE4) : QColor(0xFF, 0xFD, 0xF9));
        QPainterPath ear;
        ear.moveTo(doc.right() - fold, doc.top());
        ear.lineTo(doc.right() - fold, doc.top() + fold);
        ear.lineTo(doc.right(), doc.top() + fold);
        ear.closeSubpath();
        p.fillPath(ear, m ? QColor(0xC9, 0xC4, 0xBA) : QColor(0xE9, 0xDD, 0xF6));
        const QPen inkPen(P.ink, qMax<qreal>(1.4, s / 50.0), Qt::SolidLine, Qt::RoundCap, Qt::RoundJoin);
        p.strokePath(page, inkPen);
        p.strokePath(ear, inkPen);

        // 几行「内容」,其中一行是命中的特征:底下垫一条级别色。
        const qreal lx = doc.left() + doc.width() * 0.16;
        const qreal lw = doc.width() * 0.68;
        const qreal step = doc.height() / 6.2;
        const qreal widths[] = {0.55, 0.9, 0.7, 0.85, 0.5};
        const int hitRow = 2;
        for (int i = 0; i < 5; ++i) {
            const qreal y = doc.top() + fold + step * (0.55 + i);
            if (i == hitRow) {
                p.fillRect(QRectF(doc.left() + 2, y - step * 0.36, doc.width() - 4, step * 0.72),
                           theme::tint(lit, 0.85));
            }
            p.setPen(QPen(theme::tint(P.ink, i == hitRow ? 0.9 : 0.35), qMax<qreal>(1.6, s / 40.0),
                          Qt::SolidLine, Qt::RoundCap));
            p.drawLine(QPointF(lx, y), QPointF(lx + lw * widths[i], y));
        }

        // 瞄准框四角
        const QRectF ret = doc.adjusted(-s * 0.09, -s * 0.07, s * 0.09, s * 0.07);
        const qreal c = s * 0.13;
        QPainterPath corners;
        corners.moveTo(ret.left(), ret.top() + c); corners.lineTo(ret.left(), ret.top()); corners.lineTo(ret.left() + c, ret.top());
        corners.moveTo(ret.right() - c, ret.top()); corners.lineTo(ret.right(), ret.top()); corners.lineTo(ret.right(), ret.top() + c);
        corners.moveTo(ret.right(), ret.bottom() - c); corners.lineTo(ret.right(), ret.bottom()); corners.lineTo(ret.right() - c, ret.bottom());
        corners.moveTo(ret.left() + c, ret.bottom()); corners.lineTo(ret.left(), ret.bottom()); corners.lineTo(ret.left(), ret.bottom() - c);
        p.strokePath(corners, QPen(lit, qMax<qreal>(2.0, s / 32.0), Qt::SolidLine, Qt::SquareCap, Qt::MiterJoin));

        // 扫描线:带一截向上的拖尾。
        const qreal beamT = m_ticker->isActive() ? m_beam : 0.52;
        const qreal by = doc.top() + 2 + beamT * (doc.height() - 4);
        p.save();
        p.setClipRect(ret);
        QLinearGradient trail(0, by - step * 1.6, 0, by);
        trail.setColorAt(0.0, theme::tint(lit, 0.0));
        trail.setColorAt(1.0, theme::tint(lit, 0.38));
        p.fillRect(QRectF(ret.left(), by - step * 1.6, ret.width(), step * 1.6), trail);
        p.setPen(QPen(lit, qMax<qreal>(1.6, s / 45.0)));
        p.drawLine(QPointF(ret.left() + 1, by), QPointF(ret.right() - 1, by));
        p.restore();
    }

private:
    bool m_verified;
    qreal m_beam = 0.52;
    motion::Ticker* m_ticker = nullptr;
};

// 指纹条码:SHA-256 的 64 个十六进制位各画一根竖条,粗细与间隔由该位的值决定 ——
// 不同的文件一眼看上去就不一样,但它只是哈希的图形化,不是可扫描的条码。
class Fingerprint final : public QWidget
{
public:
    explicit Fingerprint(const QString& sha) : m_sha(sha.toUpper())
    {
        setFixedHeight(18);
        setMinimumWidth(120);
        setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
        setToolTip(u("SHA-256 指纹:") + m_sha);
    }

protected:
    void paintEvent(QPaintEvent*) override
    {
        if (m_sha.isEmpty())
            return;
        QPainter p(this);
        QList<std::pair<int, int>> bars;
        int units = 0;
        for (const QChar ch : std::as_const(m_sha)) {
            bool ok = false;
            const int v = QString(ch).toInt(&ok, 16);
            if (!ok)
                continue;
            const int w = 1 + (v & 3);
            const int gap = 1 + ((v >> 2) & 1);
            bars.append({w, gap});
            units += w + gap;
        }
        if (units == 0)
            return;
        const qreal unit = qreal(width()) / units;
        qreal x = 0;
        const QColor ink = theme::tint(theme::overlay(), 0.85);
        for (int i = 0; i < bars.size(); ++i) {
            const qreal top = (i % 8 == 0) ? 0.0 : 3.0;
            p.fillRect(QRectF(x, top, bars[i].first * unit, height() - top), ink);
            x += (bars[i].first + bars[i].second) * unit;
        }
    }

private:
    QString m_sha;
};

// 战报主体:钢印跟着卡片出现砸下来(与普通战报的钢印同一套动画),落下时整张卡片一沉。
class ReportHero final : public GlowCard
{
public:
    ReportHero() { setTone(GlowCard::Tone::Inset); }

    void attachStamp(StampLabel* stamp, QWidget* hole)
    {
        m_stamp = stamp;
        m_hole = hole;
        hole->installEventFilter(this);
    }

protected:
    bool eventFilter(QObject* watched, QEvent* event) override
    {
        if (watched == m_hole && (event->type() == QEvent::Move || event->type() == QEvent::Resize))
            placeStamp();
        return GlowCard::eventFilter(watched, event);
    }
    void showEvent(QShowEvent* e) override
    {
        GlowCard::showEvent(e);
        placeStamp();
        if (m_stamp && !m_slammed) {
            m_slammed = true;
            m_stamp->slam(motion::duration(420), [this] {
                if (auto* t = qobject_cast<ToastWindow*>(window()))
                    t->thump();
            }, QPointF(-26, -8));
        }
    }

private:
    void placeStamp()
    {
        if (!m_stamp || !m_hole)
            return;
        QRect r(QPoint(0, 0), m_stamp->size());
        r.moveCenter(QRect(m_hole->mapTo(this, QPoint(0, 0)), m_hole->size()).center());
        m_stamp->move(r.topLeft());
        m_stamp->raise();
    }

    StampLabel* m_stamp = nullptr;
    QWidget* m_hole = nullptr;
    bool m_slammed = false;
};

QLabel* caption(const QString& text, int width = 54)
{
    auto* l = ui::label(text, "caption");
    l->setFixedWidth(width);
    l->setAlignment(Qt::AlignLeft | Qt::AlignTop);
    return l;
}

QString shortHash(const QString& sha)
{
    const QString s = sha.toUpper();
    return s.size() > 28 ? s.left(12) + u(" … ") + s.right(12) : s;
}

QString provenance(const RuleInfo& info, const QString& author)
{
    const QString a = author.trimmed();
    if (info.source.isEmpty())
        return a;
    if (a.isEmpty() || a.contains(info.source, Qt::CaseInsensitive) || info.source.contains(a, Qt::CaseInsensitive))
        return a.isEmpty() ? info.source : a;
    return info.source + u(" · ") + a;
}

struct Step {
    QString text;
    QColor color;
};

QList<Step> stepsFor(bulwark::EnforcementOutcome o, bool execBlocked)
{
    using EO = bulwark::EnforcementOutcome;
    const QColor done = theme::mecha() ? theme::accentDeep() : theme::success();
    const QColor bad = theme::danger();
    const QColor info = theme::textSecondary();
    QList<Step> s;
    switch (o) {
    case EO::Terminated:         s << Step{u("✓ 已结束进程"), done}; break;
    case EO::ActorAlreadyGone:   s << Step{u("进程已先一步退出"), info}; break;
    case EO::PayloadQuarantined: s << Step{u("✗ 没能结束进程"), bad} << Step{u("✓ 已隔离文件"), done}; break;
    case EO::ExecDenied:         s << Step{u("✗ 没能结束进程"), bad}; break;
    case EO::AlertedOnly:        s << Step{u("✗ 没能结束进程"), bad}; break;
    case EO::Failed:             s << Step{u("✗ 处置未成功"), bad}; break;
    default:                     s << Step{u("✓ ") + evtfmt::disposition(bulwark::VerdictAction::Block, o).text, done}; break;
    }
    if (execBlocked || o == EO::ExecDenied)
        s << Step{u("✓ 已禁止再次运行"), done};
    return s;
}

bool tokenIn(const QString& low, std::initializer_list<const char*> words)
{
    for (const char* w : words)
        if (low == QLatin1String(w))
            return true;
    return false;
}

}

RuleInfo parseRule(const QString& rule, bool verified)
{
    RuleInfo info;
    QString rest = rule.trimmed();
    // YARA Forge 在每条规则名前加了来源仓库的大写缩写。
    static const std::pair<const char*, const char*> kSources[] = {
        {"SIGNATURE_BASE_", "signature-base"}, {"ELASTIC_", "Elastic"}, {"DITEKSHEN_", "ditekSHen"},
        {"ESET_", "ESET"}, {"CAPE_", "CAPE"}, {"RUSSIANPANDA_", "RussianPanda"}, {"TRELLIX_ARC_", "Trellix ARC"},
        {"EMBEERESEARCH_", "embee_research"}, {"DELIVRTO_", "delivr.to"}, {"HARFANGLAB_", "HarfangLab"},
        {"ARKBIRD_SOLG_", "Arkbird_SOLG"}, {"VOLEXITY_", "Volexity"}, {"DEADBITS_", "deadbits"},
        {"SEKOIA_", "Sekoia"}, {"MICROSOFT_", "Microsoft"}, {"FIREEYE_RT_", "FireEye"}, {"GCTI_", "Google GCTI"},
        {"R3C0NST_", "r3c0nst"}, {"BINARYALERT_", "BinaryAlert"}, {"DR4K0NIA_", "Dr4k0nia"},
        {"MALPEDIA_", "Malpedia"}, {"CHECKPOINT_", "Check Point"}, {"JPCERTCC_", "JPCERT/CC"},
        {"TELEKOM_SECURITY_", "Telekom Security"}, {"WITHSECURELABS_", "WithSecure"}, {"BITSIGHT_", "Bitsight"},
        {"CISA_", "CISA"}, {"NCSC_", "NCSC"}, {"MANDIANT_", "Mandiant"}, {"SBOUSSEADEN_", "sbousseaden"},
    };
    for (const auto& [prefix, name] : kSources) {
        if (rest.startsWith(QLatin1String(prefix), Qt::CaseInsensitive)) {
            info.source = QString::fromLatin1(name);
            rest = rest.mid(int(qstrlen(prefix)));
            break;
        }
    }

    // 类别词按具体程度排:同一条规则里出现多个时取最具体的(Windows_Trojan_RAT → 远控木马)。
    struct Cat {
        const char* words[5];
        const char* label;
    };
    static const Cat kCats[] = {
        {{"ransomware", "ransom"}, "勒索软件"},
        {{"wiper"}, "擦除器"},
        {{"stealer", "infostealer", "pws", "passwordstealer"}, "窃密木马"},
        {{"rat"}, "远控木马"},
        {{"backdoor"}, "后门"},
        {{"banker", "banking"}, "银行木马"},
        {{"rootkit", "bootkit"}, "Rootkit"},
        {{"miner", "coinminer", "cryptominer"}, "挖矿程序"},
        {{"keylogger"}, "键盘记录器"},
        {{"spyware", "spy"}, "间谍软件"},
        {{"loader"}, "加载器"},
        {{"downloader"}, "下载器"},
        {{"dropper"}, "释放器"},
        {{"worm"}, "蠕虫"},
        {{"virus", "infector"}, "感染型病毒"},
        {{"exploit", "cve"}, "漏洞利用"},
        {{"webshell"}, "Webshell"},
        {{"hktl", "hacktool", "hacktools"}, "黑客工具"},
        {{"trojan"}, "木马"},
        {{"adware"}, "广告软件"},
        {{"pua", "pup", "riskware"}, "潜在有害程序"},
        {{"apt"}, "APT 工具"},
        {{"packer", "packed"}, "加壳程序"},
        {{"malware", "mal"}, "恶意软件"},
        {{"susp", "suspicious", "indicator", "hunting", "heur"}, "可疑特征"},
    };
    static const QRegularExpression hexId(QStringLiteral("^(?=.*\\d)[0-9A-Fa-f]{6,}$"));
    static const QRegularExpression noiseTok(
        QStringLiteral("^(\\d+|v\\d+|(19|20)\\d{2}|(jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)[a-z]*\\d{0,4})$"),
        QRegularExpression::CaseInsensitiveOption);

    int best = int(std::size(kCats));
    QStringList keep;
    const QStringList tokens = rest.split(QLatin1Char('_'), Qt::SkipEmptyParts);
    for (const QString& tok : tokens) {
        const QString low = tok.toLower();
        if (tokenIn(low, {"win", "windows", "win32", "win64", "w32", "w64"})) {
            if (info.platform.isEmpty())
                info.platform = QStringLiteral("Windows");
            continue;
        }
        if (tokenIn(low, {"lnx", "linux"})) {
            if (info.platform.isEmpty())
                info.platform = QStringLiteral("Linux");
            continue;
        }
        if (tokenIn(low, {"macos", "osx", "mac"})) {
            if (info.platform.isEmpty())
                info.platform = QStringLiteral("macOS");
            continue;
        }
        if (tokenIn(low, {"android"})) {
            if (info.platform.isEmpty())
                info.platform = QStringLiteral("Android");
            continue;
        }
        bool isCat = false;
        for (int i = 0; i < int(std::size(kCats)); ++i) {
            for (const char* w : kCats[i].words) {
                if (w && low == QLatin1String(w)) {
                    isCat = true;
                    if (i < best) {
                        best = i;
                        info.category = QString::fromUtf8(kCats[i].label);
                    }
                }
            }
        }
        if (isCat)
            continue;
        if (tok.size() <= 1 || hexId.match(tok).hasMatch() || noiseTok.match(tok).hasMatch()
            || tokenIn(low, {"exe", "dll", "pe", "elf", "macho", "lnk", "ps", "ps1", "vbs", "js", "hta", "doc",
                             "docx", "xls", "office", "pdf", "file", "files", "generic", "gen", "strings", "str",
                             "mem", "memory", "unpacked", "payload", "payloads", "sample", "samples", "rule"}))
            continue;
        keep << tok;
    }
    const auto pretty = [](QString s) {
        if (s == s.toUpper() || s == s.toLower())
            s = s.left(1).toUpper() + s.mid(1).toLower();
        return s;
    };
    const bool technique = info.category == u("可疑特征");
    if (!keep.isEmpty() && !technique) {
        info.family = pretty(keep.first());
        info.title = info.family;
    } else if (!keep.isEmpty()) {
        QStringList words;
        for (const QString& w : std::as_const(keep))
            words << pretty(w);
        info.title = words.join(QLatin1Char(' '));
    } else {
        info.title = rest.isEmpty() ? rule : QString(rest).replace(QLatin1Char('_'), QLatin1Char(' '));
    }
    if (info.category.isEmpty())
        info.category = verified ? u("恶意家族") : u("可疑特征");
    return info;
}

bool isYaraReason(const QString& reason)
{
    // 这两种开头来自 ThreatDetector 给 YARA 证据写的文案。
    return reason.startsWith(u("程序文件命中 YARA 规则")) || reason.startsWith(u("程序文件命中已验证的 YARA 家族规则"));
}

QWidget* reportHero(const SecurityEvent& e, bulwark::EnforcementOutcome outcome, bool execBlocked,
                    const QString& stampText)
{
    const bool verified = e.yaraLevel == SecurityEvent::YaraMalicious;
    const RuleInfo info = parseRule(e.yaraRule, verified);
    const QColor tone = levelColor(verified);

    auto* hero = new ReportHero;
    auto* v = new QVBoxLayout(hero);
    v->setContentsMargins(14, 12, 14, 12);
    v->setSpacing(8);

    // 识别结果:扫描屏 + 家族大字 + 类别 / 平台 / 命中条数,右上角盖钢印。
    auto* top = new QHBoxLayout;
    top->setSpacing(12);
    top->addWidget(new ScanTile(84, verified), 0, Qt::AlignTop);
    auto* id = new QVBoxLayout;
    id->setSpacing(4);
    auto* eyebrow = ui::label(verified ? u("识别结果 · 已验证的家族规则") : u("识别结果 · YARA 特征"), "caption");
    eyebrow->setFont(sticker::labelFont(8.5));
    id->addWidget(eyebrow);
    const bool longTitle = info.title.size() > 16;
    auto* name = new StickerText(info.title, longTitle ? 20 : 30);
    name->setFill(tone);
    name->setAccessibleName(info.family.isEmpty() ? u("命中特征:") + info.title : u("恶意家族:") + info.family);
    id->addWidget(name, 0, Qt::AlignLeft);
    auto* chipsBox = new QWidget;
    auto* chips = new FlowLayout(chipsBox, 6, 6);
    chips->setContentsMargins(0, 2, 0, 0);
    chips->addWidget(ui::pill(info.category, tone));
    if (!info.platform.isEmpty())
        chips->addWidget(ui::pill(info.platform, theme::info()));
    if (e.yaraMatchCount > 1)
        chips->addWidget(ui::pill(u("命中 %1 条规则").arg(e.yaraMatchCount), theme::textSecondary()));
    id->addWidget(chipsBox);
    top->addLayout(id, 1);
    StampLabel* stamp = nullptr;
    if (!stampText.isEmpty()) {
        stamp = new StampLabel(stampText, tone, -8.0, 15.0, hero);
        auto* hole = new QWidget;
        hole->setFixedSize(stamp->sizeHint());
        hole->setAttribute(Qt::WA_TransparentForMouseEvents);
        stamp->setOverscan(2.3);
        stamp->resize(stamp->sizeHint());
        top->addWidget(hole, 0, Qt::AlignTop);
        hero->attachStamp(stamp, hole);
    }
    v->addLayout(top);

    const auto row = [&](const QString& key, QWidget* value, QWidget* tail = nullptr) {
        auto* h = new QHBoxLayout;
        h->setSpacing(8);
        h->addWidget(caption(key), 0, Qt::AlignTop);
        h->addWidget(value, 1);
        if (tail)
            h->addWidget(tail, 0, Qt::AlignTop);
        v->addLayout(h);
    };

    auto* ruleName = ui::elided(e.yaraRule, "mono");
    ruleName->setElideMode(Qt::ElideMiddle);
    ruleName->setToolTip(e.yaraRule);
    const QString rule = e.yaraRule;
    row(u("规则"), ruleName, ui::copyButton([rule] { return rule; }, u("复制规则名")));
    const QString from = provenance(info, e.yaraAuthor);
    if (!from.isEmpty())
        row(u("来源"), ui::label(u("YARA Forge · ") + from, "secondary"));

    auto* sep = new QFrame;
    sep->setFixedHeight(2);
    sep->setStyleSheet(QStringLiteral("border:none; border-top:2px dashed %1;").arg(theme::border().name()));
    v->addWidget(sep);

    auto* file = new QWidget;
    auto* fv = new QVBoxLayout(file);
    fv->setContentsMargins(0, 0, 0, 0);
    fv->setSpacing(1);
    const QString fileName = QFileInfo(e.actorPath).fileName();
    fv->addWidget(ui::label(fileName.isEmpty() ? u("(未取得文件名)") : fileName, "title"));
    auto* path = ui::elided(evtfmt::nativePath(e.actorPath), "mono");
    path->setElideMode(Qt::ElideMiddle);
    path->setToolTip(evtfmt::nativePath(e.actorPath));
    fv->addWidget(path);
    row(u("文件"), file);

    if (e.actorHash.size() == 64) {
        auto* hash = new QWidget;
        auto* hv = new QVBoxLayout(hash);
        hv->setContentsMargins(0, 0, 0, 0);
        hv->setSpacing(4);
        hv->addWidget(ui::label(shortHash(e.actorHash), "mono"));
        hv->addWidget(new Fingerprint(e.actorHash));
        const QString sha = e.actorHash.toUpper();
        row(QStringLiteral("SHA-256"), hash, ui::copyButton([sha] { return sha; }, u("复制 SHA-256")));
    }

    auto* stepsBox = new QWidget;
    auto* steps = new FlowLayout(stepsBox, 6, 6);
    steps->setContentsMargins(0, 0, 0, 0);
    for (const Step& s : stepsFor(outcome, execBlocked))
        steps->addWidget(ui::pill(s.text, s.color));
    row(u("处置"), stepsBox);
    return hero;
}

QWidget* promptStrip(const SecurityEvent& e)
{
    if (e.yaraLevel == SecurityEvent::YaraNone || e.yaraRule.trimmed().isEmpty())
        return nullptr;
    const bool verified = e.yaraLevel == SecurityEvent::YaraMalicious;
    const RuleInfo info = parseRule(e.yaraRule, verified);
    const QColor tone = levelColor(verified);

    // 询问弹窗在小屏上本来就紧,这一条只占三行:级别、名字、规则全名与来源;为什么不能单凭它定性
    // 写在悬停提示里(级别标签已经点明「仅作参考」)。
    auto* card = ui::cardAlt();
    auto* h = new QHBoxLayout(card);
    h->setContentsMargins(12, 9, 14, 9);
    h->setSpacing(12);
    h->addWidget(new ScanTile(54, verified), 0, Qt::AlignVCenter);
    auto* col = new QVBoxLayout;
    col->setSpacing(3);

    auto* head = new QHBoxLayout;
    head->setSpacing(8);
    auto* eyebrow = ui::label(u("特征扫描 · YARA"), "caption");
    eyebrow->setFont(sticker::labelFont(8.5));
    head->addWidget(eyebrow, 0, Qt::AlignVCenter);
    head->addStretch(1);
    head->addWidget(ui::pill(verified ? u("已验证的家族规则") : u("未验证规则 · 仅作参考"), tone), 0, Qt::AlignVCenter);
    col->addLayout(head);

    auto* what = new QHBoxLayout;
    what->setSpacing(8);
    auto* title = ui::label(info.title, "lead");
    title->setStyleSheet(QStringLiteral("font-weight:900; color:%1;").arg(theme::textPrimary().name()));
    what->addWidget(title, 0, Qt::AlignVCenter);
    what->addWidget(ui::pill(info.category, tone), 0, Qt::AlignVCenter);
    if (e.yaraMatchCount > 1)
        what->addWidget(ui::label(u("共命中 %1 条规则").arg(e.yaraMatchCount), "muted"), 0, Qt::AlignVCenter);
    what->addStretch(1);
    col->addLayout(what);

    auto* ruleLine = new QHBoxLayout;
    ruleLine->setSpacing(8);
    auto* ruleName = ui::elided(e.yaraRule, "mono");
    ruleName->setElideMode(Qt::ElideMiddle);
    ruleLine->addWidget(ruleName, 1, Qt::AlignVCenter);
    const QString from = provenance(info, e.yaraAuthor);
    if (!from.isEmpty())
        ruleLine->addWidget(ui::label(u("来源 ") + from, "muted"), 0, Qt::AlignVCenter);
    col->addLayout(ruleLine);
    h->addLayout(col, 1);

    const QString why = verified ? u("这条家族规则事先在正常软件上核对过,说明的是「这个文件是什么」。")
                                 : u("这条规则没在正常软件上核对过,单凭它不能定性;是它和其他迹象叠在一起,"
                                     "才让这次操作需要你确认。");
    card->setToolTip(e.yaraRule + u("\n") + why);
    card->setAccessibleName(u("YARA 特征扫描:") + info.title);
    card->setAccessibleDescription(why);
    return card;
}

}
