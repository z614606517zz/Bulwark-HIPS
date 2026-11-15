#include "pages/TablePages.h"

#include "design/Banner.h"
#include "design/Components.h"
#include "design/Format.h"
#include "design/IconTile.h"
#include "design/Icons.h"
#include "design/Identity.h"
#include "design/Skin.h"
#include "design/Theme.h"
#include "design/TitanKit.h"
#include "design/ToggleSwitch.h"
#include "ipc/IpcClient.h"
#include "pages/PageKit.h"
#include "Nav.h"

#include <QDesktopServices>
#include <QDir>
#include <QFileInfo>
#include <QGridLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QLocale>
#include <QPainter>
#include <QPointer>
#include <QPushButton>
#include <QScrollArea>
#include <QSet>
#include <QSignalBlocker>
#include <QTimer>
#include <QUrl>
#include <QUuid>
#include <QVBoxLayout>

#include <algorithm>
#include <array>
#include <cmath>
#include <memory>

using bulwark::ipc::YaraRuleSourcePayload;
using bulwark::ipc::YaraRulesActionResultPayload;
using bulwark::ipc::YaraRulesStatusPayload;
using bulwark::ipc::YaraScanHitPayload;
using bulwark::ipc::YaraScanStatusPayload;
using bulwark::ipc::YaraSkippedRulePayload;

namespace {

QString u(const char* s) { return QString::fromUtf8(s); }

constexpr int kSkippedShown = 50;
constexpr int kSourcesShown = 16;
constexpr int kHitsShown = 20;

QLabel* wrapped(const QString& text, const char* role)
{
    auto* l = ui::label(text, role);
    l->setWordWrap(true);
    l->setTextInteractionFlags(Qt::TextSelectableByMouse);
    return l;
}

void clearLayout(QLayout* l)
{
    while (QLayoutItem* it = l->takeAt(0)) {
        if (QWidget* w = it->widget())
            w->deleteLater();
        else if (QLayout* child = it->layout())
            clearLayout(child);
        delete it;
    }
}

QString number(qint64 n) { return QLocale().toString(n); }

bool busy(const YaraRulesStatusPayload& s) { return s.stage != QLatin1String("idle") && !s.stage.isEmpty(); }

QString stageText(const QString& stage)
{
    if (stage == QLatin1String("checking")) return u("正在查询 YARA Forge 最新发布…");
    if (stage == QLatin1String("downloading")) return u("正在下载规则包…");
    if (stage == QLatin1String("compiling")) return u("正在编译规则…");
    if (stage == QLatin1String("installing")) return u("正在替换规则文件…");
    return QString();
}

QString scanStateText(const YaraScanStatusPayload& sc) {
    if (!sc.enabled || sc.state == QLatin1String("off"))
        return u("已在部署配置中关闭(YaraRules.ScanProcesses)");
    if (sc.state == QLatin1String("no-rules"))
        return u("还没有可用的规则,联网更新成功后自动开始");
    QString t;
    if (sc.state == QLatin1String("idle")) t = u("待命:有新程序启动时才载入规则");
    else if (sc.state == QLatin1String("starting")) t = u("正在载入规则…");
    else if (sc.state == QLatin1String("ready")) t = u("运行中");
    else if (sc.state == QLatin1String("paused")) t = u("已暂停");
    else if (sc.state == QLatin1String("error")) t = u("出错");
    else t = sc.state;
    if (!sc.detail.isEmpty() && sc.state != QLatin1String("starting"))
        t += u(":") + sc.detail;
    return t;
}

struct State {
    YaraRulesStatusPayload last;
    bool haveData = false;
    QSet<QUuid> inflight;
};

// 金刚专属版式

constexpr int kTitanSkippedShown = 5;
constexpr int kTitanSourcesShown = 6;
constexpr int kTitanHitsShown = 6;

QPair<QString, QColor> scanBadge(const YaraScanStatusPayload& sc)
{
    if (!sc.enabled || sc.state == QLatin1String("off"))
        return {u("已关闭"), theme::textMuted()};
    if (sc.state == QLatin1String("no-rules"))
        return {u("无规则"), theme::textMuted()};
    if (sc.state == QLatin1String("idle"))
        return {u("待命"), theme::info()};
    if (sc.state == QLatin1String("starting"))
        return {u("载入中"), theme::pal().glow};
    if (sc.state == QLatin1String("ready"))
        return {u("运行中"), theme::success()};
    if (sc.state == QLatin1String("paused"))
        return {u("已暂停"), theme::warning()};
    if (sc.state == QLatin1String("error"))
        return {u("出错"), theme::danger()};
    return {sc.state, theme::textMuted()};
}

// 规则更新的五步流水线。更新进行中按 stage 点亮;空闲时如果已经有可用规则,五步都算走完过 ——
// 现在用的这一包就是这样装上的。下载完紧接着按发布页的 SHA-256 校验,服务不单独报这一步,
// 所以「下载」进行中时它还没亮。放不下时只画图标和序号,完整名称在悬停提示里。
class UpdatePipeline final : public QWidget
{
public:
    enum class Step { Pending, Active, Done };

    UpdatePipeline()
    {
        setSizePolicy(QSizePolicy::Preferred, QSizePolicy::Fixed);
        setFixedHeight(30);
        m_steps.fill(Step::Pending);
    }

    void setStatus(const YaraRulesStatusPayload& s)
    {
        int active = -1;
        if (s.stage == QLatin1String("checking")) active = 0;
        else if (s.stage == QLatin1String("downloading")) active = 1;
        else if (s.stage == QLatin1String("compiling")) active = 3;
        else if (s.stage == QLatin1String("installing")) active = 4;
        for (int i = 0; i < int(m_steps.size()); ++i) {
            if (active >= 0)
                m_steps[i] = i < active ? Step::Done : i == active ? Step::Active : Step::Pending;
            else
                m_steps[i] = s.rulesCompiled > 0 ? Step::Done : Step::Pending;
        }
        QStringList tip;
        for (int i = 0; i < int(m_steps.size()); ++i)
            tip << u("%1. %2 · %3")
                       .arg(i + 1)
                       .arg(label(i), m_steps[i] == Step::Done ? u("已完成")
                                      : m_steps[i] == Step::Active ? u("进行中")
                                                                   : u("未开始"));
        setToolTip(tip.join(QLatin1Char('\n')));
        update();
    }

    QSize sizeHint() const override { return {stripWidth(false), 30}; }
    QSize minimumSizeHint() const override { return {stripWidth(true), 30}; }

protected:
    void paintEvent(QPaintEvent*) override
    {
        const theme::Palette& P = theme::pal();
        QPainter p(this);
        p.setRenderHint(QPainter::Antialiasing, true);
        p.setRenderHint(QPainter::TextAntialiasing, true);
        const bool compact = width() < stripWidth(false);
        p.setFont(stepFont(compact));
        qreal x = width() - stripWidth(compact);
        for (int i = 0; i < int(m_steps.size()); ++i) {
            const Step s = m_steps[i];
            const QColor c = s == Step::Done ? P.success : s == Step::Active ? P.glow : P.textMuted;
            const qreal w = chip(i, compact);
            const QRectF r(x + 1.0, 2.0, w - 2.0, 26.0);
            const QPainterPath path = theme::panelPath(r, 6.0);
            p.fillPath(path, s == Step::Pending ? P.surfaceAlt : theme::blend(c, P.surface, 0.16));
            p.strokePath(path, QPen(s == Step::Pending ? P.borderStrong : c, 1.5, Qt::SolidLine, Qt::SquareCap,
                                    Qt::MiterJoin));
            const QRectF icon(r.left() + 9.0, r.center().y() - 6.5, 13.0, 13.0);
            if (s == Step::Done) {
                AppIcon::draw(p, QStringLiteral("check"), icon, c, 2.2);
            } else {
                p.setPen(QPen(c, 1.8));
                p.setBrush(s == Step::Active ? c : Qt::NoBrush);
                p.drawEllipse(icon.center(), 4.0, 4.0);
            }
            p.setPen(s == Step::Pending ? P.textMuted : c);
            p.drawText(QRectF(icon.right() + 6.0, r.top(), r.right() - icon.right() - 12.0, r.height()),
                       Qt::AlignVCenter | Qt::AlignLeft, compact ? QString::number(i + 1) : label(i));
            x += w + kGap;
        }
    }

private:
    static constexpr qreal kGap = 6.0;

    static QString label(int i)
    {
        static const char* const names[] = {"查询最新发布", "下载规则包", "SHA-256 校验", "受限子进程编译", "替换规则文件"};
        return u(names[i]);
    }

    QFont stepFont(bool compact) const
    {
        QFont f = font();
        f.setPixelSize(compact ? 11 : 12);
        f.setWeight(QFont::Bold);
        return f;
    }

    qreal chip(int i, bool compact) const
    {
        const QFontMetrics fm(stepFont(compact));
        return 9.0 + 13.0 + 6.0 + fm.horizontalAdvance(compact ? QString::number(i + 1) : label(i)) + 12.0;
    }

    int stripWidth(bool compact) const
    {
        qreal w = 0.0;
        for (int i = 0; i < int(m_steps.size()); ++i)
            w += chip(i, compact) + (i > 0 ? kGap : 0.0);
        return int(std::ceil(w)) + 2;
    }

    std::array<Step, 5> m_steps{};
};

// 「规则来源」的一行:仓库名 + 分节条(满格 = 贡献最多的那个仓库) + 条数。
class SourceBar final : public QWidget
{
public:
    SourceBar(const QString& repo, int rules, int maxRules) : m_repo(repo), m_rules(rules), m_max(maxRules)
    {
        setFixedHeight(22);
        setToolTip(u("%1 · %2 条").arg(repo, number(rules)));
    }

protected:
    void paintEvent(QPaintEvent*) override
    {
        const theme::Palette& P = theme::pal();
        QPainter p(this);
        p.setRenderHint(QPainter::TextAntialiasing, true);
        QFont mono = font();
        mono.setFamilies({QStringLiteral("Cascadia Mono"), QStringLiteral("Consolas")});
        mono.setPixelSize(12);
        p.setFont(mono);
        p.setPen(P.textSecondary);
        const int nameW = qMin(176, width() * 2 / 5);
        p.drawText(QRect(0, 0, nameW - 8, height()), Qt::AlignVCenter | Qt::AlignLeft,
                   QFontMetrics(mono).elidedText(m_repo, Qt::ElideRight, nameW - 8));
        const QFont num = titankit::numFont(12, QFont::Bold);
        const int countW = QFontMetrics(num).horizontalAdvance(number(m_rules)) + 4;
        const int x0 = nameW;
        const int x1 = width() - qMax(countW, 44) - 8;
        constexpr int kCell = 7;
        constexpr int kCellGap = 2;
        const int cells = qMax(4, (x1 - x0 + kCellGap) / (kCell + kCellGap));
        const int lit = m_max > 0 ? qBound(1, int(std::lround(double(m_rules) / m_max * cells)), cells) : 0;
        const QColor off = theme::blend(P.textMuted, P.surface, 0.22);
        for (int i = 0; i < cells; ++i)
            p.fillRect(QRect(x0 + i * (kCell + kCellGap), (height() - 10) / 2, kCell, 10), i < lit ? P.amber : off);
        p.setFont(num);
        p.setPen(P.text);
        p.drawText(QRect(0, 0, width(), height()), Qt::AlignVCenter | Qt::AlignRight, number(m_rules));
    }

private:
    QString m_repo;
    int m_rules;
    int m_max;
};

QWidget* titanHitRow(const YaraScanHitPayload& h)
{
    auto* w = new QWidget;
    w->setFixedHeight(30);
    auto* row = new QHBoxLayout(w);
    row->setContentsMargins(0, 0, 0, 0);
    row->setSpacing(8);
    const bool bad = h.level == QLatin1String("malicious");
    row->addWidget(ui::pill(bad ? u("恶意") : u("可疑"), bad ? theme::danger() : theme::warning()), 0,
                   Qt::AlignVCenter);
    const QString file = QFileInfo(h.path).fileName();
    row->addWidget(ui::label(file.isEmpty() ? h.sha256.left(16) : file, "title"), 0, Qt::AlignVCenter);
    row->addWidget(ui::elided(h.matchCount > 1 ? u("%1 · 共命中 %2 条规则").arg(h.rule).arg(h.matchCount) : h.rule,
                              "mono"),
                   1, Qt::AlignVCenter);
    if (h.timeUtc.isValid())
        row->addWidget(ui::label(fmt::relativeTime(h.timeUtc), "muted"), 0, Qt::AlignVCenter);
    QStringList tip{h.path.isEmpty() ? h.sha256 : h.path, h.rule};
    if (!h.author.isEmpty())
        tip << u("作者 %1").arg(h.author);
    w->setToolTip(tip.join(QLatin1Char('\n')));
    return w;
}

QWidget* titanSkipRow(const YaraSkippedRulePayload& r)
{
    auto* w = new QWidget;
    w->setFixedHeight(28);
    auto* row = new QHBoxLayout(w);
    row->setContentsMargins(0, 0, 0, 0);
    row->setSpacing(10);
    auto* name = ui::elided(r.rule, "mono");
    name->setMinimumWidth(120);
    row->addWidget(name, 5, Qt::AlignVCenter);
    if (r.line > 0)
        row->addWidget(ui::label(u("第 %1 行").arg(number(r.line)), "muted"), 0, Qt::AlignVCenter);
    auto* reason = ui::elided(r.reason, "secondary");
    reason->setMinimumWidth(100);
    row->addWidget(reason, 4, Qt::AlignVCenter);
    w->setToolTip(r.line > 0 ? u("%1(第 %2 行)\n%3").arg(r.rule, number(r.line), r.reason)
                             : u("%1\n%2").arg(r.rule, r.reason));
    return w;
}

QFrame* rowRule()
{
    auto* rule = new QFrame;
    rule->setFixedHeight(1);
    rule->setStyleSheet(QStringLiteral("background:%1;").arg(theme::border().name()));
    return rule;
}

}

namespace pages {

QWidget* yaraRules(IpcClient* ipc)
{
    auto* page = new QWidget;
    auto st = std::make_shared<State>();
    const QColor hue = identity::page(QString::fromLatin1(nav::YaraRules));

    auto* outer = new QVBoxLayout(page);
    outer->setContentsMargins(0, 0, 0, 0);
    auto* scroll = new QScrollArea;
    scroll->setWidgetResizable(true);
    scroll->setFrameShape(QFrame::NoFrame);
    scroll->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    scroll->viewport()->setAutoFillBackground(false);
    outer->addWidget(scroll);
    auto* content = new QWidget;
    auto* v = new QVBoxLayout(content);
    v->setContentsMargins(theme::metric::pagePad, 16, theme::metric::pagePad, theme::metric::pagePad);
    v->setSpacing(16);
    scroll->setWidget(content);
    content->setAutoFillBackground(false);

    QHBoxLayout* actions = pagekit::headerActions(page);
    QPushButton* folderBtn = pagekit::headerButton(actions, QStringLiteral("folder"), u("打开目录"));
    QPushButton* updateBtn = pagekit::headerButton(actions, QStringLiteral("download"), u("立即更新"), "primary");

    // 总览
    auto* summary = ui::card();
    summary->setGlow(hue, QPointF(0.0, 0.0), 0.7, 0.12);
    auto* sh = new QHBoxLayout(summary);
    sh->setContentsMargins(20, 16, 20, 16);
    sh->setSpacing(16);
    auto* tile = new IconTile(QStringLiteral("layers"), hue, 46, 22);
    sh->addWidget(tile, 0, Qt::AlignTop);
    auto* sv = new QVBoxLayout;
    sv->setSpacing(4);
    auto* headline = ui::label(u("正在读取…"), "h2");
    headline->setWordWrap(true);
    sv->addWidget(headline);
    auto* subline = wrapped(QString(), "secondary");
    sv->addWidget(subline);
    auto* messageLine = wrapped(QString(), "muted");
    sv->addWidget(messageLine);
    sh->addLayout(sv, 1);

    const bool titan = theme::titan();
    auto* autoSw = new ToggleSwitch(true);
    autoSw->setAccessibleName(u("自动更新 YARA 规则"));
    auto* autoCaption = ui::label(QString(), "muted");
    UpdatePipeline* pipeline = nullptr;
    if (titan) {
        // 金刚:总览右边是更新流水线;自动更新开关挪到「当前规则」面板头上。
        pipeline = new UpdatePipeline;
        sh->addWidget(pipeline, 0, Qt::AlignVCenter);
    } else {
        auto* autoBox = new QVBoxLayout;
        autoBox->setSpacing(4);
        auto* autoRow = new QHBoxLayout;
        autoRow->setSpacing(8);
        autoRow->addStretch();
        autoRow->addWidget(ui::label(u("自动更新"), "title"));
        autoRow->addWidget(autoSw);
        autoBox->addLayout(autoRow);
        autoCaption->setAlignment(Qt::AlignRight);
        autoBox->addWidget(autoCaption);
        autoBox->addStretch();
        sh->addLayout(autoBox);
    }
    v->addWidget(summary);

    auto* titanGrid = titan ? new QGridLayout : nullptr;
    QList<titankit::Panel> panels;
    const auto section = [v, titanGrid, &panels](const QString& icon, const QColor& color, const QString& title,
                                                const QString& note, QLabel** countOut) -> QVBoxLayout* {
        if (titanGrid) {
            // 金刚:四块面板两行两列,标题后的小字就是原来的计数。
            titankit::Panel p = titankit::panel(title, QString(), QString(), color);
            *countOut = p.head.note;
            if (!note.isEmpty())
                p.body->addWidget(wrapped(note, "muted"));
            auto* body = new QVBoxLayout;
            body->setSpacing(0);
            p.body->addLayout(body);
            p.body->addStretch();
            titanGrid->addWidget(p.card, int(panels.size()) / 2, int(panels.size()) % 2);
            panels << p;
            return body;
        }
        auto* card = ui::card();
        auto* cv = new QVBoxLayout(card);
        cv->setContentsMargins(20, 16, 20, 14);
        cv->setSpacing(10);
        auto* head = new QHBoxLayout;
        head->setSpacing(10);
        head->addWidget(new IconTile(icon, color, 30, 15));
        head->addWidget(ui::label(title, "title"));
        *countOut = ui::label(QString(), "muted");
        head->addWidget(*countOut);
        head->addStretch();
        cv->addLayout(head);
        if (!note.isEmpty())
            cv->addWidget(wrapped(note, "muted"));
        auto* body = new QVBoxLayout;
        body->setSpacing(0);
        cv->addLayout(body);
        v->addWidget(card);
        return body;
    };

    QLabel *scanCount = nullptr, *rulesCount = nullptr, *sourceCount = nullptr, *skipCount = nullptr;
    QVBoxLayout* scanBody = section(QStringLiteral("shield"), theme::success(), u("进程启动扫描"),
                                    u("程序启动时扫描它的文件,结论按文件哈希记住,同一个文件不重复扫。"
                                      "命中已验证的家族规则判恶意:结束进程、禁止再次运行、隔离文件;"
                                      "其余命中判可疑,只作弱信号参与裁决。微软签名的系统文件、"
                                      "本产品自身和你信任的程序不扫。"),
                                    &scanCount);
    QVBoxLayout* rulesBody = section(QStringLiteral("file"), hue, u("当前规则"), QString(), &rulesCount);
    QVBoxLayout* sourceBody = section(QStringLiteral("layers"), theme::olive(), u("规则来源"),
                                      u("YARA Forge 从这些公开仓库汇总规则,按质量筛选后打包。"
                                        "各仓库的许可证不同,规则里保留着原作者署名。"),
                                      &sourceCount);
    QVBoxLayout* skipBody = section(QStringLiteral("alert"), theme::warning(), u("被跳过的规则"),
                                    u("编译不过,或被 YARA-X 判为可能明显拖慢扫描的规则,会在编译时逐条剔除,"
                                      "其余规则照常可用。"),
                                    &skipCount);
    QWidget* skipCard = skipBody->parentWidget();
    QLabel* scanBadgeLabel = nullptr;
    if (titanGrid) {
        titanGrid->setHorizontalSpacing(14);
        titanGrid->setVerticalSpacing(14);
        titanGrid->setColumnStretch(0, 1);
        titanGrid->setColumnStretch(1, 1);
        v->addLayout(titanGrid);
        scanBadgeLabel = ui::pill(QString(), theme::textMuted());
        panels[0].head.trailing->addWidget(scanBadgeLabel);
        panels[1].head.trailing->addWidget(ui::label(u("自动更新"), "muted"));
        panels[1].head.trailing->addWidget(autoSw);
        panels[1].body->addWidget(autoCaption);
    }

    auto* noteCard = ui::cardAlt();
    auto* nv = new QVBoxLayout(noteCard);
    nv->setContentsMargins(18, 14, 18, 14);
    nv->setSpacing(6);
    nv->addWidget(ui::label(u("更新是怎么做的"), "title"));
    nv->addWidget(wrapped(u("只连 GitHub:先查 YARA Forge 的最新发布,有新版本才下载规则包(约 2 MB),"
                            "按发布页给出的 SHA-256 校验后,交给独立的编译程序解压、编译。"
                            "编译程序在受限的子进程里运行,出问题只影响它自己;"
                            "任何一步失败,或新规则数量明显异常,都会继续用现有规则。"),
                          "secondary"));
    auto* detectionNote = wrapped(QString(), "secondary");
    nv->addWidget(detectionNote);
    v->addWidget(noteCard);
    v->addStretch();

    QPointer<QWidget> pageGuard(page);

    const auto kv = [](QGridLayout* g, int row, const QString& key, QWidget* value) {
        auto* k = ui::label(key, "muted");
        k->setMinimumWidth(84);
        g->addWidget(k, row, 0, Qt::AlignTop);
        g->addWidget(value, row, 1);
    };

    const auto render = [=]() {
        if (!pageGuard)
            return;
        const YaraRulesStatusPayload& s = st->last;
        const bool working = busy(s);
        const bool haveRules = s.rulesCompiled > 0;
        const bool bundledInUse = !haveRules && !s.scan.rulesLabel.isEmpty();

        // 总览
        if (!s.featureEnabled)
            headline->setText(u("规则联网更新已在部署配置中关闭"));
        else if (!s.compilerAvailable)
            headline->setText(u("缺少辅助程序,规则没法更新"));
        else if (working)
            headline->setText(stageText(s.stage));
        else if (haveRules)
            headline->setText(u("规则库就绪:%1 条 YARA 规则").arg(number(s.rulesCompiled)));
        else if (bundledInUse)
            headline->setText(u("暂用安装包内置的规则"));
        else if (s.lastCheckFailed)
            headline->setText(u("还没有可用的规则:上次更新失败"));
        else
            headline->setText(u("还没有下载规则"));

        QString sub;
        if (working && !s.stageDetail.isEmpty())
            sub = s.stageDetail;
        else if (haveRules)
            sub = u("YARA Forge %1 · %2 规则包 · 更新于 %3")
                      .arg(s.releaseTag, s.package, fmt::relativeTime(s.lastSuccessUtc));
        else if (!s.featureEnabled)
            sub = u("appsettings.json 里的 YaraRules.Enabled 为 false:服务不会联网检查或下载规则。");
        else if (!s.compilerAvailable)
            sub = u("安装目录里没有 bulwark_yarac.exe。重新安装,或用 cpp\\scripts\\package.ps1 重新打包。");
        else if (bundledInUse)
            sub = u("%1。联网更新成功后自动换成最新版。").arg(s.scan.rulesLabel);
        else
            sub = u("服务启动约 1.5 分钟后会自动检查;也可以点右上角「立即更新」。");
        subline->setText(sub);

        QString msg = s.message;
        if (s.lastCheckUtc.isValid())
            msg = u("上次检查 %1%2").arg(fmt::relativeTime(s.lastCheckUtc),
                                        s.message.isEmpty() ? QString() : u(":") + s.message);
        messageLine->setText(msg);
        messageLine->setVisible(!msg.isEmpty());
        messageLine->setStyleSheet(s.lastCheckFailed
                                       ? QStringLiteral("color:%1;").arg(theme::warning().name())
                                       : QString());
        tile->set(QStringLiteral("layers"),
                  s.lastCheckFailed && !haveRules ? theme::warning() : (haveRules ? hue : theme::textMuted()));

        {
            const QSignalBlocker block(autoSw);
            autoSw->setChecked(s.autoUpdate);
        }
        autoSw->setEnabled(s.featureEnabled);
        if (!s.featureEnabled)
            autoCaption->setText(u("部署配置已关闭联网更新"));
        else if (!s.autoUpdate)
            autoCaption->setText(u("已关闭:只在点「立即更新」时联网"));
        else if (s.nextCheckUtc.isValid())
            autoCaption->setText(u("每 %1 小时检查一次 · 下次 %2")
                                     .arg(s.checkIntervalHours)
                                     .arg(s.nextCheckUtc.toLocalTime().toString(QStringLiteral("MM-dd HH:mm"))));
        else
            autoCaption->setText(u("每 %1 小时检查一次").arg(s.checkIntervalHours));

        if (pipeline)
            pipeline->setStatus(s);

        updateBtn->setEnabled(s.featureEnabled && s.compilerAvailable && !working && ipc->isConnected());
        updateBtn->setText(working ? u("更新中…") : u("立即更新"));
        updateBtn->setToolTip(!s.featureEnabled ? u("部署配置关闭了 YARA 规则联网更新(YaraRules.Enabled)。")
                              : !s.compilerAvailable ? u("辅助程序 bulwark_yarac.exe 不在安装目录。")
                                                     : QString());
        folderBtn->setEnabled(!s.dataDir.isEmpty());

        // 进程启动扫描
        clearLayout(scanBody);
        const YaraScanStatusPayload& sc = s.scan;
        scanCount->setText(sc.scannedFiles > 0 ? u("已扫描 %1 个程序").arg(number(sc.scannedFiles)) : QString());
        if (scanBadgeLabel) {
            const QPair<QString, QColor> badge = scanBadge(sc);
            ui::stylePill(scanBadgeLabel, badge.first, badge.second);
        }
        {
            auto* gw = new QWidget;
            auto* g = new QGridLayout(gw);
            g->setContentsMargins(0, 0, 0, 0);
            g->setHorizontalSpacing(16);
            g->setVerticalSpacing(8);
            g->setColumnStretch(1, 1);
            int row = 0;
            auto* state = wrapped(scanStateText(sc), "secondary");
            if (sc.state == QLatin1String("error") || sc.state == QLatin1String("paused"))
                state->setStyleSheet(QStringLiteral("color:%1;").arg(theme::warning().name()));
            kv(g, row++, u("状态"), state);
            if (!sc.rulesLabel.isEmpty())
                kv(g, row++, u("使用规则"),
                   wrapped(sc.rulesLoaded > 0 ? u("%1 · %2 条").arg(sc.rulesLabel, number(sc.rulesLoaded))
                                              : sc.rulesLabel,
                           "secondary"));
            kv(g, row++, u("判恶意"),
               wrapped(sc.verifiedRulePatterns > 0
                           ? u("YaraRules.MaliciousRules 里列了 %1 条已验证的家族规则,命中即处置")
                                 .arg(sc.verifiedRulePatterns)
                           : u("没有配置已验证的家族规则:所有命中都只按可疑处理,不会因此结束或隔离任何程序"),
                       "secondary"));
            kv(g, row++, u("统计"),
               wrapped(u("可疑 %1 · 恶意 %2 · 没扫成 %3 · 排队 %4")
                           .arg(number(sc.suspiciousFiles), number(sc.maliciousFiles), number(sc.failedScans),
                                number(sc.pendingScans)),
                       "secondary"));
            scanBody->addWidget(gw);
        }
        const int shownHits = std::min<int>(titan ? kTitanHitsShown : kHitsShown, sc.recentHits.size());
        if (shownHits > 0) {
            auto* title = ui::label(u("最近命中"), "title");
            title->setContentsMargins(0, 12, 0, 0);
            scanBody->addWidget(title);
        }
        for (int i = 0; i < shownHits; ++i) {
            const YaraScanHitPayload& h = sc.recentHits[i];
            if (i > 0) {
                auto* rule = new QFrame;
                rule->setFixedHeight(1);
                rule->setStyleSheet(QStringLiteral("background:%1;").arg(theme::border().name()));
                scanBody->addWidget(rule);
            }
            if (titan) {
                scanBody->addWidget(titanHitRow(h));
                continue;
            }
            auto* w = new QWidget;
            auto* rv = new QVBoxLayout(w);
            rv->setContentsMargins(0, 8, 0, 8);
            rv->setSpacing(2);
            auto* top = new QHBoxLayout;
            top->setSpacing(10);
            const bool bad = h.level == QLatin1String("malicious");
            top->addWidget(ui::pill(bad ? u("恶意") : u("可疑"), bad ? theme::danger() : theme::warning()), 0,
                           Qt::AlignVCenter);
            auto* name = ui::label(h.rule, "mono");
            name->setTextInteractionFlags(Qt::TextSelectableByMouse);
            top->addWidget(name, 1);
            if (h.timeUtc.isValid())
                top->addWidget(ui::label(fmt::relativeTime(h.timeUtc), "muted"));
            rv->addLayout(top);
            rv->addWidget(wrapped(h.path.isEmpty() ? h.sha256 : h.path, "mono"));
            QStringList meta;
            if (!h.author.isEmpty())
                meta << u("作者 %1").arg(h.author);
            if (h.matchCount > 1)
                meta << u("共命中 %1 条规则").arg(h.matchCount);
            if (!meta.isEmpty())
                rv->addWidget(wrapped(meta.join(u(" · ")), "muted"));
            scanBody->addWidget(w);
        }

        // 当前规则
        clearLayout(rulesBody);
        if (!haveRules) {
            rulesCount->setText(u("暂无"));
            rulesBody->addWidget(wrapped(u("还没有成功编译过规则包。第一次更新成功后,这里会显示版本、条数和规则文件位置。"),
                                         "muted"));
        } else {
            rulesCount->setText(u("%1 条可用").arg(number(s.rulesCompiled)));
            auto* gw = new QWidget;
            auto* g = new QGridLayout(gw);
            g->setContentsMargins(0, 0, 0, 0);
            g->setHorizontalSpacing(16);
            g->setVerticalSpacing(8);
            g->setColumnStretch(1, 1);
            int row = 0;
            kv(g, row++, u("发布版本"),
               wrapped(u("YARA Forge %1 · %2 规则包%3")
                           .arg(s.releaseTag, s.package,
                                s.releasePublishedUtc.isValid()
                                    ? u(" · 发布于 %1").arg(fmt::absoluteTime(s.releasePublishedUtc))
                                    : QString()),
                       "secondary"));
            kv(g, row++, u("编译结果"),
               wrapped(u("包内 %1 条 · 可用 %2 条 · 跳过 %3 条")
                           .arg(number(s.rulesFound), number(s.rulesCompiled), number(s.rulesSkipped)),
                       "secondary"));
            kv(g, row++, u("编译引擎"),
               wrapped(u("%1 · 用时 %2 秒")
                           .arg(s.engine)
                           .arg(QString::number(static_cast<double>(s.compileMs) / 1000.0, 'f', 1)),
                       "secondary"));
            auto* path = wrapped(s.rulesPath, "mono");
            kv(g, row++, u("规则文件"), path);
            kv(g, row++, u("文件大小"),
               wrapped(u("编译后 %1 · 规则包 %2").arg(fmt::bytes(s.compiledBytes), fmt::bytes(s.packageBytes)),
                       "secondary"));
            if (!s.packageSha256.isEmpty()) {
                // 金刚的半宽面板放不下 64 位十六进制(没有断行点),只留头尾,完整值在悬停提示里。
                const bool shorten = titan && s.packageSha256.size() > 28;
                QLabel* sha = wrapped(shorten ? s.packageSha256.left(12) + u("…") + s.packageSha256.right(12)
                                              : s.packageSha256,
                                      "mono");
                if (shorten)
                    sha->setToolTip(s.packageSha256);
                kv(g, row++, u("包 SHA-256"), sha);
            }
            if (s.lastSuccessUtc.isValid())
                kv(g, row++, u("更新时间"), wrapped(fmt::absoluteTime(s.lastSuccessUtc), "secondary"));
            rulesBody->addWidget(gw);
        }

        // 来源
        clearLayout(sourceBody);
        QList<YaraRuleSourcePayload> sources = s.sources;
        std::sort(sources.begin(), sources.end(),
                  [](const YaraRuleSourcePayload& a, const YaraRuleSourcePayload& b) { return a.rules > b.rules; });
        int withRules = 0;
        for (const auto& src : sources)
            withRules += src.rules > 0 ? 1 : 0;
        sourceCount->setText(withRules > 0 ? u("%1 个仓库").arg(withRules) : u("暂无"));
        if (withRules == 0) {
            sourceBody->addWidget(wrapped(u("更新成功后显示各来源仓库贡献的规则条数。"), "muted"));
        } else if (titan) {
            auto* bars = new QWidget;
            auto* bl = new QVBoxLayout(bars);
            bl->setContentsMargins(0, 2, 0, 2);
            bl->setSpacing(3);
            int shown = 0;
            for (const auto& src : sources) {
                if (src.rules <= 0)
                    continue;
                if (shown >= kTitanSourcesShown)
                    break;
                bl->addWidget(new SourceBar(src.repository, src.rules, sources.first().rules));
                ++shown;
            }
            sourceBody->addWidget(bars);
            if (withRules > shown)
                sourceBody->addWidget(wrapped(u("另有 %1 个仓库未列出。").arg(withRules - shown), "muted"));
        } else {
            auto* gw = new QWidget;
            auto* g = new QGridLayout(gw);
            g->setContentsMargins(0, 0, 0, 0);
            g->setHorizontalSpacing(24);
            g->setVerticalSpacing(6);
            int shown = 0;
            for (const auto& src : sources) {
                if (src.rules <= 0)
                    continue;
                if (shown >= kSourcesShown)
                    break;
                auto* cell = new QHBoxLayout;
                cell->setSpacing(8);
                cell->addWidget(ui::label(src.repository, "secondary"), 1);
                cell->addWidget(ui::label(number(src.rules), "caption"));
                g->addLayout(cell, shown / 2, shown % 2);
                ++shown;
            }
            g->setColumnStretch(0, 1);
            g->setColumnStretch(1, 1);
            sourceBody->addWidget(gw);
            if (withRules > shown)
                sourceBody->addWidget(wrapped(u("另有 %1 个仓库未列出。").arg(withRules - shown), "muted"));
        }

        // 跳过的规则
        clearLayout(skipBody);
        if (titan) {
            // 金刚的四块面板固定两行两列:没有被跳过的规则也留着这一块,只说一句。
            skipCount->setText(haveRules ? u("%1 条").arg(number(s.rulesSkipped)) : u("暂无"));
            if (!haveRules || s.skipped.isEmpty()) {
                skipBody->addWidget(wrapped(!haveRules ? u("更新成功后,编译时被剔除的规则会逐条列在这里。")
                                            : s.rulesSkipped > 0 ? u("这一包跳过了 %1 条规则,服务没有给出明细。")
                                                                       .arg(number(s.rulesSkipped))
                                                                 : u("这一包规则全部编译通过,没有被跳过的。"),
                                            "muted"));
            } else {
                const int n = std::min<int>(kTitanSkippedShown, s.skipped.size());
                for (int i = 0; i < n; ++i) {
                    if (i > 0)
                        skipBody->addWidget(rowRule());
                    skipBody->addWidget(titanSkipRow(s.skipped[i]));
                }
                if (s.rulesSkipped > n)
                    skipBody->addWidget(wrapped(u("共 %1 条,只列出前 %2 条;完整清单见规则目录里的 last-compile-report.json。")
                                                    .arg(number(s.rulesSkipped))
                                                    .arg(n),
                                                "muted"));
            }
        } else {
            skipCard->setVisible(haveRules && s.rulesSkipped > 0);
            skipCount->setText(u("%1 条").arg(number(s.rulesSkipped)));
        }
        const int shownSkips = titan ? 0 : std::min<int>(kSkippedShown, s.skipped.size());
        for (int i = 0; i < shownSkips; ++i) {
            const YaraSkippedRulePayload& r = s.skipped[i];
            if (i > 0) {
                auto* rule = new QFrame;
                rule->setFixedHeight(1);
                rule->setStyleSheet(QStringLiteral("background:%1;").arg(theme::border().name()));
                skipBody->addWidget(rule);
            }
            auto* w = new QWidget;
            auto* rv = new QVBoxLayout(w);
            rv->setContentsMargins(0, 8, 0, 8);
            rv->setSpacing(2);
            auto* top = new QHBoxLayout;
            top->setSpacing(10);
            auto* name = ui::label(r.rule, "mono");
            name->setTextInteractionFlags(Qt::TextSelectableByMouse);
            top->addWidget(name, 1);
            if (r.line > 0)
                top->addWidget(ui::label(u("第 %1 行").arg(r.line), "muted"));
            rv->addLayout(top);
            rv->addWidget(wrapped(r.reason, "secondary"));
            skipBody->addWidget(w);
        }
        if (!titan && s.rulesSkipped > shownSkips)
            skipBody->addWidget(wrapped(u("共 %1 条,只列出前 %2 条;完整清单见规则目录里的 last-compile-report.json。")
                                            .arg(number(s.rulesSkipped))
                                            .arg(shownSkips),
                                        "muted"));

        detectionNote->setText(
            s.usedForDetection
                ? u("规则已接入检测:目前只扫进程启动时的程序文件,判级与处置见上方「进程启动扫描」。")
                : u("进程启动扫描没有在运行(%1),规则文件只落盘,不参与检测。").arg(scanStateText(s.scan)));
    };

    const auto refresh = [ipc, headline, st]() {
        if (!ipc->isConnected()) {
            if (!st->haveData)
                headline->setText(u("未连接后台服务"));
            return;
        }
        ipc->requestYaraStatus();
    };

    QObject::connect(ipc, &IpcClient::yaraStatusReceived, page, [st, render](const YaraRulesStatusPayload& p) {
        st->last = p;
        st->haveData = true;
        render();
    });
    QObject::connect(ipc, &IpcClient::yaraActionResult, page,
                     [st, page, refresh](const YaraRulesActionResultPayload& r) {
                         if (!st->inflight.remove(r.requestId))
                             return;
                         ui::notify(page, r.ok ? ui::Tone::Success : ui::Tone::Danger,
                                    r.message.isEmpty() ? (r.ok ? u("已受理。") : u("服务没有给出原因。")) : r.message);
                         refresh();
                     });

    QObject::connect(updateBtn, &QPushButton::clicked, page, [ipc, st, page] {
        if (!ipc->isConnected()) {
            ui::notify(page, ui::Tone::Warning, u("未连接后台服务,没法更新。"));
            return;
        }
        st->inflight.insert(ipc->yaraAction(QStringLiteral("update")));
    });
    QObject::connect(autoSw, &QAbstractButton::toggled, page, [ipc, st, page, autoSw](bool on) {
        if (!ipc->isConnected()) {
            const QSignalBlocker block(autoSw);
            autoSw->setChecked(!on);
            ui::notify(page, ui::Tone::Warning, u("未连接后台服务,改不了这个开关。"));
            return;
        }
        st->inflight.insert(ipc->yaraAction(QStringLiteral("auto"), on));
    });
    QObject::connect(folderBtn, &QPushButton::clicked, page, [st, page] {
        const QString dir = st->last.dataDir;
        if (dir.isEmpty() || !QDir(dir).exists()) {
            ui::notify(page, ui::Tone::Warning, u("规则目录还不存在:服务第一次检查更新时才会创建。"));
            return;
        }
        QDesktopServices::openUrl(QUrl::fromLocalFile(dir));
    });

    pagekit::onConnected(page, ipc, nullptr, 700, refresh);
    QObject::connect(ipc, &IpcClient::connectionChanged, page, [render, st](bool) {
        if (st->haveData)
            render();
    });
    auto* tick = new QTimer(page);
    tick->setInterval(30000);
    QObject::connect(tick, &QTimer::timeout, page, [page, refresh] {
        if (page->isVisible())
            refresh();
    });
    tick->start();
    nav::onArrive(page, QString::fromLatin1(nav::YaraRules), [refresh](const QVariantMap&) { refresh(); });
    return page;
}

}
