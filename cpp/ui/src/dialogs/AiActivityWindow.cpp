#include "dialogs/AiActivityWindow.h"

#include "design/Backdrop.h"
#include "design/Banner.h"
#include "design/Components.h"
#include "design/Confirm.h"
#include "design/Format.h"
#include "design/GlowCard.h"
#include "design/IconTile.h"
#include "design/Inspector.h"
#include "design/ListShell.h"
#include "design/Segmented.h"
#include "design/Theme.h"
#include "widgets/ElidingLabel.h"

#include <QAction>
#include <QClipboard>
#include <QDateTime>
#include <QDesktopServices>
#include <QFileInfo>
#include <QGuiApplication>
#include <QHBoxLayout>
#include <QLabel>
#include <QLayout>
#include <QLineEdit>
#include <QLocale>
#include <QMenu>
#include <QPointer>
#include <QPushButton>
#include <QStringList>
#include <QTimer>
#include <QUrl>
#include <QVBoxLayout>

namespace {

QString u(const char* s) { return QString::fromUtf8(s); }

using Kind = AiCallRecord::Kind;
using Outcome = AiCallRecord::Outcome;

QPointer<AiActivityWindow> g_open;

constexpr int kRefreshCoalesceMs = 250;

QString kindLabel(Kind k)
{
    switch (k) {
    case Kind::ExplainPrompt:  return u("行为询问解读");
    case Kind::ExplainBlocked: return u("拦截通知解读 · 已拦下");
    case Kind::ExplainAlerted: return u("拦截通知解读 · 未拦下");
    case Kind::ExplainTraffic: return u("流量悬浮窗 · AI 分析");
    case Kind::Rules:          return u("AI 生成规则");
    case Kind::Test:           return u("测试连接");
    }
    return u("AI 调用");
}

QString kindGlyph(Kind k)
{
    switch (k) {
    case Kind::Rules:          return QStringLiteral("sliders");
    case Kind::Test:           return QStringLiteral("globe");
    case Kind::ExplainPrompt:
    case Kind::ExplainBlocked:
    case Kind::ExplainAlerted:
    case Kind::ExplainTraffic: break;
    }
    return QStringLiteral("sparkles");
}

struct Badge {
    QString text;
    QColor color;
    bool isEmpty() const { return text.isEmpty(); }
};

Badge outcomeBadge(const AiCallRecord& r)
{
    switch (r.outcome) {
    case Outcome::Ok:      return {u("已调用"), theme::accentAlt()};
    case Outcome::Failed:  return {u("失败"), theme::danger()};
    case Outcome::Cached:  return {r.cachedSimilar ? u("沿用同类") : u("沿用"), theme::success()};
    case Outcome::Skipped: return {u("未调用"), theme::textMuted()};
    }
    return {u("—"), theme::textMuted()};
}

QString outcomeDetail(const AiCallRecord& r)
{
    switch (r.outcome) {
    case Outcome::Ok:
        return u("向模型发出了一次请求并拿到结果,本次消耗了 token。");
    case Outcome::Failed:
        return u("向模型发出了请求但没拿到可用结果。任何失败都 fail-open:不影响实时防护,"
                 "也不会替你猜一个结论。");
    case Outcome::Cached:
        return r.cachedSimilar
                   ? u("没有发请求:沿用了【同类行为】此前的结论(随机文件名之类归并之后内容一致),"
                       "本次没有消耗 token。")
                   : u("没有发请求:沿用了本机解读库里这一条自己此前的结论,本次没有消耗 token。");
    case Outcome::Skipped:
        return u("没有发出任何请求,原因见上面那句话。本次没有消耗 token。");
    }
    return QString();
}

Badge adviceBadge(Kind k, const QString& raw)
{
    const QString a = raw.trimmed().toLower();
    if (a.isEmpty())
        return {};
    const bool block = a == QLatin1String("block");
    const bool allow = a == QLatin1String("allow");
    switch (k) {
    case Kind::ExplainPrompt:
        if (block) return {u("建议拦截"), theme::danger()};
        if (allow) return {u("建议放行"), theme::success()};
        return {u("谨慎处理"), theme::warning()};
    case Kind::ExplainBlocked:
        if (block) return {u("拦得对"), theme::danger()};
        if (allow) return {u("疑似误拦"), theme::warning()};
        return {u("拿不准"), theme::warning()};
    case Kind::ExplainAlerted:
        if (block) return {u("确属危险"), theme::danger()};
        if (allow) return {u("多半无害"), theme::success()};
        return {u("拿不准"), theme::warning()};
    case Kind::ExplainTraffic:
        if (block) return {u("可疑"), theme::danger()};
        if (allow) return {u("看起来正常"), theme::success()};
        return {u("拿不准"), theme::warning()};
    case Kind::Rules:
    case Kind::Test:
        break;
    }
    return {};
}

Badge libraryAdviceBadge(AiExplanation::Advice a)
{
    switch (a) {
    case AiExplanation::Advice::Block:   return {u("倾向拦截"), theme::danger()};
    case AiExplanation::Advice::Allow:   return {u("倾向放行"), theme::success()};
    case AiExplanation::Advice::Caution: return {u("拿不准"), theme::warning()};
    case AiExplanation::Advice::Unknown: break;
    }
    return {};
}

QString secondsText(qint64 ms) { return QString::number(ms / 1000.0, 'f', 1) + QStringLiteral("s"); }

RecordView callView(const AiCallRecord& r)
{
    const Badge oc = outcomeBadge(r);
    const Badge ad = adviceBadge(r.kind, r.advice);
    RecordView v;
    v.icon = kindGlyph(r.kind);
    v.iconColor = oc.color;
    v.title = kindLabel(r.kind) + u(" · ") + r.subject;
    v.subtitle = r.result;
    v.pill = oc.text;
    v.pillColor = oc.color;
    v.time = QDateTime::fromMSecsSinceEpoch(r.atMs);
    const auto chip = [&v](const QString& text, const QColor& c = QColor()) {
        v.chips << text;
        v.chipColors << c;
    };
    if (!ad.isEmpty())
        chip(ad.text, ad.color);
    if (!r.confidence.isEmpty())
        chip(u("置信度 ") + r.confidence);
    if (r.tokens > 0)
        chip(u("%1 tok").arg(r.tokens));
    if (r.elapsedMs > 0)
        chip(secondsText(r.elapsedMs));
    if (r.entryId > 0)
        chip(u("解读 #%1").arg(r.entryId));
    v.tooltip = r.result;
    v.haystack = QStringList{kindLabel(r.kind), r.subject, r.result, oc.text, ad.text,
                             r.confidence, r.model, r.host}
                     .join(QLatin1Char(' '));
    v.key = r.seq;
    return v;
}

RecordView libraryView(const AiScanner::ExplainEntry& e)
{
    const Badge ad = libraryAdviceBadge(e.advice);
    RecordView v;
    v.icon = QStringLiteral("sparkles");
    v.iconColor = ad.isEmpty() ? theme::accentAlt() : ad.color;
    v.title = e.summary.isEmpty() ? u("(这条没有解读文本)") : e.summary;
    v.subtitle = u("本机解读 #%1").arg(e.id);
    v.time = QDateTime::fromMSecsSinceEpoch(e.atMs);
    const auto chip = [&v](const QString& text, const QColor& c = QColor()) {
        v.chips << text;
        v.chipColors << c;
    };
    if (!ad.isEmpty())
        chip(ad.text, ad.color);
    if (!e.confidence.isEmpty())
        chip(u("置信度 ") + e.confidence);
    if (e.namesActor)
        chip(u("仅原样沿用"), theme::warning());
    v.tooltip = e.summary;
    v.haystack = QStringList{e.summary, ad.text, e.confidence, QString::number(e.id)}
                     .join(QLatin1Char(' '));
    v.key = -e.id;   // 解读库用负数:两份数据共用一个 model,键不能撞
    return v;
}

RecordView rowView(const AiActivityRow& row)
{
    return row.fromLibrary ? libraryView(row.entry) : callView(row.call);
}

GlowCard* statTile(const QString& icon, const QColor& hue, const QString& name,
                   QLabel** valueOut, ElidingLabel** noteOut)
{
    auto* c = ui::card();
    c->setGlow(hue, QPointF(1.0, 0.0), 0.7, 0.12);
    auto* v = new QVBoxLayout(c);
    v->setContentsMargins(16, 12, 16, 12);
    v->setSpacing(3);
    auto* top = new QHBoxLayout;
    top->setContentsMargins(0, 0, 0, 0);
    top->addWidget(ui::label(name, "secondary"), 1, Qt::AlignVCenter);
    top->addWidget(ui::iconBadge(icon, hue, 30, 16), 0, Qt::AlignTop);
    v->addLayout(top);
    auto* value = ui::label(QStringLiteral("—"), "stat");
    v->addWidget(value);
    auto* note = ui::elided(QString(), "muted");
    v->addWidget(note);
    if (valueOut)
        *valueOut = value;
    if (noteOut)
        *noteOut = note;
    return c;
}

QString callText(const AiCallRecord& r)
{
    const Badge oc = outcomeBadge(r);
    const Badge ad = adviceBadge(r.kind, r.advice);
    QStringList lines;
    lines << u("时间:") + fmt::absoluteTime(QDateTime::fromMSecsSinceEpoch(r.atMs))
          << u("来源:") + kindLabel(r.kind)
          << u("对象:") + r.subject
          << u("结果:") + oc.text;
    if (!ad.isEmpty())
        lines << u("建议:") + ad.text;
    if (!r.confidence.isEmpty())
        lines << u("置信度:") + r.confidence;
    lines << u("内容:") + r.result;
    lines << u("token:") + QString::number(r.tokens)
          << u("耗时:") + (r.elapsedMs > 0 ? secondsText(r.elapsedMs) : u("—"));
    lines << u("模型:") + (r.model.isEmpty() ? u("(接口默认模型)") : r.model);
    if (!r.host.isEmpty())
        lines << u("主机:") + r.host;
    if (r.entryId > 0)
        lines << u("解读库编号:#") + QString::number(r.entryId);
    return lines.join(QLatin1Char('\n'));
}

QString libraryText(const AiScanner::ExplainEntry& e)
{
    const Badge ad = libraryAdviceBadge(e.advice);
    QStringList lines;
    lines << u("本机解读 #") + QString::number(e.id)
          << u("取得时间:") + fmt::absoluteTime(QDateTime::fromMSecsSinceEpoch(e.atMs));
    if (!ad.isEmpty())
        lines << u("结论:") + ad.text;
    if (!e.confidence.isEmpty())
        lines << u("置信度:") + e.confidence;
    lines << u("解读:") + e.summary
          << u("沿用范围:") + (e.namesActor ? u("仅同一行为原样沿用") : u("同类行为也可沿用"));
    return lines.join(QLatin1Char('\n'));
}

}

AiActivityWindow::AiActivityWindow(AiScanner* ai, QWidget* parent) : QDialog(parent), m_ai(ai)
{
    g_open = this;
    setWindowTitle(u("AI 活动"));
    setAccessibleName(windowTitle());
    Backdrop::install(this);
    resize(1180, 790);
    setMinimumSize(900, 600);
    setSizeGripEnabled(true);

    auto* outer = new QVBoxLayout(this);
    outer->setContentsMargins(20, 16, 20, 18);
    outer->setSpacing(12);

    auto* head = new QHBoxLayout;
    head->setSpacing(14);
    head->addWidget(new IconTile(QStringLiteral("sparkles"), theme::accentAlt(), 42, 21), 0,
                    Qt::AlignTop);
    auto* hc = new QVBoxLayout;
    hc->setSpacing(2);
    hc->addWidget(ui::label(u("AI 活动"), "h2"));
    hc->addWidget(ui::elided(
        u("调用流水只记在内存里,显示的是【本次运行以来】;解读库与 token 账本存在本机,跨重启保留。"),
        "secondary"));
    head->addLayout(hc, 1);
    outer->addLayout(head);

    m_banners = new BannerHost(this);
    if (QLayout* bl = m_banners->layout())
        bl->setContentsMargins(0, 0, 0, 0);
    outer->addWidget(m_banners);

    auto* tiles = new QHBoxLayout;
    tiles->setSpacing(12);
    auto* creditTile = statTile(QStringLiteral("zap"), theme::accentAlt(), u("本月 token 用量"),
                                &m_creditValue, &m_creditNote);
    creditTile->setToolTip(u("账本文件:") + AiScanner::creditFilePath());
    tiles->addWidget(creditTile, 1);
    tiles->addWidget(statTile(QStringLiteral("activity"), theme::periwinkle(), u("本次运行已发请求"),
                              &m_callValue, &m_callNote), 1);
    tiles->addWidget(statTile(QStringLiteral("layers"), theme::cyan(), u("本机解读库"),
                              &m_libValue, &m_libNote), 1);
    tiles->addWidget(statTile(QStringLiteral("cloud"), theme::olive(), u("大模型接口"),
                              &m_apiValue, &m_apiNote), 1);
    outer->addLayout(tiles);

    m_list = new RecordBrowser;
    if (QLayout* ll = m_list->layout())
        ll->setContentsMargins(0, 2, 0, 0);
    m_list->setIdentity(theme::accentAlt());
    m_list->setNeedsConnection(false);
    m_list->setConnected(true);
    m_list->setLoading(false);
    m_list->segments()->addSegment(u("调用流水"), QStringLiteral("calls"));
    m_list->segments()->addSegment(u("解读库"), QStringLiteral("library"));
    m_store = std::make_shared<RecordStore<AiActivityRow>>(m_list->model(), &rowView);
    m_list->setInspectorBuilder([this](Inspector* ins, int row) { buildInspector(ins, row); });
    m_list->setContextMenuBuilder(
        [this](QMenu* menu, const QList<int>& rows) { fillMenu(menu, rows); });
    connect(m_list->segments(), &Segmented::currentChanged, this, [this](int) { rebuild(); });
    outer->addWidget(m_list, 1);

    auto* foot = new QHBoxLayout;
    foot->setSpacing(8);
    auto* dir = ui::button(u("打开数据目录"), "ghost", QStringLiteral("folder"), true);
    dir->setToolTip(QFileInfo(AiScanner::explainCacheFilePath()).absolutePath());
    connect(dir, &QPushButton::clicked, this, [] {
        QDesktopServices::openUrl(
            QUrl::fromLocalFile(QFileInfo(AiScanner::explainCacheFilePath()).absolutePath()));
    });
    auto* clearLog = ui::button(u("清空流水"), "ghost", QStringLiteral("trash"), true);
    clearLog->setToolTip(u("只清掉这张内存里的表,不影响解读库、token 账本和任何防护"));
    connect(clearLog, &QPushButton::clicked, this, [this] {
        if (m_ai->callLog().isEmpty()) {
            m_banners->post(ui::Tone::Info, u("流水已经是空的。"));
            return;
        }
        m_ai->clearCallLog();
        m_banners->post(ui::Tone::Success, u("已清空调用流水(这张表本来就只在内存里)。"));
    });
    auto* clearLib = ui::button(u("清空解读库"), "ghost", QStringLiteral("trash"), true);
    connect(clearLib, &QPushButton::clicked, this, [this] {
        const int n = int(m_library.size());
        if (n <= 0) {
            m_banners->post(ui::Tone::Info, u("解读库已经是空的。"));
            return;
        }
        ui::ConfirmSpec s;
        s.risk = ui::Risk::Caution;
        s.title = u("清空本机解读库");
        s.summary = u("清空后,接下来遇到的行为都要重新问一次大模型才会有解读。");
        s.consequences << u("不影响任何防护:解读本来就只给人看,不参与裁决")
                       << u("代价是接下来一段时间多花一些 token(原本一周内同类行为可以直接沿用)")
                       << u("已显示出去的解读不会撤回");
        s.subjectLabel = u("条目数");
        s.subject = u("%1 条").arg(n);
        s.confirmText = u("清空");
        if (!ui::confirm(this, s))
            return;
        const int removed = m_ai->clearExplainCache();
        m_banners->post(ui::Tone::Success, u("已清空解读库,共 %1 条。").arg(removed));
    });
    auto* close = ui::button(u("关闭"), "primary", QString(), true);
    connect(close, &QPushButton::clicked, this, &QDialog::accept);
    foot->addWidget(dir);
    foot->addStretch();
    foot->addWidget(clearLog);
    foot->addWidget(clearLib);
    foot->addWidget(close);
    outer->addLayout(foot);

    m_refresh = new QTimer(this);
    m_refresh->setSingleShot(true);
    m_refresh->setInterval(kRefreshCoalesceMs);
    connect(m_refresh, &QTimer::timeout, this, [this] {
        rebuild();
        refreshSummary();
    });
    m_library = m_ai->explainEntries();
    m_libraryDirty = false;
    rebuild();
    refreshSummary();

    connect(m_ai, &AiScanner::callLogged, this, [this](const AiCallRecord&) { scheduleRefresh(); });
    connect(m_ai, &AiScanner::callLogCleared, this, [this] { scheduleRefresh(); });
    connect(m_ai, &AiScanner::explainCacheChanged, this, [this] {
        m_libraryDirty = true;
        scheduleRefresh();
    });
    connect(m_ai, &AiScanner::creditUsageChanged, this,
            [this](qint64, qint64) { scheduleRefresh(); });
}

AiActivityWindow::~AiActivityWindow() = default;

void AiActivityWindow::open(QWidget* context, AiScanner* ai)
{
    if (!ai)
        return;
    if (g_open) {
        g_open->showNormal();
        g_open->raise();
        g_open->activateWindow();
        return;
    }
    auto* w = new AiActivityWindow(ai, context ? context->window() : nullptr);
    w->setAttribute(Qt::WA_DeleteOnClose);
    w->show();
}

bool AiActivityWindow::isLibrarySegment() const
{
    return m_list->segments()->currentData().toString() == QLatin1String("library");
}

void AiActivityWindow::scheduleRefresh()
{
    if (m_refresh && !m_refresh->isActive())
        m_refresh->start();
}

void AiActivityWindow::rebuild()
{
    if (m_libraryDirty) {
        m_library = m_ai->explainEntries();
        m_libraryDirty = false;
    }
    const QList<AiCallRecord>& log = m_ai->callLog();
    QList<AiActivityRow> rows;
    if (isLibrarySegment()) {
        rows.reserve(m_library.size());
        for (const AiScanner::ExplainEntry& e : m_library) {
            AiActivityRow row;
            row.fromLibrary = true;
            row.entry = e;
            rows.append(row);
        }
        m_list->searchBox()->setPlaceholderText(u("搜索解读内容 / 结论 / 编号…"));
        m_list->setNoDataContent(
            QStringLiteral("sparkles"), u("本机解读库还是空的"),
            u("「AI 解读」每问到一条结论就在本机存一份,一周内的同类行为直接沿用、不再花 token。"
              "开启设置里的「行为询问 AI 解读」或「拦截通知 AI 解读」之后,这里会慢慢攒起来。"));
    } else {
        rows.reserve(log.size());
        for (qsizetype i = log.size() - 1; i >= 0; --i) {
            AiActivityRow row;
            row.call = log.at(i);
            rows.append(row);
        }
        m_list->searchBox()->setPlaceholderText(u("搜索程序名 / 结论 / 模型…"));
        m_list->setNoDataContent(
            QStringLiteral("activity"), u("本次运行还没有 AI 调用"),
            u("行为询问、拦截通知与流量悬浮窗的「AI 解读」、AI 生成规则"
              "和「测试连接」都会记在这里，包括未发出的请求。"));
    }
    m_store->reset(rows);
    m_list->segments()->setCount(0, int(log.size()));
    m_list->segments()->setCount(1, int(m_library.size()));
}

void AiActivityWindow::refreshSummary()
{
    const QLocale loc;
    int sent = 0, failed = 0, reused = 0, skipped = 0;
    for (const AiCallRecord& r : m_ai->callLog()) {
        switch (r.outcome) {
        case Outcome::Ok:      ++sent; break;
        case Outcome::Failed:  ++failed; break;
        case Outcome::Cached:  ++reused; break;
        case Outcome::Skipped: ++skipped; break;
        }
    }

    const qint64 used = m_ai->creditUsedThisMonth();
    const qint64 budget = m_ai->creditBudget();
    m_creditValue->setText(loc.toString(used));
    if (budget > 0 && m_ai->creditGuardEnabled()) {
        const int pct = int(qMin<qint64>(999, used * 100 / budget));
        m_creditNote->setText(u("预算 %1 · 已用 %2% · 超出后直接跳过请求")
                                  .arg(loc.toString(budget)).arg(pct));
    } else if (budget > 0) {
        m_creditNote->setText(u("预算 %1,但额度守卫未开启:只计数,不会因超出而停止请求")
                                  .arg(loc.toString(budget)));
    } else {
        m_creditNote->setText(u("未设月度预算:只计数,不会因用量而停止请求"));
    }

    m_callValue->setText(loc.toString(sent + failed));
    QStringList callParts;
    callParts << u("其中失败 %1").arg(failed) << u("沿用省下 %1 次").arg(reused)
              << u("未问出去 %1 次").arg(skipped);
    m_callNote->setText(callParts.join(u(" · ")));

    m_libValue->setText(loc.toString(m_library.size()));
    if (m_library.isEmpty()) {
        m_libNote->setText(u("每条保存一周,到期自动清理"));
    } else {
        m_libNote->setText(
            u("最新一条 %1 · 每条保存一周,到期自动清理")
                .arg(fmt::relativeTime(QDateTime::fromMSecsSinceEpoch(m_library.first().atMs))));
    }

    if (!m_ai->configKnown()) {
        m_apiValue->setText(u("读取中…"));
        m_apiNote->setText(u("正在从后台服务取回大模型设置"));
    } else if (!m_ai->isConfigured()) {
        m_apiValue->setText(u("未配置"));
        m_apiNote->setText(u("设置 > AI 辅助 > 大模型接入"));
    } else {
        const QString model = m_ai->modelName();
        m_apiValue->setText(model.isEmpty() ? u("接口默认模型") : model);
        const QString host = m_ai->endpointHost();
        m_apiNote->setText(host.isEmpty() ? u("接口地址格式不对") : host);
    }
}

void AiActivityWindow::buildInspector(Inspector* ins, int sourceRow)
{
    const AiActivityRow* row = m_store->itemAt(sourceRow);
    if (!ins || !row)
        return;

    if (!row->fromLibrary) {
        const AiCallRecord r = row->call;
        const Badge oc = outcomeBadge(r);
        const Badge ad = adviceBadge(r.kind, r.advice);
        ins->setHeader(kindGlyph(r.kind), oc.color, kindLabel(r.kind), r.subject);
        ins->addLead(r.result);

        QVBoxLayout* s = ins->addSection(u("这一次"));
        ins->addField(s, u("结果"), oc.text);
        ins->addText(s, outcomeDetail(r), "muted");
        ins->addField(s, u("时间"), fmt::absoluteTime(QDateTime::fromMSecsSinceEpoch(r.atMs)));
        if (!ad.isEmpty())
            ins->addField(s, u("建议"), ad.text);
        if (!r.confidence.isEmpty())
            ins->addField(s, u("置信度"), r.confidence);
        ins->addField(s, u("token"),
                      r.tokens > 0 ? QString::number(r.tokens) : u("0(本次没有发出请求)"));
        ins->addField(s, u("耗时"), r.elapsedMs > 0 ? secondsText(r.elapsedMs) : u("—"));

        QVBoxLayout* a = ins->addSection(u("接口"));
        ins->addField(a, u("模型"), r.model.isEmpty() ? u("(接口默认模型)") : r.model,
                      Inspector::Mono);
        ins->addField(a, u("主机"), r.host.isEmpty() ? u("—") : r.host,
                      Inspector::Mono | Inspector::Copy);
        ins->addText(a, u("只记主机名:完整接口地址不进这张表,API Key 更不会。"), "muted");

        if (r.entryId > 0) {
            QVBoxLayout* c = ins->addSection(u("本机解读库"));
            ins->addField(c, u("编号"), u("#%1").arg(r.entryId));
            ins->addText(c,
                         u("同一个编号出现在好几条上,说的就是「这还是上次那条本机数据」。"
                           "在「解读库」分段里能找到它,也能在那里把它删掉。"),
                         "muted");
        }
        ins->addAction(QStringLiteral("copy"), u("复制这条记录"), "ghost",
                       [this, sourceRow] { copyRow(sourceRow); });
        ins->setNote(u("这张表只在内存里:界面退出即清空,不落盘。"), theme::textMuted());
        return;
    }

    const AiScanner::ExplainEntry e = row->entry;
    const Badge ad = libraryAdviceBadge(e.advice);
    ins->setHeader(QStringLiteral("sparkles"), ad.isEmpty() ? theme::accentAlt() : ad.color,
                   u("本机解读 #%1").arg(e.id),
                   fmt::relativeTime(QDateTime::fromMSecsSinceEpoch(e.atMs)));
    ins->addLead(e.summary);

    QVBoxLayout* s = ins->addSection(u("这条解读"));
    ins->addField(s, u("取得时间"), fmt::absoluteTime(QDateTime::fromMSecsSinceEpoch(e.atMs)));
    const QDateTime expires = QDateTime::fromMSecsSinceEpoch(e.atMs).addDays(7);
    ins->addField(s, u("到期"), fmt::absoluteTime(expires) + u("(之后不再被沿用)"));
    if (!ad.isEmpty())
        ins->addField(s, u("结论"), ad.text);
    if (!e.confidence.isEmpty())
        ins->addField(s, u("置信度"), e.confidence);
    ins->addField(s, u("沿用范围"),
                  e.namesActor ? u("仅同一行为原样沿用") : u("同类行为也可沿用"));
    if (e.namesActor) {
        ins->addText(s,
                     u("这条解读里点到了那次事件自己的随机文件名,安到同类的另一个文件上就文不对题,"
                       "所以它只会被原样沿用。"),
                     "muted");
    }

    QVBoxLayout* w = ins->addSection(u("关于这份数据"));
    ins->addText(w,
                 u("解读库只存【结论 + 提示词的 SHA-256 摘要】,从不存路径、命令行等原文,"
                   "摘要也反推不出原文。它也不记这条结论当初来自行为询问还是拦截通知 —— "
                   "而同一个结论在两处的说法并不一样,所以上面用的是中性说法。"),
                 "muted");
    ins->addField(w, u("文件"), AiScanner::explainCacheFilePath(),
                  Inspector::Mono | Inspector::Copy);

    ins->addAction(QStringLiteral("copy"), u("复制"), "ghost",
                   [this, sourceRow] { copyRow(sourceRow); });
    ins->addAction(QStringLiteral("trash"), u("删除这条解读"), "danger", [this, id = e.id] {
        if (m_ai->forgetExplainEntry(id))
            m_banners->post(ui::Tone::Success,
                            u("已删除解读 #%1,下次遇到同类行为会重新问一次模型。").arg(id));
        else
            m_banners->post(ui::Tone::Warning, u("解读 #%1 已经不在库里了。").arg(id));
    });
    ins->setNote(u("删除只是让下一次同类行为重新问一次模型,不影响任何防护。"), theme::textMuted());
}

void AiActivityWindow::fillMenu(QMenu* menu, const QList<int>& sourceRows)
{
    if (!menu || sourceRows.isEmpty())
        return;
    const int sourceRow = sourceRows.first();
    const AiActivityRow* row = m_store->itemAt(sourceRow);
    if (!row)
        return;
    const QColor ic = theme::textSecondary();
    QObject::connect(menu->addAction(AppIcon::icon(QStringLiteral("copy"), ic, 16), u("复制这条记录")),
                     &QAction::triggered, this, [this, sourceRow] { copyRow(sourceRow); });
    if (!row->fromLibrary)
        return;
    menu->addSeparator();
    const qint64 id = row->entry.id;
    QObject::connect(menu->addAction(AppIcon::icon(QStringLiteral("trash"), ic, 16), u("删除这条解读")),
                     &QAction::triggered, this, [this, id] {
                         if (m_ai->forgetExplainEntry(id))
                             m_banners->post(
                                 ui::Tone::Success,
                                 u("已删除解读 #%1,下次遇到同类行为会重新问一次模型。").arg(id));
                     });
}

void AiActivityWindow::copyRow(int sourceRow)
{
    const AiActivityRow* row = m_store->itemAt(sourceRow);
    if (!row)
        return;
    QClipboard* cb = QGuiApplication::clipboard();
    if (!cb)
        return;
    cb->setText(row->fromLibrary ? libraryText(row->entry) : callText(row->call));
    m_banners->post(ui::Tone::Success, u("已复制到剪贴板。"));
}
