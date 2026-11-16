#include "dialogs/PromptDialog.h"
#include "ai/AiScanner.h"
#include "dialogs/AiInsightPanel.h"
#include "dialogs/ExplainCard.h"
#include "dialogs/AttackTimelineWindow.h"
#include "dialogs/EventFormat.h"
#include "dialogs/ThreatCodeView.h"
#include "design/Components.h"
#include "design/Confirm.h"
#include "design/CountdownBar.h"
#include "design/FitScroll.h"
#include "design/FlowLayout.h"
#include "design/Icons.h"
#include "design/Robot.h"
#include "design/Segmented.h"
#include "design/Theme.h"
#include "widgets/WrapLabel.h"

#include <QAbstractButton>
#include <QFrame>
#include <QHBoxLayout>
#include <QKeyEvent>
#include <QLabel>
#include <QPushButton>
#include <QScrollBar>
#include <QShowEvent>
#include <QTimer>
#include <QToolButton>
#include <QVBoxLayout>

using evtfmt::u;

namespace {

constexpr int kCardW = 580;
constexpr int kContentW = kCardW - 48;

// 这张卡片是抢到前台的:刚弹出的这段时间内,落到它身上的点击 / 按键多半是用户本来要给
// 别的窗口的,不能算作裁决。
constexpr int kInputGuardMs = 800;

// 「记住选择」各段的下标。
constexpr int kScopeOnce = 0;
constexpr int kScopePermanent = 4;

// 风险分达到这个值(或带硬指标)的询问,选「永久」放行时要再确认一次。与卡片顶部红色警示带同一条线。
constexpr int kHighRiskScore = 80;

// 屏幕可用高度低于这个值算「矮屏」:常见的询问在这样的屏上放不下,中段要整体滚动
// (1080p 开 125% 缩放约 820,开 150% 约 670,768 线的屏约 720)。
constexpr int kShortScreenHeight = 900;

QWidget* reasonRow(const QString& text, const QColor& color)
{
    auto* w = new QWidget;
    auto* h = new QHBoxLayout(w);
    h->setContentsMargins(0, 0, 0, 0);
    h->setSpacing(10);
    auto* dotBox = new QWidget;
    auto* db = new QVBoxLayout(dotBox);
    db->setContentsMargins(0, 7, 0, 0);
    db->addWidget(ui::statusDot(color));
    h->addWidget(dotBox, 0, Qt::AlignTop);
    auto* l = ui::label(text);
    l->setWordWrap(true);
    l->setTextInteractionFlags(Qt::TextSelectableByMouse);
    h->addWidget(l, 1);
    return w;
}

QWidget* detailRow(const QString& name, const QString& value, bool mono, bool copy)
{
    auto* row = new QWidget;
    auto* h = new QHBoxLayout(row);
    h->setContentsMargins(0, 0, 0, 0);
    h->setSpacing(10);
    auto* k = ui::label(name, "caption");
    k->setFixedWidth(64);
    k->setAlignment(Qt::AlignLeft | Qt::AlignTop);
    h->addWidget(k, 0, Qt::AlignTop);
    const bool empty = value.trimmed().isEmpty();
    auto* v = new WrapLabel(empty ? u("—") : value);
    if (mono && !empty)
        v->setProperty("role", "mono");
    else
        v->setProperty("role", "secondary");
    v->setAccessibleName(name);
    h->addWidget(v, 1);
    if (copy && !empty)
        h->addWidget(ui::copyButton([value] { return value; }, u("复制") + name), 0, Qt::AlignTop);
    return row;
}

QWidget* chipCloud(const QList<QPair<QString, QColor>>& chips)
{
    auto* w = new QWidget;
    auto* flow = new FlowLayout(w, 6, 6);
    for (const auto& [text, color] : chips)
        flow->addWidget(ui::pill(text, color));
    return w;
}

// 拼在裁决按钮后面的范围名(「放行 · 1 小时」);「仅本次」不拼。
QString scopeName(int index)
{
    static const char* const kNames[] = {"", "本次会话", "1 小时", "1 天", "永久"};
    return u(kNames[qBound(kScopeOnce, index, kScopePermanent)]);
}

// 规则按「同一程序 + 同一类动作 + 同一目标」匹配(见 RuleEngine::createRuleFrom),会话级规则不落盘,
// 后台服务一重启就没了(见 RuleStore::save)。这几句话要与那边的实际行为保持一致。
QString scopeHint(int index)
{
    static const char* const kHints[] = {
        "只处理这一次,不保存规则;它再这样做时还会再问。",
        "保存为规则:它再这样做时照此处理,不再询问;到电脑或后台服务下次重启为止。",
        "保存为规则:它再这样做时照此处理,不再询问;1 小时后自动失效。",
        "保存为规则:它再这样做时照此处理,不再询问;1 天后自动失效。",
        "保存为永久规则:它再这样做时一律照此处理,不会过期;要到「防护规则」里手动删除。",
    };
    return u(kHints[qBound(kScopeOnce, index, kScopePermanent)]);
}

}

PromptDialog::PromptDialog(const bulwark::SecurityEvent& event, QWidget* parent,
                           int timeoutSeconds, bool defaultAllow, AiScanner* ai)
    : Sheet(parent), m_event(event), m_timeoutSeconds(timeoutSeconds), m_defaultAllow(defaultAllow)
{
    const bulwark::SecurityEvent& e = m_event;
    const QColor risk = evtfmt::riskColor(e.riskScore);

    // A security question must not end up behind other windows while its
    // countdown runs (the main window may be hidden in the tray).
    setWindowFlag(Qt::WindowStaysOnTopHint, true);
    setPlacement(Placement::BottomRight);
    setSheetWidth(kCardW);
    setCloseButtonVisible(false);
    const bool installer = e.isInstaller;
    // 斑马带的颜色就是轻重:红 = 高危,黄 = 可疑,灰白 / 浅蓝 = 软件安装管控。
    const bool k = !theme::mecha();
    const QColor band = installer          ? (k ? QColor(0xBF, 0xDD, 0xFF) : QColor(0xD4, 0xD1, 0xCA))
                      : e.riskScore >= 80  ? (k ? QColor(0xFF, 0xB3, 0xB8) : QColor(0xE5, 0x38, 0x3B))
                                           : (k ? QColor(0xFF, 0xE3, 0x9A) : QColor(0xFF, 0xCF, 0x33));
    setHazard(band);
    if (installer)
        setEyebrow(u("软件安装管控 · 待确认"), theme::info());
    else
        setEyebrow(u("%1 %2 · 行为防护").arg(evtfmt::riskLevel(e.riskScore)).arg(e.riskScore), risk);
    setMascot(int(installer ? robot::Mood::Info : (e.riskScore >= 80 ? robot::Mood::Alert : robot::Mood::Ask)));
    if (!installer && e.riskScore >= 80)
        setPulse(true);
    if (installer) {
        const QString nm = e.fileDescription.trimmed();
        setTitle(nm.isEmpty() ? u("检测到软件安装,是否允许?")
                              : u("是否允许安装「%1」?").arg(nm));
    } else {
        setTitle(evtfmt::sentence(e, true));
    }
    titleLabel()->setStyleSheet(QStringLiteral("font-size:14pt; font-weight:900; color:%1;")
                                    .arg(theme::textPrimary().name()));
    setWindowTitle(u("行为防护提示"));

    QVBoxLayout* body = this->body();
    body->setSpacing(10);

    auto* path = new WrapLabel(e.actorPath.isEmpty() ? u("(未取得程序路径)")
                                                     : evtfmt::nativePath(e.actorPath));
    path->setProperty("role", "mono");
    path->setAccessibleName(u("发起程序路径"));
    body->addWidget(path);

    QList<QPair<QString, QColor>> facts;
    if (e.actorSigned && !e.signatureMismatch)
        facts << qMakePair(e.actorPublisher.isEmpty() ? u("已签名") : u("已签名 · ") + e.actorPublisher,
                           theme::success());
    else if (e.signatureMismatch)
        facts << qMakePair(u("签名失配"), theme::danger());
    else
        facts << qMakePair(u("无签名"), theme::warning());
    if (e.certRevoked)
        facts << qMakePair(u("证书已吊销"), theme::danger());
    if (e.signedAfterCertExpiry)
        facts << qMakePair(u("证书过期后签名"), theme::danger());
    if (e.isFirstSeen)
        facts << qMakePair(u("本机首见"), theme::warning());
    body->addWidget(chipCloud(facts));

    threatcode::Options codeOpt;
    codeOpt.maxSnippets = 3;
    codeOpt.maxRows = 7;
    QWidget* codeBlock = threatcode::build(e, risk, codeOpt);

    // 离线解释,不联网:这类行为是什么、怎么判断是不是自己的操作、建议怎么做。
    // 下面的 AI 面板要用户自己配好 OpenAI 兼容端点;两者并存,各自标明来源。
    QWidget* explainCard = explaincard::build(e);
    const bool hasExpl = explainCard != nullptr;

    // 解释卡片、「为什么提示」、命中代码和 AI 面板装在同一个可滚动的中段里:屏幕够高时按内容取高,
    // 不够高时(1080p 开 150% 缩放、768 线的屏,可用高度只有 670–730)中段整体滚动,解释卡片排在最上面。
    // 标题、程序路径、记住选择、倒计时和裁决按钮不在中段里,始终可见。
    auto* mid = new QWidget;
    auto* midL = new QVBoxLayout(mid);
    midL->setContentsMargins(0, 0, 0, 0);
    midL->setSpacing(body->spacing());
    auto* midScroll = new FitScrollArea(QWIDGETSIZE_MAX, kContentW);
    midScroll->setContent(mid);
    body->addWidget(midScroll, 1);
    if (hasExpl)
        midL->addWidget(explainCard);

    // 解释卡片占掉一部分高度,相应收窄「为什么提示」的可视区(它本身可滚动)。矮屏上中段要整体滚动,
    // 这块和下面的命中代码不再各自限高,免得两层滚动条套在一起;屏幕够高时照旧限高。
    // 屏幕取鼠标所在的那块,与卡片实际出现的位置一致(见 Sheet::placeOnScreen)。
    const int screenH = Sheet::screenHeightFor(nullptr, 1.0);
    const bool shortScreen = screenH < kShortScreenHeight;
    const double reasonsFrac = hasExpl ? (codeBlock ? 0.20 : 0.26)
                                       : (codeBlock ? 0.26 : 0.34);
    auto* scroll = new FitScrollArea(shortScreen ? QWIDGETSIZE_MAX : int(screenH * reasonsFrac), kContentW);
    auto* ev = new QWidget;
    auto* evl = new QVBoxLayout(ev);
    evl->setContentsMargins(0, 4, 4, 0);
    evl->setSpacing(8);
    evl->setAlignment(Qt::AlignTop);
    evl->addWidget(ui::eyebrow(u("为什么提示")));
    const QStringList& reasons = e.riskReasons;
    constexpr int kMaxReasons = 6;
    int shown = 0;
    for (const QString& r : std::as_const(reasons)) {
        if (shown++ >= kMaxReasons)
            break;
        evl->addWidget(reasonRow(r, risk));
    }
    if (reasons.size() > kMaxReasons)
        evl->addWidget(ui::label(u("… 另有 %1 条,见「查看攻击时间线」")
                                     .arg(reasons.size() - kMaxReasons), "muted"));
    if (reasons.isEmpty())
        evl->addWidget(ui::label(u("引擎评分 %1,未列出具体原因。").arg(e.riskScore), "muted"));
    if (!e.techniques.isEmpty()) {
        QList<QPair<QString, QColor>> tags;
        for (const QString& t : e.techniques)
            tags << qMakePair(t, theme::info());
        auto* cloud = chipCloud(tags);
        cloud->setToolTip(u("ATT&CK 技战术:") + e.techniques.join(QStringLiteral(", ")));
        evl->addWidget(cloud);
    }

    auto* toggle = new QToolButton;
    toggle->setCheckable(true);
    toggle->setCursor(Qt::PointingHandCursor);
    toggle->setToolButtonStyle(Qt::ToolButtonTextBesideIcon);
    toggle->setIconSize(QSize(14, 14));
    toggle->setIcon(AppIcon::icon(QStringLiteral("chevron-right"), theme::textSecondary(), 14));
    toggle->setText(u("展开详情:命令行 · 父进程 · 启动来源 · SHA-256"));
    toggle->setAccessibleName(u("展开详情"));
    evl->addWidget(toggle, 0, Qt::AlignLeft);

    auto* details = ui::cardAlt();
    auto* dl = new QVBoxLayout(details);
    dl->setContentsMargins(14, 12, 14, 12);
    dl->setSpacing(8);
    dl->addWidget(detailRow(u("命令行"), e.commandLine, true, true));
    const QString parentText =
        e.parentPath.isEmpty()
            ? (e.parentPid > 0 ? QStringLiteral("PID %1").arg(e.parentPid) : QString())
            : evtfmt::nativePath(e.parentPath)
                  + (e.parentPid > 0 ? QStringLiteral("  (PID %1)").arg(e.parentPid) : QString());
    dl->addWidget(detailRow(u("父进程"), parentText, true, true));
    const QString origin = e.originLabel();
    dl->addWidget(detailRow(u("启动来源"), origin.isEmpty() ? u("未能判定") : origin, false, false));
    dl->addWidget(detailRow(QStringLiteral("SHA-256"), e.actorHash, true, true));
    if (e.actorPid > 0)
        dl->addWidget(detailRow(QStringLiteral("PID"), QString::number(e.actorPid), true, false));
    details->hide();
    evl->addWidget(details);

    connect(toggle, &QToolButton::toggled, this, [this, toggle, details, scroll, midScroll](bool on) {
        details->setVisible(on);
        toggle->setIcon(AppIcon::icon(on ? QStringLiteral("chevron-down") : QStringLiteral("chevron-right"),
                                      theme::textSecondary(), 14));
        toggle->setText(on ? u("收起详情") : u("展开详情:命令行 · 父进程 · 启动来源 · SHA-256"));
        refit();
        if (on)
            QTimer::singleShot(0, scroll, [scroll, midScroll, toggle, details] {
                scroll->verticalScrollBar()->setValue(toggle->y() - 2);
                // 中段本身在滚动时,把刚展开的详情(连同它上面的「收起详情」)带进可视区。
                midScroll->ensureWidgetVisible(details, 0, toggle->height() + 10);
            });
    });

    scroll->setContent(ev);
    midL->addWidget(scroll, 1);

    if (codeBlock) {
        auto* codeScroll = new FitScrollArea(shortScreen ? QWIDGETSIZE_MAX : int(screenH * 0.22), kContentW);
        codeScroll->setContent(codeBlock);
        midL->addWidget(codeScroll);
    }

    if (ai && ai->isConfigured() && ai->promptExplainEnabled()) {
        auto* panel = new AiInsightPanel(AiExplainContext::Prompt);
        panel->setLoading();
        midL->addWidget(panel);
        const bool hardIndicator = e.hasThreatIndicator;
        ai->explainEvent(e, panel, [this, panel, hardIndicator](const AiExplanation& r) {
            panel->setResult(r, hardIndicator);
            if (isVisible())
                refit();
        });
    }
    body->addWidget(ui::hDivider());

    auto* rememberRow = new QHBoxLayout;
    rememberRow->setSpacing(12);
    rememberRow->addWidget(ui::label(u("记住选择"), "caption"), 0, Qt::AlignVCenter);
    m_scope = new Segmented;
    m_scope->setAccessibleName(u("记住选择的范围"));
    for (const char* s : {"仅本次", "本次会话", "1 小时", "1 天", "永久"})
        m_scope->addSegment(u(s));
    m_scope->setToolTip(u("选「仅本次」之外的范围,会把这次裁决保存为规则"));
    rememberRow->addWidget(m_scope, 0, Qt::AlignVCenter);
    rememberRow->addStretch();

    // 范围的含义直接写在卡片上并跟着选择变:「永久」会留下一条不过期的规则,不能只靠悬停提示说明。
    m_scopeHint = ui::label(QString(), "secondary");
    m_scopeHint->setWordWrap(true);
    m_scopeHint->setAlignment(Qt::AlignLeft | Qt::AlignTop);
    m_scopeHint->setAccessibleName(u("所选范围的说明"));
    // 说明紧贴在范围选择下面(它解释的就是那一行),也少占一点高度。
    auto* scopeBox = new QVBoxLayout;
    scopeBox->setSpacing(4);
    scopeBox->addLayout(rememberRow);
    scopeBox->addWidget(m_scopeHint);
    body->addLayout(scopeBox);
    // 按最长的那句预留高度:切换范围时卡片不能跳动,否则正要点下去的按钮会挪位。
    m_scopeHint->ensurePolished();
    int hintHeight = 0;
    for (int i = kScopeOnce; i <= kScopePermanent; ++i)
        hintHeight = qMax(hintHeight,
                          m_scopeHint->fontMetrics()
                              .boundingRect(QRect(0, 0, kContentW, 4096), Qt::TextWordWrap, scopeHint(i))
                              .height());
    m_scopeHint->setMinimumHeight(hintHeight);
    connect(m_scope, &Segmented::currentChanged, this, [this](int) { syncScopeUi(); });

    if (m_timeoutSeconds > 0) {
        m_countdown = new CountdownBar;
        m_countdown->setColor(m_defaultAllow ? theme::accent() : theme::danger());
        const bool allowByDefault = m_defaultAllow;
        m_countdown->setFormatter([allowByDefault](int s) {
            return allowByDefault ? u("%1 秒后自动放行").arg(s) : u("%1 秒后自动拦截").arg(s);
        });
        body->addWidget(m_countdown);
    }

    auto* timeline = ui::button(u("查看攻击时间线"), "ghost", QStringLiteral("clock"), true);
    timeline->setAutoDefault(false);
    connect(timeline, &QPushButton::clicked, this, [this] {
        AttackTimelineWindow dlg(m_event, this);
        dlg.exec();
    });
    addFooterLeft(timeline);

    m_blockText = installer ? u("阻止安装") : u("拦截");
    m_allowText = installer ? u("允许安装") : u("放行");
    m_blockBtn = addButton(m_blockText, "ghost", [this] { decide(false); });
    m_allowBtn = addButton(m_allowText, "ghost", [this] { decide(true); });
    for (QPushButton* b : {m_blockBtn, m_allowBtn}) {
        b->setMinimumWidth(120);
        b->setMinimumHeight(42);
    }
    syncScopeUi();

    // 视觉重点必须落在真正会发生的那个动作上:有倒计时时强调项 = 超时后的默认动作,
    // 与倒计时条的说明文字一致;没有倒计时(timeoutSeconds<=0)时不会自动裁决,
    // 关窗 / Esc 走的是"拦截"这条保守路径,所以强调项是拦截。
    QPushButton* primaryBtn = (m_timeoutSeconds > 0 && m_defaultAllow) ? m_allowBtn : m_blockBtn;
    QPushButton* secondaryBtn = primaryBtn == m_allowBtn ? m_blockBtn : m_allowBtn;
    // 「拦截」作默认动作时是红色大按钮,「放行 / 允许」作默认动作时是主色大按钮。
    ui::setVariant(primaryBtn, primaryBtn == m_blockBtn ? "danger" : "primary");
    ui::setVariant(secondaryBtn, "ghost");

    // 强调项只是视觉重点,不是「默认键」:两个裁决按钮都不响应卡片级的回车,初始键盘焦点
    // 也不落在它们上面(落在卡片本身)。这张卡片是抢到前台的,用户此刻很可能正在别的窗口里
    // 打字,一个回车或空格不该替他作出「放行」的决定。要用键盘裁决:按 Tab 先到「拦截」、
    // 再到「放行」,然后回车或空格。卡片里其余按钮的 autoDefault 在 showEvent 里统一关掉。
    for (QPushButton* b : {m_blockBtn, m_allowBtn}) {
        b->setAutoDefault(false);
        b->setDefault(false);
    }
    // setTabOrder 要求起点的焦点策略不是 NoFocus;ClickFocus 不占 Tab 停靠位。
    setFocusPolicy(Qt::ClickFocus);
    setTabOrder(this, m_blockBtn);
    setTabOrder(m_blockBtn, m_allowBtn);
    setFocus();

    m_allowBtn->setAccessibleName(installer ? u("允许安装") : u("放行"));
    m_allowBtn->setAccessibleDescription(installer ? u("允许本次软件安装继续")
                                                   : u("允许本次行为继续执行"));
    m_blockBtn->setAccessibleName(installer ? u("阻止安装") : u("拦截"));
    m_blockBtn->setAccessibleDescription(installer ? u("阻止本次软件安装") : u("阻止本次行为"));

    if (m_countdown) {
        connect(m_countdown, &CountdownBar::finished, this, [this] {
            for (QDialog* d : findChildren<QDialog*>())
                if (d->isVisible())
                    d->reject();
            m_timedOut = true;
            decide(m_defaultAllow);
        });
        m_countdown->start(m_timeoutSeconds * 1000);
    }
}

void PromptDialog::showEvent(QShowEvent* event)
{
    // QDialog 在显示时会把焦点链上第一个 autoDefault 的按钮升为默认键(回车即触发)。
    // 这张卡片不要默认键,所以赶在它动手之前把卡片里所有按钮的 autoDefault 关掉。
    for (QPushButton* b : findChildren<QPushButton*>()) {
        b->setAutoDefault(false);
        b->setDefault(false);
    }
    Sheet::showEvent(event);
    if (!m_shownAt.isValid())
        m_shownAt.start();
}

bool PromptDialog::inputGuardActive() const
{
    return m_shownAt.isValid() && m_shownAt.elapsed() < kInputGuardMs;
}

void PromptDialog::keyPressEvent(QKeyEvent* event)
{
    if (inputGuardActive()) {
        event->accept();
        return;
    }
    if (event->key() == Qt::Key_Return || event->key() == Qt::Key_Enter) {
        // 没有默认键:回车只触发当前有键盘焦点的那个按钮;焦点不在按钮上就什么也不做,
        // 也不交给 QDialog(它会去点默认键)。
        if (auto* b = qobject_cast<QAbstractButton*>(focusWidget()); b && b->isEnabled() && b->isVisible())
            b->click();
        event->accept();
        return;
    }
    Sheet::keyPressEvent(event);
}

bool PromptDialog::focusNextPrevChild(bool next)
{
    // Tab 也算在刚弹出时要忽略的输入里:否则本来敲给别的窗口的「Tab、回车」会先把焦点挪到
    // 「拦截」上再触发它。
    if (inputGuardActive())
        return true;
    return Sheet::focusNextPrevChild(next);
}

void PromptDialog::syncScopeUi()
{
    const int index = m_scope ? m_scope->currentIndex() : kScopeOnce;
    const bool once = index <= kScopeOnce;
    const QString suffix = once ? QString() : u(" · ") + scopeName(index);
    if (m_blockBtn)
        m_blockBtn->setText(once && !m_event.isInstaller ? m_blockText + u("!") : m_blockText + suffix);
    if (m_allowBtn)
        m_allowBtn->setText(m_allowText + suffix);
    if (m_scopeHint)
        m_scopeHint->setText(scopeHint(index));
}

bool PromptDialog::needsPermanentAllowConfirm() const
{
    return m_scope && m_scope->currentIndex() == kScopePermanent
           && (m_event.hasThreatIndicator || m_event.riskScore >= kHighRiskScore);
}

ui::ConfirmSpec PromptDialog::permanentAllowConfirmSpec(const bulwark::SecurityEvent& event)
{
    ui::ConfirmSpec c;
    c.risk = ui::Risk::Danger;
    c.title = u("永久放行这个高危行为?");
    c.summary = u("这条询问带有高危迹象(风险分 %1)。永久放行会保存一条不会过期的规则:"
                  "这个程序再这样做时不再询问,直接放行。")
                    .arg(event.riskScore);
    c.consequences = QStringList{
        u("如果它确实是恶意程序,或者以后被替换、被利用,同样的行为不会再被拦下"),
        u("这条规则不会自动失效,要到「防护规则」里手动删除"),
        u("拿不准时,改选「仅本次」或「1 小时」更稳妥"),
    };
    c.subjectLabel = u("程序");
    c.subject = event.actorPath.isEmpty() ? u("(未取得程序路径)") : evtfmt::nativePath(event.actorPath);
    c.confirmText = u("仍然永久放行");
    c.cancelText = u("返回");
    // 倒计时还在走(截止时间由后台服务掌握),这里不再加「我已了解」的勾选;默认焦点仍在「返回」上。
    c.requireAck = false;
    return c;
}

bool PromptDialog::confirmPermanentAllow()
{
    return ui::confirm(this, permanentAllowConfirmSpec(m_event));
}

void PromptDialog::decide(bool allow)
{
    if (!m_timedOut) {
        if (inputGuardActive() || m_confirming)
            return;
        if (allow && needsPermanentAllowConfirm()) {
            m_confirming = true;
            const bool confirmed = confirmPermanentAllow();
            m_confirming = false;
            // 确认框开着的时候,倒计时可能已经到点(那条路径会关掉确认框并自行完成裁决),
            // 询问也可能已被后台撤回(卡片已关):这两种情况都不能再让这次点击改写结果。
            if (!confirmed || m_timedOut || !isVisible())
                return;
        }
        m_decided = true;
    }
    if (m_countdown)
        m_countdown->stop();
    m_allowed = allow;
    accept();
}

// 只有用户亲手点了裁决按钮才保存规则。Esc / 关窗同样按「拦截」处理,但只拦这一次:
// 一次随手的关闭不该顺带留下一条(可能是永久的)规则。
bool PromptDialog::remember() const
{
    return m_decided && m_scope && m_scope->currentIndex() > kScopeOnce;
}

int PromptDialog::scopeIndex() const
{
    switch (m_scope ? m_scope->currentIndex() : 0) {
    case 1: return 1;
    case 2: return 2;
    case 3: return 3;
    default: return 0;
    }
}
