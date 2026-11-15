#include "MainWindow.h"
#include "Bootstrap.h"
#include "Nav.h"
#include "design/Backdrop.h"
#include "design/Banner.h"
#include "design/Cockpit.h"
#include "design/Components.h"
#include "design/Confirm.h"
#include "design/IconTile.h"
#include "design/Icons.h"
#include "design/Identity.h"
#include "design/Motion.h"
#include "design/PageTransition.h"
#include "design/Robot.h"
#include "design/Shell.h"
#include "design/Theme.h"
#include "dialogs/AiActivityWindow.h"
#include "dialogs/PromptDialog.h"
#include "dialogs/RemediationReportDialog.h"
#include "dialogs/ToastNotifier.h"
#include "ipc/IpcClient.h"
#include "pages/CardPages.h"
#include "pages/TablePages.h"
#include "pages/DashboardPage.h"
#include "voice/VoiceAnnouncer.h"
#include "widgets/ResidentBot.h"
#include "widgets/TrafficOverlay.h"

#include "bulwark/Version.h"
#include "bulwark/ipc/Payloads.h"
#include "bulwark/models/Enums.h"
#include "bulwark/models/SecurityEvent.h"

#include <QActionGroup>
#include <QApplication>
#include <QButtonGroup>
#include <QCloseEvent>
#include <QDateTime>
#include <QDialog>
#include <QFileInfo>
#include <QFrame>
#include <QHash>
#include <QHBoxLayout>
#include <QIcon>
#include <QKeySequence>
#include <QLabel>
#include <QLineEdit>
#include <QLocale>
#include <QMenu>
#include <QMouseEvent>
#include <QPainter>
#include <QPropertyAnimation>
#include <QPushButton>
#include <QScreen>
#include <QSet>
#include <QSettings>
#include <QShortcut>
#include <QSignalBlocker>
#include <QStackedWidget>
#include <QSystemTrayIcon>
#include <QTimer>
#include <QUuid>
#include <QVBoxLayout>
#include <QWindow>

#include <algorithm>
#include <cmath>
#include <utility>

namespace {

QString u(const char* s) { return QString::fromUtf8(s); }

// 小垒的台词:机甲版是战报腔,卡哇伊版软一点。
QString line(const char* mecha, const char* kawaii)
{
    return QString::fromUtf8(theme::mecha() ? mecha : kawaii);
}

QIcon buildTrayIcon()
{
    return AppIcon::appBadge();
}

QString stickerIconFor(const QString& key)
{
    static const QHash<QString, QString> map = {
        {QString::fromLatin1(nav::Dashboard), QStringLiteral("dash")},
        {QString::fromLatin1(nav::Events), QStringLiteral("events")},
        {QString::fromLatin1(nav::Timeline), QStringLiteral("timeline")},
        {QString::fromLatin1(nav::Boost), QStringLiteral("boost")},
        {QString::fromLatin1(nav::Processes), QStringLiteral("proc")},
        {QString::fromLatin1(nav::Rules), QStringLiteral("rules")},
        {QString::fromLatin1(nav::Trust), QStringLiteral("trust")},
        {QString::fromLatin1(nav::SoftwareCatalog), QStringLiteral("catalog")},
        {QString::fromLatin1(nav::Quarantine), QStringLiteral("quar")},
        {QString::fromLatin1(nav::Persistence), QStringLiteral("auto")},
        {QString::fromLatin1(nav::Hardening), QStringLiteral("harden")},
        {QString::fromLatin1(nav::YaraRules), QStringLiteral("yara")},
        {QString::fromLatin1(nav::Settings), QStringLiteral("settings")},
    };
    return map.value(key, QStringLiteral("dash"));
}

// 金刚顶栏 / 页标题专用

// 页标题右边的英文代号。
QString titanPageCode(const QString& key)
{
    static const QHash<QString, QString> map = {
        {QString::fromLatin1(nav::Dashboard), QStringLiteral("BRIDGE")},
        {QString::fromLatin1(nav::Events), QStringLiteral("COMBAT LOG")},
        {QString::fromLatin1(nav::Timeline), QStringLiteral("CHRONO")},
        {QString::fromLatin1(nav::Boost), QStringLiteral("TURBO")},
        {QString::fromLatin1(nav::Processes), QStringLiteral("ROSTER")},
        {QString::fromLatin1(nav::Rules), QStringLiteral("PROTOCOL")},
        {QString::fromLatin1(nav::Trust), QStringLiteral("ALLIES")},
        {QString::fromLatin1(nav::SoftwareCatalog), QStringLiteral("REGISTRY")},
        {QString::fromLatin1(nav::Quarantine), QStringLiteral("STASIS")},
        {QString::fromLatin1(nav::Persistence), QStringLiteral("IGNITION")},
        {QString::fromLatin1(nav::Hardening), QStringLiteral("ARMOR UP")},
        {QString::fromLatin1(nav::YaraRules), QStringLiteral("DATABANK")},
        {QString::fromLatin1(nav::Settings), QStringLiteral("CONFIG")},
    };
    return map.value(key);
}

// 键组铭牌右边的英文代号。
QString titanGroupCode(const QString& group)
{
    if (group == u("监控"))
        return QStringLiteral("MONITOR");
    if (group == u("管控"))
        return QStringLiteral("CONTROL");
    if (group == u("其他"))
        return QStringLiteral("MISC");
    return QString();
}

// 线条图标库里没有 "package"(画出来是占位圆点):金刚的键帽和页标题改用 "box"。
QString titanIconFor(const QString& icon)
{
    return icon == QLatin1String("package") ? QStringLiteral("box") : icon;
}

// 页标题色块:仪表盘 / 进程管理 / 设置是能量蓝,规则库是琥珀,其余与 identity::page 一致。
QColor titanPageHue(const QString& key)
{
    if (key == QLatin1String(nav::Dashboard) || key == QLatin1String(nav::Processes)
        || key == QLatin1String(nav::Settings))
        return theme::pal().glow;
    if (key == QLatin1String(nav::YaraRules))
        return theme::pal().amber;
    return identity::page(key);
}

constexpr int kEdgeGrip = 7;

}

MainWindow::MainWindow(QWidget* parent, bool quiet) : QWidget(parent), m_quiet(quiet)
{
    setObjectName(QStringLiteral("Root"));
    setWindowTitle(u("磐垒主动防御"));
    setWindowIcon(AppIcon::appBadge());
    setWindowFlags(Qt::Window | Qt::FramelessWindowHint | Qt::WindowSystemMenuHint
                   | Qt::WindowMinMaxButtonsHint);
    setAttribute(Qt::WA_TranslucentBackground);
    setMouseTracking(true);
    const QMargins in = shell::insets(false);
    // 990:机甲 / 卡哇伊顶部那排导航键帽并排放得下的最窄宽度,再窄键帽上的字会被挤掉。
    setMinimumSize(990 + in.left() + in.right(), 600 + in.top() + in.bottom());
    {
        QSize want(1240 + in.left() + in.right(), 790 + in.top() + in.bottom());
        if (const QScreen* scr = screen())
            want = want.boundedTo(scr->availableGeometry().size() * 0.94);
        resize(want.expandedTo(minimumSize()));
    }

    auto* root = new QVBoxLayout(this);
    root->setSpacing(10);
    root->addWidget(buildTopBar());
    root->addWidget(buildContent(), 1);
    applyShellMargins();
    m_brand->setStartServiceHandler([this] { startBackendFromUi(); });
    // 外壳上的能量宝石 / 信标灯 / 小旗:只重画那几小块。
    m_crownTicker = new motion::Ticker(this, [this](qint64) {
        update(shell::animatedRegion(shellBody(), shellMaximized()));
    }, 50);

    m_ipc = new IpcClient(this);
    // 悬浮窗与常驻机器人要先于页面创建:设置页构造时就要拿到它们来接开关。
    m_traffic = new TrafficOverlay(m_ipc);
    m_resident = new ResidentBot;

    addPage(nav::Dashboard, u("监控"), "dashboard", u("仪表盘"), u("仪表盘"), u("系统防护总览"),
            new DashboardPage(m_ipc));
    addPage(nav::Events, u("监控"), "activity", u("事件记录"), u("事件记录"), u("拦截 · 询问 · 放行的全部安全事件"),
            pages::interceptions(m_ipc));
    addPage(nav::Timeline, u("监控"), "clock", u("时间线"), u("事件时间线"), u("按时间回溯 · 攻击关系图"),
            pages::timeline(m_ipc));
    addPage(nav::Boost, u("管控"), "zap", u("一键加速"), u("一键加速"), u("开机加速 · 内存回收 · 占资源程序"),
            pages::boost(m_ipc));
    addPage(nav::Processes, u("管控"), "target", u("进程管理"), u("进程管理"), u("在跑进程 · 服务与计划任务溯源"),
            pages::processes(m_ipc));
    addPage(nav::Rules, u("管控"), "sliders", u("防护规则"), u("防护规则"), u("自定义放行 / 拦截策略"),
            pages::rules(m_ipc));
    addPage(nav::Trust, u("管控"), "trust", u("信任名单"), u("信任名单"), u("受信任的程序与目录"),
            pages::trust(m_ipc));
    addPage(nav::SoftwareCatalog, u("管控"), "package", u("软件库"), u("软件信任库"),
            u("常用软件画像 · 降低误报"), pages::softwareCatalog());
    addPage(nav::Quarantine, u("管控"), "lock", u("隔离区"), u("隔离区"), u("已隔离的威胁文件"),
            pages::quarantine(m_ipc));
    addPage(nav::Persistence, u("管控"), "power", u("自启动"), u("自启动项"), u("开机持久化审计"),
            pages::persistence(m_ipc));
    addPage(nav::Hardening, u("管控"), "shield", u("系统加固"), u("系统加固"), u("基线体检 · 一键加固 · 劫持防护"),
            pages::hardening(m_ipc));
    addPage(nav::YaraRules, u("管控"), "layers", u("规则库"), u("YARA 规则库"),
            u("自动下载 · 自动编译 · 来源与跳过明细"), pages::yaraRules(m_ipc));
    {
        auto* aiAct = new KeyCap(QStringLiteral("ai"), u("AI 活动"));
        aiAct->setLineIcon(QStringLiteral("cpu"));
        aiAct->setCheckable(false);
        connect(aiAct, &QAbstractButton::clicked, this, [this] {
            // 父窗口可能缩在托盘里,子窗单独 show 落点不可靠 —— 先请回主窗再开(与托盘 toast 同路)。
            showFromTray();
            AiActivityWindow::open(this, m_ipc->aiScanner());
        });
        groupFor(u("其他"))->addKey(aiAct);
    }
    addPage(nav::Settings, u("其他"), "settings", u("设置"), u("设置"), u("防护与情报配置 · 界面风格"),
            pages::settings(m_ipc));

    if (auto* b = m_navGroup->button(0))
        b->setChecked(true);
    onNavClicked(0);

    connect(NavHub::instance(), &NavHub::requested, this,
            [this](const QString& key, const QVariantMap& args) { navigateTo(key, args); });

    auto* find = new QShortcut(QKeySequence::Find, this);
    connect(find, &QShortcut::activated, this, &MainWindow::focusPageSearch);

    m_toasts = new ToastNotifier(this);
    connect(m_traffic, &TrafficOverlay::notice, this, [this](const QString& heading, const QString& detail) {
        if (m_toasts)
            m_toasts->showInfo(heading, detail, 6000);
    });
    m_traffic->applySavedState();

    m_toasts->reserveCorner(m_resident);
    connect(m_resident, &ResidentBot::openMainRequested, this, [this] { showFromTray(); });
    connect(m_resident, &ResidentBot::pageRequested, this, [this](const QString& key) {
        showFromTray();
        navigateTo(key);
    });
    connect(m_resident, &ResidentBot::radarRequested, this, [this] {
        if (m_traffic)
            m_traffic->setOverlayEnabled(!m_traffic->overlayEnabled());
    });
    m_resident->applySavedState();

    m_toasts->setAiScanner(m_ipc->aiScanner());
    // AI 纠错(疑似误拦时信任 / 删规则)要写规则,必须能摸到服务。
    m_toasts->setIpc(m_ipc);
    connect(m_toasts, &ToastNotifier::blockToastClicked, this, [this](bool unenforced) {
        showFromTray();
        // 没拦住的行在事件记录里单独一个页签,跳到「拦截」下反而找不到刚才那一条。
        navigateTo(nav::Events, {{QStringLiteral("segment"),
                                  unenforced ? QStringLiteral("missed") : QStringLiteral("block")}});
    });
    connect(m_ipc, &IpcClient::hijackAlertReceived, this, [this](const bulwark::ipc::HijackAlertPayload& a) {
        if (!m_toasts || a.state != QLatin1String("pending"))
            return;
        m_toasts->showInfo(u("发现疑似劫持:%1").arg(a.title),
                           a.detail.isEmpty() ? a.location : a.detail, 15000, u("去处理"),
                           QStringLiteral("hardening"));
        if (m_resident)
            m_resident->say(robot::Mood::Info, line("发现疑似劫持,请查看!", "好像有东西被动过,去看看?"));
    });
    connect(m_toasts, &ToastNotifier::infoToastActivated, this, [this](const QString& id) {
        if (id == QLatin1String("hardening")) {
            showFromTray();
            navigateTo(nav::Hardening);
            return;
        }
        if (id != QLatin1String("ai-activity"))
            return;
        // 先把主窗口请回来:这条通知多半是在界面缩在托盘里的时候弹的,而 AI 活动窗是它的
        // 子窗口 —— 父窗口藏着的时候单独 show() 一个子窗,落点与层级都不可靠。
        showFromTray();
        AiActivityWindow::open(this, m_ipc->aiScanner());
    });
    connect(m_toasts, &ToastNotifier::blockPresented, VoiceAnnouncer::instance(), &VoiceAnnouncer::announceBlock);
    connect(m_toasts, &ToastNotifier::blockBatchPresented, VoiceAnnouncer::instance(),
            &VoiceAnnouncer::announceBatch);
    setupTray();

    connect(m_ipc, &IpcClient::connectionChanged, this, &MainWindow::setConnected);
    connect(m_ipc, &IpcClient::promptReceived, this, &MainWindow::onPromptReceived);
    connect(m_ipc, &IpcClient::blockNotification, this, &MainWindow::onBlockNotification);
    connect(m_ipc->aiScanner(), &AiScanner::creditExhausted, this,
            [this](qint64 used, qint64 budget) {
                constexpr qint64 kRepeatMs = 6LL * 60 * 60 * 1000;
                const qint64 now = QDateTime::currentMSecsSinceEpoch();
                if (m_aiCreditNoticeMs > 0 && now - m_aiCreditNoticeMs < kRepeatMs)
                    return;
                m_aiCreditNoticeMs = now;
                if (!m_toasts)
                    return;
                const QLocale loc;
                m_toasts->showInfo(
                    u("本月 AI token 额度已用尽"),
                    u("已用 %1 / 预算 %2。AI 解读与 AI 生成规则都已暂停,"
                      "下个月自动恢复;要现在就恢复,需在服务端配置(appsettings.json 的 AI 月度预算 / "
                      "额度守卫)调整——当前界面暂未提供该开关。实时防护与拦截不受影响。")
                        .arg(loc.toString(used), loc.toString(budget)),
                    14000, u("查看 AI 活动"), QStringLiteral("ai-activity"));
            });
    connect(m_ipc, &IpcClient::remediationReport, this, &MainWindow::onRemediationReport);
    connect(m_ipc, &IpcClient::yaraStatusReceived, this, &MainWindow::onYaraStatus);
    connect(m_ipc, &IpcClient::eventLogReceived, this, [this](const bulwark::ipc::EventLogPayload& p) {
        if (p.action == bulwark::VerdictAction::Block)
            bumpBadge(nav::Events);
    });
    connect(m_ipc, &IpcClient::settingsReceived, this,
            [this](const bulwark::RuntimeSettings& s) {
                m_promptTimeoutSeconds = s.promptTimeoutSeconds;
                m_defaultBlock = s.defaultBlock;
                m_promptTimeoutBlockHighRisk = s.promptTimeoutBlockHighRisk;
                m_protectionEnabled = s.protectionEnabled;
                m_protectionFollowsUi = s.protectionFollowsUi;
                m_dimLights = (s.processProtection ? 0x01 : 0) | (s.fileProtection ? 0x02 : 0)
                              | (s.registryProtection ? 0x04 : 0) | (s.networkProtection ? 0x08 : 0)
                              | (s.selfProtection ? 0x10 : 0) | (s.memoryProtectionEnabled ? 0x20 : 0);
                const bool hadSettings = m_haveSettings;
                const bool wasConnected = m_kernelConnected;
                m_kernelConnected = s.kernelConnected;
                m_kernelStatus = s.kernelStatus;
                m_haveSettings = true;
                if (hadSettings && wasConnected != m_kernelConnected && m_toasts) {
                    const QString detail = m_kernelStatus.isEmpty()
                        ? u("请在「设置」里查看当前防护档位。")
                        : m_kernelStatus;
                    if (!m_kernelConnected) {
                        m_toasts->showInfo(u("内核驱动已断开 · 防护已降级"), detail, 12000);
                    } else {
                        m_toasts->showInfo(u("内核驱动已连接 · 行为前拦截恢复"), detail, 6000);
                    }
                }
                refreshProtectionPill();
                refreshQuitAction();
            });
    connect(m_ipc, &IpcClient::manualQuarantineResult, this,
            [this](const bulwark::ipc::ManualQuarantineResultPayload& r) {
                if (m_toasts)
                    m_toasts->showQuarantineRetry(r);
            });

    refreshProtectionPill();
    // 离屏预览工具(PromptPreviewMain)设置此变量:只画界面,绝不连到正在运行的防护服务。
    if (qEnvironmentVariableIsEmpty("BULWARK_UI_NO_IPC"))
        m_ipc->start();
}

MainWindow::~MainWindow()
{
    delete m_traffic;
    m_traffic = nullptr;
    delete m_resident;
    m_resident = nullptr;
}

// 顶栏:品牌 + 键帽导航 + 窗口按钮

QWidget* MainWindow::buildTopBar()
{
    // 金刚:器件之间按原稿收紧(品牌 / 键组 / 窗口按钮间距 9,键组之间 8),默认窗口宽度下刚好放得下带字的键帽;
    // 顶栏比键组高一截,窗口按钮贴顶、键组和品牌贴底。
    const bool titan = theme::titan();
    m_topBar = new QWidget;
    m_topBar->setObjectName(QStringLiteral("RobotTopBar"));
    if (titan)
        m_topBar->setMinimumHeight(80);
    auto* h = new QHBoxLayout(m_topBar);
    h->setContentsMargins(0, 0, 0, 0);
    h->setSpacing(titan ? 9 : 12);

    m_brand = new BrandPanel;
    connect(m_brand, &BrandPanel::clicked, this, [this] { navigateTo(nav::Dashboard); });
    h->addWidget(m_brand, 0, Qt::AlignBottom);

    m_keysRow = new QHBoxLayout;
    m_keysRow->setContentsMargins(0, 0, 0, 0);
    m_keysRow->setSpacing(titan ? 8 : 10);
    h->addLayout(m_keysRow);
    h->addStretch(1);

    const bool m = theme::mecha();
    auto* wb = new QHBoxLayout;
    wb->setContentsMargins(0, 0, 0, 0);
    wb->setSpacing(6);
    auto* minBtn = new HexButton(QStringLiteral("minus"), m ? QColor(0xFF, 0xCF, 0x33) : QColor(0xFF, 0xD9, 0x6B),
                                 u("最小化"));
    connect(minBtn, &QAbstractButton::clicked, this, &QWidget::showMinimized);
    m_maxBtn = new HexButton(QStringLiteral("square"), m ? QColor(0xD4, 0xD1, 0xCA) : QColor(0x7F, 0xE3, 0xC6),
                             u("最大化"));
    connect(m_maxBtn, &QAbstractButton::clicked, this, &MainWindow::toggleMaximize);
    // 金刚的顶栏本身是红色胸甲,关闭键用亮一档的红才分得出来。
    auto* closeBtn = new HexButton(QStringLiteral("x"),
                                   theme::titan() ? QColor(0xFF, 0x6B, 0x75)
                                   : m            ? QColor(0xE5, 0x38, 0x3B)
                                                  : QColor(0xFF, 0x8E, 0x8E),
                                   u("关闭(收进托盘,防护继续)"));
    connect(closeBtn, &QAbstractButton::clicked, this, &QWidget::close);
    wb->addWidget(minBtn);
    wb->addWidget(m_maxBtn);
    wb->addWidget(closeBtn);
    h->addLayout(wb);
    h->setAlignment(wb, Qt::AlignTop);

    m_topBar->installEventFilter(this);
    m_brand->installEventFilter(this);

    m_navGroup = new QButtonGroup(this);
    m_navGroup->setExclusive(true);
    connect(m_navGroup, &QButtonGroup::idClicked, this, &MainWindow::onNavClicked);
    return m_topBar;
}

KeyGroup* MainWindow::groupFor(const QString& title)
{
    for (KeyGroup* g : std::as_const(m_groups))
        if (g->property("bw.group").toString() == title)
            return g;
    auto* g = new KeyGroup(title);
    g->setCode(titanGroupCode(title));
    g->setProperty("bw.group", title);
    g->installEventFilter(this);
    m_groups << g;
    m_keysRow->addWidget(g, 0, Qt::AlignBottom);
    return g;
}

QWidget* MainWindow::buildContent()
{
    auto* content = new Backdrop(Backdrop::Kind::Content);
    m_content = content;
    content->setObjectName(QStringLiteral("Content"));
    content->setFocusPolicy(Qt::ClickFocus);
    auto* v = new QVBoxLayout(content);
    v->setContentsMargins(0, 0, 0, 0);
    v->setSpacing(0);

    auto* top = new QFrame;
    top->setObjectName(QStringLiteral("PageHeader"));
    top->setFixedHeight(theme::metric::topbarH);
    auto* h = new QHBoxLayout(top);
    h->setContentsMargins(theme::metric::pagePad, 12, theme::metric::pagePad, 0);
    h->setSpacing(16);

    auto* titleRow = new QHBoxLayout;
    titleRow->setSpacing(14);
    m_titleTile = new IconTile(QStringLiteral("dashboard"), theme::accent(), 40, 20);
    titleRow->addWidget(m_titleTile, 0, Qt::AlignVCenter);
    auto* tcol = new QVBoxLayout;
    tcol->setSpacing(1);
    m_title = ui::label(QString(), "h1");
    m_subtitle = ui::label(QString(), "secondary");
    if (theme::titan()) {
        // 金刚:标题右边跟一个英文代号(BRIDGE / CONFIG …),与标题下沿对齐。
        auto* line = new QHBoxLayout;
        line->setContentsMargins(0, 0, 0, 0);
        line->setSpacing(10);
        line->addWidget(m_title, 0, Qt::AlignBottom);
        m_titleCode = new QLabel;
        QFont cf;
        cf.setFamilies({QStringLiteral("Bahnschrift"), QStringLiteral("Segoe UI"), QStringLiteral("Microsoft YaHei UI")});
        cf.setPixelSize(10);
        cf.setWeight(QFont::Bold);
        cf.setLetterSpacing(QFont::AbsoluteSpacing, 2.5);
        m_titleCode->setFont(cf);
        m_titleCode->setStyleSheet(QStringLiteral("color:%1;").arg(theme::pal().textDisabled.name()));
        m_titleCode->setContentsMargins(0, 0, 0, 5);
        line->addWidget(m_titleCode, 0, Qt::AlignBottom);
        line->addStretch(1);
        tcol->addLayout(line);
    } else {
        tcol->addWidget(m_title);
    }
    tcol->addWidget(m_subtitle);
    titleRow->addLayout(tcol);
    h->addLayout(titleRow);
    h->addStretch();

    auto* actions = new QWidget;
    m_headerActions = new QHBoxLayout(actions);
    m_headerActions->setContentsMargins(0, 0, 0, 0);
    m_headerActions->setSpacing(8);
    h->addWidget(actions, 0, Qt::AlignVCenter);
    v->addWidget(top);

    m_banners = new BannerHost(content);
    if (QLayout* bl = m_banners->layout())
        bl->setContentsMargins(theme::metric::pagePad, 8, theme::metric::pagePad, 0);
    v->addWidget(m_banners);

    m_stack = new QStackedWidget;
    v->addWidget(m_stack, 1);

    m_pageFx = new PageTransition(content, top, {m_banners, m_stack});
    return content;
}

void MainWindow::addPage(const QString& key, const QString& group, const QString& icon, const QString& nav,
                         const QString& title, const QString& subtitle, QWidget* page)
{
    const int idx = m_stack->count();
    const bool titan = theme::titan();
    const QColor hue = titan ? titanPageHue(key) : identity::page(key);
    auto* btn = new KeyCap(stickerIconFor(key), nav);
    btn->setLineIcon(titanIconFor(icon));
    groupFor(group)->addKey(btn);
    m_navGroup->addButton(btn, idx);
    m_navButtons << btn;
    m_stack->addWidget(page);
    m_titles << title;
    m_subtitles << subtitle;
    m_pageKeys << key;
    m_pageIcons << (titan ? titanIconFor(icon) : icon);
    m_pageHues << hue;

    QWidget* actions = ui::pageActions(page);
    if (actions) {
        m_headerActions->addWidget(actions);
        actions->hide();
    }
    m_pageActions << actions;
}

QString MainWindow::currentKey() const
{
    return m_pageKeys.value(m_stack ? m_stack->currentIndex() : -1);
}

void MainWindow::navigateTo(const QString& pageKey, const QVariantMap& args)
{
    const int idx = m_pageKeys.indexOf(pageKey);
    if (idx < 0)
        return;
    if (auto* b = m_navGroup->button(idx))
        b->setChecked(true);
    onNavClicked(idx);
    NavHub::instance()->deliver(pageKey, args);
}

void MainWindow::onNavClicked(int index)
{
    if (index < 0 || index >= m_stack->count())
        return;
    const bool changing = index != m_stack->currentIndex();
    const bool fading = changing && m_pageFx && m_pageFx->start();
    if (changing && m_banners)
        m_banners->clear(!fading);
    m_stack->setCurrentIndex(index);
    m_titleTile->set(m_pageIcons.value(index), m_pageHues.value(index, theme::accent()));
    m_title->setText(m_titles.value(index));
    if (m_titleCode)
        m_titleCode->setText(titanPageCode(m_pageKeys.value(index)));
    m_subtitle->setText(m_subtitles.value(index));
    for (int i = 0; i < m_pageActions.size(); ++i)
        if (QWidget* a = m_pageActions[i])
            a->setVisible(i == index);
    clearBadge(m_pageKeys.value(index));
    // 旧页面隐藏时 Qt 会按 Tab 顺序把焦点挪给下一个控件,常常落到某颗键帽上顶着焦点框。
    QTimer::singleShot(0, this, [this] {
        if (qobject_cast<KeyCap*>(focusWidget()) && m_content)
            m_content->setFocus(Qt::OtherFocusReason);
    });
}

void MainWindow::focusPageSearch()
{
    QWidget* page = m_stack ? m_stack->currentWidget() : nullptr;
    if (!page)
        return;
    const auto boxes = page->findChildren<QLineEdit*>(QStringLiteral("PageSearch"));
    for (QLineEdit* e : boxes) {
        if (e->isVisible() && e->isEnabled()) {
            e->setFocus(Qt::ShortcutFocusReason);
            e->selectAll();
            return;
        }
    }
}

// 机身:外壳绘制、拖动、缩放、最大化

bool MainWindow::shellMaximized() const
{
    return m_fakeMax || isMaximized() || isFullScreen();
}

QRect MainWindow::bodyRect() const
{
    return rect().marginsRemoved(shell::insets(shellMaximized()));
}

void MainWindow::applyShellMargins()
{
    QLayout* l = layout();
    if (!l)
        return;
    const QMargins in = shell::insets(shellMaximized());
    if (shellMaximized())
        l->setContentsMargins(in.left() + 12, in.top() + 10, in.right() + 12, in.bottom() + 22);
    else
        l->setContentsMargins(in.left() + 16, in.top() + 14, in.right() + 18, in.bottom() + 24);
    if (m_maxBtn)
        m_maxBtn->setToolTip(shellMaximized() ? u("还原") : u("最大化"));
    update();
}

void MainWindow::toggleMaximize()
{
    if (isMaximized() || isFullScreen()) {
        showNormal();
        return;
    }
    if (m_fakeMax) {
        m_fakeMax = false;
        applyShellMargins();
        setGeometry(m_restoreGeometry);
        return;
    }
    const QScreen* scr = screen();
    if (!scr)
        return;
    m_restoreGeometry = geometry();
    m_fakeMax = true;
    applyShellMargins();
    setGeometry(scr->availableGeometry());
}

void MainWindow::syncKeyDensity()
{
    if (!m_topBar || m_navButtons.isEmpty())
        return;
    // 防护状态文字优先于键帽上的字:放不下时先把键帽收成纯图标,还放不下才收起品牌文字。
    const int avail = m_topBar->width();
    const auto keysWidth = [this](bool compact) {
        int w = 0;
        for (KeyGroup* g : std::as_const(m_groups))
            w += g->widthFor(compact);
        return w + m_keysRow->spacing() * qMax(0, int(m_groups.size()) - 1);
    };
    const QLayout* bar = m_topBar->layout();
    const int fixed = (bar ? bar->spacing() * 3 : 36) + 3 * 34 + 2 * 6;
    const int brandFull = m_brand->widthFor(false);
    bool compactKeys = false;
    bool compactBrand = false;
    if (keysWidth(false) + brandFull + fixed > avail) {
        compactKeys = true;
        compactBrand = keysWidth(true) + brandFull + fixed > avail;
    }
    for (KeyGroup* g : std::as_const(m_groups))
        g->setCompact(compactKeys);
    m_brand->setCompact(compactBrand);
    m_compactKeys = compactKeys;
}

Qt::Edges MainWindow::edgesAt(const QPoint& pos) const
{
    if (shellMaximized())
        return {};
    const QRect b = bodyRect();
    Qt::Edges e;
    const bool inY = pos.y() >= b.top() - kEdgeGrip && pos.y() <= b.bottom() + kEdgeGrip;
    const bool inX = pos.x() >= b.left() - kEdgeGrip && pos.x() <= b.right() + kEdgeGrip;
    if (inY && qAbs(pos.x() - b.left()) <= kEdgeGrip)
        e |= Qt::LeftEdge;
    if (inY && qAbs(pos.x() - b.right()) <= kEdgeGrip)
        e |= Qt::RightEdge;
    if (inX && qAbs(pos.y() - b.top()) <= kEdgeGrip)
        e |= Qt::TopEdge;
    if (inX && qAbs(pos.y() - b.bottom()) <= kEdgeGrip)
        e |= Qt::BottomEdge;
    return e;
}

void MainWindow::beginMove(const QPoint& globalPos)
{
    QWindow* w = windowHandle();
    if (!w)
        return;
    if (m_fakeMax || isMaximized()) {
        // 从最大化拖出来:还原尺寸,并让光标停在窗口里相同的相对位置。
        const qreal fx = width() > 0 ? qreal(globalPos.x() - x()) / width() : 0.5;
        QRect g = m_fakeMax ? m_restoreGeometry : normalGeometry();
        if (isMaximized())
            showNormal();
        m_fakeMax = false;
        applyShellMargins();
        g.moveTopLeft(QPoint(globalPos.x() - int(g.width() * fx), globalPos.y() - shell::insets(false).top() - 30));
        setGeometry(g);
    }
    w->startSystemMove();
}

QRectF MainWindow::shellBody() const
{
    const bool max = shellMaximized();
    return QRectF(bodyRect()).adjusted(1.5, 1.5, max ? -1.5 : -7.5, max ? -1.5 : -7.5);
}

void MainWindow::paintEvent(QPaintEvent*)
{
    QPainter p(this);
    const qreal phase = m_crownTicker && m_crownTicker->isActive()
                            ? std::fmod(qreal(motion::clockMs()) / 2400.0, 1.0) : -1.0;
    // 金刚外壳:胸甲画到页面区上沿;示廓灯 = 六个防护维度,状态未知时全灭,防护关闭时转红交替闪。
    shell::Extras ex;
    if (m_content)
        ex.content = QRectF(m_content->geometry());
    ex.mood = m_brandMood;
    if (!m_svcConnected || !m_haveSettings)
        ex.lights = 0;
    else if (!m_protectionEnabled)
        ex.alarm = true;
    else
        ex.lights = m_dimLights;
    shell::paint(p, shellBody(), shellMaximized(), robot::led(robot::Mood(m_brandMood)), phase, ex);
    if (m_content)
        shell::frameContent(p, QRectF(m_content->geometry()));
}

void MainWindow::mousePressEvent(QMouseEvent* event)
{
    if (event->button() == Qt::LeftButton) {
        const Qt::Edges e = edgesAt(event->position().toPoint());
        if (e && windowHandle()) {
            windowHandle()->startSystemResize(e);
            event->accept();
            return;
        }
        beginMove(event->globalPosition().toPoint());
        event->accept();
        return;
    }
    QWidget::mousePressEvent(event);
}

void MainWindow::mouseMoveEvent(QMouseEvent* event)
{
    if (event->buttons() == Qt::NoButton) {
        const Qt::Edges e = edgesAt(event->position().toPoint());
        if (e == (Qt::LeftEdge | Qt::TopEdge) || e == (Qt::RightEdge | Qt::BottomEdge))
            setCursor(Qt::SizeFDiagCursor);
        else if (e == (Qt::RightEdge | Qt::TopEdge) || e == (Qt::LeftEdge | Qt::BottomEdge))
            setCursor(Qt::SizeBDiagCursor);
        else if (e & (Qt::LeftEdge | Qt::RightEdge))
            setCursor(Qt::SizeHorCursor);
        else if (e & (Qt::TopEdge | Qt::BottomEdge))
            setCursor(Qt::SizeVerCursor);
        else
            unsetCursor();
    }
    QWidget::mouseMoveEvent(event);
}

void MainWindow::leaveEvent(QEvent* event)
{
    unsetCursor();
    QWidget::leaveEvent(event);
}

void MainWindow::mouseDoubleClickEvent(QMouseEvent* event)
{
    if (event->button() == Qt::LeftButton && event->position().y() < bodyRect().top() + 80) {
        toggleMaximize();
        event->accept();
        return;
    }
    QWidget::mouseDoubleClickEvent(event);
}

bool MainWindow::eventFilter(QObject* watched, QEvent* event)
{
    // 顶栏的空白、品牌面板、键组标题都是「标题栏」:按住拖动窗口,双击最大化。
    switch (event->type()) {
    case QEvent::MouseButtonPress: {
        auto* me = static_cast<QMouseEvent*>(event);
        if (me->button() == Qt::LeftButton) {
            m_pressPos = me->globalPosition().toPoint();
            m_pressOnChrome = true;
        }
        break;
    }
    case QEvent::MouseMove: {
        auto* me = static_cast<QMouseEvent*>(event);
        if (m_pressOnChrome && (me->buttons() & Qt::LeftButton)
            && (me->globalPosition().toPoint() - m_pressPos).manhattanLength() > 5) {
            m_pressOnChrome = false;
            beginMove(me->globalPosition().toPoint());
            return true;
        }
        break;
    }
    case QEvent::MouseButtonRelease:
        m_pressOnChrome = false;
        break;
    case QEvent::MouseButtonDblClick:
        if (watched != m_brand) {
            toggleMaximize();
            return true;
        }
        break;
    default:
        break;
    }
    return QWidget::eventFilter(watched, event);
}

// 状态

void MainWindow::resizeEvent(QResizeEvent* event)
{
    QWidget::resizeEvent(event);
    QTimer::singleShot(0, this, &MainWindow::syncKeyDensity);
}

bool MainWindow::isViewing(const QString& key) const
{
    return isVisible() && !isMinimized() && currentKey() == key;
}

void MainWindow::bumpBadge(const QString& key)
{
    if (isViewing(key))
        return;
    const int idx = m_pageKeys.indexOf(key);
    if (idx < 0 || idx >= m_navButtons.size())
        return;
    const int n = ++m_unread[key];
    m_navButtons[idx]->setBadge(n);
}

void MainWindow::clearBadge(const QString& key)
{
    if (!m_unread.value(key))
        return;
    m_unread.remove(key);
    const int idx = m_pageKeys.indexOf(key);
    if (idx >= 0 && idx < m_navButtons.size())
        m_navButtons[idx]->setBadge(0);
}

void MainWindow::clearViewedBadge()
{
    if (isVisible() && !isMinimized())
        clearBadge(currentKey());
}

void MainWindow::changeEvent(QEvent* event)
{
    QWidget::changeEvent(event);
    if (event->type() == QEvent::WindowStateChange) {
        if (!isMaximized() && !isFullScreen() && m_fakeMax && !isMinimized()) {
            // 系统把窗口从「假最大化」拖走(贴边分屏等)时,外壳回到普通形态。
            const QScreen* scr = screen();
            if (scr && geometry() != scr->availableGeometry())
                m_fakeMax = false;
        }
        applyShellMargins();
    }
    if (event->type() == QEvent::WindowStateChange || event->type() == QEvent::ActivationChange)
        clearViewedBadge();
    // 窗口被激活时 Qt 按 Tab 顺序把焦点给第一颗键帽,它会一直顶着焦点框;交给页面区。
    if (event->type() == QEvent::ActivationChange && isActiveWindow()) {
        QTimer::singleShot(0, this, [this] {
            if (qobject_cast<KeyCap*>(focusWidget()) && m_content)
                m_content->setFocus(Qt::OtherFocusReason);
        });
    }
}

void MainWindow::showEvent(QShowEvent* event)
{
    emit windowVisibilityIntentChanged(false);
    QWidget::showEvent(event);
    // 从托盘 / 启动时 show():整台机器人淡入。系统还原最小化窗口有自己的动画,不叠加。
    const bool skipIntro = std::exchange(m_skipIntro, false);
    if (!event->spontaneous() && motion::enabled() && !skipIntro) {
        if (!m_intro) {
            m_intro = new QPropertyAnimation(this, "windowOpacity", this);
            m_intro->setEasingCurve(QEasingCurve::OutCubic);
        }
        m_intro->stop();
        m_intro->setDuration(220);
        m_intro->setStartValue(0.0);
        m_intro->setEndValue(1.0);
        setWindowOpacity(0.0);
        m_intro->start();
    }
    if (m_crownTicker)
        m_crownTicker->setActive(true);
    clearViewedBadge();
    QTimer::singleShot(0, this, [this] {
        syncKeyDensity();
        if (qobject_cast<KeyCap*>(focusWidget()) && m_content)
            m_content->setFocus(Qt::OtherFocusReason);
    });
}

void MainWindow::hideEvent(QHideEvent* event)
{
    QWidget::hideEvent(event);
    if (m_intro && m_intro->state() == QAbstractAnimation::Running) {
        m_intro->stop();
        setWindowOpacity(1.0);
    }
    if (m_crownTicker)
        m_crownTicker->setActive(false);
}

bool MainWindow::canRebuild() const
{
    return m_openPrompts.isEmpty() && !QApplication::activeModalWidget();
}

void MainWindow::onPromptReceived(const bulwark::SecurityEvent& event)
{
    const bool timeoutBlocks = bulwark::promptTimeoutShouldBlock(
        m_defaultBlock, m_promptTimeoutBlockHighRisk, event.hasThreatIndicator, event.riskScore);
    PromptDialog dlg(event, this, m_promptTimeoutSeconds, !timeoutBlocks, m_ipc->aiScanner());
    if (m_toasts)
        m_toasts->reserveCorner(&dlg);
    if (m_resident) {
        m_resident->setPending(int(m_openPrompts.size()) + 1);
        m_resident->say(robot::Mood::Ask, line("指挥官,请下令!", "要放行吗?等你回话~"), 0);
    }
    m_openPrompts.insert(event.id, &dlg);
    // 询问带倒计时,到点会自动裁决,而人不一定正盯着屏幕这个角落:用系统提示音提醒一声。
    // 音量与是否静音跟随系统的声音设置。放在这里而不是弹窗类里,离屏预览出图时不会响。
    QApplication::beep();
    dlg.exec();
    m_openPrompts.remove(event.id);      // 栈对象即将离开作用域,指针必须先摘
    if (m_toasts)
        m_toasts->releaseCorner(&dlg);
    if (m_resident) {
        m_resident->setPending(int(m_openPrompts.size()));
        if (m_openPrompts.isEmpty())
            m_resident->say(robot::Mood::Happy, line("收到!", "好哒~"), 1800);
    }
    if (dlg.timedOut()) {
        const auto legacyAction = m_defaultBlock ? bulwark::VerdictAction::Block
                                                 : bulwark::VerdictAction::Allow;
        m_ipc->sendVerdict(event.id, legacyAction, false,
                           bulwark::RememberScope::Permanent, true);
        return;
    }
    const auto action = dlg.allowed() ? bulwark::VerdictAction::Allow
                                      : bulwark::VerdictAction::Block;
    m_ipc->sendVerdict(event.id, action, dlg.remember(),
                       static_cast<bulwark::RememberScope>(dlg.scopeIndex()));
}

void MainWindow::refreshProtectionPill()
{
    if (!m_brand)
        return;

    QString text;
    QColor color;
    QString tip;
    robot::Mood mood = robot::Mood::Sleep;
    // 金刚的品牌面板把状态拆成两行短字 + 一盏指示灯。
    QString brief;
    QString briefSub;
    QColor lamp;

    if (!m_svcConnected || !m_haveSettings) {
        text  = m_svcConnected ? u("正在读取防护配置…") : u("后台服务未连接");
        color = theme::textMuted();
        tip   = u("尚未与后台服务建立连接,无法确认防护状态。");
        mood  = robot::Mood::Sleep;
        brief    = m_svcConnected ? u("自检中") : u("待机");
        briefSub = m_svcConnected ? u("读取配置") : u("服务未连接");
        lamp     = m_svcConnected ? theme::pal().glow : QColor(0x45, 0x4F, 0x5F);
    } else if (!m_protectionEnabled) {
        text  = u("防护已关闭");
        color = theme::danger();
        tip   = u("防护总开关处于关闭状态,系统当前不受保护。可在「设置」中重新开启。");
        mood  = robot::Mood::Alert;
        brief    = u("防护关闭");
        briefSub = u("系统不受保护");
        lamp     = theme::danger();
    } else if (!m_kernelConnected) {
        text  = u("防护开启 · 无内核");
        color = theme::warning();
        brief    = u("半防护");
        briefSub = u("内核未连接");
        lamp     = theme::warning();
        tip   = m_kernelStatus.isEmpty()
                    ? u("防护已开启,但内核驱动未连接:仅有用户态观测与补偿处置,"
                        "缺少「动作发生前阻断」能力。")
                    : m_kernelStatus;
        mood  = robot::Mood::Info;
    } else {
        text  = u("防护开启 · 内核已连接");
        color = theme::textPrimary();
        tip   = m_kernelStatus.isEmpty() ? u("防护已开启,内核驱动已连接。") : m_kernelStatus;
        mood  = robot::Mood::Guard;
        brief    = u("防御中");
        briefSub = u("实时防护");
        lamp     = theme::pal().glow;
    }

    m_brand->setTitanStatus(brief, briefSub, lamp);
    m_brand->setProtection(mood, text, color, tip + u("\n") + bulwark::version::displayString());
    m_brand->setService(m_svcConnected);
    m_brandMood = int(mood);
    update();
    // 「启动服务」按钮的出现 / 消失会改变品牌面板的宽度,顶栏要重新排一次。
    QTimer::singleShot(0, this, &MainWindow::syncKeyDensity);
    if (m_resident)
        m_resident->setStatus(mood, text, tip);

    if (m_tray)
        m_tray->setToolTip(u("磐垒主动防御 — ") + text);
}

// 未验证规则的 YARA 命中只是弱信号:不弹窗,常驻小垒冒个气泡,规则库键帽记未读。
// 家族规则命中另有拦截通知(特征识别战报),这里不重复。
void MainWindow::onYaraStatus(const bulwark::ipc::YaraRulesStatusPayload& status)
{
    QSet<QString> current;
    int fresh = 0;
    for (const bulwark::ipc::YaraScanHitPayload& h : status.scan.recentHits) {
        const QString key = h.sha256 + QLatin1Char('|') + QString::number(h.timeUtc.toMSecsSinceEpoch());
        current.insert(key);
        if (m_yaraBaseline && !m_yaraSeen.contains(key) && h.level != QLatin1String("malicious"))
            ++fresh;
    }
    m_yaraSeen = current;
    m_yaraBaseline = true;
    if (fresh == 0)
        return;
    for (int i = 0; i < fresh; ++i)
        bumpBadge(nav::YaraRules);
    if (m_resident && m_openPrompts.isEmpty())
        m_resident->say(robot::Mood::Info, line("扫描到 %1 个可疑特征", "发现 %1 个可疑特征~").arg(fresh), 6000);
}

void MainWindow::setConnected(bool connected)
{
    const bool was = m_svcConnected;
    m_svcConnected = connected;
    if (!connected)
        m_haveSettings = false;
    m_yaraBaseline = false;
    m_yaraSeen.clear();
    refreshProtectionPill();
    if (connected) {
        if (m_backendStarting) {
            m_backendStarting = false;
            m_brand->setServiceStarting(false);
        }
        if (m_ipc) {
            m_ipc->requestSettings();
            m_ipc->requestYaraStatus();
        }
        return;
    }
    // 服务在运行中掉线:给一条带「启动服务」动作的横幅。
    if (was && !m_backendStarting && m_banners) {
        auto* b = m_banners->post(ui::Tone::Danger,
                                  u("后台服务已断开 · 系统此刻不受本软件保护"));
        if (b)
            b->setAction(u("启动服务"), [this] { startBackendFromUi(); });
    }
}

void MainWindow::startBackendFromUi()
{
    if (m_backendStarting)
        return;
    m_backendStarting = true;
    m_brand->setServiceStarting(true);
    syncKeyDensity();
    using Outcome = bulwark::ui::bootstrap::BackendStartOutcome;
    bulwark::ui::bootstrap::startBackendAsync(
        this, [this](Outcome outcome, const QString& detail) {
            m_backendStarting = false;
            m_brand->setServiceStarting(false);
            syncKeyDensity();
            if (!m_toasts)
                return;
            switch (outcome) {
            case Outcome::AlreadyRunning:
                // 服务在跑但界面还没连上:IpcClient 每秒重连,稍等即可。
                break;
            case Outcome::Started:
                m_toasts->showInfo(u("后台服务已启动"), u("防护已恢复运行。"), 5000);
                break;
            case Outcome::Missing:
                m_toasts->showInfo(u("找不到后台服务"),
                                   u("找不到 bulwark_service.exe,它需要与界面在同一目录。"), 8000);
                break;
            case Outcome::Refused:
                m_toasts->showInfo(u("已取消启动后台服务"),
                                   u("需要管理员权限才能启动防护服务。在提权提示里选「是」后即可启动。"),
                                   8000);
                break;
            case Outcome::Failed:
                m_toasts->showInfo(u("后台服务未能启动"),
                                   detail.isEmpty() ? u("详见 %ProgramData%\\Bulwark\\service.log。")
                                                    : detail,
                                   12000);
                break;
            }
        });
}

void MainWindow::onBlockNotification(const bulwark::SecurityEvent& event,
                                     bulwark::EnforcementOutcome enforcement,
                                     bool timeoutBlock, bool execBlocked)
{
    if (m_toasts)
        m_toasts->showBlock(event, enforcement, timeoutBlock, execBlocked);
    if (m_resident) {
        m_resident->setBlocked(++m_blockedToday);
        // 受保护目录拒掉一次普通写入不是「击退威胁」:计数照记,不喊。
        if (!ToastNotifier::isGuardedWriteDenial(event, enforcement, timeoutBlock, execBlocked))
            m_resident->say(robot::Mood::Alert, line("威胁已击退!", "坏东西被我挡住啦!"), 4500);
    }
}

void MainWindow::onRemediationReport(const bulwark::ipc::RemediationReportPayload& report)
{
    static QHash<QString, qint64> recentReports;
    const qint64 nowMs = QDateTime::currentMSecsSinceEpoch();
    const QString rkey = report.actorPath.isEmpty() ? report.reason : report.actorPath;
    const auto rit = recentReports.find(rkey);
    if (rit != recentReports.end() && nowMs - rit.value() < 30000) {
        rit.value() = nowMs;
        return;
    }
    recentReports.insert(rkey, nowMs);
    if (recentReports.size() > 512) {
        for (auto i = recentReports.begin(); i != recentReports.end(); ) {
            if (nowMs - i.value() > 30000) i = recentReports.erase(i);
            else ++i;
        }
    }

    if (m_toasts)
        m_toasts->showRemediation(report);
    if (m_resident)
        m_resident->say(robot::Mood::Happy, line("清场完毕!", "打扫干净啦~"), 3500);

    (new RemediationReportDialog(report, m_ipc, this))->show();
}

void MainWindow::setupTray()
{
    if (!qEnvironmentVariableIsEmpty("BULWARK_UI_NO_IPC"))
        return;
    if (!QSystemTrayIcon::isSystemTrayAvailable()) {
        if (m_trayRetries++ < 30) {
            QTimer::singleShot(1000, this, &MainWindow::setupTray);
            return;
        }
        return;
    }
    if (m_tray)
        return;

    m_tray = new QSystemTrayIcon(this);
    m_tray->setIcon(buildTrayIcon());
    m_tray->setToolTip(u("磐垒主动防御"));

    auto* menu = new QMenu(this);
    auto* actShow = menu->addAction(u("显示主界面"));
    auto* actScan = menu->addAction(u("扫描自启动项"));
    m_actTraffic = menu->addAction(u("桌面流量悬浮窗"));
    m_actTraffic->setCheckable(true);
    m_actTraffic->setChecked(m_traffic && m_traffic->overlayEnabled());
    connect(m_actTraffic, &QAction::triggered, this, [this](bool on) {
        if (m_traffic)
            m_traffic->setOverlayEnabled(on);
    });
    if (m_traffic) {
        connect(m_traffic, &TrafficOverlay::overlayEnabledChanged, m_actTraffic, [this](bool on) {
            if (!m_actTraffic)
                return;
            const QSignalBlocker block(m_actTraffic);
            m_actTraffic->setChecked(on);
        });
    }
    m_actResident = menu->addAction(u("常驻机器人小垒"));
    m_actResident->setCheckable(true);
    m_actResident->setChecked(m_resident && m_resident->residentEnabled());
    connect(m_actResident, &QAction::triggered, this, [this](bool on) {
        if (m_resident)
            m_resident->setResidentEnabled(on);
    });
    if (m_resident) {
        connect(m_resident, &ResidentBot::enabledChanged, m_actResident, [this](bool on) {
            if (!m_actResident)
                return;
            const QSignalBlocker block(m_actResident);
            m_actResident->setChecked(on);
        });
    }
    QMenu* skins = menu->addMenu(u("界面风格"));
    auto* skinGroup = new QActionGroup(skins);
    for (const theme::Skin s : {theme::Skin::Mecha, theme::Skin::Kawaii, theme::Skin::Titan}) {
        QAction* a = skins->addAction(theme::skinName(s));
        a->setCheckable(true);
        a->setChecked(theme::skin() == s);
        skinGroup->addAction(a);
        connect(a, &QAction::triggered, this, [s] { theme::requestSkin(s); });
    }
    menu->addSeparator();
    m_actQuit = menu->addAction(QString());
    connect(actShow, &QAction::triggered, this, &MainWindow::showFromTray);
    connect(actScan, &QAction::triggered, this, [this] {
        showFromTray();
        navigateTo(nav::Persistence);
    });
    connect(m_actQuit, &QAction::triggered, this, &MainWindow::quitApp);
    refreshQuitAction();
    m_tray->setContextMenu(menu);

    connect(m_tray, &QSystemTrayIcon::activated, this,
            [this](QSystemTrayIcon::ActivationReason reason) {
                if (reason == QSystemTrayIcon::Trigger
                    || reason == QSystemTrayIcon::DoubleClick)
                    showFromTray();
            });

    m_tray->show();
    refreshProtectionPill();

    if (!m_trayIntroShown && m_toasts && !m_quiet) {
        m_trayIntroShown = true;
        m_toasts->showInfo(
            u("磐垒主动防御 · 防护运行中"),
            u("图标已在系统托盘。若未看到,请点任务栏通知区的 ‘^’ 展开;双击图标可打开主界面。"),
            6000);
    }
}

void MainWindow::showFromTray()
{
    emit windowVisibilityIntentChanged(false);
    show();
    setWindowState((windowState() & ~Qt::WindowMinimized) | Qt::WindowActive);
    raise();
    activateWindow();
    clearViewedBadge();
}

void MainWindow::refreshQuitAction()
{
    if (!m_actQuit)
        return;
    if (!m_haveSettings) {
        m_actQuit->setText(u("退出界面"));
        m_actQuit->setToolTip(u("尚未连上后台服务,无法确认退出后防护是否继续运行。"));
        return;
    }
    if (m_protectionFollowsUi) {
        m_actQuit->setText(u("退出(防护同时停止)"));
        m_actQuit->setToolTip(u("已开启「退出界面即停止防护」:退出后事件监控与处置全部停止,"
                               "内核驱动也会被卸载。要让防护常驻,请在「设置 → 防护总控」里关掉该项。"));
    } else {
        m_actQuit->setText(u("退出界面(防护继续运行)"));
        m_actQuit->setToolTip(u("仅关闭界面,后台防护保持运行。"
                               "想让防护随界面一起停,可在「设置 → 防护总控」里开启"
                               "「退出界面即停止防护」。"));
    }
}

void MainWindow::quitApp()
{
    if (m_protectionFollowsUi && m_haveSettings) {
        ui::ConfirmSpec c;
        c.risk = ui::Risk::Caution;
        c.title = u("退出并停止防护");
        c.summary = u("你开启了「退出界面即停止防护」,所以退出后本软件不再提供任何防护。");
        c.consequences << u("事件监控与处置停止,内核驱动会被卸载")
                       << u("重新打开本程序即恢复全部防护")
                       << u("只想收起窗口的话,点右上角关闭即最小化到托盘,防护照常运行");
        c.confirmText = u("退出并停止防护");
        if (!ui::confirm(this, c))
            return;
    }
    m_forceQuit = true;
    if (m_quitAuthorizer)
        m_quitAuthorizer(u("用户从托盘菜单选择退出"));
    qApp->quit();
}

void MainWindow::reportSelfProtectionEvent(const QString& what, const QString& detail)
{
    qWarning("[WindowGuard] %s - %s", qUtf8Printable(what), qUtf8Printable(detail));
    if (m_toasts)
        m_toasts->showInfo(u("已拦截对本软件的攻击 · ") + what, detail, 7000);
    if (m_resident)
        m_resident->say(robot::Mood::Alert, line("有人想关掉我,已挡住!", "有人想欺负我,被我挡住啦!"), 4500);
}

bool MainWindow::nativeEvent(const QByteArray& eventType, void* message, qintptr* result)
{
    if (m_nativeEventHook && m_nativeEventHook(eventType, message, result))
        return true;
    return QWidget::nativeEvent(eventType, message, result);
}

void MainWindow::closeEvent(QCloseEvent* event)
{
    if (!m_forceQuit && m_tray && QSystemTrayIcon::isSystemTrayAvailable()) {
        if (m_closeToTrayAuthorizer && !m_closeToTrayAuthorizer()) {
            event->ignore();
            return;
        }
        emit windowVisibilityIntentChanged(true);
        hide();
        event->ignore();
        if (!m_trayHintShown && m_toasts) {
            m_trayHintShown = true;
            m_toasts->showInfo(
                u("磐垒仍在后台防护"),
                m_protectionFollowsUi && m_haveSettings
                    ? u("已最小化到系统托盘,防护持续运行 —— 收起窗口不算退出。"
                        "要连防护一起停,请右键托盘图标选「退出」。")
                    : u("已最小化到系统托盘,防护持续运行。右键托盘图标可退出。"),
                4000);
        }
        return;
    }
    if (m_quitAuthorizer)
        m_quitAuthorizer(m_forceQuit ? u("用户确认退出") : u("无系统托盘可用,关闭窗口即退出"));
    event->accept();
    qApp->quit();
}
