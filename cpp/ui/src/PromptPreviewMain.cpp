// 界面离屏预览工具(默认不构建,见 cpp/ui/CMakeLists.txt 的 BULWARK_BUILD_UI_PREVIEW)。
// 三套皮肤都会出图:主窗口每一页、询问弹窗、拦截通知、流量悬浮窗、常驻机器人;--anim 把各段动画逐帧拼成带时间标注的图。
// fixture 经 RuleEngine::evaluate 真实评估,证据链、技术标注、代码片段都是引擎产出的,不手写 riskReasons。
// 主窗口用假数据,BULWARK_UI_NO_IPC 保证不连真服务;不进发布包、不写系统状态,截图只存到 --out 目录。

#include "MainWindow.h"
#include "Nav.h"
#include "PreviewAudit.h"
#include "UiHost.h"
#include "ai/AiScanner.h"
#include "dialogs/AiActivityWindow.h"
#include "dialogs/AttackGraphWindow.h"
#include "dialogs/AttackTimelineWindow.h"
#include "dialogs/McpServerDialog.h"
#include "dialogs/ProcessDetailDialog.h"
#include "dialogs/RemediationReportDialog.h"
#include "widgets/TrafficDetailWindow.h"
#include "design/Cockpit.h"
#include "design/Confirm.h"
#include "design/Icons.h"
#include "design/ListShell.h"
#include "design/NavButton.h"
#include "design/Segmented.h"
#include "design/Sticker.h"
#include "design/Theme.h"
#include "dialogs/AiInsightPanel.h"
#include "dialogs/EventFormat.h"
#include "dialogs/ExplainCard.h"
#include "dialogs/PromptDialog.h"
#include "dialogs/ThreatCodeView.h"
#include "dialogs/ToastNotifier.h"
#include "dialogs/ToastWindow.h"
#include "ipc/IpcClient.h"
#include "widgets/ResidentBot.h"
#include "widgets/TrafficOverlay.h"

#include "bulwark/Clock.h"
#include "bulwark/engine/DefaultRules.h"
#include "bulwark/engine/RuleEngine.h"
#include "bulwark/models/SecurityEvent.h"

#include <QAbstractItemView>
#include <QApplication>
#include <QDate>
#include <QDialog>
#include <QDir>
#include <QElapsedTimer>
#include <QFileInfo>
#include <QImage>
#include <QMouseEvent>
#include <QPainter>
#include <QPixmap>
#include <QScreen>
#include <QTextStream>
#include <QTime>
#include <QTimeZone>
#include <QTimer>
#include <QToolButton>
#include <QTreeView>

#include <functional>
#include <utility>

using namespace bulwark;
using namespace bulwark::engine;

namespace {

QTextStream& out()
{
    static QTextStream s(stdout);
    s.setEncoding(QStringConverter::Utf8);
    return s;
}

struct Fixture {
    QString name;
    SecurityEvent event;
};

SecurityEvent proc(const QString& actorPath, const QString& cmd, const QString& parentPath,
                   bool signed_, const QString& publisher)
{
    SecurityEvent e;
    e.type = EventType::ProcessCreate;
    e.actorPid = 4242;
    e.actorPath = actorPath;
    e.commandLine = cmd;
    e.target = actorPath.section(QLatin1Char('\\'), -1);
    e.parentPath = parentPath;
    e.parentPid = 1000;
    e.actorSigned = signed_;
    e.actorPublisher = publisher;
    e.actorFileSize = 320 * 1024;
    e.actorHash = QString(64, QLatin1Char('a'));
    e.originKind = ProcessOriginKind::Interactive;
    return e;
}

QList<Fixture> fixtures()
{
    const QString sys = QStringLiteral("C:\\Windows\\System32\\");
    QList<Fixture> v;

    // 1) 有硬指标 + 命令行被 ^ 转义混淆:同时检验「还原后的命令行」片段与解释卡片。
    {
        Fixture f;
        f.name = QStringLiteral("danger-lsass-obfuscated");
        f.event = proc(sys + QStringLiteral("rundll32.exe"),
                       QStringLiteral("r^u^n^d^l^l^3^2.exe C:\\Windows\\System32\\comsvcs.dll, "
                                      "M^i^n^i^D^u^m^p 672 C:\\Users\\u\\AppData\\Local\\Temp\\l.dmp full"),
                       QStringLiteral("C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE"),
                       true, QStringLiteral("Microsoft Corporation"));
        f.event.isFirstSeen = true;
        v << f;
    }

    // 2) 证书被吊销 —— 身份问题优先级最高的那一档,文案最长,最容易把弹窗撑高。
    {
        Fixture f;
        f.name = QStringLiteral("danger-cert-revoked");
        f.event = proc(QStringLiteral("C:\\Users\\u\\AppData\\Roaming\\Sync\\sync_host.exe"),
                       QStringLiteral("sync_host.exe --daemon --server 198.51.100.42:8443"),
                       QStringLiteral("C:\\Windows\\explorer.exe"),
                       true, QStringLiteral("Shanghai Example Network Technology Co., Ltd."));
        f.event.certRevoked = true;
        f.event.isFirstSeen = true;
        f.event.originKind = ProcessOriginKind::LogonAutostart;
        v << f;
    }

    // 3) 只有软信号:未签名 + Temp + 首见。这一档最容易是误报,解释应该说得克制。
    {
        Fixture f;
        f.name = QStringLiteral("caution-unsigned-temp");
        f.event = proc(QStringLiteral("C:\\Users\\u\\AppData\\Local\\Temp\\is-9F2K.tmp\\helper.exe"),
                       QStringLiteral("helper.exe /S /D=\"C:\\Program Files\\App\""),
                       QStringLiteral("C:\\Program Files\\7-Zip\\7zG.exe"),
                       false, QString());
        f.event.isFirstSeen = true;
        v << f;
    }

    // 4) 中间档(Caution):风险分过了可疑线但没有硬指标 —— 实践中最常见的灰区,
    //    也是唯一一档"解释必须自己承认证据不够硬"的情形。靠纯软信号堆到 50 分以上:
    //    未签名 + 可疑目录 + 本机首见 + 异常大的可执行体。
    {
        Fixture f;
        f.name = QStringLiteral("caution-softsignals-only");
        f.event = proc(QStringLiteral("C:\\Users\\u\\AppData\\Local\\Temp\\pack\\svc_helper.exe"),
                       QStringLiteral("svc_helper.exe --install --silent"),
                       QStringLiteral("C:\\Windows\\explorer.exe"),
                       false, QString());
        f.event.isFirstSeen = true;
        f.event.actorFileSize = 95LL * 1024 * 1024;   // 超大未签名可执行体:软信号,需互证
        v << f;
    }

    // 5) 安装程序:语气应为 Info,不该把正常安装说成攻击。
    {
        Fixture f;
        f.name = QStringLiteral("info-installer");
        f.event = proc(QStringLiteral("C:\\Users\\u\\Downloads\\AppSetup_1.4.2.exe"),
                       QStringLiteral("\"C:\\Users\\u\\Downloads\\AppSetup_1.4.2.exe\" /SILENT"),
                       QStringLiteral("C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe"),
                       true, QStringLiteral("Example Software GmbH"));
        f.event.isInstaller = true;
        f.event.fileDescription = QStringLiteral("Example App 安装程序");
        f.event.isFirstSeen = true;
        v << f;
    }

    return v;
}

void settle(int ms)
{
    QElapsedTimer t;
    t.start();
    while (t.elapsed() < ms) {
        QCoreApplication::processEvents(QEventLoop::AllEvents, 10);
        QCoreApplication::sendPostedEvents();
    }
}

bool save(const QPixmap& shot, const QString& dir, const QString& name, int& failed)
{
    const QString path = QDir(dir).filePath(name + QStringLiteral(".png"));
    if (shot.isNull() || !shot.save(path)) {
        out() << "截图失败: " << name << "\n";
        ++failed;
        return false;
    }
    out() << name << "  " << shot.width() << "x" << shot.height() << "  -> " << path << "\n";
    // --audit:每拍一张图,顺手把此刻可见的窗口都体检一遍(文字 / 控件有没有显示不全)。
    previewaudit::scanAll(name);
    return true;
}

// 主窗口出图时的尺寸,--size 宽x高 可改(比如按最小尺寸再拍一遍)。
QSize g_mainSize(1320, 880);

ipc::EventLogPayload logEntry(EventType type, const QString& actor, const QString& target, VerdictAction action,
                              EnforcementOutcome enf, int secsAgo)
{
    ipc::EventLogPayload p;
    p.event.type = type;
    p.event.actorPath = actor;
    p.event.target = target;
    p.event.timestampUtc = QDateTime::currentDateTimeUtc().addSecs(-secsAgo);
    p.event.riskScore = action == VerdictAction::Block ? 92 : (action == VerdictAction::Ask ? 64 : 12);
    p.action = action;
    p.enforcement = enf;
    return p;
}

// 仪表盘 24 小时柱状图的样例:每小时(放行, 询问, 拦截)条数照金刚设计稿,最后一项是当前这个小时。
ipc::TimelineResponsePayload demoTimeline()
{
    static const int kHours[24][3] = {{12, 0, 0}, {8, 0, 0},  {5, 0, 0},   {3, 0, 0},  {4, 0, 0},   {9, 0, 0},
                                      {22, 0, 0}, {41, 1, 0}, {66, 0, 0},  {88, 0, 1}, {97, 0, 0},  {102, 0, 0},
                                      {76, 0, 0}, {91, 0, 2}, {110, 0, 0}, {95, 0, 0}, {84, 0, 0},  {73, 0, 1},
                                      {58, 0, 0}, {49, 0, 0}, {61, 0, 0},  {70, 0, 1}, {52, 1, 4},  {37, 1, 3}};
    ipc::TimelineResponsePayload t;
    const qint64 now = QDateTime::currentMSecsSinceEpoch();
    const qint64 thisHour = now - now % 3600000;
    for (int i = 0; i < 24; ++i) {
        const qint64 start = thisHour - qint64(23 - i) * 3600000;
        const qint64 span = i == 23 ? qMax<qint64>(1, now - start) : 3600000;
        const int allow = kHours[i][0], ask = kHours[i][1];
        const int n = allow + ask + kHours[i][2];
        for (int k = 0; k < n; ++k) {
            const VerdictAction a = k < allow ? VerdictAction::Allow : k < allow + ask ? VerdictAction::Ask : VerdictAction::Block;
            ipc::EventLogPayload e = logEntry(EventType::ProcessCreate, QStringLiteral("C:\\Windows\\explorer.exe"), QString(), a,
                                              a == VerdictAction::Block ? EnforcementOutcome::KernelBlocked
                                                                        : EnforcementOutcome::NotApplicable,
                                              0);
            e.event.timestampUtc = QDateTime::fromMSecsSinceEpoch(start + span * (k + 1) / (n + 1), QTimeZone::UTC);
            t.events.append(e);
        }
    }
    t.scanned = t.matched = int(t.events.size());
    t.truncated = false;
    return t;
}

// 信任名单的样例:照金刚设计稿的 7 条,其中 Python 是今天加的、还剩 48 分钟的临时信任。
QList<DefenseRule> demoTrust()
{
    QList<DefenseRule> list;
    const auto add = [&list](bool dir, const char* path, const char* note, const QDateTime& createdLocal) {
        const QString p = QString::fromUtf8(path), n = QString::fromUtf8(note);
        DefenseRule r = dir ? DefenseRule::createTrustDirectory(p, n) : DefenseRule::createTrust(p, n);
        r.createdUtc = createdLocal.toUTC();
        list << r;
        return &list.last();
    };
    const auto on = [](int month, int day, int h, int m) { return QDateTime(QDate(2026, month, day), QTime(h, m)); };
    add(true, "D:\\Work\\build-tools", "用户手动信任文件夹 · 今后放进这个文件夹的新程序同样不受检测", on(11, 3, 10, 22));
    add(true, "C:\\Program Files\\JetBrains", "用户手动信任文件夹", on(10, 28, 19, 40));
    add(false, "D:\\Tools\\npp\\notepad++.exe", "从事件记录信任", on(11, 12, 23, 46));
    add(false, "C:\\Program Files\\7-Zip\\7zFM.exe", "用户手动信任", on(11, 9, 8, 15));
    add(false, "D:\\Games\\Launcher\\launcher.exe", "从自启动项信任", on(11, 5, 21, 3));
    DefenseRule* py = add(false, "C:\\Users\\User\\AppData\\Local\\Programs\\Python\\python.exe", "纠正误拦 · 1 小时后到期",
                          QDateTime(QDate::currentDate(), QTime(0, 12)));
    py->expiresUtc = QDateTime::currentDateTimeUtc().addSecs(48 * 60 + 30);
    add(false, "C:\\Program Files\\OBS Studio\\bin\\64bit\\obs64.exe", "用户手动信任", on(10, 21, 13, 37));
    return list;
}

QPixmap crop(const QPixmap& full, const QRect& logical);

// 给主窗口喂一份「防护正常、内核已连接、刚拦过一次」的假状态。
void feedDemo(IpcClient* client)
{
    if (!client)
        return;
    emit client->connectionChanged(true);
    RuntimeSettings s;
    s.kernelConnected = true;
    s.kernelStatus = QString::fromUtf8("内核驱动已连接 · 动作发生前拦截 进程 / 文件 / 注册表 / 自保 / 网络");
    emit client->settingsReceived(s);
    emit client->rulesReceived(QList<DefenseRule>(58));
    emit client->quarantineReceived(QList<ipc::QuarantineItemPayload>(5));
    const QString sys = QStringLiteral("C:\\Windows\\System32\\");
    emit client->eventLogReceived(logEntry(EventType::ProcessCreate, QStringLiteral("C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE"),
                                           QStringLiteral("rundll32.exe comsvcs.dll, MiniDump"), VerdictAction::Ask,
                                           EnforcementOutcome::NotApplicable, 1200));
    emit client->eventLogReceived(logEntry(EventType::ProcessCreate, sys + QStringLiteral("rundll32.exe"),
                                           QStringLiteral("comsvcs.dll MiniDump → lsass.exe"), VerdictAction::Block,
                                           EnforcementOutcome::KernelBlocked, 1100));
    emit client->eventLogReceived(logEntry(EventType::FileDelete, QStringLiteral("C:\\Users\\u\\AppData\\Local\\Programs\\Kiro\\Kiro.exe"),
                                           QStringLiteral("C:\\Users\\u\\.kiro\\sessions\\index.lock"), VerdictAction::Allow,
                                           EnforcementOutcome::NotApplicable, 300));
    emit client->eventLogReceived(logEntry(EventType::NetworkConnect, QStringLiteral("C:\\Program Files\\Microsoft Office\\root\\Office16\\OneNoteStorageHelper.exe"),
                                           QStringLiteral("172.67.179.235:443"), VerdictAction::Allow,
                                           EnforcementOutcome::NotApplicable, 60));
    emit client->eventLogReceived(logEntry(EventType::ProcessCreate, QStringLiteral("C:\\Users\\u\\AppData\\Roaming\\Sync\\sync_host.exe"),
                                           QStringLiteral("sync_host.exe --daemon"), VerdictAction::Block,
                                           EnforcementOutcome::AlertedOnly, 30));
    // 只给金刚:机甲 / 卡哇伊的预览图要和基线逐像素一致。放在最后,上面几条实时事件就不会叠进柱子。
    if (theme::titan()) {
        emit client->timelineReceived(demoTimeline());
        emit client->trustReceived(demoTrust());
    }
}

ipc::NetTrafficSnapshotPayload demoTraffic()
{
    ipc::NetTrafficSnapshotPayload s;
    s.totalDownBps = 2'400'000;
    s.totalUpBps = 136'000;
    const auto row = [&](int pid, const char* name, qint64 down, qint64 up) {
        ipc::NetTrafficRowPayload r;
        r.pid = pid;
        r.name = QString::fromLatin1(name);
        r.path = QStringLiteral("C:\\Program Files\\App\\") + r.name;
        r.downBps = down;
        r.upBps = up;
        r.tcpConns = 3;
        s.rows << r;
    };
    row(4120, "msedge.exe", 1'600'000, 96'000);
    row(7300, "Code.exe", 312'000, 18'000);
    row(1880, "svchost.exe", 210'000, 4'100);
    row(9032, "git.exe", 64'000, 12'000);
    row(5512, "WeChat.exe", 46'000, 12'000);
    row(6620, "OneDrive.exe", 22'000, 3'000);
    return s;
}

// 一次自启动项检测的结果(全部虚构):开机加速的分类格子与自启动项页的分组靠它出图。
ipc::PersistenceListResponsePayload demoPersistence()
{
    using C = bulwark::PersistenceCategory;
    ipc::PersistenceListResponsePayload p;
    const auto add = [&p](C c, const char* name, const char* command, std::optional<bool> isSigned,
                          const char* publisher, int risk, const char* reason = nullptr) {
        bulwark::PersistenceEntry e;
        e.id = QString::number(p.entries.size() + 1);
        e.category = c;
        e.name = QString::fromUtf8(name);
        e.command = QString::fromUtf8(command);
        e.isSigned = isSigned;
        e.publisher = QString::fromUtf8(publisher);
        e.riskScore = risk;
        if (reason)
            e.riskReasons << QString::fromUtf8(reason);
        p.entries << e;
    };
    add(C::RegistryRun, "OneDrive", "\"C:\\Program Files\\Microsoft OneDrive\\OneDrive.exe\" /background", true,
        "Microsoft Corporation", 0);
    add(C::RegistryRun, "Steam", "\"C:\\Program Files (x86)\\Steam\\steam.exe\" -silent", true, "Valve Corp.", 0);
    add(C::RegistryRun, "SecurityHealth", "C:\\Windows\\System32\\SecurityHealthSystray.exe", true,
        "Microsoft Windows", 0);
    add(C::RegistryRun, "upd_helper", "C:\\Users\\u\\AppData\\Local\\Temp\\upd\\svc_helper.exe /q", false, "", 62,
        "从临时目录开机自启,且没有签名");
    add(C::StartupFolder, "Snipaste", "C:\\Tools\\Snipaste\\Snipaste.exe", false, "", 0);
    add(C::ScheduledTask, "Adobe Acrobat Update Task",
        "\"C:\\Program Files (x86)\\Common Files\\Adobe\\ARM\\1.0\\AdobeARM.exe\"", true, "Adobe Inc.", 0);
    add(C::ScheduledTask, "MicrosoftEdgeUpdateTaskMachineCore",
        "\"C:\\Program Files (x86)\\Microsoft\\EdgeUpdate\\MicrosoftEdgeUpdate.exe\" /c", true,
        "Microsoft Corporation", 0);
    add(C::ScheduledTask, "SyncTimeTask", "powershell.exe -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBi...", true,
        "Microsoft Windows", 74, "计划任务里运行隐藏窗口的编码 PowerShell");
    add(C::Service, "Steam Client Service",
        "\"C:\\Program Files (x86)\\Common Files\\Steam\\steamservice.exe\" /RunAsService", true, "Valve Corp.", 0);
    add(C::Service, "BulwarkService", "\"C:\\Program Files\\Bulwark\\bulwark_service.exe\"", true, "Bulwark", 0);
    add(C::Winlogon, "Userinit", "C:\\Windows\\system32\\userinit.exe,", true, "Microsoft Windows", 0);
    return p;
}

// 一次系统加固体检的结果(全部虚构):11 个加固 / 基线项里 8 个达标,外加一条待处理的代理劫持告警。
ipc::HardeningStatusResponsePayload demoHardening()
{
    ipc::HardeningStatusResponsePayload s;
    s.hijackGuardActive = true;
    const auto item = [&s](const char* group, const char* title, const char* current, const char* recommended,
                           const char* cost, bool satisfied, const char* severity = "info") {
        ipc::HardeningItemPayload it;
        it.id = QString::number(s.items.size() + 1);
        it.group = QString::fromLatin1(group);
        it.title = QString::fromUtf8(title);
        it.current = QString::fromUtf8(current);
        it.recommended = QString::fromUtf8(recommended);
        it.cost = QString::fromUtf8(cost);
        it.satisfied = satisfied;
        it.severity = QString::fromLatin1(severity);
        it.actionable = !satisfied && it.group == QLatin1String("harden");
        it.revertible = satisfied && it.group == QLatin1String("harden");
        s.items << it;
    };
    item("harden", "阻止来自互联网的 Office 文档运行宏", "未限制", "带网络标记的文档里的宏一律不运行",
         "从邮件 / 网页下载的带宏文档,需先手动解除锁定", false, "warn");
    item("harden", "关闭 PowerShell v2 引擎", "已启用", "移除旧引擎,堵住绕过脚本日志与 AMSI 的降级路径",
         "极少数旧脚本会失效", false);
    item("harden", "开启 LSA 保护(RunAsPPL)", "已应用", "", "", true);
    item("harden", "禁用 WDigest 明文凭据缓存", "已禁用", "", "", true);
    item("harden", "开启受控文件夹访问", "已开启", "", "", true);
    item("baseline", "远程桌面", "已关闭", "", "", true);
    item("baseline", "SMBv1 协议", "已启用", "关闭 SMBv1", "依赖它的老 NAS / 打印机会连不上", false, "danger");
    item("baseline", "UAC 提示级别", "默认", "", "", true);
    item("baseline", "Windows 防火墙", "全部配置文件已开启", "", "", true);
    item("baseline", "自动播放", "已关闭", "", "", true);
    item("baseline", "来宾账户", "已禁用", "", "", true);
    item("monitor", "系统代理", "在盯", "", "", true);
    item("monitor", "浏览器策略", "在盯", "", "", true);
    item("monitor", "网卡 DNS", "在盯", "", "", true);
    item("monitor", "浏览器快捷方式", "在盯", "", "", true);
    ipc::HijackAlertPayload a;
    a.id = QStringLiteral("proxy-1");
    a.surface = QStringLiteral("proxy");
    a.title = QString::fromUtf8("系统代理被改动");
    a.location = QStringLiteral("HKCU\\...\\Internet Settings\\ProxyServer");
    a.newValue = QStringLiteral("127.0.0.1:7890");
    a.detail = QString::fromUtf8("如果这个改动其实是你自己(或你装的代理 / VPN / 浏览器)做的,还原会让那个设置失效。");
    s.alerts << a;
    return s;
}

// 一份进程快照(全部虚构):有父子关系、有带提示的进程,用来看进程树。
QList<bulwark::ProcessEntry> demoProcesses()
{
    QList<bulwark::ProcessEntry> list;
    const QDateTime boot = QDateTime::currentDateTimeUtc().addSecs(-6 * 3600);
    const auto add = [&list, &boot](int pid, int parent, const char* name, const char* path, qint64 mb, int threads,
                                    bool isSigned, const char* publisher, int risk = 0, const char* reason = nullptr) {
        bulwark::ProcessEntry e;
        e.pid = pid;
        e.parentPid = parent;
        e.name = QString::fromLatin1(name);
        e.imagePath = QString::fromLatin1(path);
        e.startTimeUtc = boot.addSecs(list.size() * 60);
        e.workingSetBytes = mb * 1024 * 1024 / 10;
        e.threadCount = threads;
        e.isSigned = isSigned;
        e.publisher = QString::fromUtf8(publisher);
        e.riskScore = risk;
        if (reason)
            e.riskReasons << QString::fromUtf8(reason);
        list << e;
    };
    add(812, 4, "services.exe", "C:\\Windows\\System32\\services.exe", 84, 12, true, "Microsoft Windows");
    add(1480, 812, "svchost.exe", "C:\\Windows\\System32\\svchost.exe", 421, 24, true, "Microsoft Windows");
    add(4312, 0, "explorer.exe", "C:\\Windows\\explorer.exe", 1126, 96, true, "Microsoft Windows");
    add(5520, 4312, "chrome.exe", "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe", 4862, 41, true,
        "Google LLC");
    add(8840, 4312, "invoice_2026.exe", "C:\\Users\\u\\Downloads\\invoice_2026.exe", 237, 14, false, "", 60,
        "从「下载」目录启动,且没有签名");
    add(9124, 8840, "powershell.exe", "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", 610, 18,
        true, "Microsoft Windows", 40, "隐藏窗口运行的编码命令");
    add(6140, 4312, "WINWORD.EXE", "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE", 2014, 33,
        true, "Microsoft Corporation");
    add(4470, 4312, "python.exe", "C:\\Users\\u\\AppData\\Local\\Programs\\Python\\python.exe", 389, 6, true,
        "Python Software Foundation", 30, "与陌生地址建立外联");
    return list;
}

// 隔离区里的几个文件(全部虚构);最后一个原路径仍有文件,用来看「部分完成」的样子。
QList<ipc::QuarantineItemPayload> demoQuarantine()
{
    QList<ipc::QuarantineItemPayload> list;
    const QDateTime now = QDateTime::currentDateTimeUtc();
    const auto add = [&list, &now](const char* path, const char* reason, qint64 size, int minutesAgo,
                                   bool removed = true) {
        ipc::QuarantineItemPayload it;
        it.id = QUuid::createUuid();
        it.originalPath = QString::fromUtf8(path);
        it.fileName = QFileInfo(it.originalPath).fileName();
        it.reason = QString::fromUtf8(reason);
        it.size = size;
        it.sha256 = QStringLiteral("9f2c41d0a7735be1c08d5e2f64a9b3c7d1e08f52a6c94b17e3d0f8a2b7e3a6c1");
        it.quarantinedUtc = now.addSecs(-60 * minutesAgo);
        it.actorPid = 8840;
        it.originalRemoved = removed;
        it.deleteOnRebootScheduled = !removed;
        list << it;
    };
    add("C:\\Users\\u\\Downloads\\invoice_2026.exe", "向 explorer.exe 注入远程线程(进程注入 · T1055)", 1'992'294, 25);
    add("C:\\Users\\u\\AppData\\Local\\Temp\\a1b2c3.dll", "白加黑侧载的恶意 DLL", 421'888, 26);
    add("C:\\Users\\u\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\helper.exe",
        "木马加载器 · 写入启动文件夹持久化", 2'411'724, 180);
    add("C:\\Users\\u\\Desktop\\报价单.js", "混淆脚本下载并运行可疑程序", 2'150, 1440);
    add("C:\\Users\\u\\AppData\\Roaming\\svch0st.exe", "批量改写用户文档(勒索加密行为)", 7'130'317, 300, false);
    return list;
}

// --audit 时补拍的界面:平时出图不覆盖、但用户看得到的那些(设置页每个分节、小垒的指挥终端、各个独立窗口)。
void renderAuditExtras(MainWindow* w, const QString& dir, const QString& prefix, int& failed)
{
    IpcClient* client = w->findChild<IpcClient*>();

    w->openPage(QString::fromLatin1(nav::Settings));
    settle(300);
    const char* sections[] = {"防护总控", "防护维度", "决策与监控", "受保护目录(反勒索)", "受保护目录",
                              "AI 辅助",  "MCP 服务器", "外观与通知", "关于"};
    int shot = 0;
    for (const char* title : sections) {
        for (QAbstractButton* nb : w->findChildren<QAbstractButton*>()) {
            if (nb->isVisible() && nb->text() == QString::fromUtf8(title)) {
                nb->click();
                settle(400);
                save(w->grab(), dir, prefix + QStringLiteral("page-settings-s%1").arg(++shot), failed);
                break;
            }
        }
    }
    w->openPage(QString::fromLatin1(nav::Dashboard));
    settle(200);

    // 小垒的指挥终端:点一下小垒就递出来。它 250ms 查一次鼠标还在不在,所以要赶在那之前拍。
    if (ResidentBot* bot = ResidentBot::instance()) {
        bot->setResidentEnabled(true);
        bot->say(robot::Mood::Guard, QString(), 1);
        settle(200);
        const QPointF at(bot->width() - 56, bot->height() - 40);
        const QPointF global = bot->mapToGlobal(at);
        QMouseEvent press(QEvent::MouseButtonPress, at, global, Qt::LeftButton, Qt::LeftButton, Qt::NoModifier);
        QApplication::sendEvent(bot, &press);
        QMouseEvent release(QEvent::MouseButtonRelease, at, global, Qt::LeftButton, Qt::NoButton, Qt::NoModifier);
        QApplication::sendEvent(bot, &release);
        settle(120);
        bool found = false;
        for (QWidget* top : QApplication::topLevelWidgets()) {
            if (top->isVisible() && previewaudit::typeName(top).contains(QLatin1String("Terminal"))) {
                found = true;
                save(top->grab(), dir, prefix + QStringLiteral("resident-terminal"), failed);
            }
        }
        if (!found) {
            out() << "没找到小垒的指挥终端\n";
            ++failed;
        }
        settle(400);
    }

    const auto window = [&](QWidget* dlg, const char* name) {
        dlg->show();
        settle(500);
        save(dlg->grab(), dir, prefix + QStringLiteral("win-") + QString::fromLatin1(name), failed);
        dlg->hide();
        delete dlg;
        settle(80);
    };
    if (client)
        window(new AiActivityWindow(client->aiScanner()), "ai-activity");
    window(new ProcessDetailDialog(demoProcesses().at(4), client), "process-detail");
    window(new AttackTimelineWindow(fixtures().first().event, nullptr, client), "attack-timeline");
    window(new AttackGraphWindow(client, QUuid::createUuid(), 8840, QStringLiteral("invoice_2026.exe")),
           "attack-graph");
    window(new TrafficDetailWindow(client, demoTraffic().rows.first()), "traffic-detail");
    {
        ipc::RemediationReportPayload r;
        r.actorPath = QStringLiteral("C:\\Users\\u\\AppData\\Roaming\\Sync\\sync_host.exe");
        r.actorPid = 8840;
        r.reason = QString::fromUtf8("批量改写用户文档(勒索加密行为)");
        r.actorQuarantined = true;
        r.quarantinedFiles << QStringLiteral("C:\\Users\\u\\AppData\\Local\\Temp\\a1b2c3.dll")
                           << QStringLiteral("C:\\Users\\u\\AppData\\Roaming\\Sync\\sync_host.exe");
        r.removedRegistryValues << QStringLiteral("HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\SyncHost");
        ipc::RemediationSkippedItem s;
        s.target = QStringLiteral("C:\\Users\\u\\AppData\\Roaming\\Sync\\updater.exe");
        s.reason = QString::fromUtf8("文件正被占用,已安排重启后删除");
        s.isFile = true;
        s.name = QStringLiteral("updater.exe");
        s.forceable = true;
        r.skipped << s;
        window(new RemediationReportDialog(r, client), "remediation-report");
    }

    // MCP 服务器编辑框是模态的:先排一个定时器,等它弹出来、拍下来,再把它关掉。
    if (client && client->aiScanner() && client->aiScanner()->mcp()) {
        QTimer::singleShot(600, qApp, [&] {
            for (QWidget* top : QApplication::topLevelWidgets()) {
                if (auto* d = qobject_cast<QDialog*>(top); d && d->isModal() && d->isVisible()) {
                    save(d->grab(), dir, prefix + QStringLiteral("win-mcp-server"), failed);
                    d->reject();
                }
            }
        });
        mcpui::editServer(nullptr, client->aiScanner()->mcp(), McpServerConfig{}, true);
        settle(100);
    }
}

void renderMain(const QString& dir, const QString& prefix, int& failed)
{
    auto* w = new MainWindow(nullptr, true);
    w->resize(g_mainSize);
    w->move(16, 16);
    w->show();
    settle(500);
    feedDemo(w->findChild<IpcClient*>());
    settle(400);
    const char* pages[] = {nav::Dashboard, nav::Events, nav::Timeline, nav::Boost, nav::Processes, nav::Rules,
                           nav::Trust, nav::SoftwareCatalog, nav::Quarantine, nav::Persistence, nav::Hardening,
                           nav::Settings};
    for (const char* key : pages) {
        w->openPage(QString::fromLatin1(key));
        settle(380);
        save(w->grab(), dir, prefix + QStringLiteral("page-") + QString::fromLatin1(key), failed);
    }
    // 设置页里的「外观与通知」(界面风格卡片)在首屏之下:点左侧分节导航滚过去再拍一张。
    w->openPage(QString::fromLatin1(nav::Settings));
    settle(200);
    // 分节导航在机甲 / 卡哇伊里是 NavButton,在金刚里是设置页自己的导航项:按按钮文字找,不认类型。
    for (QAbstractButton* nb : w->findChildren<QAbstractButton*>()) {
        if (nb->isVisible() && nb->text() == QString::fromUtf8("外观与通知")) {
            nb->click();
            settle(400);
            save(w->grab(), dir, prefix + QStringLiteral("page-settings-appearance"), failed);
            break;
        }
    }
    w->openPage(QString::fromLatin1(nav::Dashboard));
    settle(200);

    if (TrafficOverlay* overlay = TrafficOverlay::instance()) {
        overlay->setOverlayEnabled(true);
        if (IpcClient* client = w->findChild<IpcClient*>()) {
            for (int i = 0; i < 4; ++i) {
                emit client->netTrafficReceived(demoTraffic());
                settle(260);
            }
        }
        settle(300);
        save(overlay->grab(), dir, prefix + QStringLiteral("overlay"), failed);
    }
    if (ResidentBot* bot = ResidentBot::instance()) {
        bot->setResidentEnabled(true);
        bot->setBlocked(3);
        bot->say(robot::Mood::Alert, QString::fromUtf8("威胁已击退!"), 60000);
        settle(300);
        save(bot->grab(), dir, prefix + QStringLiteral("resident-alert"), failed);
        bot->say(robot::Mood::Ask, QString::fromUtf8("指挥官,请下令!"), 60000);
        settle(200);
        save(bot->grab(), dir, prefix + QStringLiteral("resident-ask"), failed);
        bot->say(robot::Mood::Guard, QString(), 1);
        settle(200);
        // 没话说、没有待下令时的样子(金刚:停着的小卡车)。
        save(bot->grab(), dir, prefix + QStringLiteral("resident-idle"), failed);
    }
    // 检测过自启动项之后的样子。放在最后,前面那批图(和改动前的基线逐张比对的)不受影响。
    if (IpcClient* client = w->findChild<IpcClient*>()) {
        emit client->persistenceReceived(demoPersistence());
        settle(200);
        w->openPage(QString::fromLatin1(nav::Boost));
        settle(380);
        save(w->grab(), dir, prefix + QStringLiteral("page-boost-detected"), failed);
        w->openPage(QString::fromLatin1(nav::Persistence));
        settle(380);
        save(w->grab(), dir, prefix + QStringLiteral("page-persistence-detected"), failed);

        const QList<ipc::QuarantineItemPayload> vault = demoQuarantine();
        emit client->quarantineReceived(vault);
        w->openPage(QString::fromLatin1(nav::Quarantine));
        settle(380);
        for (RecordBrowser* rb : w->findChildren<RecordBrowser*>()) {
            if (rb->isVisible()) {
                rb->selectKey(vault.first().id.toString(QUuid::WithoutBraces));
                break;
            }
        }
        settle(400);
        save(w->grab(), dir, prefix + QStringLiteral("page-quarantine-detected"), failed);

        // 事件记录:选中第一条,拍右侧抽屉。
        w->openPage(QString::fromLatin1(nav::Events));
        settle(380);
        for (RecordBrowser* rb : w->findChildren<RecordBrowser*>()) {
            if (!rb->isVisible())
                continue;
            if (auto* view = rb->findChild<QAbstractItemView*>(); view && view->model()->rowCount() > 0)
                rb->selectKey(view->model()->index(0, 0).data(rec::Key));
            break;
        }
        settle(400);
        save(w->grab(), dir, prefix + QStringLiteral("page-events-drawer"), failed);

        emit client->hardeningStatusReceived(demoHardening());
        w->openPage(QString::fromLatin1(nav::Hardening));
        settle(380);
        save(w->grab(), dir, prefix + QStringLiteral("page-hardening-detected"), failed);

        // 进程管理:切到进程树、打开一条带提示的进程。拍完切回列表,免得下次出图时这一页记着树视图。
        w->openPage(QString::fromLatin1(nav::Processes));
        settle(300);
        Segmented* viewMode = nullptr;
        for (Segmented* sg : w->findChildren<Segmented*>())
            if (sg->isVisible() && sg->accessibleName() == QString::fromUtf8("视图"))
                viewMode = sg;
        if (viewMode)
            viewMode->setCurrentIndex(1);
        ipc::ProcessListResponsePayload procs;
        procs.processes = demoProcesses();
        emit client->processListReceived(procs);
        settle(300);
        for (QTreeView* tv : w->findChildren<QTreeView*>()) {
            if (!tv->isVisible() || tv->objectName() != QStringLiteral("ProcessTree"))
                continue;
            tv->expandAll();
            const QModelIndexList hits =
                tv->model()->match(tv->model()->index(0, 0), Qt::DisplayRole, QStringLiteral("invoice_2026.exe"), 1,
                                   Qt::MatchRecursive | Qt::MatchExactly);
            if (!hits.isEmpty()) {
                tv->setCurrentIndex(hits.first());
                emit tv->clicked(hits.first());
            }
            break;
        }
        settle(400);
        save(w->grab(), dir, prefix + QStringLiteral("page-processes-tree"), failed);
        if (viewMode)
            viewMode->setCurrentIndex(0);
    }
    if (previewaudit::enabled())
        renderAuditExtras(w, dir, prefix, failed);
    w->hide();
    delete w;
    settle(200);
}

void renderPopups(const QString& dir, const QString& prefix, int& failed)
{
    for (Fixture f : fixtures()) {
        RuleEngine engine;
        engine.loadRules(DefaultRules::build());
        const Verdict v = engine.evaluate(f.event);

        PromptDialog dlg(f.event, nullptr, 30, v.action != VerdictAction::Block, nullptr);
        dlg.show();
        settle(500);
        if (save(dlg.grab(), dir, prefix + QStringLiteral("prompt-") + f.name, failed))
            out() << "  裁决=" << verdictActionToString(v.action) << "  风险分=" << f.event.riskScore
                  << "  硬指标=" << (f.event.hasThreatIndicator ? "是" : "否") << "\n";
        // 「记住选择」切到最长的两档再各拍一张:裁决按钮的文字和那行说明都跟着范围变,
        // 要看的是底部那一排按钮会不会被挤出卡片、卡片高度会不会跳。
        if (auto* scope = dlg.findChild<Segmented*>()) {
            const int restHeight = dlg.height();
            const auto shoot = [&](int index, const char* tag) {
                scope->setCurrentIndex(index);
                settle(200);
                if (save(dlg.grab(), dir, prefix + QStringLiteral("prompt-") + f.name + QLatin1Char('-')
                                              + QString::fromLatin1(tag), failed)
                    && dlg.height() != restHeight) {
                    out() << "  切换范围后卡片高度变了: " << restHeight << " -> " << dlg.height() << "\n";
                    ++failed;
                }
            };
            shoot(1, "scope-session");
            shoot(4, "scope-permanent");
            scope->setCurrentIndex(0);
        }
        // 展开「详情」再拍一张:解释 / 原因 / 命中代码这一段在矮屏上是整体滚动的,要看的是刚展开的
        // 那块有没有被带进可视区、卡片有没有长出屏幕。
        const auto toggles = dlg.findChildren<QToolButton*>();
        for (QToolButton* b : toggles) {
            if (b->accessibleName() != QStringLiteral("展开详情"))
                continue;
            b->click();
            settle(300);
            const int screenH = dlg.screen() ? dlg.screen()->availableGeometry().height() : 0;
            if (save(dlg.grab(), dir, prefix + QStringLiteral("prompt-") + f.name + QStringLiteral("-details"), failed)
                && screenH > 0 && dlg.height() > screenH) {
                out() << "  展开详情后卡片高过屏幕: " << dlg.height() << " > " << screenH << "\n";
                ++failed;
            }
            break;
        }
        dlg.close();
        settle(80);

        // 拦截通知:AI 未配置时这张卡片上挂的就是同一份离线解释(紧凑版、省掉处置建议)。
        auto* toast = new ToastWindow(ToastWindow::Kind::Block,
                                      QStringLiteral("已拦截危险行为"),
                                      evtfmt::arrowLine(f.event),
                                      QStringLiteral("依据:命中规则 · 同时已禁止该程序再次启动"),
                                      f.event.techniques,
                                      600000,   // 预览期间不让它自动关闭
                                      QStringLiteral("已拦截"),
                                      QStringLiteral("查看详情 ›"));
        // 与 ToastNotifier::showBlock 同一套摆法:主按钮是「查看详情」,撤销是次要按钮。
        toast->setSecondaryAction(QStringLiteral("撤销拦截 · 信任 1 小时"));
        threatcode::Options tcodeOpt;
        tcodeOpt.maxSnippets = 1;
        tcodeOpt.maxRows = 6;
        tcodeOpt.moreHint = QStringLiteral("另有 %1 段命中代码,见拦截记录详情");
        if (QWidget* tcode = threatcode::build(f.event, evtfmt::riskColor(f.event.riskScore), tcodeOpt))
            toast->setCode(tcode);
        explaincard::Options opt;
        opt.compact = true;
        opt.omitAdvice = true;
        if (QWidget* card = explaincard::build(f.event, opt)) {
            toast->setInsight(card);   // 必须先于 show():它改卡片的宽和高
            toast->settleInsight(0);
        }
        toast->place(QPoint(120, 120));
        toast->show();
        settle(500);
        save(toast->grab(), dir, prefix + QStringLiteral("toast-") + f.name, failed);
        toast->hide();
        toast->deleteLater();
        settle(80);

        // 配了 AI 时卡片上挂的是紧凑版 AI 解读;判成误拦时会露出「信任 1h / 1d / 本次会话 / 删规则」一排。
        if (f.name != QLatin1String("danger-cert-revoked"))
            continue;
        for (const bool withCode : {true, false}) {
            auto* aiToast = new ToastWindow(ToastWindow::Kind::Block, QStringLiteral("已拦截危险行为"),
                                            evtfmt::arrowLine(f.event),
                                            QStringLiteral("依据:命中规则 · 同时已禁止该程序再次启动"),
                                            f.event.techniques, 600000, QStringLiteral("已拦截"),
                                            QStringLiteral("查看详情 ›"));
            aiToast->setSecondaryAction(QStringLiteral("撤销拦截 · 信任 1 小时"));
            if (withCode) {
                if (QWidget* tcode = threatcode::build(f.event, evtfmt::riskColor(f.event.riskScore), tcodeOpt))
                    aiToast->setCode(tcode);
            }
            auto* panel = new AiInsightPanel(AiExplainContext::Blocked, true);
            panel->setCorrectionContext(f.event.actorPath.isEmpty() ? QStringLiteral("C:\\Tools\\sync_host.exe")
                                                                    : f.event.actorPath,
                                        QStringLiteral("示例规则"));
            AiExplanation r;
            r.ok = true;
            r.advice = AiExplanation::Advice::Allow;
            r.confidence = QStringLiteral("中");
            r.summary = QStringLiteral("这是常见的同步工具,证书吊销多半是厂商换证;行为与它的功能一致,多半是误拦。");
            r.elapsedMs = 2300;
            r.tokens = 812;
            panel->setResult(r, false);
            aiToast->setInsight(panel);
            aiToast->settleInsight(0);
            aiToast->place(QPoint(120, 120));
            aiToast->show();
            settle(500);
            save(aiToast->grab(), dir,
                 prefix + QStringLiteral("toast-ai-") + (withCode ? QStringLiteral("code-") : QString()) + f.name, failed);
            aiToast->hide();
            aiToast->deleteLater();
            settle(80);
        }
    }
    // 其余几种通知:通报 / 清场。
    const auto simple = [&](ToastWindow::Kind kind, const char* name, const char* heading, const char* line,
                            const char* badge) {
        auto* toast = new ToastWindow(kind, QString::fromUtf8(heading), QString::fromUtf8(line), QString(), {},
                                      600000, QString::fromUtf8(badge), QString());
        toast->place(QPoint(120, 120));
        toast->show();
        settle(400);
        save(toast->grab(), dir, prefix + QStringLiteral("toast-") + QString::fromLatin1(name), failed);
        toast->hide();
        toast->deleteLater();
        settle(60);
    };
    simple(ToastWindow::Kind::Info, "info", "内核驱动已连接 · 行为前拦截恢复", "防护档位已回到「内核前拦」。", "");
    simple(ToastWindow::Kind::Cleanup, "cleanup", "已清理 sync_host.exe 留下的痕迹",
           "结束 4 个进程 · 隔离 2 个文件 · 删除 1 个自启动项", "已清场");
    simple(ToastWindow::Kind::BlockAlertedOnly, "alerted", "powershell.exe 写入注册表 Run\\Updater",
           "驱动未连接:这次只记录,没能在动作前拦下", "仅记录");

    // 两张二次确认框:高危询问选「永久」放行、拦截通知上点「撤销拦截」。它们是 ui::confirm 里的
    // 模态卡片,这里拿不到指针,所以先排一个定时器:等卡片弹出来、截下来,再把它关掉。
    // 本文件 using namespace bulwark,而 bulwark 里也有一个 ui 命名空间,所以这里要写全局限定的 ::ui。
    const auto confirmShot = [&](const char* name, const ::ui::ConfirmSpec& spec) {
        bool found = false;
        QTimer::singleShot(600, qApp, [&] {
            if (QWidget* w = QApplication::activeModalWidget()) {
                found = true;
                save(w->grab(), dir, prefix + QStringLiteral("confirm-") + QString::fromLatin1(name), failed);
            }
            // 不管截没截到都要关掉,否则下面的 ui::confirm 不会返回。
            const auto tops = QApplication::topLevelWidgets();
            for (QWidget* top : tops)
                if (auto* d = qobject_cast<QDialog*>(top); d && d->isModal() && d->isVisible())
                    d->reject();
        });
        ::ui::confirm(nullptr, spec);
        if (!found) {
            out() << "确认框没有弹出: " << name << "\n";
            ++failed;
        }
        settle(80);
    };
    bool shot = false;
    for (Fixture f : fixtures()) {
        // 硬指标和风险分是规则引擎评估时填进事件里的,没评估过的样例一律是「无」。
        RuleEngine engine;
        engine.loadRules(DefaultRules::build());
        engine.evaluate(f.event);
        if (!f.event.hasThreatIndicator)
            continue;
        confirmShot("permanent-allow", PromptDialog::permanentAllowConfirmSpec(f.event));
        confirmShot("undo-block", ToastNotifier::undoBlockConfirmSpec(evtfmt::nativePath(f.event.actorPath)));
        shot = true;
        break;
    }
    if (!shot) {
        out() << "没有带硬指标的样例,两张确认框没有拍\n";
        ++failed;
    }
}

// 动画逐帧图
// 每段动画按固定间隔抓若干帧,拼成一张带时间标注的图,用来检查动画的每个阶段。

class FrameSheet
{
public:
    explicit FrameSheet(QString title) : m_title(std::move(title)) {}

    void add(const QPixmap& shot, qint64 ms)
    {
        if (!shot.isNull())
            m_frames.append({shot, ms});
    }

    void save(const QString& dir, const QString& name, int& failed, int cols = 4, qreal scale = 1.0) const
    {
        if (m_frames.isEmpty()) {
            out() << "没有抓到帧: " << name << "\n";
            ++failed;
            return;
        }
        const QSize cell = (m_frames.first().shot.deviceIndependentSize() * scale).toSize();
        constexpr int kPad = 10, kLabel = 18, kHead = 30;
        cols = qMax(1, qMin(cols, int(m_frames.size())));
        const int rows = (int(m_frames.size()) + cols - 1) / cols;
        QImage img(kPad + cols * (cell.width() + kPad), kHead + rows * (cell.height() + kLabel + kPad) + kPad,
                   QImage::Format_ARGB32);
        img.fill(QColor(0x8E, 0x8C, 0x88));
        QPainter p(&img);
        p.setRenderHint(QPainter::SmoothPixmapTransform, true);
        QFont f;
        f.setPixelSize(13);
        f.setBold(true);
        p.setFont(f);
        p.setPen(Qt::white);
        p.drawText(QRect(kPad, 0, img.width() - kPad, kHead), Qt::AlignVCenter | Qt::AlignLeft, m_title);
        for (int i = 0; i < m_frames.size(); ++i) {
            const QRect at(kPad + (i % cols) * (cell.width() + kPad), kHead + (i / cols) * (cell.height() + kLabel + kPad),
                           cell.width(), cell.height());
            p.drawPixmap(at, m_frames[i].shot);
            p.drawText(QRect(at.left(), at.bottom() + 2, at.width(), kLabel), Qt::AlignVCenter | Qt::AlignLeft,
                       QStringLiteral("t = %1 ms").arg(m_frames[i].ms));
        }
        p.end();
        ::save(QPixmap::fromImage(img), dir, name, failed);
    }

private:
    struct Frame {
        QPixmap shot;
        qint64 ms;
    };
    QString m_title;
    QList<Frame> m_frames;
};

QPixmap crop(const QPixmap& full, const QRect& logical)
{
    const qreal dpr = full.devicePixelRatio();
    QPixmap out = full.copy(QRectF(QPointF(logical.topLeft()) * dpr, QSizeF(logical.size()) * dpr).toAlignedRect());
    out.setDevicePixelRatio(dpr);
    return out;
}

void film(FrameSheet& sheet, int frames, int stepMs, const std::function<QPixmap()>& grab)
{
    QElapsedTimer t;
    t.start();
    for (int i = 0; i < frames; ++i) {
        sheet.add(grab(), t.elapsed());
        settle(stepMs);
    }
}

QRect rectIn(const QWidget* w, const QWidget* top, int pad = 0)
{
    return QRect(w->mapTo(top, QPoint(0, 0)), w->size()).adjusted(-pad, -pad, pad, pad);
}

QString txt(const char* s) { return QString::fromUtf8(s); }

void renderAnim(const QString& dir, const QString& prefix, int& failed)
{
    auto* w = new MainWindow(nullptr, true);
    w->resize(1320, 880);
    w->move(16, 16);
    w->show();
    settle(400);
    IpcClient* client = w->findChild<IpcClient*>();
    feedDemo(client);
    settle(700);

    // 外壳:能量宝石呼吸 / 小旗飘动 / 耳朵信标(一个循环 2.4 秒)
    {
        FrameSheet crown(txt("外壳 · 能量宝石 / 小旗(每 200ms)"));
        FrameSheet ear(txt("外壳 · 左耳信标(每 200ms)"));
        const QRect crownRect(w->width() / 2 - 150, 0, 300, 120);
        const QRect earRect(0, 60, 120, 180);
        QElapsedTimer t;
        t.start();
        for (int i = 0; i < 12; ++i) {
            const QPixmap full = w->grab();
            crown.add(crop(full, crownRect), t.elapsed());
            ear.add(crop(full, earRect), t.elapsed());
            settle(200);
        }
        crown.save(dir, prefix + QStringLiteral("anim-crown"), failed, 6);
        ear.save(dir, prefix + QStringLiteral("anim-ear"), failed, 6);
    }

    // 金刚:机器人 → 小卡车的变形过程。按进度均匀取 12 帧(不依赖墙钟),标注的是在 820ms 变形里的位置。
    if (theme::titan()) {
        FrameSheet sheet(txt("小垒变形 · 机器人 → 小卡车(按进度取帧)"));
        for (int i = 0; i < 12; ++i) {
            QPixmap pm(180, 225);
            pm.fill(QColor(0x14, 0x1C, 0x2A));
            QPainter p(&pm);
            robot::Look lk;
            lk.vehicle = i / 11.0;
            robot::paint(p, QRectF(0, 0, 180, 225), lk);
            p.end();
            sheet.add(pm, qRound(i / 11.0 * 820));
        }
        sheet.save(dir, prefix + QStringLiteral("anim-transform"), failed, 6);
    }

    // 仪表盘:表情屏扫描光 + 雷达扫描线(两者都是间歇触发,拍 9 秒总能拍到)
    {
        QWidget* face = nullptr;
        QWidget* chart = nullptr;
        for (QWidget* c : w->findChildren<QWidget*>()) {
            if (!c->isVisible())
                continue;
            if (!face && (c->accessibleName() == txt("防御中") || c->accessibleName() == txt("守护中")))
                face = c;
            if (!chart && c->accessibleName().startsWith(txt("过去 24 小时的事件分布")))
                chart = c;
        }
        if (face && chart) {
            FrameSheet faceSheet(txt("表情屏 · 扫描光 / 扫视(每 250ms)"));
            FrameSheet chartSheet(txt("战况雷达 · 扫描线(每 250ms)"));
            const QRect fr = rectIn(face, w);
            const QRect cr = rectIn(chart, w);
            QElapsedTimer t;
            t.start();
            for (int i = 0; i < 36; ++i) {
                const QPixmap full = w->grab();
                faceSheet.add(crop(full, QRect(fr.left(), fr.top(), qMin(fr.width(), 360), fr.height())), t.elapsed());
                chartSheet.add(crop(full, cr), t.elapsed());
                settle(250);
            }
            faceSheet.save(dir, prefix + QStringLiteral("anim-face"), failed, 6, 0.6);
            chartSheet.save(dir, prefix + QStringLiteral("anim-radar"), failed, 4, 0.5);
        } else {
            out() << "没找到表情屏 / 雷达\n";
            ++failed;
        }
    }

    // 战绩数码管:数值跳变时滚动 + 泛光
    if (client) {
        QRect area;
        for (QWidget* c : w->findChildren<QWidget*>())
            if (dynamic_cast<SevenSegCounter*>(c) && c->isVisible() && c->window() == w)
                area |= rectIn(c, w);
        FrameSheet sheet(txt("数码管 · 滚动计数 + 泛光(每 80ms)"));
        emit client->quarantineReceived(QList<ipc::QuarantineItemPayload>(128));
        emit client->rulesReceived(QList<DefenseRule>(73));
        film(sheet, 12, 80, [&] { return crop(w->grab(), area.adjusted(-10, -8, 10, 8)); });
        sheet.save(dir, prefix + QStringLiteral("anim-counters"), failed, 4);
    }

    // 键帽:点「事件」键 → 键帽下沉 + 翻页(新页面升起时略过冲)
    {
        const QList<KeyCap*> keys = w->findChildren<KeyCap*>();
        if (keys.size() > 2) {
            KeyCap* key = keys.at(1);
            QRect keyArea = rectIn(keys.at(0), w) | rectIn(keys.at(2), w);
            keyArea.adjust(-6, -6, 6, 6);
            // 金刚的变形切页要 620ms,多拍几帧才能看全「推进来 → 合拢 → 退出去」。
            const bool plates = theme::titan();
            FrameSheet keySheet(txt("键帽 · 按下 / 弹回(每 30ms)"));
            FrameSheet pageSheet(plates ? txt("变形切页 · 六块装甲板对合再打开(每 40ms)") : txt("翻页 · 新页面升起(每 40ms)"));
            const QRect page(60, 150, w->width() - 120, w->height() - 200);
            key->click();
            QElapsedTimer t;
            t.start();
            for (int i = 0; i < (plates ? 18 : 10); ++i) {
                const QPixmap full = w->grab();
                if (i < 10)
                    keySheet.add(crop(full, keyArea), t.elapsed());
                pageSheet.add(crop(full, page), t.elapsed());
                settle(i < 8 ? 30 : 40);
            }
            keySheet.save(dir, prefix + QStringLiteral("anim-keycap"), failed, 5);
            pageSheet.save(dir, prefix + QStringLiteral("anim-page"), failed, plates ? 6 : 5, 0.3);
            w->openPage(QString::fromLatin1(nav::Dashboard));
            settle(400);
        }
    }

    // 流量悬浮窗:雷达表指针按弹簧追到目标刻度
    if (TrafficOverlay* overlay = TrafficOverlay::instance(); overlay && client) {
        overlay->setOverlayEnabled(true);
        settle(250);
        FrameSheet sheet(txt("雷达表 · 指针弹簧(每 60ms)"));
        emit client->netTrafficReceived(demoTraffic());
        film(sheet, 16, 60, [&] { return crop(overlay->grab(), QRect(0, 0, overlay->width(), 182)); });
        sheet.save(dir, prefix + QStringLiteral("anim-needles"), failed, 4);
        overlay->setOverlayEnabled(false);
    }

    // 常驻小垒:出场升起 → 拦截(气泡弹出 + 抖动)→ 询问(蹦一下 + 挥手)
    if (ResidentBot* bot = ResidentBot::instance()) {
        bot->setResidentEnabled(false);
        settle(100);
        FrameSheet enter(txt("常驻小垒 · 出场(每 90ms)"));
        bot->setResidentEnabled(true);
        film(enter, 10, 90, [&] { return bot->grab(); });
        enter.save(dir, prefix + QStringLiteral("anim-resident-enter"), failed, 5);
        FrameSheet alert(txt("常驻小垒 · 拦截:气泡弹出 + 抖动(每 70ms)"));
        bot->say(robot::Mood::Alert, txt("威胁已击退!"), 60000);
        film(alert, 10, 70, [&] { return bot->grab(); });
        alert.save(dir, prefix + QStringLiteral("anim-resident-alert"), failed, 5);
        FrameSheet ask(txt("常驻小垒 · 询问:蹦一下 + 挥手(每 90ms)"));
        bot->say(robot::Mood::Ask, txt("指挥官,请下令!"), 60000);
        film(ask, 10, 90, [&] { return bot->grab(); });
        ask.save(dir, prefix + QStringLiteral("anim-resident-ask"), failed, 5);
        bot->say(robot::Mood::Guard, QString(), 1);
        settle(100);
    }
    w->hide();
    delete w;
    settle(200);
}

void renderAnimPopups(const QString& dir, const QString& prefix, int& failed)
{
    // 高风险询问弹窗(红色斑马带走得快):斑马带推进 + 小垒落到卡片边沿
    RuleEngine engine;
    engine.loadRules(DefaultRules::build());
    const auto all = fixtures();
    Fixture pick = all.first();
    for (Fixture f : all) {
        engine.evaluate(f.event);
        if (f.event.riskScore >= 80) {
            pick = f;
            break;
        }
    }
    {
        PromptDialog dlg(pick.event, nullptr, 30, true, nullptr);
        dlg.show();
        FrameSheet sheet(txt("询问弹窗 · 入场 / 小垒落下 / 斑马带推进(每 90ms)"));
        film(sheet, 12, 90, [&] { return dlg.grab(); });
        sheet.save(dir, prefix + QStringLiteral("anim-prompt"), failed, 4, 0.5);
        dlg.close();
        settle(120);
    }
    // 拦截战报:钢印砸下 + 卡片一沉
    {
        auto* toast = new ToastWindow(ToastWindow::Kind::Block, QStringLiteral("已拦截危险行为"),
                                      evtfmt::arrowLine(pick.event), QStringLiteral("依据:命中规则"),
                                      pick.event.techniques, 600000, QStringLiteral("已拦截"), QString());
        toast->place(QPoint(120, 120));
        FrameSheet sheet(txt("拦截战报 · 钢印砸下(每 60ms)"));
        film(sheet, 16, 60, [&] { return toast->grab(); });
        sheet.save(dir, prefix + QStringLiteral("anim-toast"), failed, 4, 0.6);
        toast->hide();
        toast->deleteLater();
        settle(100);
    }
}

// 换装转场:走 UiHost 的真实路径,把新窗口与上面的转场浮层叠成一帧。
void renderWipe(QApplication& app, const QString& dir, int& failed)
{
    theme::setSkin(theme::Skin::Mecha);
    theme::apply(app);
    UiHost host(app, false);
    QObject::connect(&host, &UiHost::windowCreated, &app, [](MainWindow* w) {
        QTimer::singleShot(200, w, [w] { feedDemo(w->findChild<IpcClient*>()); });
    });
    host.start(true);
    host.window()->resize(1320, 880);
    host.window()->move(16, 16);
    settle(900);
    const auto overlay = []() -> QWidget* {
        for (QWidget* t : QApplication::topLevelWidgets())
            if (t->isVisible() && t->windowFlags().testFlag(Qt::WindowTransparentForInput)
                && t->windowFlags().testFlag(Qt::WindowStaysOnTopHint))
                return t;
        return nullptr;
    };
    const auto shoot = [&]() -> QPixmap {
        MainWindow* w = host.window();
        if (!w)
            return QPixmap();
        QPixmap frame = w->grab();
        if (QWidget* o = overlay()) {
            QPainter p(&frame);
            p.drawPixmap(o->geometry().topLeft() - w->geometry().topLeft(), o->grab());
        }
        return frame;
    };
    for (const auto& [skin, name] : {std::pair{theme::Skin::Kawaii, "wipe-to-kawaii"}, std::pair{theme::Skin::Titan, "wipe-to-titan"},
                                     std::pair{theme::Skin::Mecha, "wipe-to-mecha"}}) {
        FrameSheet sheet(txt("换装转场 · %1(每 70ms)").arg(QString::fromLatin1(name)));
        theme::requestSkin(skin);
        settle(20);
        film(sheet, 14, 70, shoot);
        sheet.save(dir, QString::fromLatin1(name), failed, 5, 0.3);
        settle(800);
    }
}

}

int main(int argc, char** argv)
{
    qputenv("BULWARK_UI_NO_IPC", "1");

    QString outDir = QStringLiteral(".agents/ui-preview");
    QStringList skins{QStringLiteral("mecha"), QStringLiteral("kawaii"), QStringLiteral("titan")};
    QStringList only{QStringLiteral("main"), QStringLiteral("popups")};
    int interactiveSecs = 0;
    bool audit = false;
    for (int i = 1; i < argc; ++i) {
        const QString a = QString::fromLocal8Bit(argv[i]);
        if (a == QLatin1String("--out") && i + 1 < argc)
            outDir = QString::fromLocal8Bit(argv[++i]);
        else if (a == QLatin1String("--audit"))
            audit = true;
        else if (a == QLatin1String("--size") && i + 1 < argc) {
            const QStringList wh = QString::fromLocal8Bit(argv[++i]).split(QLatin1Char('x'));
            if (wh.size() == 2 && wh[0].toInt() > 0 && wh[1].toInt() > 0)
                g_mainSize = QSize(wh[0].toInt(), wh[1].toInt());
        }
        else if (a == QLatin1String("--skin") && i + 1 < argc)
            skins = QString::fromLocal8Bit(argv[++i]).split(QLatin1Char(','));
        else if (a == QLatin1String("--only") && i + 1 < argc)
            only = QString::fromLocal8Bit(argv[++i]).split(QLatin1Char(','));
        else if (a == QLatin1String("--interactive") && i + 1 < argc)
            interactiveSecs = QString::fromLocal8Bit(argv[++i]).toInt();
        else if (a == QLatin1String("--rebuild-test"))
            only = QStringList{QStringLiteral("rebuild")};
        else if (a == QLatin1String("--anim"))
            only = QStringList{QStringLiteral("anim")};
    }
    // 静态截图要的是动画播完后的样子:关掉动画。逐帧图、换皮肤重建与交互模式走真实的动画路径。
    // 必须在任何控件读 motion::enabled() 之前定下来(它只读一次)。
    if (qEnvironmentVariableIsEmpty("BULWARK_UI_MOTION")) {
        const bool live = interactiveSecs > 0 || only.contains(QStringLiteral("anim"))
                          || only.contains(QStringLiteral("rebuild"));
        qputenv("BULWARK_UI_MOTION", live ? "1" : "0");
    }

    QApplication app(argc, argv);
    // BULWARK_PREVIEW_HIDDEN:用真实平台插件(真实字体引擎与 DPI)出图时,窗口照常布局、grab,但不真的弹到桌面上。
    struct DontShowOnScreen : QObject {
        bool eventFilter(QObject* o, QEvent* e) override
        {
            if (e->type() == QEvent::Polish || e->type() == QEvent::Show) {
                auto* w = qobject_cast<QWidget*>(o);
                if (w && w->isWindow())
                    w->setAttribute(Qt::WA_DontShowOnScreen);
            }
            return false;
        }
    } dontShow;
    if (!qEnvironmentVariableIsEmpty("BULWARK_PREVIEW_HIDDEN"))
        app.installEventFilter(&dontShow);
    // 独立的设置命名空间:预览里挪动的悬浮窗 / 小垒位置不会写进真实界面的配置。
    app.setOrganizationName(QStringLiteral("BulwarkPreview"));
    app.setApplicationName(QStringLiteral("BulwarkPreview"));
    app.setQuitOnLastWindowClosed(false);

    if (only.contains(QStringLiteral("anim"))) {
        if (!QDir().mkpath(outDir))
            return 1;
        int failed = 0;
        for (const QString& key : skins) {
            theme::setSkin(theme::skinFromKey(key));
            theme::apply(app);
            const QString prefix = key + QLatin1Char('-');
            renderAnim(outDir, prefix, failed);
            setFixedNowUtcForTest(QDateTime(QDate(2026, 3, 1), QTime(12, 0, 0), QTimeZone::UTC));
            renderAnimPopups(outDir, prefix, failed);
            setFixedNowUtcForTest(QDateTime());
            out().flush();
        }
        renderWipe(app, outDir, failed);
        out().flush();
        return failed == 0 ? 0 : 1;
    }

    // 换皮肤重建:走 UiHost 的真实路径(与正式界面同一份代码),每一步检查窗口、皮肤与页面。
    if (only.contains(QStringLiteral("rebuild"))) {
        if (!QDir().mkpath(outDir))
            return 1;
        int failed = 0;
        theme::setSkin(theme::Skin::Mecha);
        theme::apply(app);
        UiHost host(app, false);
        int created = 0;
        QObject::connect(&host, &UiHost::windowCreated, &app, [&created](MainWindow* w) {
            ++created;
            QTimer::singleShot(300, w, [w] { feedDemo(w->findChild<IpcClient*>()); });
        });
        host.start(true);
        host.window()->resize(1320, 880);
        host.window()->move(16, 16);
        settle(900);
        host.window()->openPage(QString::fromLatin1(nav::Settings));
        settle(300);
        save(host.window()->grab(), outDir, QStringLiteral("rebuild-0-mecha"), failed);
        const QSize want = host.window()->size();
        const auto step = [&](theme::Skin s, const char* name) {
            const int before = created;
            theme::requestSkin(s);
            settle(1500);
            MainWindow* w = host.window();
            const bool ok = w && created == before + 1 && w->isVisible() && theme::skin() == s
                            && w->currentPageKey() == QString::fromLatin1(nav::Settings) && w->size() == want;
            out() << name << (ok ? "  重建正常" : "  重建异常")
                  << "  新窗口=" << (created == before + 1 ? "是" : "否")
                  << "  可见=" << (w && w->isVisible() ? "是" : "否")
                  << "  皮肤=" << theme::skinKey(theme::skin())
                  << "  页面=" << (w ? w->currentPageKey() : QString())
                  << "  尺寸=" << (w ? w->width() : 0) << "x" << (w ? w->height() : 0) << "\n";
            if (!ok)
                ++failed;
            if (w)
                save(w->grab(), outDir, QString::fromLatin1(name), failed);
        };
        step(theme::Skin::Kawaii, "rebuild-1-kawaii");
        step(theme::Skin::Titan, "rebuild-2-titan");
        step(theme::Skin::Mecha, "rebuild-3-mecha");
        out().flush();
        return failed == 0 ? 0 : 1;
    }

    // 交互模式:用与正式界面同一个 UiHost 打开一扇可操作的主窗口(假数据、不连服务),
    // 用来手动验证拖动 / 缩放 / 最大化与换皮肤重建。到时自动退出。
    if (interactiveSecs > 0) {
        theme::setSkin(theme::skinFromKey(skins.value(0)));
        theme::apply(app);
        UiHost host(app, false);
        QObject::connect(&host, &UiHost::windowCreated, &app, [](MainWindow* w) {
            QTimer::singleShot(300, w, [w] { feedDemo(w->findChild<IpcClient*>()); });
        });
        host.start(true);
        if (MainWindow* w = host.window()) {
            w->resize(1320, 880);
            w->move(60, 40);
        }
        QTimer::singleShot(interactiveSecs * 1000, &app, &QApplication::quit);
        return app.exec();
    }
    if (!QDir().mkpath(outDir)) {
        out() << "无法创建输出目录: " << outDir << "\n";
        out().flush();
        return 1;
    }

    int failed = 0;
    if (audit)
        previewaudit::enable(outDir);
    for (const QString& key : skins) {
        theme::setSkin(theme::skinFromKey(key));
        theme::apply(app);
        previewaudit::setSkin(key);
        const QString prefix = key + QLatin1Char('-');
        if (only.contains(QStringLiteral("main")))
            renderMain(outDir, prefix, failed);
        if (only.contains(QStringLiteral("popups"))) {
            // 时间固定,弹窗截图才可重复比对。
            setFixedNowUtcForTest(QDateTime(QDate(2026, 3, 1), QTime(12, 0, 0), QTimeZone::UTC));
            renderPopups(outDir, prefix, failed);
            setFixedNowUtcForTest(QDateTime());
        }
        out().flush();
        previewaudit::flush();
    }
    out().flush();
    return failed == 0 ? 0 : 1;
}
