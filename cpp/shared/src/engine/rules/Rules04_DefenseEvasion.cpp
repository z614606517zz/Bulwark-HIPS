#include "RuleDsl.h"

namespace bulwark::engine::rules {

namespace {

const QStringList& powerShellHosts() {
    static const QStringList s = exes({ "powershell.exe", "pwsh.exe", "powershell_ise.exe" });
    return s;
}

void defender(Segment& s) {
    // 只认「关」的方向:-Disable* $false / 0 是重新开启。实时、行为、下载、脚本扫描是勒索前的必经一步,直接拦;
    // 归档 / 移动盘 / 邮件扫描常被调优脚本关掉,只问。
    // 值紧跟开关才硬拦:-DisableRealtimeMonitoring $false -SignatureUpdateInterval 1 是重新开启,
    // 不能因为后面别的参数带了 1 / true 就拦。值与开关隔开的(括号表达式等混淆写法)只问。
    const char* const switchedOn[] = { " $true*", ":$true*", " 1*", ":1*" };
    for (const char* sw : { "disablerealtimemonitoring", "disablebehaviormonitoring", "disableioavprotection",
                            "disablescriptscanning", "disableblockatfirstseen", "disableintrusionpreventionsystem" }) {
        for (const char* on : switchedOn)
            s.proc(Block, "命令行关闭 Defender 核心防护(T1562.001)")
                .cmd(u("*set-mppreference*") + u(sw) + u(on)).hard();
        for (const char* on : { "*true*", "* 1*" })
            s.proc(Ask, "命令行疑似关闭 Defender 核心防护(T1562.001)")
                .cmd(u("*set-mppreference*") + u(sw) + u(on)).disableSignedAutoAllow();
    }
    for (const QString& host : powerShellHosts()) {
        for (const char* sw : { "disablearchivescanning", "disableremovabledrivescanning", "disableemailscanning" })
            for (const char* on : switchedOn)
                s.proc(Ask, "PowerShell 关闭 Defender 防护项(T1562.001)")
                    .actor(host).cmd(u("*set-mppreference*") + u(sw) + u(on)).disableSignedAutoAllow();
        // Set-MpPreference -Exclusion* 是整表覆盖,一样能添上排除项。
        for (const char* p : { "*add-mppreference*exclusionpath*", "*add-mppreference*exclusionprocess*",
                               "*add-mppreference*exclusionextension*", "*add-mppreference*exclusionipaddress*",
                               "*set-mppreference*exclusionpath*", "*set-mppreference*exclusionprocess*",
                               "*set-mppreference*exclusionextension*", "*set-mppreference*exclusionipaddress*" })
            s.proc(Ask, "PowerShell 添加 Defender 排除项(T1562.001)")
                .actor(host).cmd(p).disableSignedAutoAllow();
        // MAPSReporting 0 = Disabled,SubmitSamplesConsent 2 = NeverSend;值同样要紧跟开关。
        for (const char* p : { "*set-mppreference*mapsreporting 0*", "*set-mppreference*mapsreporting:0*",
                               "*set-mppreference*mapsreporting disabled*", "*set-mppreference*mapsreporting:disabled*",
                               "*set-mppreference*submitsamplesconsent 2*", "*set-mppreference*submitsamplesconsent:2*",
                               "*set-mppreference*submitsamplesconsent neversend*",
                               "*set-mppreference*submitsamplesconsent:neversend*" })
            s.proc(Ask, "PowerShell 关闭 Defender 云保护 / 样本提交(T1562.001)")
                .actor(host).cmd(p).disableSignedAutoAllow();
    }
    s.proc(Ask, "删除 Defender 特征库(T1562.001)")
        .actor("*\\mpcmdrun.exe").cmd("*removedefinitions*all*").disableSignedAutoAllow();

    // 把威胁默认处置改成「允许 / 不处理」:Defender 照样报,样本照样跑。
    // 按严重级放行高危 / 严重威胁没有正当理由;按威胁 ID 放行是管理员处理误报的做法,只问。
    for (const char* sev : { "highthreatdefaultaction", "severethreatdefaultaction" })
        for (const char* v : { " allow*", ":allow*", " 6*", ":6*", " noaction*", ":noaction*", " 9*", ":9*" })
            s.proc(Block, "把高危 / 严重威胁的默认处置改为放行(T1562.001)")
                .cmd(u("*-") + u(sev) + u(v)).hard();
    for (const char* key : { "lowthreatdefaultaction", "moderatethreatdefaultaction", "threatiddefaultaction_actions" })
        for (const char* v : { " allow*", ":allow*", " 6*", ":6*", " noaction*", ":noaction*", " 9*", ":9*" })
            s.proc(Ask, "把威胁的默认处置改为放行(T1562.001)")
                .cmd(u("*-") + u(key) + u(v)).disableSignedAutoAllow();
    for (const char* key : { "*\\Windows Defender\\Threats\\ThreatSeverityDefaultAction\\*",
                             "*\\Windows Defender\\Threats\\ThreatIdDefaultAction\\*" }) {
        s.reg(Block, "通过注册表改写 Defender 威胁默认处置(未签名写入者,T1562.001)")
            .target(key).unsignedOnly().onlySetValue().exemptOs().hard();
        for (const QString& w : scriptedWriters())
            s.reg(Ask, u("经 ") + imageNameOf(w) + u(" 改写 Defender 威胁默认处置(T1562.001)"))
                .actor(w).target(key).onlySetValue().disableSignedAutoAllow();
    }

    struct PolicyValue { const char* key; quint32 value; };
    const PolicyValue policies[] = {
        { "*\\Windows Defender\\DisableAntiSpyware", 1 },
        { "*\\Windows Defender\\DisableAntiVirus", 1 },
        { "*\\Real-Time Protection\\DisableRealtimeMonitoring", 1 },
        { "*\\Real-Time Protection\\DisableBehaviorMonitoring", 1 },
        { "*\\Real-Time Protection\\DisableOnAccessProtection", 1 },
        { "*\\Real-Time Protection\\DisableScanOnRealtimeEnable", 1 },
        { "*\\Real-Time Protection\\DisableIOAVProtection", 1 },
        { "*\\Spynet\\SpynetReporting", 0 },
        { "*\\Spynet\\SubmitSamplesConsent", 2 },
        { "*\\Windows Defender\\Features\\TamperProtection", 0 },
    };
    // 组策略由系统组件落地(豁免);用户在 Windows 安全中心里改由 MsMpEng 写,不在脚本写入者之列。
    for (const PolicyValue& p : policies) {
        s.reg(Block, "通过注册表关闭 Defender 防护(未签名写入者,T1562.001)")
            .target(p.key).regDword(p.value).unsignedOnly().onlySetValue().exemptOs().hard();
        for (const QString& w : scriptedWriters())
            s.reg(Ask, u("经 ") + imageNameOf(w) + u(" 通过注册表关闭 Defender 防护(T1562.001)"))
                .actor(w).target(p.key).regDword(p.value).onlySetValue().disableSignedAutoAllow();
    }
    for (const char* key : { "*\\Windows Defender\\Exclusions\\Paths\\*", "*\\Windows Defender\\Exclusions\\Processes\\*",
                             "*\\Windows Defender\\Exclusions\\Extensions\\*" }) {
        s.reg(Block, "直接写入 Defender 排除项(未签名写入者,T1562.001)")
            .target(key).unsignedOnly().onlySetValue().exemptOs().hard();
        for (const QString& w : scriptedWriters())
            s.reg(Ask, u("经 ") + imageNameOf(w) + u(" 直接写入 Defender 排除项(T1562.001)"))
                .actor(w).target(key).onlySetValue().disableSignedAutoAllow();
    }
}

void telemetryBlinding(Segment& s) {
    s.reg(Block, "改写 / 删除 AMSI 提供程序注册(未签名写入者,T1562.001)")
        .target("*\\Microsoft\\AMSI\\Providers\\*").unsignedOnly().exemptOs().hard();
    for (const QString& w : scriptedWriters())
        s.reg(Ask, u("经 ") + imageNameOf(w) + u(" 删除 AMSI 提供程序注册(T1562.001)"))
            .actor(w).target("*\\Microsoft\\AMSI\\Providers\\*").onlyDeleteKey().disableSignedAutoAllow();
    s.reg(Block, "关闭 Windows 脚本宿主的 AMSI(T1562.001)")
        .target("*\\Windows Script\\Settings\\AmsiEnable").regDword(0).onlySetValue().exemptOs().hard();

    // 只盯安全相关的会话;隐私优化工具关 DiagTrack 等遥测会话是常见的正常操作。
    struct Toggle { const char* what; const char* key; quint32 value; };
    const Toggle toggles[] = {
        { "关闭安全事件日志会话(T1562.006)", "*\\Autologger\\EventLog-Security\\Start", 0 },
        { "关闭安全事件日志会话(T1562.006)", "*\\Autologger\\EventLog-Security\\Enabled", 0 },
        { "关闭系统事件日志会话(T1562.006)", "*\\Autologger\\EventLog-System\\Start", 0 },
        { "关闭 Defender 跟踪会话(T1562.006)", "*\\Autologger\\DefenderApiLogger\\Start", 0 },
        { "关闭 Defender 跟踪会话(T1562.006)", "*\\Autologger\\DefenderAuditLogger\\Start", 0 },
        { "关闭 PowerShell 脚本块日志(T1562.002)", "*\\PowerShell\\ScriptBlockLogging\\EnableScriptBlockLogging", 0 },
        { "关闭 PowerShell 模块日志(T1562.002)", "*\\PowerShell\\ModuleLogging\\EnableModuleLogging", 0 },
    };
    for (const Toggle& t : toggles) {
        s.reg(Ask, u(t.what) + u("(未签名写入者)")).target(t.key).regDword(t.value).unsignedOnly().onlySetValue();
        for (const QString& w : scriptedWriters())
            s.reg(Ask, u(t.what) + u("(经 ") + imageNameOf(w) + u(")"))
                .actor(w).target(t.key).regDword(t.value).onlySetValue().disableSignedAutoAllow();
    }

    for (const char* p : { "*cl *", "*clear-log*" })
        s.proc(Ask, "清除事件日志(T1070.001)").actor("*\\wevtutil.exe").cmd(p).disableSignedAutoAllow();
    s.proc(Ask, "关闭事件日志通道(T1562.002)").actor("*\\wevtutil.exe").cmd("*sl*/e:false*").disableSignedAutoAllow();
    for (const QString& host : powerShellHosts())
        for (const char* p : { "*clear-eventlog*", "*remove-eventlog*", "*globalsession.clearlog*",
                               "*limit-eventlog*-maximumsize*" })
            s.proc(Ask, "PowerShell 清除 / 截断事件日志(T1070.001)").actor(host).cmd(p).disableSignedAutoAllow();
    for (const char* p : { "*/clear*", "*/remove*", "*/success:disable*/failure:disable*" })
        s.proc(Ask, "清空或关闭审计策略(T1562.002)").actor("*\\auditpol.exe").cmd(p).disableSignedAutoAllow();
    for (const char* p : { "*stop*eventlog-*", "*update*trace*--p*" })
        s.proc(Ask, "停止或改写事件跟踪会话(T1562.006)").actor("*\\logman.exe").cmd(p).disableSignedAutoAllow();
    s.proc(Ask, "卸载 Sysmon(T1562.001)").actor("*\\sysmon*.exe").cmd("* -u*").disableSignedAutoAllow();
}

void systemDefenses(Segment& s) {
    for (const char* p : { "*advfirewall*set*state*off*", "*firewall*set*opmode*disable*" })
        s.proc(Ask, "关闭 Windows 防火墙(T1562.004)").actor("*\\netsh.exe").cmd(p).disableSignedAutoAllow();
    for (const QString& host : powerShellHosts())
        s.proc(Ask, "PowerShell 关闭 Windows 防火墙(T1562.004)")
            .actor(host).cmd("*set-netfirewallprofile*-enabled*false*").disableSignedAutoAllow();

    struct Toggle { const char* what; const char* key; quint32 value; };
    const Toggle toggles[] = {
        { "通过注册表关闭防火墙(T1562.004)", "*\\FirewallPolicy\\*Profile\\EnableFirewall", 0 },
        { "通过组策略关闭防火墙(T1562.004)", "*\\WindowsFirewall\\*Profile\\EnableFirewall", 0 },
        { "关闭 UAC(T1548.002)", "*\\Policies\\System\\EnableLUA", 0 },
        { "管理员提权不再提示(T1548.002)", "*\\Policies\\System\\ConsentPromptBehaviorAdmin", 0 },
        { "UAC 不再使用安全桌面(T1548.002)", "*\\Policies\\System\\PromptOnSecureDesktop", 0 },
        { "放开远程本地账户令牌过滤(横向移动前置,T1548.002)", "*\\Policies\\System\\LocalAccountTokenFilterPolicy", 1 },
        { "禁用任务管理器(T1562)", "*\\Policies\\System\\DisableTaskMgr", 1 },
        { "禁用注册表编辑器(T1562)", "*\\Policies\\System\\DisableRegistryTools", 1 },
        { "关闭系统还原(T1490)", "*\\SystemRestore\\DisableSR", 1 },
        { "禁用命令提示符(T1562)", "*\\Policies\\Microsoft\\Windows\\System\\DisableCMD", 1 },
        { "禁用命令提示符(T1562)", "*\\Policies\\Microsoft\\Windows\\System\\DisableCMD", 2 },
        { "关闭 SmartScreen(T1553.005)", "*\\Policies\\Microsoft\\Windows\\System\\EnableSmartScreen", 0 },
        { "关闭 Edge SmartScreen(T1553.005)", "*\\Policies\\Microsoft\\Edge\\SmartScreenEnabled", 0 },
        { "隐藏「文件夹选项」(让用户没法显示隐藏文件,T1564.001)", "*\\Policies\\Explorer\\NoFolderOptions", 1 },
        { "开启「禁止运行指定程序」(可用来封锁安全工具,T1562.001)", "*\\Policies\\Explorer\\DisallowRun", 1 },
        { "隐藏安全中心通知图标(T1562.001)", "*\\Policies\\Explorer\\HideSCAHealth", 1 },
        { "关闭 Defender 通知(T1562.001)", "*\\Windows Defender Security Center\\Notifications\\DisableNotifications", 1 },
        { "关闭 Defender 通知(T1562.001)",
          "*\\Windows Defender Security Center\\Notifications\\DisableEnhancedNotifications", 1 },
        { "抑制 Defender 通知(T1562.001)", "*\\Windows Defender\\UX Configuration\\Notification_Suppress", 1 },
        { "关闭易受攻击驱动黑名单(为 BYOVD 铺路,T1562.001/T1068)",
          "*\\Control\\CI\\Config\\VulnerableDriverBlocklistEnable", 0 },
        { "关闭内存完整性 HVCI(T1562.001)",
          "*\\DeviceGuard\\Scenarios\\HypervisorEnforcedCodeIntegrity\\Enabled", 0 },
        { "关闭基于虚拟化的安全 VBS(T1562.001)", "*\\Control\\DeviceGuard\\EnableVirtualizationBasedSecurity", 0 },
        { "关闭 Windows 自动更新(T1562)", "*\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU\\NoAutoUpdate", 1 },
    };
    for (const Toggle& t : toggles) {
        s.reg(Ask, u(t.what) + u("(未签名写入者)"))
            .target(t.key).regDword(t.value).unsignedOnly().onlySetValue().exemptOs();
        for (const QString& w : scriptedWriters())
            s.reg(Ask, u(t.what) + u("(经 ") + imageNameOf(w) + u(")"))
                .actor(w).target(t.key).regDword(t.value).onlySetValue().disableSignedAutoAllow();
    }

    // 安全软件会把自己登记进安全模式服务表;勒索也会,借安全模式绕开防护。
    s.reg(Ask, "向安全模式启动表登记服务(未签名写入者,T1562.009)")
        .target("*\\Control\\SafeBoot\\*").unsignedOnly().onlySetValue();
    for (const QString& w : scriptedWriters())
        s.reg(Ask, u("经 ") + imageNameOf(w) + u(" 向安全模式启动表登记服务(T1562.009)"))
            .actor(w).target("*\\Control\\SafeBoot\\*").disableSignedAutoAllow();

    for (const char* p : { "*testsigning*on*", "*nointegritychecks*on*", "*loadoptions*disable_integrity_checks*",
                           "*set*safeboot*" })
        s.proc(Ask, "改写启动配置以关闭驱动签名校验或进入安全模式(T1562.009/T1553.006)")
            .actor("*\\bcdedit.exe").cmd(p).disableSignedAutoAllow();

    // 用策略封锁安全工具:DisallowRun 名单、软件限制策略的路径 / 哈希规则;把更新指向别的 WSUS。
    // 组策略由系统组件落地(豁免);小厂商的加固工具可能没签名,只问。
    for (const char* key : { "*\\Policies\\Explorer\\DisallowRun\\*",
                             "*\\Policies\\Microsoft\\Windows\\Safer\\CodeIdentifiers\\*",
                             "*\\Policies\\Microsoft\\Windows\\WindowsUpdate\\WUServer",
                             "*\\Policies\\Microsoft\\Windows\\WindowsUpdate\\WUStatusServer" }) {
        s.reg(Ask, "写入程序封锁 / 更新服务器策略(可用来封锁安全软件或劫持更新,未签名写入者,T1562.001)")
            .target(key).unsignedOnly().onlySetValue().exemptOs();
        for (const QString& w : scriptedWriters())
            s.reg(Ask, u("经 ") + imageNameOf(w) + u(" 写入程序封锁 / 更新服务器策略(T1562.001)"))
                .actor(w).target(key).onlySetValue().disableSignedAutoAllow();
    }

    // 把服务的安全描述符改成拒绝访问:服务照常运行,却从 services.msc / sc query 里消失。
    s.proc(Ask, "改写服务安全描述符并加入拒绝项(隐藏服务,T1564/T1543.003)")
        .actor("*\\sc.exe").cmd("*sdset*(d;*").disableSignedAutoAllow();
    for (const QString& host : powerShellHosts())
        s.proc(Ask, "PowerShell 改写服务安全描述符并加入拒绝项(隐藏服务,T1564/T1543.003)")
            .actor(host).cmd("*-securitydescriptorsddl*(d;*").disableSignedAutoAllow();

    for (const char* p : { "*usn*deletejournal*" })
        s.proc(Ask, "删除 USN 变更日志(清除痕迹,T1070)").actor("*\\fsutil.exe").cmd(p).disableSignedAutoAllow();
    for (const QString& host : exes({ "cmd.exe", "powershell.exe", "pwsh.exe" }))
        for (const char* p : { "*\\windows\\prefetch\\*", "*\\windows\\system32\\winevt\\logs\\*" })
            for (const char* verb : { "*del *", "*remove-item*", "*erase *" })
                s.proc(Ask, "删除预读 / 事件日志文件(清除痕迹,T1070.004)")
                    .actor(host).cmd(u(verb) + u(p)).disableSignedAutoAllow();

    // 「touch」写法是 = Get-Date;把时间戳写成一个写死的过去日期,多是伪装文件年龄。
    // 整理照片、归档文档时按拍摄 / 原始日期回写也是这个写法:一般文件只问,
    // 改的是程序、驱动才硬拦。命令行开头就是 powershell.exe / cmd.exe 自己的路径,属性写法里
    // .exe 只认引号 / 括号收尾的目标,如 (Get-Item 'x.exe').LastWriteTime;调用写法的目标在 Set*Time( 之后。
    for (const char* prop : { ".lastwritetime", ".creationtime", ".lastaccesstime" })
        for (const char* assign : { " = '", "='", " = \"", " = [datetime]", "=[datetime]" }) {
            s.proc(Ask, "改写文件时间戳为指定日期(Timestomp,T1070.006)")
                .cmd(u("*") + u(prop) + u(assign) + u("*")).disableSignedAutoAllow();
            for (const char* target : { ".dll", ".sys", ".exe'", ".exe)", ".exe\")" })
                s.proc(Block, "改写程序 / 系统文件的时间戳为指定日期(Timestomp,T1070.006)")
                    .cmd(u("*") + u(target) + u("*") + u(prop) + u(assign) + u("*")).hard();
        }
    for (const char* api : { "setlastwritetime", "setcreationtime", "setlastaccesstime" }) {
        s.proc(Ask, "经 [IO.File]::Set*Time 把时间戳改成指定日期(Timestomp,T1070.006)")
            .cmd(u("*") + u(api) + u("(*,*'*")).disableSignedAutoAllow();
        for (const char* target : { ".exe", ".dll", ".sys", ".ps1", "\\windows\\" })
            s.proc(Block, "经 [IO.File]::Set*Time 改写程序 / 系统文件的时间戳(Timestomp,T1070.006)")
                .cmd(u("*") + u(api) + u("(*") + u(target) + u("*,*'*")).hard();
    }

    for (const char* p : { "*attrib*+h*\\users\\public\\*", "*attrib*+s*\\users\\public\\*" })
        s.proc(Block, "隐藏公共用户目录里的载荷(T1564.001)").cmd(p).hard();
    // 程序隐藏自己的文件走 API,不经 attrib;命令行把可执行内容设成隐藏多是投递后的收尾。
    // 扩展名必须出现在 +h 之后:命令行开头的 attrib.exe 自己也带 .exe。
    for (const char* x : { ".exe", ".dll", ".scr", ".vbs", ".vbe", ".jse", ".wsf", ".hta", ".ps1", ".bat", ".cmd",
                           ".lnk" })
        s.proc(Ask, "把可执行内容设为隐藏(T1564.001)")
            .actor("*\\attrib.exe").cmd(u("*+h*") + u(x) + u("*")).disableSignedAutoAllow();
    // 给载荷加拒绝访问项,让杀软读不到、删不掉。
    s.proc(Ask, "为文件 / 目录加拒绝访问项(阻止查杀,T1222.001)")
        .actor("*\\icacls.exe").cmd("*/deny*").disableSignedAutoAllow();
    // 删除 Amcache / 安全擦除:抹掉程序运行记录与投递工具。
    s.del(Ask, "未签名程序删除程序运行记录 Amcache(T1070)")
        .target("*\\AppCompat\\Programs\\Amcache.hve*").unsignedOnly().exemptOs();
    for (const QString& w : scriptHosts())
        s.del(Ask, u("经 ") + imageNameOf(w) + u(" 删除程序运行记录 Amcache(T1070)"))
            .actor(w).target("*\\AppCompat\\Programs\\Amcache.hve*").disableSignedAutoAllow();
    s.proc(Ask, "运行安全擦除工具 sdelete(抹除痕迹,T1070.004)").actor("*\\sdelete*.exe").disableSignedAutoAllow();
    // 把载荷放进便携 QEMU 虚拟机里跑:主机上的安全软件看不到虚拟机里的进程与文件。
    for (const char* d : { "\\appdata\\", "\\temp\\", "\\users\\public\\", "\\programdata\\" })
        s.proc(Ask, "从投递目录运行 QEMU 虚拟机(在虚拟机里藏匿载荷,T1564.006)")
            .actor(u("*") + u(d) + u("*\\qemu-system-*.exe")).disableSignedAutoAllow();
    // Android SDK 的模拟器就是 QEMU,默认装在 %LOCALAPPDATA%\Android\Sdk 下;签名健康的放行。
    s.proc(Allow, "Android SDK 模拟器(QEMU)")
        .actor("*\\android\\sdk\\emulator\\*qemu-system-*.exe").signedOnly();
    // 更新程序也会延时清理自己的临时文件,只认删的是程序本体。
    for (const char* wait : { "*ping*127.0.0.1*", "*timeout*/t*" })
        for (const char* d : { "\\users\\public\\", "\\appdata\\local\\temp\\", "\\windows\\temp\\" })
            s.proc(Ask, "延时后删除投递目录里的程序(释放器自删收尾,T1070.004)")
                .cmd(u(wait) + u("*&*del *") + u(d) + u("*.exe*")).disableSignedAutoAllow();
    s.proc(Ask, "关闭 PowerShell 命令历史(T1070.003)")
        .cmd("*set-psreadlineoption*-historysavestyle*savenothing*").disableSignedAutoAllow();
    for (const char* p : { "*remove-item*consolehost_history*", "*del *consolehost_history*", "*clear-content*consolehost_history*",
                           "*remove-item*historysavepath*", "*historysavepath*remove-item*" })
        s.proc(Ask, "删除 PowerShell 命令历史文件(T1070.003)").cmd(p).disableSignedAutoAllow();
    for (const char* p : { "*disable-computerrestore*", "*\\systemrestore*disablesr*" })
        s.proc(Ask, "关闭系统还原(T1490)").cmd(p).disableSignedAutoAllow();

    // 把可执行内容藏进 NTFS 备用数据流,目录列表与大多数扫描都看不到。
    for (const char* p : { "*set-content*-stream*", "*add-content*-stream*" })
        s.proc(Ask, "写入 NTFS 备用数据流(T1564.004)").cmd(p).disableSignedAutoAllow();
    for (const char* x : { ".exe", ".dll", ".ps1", ".vbs", ".js", ".bat", ".hta" }) {
        const QString target = u("?:\\*:*") + u(x);
        s.file(Ask, "向 NTFS 备用数据流写入可执行内容(未签名写入者,T1564.004)").target(target).unsignedOnly();
        for (const QString& w : scriptHosts())
            s.file(Ask, u("经 ") + imageNameOf(w) + u(" 向 NTFS 备用数据流写入可执行内容(T1564.004)"))
                .actor(w).target(target).disableSignedAutoAllow();
    }

    // 替换系统文件前要先拿到所有权 / 放开权限。
    for (const char* p : { "*takeown*/f*\\windows\\*/r*", "*icacls*\\windows\\*/grant*everyone*",
                           "*icacls*\\windows\\*/grant*users*" })
        s.proc(Ask, "接管 / 放开 Windows 目录权限(替换系统文件的前置,T1222.001)").cmd(p).disableSignedAutoAllow();

    // Office 宏安全设置被调低是宏文档的铺路;Office 自己(签名)在信任中心里改不在此列。
    const char* officeSecurity[] = {
        "*\\Word\\Security\\VBAWarnings", "*\\Excel\\Security\\VBAWarnings", "*\\PowerPoint\\Security\\VBAWarnings",
        "*\\Word\\Security\\AccessVBOM", "*\\Excel\\Security\\AccessVBOM", "*\\PowerPoint\\Security\\AccessVBOM",
        "*\\Security\\ProtectedView\\*",
    };
    for (const char* key : officeSecurity) {
        s.reg(Ask, "调低 Office 宏安全设置 / 关闭受保护视图(未签名写入者,T1112)")
            .target(key).unsignedOnly().onlySetValue().exemptOs();
        for (const QString& w : scriptedWriters())
            s.reg(Ask, u("经 ") + imageNameOf(w) + u(" 调低 Office 宏安全设置 / 关闭受保护视图(T1112)"))
                .actor(w).target(key).onlySetValue().exemptOs().disableSignedAutoAllow();
    }

    // 投放代码完整性策略可以让安全软件的驱动开机就加载不了。
    for (const char* p : { "*\\System32\\CodeIntegrity\\SiPolicy.p7b", "*\\CodeIntegrity\\CiPolicies\\Active\\*.cip" }) {
        s.file(Block, "投放代码完整性策略(可禁止安全软件加载,T1562.001)")
            .target(p).unsignedOnly().exemptOs().hard();
        for (const QString& w : scriptHosts())
            s.file(Ask, u("经 ") + imageNameOf(w) + u(" 投放代码完整性策略(T1562.001)"))
                .actor(w).target(p).disableSignedAutoAllow();
    }
}

void securityProducts(Segment& s) {
    // 安全软件自己的卸载器走服务控制 API,不经 taskkill / net stop;命令行里点名结束才问。
    for (const QString& img : securityProductImages()) {
        const QString pattern = u("*\\") + img;
        s.kill(Block, u("未签名程序结束安全软件进程 ") + img + u("(T1562.001)"))
            .target(pattern).unsignedOnly().hard();
        for (const QString& killer : exes({ "taskkill.exe", "tskill.exe", "ntsd.exe", "pskill.exe", "pskill64.exe",
                                            "powershell.exe", "pwsh.exe", "wmic.exe" }))
            s.kill(Block, u("经 ") + imageNameOf(killer) + u(" 结束安全软件进程 ") + img + u("(T1562.001)"))
                .actor(killer).target(pattern).hard();
        s.proc(Ask, u("命令行点名结束安全软件进程 ") + img + u("(T1562.001)"))
            .actor("*\\taskkill.exe").cmd(u("*") + img + u("*")).disableSignedAutoAllow();
        // 挂起比结束更隐蔽:进程还在,检测却停了。
        for (const QString& tool : exes({ "pssuspend.exe", "pssuspend64.exe" }))
            s.proc(Block, u("挂起安全软件进程 ") + img + u("(T1562.001)"))
                .actor(tool).cmd(u("*") + img + u("*")).hard();
        // 用防火墙规则掐断安全软件联网(EDRSilencer 的手法):进程照常运行,告警与云查杀却出不去。
        for (const QString& form : { u("*advfirewall*add*rule*action=block*") + img + u("*"),
                                     u("*advfirewall*add*rule*") + img + u("*action=block*") })
            s.proc(Block, u("用防火墙规则阻断安全软件 ") + img + u(" 联网(T1562.004)"))
                .actor("*\\netsh.exe").cmd(form).hard();
        for (const QString& host : powerShellHosts())
            for (const QString& form : { u("*new-netfirewallrule*-action*block*") + img + u("*"),
                                         u("*new-netfirewallrule*") + img + u("*-action*block*") })
                s.proc(Block, u("PowerShell 用防火墙规则阻断安全软件 ") + img + u(" 联网(T1562.004)"))
                    .actor(host).cmd(form).hard();
    }
    for (const QString& tool : exes({ "pssuspend.exe", "pssuspend64.exe" }))
        s.proc(Ask, "挂起进程(PsSuspend,T1562.001)").actor(tool).disableSignedAutoAllow();

    // 专门对付安全软件的工具:用 WFP 掐网、拆内核回调、借易受攻击驱动结束受保护进程。
    for (const char* name : { "edrsilencer", "edrsandblast", "edr-freeze", "edrfreeze", "aukill", "backstab",
                              "killdefender", "edrkiller" }) {
        s.proc(Block, u("运行反安全软件工具 ") + u(name) + u("(T1562.001)"))
            .actor(u("*\\") + u(name) + u("*.exe")).unsignedOnly().hard();
        s.file(Block, u("投放反安全软件工具 ") + u(name) + u("(T1562.001)"))
            .target(u("*\\") + u(name) + u("*.exe")).unsignedOnly().hard();
    }
    // EDR-Freeze:让 WerFaultSecure 以「转储」名义挂起受保护的安全软件进程。正常由 WER 拉起;
    // Defender 平台本体装在 ProgramData 下,ProgramData 不算投递目录。
    for (const QString& parent : scriptHosts())
        s.proc(Block, u("脚本宿主 ") + imageNameOf(parent) + u(" 拉起 WerFaultSecure(挂起受保护进程,T1562.001)"))
            .actor("*\\werfaultsecure.exe").parent(parent).hard();
    for (const char* d : { "\\appdata\\", "\\temp\\", "\\users\\public\\", "\\downloads\\" })
        s.proc(Block, "投递目录中的程序拉起 WerFaultSecure(挂起受保护进程,T1562.001)")
            .actor("*\\werfaultsecure.exe").parent(u("*") + u(d) + u("*")).hard();
    // 按命令行匹配:cmd /c 套一层或 & 串接(sc stop A & sc stop WinDefend)都能命中。
    // Defender 本体服务没有正当的命令行停用场景,直接拦;第三方安全软件与 Sysmon 由管理员维护,只问。
    const QStringList defenderServices = { u("windefend"), u("wdnissvc"), u("sense"), u("wdboot"), u("wdfilter"),
                                           u("securityhealthservice"), u("wscsvc") };
    const QStringList stopForms = { u("*sc stop *"), u("*sc.exe stop *"), u("*sc.exe\" stop *"), u("*sc delete *"),
                                    u("*sc.exe delete *"), u("*sc.exe\" delete *"), u("*net stop *"), u("*net1 stop *"),
                                    u("*net.exe stop *"), u("*stop-service*") };
    // sense 同时是常见词片段(license、nonsense):这个服务名必须紧跟在动词或 -Name 后面才算。
    const auto serviceCmds = [](const QString& form, const QString& svc, const char* tail) {
        if (svc != QLatin1String("sense"))
            return QStringList{ form + svc + u(tail) };
        const QString verb = form.chopped(1);
        QStringList out;
        if (verb.endsWith(QLatin1String("-service"))) {
            for (const char* lead : { " ", " \"", " '", "*-name ", "*-name \"", "*-name '" })
                out << verb + u(lead) + svc + u(tail);
        } else {
            for (const char* lead : { "", "\"" })
                out << verb + u(lead) + svc + u(tail);
        }
        return out;
    };
    for (const QString& svc : securityServiceNames()) {
        const bool core = defenderServices.contains(svc);
        for (const QString& form : stopForms)
            for (const QString& cmd : serviceCmds(form, svc, "*")) {
                if (core)
                    s.proc(Block, u("停止 / 删除 Defender 服务 ") + svc + u("(T1562.001)"))
                        .cmd(cmd).hard();
                else
                    s.proc(Ask, u("停止 / 删除安全服务 ") + svc + u("(T1562.001)"))
                        .cmd(cmd).disableSignedAutoAllow();
            }
        for (const char* form : { "*sc*config *", "*set-service*" }) {
            for (const QString& cmd : serviceCmds(u(form), svc, "*"))
                s.proc(Ask, u("改写安全服务 ") + svc + u(" 的启动方式(T1562.001)"))
                    .cmd(cmd).disableSignedAutoAllow();
            if (core)
                for (const QString& cmd : serviceCmds(u(form), svc, "*disabled*"))
                    s.proc(Block, u("禁用 Defender 服务 ") + svc + u("(T1562.001)"))
                        .cmd(cmd).hard();
        }
    }
    for (const char* filter : { "wdfilter", "sysmondrv", "wdboot" })
        s.proc(Ask, u("卸载安全产品的文件系统过滤驱动 ") + u(filter) + u("(T1562.001)"))
            .actor("*\\fltmc.exe").cmd(u("*unload*") + u(filter) + u("*")).disableSignedAutoAllow();

    // 停掉更新与日志:断了补丁和安全情报,也断了事后取证。
    // 重置更新组件的排障脚本第一步就是 net stop wuauserv,停更新服务只留记录(签名程序照常放行);
    // 删除、禁用更新服务和停事件日志才真的问。
    for (const char* svc : { "wuauserv", "usosvc", "uhssvc", "waasmedicsvc", "dosvc", "eventlog" }) {
        const bool updateService = qstrcmp(svc, "eventlog") != 0;
        for (const QString& form : stopForms) {
            RuleRef r = s.proc(Ask, u("停止 / 删除系统服务 ") + u(svc) + u("(更新 / 日志,T1562.001/T1562.002)"))
                            .cmd(form + u(svc) + u("*"));
            if (!updateService || form.contains(QLatin1String("delete")))
                r.disableSignedAutoAllow();
        }
        for (const char* form : { "*sc*config *", "*set-service*" })
            s.proc(Ask, u("禁用系统服务 ") + u(svc) + u("(更新 / 日志,T1562.001/T1562.002)"))
                .cmd(u(form) + u(svc) + u("*disabled*")).disableSignedAutoAllow();
    }
}

// 整棵恢复 / 替换注册表键(RegRestoreKey、reg restore、RegReplaceKey)一次改写整个子树,逐值规则全看不见。
// 子树含内核硬拦项、凭据配置单元或本产品服务键的,内核已经直接拒绝;这里管其余的。
// 系统配置与自启动所在的子树(连同它们的上级)直接拦,其余只问 —— 正常软件几乎不这么写注册表。
void registryRestore(Segment& s) {
    for (const char* key : { "*\\MACHINE\\SYSTEM", "*\\MACHINE\\SYSTEM\\*",
                             "*\\MACHINE\\SOFTWARE", "*\\MACHINE\\SOFTWARE\\Microsoft*",
                             "*\\MACHINE\\SOFTWARE\\Classes*", "*\\MACHINE\\SOFTWARE\\Policies*",
                             "*\\MACHINE\\SOFTWARE\\WOW6432Node", "*\\MACHINE\\SOFTWARE\\WOW6432Node\\Microsoft*",
                             "*\\MACHINE\\SOFTWARE\\WOW6432Node\\Classes*",
                             "*\\USER\\*\\Software", "*\\USER\\*\\Software\\Microsoft",
                             "*\\USER\\*\\Software\\Microsoft\\Windows*", "*\\USER\\*\\Software\\Classes*",
                             "*\\USER\\*\\Software\\Policies*", "*\\USER\\*\\Environment*" })
        s.reg(Block, "整棵恢复系统配置 / 自启动所在的注册表子树(绕过逐值监控,T1112)")
            .target(key).regOp(RegistryOperation::RestoreKey).exemptOs().hard();
    s.reg(Ask, "整棵恢复 / 替换注册表键(绕过逐值监控,T1112)")
        .target("*").regOp(RegistryOperation::RestoreKey).exemptOs().disableSignedAutoAllow();
}

}

void addDefenseEvasionRules(QVector<DefenseRule>& out) {
    Segment s(out, "防御规避");
    defender(s);
    telemetryBlinding(s);
    systemDefenses(s);
    securityProducts(s);
    registryRestore(s);
}

}
