#include "RuleDsl.h"

namespace bulwark::engine::rules {

namespace {

QString any(const QString& fragment) { return u("*") + fragment + u("*"); }

// 签名健康的安装器写这些键是常态,不管;未签名写入者、或经 reg / 脚本宿主写入才值得问。
void guardKey(Segment& s, const char* what, const char* keyPattern, bool blockUnsigned,
              const QStringList& writers = scriptedWriters()) {
    const QString label = u(what);
    s.reg(blockUnsigned ? Block : Ask, label + u("(未签名写入者)"))
        .target(keyPattern).unsignedOnly().onlySetValue();
    for (const QString& w : writers)
        s.reg(Ask, label + u("(经 ") + imageNameOf(w) + u(")"))
            .actor(w).target(keyPattern).onlySetValue().disableSignedAutoAllow();
}

void registryAutostart(Segment& s) {
    struct Key { const char* what; const char* pattern; bool blockUnsigned; };
    const Key keys[] = {
        { "写入开机自启动项 Run(T1547.001)", "*\\CurrentVersion\\Run\\*", false },
        { "写入开机自启动项 RunOnce(T1547.001)", "*\\CurrentVersion\\RunOnce\\*", false },
        { "写入开机自启动项 RunOnceEx(T1547.001)", "*\\CurrentVersion\\RunOnceEx\\*", false },
        { "写入策略自启动项 Explorer\\Run(T1547.001)", "*\\Policies\\Explorer\\Run\\*", false },
        { "写入旧式服务自启动项 RunServices(T1547.001)", "*\\CurrentVersion\\RunServices*", false },
        { "改写 Winlogon Shell(T1547.004)", "*\\Winlogon\\Shell", true },
        { "改写 Winlogon Userinit(T1547.004)", "*\\Winlogon\\Userinit", true },
        { "注册 Winlogon Notify 组件(T1547.004)", "*\\Winlogon\\Notify\\*", true },
        { "改写 Winlogon TaskMan(T1547.004)", "*\\Winlogon\\TaskMan", true },
        // 清空 AppInit_DLLs 是加固工具的动作,同样是设值,只问不拦。
        { "写入 AppInit_DLLs(T1546.010)", "*\\Windows NT\\CurrentVersion\\Windows\\AppInit_DLLs", false },
        { "写入旧式 load / run 自启动值(T1547)", "*\\Windows NT\\CurrentVersion\\Windows\\Load", true },
        { "写入旧式 load / run 自启动值(T1547)", "*\\Windows NT\\CurrentVersion\\Windows\\Run", true },
        { "注册 AppCertDlls(T1546.009)", "*\\Session Manager\\AppCertDlls\\*", true },
        { "改写开机自检 BootExecute(T1547.012)", "*\\Session Manager\\BootExecute", false },
        { "设置 cmd 自动运行 AutoRun(T1546)", "*\\Command Processor\\AutoRun", false },
        { "设置登录脚本 UserInitMprLogonScript(T1037.001)", "*\\Environment\\UserInitMprLogonScript", false },
        { "更换屏保程序(T1546.002)", "*\\Control Panel\\Desktop\\SCRNSAVE.EXE", false },
        { "写入 Active Setup StubPath(T1547.014)", "*\\Active Setup\\Installed Components\\*\\StubPath", false },
        { "注册 LSA 安全包(T1547.005)", "*\\Control\\Lsa\\Security Packages", true },
        { "注册 LSA 认证包(T1547.002)", "*\\Control\\Lsa\\Authentication Packages", true },
        { "注册 LSA 密码筛选器(T1556.002)", "*\\Control\\Lsa\\Notification Packages", true },
        { "注册 LSA 安全包(T1547.005)", "*\\Lsa\\OSConfig\\Security Packages", true },
        { "注册打印监视器(T1547.010)", "*\\Control\\Print\\Monitors\\*", true },
        { "注册打印处理器(T1547.012)", "*\\Print Processors\\*", false },
        { "注册时间提供程序(T1547.003)", "*\\W32Time\\TimeProviders\\*", true },
        { "设置 DNS 服务插件 DLL(DnsAdmins 提权,T1574)", "*\\Services\\DNS\\Parameters\\ServerLevelPluginDll", true },
        { "改写通讯簿 DLL 路径(wab 加载劫持,T1574.001)", "*\\Microsoft\\WAB\\DLLPath*", true },
        { "注册 Netsh 辅助 DLL(T1546.007)", "*\\Microsoft\\NetSh\\*", true },
        { "改写网络提供程序顺序(NPPSpy 凭据截获,T1556.008)", "*\\NetworkProvider\\Order\\*", true },
        { "注册凭据提供程序(T1556)", "*\\Authentication\\Credential Providers\\*", false },
        { "强制安装 Chrome 扩展(T1176)", "*\\Policies\\Google\\Chrome\\ExtensionInstallForcelist\\*", false },
        { "强制安装 Edge 扩展(T1176)", "*\\Policies\\Microsoft\\Edge\\ExtensionInstallForcelist\\*", false },
        { "改写 Winsock 目录(LSP,T1547)", "*\\WinSock2\\Parameters\\*", false },
        { "重定向启动文件夹(T1547.001)", "*\\User Shell Folders\\Startup", false },
        { "重定向启动文件夹(T1547.001)", "*\\User Shell Folders\\Common Startup", false },
        { "重定向启动文件夹(T1547.001)", "*\\Shell Folders\\Startup", false },
        { "注册静默退出监视进程(T1546.012)", "*\\SilentProcessExit\\*\\MonitorProcess", false },
        { "设置映像劫持调试器(T1546.012)", "*\\Image File Execution Options\\*\\Debugger", false },
        { "设置映像劫持全局标志(T1546.012)", "*\\Image File Execution Options\\*\\GlobalFlag", false },
        { "改写服务映像路径(T1543.003)", "*\\Services\\*\\ImagePath", false },
        { "改写服务 DLL(T1543.003)", "*\\Services\\*\\Parameters\\ServiceDll", false },
        { "设置服务故障恢复命令(服务一崩溃就执行,T1543.003)", "*\\Services\\*\\FailureCommand", false },
        // 小厂商的 Office 插件、国产读屏软件不少没签名,这两类只问。
        { "写入 Office 弹性加载键 Resiliency(T1137)", "*\\Office\\*\\Resiliency\\*", false },
        { "改写启动项批准状态 StartupApproved(把自启动项藏起来,T1547.001)", "*\\Explorer\\StartupApproved\\*", false },
        { "注册辅助技术 Accessibility\\ATs(锁屏界面可拉起,T1546.008)", "*\\Accessibility\\ATs\\*", false },
        { "改写 KnownDLLs(全局 DLL 劫持,T1574.001)", "*\\Session Manager\\KnownDLLs\\*", true },
        { "写入组策略登录 / 开关机脚本(T1037)", "*\\Windows\\System\\Scripts\\*", false },
        { "在登录界面隐藏账户 SpecialAccounts\\UserList(T1564.002)", "*\\Winlogon\\SpecialAccounts\\UserList\\*", false },
        { "设置 .NET 性能探查器 COR_PROFILER(任意 .NET 程序启动即加载,T1574.012)", "*\\Environment\\COR_PROFILER*", true },
        { "设置 .NET 性能探查器 COR_ENABLE_PROFILING(T1574.012)", "*\\Environment\\COR_ENABLE_PROFILING", false },
        { "安装兼容性垫片数据库(T1546.011)", "*\\AppCompatFlags\\InstalledSDB\\*", true },
        { "安装兼容性垫片数据库(T1546.011)", "*\\AppCompatFlags\\Custom\\*", true },
        { "设置 Excel 启动即加载的 XLL(T1137.006)", "*\\Excel\\Options\\OPEN*", false },
        { "设置 Outlook 主页(打开文件夹即执行,T1137.004)", "*\\Outlook\\WebView\\*", true },
        { "设置 Outlook 今日页面(T1137.004)", "*\\Outlook\\Today\\UserDefinedUrl", true },
        { "向受信任根证书存储加证书(可中间人解密 HTTPS,T1553.004)", "*\\SystemCertificates\\Root\\Certificates\\*", false },
    };
    for (const Key& k : keys)
        guardKey(s, k.what, k.pattern, k.blockUnsigned);

    s.reg(Ask, "开启 AppInit_DLLs 加载(T1546.010)")
        .target("*\\Windows NT\\CurrentVersion\\Windows\\LoadAppInit_DLLs").regDword(1)
        .onlySetValue().exemptOs().disableSignedAutoAllow();

    // regsvr32 注册 COM 是安装器的常规动作,COM 键不把它算作脚本写入者;Shell 扩展、图标覆盖、
    // BHO、Office 加载项也都在 DllRegisterServer 里登记。
    // 当前用户类根键形如 \REGISTRY\USER\<SID>_Classes\CLSID\...,「Classes」前面不一定是反斜杠。
    const QStringList comWriters = exes({ "reg.exe", "regedit.exe", "powershell.exe", "pwsh.exe",
                                          "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe" });
    guardKey(s, "注册 / 劫持 COM 进程内服务器(T1546.015)", "*Classes\\CLSID\\*\\InprocServer32*", false, comWriters);
    guardKey(s, "注册 / 劫持 COM 本地服务器(T1546.015)", "*Classes\\CLSID\\*\\LocalServer32*", false, comWriters);
    guardKey(s, "重定向 COM 类 TreatAs(T1546.015)", "*Classes\\CLSID\\*\\TreatAs*", false, comWriters);
    guardKey(s, "注册浏览器辅助对象 BHO(T1176)", "*\\Explorer\\Browser Helper Objects\\*", false, comWriters);
    guardKey(s, "注册图标覆盖处理程序(T1546.015)", "*\\ShellIconOverlayIdentifiers\\*", false, comWriters);
    guardKey(s, "注册已批准的 Shell 扩展(资源管理器加载,T1546)", "*\\Shell Extensions\\Approved\\*", false, comWriters);
    guardKey(s, "注册 ShellServiceObjectDelayLoad(资源管理器启动即加载,T1547)", "*\\ShellServiceObjectDelayLoad\\*",
             true, comWriters);
    guardKey(s, "注册 Office 加载项(T1137.006)", "*\\Office\\*\\Addins\\*", false, comWriters);
    s.reg(Block, "注册远程脚本组件 ScriptletURL(T1546.015)")
        .target("*Classes\\CLSID\\*\\ScriptletURL*").onlySetValue().exemptOs().hard();

    // Tarrask:删掉或改写任务的安全描述符 / 索引,任务照常运行却从任务计划程序里消失。
    // 这些值只该由计划任务服务自己写。
    for (const char* key : { "*\\Schedule\\TaskCache\\Tree\\*\\SD", "*\\Schedule\\TaskCache\\Tree\\*\\Index" }) {
        s.reg(Block, "隐藏计划任务(删改 TaskCache 安全描述符,Tarrask,T1053.005/T1564)")
            .target(key).unsignedOnly().hard();
        for (const QString& w : scriptedWriters())
            s.reg(Block, u("经 ") + imageNameOf(w) + u(" 隐藏计划任务(删改 TaskCache 安全描述符,Tarrask,T1053.005/T1564)"))
                .actor(w).target(key).hard();
    }
    s.reg(Block, "写入 Office test 持久化键(T1137.002)").target("*\\Office test\\Special\\Perf*").exemptOs().hard();

    // RID 劫持:改 SAM 里账户的 F 值,让普通账户 / 来宾以 Administrator 的 RID 登录。只有 lsass 该写这里。
    s.reg(Block, "改写 SAM 账户数据(RID 劫持,T1098)")
        .target("*\\SAM\\SAM\\Domains\\Account\\Users\\*").onlySetValue().exemptOs().hard();
    // DSRM 管理员可以像域账户一样从网络登录:域控上的后门。
    s.reg(Block, "允许 DSRM 管理员网络登录(域控后门,未签名写入者,T1098)")
        .target("*\\Control\\Lsa\\DsrmAdminLogonBehavior").regDword(2).unsignedOnly().onlySetValue().exemptOs().hard();
    for (const QString& w : scriptedWriters())
        s.reg(Ask, u("经 ") + imageNameOf(w) + u(" 允许 DSRM 管理员网络登录(T1098)"))
            .actor(w).target("*\\Control\\Lsa\\DsrmAdminLogonBehavior").regDword(2).onlySetValue()
            .disableSignedAutoAllow();
}

void scheduledTasksAndServices(Segment& s) {
    // 按用户安装的应用(Electron、Chrome 用户版)经 API 建任务,不走命令行;命令行里指向 AppData 的少见。
    // -EncodedCommand 只认完整的缩写(-e / -ec / -en / -enc … -encoded*),-Encoding UTF8 不算。
    const char* suspiciousPayloads[] = {
        "*\\appdata\\local\\temp\\*", "*\\appdata\\roaming\\*", "*\\users\\public\\*", "*\\$recycle.bin\\*",
        "*\\perflogs\\*", "*\\windows\\temp\\*", "*mshta*", "*wscript*", "*cscript*", "*regsvr32*", "*rundll32*",
        "*certutil*", "*bitsadmin*", "*-e *", "*-ec *", "*-en *", "*-enc *", "*-enco *", "*-encod *", "*-encode *",
        "*-encoded*", "*frombase64string*", "*downloadstring*", "*http:*", "*https:*",
    };
    for (const char* p : suspiciousPayloads) {
        s.proc(Ask, "计划任务指向临时目录 / 脚本宿主 / 编码命令(T1053.005)")
            .actor("*\\schtasks.exe").cmd(u("*/create*") + u(p)).disableSignedAutoAllow();
        s.proc(Ask, "创建服务指向临时目录 / 脚本宿主 / 编码命令(T1543.003)")
            .actor("*\\sc.exe").cmd(u("*create*binpath*") + u(p)).disableSignedAutoAllow();
        s.proc(Ask, "改写服务映像指向临时目录 / 脚本宿主(T1543.003)")
            .actor("*\\sc.exe").cmd(u("*config*binpath*") + u(p)).disableSignedAutoAllow();
    }
    for (const QString& host : exes({ "powershell.exe", "pwsh.exe" })) {
        for (const char* p : { "*register-scheduledtask*\\appdata\\local\\temp\\*",
                               "*register-scheduledtask*\\users\\public\\*",
                               "*new-service*\\appdata\\local\\temp\\*",
                               "*new-service*\\users\\public\\*" })
            s.proc(Ask, "PowerShell 注册指向临时目录的任务 / 服务(T1053.005/T1543.003)")
                .actor(host).cmd(p).disableSignedAutoAllow();
    }

    // 计划任务里内联编码 PowerShell:正常部署把脚本落盘再指过去,不需要藏。
    for (const char* p : { "*schtasks*/create*-encodedcommand*", "*schtasks*/create*-enc *", "*schtasks*/create*-ec *",
                           "*scheduledtaskaction*-encodedcommand*", "*scheduledtaskaction*-enc *",
                           "*register-scheduledtask*-encodedcommand*" })
        s.proc(Block, "计划任务内联编码 PowerShell(T1053.005/T1027)").cmd(p).hard();
    // 银狐把任务名伪装成 Edge 更新并缀上 SYSTEM 的 SID;真 Edge 任务叫 MicrosoftEdgeUpdateTaskMachine*。
    // 只认建 / 改任务;schtasks /query 和取证工具读到这个名字不算。
    for (const char* verb : { "/create", "-create", "/change", "-change", "register-scheduledtask", "set-scheduledtask" })
        for (const QString& p : { u("*") + u(verb) + u("*task-s-1-5-18*"), u("*task-s-1-5-18*") + u(verb) + u("*") })
            s.proc(Block, "创建伪装 Edge 更新的计划任务(任务名含 Task-S-1-5-18,T1053.005/T1036.004)")
                .cmd(p).hard();
    // 只认与正规任务名「完全相同」的仿冒;Adobe Acrobat Update Task 这类真名不在此列。
    const char* fakeNames[] = {
        "windows update", "windowsupdate", "microsoft update", "adobe updater", "adobe update", "google update",
        "chrome update", "security update", "system update", "windows defender", "windows security",
        "microsoft defender", "svchost", "explorer",
    };
    for (const char* n : fakeNames) {
        const QString name = u(n);
        // 只认创建:schtasks /query /tn "Windows Update" 这类查询不算。
        for (const QString& form : { u("*/create*/tn \"") + name + u("\"*"), u("*/create*/tn '") + name + u("'*"),
                                     u("*/create*/tn ") + name + u(" *"),
                                     u("*register-scheduledtask*-taskname \"") + name + u("\"*"),
                                     u("*register-scheduledtask*-taskname '") + name + u("'*") })
            s.proc(Ask, u("创建仿冒正规更新 / 安全组件名称的计划任务「") + name + u("」(T1053.005/T1036.004)"))
                .cmd(form).disableSignedAutoAllow();
    }

    // 监控代理走 WMI API 建订阅,命令行里出现消费者类型基本就是持久化后门。
    for (const char* p : { "*commandlineeventconsumer*", "*activescripteventconsumer*" })
        s.proc(Block, "创建 WMI 事件消费者(T1546.003)").cmd(p).hard();
    s.proc(Ask, "创建 WMI 事件过滤器绑定(T1546.003)").cmd("*__filtertoconsumerbinding*").disableSignedAutoAllow();
    for (const QString& d : rareExecutionDirs())
        s.proc(Block, "编译罕见目录中的 MOF(T1546.003)").actor("*\\mofcomp.exe").cmd(any(d)).hard();

    s.proc(Block, "BITS 任务完成后执行命令(T1197)").cmd("*bitsadmin*setnotifycmdline*").hard();

    // at 早已废弃,正常软件不再用它建任务。
    s.proc(Block, "用已废弃的 at 命令创建计划任务(T1053.002)").actor("*\\at.exe").cmd("*:*").hard();
    s.proc(Ask, "设置服务故障恢复命令(服务一崩溃就执行,T1543.003)").cmd("*sc*failure*command=*").disableSignedAutoAllow();
    for (const char* p : { "*appdomainmanager*", "*appdomain_manager_*", "*setx*cor_profiler*", "*setx*cor_enable_profiling*" })
        s.proc(Ask, ".NET 启动劫持(AppDomainManager / COR_PROFILER,T1574.012/T1574.014)").cmd(p).disableSignedAutoAllow();
    s.proc(Ask, "命令行在登录界面隐藏账户(SpecialAccounts\\UserList,T1564.002)")
        .cmd("*specialaccounts\\userlist*").disableSignedAutoAllow();

    // 兼容性垫片能在目标程序启动时注入 DLL、改写它的行为,而且不改动程序本身。
    s.proc(Ask, "安装兼容性垫片(T1546.011)").actor("*\\sdbinst.exe").disableSignedAutoAllow();
    for (const char* d : { "\\appdata\\", "\\temp\\", "\\users\\public\\", "\\programdata\\", "\\downloads\\" })
        s.proc(Block, "安装投递目录中的兼容性垫片(T1546.011)")
            .actor("*\\sdbinst.exe").cmd(u("*") + u(d) + u("*.sdb*")).hard();
}

void browserExtensions(Segment& s) {
    // 命令行加载未打包的扩展(ChromeLoader 一类):扩展放在用户可写目录,随计划任务或快捷方式每次带上。
    for (const QString& b : browsers())
        for (const char* d : { "\\appdata\\", "\\users\\public\\", "\\programdata\\", "\\temp\\" })
            s.proc(Ask, u("浏览器 ") + imageNameOf(b) + u(" 以命令行加载用户目录中的未打包扩展(T1176)"))
                .actor(b).cmd(u("*--load-extension=*") + u(d) + u("*")).disableSignedAutoAllow();
}

void accountsAndEnvironment(Segment& s) {
    // 建号与提权进管理员组是正常运维,但都是值得当场确认的动作;以 $ 结尾的隐身账户另由分析器给硬指标。
    for (const char* p : { "*net user * /add*", "*net1 user * /add*", "*net.exe user * /add*",
                           "*net.exe\" user * /add*", "*new-localuser *" })
        s.proc(Ask, "创建本地账户(T1136.001)").cmd(p).disableSignedAutoAllow();
    for (const char* p : { "*net localgroup administrators * /add*", "*net1 localgroup administrators * /add*",
                           "*net.exe localgroup administrators * /add*",
                           "*add-localgroupmember*-group*administrators*" })
        s.proc(Ask, "把账户加入管理员组(T1098)").cmd(p).disableSignedAutoAllow();

    // 公共目录对所有用户可写,放进 PATH 等于让任何人替换后续按名字启动的程序。
    s.proc(Block, "把公共用户目录加入 PATH(搜索路径劫持,T1574.007)").cmd("*setx*path*\\users\\public\\*").hard();
    for (const char* p : { "*regedit*/s*\\users\\public\\*", "*reg import *\\users\\public\\*",
                           "*reg.exe import *\\users\\public\\*", "*reg.exe\" import *\\users\\public\\*" })
        s.proc(Block, "静默导入公共用户目录里的注册表文件(T1112)").cmd(p).hard();
}

void startupFiles(Segment& s) {
    const char* exts[] = { ".exe", ".scr", ".com", ".pif", ".bat", ".cmd", ".vbs", ".vbe", ".js",
                           ".jse", ".wsf", ".hta", ".ps1", ".lnk", ".url", ".dll" };
    for (const char* ext : exts) {
        const QString target = u("*\\Start Menu\\Programs\\Startup\\*") + u(ext);
        s.file(Ask, "向启动文件夹写入可执行项(未签名写入者,T1547.001)").target(target).unsignedOnly();
        for (const QString& w : exes({ "wscript.exe", "cscript.exe", "mshta.exe" }))
            s.file(Block, u("Windows 脚本宿主 ") + imageNameOf(w) + u(" 向启动文件夹写入可执行项(T1547.001)"))
                .actor(w).target(target).hard();
        for (const QString& w : exes({ "powershell.exe", "pwsh.exe", "cmd.exe", "rundll32.exe", "regsvr32.exe" }))
            s.file(Ask, u("经 ") + imageNameOf(w) + u(" 向启动文件夹写入可执行项(T1547.001)"))
                .actor(w).target(target).disableSignedAutoAllow();
    }

    const char* profiles[] = {
        "*\\Documents\\WindowsPowerShell\\*profile.ps1", "*\\Documents\\PowerShell\\*profile.ps1",
        "*\\System32\\WindowsPowerShell\\v1.0\\*profile.ps1",
    };
    for (const char* p : profiles) {
        s.file(Ask, "改写 PowerShell 配置文件(未签名写入者,T1546.013)").target(p).unsignedOnly();
        for (const QString& w : exes({ "wscript.exe", "cscript.exe", "mshta.exe", "cmd.exe" }))
            s.file(Ask, u("经 ") + imageNameOf(w) + u(" 改写 PowerShell 配置文件(T1546.013)"))
                .actor(w).target(p).disableSignedAutoAllow();
    }

    const char* officeStartup[] = {
        "*\\Microsoft\\Word\\STARTUP\\*", "*\\Microsoft\\Excel\\XLSTART\\*",
        "*\\Microsoft\\Templates\\Normal.dotm", "*\\Microsoft\\AddIns\\*",
    };
    for (const char* p : officeStartup) {
        s.file(Ask, "向 Office 启动目录 / 模板写入内容(未签名写入者,T1137)").target(p).unsignedOnly();
        for (const QString& w : scriptHosts())
            s.file(Ask, u("经 ") + imageNameOf(w) + u(" 向 Office 启动目录 / 模板写入内容(T1137)"))
                .actor(w).target(p).disableSignedAutoAllow();
    }

    s.file(Ask, "直接写入计划任务定义文件(未签名写入者,T1053.005)")
        .target("*\\Windows\\System32\\Tasks\\*").unsignedOnly();
    for (const char* p : { "*\\GroupPolicy\\Machine\\Scripts\\*", "*\\GroupPolicy\\User\\Scripts\\*" }) {
        s.file(Ask, "写入组策略登录 / 启动脚本(未签名写入者,T1037)").target(p).unsignedOnly();
        for (const QString& w : scriptHosts())
            s.file(Ask, u("经 ") + imageNameOf(w) + u(" 写入组策略登录 / 启动脚本(T1037)"))
                .actor(w).target(p).disableSignedAutoAllow();
    }
}

}

void addPersistenceRules(QVector<DefenseRule>& out) {
    Segment s(out, "持久化");
    registryAutostart(s);
    scheduledTasksAndServices(s);
    accountsAndEnvironment(s);
    startupFiles(s);
    browserExtensions(s);
}

}
