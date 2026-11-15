#include "RuleDsl.h"

namespace bulwark::engine::rules {

namespace {

QString any(const QString& fragment) { return u("*") + fragment + u("*"); }
QString any(const char* fragment) { return any(u(fragment)); }

void documentChildren(Segment& s) {
    // 文档程序几乎不会正常拉起这些宿主;宏、OLE 与公式编辑器漏洞的落地形态都是这一跳。
    const QStringList scripting = exes({
        "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe",
        "regsvr32.exe", "certutil.exe", "bitsadmin.exe", "msbuild.exe", "installutil.exe",
        "regasm.exe", "regsvcs.exe", "cmstp.exe", "msxsl.exe", "wmic.exe", "schtasks.exe",
        "wsl.exe", "bash.exe",
    });
    // cmd / rundll32 偶有正常用途(VBA Shell、url.dll 打开链接),只询问。
    const QStringList dualUse = exes({ "cmd.exe", "rundll32.exe" });

    QStringList parents = officeApps();
    parents += documentReaders();
    for (const QString& parent : parents) {
        const QString who = imageNameOf(parent);
        for (const QString& child : scripting)
            s.proc(Block, u("文档程序 ") + who + u(" 派生 ") + imageNameOf(child)
                              + u("(宏 / 漏洞利用投递,T1204.002)"))
                .actor(child).parent(parent).hard();
        for (const QString& child : dualUse)
            s.proc(Ask, u("文档程序 ") + who + u(" 派生 ") + imageNameOf(child) + u("(T1204.002)"))
                .actor(child).parent(parent).disableSignedAutoAllow();
    }
    s.proc(Block, "公式编辑器 eqnedt32 派生进程(CVE-2017-11882 利用形态,T1203)")
        .actor("*").parent("*\\eqnedt32.exe").hard();

    // 浏览器正常只经 cmd 启动原生消息宿主(另由分析器豁免);直接拉起脚本宿主多是下载即执行。
    for (const QString& b : browsers())
        for (const QString& child : exes({ "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe",
                                           "mshta.exe", "regsvr32.exe", "msbuild.exe", "installutil.exe",
                                           "regasm.exe", "regsvcs.exe" }))
            s.proc(Ask, u("浏览器 ") + imageNameOf(b) + u(" 直接派生 ") + imageNameOf(child)
                            + u("(下载即执行,T1189)"))
                .actor(child).parent(b).disableSignedAutoAllow();

    // 压缩包里双击脚本、WinRAR 漏洞(CVE-2023-38831)、聊天软件里点开收到的文件,都是这一跳。
    const QStringList archivers = exes({ "winrar.exe", "7zfm.exe", "7zg.exe", "bandizip.exe", "360zip.exe",
                                         "haozip.exe", "peazip.exe", "winzip32.exe", "winzip64.exe" });
    const QStringList messengers = exes({ "wechat.exe", "weixin.exe", "qq.exe", "tim.exe", "wxwork.exe",
                                          "dingtalk.exe", "feishu.exe", "lark.exe", "telegram.exe",
                                          "whatsapp.exe", "foxmail.exe", "thunderbird.exe", "mailmaster.exe" });
    const auto spawn = [&s](const QString& parent, const QString& child) {
        return s.proc(Ask, u("压缩 / 邮件 / 聊天软件 ") + imageNameOf(parent) + u(" 直接派生 ") + imageNameOf(child)
                               + u("(打开投递文件,T1204.002)"))
            .actor(child).parent(parent);
    };
    for (const QString& parent : archivers + messengers)
        for (const QString& child : exes({ "wscript.exe", "cscript.exe", "mshta.exe", "regsvr32.exe" }))
            spawn(parent, child).disableSignedAutoAllow();
    for (const QString& parent : archivers)
        for (const QString& child : exes({ "powershell.exe", "pwsh.exe", "cmd.exe" }))
            spawn(parent, child).disableSignedAutoAllow();
    // 经典照片查看器(rundll32 PhotoViewer.dll)、「打开方式」对话框都走 rundll32;Electron 聊天客户端
    // 会自己调 PowerShell / cmd 查系统信息。这些只在带硬指标时才问。
    const QString rundll32 = exe("rundll32.exe");
    for (const QString& parent : archivers + messengers)
        spawn(parent, rundll32);
    for (const QString& parent : messengers)
        for (const QString& child : exes({ "powershell.exe", "pwsh.exe", "cmd.exe" }))
            spawn(parent, child);
    // 银狐主要经聊天软件发送伪装成文档的程序;同事互发小工具也常见,只问。
    for (const QString& parent : messengers)
        s.proc(Ask, u("聊天 / 邮件软件 ") + imageNameOf(parent) + u(" 直接打开未签名程序(T1204.002)"))
            .actor("*").parent(parent).unsignedOnly();
}

void proxyExecution(Segment& s) {
    const QStringList tempDirs = {
        u("\\appdata\\local\\temp\\"), u("\\windows\\temp\\"), u("\\downloads\\"),
    };

    for (const char* p : { "*http:*", "*https:*", "*javascript:*", "*vbscript:*", "*about:*" })
        s.proc(Block, "mshta 执行远程或内联脚本(T1218.005)").actor("*\\mshta.exe").cmd(p).hard();
    // MDT、少数企业工具仍用 HTA;其余场景几乎只剩投递。
    s.proc(Ask, "mshta 运行 HTA 应用(T1218.005)").actor("*\\mshta.exe").disableSignedAutoAllow();

    for (const char* p : { "*scrobj*", "*/i:http*", "*-i:http*" })
        s.proc(Block, "regsvr32 加载远程 / 脚本组件(Squiblydoo,T1218.010)")
            .actor("*\\regsvr32.exe").cmd(p).hard();
    for (const QString& d : rareExecutionDirs())
        s.proc(Block, "regsvr32 注册罕见目录中的组件(T1218.010)").actor("*\\regsvr32.exe").cmd(any(d)).hard();
    for (const QString& d : tempDirs)
        s.proc(Ask, "regsvr32 注册临时 / 下载目录中的组件(T1218.010)")
            .actor("*\\regsvr32.exe").cmd(any(d)).disableSignedAutoAllow();

    for (const char* p : { "*javascript:*", "*vbscript:*", "*mshtml*runhtmlapplication*" })
        s.proc(Block, "rundll32 执行脚本协议(T1218.011)").actor("*\\rundll32.exe").cmd(p).hard();
    for (const QString& d : rareExecutionDirs())
        s.proc(Block, "rundll32 加载罕见目录中的 DLL(T1218.011)").cmd(u("*rundll32*") + d + u("*")).hard();
    // IExpress / 驱动包用 advpack.dll 安装 %TEMP% 里的 INF,被加载的 DLL 本身在 System32:
    // 要求 DLL / CPL 落在临时目录之后才算。按命令行匹配,cmd /c 套一层也命中。
    for (const QString& d : tempDirs)
        for (const char* x : { ".dll", ".cpl", ".ocx" })
            s.proc(Block, "rundll32 加载临时 / 下载目录中的 DLL 或控制面板项(T1218.011/T1218.002)")
                .cmd(u("*rundll32*") + d + u("*") + u(x) + u("*")).hard();
    for (const char* p : { "*zipfldr*routethecall*", "*pcwutl*launchapplication*",
                           "*desk.cpl*installscreensaver*" })
        s.proc(Ask, "rundll32 经系统组件代理启动程序(T1218.011)")
            .actor("*\\rundll32.exe").cmd(p).disableSignedAutoAllow();

    // 证书运维几乎不用 -urlcache 拉文件;落地为可执行内容基本只剩投递。
    // 按命令行匹配:cmd /c certutil ... 在外壳这一层就拦下。
    for (const char* x : { ".exe", ".dll", ".ps1", ".bat", ".cmd", ".vbs", ".js", ".hta", ".scr" }) {
        for (const char* verb : { "urlcache", "verifyctl" })
            s.proc(Block, "certutil 远程下载可执行内容(T1105)")
                .cmd(u("*certutil*") + u(verb) + u("*http*") + u(x) + u("*")).hard();
    }
    for (const char* verb : { "urlcache", "verifyctl" })
        s.proc(Ask, "certutil 远程下载(T1105)")
            .cmd(u("*certutil*") + u(verb) + u("*http*")).disableSignedAutoAllow();
    // 证书运维也会 -decode(还原 .pem / .cer),只有解出可执行体才是投递链的一步。
    for (const char* x : { ".exe", ".dll", ".scr" })
        s.proc(Block, "certutil 解码落地可执行体(T1140/T1105)")
            .cmd(u("*certutil*decode*") + u(x) + u("*")).hard();
    for (const char* x : { ".ps1", ".vbs", ".js", ".hta", ".bat", ".cmd" })
        s.proc(Ask, "certutil 解码出脚本(T1140)").cmd(u("*certutil*decode*") + u(x) + u("*")).disableSignedAutoAllow();
    s.proc(Ask, "certutil 解码文件(证书运维也用,T1140)").cmd("*certutil*decode*").disableSignedAutoAllow();
    for (const char* p : { "*certutil*addstore*root*", "*import-certificate*cert:\\localmachine\\root*",
                           "*import-certificate*cert:\\currentuser\\root*" })
        s.proc(Ask, "安装受信任根证书(企业 PKI 也用,可用于中间人劫持,T1553.004)").cmd(p).disableSignedAutoAllow();

    // 往临时目录解包可执行体;msu / cab 解到目录(不点名 .exe)是正常运维。
    for (const char* d : { "\\appdata\\local\\temp\\", "\\windows\\temp\\", "\\users\\public\\" }) {
        s.proc(Block, "expand 把 cab 解包成临时目录里的可执行体(T1140/T1105)")
            .actor("*\\expand.exe").cmd(any(d) + u(".exe*")).hard();
        s.proc(Block, "extrac32 把 cab 解包成临时目录里的可执行体(T1140/T1105)")
            .cmd(u("*extrac32*") + d + u("*.exe*")).hard();
        // regini 导入注册表脚本、jsc 编译 JScript:正常用法不会指向临时 / 公共目录。
        s.proc(Block, "regini 导入临时 / 公共目录里的注册表脚本(T1112)").actor("*\\regini.exe").cmd(any(d)).hard();
        s.proc(Block, "jsc 编译临时 / 公共目录里的 JScript(T1127/T1059.007)").actor("*\\jsc.exe").cmd(any(d)).hard();
    }
    s.proc(Ask, "regini 导入注册表脚本(T1112)").actor("*\\regini.exe").disableSignedAutoAllow();
    s.proc(Ask, "jsc 编译 JScript.NET(T1127)").actor("*\\jsc.exe").disableSignedAutoAllow();
    for (const char* p : { "*wecutil* cs *", "*wecutil*create-subscription*" })
        s.proc(Ask, "wecutil 创建事件订阅(可作持久化 / 收集,T1053)").cmd(p).disableSignedAutoAllow();
    for (const char* x : { ".exe", ".dll", ".scr", ".ps1", ".vbs", ".hta", ".bat" })
        s.proc(Block, "desktopimgdownldr 下载可执行内容(T1105)")
            .actor("*\\desktopimgdownldr.exe").cmd(u("*http*") + u(x) + u("*")).hard();

    for (const char* p : { "*/transfer*http*", "*/addfile*http*" })
        s.proc(Ask, "bitsadmin 后台下载(T1197)").actor("*\\bitsadmin.exe").cmd(p).disableSignedAutoAllow();

    // 开发者会在 Temp 里构建,只认罕见目录。
    for (const QString& tool : exes({ "msbuild.exe", "installutil.exe", "regasm.exe", "regsvcs.exe" }))
        for (const QString& d : rareExecutionDirs())
            s.proc(Block, imageNameOf(tool) + u(" 构建 / 加载罕见目录中的项目或程序集(T1127/T1218)"))
                .actor(tool).cmd(any(d)).hard();
    for (const QString& tool : exes({ "installutil.exe", "regasm.exe", "regsvcs.exe" }))
        for (const QString& d : tempDirs)
            s.proc(Ask, imageNameOf(tool) + u(" 加载临时 / 下载目录中的程序集(T1218.004)"))
                .actor(tool).cmd(any(d)).disableSignedAutoAllow();
    s.proc(Block, "installutil 卸载模式静默加载程序集(白名单绕过,T1218.004)")
        .actor("*\\installutil.exe").cmd("*/logtoconsole=false*/u*").hard();
    // 系统自带的 .NET Framework MSBuild 不算开发工具(VS 的 MSBuild 在 Visual Studio 目录下):
    // 用它编译下载、AppData、公共目录里的项目是内联任务白利用,只问。
    for (const char* d : { "\\appdata\\", "\\downloads\\", "\\programdata\\", "\\users\\public\\", "\\windows\\temp\\" })
        s.proc(Ask, "系统 MSBuild 构建投递目录中的项目(白利用编译执行,T1127.001)")
            .actor("*\\microsoft.net\\framework*\\msbuild.exe").cmd(any(d)).disableSignedAutoAllow();
    // VBS / JS / HTA 脚本直接拉起这几个 .NET 工具,是「脚本投递 → 白利用编译 / 加载」的典型链。
    for (const QString& host : exes({ "wscript.exe", "cscript.exe", "mshta.exe" }))
        for (const QString& tool : exes({ "msbuild.exe", "installutil.exe", "regasm.exe", "regsvcs.exe" }))
            s.proc(Ask, imageNameOf(host) + u(" 拉起 ") + imageNameOf(tool) + u("(脚本投递后白利用,T1127/T1218)"))
                .actor(tool).parent(host).disableSignedAutoAllow();

    // 企业 VPN 配置会从 Temp 静默装 INF,临时目录只询问。
    s.proc(Ask, "cmstp 安装连接配置(T1218.003)").actor("*\\cmstp.exe").cmd("*.inf*").disableSignedAutoAllow();
    for (const QString& d : rareExecutionDirs())
        s.proc(Block, "cmstp 安装罕见目录中的 INF(UAC 绕过,T1218.003)").actor("*\\cmstp.exe").cmd(any(d)).hard();

    for (const char* p : { "*/format:*http*", "*-format:*http*" })
        s.proc(Block, "wmic 加载远程 XSL 样式表(T1220)").actor("*\\wmic.exe").cmd(p).hard();

    for (const char* p : { "*it_browseforfile*", "*it_rebrowseforfile*", "*pcwdiagnostic*/skip*" })
        s.proc(Block, "msdt 诊断协议注入(Follina,CVE-2022-30190)").actor("*\\msdt.exe").cmd(p).hard();
    s.proc(Block, "hh 打开远程帮助文件(T1218.001)").actor("*\\hh.exe").cmd("*http*").hard();
    s.proc(Block, "hh 执行内联脚本(T1218.001)").actor("*\\hh.exe").cmd("*javascript:*").hard();
    s.proc(Block, "cmstp 加载远程 INF(T1218.003)").actor("*\\cmstp.exe").cmd("*http*").hard();
    // forfiles /c "cmd /c del @path" 是日志清理的常见写法;拉起脚本 / 代理宿主才问。
    for (const char* host : { "powershell", "pwsh", "mshta", "wscript", "cscript", "rundll32", "regsvr32" })
        s.proc(Ask, u("forfiles 代理执行 ") + u(host) + u("(T1202)"))
            .actor("*\\forfiles.exe").cmd(u("*/c*") + u(host) + u("*")).disableSignedAutoAllow();

    // ClickFix / 假验证码:诱导用户把「下载后直接交给解释器」的命令粘贴进运行框。
    // 解释器必须紧跟在管道后面:curl ... | jq .cmd 之类的开发用法不算。
    for (const char* interp : { "cmd", "powershell", "pwsh" })
        for (const char* pipe : { "|", "| " })
            s.proc(Block, "把远端内容直接交给命令解释器执行(ClickFix,T1204.004/T1105)")
                .cmd(u("*curl*http*") + u(pipe) + u(interp) + u("*")).hard();
    for (const char* p : { "*finger *@*|*", "*finger.exe*@*|*" })
        s.proc(Block, "经 finger 取回命令交给解释器执行(ClickFix,T1204.004/T1105)").cmd(p).hard();
    for (const char* host : { "powershell", "pwsh", "cmd", "mshta", "wscript", "cscript", "rundll32" })
        s.proc(Ask, u("经 conhost --headless 隐藏窗口运行 ") + u(host) + u("(T1564.003)"))
            .cmd(u("*conhost*--headless*") + u(host) + u("*")).disableSignedAutoAllow();
    for (const QString& d : tempDirs)
        s.proc(Ask, "hh 打开临时 / 下载目录中的 CHM(T1218.001)").actor("*\\hh.exe").cmd(any(d)).disableSignedAutoAllow();
    s.proc(Block, "ieexec 运行远程程序(T1218)").actor("*\\ieexec.exe").cmd("*http*").hard();
    // msxsl 不随系统分发,现今几乎只出现在攻击工具包里。
    s.proc(Block, "msxsl 执行 XSL 脚本(T1220)").actor("*\\msxsl.exe").hard();
    for (const char* p : { "*/i*http*", "*-i*http*", "*/package*http*" })
        s.proc(Ask, "msiexec 安装远程安装包(T1218.007)").actor("*\\msiexec.exe").cmd(p).disableSignedAutoAllow();
    for (const char* p : { "*/y*.dll*", "*/z*.dll*" })
        s.proc(Ask, "msiexec 自注册 DLL(T1218.007)").actor("*\\msiexec.exe").cmd(p).disableSignedAutoAllow();
    s.proc(Ask, "odbcconf 注册 DLL(T1218.008)").actor("*\\odbcconf.exe").cmd("*regsvr*").disableSignedAutoAllow();
    for (const QString& d : tempDirs)
        s.proc(Block, "odbcconf 注册临时 / 下载目录中的 DLL(T1218.008)")
            .actor("*\\odbcconf.exe").cmd(u("*regsvr*") + d + u("*")).hard();
    s.proc(Ask, "pcalua 代理启动程序(T1202)").actor("*\\pcalua.exe").cmd("*-a*").disableSignedAutoAllow();
    s.proc(Block, "mavinject 向运行中进程注入 DLL(T1218.013)")
        .actor("*\\mavinject*.exe").cmd("*/injectrunning*").hard();
    s.proc(Ask, "presentationhost 运行远程 XBAP(T1218)")
        .actor("*\\presentationhost.exe").cmd("*http*").disableSignedAutoAllow();
    s.proc(Ask, "infdefaultinstall 安装 INF(T1218)").actor("*\\infdefaultinstall.exe").disableSignedAutoAllow();
    // 用户在资源管理器里对压缩包内的 .inf 点「安装」同样落在 %TEMP%,区别只在父进程。
    for (const QString& host : scriptHosts())
        for (const QString& d : tempDirs)
            s.proc(Block, u("脚本宿主 ") + imageNameOf(host) + u(" 拉起 infdefaultinstall 安装临时目录中的 INF(T1218)"))
                .actor("*\\infdefaultinstall.exe").parent(host).cmd(any(d)).hard();
    for (const QString& d : rareExecutionDirs())
        s.proc(Block, "control 加载罕见目录中的控制面板项(T1218.002)").actor("*\\control.exe").cmd(any(d)).hard();
    for (const QString& d : tempDirs)
        s.proc(Block, "control 加载临时 / 下载目录中的控制面板项(T1218.002)")
            .actor("*\\control.exe").cmd(any(d) + u(".cpl*")).hard();

    // 这些签名程序都能把命令行里的文件当代码跑;正常用法从不指向临时 / 公共目录。
    // 命令行开头是程序自身的路径(从压缩包里直接运行时就在 %TEMP% 下),目录必须出现在参数里;
    // bginfo / rcsi 常被直接放在「下载」里运行,对它们不认下载目录。
    const QStringList stagingDirs = { u("\\appdata\\local\\temp\\"), u("\\windows\\temp\\"),
                                      u("\\users\\public\\") };
    const auto inArgs = [](const QString& d) { return u("*.exe*") + d + u("*"); };
    for (const QString& d : stagingDirs + QStringList{ u("\\downloads\\") }) {
        s.proc(Block, "mmc 打开投递目录中的 .msc(GrimResource,T1218.014)")
            .actor("*\\mmc.exe").cmd(any(d) + u(".msc*")).hard();
        s.proc(Block, "appvlp 代理执行投递目录中的程序(T1218)").actor("*\\appvlp.exe").cmd(inArgs(d)).hard();
    }
    for (const QString& d : stagingDirs) {
        s.proc(Block, "bginfo 加载投递目录中的配置 / 脚本(T1218)").actor("*\\bginfo*.exe").cmd(inArgs(d)).hard();
        s.proc(Block, "Workflow.Compiler 编译执行投递目录中的代码(T1127)")
            .actor("*\\workflow.compiler.exe").cmd(inArgs(d)).hard();
        s.proc(Block, "rcsi 执行投递目录中的 C# 脚本(T1127)").actor("*\\rcsi.exe").cmd(inArgs(d)).hard();
    }
    s.proc(Block, "bginfo 执行 VBScript(T1218/T1059.005)").actor("*\\bginfo*.exe").cmd("*.vbs*").hard();
    s.proc(Ask, "Workflow.Compiler 编译执行代码(T1127)").actor("*\\workflow.compiler.exe").disableSignedAutoAllow();
    // 两者正常都不带 DLL 路径参数(xwizard 走注册表里的向导,wab 打开联系人)。
    s.proc(Block, "xwizard 加载命令行指定的 DLL(T1218)").actor("*\\xwizard.exe").cmd("*.dll*").hard();
    s.proc(Block, "wab 加载命令行指定的 DLL(T1574.001)").actor("*\\wab.exe").cmd("*.dll*").hard();
    s.proc(Ask, "SyncAppvPublishingServer 夹带 PowerShell 语句(T1216)")
        .actor("*\\syncappvpublishingserver.exe").cmd("*;*").disableSignedAutoAllow();
    s.proc(Ask, "scriptrunner 运行 App-V 脚本(T1216)")
        .actor("*\\scriptrunner.exe").cmd("*-appvscript*").disableSignedAutoAllow();

    // 经 WMI 创建进程:新进程挂在 WmiPrvSE 名下,与真正的发起者断开父子关系。
    s.proc(Ask, "经 WMI 创建进程(断开父子链,T1047)").actor("*\\wmic.exe").cmd("*process*call*create*")
        .disableSignedAutoAllow();
    for (const QString& host : exes({ "powershell.exe", "pwsh.exe", "powershell_ise.exe" }))
        for (const char* p : { "*invoke-wmimethod*win32_process*create*", "*invoke-cimmethod*win32_process*create*",
                               "*[wmiclass]*win32_process*" })
            s.proc(Ask, "PowerShell 经 WMI 创建进程(断开父子链,T1047)").actor(host).cmd(p).disableSignedAutoAllow();

    // rundll32 的几个「打开文件」入口会替调用者启动程序;正常用来打开网址与文档,不指向投递目录里的程序。
    for (const char* entry : { "shellexec_rundll", "fileprotocolhandler", "openurl", "routethecall" })
        for (const QString& d : stagingDirs + QStringList{ u("\\programdata\\") })
            for (const char* x : { ".exe", ".hta", ".bat", ".cmd", ".vbs", ".js", ".scr", ".lnk" })
                s.proc(Ask, u("rundll32 经 ") + u(entry) + u(" 启动投递目录中的程序(断开父子链,T1218.011)"))
                    .actor("*\\rundll32.exe").cmd(u("*") + u(entry) + u("*") + d + u("*") + u(x) + u("*"))
                    .disableSignedAutoAllow();

    s.proc(Block, "rasautou 加载命令行指定的 DLL(T1218)").actor("*\\rasautou.exe").cmd("*-d*.dll*").hard();
    s.proc(Block, "pubprn.vbs 执行远程脚本组件(T1216.001)").cmd("*pubprn*script:*").hard();
    // ie4uinit 会读取同目录下的 ie4uinit.inf:被拷出系统目录运行就是借它执行 INF 里的命令。
    for (const QString& d : stagingDirs + QStringList{ u("\\programdata\\"), u("\\downloads\\"), u("\\appdata\\") })
        s.proc(Block, "运行拷出系统目录的 ie4uinit(借同目录 INF 执行命令,T1218)")
            .actor(u("*") + d + u("*\\ie4uinit.exe")).hard();
    s.proc(Ask, "cmdl32 下载文件(T1105)").actor("*\\cmdl32.exe").cmd("*/vpn*/lan*").disableSignedAutoAllow();
    s.proc(Ask, "certreq 向远端 POST 数据或下载文件(T1105/T1048)")
        .actor("*\\certreq.exe").cmd("*-post*-config*http*").disableSignedAutoAllow();
    for (const QString& host : exes({ "powershell.exe", "pwsh.exe" }))
        s.proc(Ask, "注册 CIM 提供程序 DLL(T1218)").actor(host).cmd("*register-cimprovider*-path*")
            .disableSignedAutoAllow();
    // Windows 更新自己用 System32 下的 UpdateDeploy.dll;指向投递目录的 DLL 就是借它加载代码。
    for (const QString& d : stagingDirs + QStringList{ u("\\programdata\\"), u("\\appdata\\"), u("\\downloads\\") })
        s.proc(Block, "wuauclt 加载投递目录中的 DLL(T1218)")
            .actor("*\\wuauclt.exe").cmd(u("*/updatedeploymentprovider*") + d + u("*")).hard();

    // 从 WebDAV 共享直接运行:文件不落本地盘,也不带「来自网络」标记。
    for (const char* mark : { "@ssl\\", "\\davwwwroot\\", "@80\\", "@8080\\", "@443\\" }) {
        const QString pattern = u("*") + u(mark) + u("*");
        s.proc(Block, "运行 WebDAV 共享上的未签名程序(T1204.002/T1105)").actor(pattern).unsignedOnly().hard();
        s.proc(Ask, "运行 WebDAV 共享上的程序(T1204.002)").actor(pattern).signedOnly().disableSignedAutoAllow();
        for (const QString& host : scriptHosts() + exes({ "rundll32.exe", "regsvr32.exe", "msiexec.exe" }))
            s.proc(Block, u("经 ") + imageNameOf(host) + u(" 运行 WebDAV 共享上的脚本 / DLL(T1204.002/T1218)"))
                .actor(host).cmd(pattern).hard();
    }
    // search-ms: 把资源管理器的搜索结果指向远端共享,伪装成本地文件夹诱导双击。
    for (const char* p : { "*search-ms:*location:\\\\*", "*search-ms:*location:%5c%5c*", "*search:*location:\\\\*",
                           "*search:*location:%5c%5c*" })
        s.proc(Ask, "打开指向远端共享的 search-ms 搜索(钓鱼投递,T1204.002)").cmd(p).disableSignedAutoAllow();
    // 挂载 ISO / VHD:里面的文件没有「来自网络」标记,SmartScreen 与宏拦截都不再生效。
    for (const QString& host : exes({ "powershell.exe", "pwsh.exe" }))
        s.proc(Ask, "PowerShell 挂载磁盘映像(绕过网络来源标记,T1553.005)")
            .actor(host).cmd("*mount-diskimage*").disableSignedAutoAllow();
}

void powerShell(Segment& s) {
    const QStringList hosts = exes({ "powershell.exe", "pwsh.exe", "powershell_ise.exe" });

    const char* blinding[] = { "*amsiinitfailed*", "*amsiutils*", "*amsiscanbuffer*", "*amsicontext*" };
    const char* frameworks[] = {
        "*invoke-shellcode*", "*invoke-reflectivepeinjection*", "*invoke-dllinjection*",
        "*invoke-psinject*", "*invoke-powershelltcp*", "*powercat*", "*invoke-tokenmanipulation*",
        "*powersploit*", "*invoke-smbexec*", "*invoke-thehash*", "*invoke-bloodhound*",
    };
    const char* reverseShell[] = { "*net.sockets.tcpclient*getstream*", "*net.sockets.tcpclient*readline*" };
    const char* inMemoryPe[] = {
        "*reflection.assembly*load*frombase64string*", "*frombase64string*reflection.assembly*load*",
        "*virtualalloc*createthread*", "*virtualalloc*marshal*copy*",
    };
    // Chocolatey / Scoop 官方安装一行流也是这个形状,不能直接拦。
    const char* downloadExec[] = {
        "*iex*downloadstring*", "*invoke-expression*downloadstring*", "*downloadstring*|*iex*",
        "*downloadstring*invoke-expression*", "*iex*(iwr *", "*iex*invoke-webrequest*",
        "*iwr *|*iex*", "*invoke-webrequest*|*iex*", "*iex*(irm *", "*iex*invoke-restmethod*",
        "*irm *|*iex*", "*invoke-restmethod*|*iex*",
    };

    for (const QString& host : hosts) {
        for (const char* p : blinding)
            s.proc(Block, "PowerShell 命令行内含 AMSI 致盲代码(T1562.001)").actor(host).cmd(p).hard();
        for (const char* p : frameworks)
            s.proc(Block, "PowerShell 调用公开攻击框架(T1059.001)").actor(host).cmd(p).hard();
        for (const char* p : reverseShell)
            s.proc(Block, "PowerShell 反弹 Shell(T1059.001/T1095)").actor(host).cmd(p).hard();
        for (const char* p : inMemoryPe)
            s.proc(Block, "PowerShell 内存加载 PE / Shellcode(T1620)").actor(host).cmd(p).hard();
        // 载荷藏在注册表值里,磁盘上没有脚本文件(无文件驻留)。
        for (const char* p : { "*iex*(*get-itemproperty*", "*iex *get-itemproperty*", "*invoke-expression*get-itemproperty*",
                               "*iex*(gp *", "*[scriptblock]::create(*get-itemproperty*" })
            s.proc(Block, "PowerShell 从注册表值读出载荷并在内存执行(无文件驻留,T1059.001/T1112)")
                .actor(host).cmd(p).hard();
        for (const char* p : downloadExec)
            s.proc(Ask, "PowerShell 下载后立即执行(T1059.001/T1105)")
                .actor(host).cmd(p).disableSignedAutoAllow();
        // 前后都要空格:choco / winget 包脚本里的 --version 2.3.1 不是降级。
        for (const char* p : { "* -version 2 *", "* -version 2", "* -version 2.0 *", "* -version 2.0" })
            s.proc(Ask, "PowerShell 降级到 2.0 运行(绕过 AMSI 与脚本块日志,T1562.010)")
                .actor(host).cmd(p).disableSignedAutoAllow();
        for (const QString& d : rareExecutionDirs())
            s.proc(Ask, "PowerShell 运行罕见目录中的脚本(T1059.001)")
                .actor(host).cmd(any(d) + u(".ps1*")).disableSignedAutoAllow();
        for (const char* parent : { "*\\wscript.exe", "*\\cscript.exe", "*\\mshta.exe" })
            s.proc(Ask, "Windows 脚本宿主拉起 PowerShell(脚本投递链,T1059)")
                .actor(host).parent(parent).disableSignedAutoAllow();
    }
}

void windowsScriptHost(Segment& s) {
    const QStringList userDirs = {
        u("\\downloads\\"), u("\\desktop\\"), u("\\documents\\"), u("\\appdata\\local\\temp\\"),
        u("\\users\\public\\"), u("\\appdata\\roaming\\"),
    };
    const QStringList dropDirs = {
        u("\\downloads\\"), u("\\appdata\\local\\temp\\"), u("\\users\\public\\"),
    };
    for (const QString& host : exes({ "wscript.exe", "cscript.exe" })) {
        // 编码脚本(.jse / .vbe)在正常软件里几乎不存在,用户目录里出现基本就是投递。
        for (const char* ext : { ".jse", ".vbe" })
            for (const QString& d : userDirs)
                s.proc(Block, u("Windows 脚本宿主运行用户目录中的编码脚本(T1059.005/T1027)"))
                    .actor(host).cmd(any(d) + u(ext) + u("*")).hard();
        for (const char* ext : { ".js", ".vbs", ".wsf", ".wsh" })
            for (const QString& d : dropDirs)
                s.proc(Ask, u("Windows 脚本宿主运行下载 / 临时目录中的脚本(T1059.005/T1059.007)"))
                    .actor(host).cmd(any(d) + u(ext) + u("*")).disableSignedAutoAllow();
        s.proc(Ask, "Windows 脚本宿主强制指定脚本引擎(以非脚本扩展名伪装,T1036)")
            .actor(host).cmd("*//e:*").disableSignedAutoAllow();
    }
}

void scriptRuntimes(Segment& s) {
    // DarkGate 等载荷把 AutoIt 解释器连同编译脚本(.a3x)一起放进临时 / 公共目录运行。
    const QStringList autoIt = { u("*\\autoit3*.exe"), u("*\\autohotkey*.exe") };
    for (const char* d : { "\\appdata\\local\\temp\\", "\\windows\\temp\\", "\\users\\public\\", "\\programdata\\",
                           "\\appdata\\roaming\\" })
        for (const QString& host : autoIt)
            s.proc(Block, "AutoIt / AutoHotkey 运行投递目录中的编译脚本(T1059.010)")
                .actor(host).cmd(u("*") + u(d) + u("*.a3x*")).hard();
    // 只认临时 / 公共目录:用户的 AutoHotkey 脚本常放在「启动」文件夹(AppData\Roaming);
    // Anaconda、Chocolatey 垫片在 ProgramData;install4j 一类 Java 安装包把 JRE 解到 %TEMP% 运行,
    // 所以 java.exe 的位置不作数,只看它是否直接跑临时目录里的 JAR。
    for (const char* d : { "\\appdata\\local\\temp\\", "\\windows\\temp\\", "\\users\\public\\" }) {
        for (const QString& host : autoIt)
            s.proc(Ask, "AutoIt / AutoHotkey 运行投递目录中的脚本(T1059.010)")
                .actor(host).cmd(u("*.exe*") + u(d) + u("*")).disableSignedAutoAllow();
        for (const char* rt : { "python.exe", "pythonw.exe" })
            s.proc(Ask, u("从投递目录运行 ") + u(rt) + u("(自带解释器的投递载荷,T1059.006)"))
                .actor(u("*") + u(d) + u("*\\") + u(rt)).disableSignedAutoAllow().disableDevToolAutoAllow();
        s.proc(Ask, "Java 运行临时 / 公共目录中的 JAR(T1059)")
            .cmd(u("*java*-jar*") + u(d) + u("*.jar*")).disableSignedAutoAllow();
    }
    for (const QString& host : autoIt)
        for (const QString& parent : scriptHosts())
            s.proc(Ask, u("脚本宿主 ") + imageNameOf(parent) + u(" 拉起 AutoIt / AutoHotkey(T1059.010)"))
                .actor(host).parent(parent).disableSignedAutoAllow();
}

void disguisedImages(Segment& s) {
    // 自解压包常命名为 *.7z.exe / *.zip.exe,不在此列。
    for (const char* doc : { ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".txt",
                             ".rtf", ".jpg", ".jpeg", ".png", ".gif", ".mp3", ".mp4", ".avi" })
        for (const char* x : { ".exe", ".scr", ".com", ".pif" })
            s.proc(Block, "运行伪装成文档的可执行文件(双扩展名,T1036.007)")
                .actor(u("*") + u(doc) + u(x)).hard();
    s.proc(Block, "运行文件名含反转字符(RLO)的程序(T1036.002)")
        .actor(u("*") + QChar(0x202E) + u("*")).hard();

    for (const QString& d : rareExecutionDirs()) {
        if (d == u("\\users\\public\\")) {
            s.proc(Ask, "运行公共用户目录中的未签名程序(T1204.002)").actor(any(d)).unsignedOnly();
            continue;
        }
        s.proc(Block, "运行罕见目录中的未签名程序(回收站 / PerfLogs / Windows 资源子目录,T1036.005)")
            .actor(any(d)).unsignedOnly().hard();
    }
    for (const char* d : { "\\downloads\\", "\\desktop\\", "\\documents\\", "\\appdata\\local\\temp\\" })
        s.proc(Ask, "运行用户目录中的未签名屏保程序(T1546.002)")
            .actor(u("*") + u(d) + u("*.scr")).unsignedOnly();
}

}

void addExecutionRules(QVector<DefenseRule>& out) {
    Segment s(out, "执行");
    documentChildren(s);
    proxyExecution(s);
    powerShell(s);
    windowsScriptHost(s);
    scriptRuntimes(s);
    disguisedImages(s);
}

}
