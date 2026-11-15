#include "RuleDsl.h"

namespace bulwark::engine::rules {

namespace {

void remoteExecution(Segment& s) {
    for (const QString& tool : exes({ "psexec.exe", "psexec64.exe", "paexec.exe", "remcom.exe", "csexec.exe" }))
        s.proc(Ask, imageNameOf(tool) + u(" 在远程主机执行命令(T1569.002/T1021.002)"))
            .actor(tool).cmd("*\\\\*").disableSignedAutoAllow();
    s.proc(Ask, "PsExec 服务端在本机被拉起(被横向移动,T1569.002)")
        .actor("*\\psexesvc*.exe").disableSignedAutoAllow();
    s.file(Ask, "写入 PsExec 服务端(被横向移动,T1569.002)").target("*\\psexesvc*.exe");

    for (const char* verb : { "create", "config", "start" })
        s.proc(Ask, u("在远程主机 ") + u(verb) + u(" 服务(T1021.002/T1569.002)"))
            .actor("*\\sc.exe").cmd(u("*\\\\*") + u(verb) + u("*")).disableSignedAutoAllow();
    s.proc(Ask, "在远程主机创建计划任务(T1053.005)")
        .actor("*\\schtasks.exe").cmd("*/create*/s *").disableSignedAutoAllow();
    s.proc(Ask, "wmic 在远程主机创建进程(T1047)")
        .actor("*\\wmic.exe").cmd("*/node:*process*call*create*").disableSignedAutoAllow();
    s.proc(Ask, "winrs 在远程主机执行命令(T1021.006)").actor("*\\winrs.exe").cmd("*-r:*").disableSignedAutoAllow();
    for (const QString& host : exes({ "powershell.exe", "pwsh.exe" })) {
        for (const char* p : { "*invoke-command*-computername*", "*invoke-wmimethod*-computername*win32_process*",
                               "*invoke-cimmethod*-computername*win32_process*",
                               "*gettypefromprogid*mmc20.application*", "*gettypefromclsid*9ba05972-f6a8-11cf-a442-00a0c90a8f39*",
                               "*gettypefromclsid*c08afd90-f2a1-11d1-8455-00a0c91f3880*" })
            s.proc(Ask, "PowerShell 在远程主机执行命令(WinRM / WMI / DCOM,T1021)")
                .actor(host).cmd(p).disableSignedAutoAllow();
    }

    for (const char* share : { "ipc$", "admin$", "c$" })
        for (const char* tool : { "*net use \\\\*\\", "*net1 use \\\\*\\", "*net.exe use \\\\*\\" })
            s.proc(Ask, u("挂载远程主机的管理共享 ") + u(share) + u("(横向移动前置,T1021.002)"))
                .cmd(u(tool) + u(share) + u("*")).disableSignedAutoAllow();
    for (const char* p : { "*winrm*quickconfig*", "*enable-psremoting*", "*winrm*set*winrm/config/service*" })
        s.proc(Ask, "开启 WinRM 远程管理(T1021.006)").cmd(p).disableSignedAutoAllow();
    for (const QString& shell : scriptHosts())
        s.proc(Ask, u("WinRM 远程会话拉起 ") + imageNameOf(shell) + u("(被远程执行命令,T1021.006)"))
            .actor(shell).parent("*\\wsmprovhost.exe").disableSignedAutoAllow();
    // DCOM 横向(MMC20.Application.ExecuteShellCommand)在目标机上就是 mmc 直接派生脚本宿主。
    for (const QString& shell : scriptHosts())
        s.proc(Ask, u("MMC 派生 ") + imageNameOf(shell) + u("(DCOM 远程执行,T1021.003)"))
            .actor(shell).parent("*\\mmc.exe").disableSignedAutoAllow();
    // 系统级代理会把 Windows 更新、证书吊销检查等后台流量都转给代理方。
    s.proc(Ask, "设置 WinHTTP 系统代理(劫持后台流量,T1090)")
        .actor("*\\netsh.exe").cmd("*winhttp*set*proxy*").disableSignedAutoAllow();
    // 程序自己加防火墙例外走 API;命令行为投递目录里的程序开口子,多是后门在等连入。
    for (const char* d : { "\\appdata\\", "\\users\\public\\", "\\programdata\\", "\\temp\\" })
        s.proc(Ask, "为投递目录中的程序添加防火墙规则(T1562.004)")
            .actor("*\\netsh.exe").cmd(u("*advfirewall*add*rule*") + u(d) + u("*")).disableSignedAutoAllow();
    s.proc(Ask, "PowerShell 监听 TCP 端口(绑定 Shell,T1059.001)").cmd("*net.sockets.tcplistener*").disableSignedAutoAllow();
    // lcx 是专门的内网端口转发工具,正常运维用 netsh / ssh。
    for (const char* p : { "*lcx*-slave*", "*lcx*-listen*", "*lcx*-tran*" })
        s.proc(Block, "运行 lcx 端口转发(内网跳板,T1090.001)").cmd(p).hard();

    // Impacket wmiexec / smbexec 的回显重定向:正常管理工具不会把输出写回自己的管理共享。
    for (const char* p : { "*\\\\127.0.0.1\\admin$\\__*", "*\\\\127.0.0.1\\c$\\__output*",
                           "*1> \\\\127.0.0.1\\*", "*\\\\localhost\\admin$\\__*" })
        s.proc(Block, "Impacket 远程执行回显痕迹(T1047/T1021.002)").cmd(p).hard();
}

void adminShares(Segment& s) {
    for (const QString& host : exes({ "cmd.exe", "powershell.exe", "pwsh.exe", "robocopy.exe", "xcopy.exe" }))
        for (const char* share : { "\\\\*\\admin$*", "\\\\*\\c$\\windows\\*" })
            for (const char* ext : { ".exe", ".dll", ".bat", ".ps1" })
                s.proc(Ask, u("经 ") + imageNameOf(host) + u(" 向远程管理共享投放可执行内容(T1570)"))
                    .actor(host).cmd(u("*") + u(ext) + u("*") + u(share)).disableSignedAutoAllow();
}

void remoteDesktop(Segment& s) {
    // 管理员在自己的会话里切换只问;以 SYSTEM 服务身份运行 tscon 可以不要密码接管任何人的会话。
    s.proc(Ask, "切换 / 接管 RDP 会话(管理员也用,T1563.002)").cmd("*tscon*/dest:*").disableSignedAutoAllow();
    s.proc(Block, "以 SYSTEM 服务身份劫持他人 RDP 会话(T1563.002)")
        .parent("*\\services.exe").cmd("*tscon*/dest:*").hard();
    s.proc(Block, "创建运行 tscon 的服务(RDP 会话劫持,T1563.002)").cmd("*binpath*tscon*").hard();
    for (const char* p : { "*net localgroup \"remote desktop users\" * /add*",
                           "*net1 localgroup \"remote desktop users\" * /add*",
                           "*add-localgroupmember*remote desktop users*" })
        s.proc(Ask, "把账户加入远程桌面用户组(T1098/T1021.001)").cmd(p).disableSignedAutoAllow();
    // 域管理员组变更正常走 AD 管理工具;命令行加人多是攻击者,但域管理员偶尔也这么做,当场问。
    for (const char* group : { "domain admins", "enterprise admins", "schema admins" })
        s.proc(Ask, u("把账户加入域特权组 ") + u(group) + u("(T1098.007)"))
            .cmd(u("*group*") + u(group) + u("*/add*")).disableSignedAutoAllow();
    s.proc(Ask, "启用内置管理员账户(T1078.001)").cmd("*net*user*administrator*/active:yes*").disableSignedAutoAllow();
    // RDPWrap 让家庭版也能多人同时远程登录;个人用户确有在用,只问。
    for (const char* tool : { "*\\rdpwinst*.exe", "*\\rdpconf*.exe", "*\\rdpwrap*.exe" })
        s.proc(Ask, "安装 / 配置 RDPWrap(多会话远程桌面,T1021.001)").actor(tool).disableSignedAutoAllow();

    struct Toggle { const char* what; const char* key; quint32 value; };
    const Toggle toggles[] = {
        { "开启远程桌面(T1021.001)", "*\\Terminal Server\\fDenyTSConnections", 0 },
        { "允许多会话并发远程桌面(T1021.001)", "*\\Terminal Server\\fSingleSessionPerUser", 0 },
        { "关闭远程桌面网络级身份验证(T1021.001)", "*\\WinStations\\RDP-Tcp\\UserAuthentication", 0 },
        { "允许不经同意远程控制会话(T1021.001)", "*\\Terminal Services\\Shadow", 2 },
    };
    for (const Toggle& t : toggles) {
        s.reg(Ask, u(t.what) + u("(未签名写入者)")).target(t.key).regDword(t.value).unsignedOnly().onlySetValue();
        for (const QString& w : scriptedWriters())
            s.reg(Ask, u(t.what) + u("(经 ") + imageNameOf(w) + u(")"))
                .actor(w).target(t.key).regDword(t.value).onlySetValue().disableSignedAutoAllow();
    }
    for (const QString& w : scriptedWriters())
        s.reg(Ask, u("经 ") + imageNameOf(w) + u(" 改写远程桌面端口(T1021.001)"))
            .actor(w).target("*\\WinStations\\RDP-Tcp\\PortNumber").onlySetValue().disableSignedAutoAllow();
    s.proc(Ask, "防火墙放行远程桌面(T1021.001)")
        .actor("*\\netsh.exe").cmd("*remote desktop*enable*yes*").disableSignedAutoAllow();
}

}

void addLateralMovementRules(QVector<DefenseRule>& out) {
    Segment s(out, "横向移动");
    remoteExecution(s);
    adminShares(s);
    remoteDesktop(s);
}

}
