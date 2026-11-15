#include "RuleDsl.h"

namespace bulwark::engine::rules {

namespace {

void uacBypassKeys(Segment& s) {
    // 自动提权程序读当前用户的类注册表时会执行这里的命令;HKLM 下的默认值由系统组件写,豁免。
    // 内核上报的当前用户类根键形如 \REGISTRY\USER\<SID>_Classes\...,「Classes」前面不一定是反斜杠。
    const char* hijacks[] = {
        "*Classes\\ms-settings\\shell\\open\\command*",
        "*Classes\\mscfile\\shell\\open\\command*",
        "*Classes\\exefile\\shell\\open\\command*",
        "*Classes\\Folder\\shell\\open\\command*",
        "*Classes\\Launcher.SystemSettings\\shell\\open\\command*",
        "*Classes\\AppX82a6gwre4fdg3bt635tn5ctqjf8msdd2\\Shell\\open\\command*",
        "*Classes\\ms-cxh\\shell\\open\\command*",
        "*\\Environment\\windir",
    };
    for (const char* key : hijacks) {
        s.reg(Block, "改写自动提权程序读取的命令键(UAC 绕过,未签名写入者,T1548.002)")
            .target(key).unsignedOnly().onlySetValue().exemptOs().hard();
        for (const QString& w : scriptedWriters())
            s.reg(Block, u("经 ") + imageNameOf(w) + u(" 改写自动提权程序读取的命令键(UAC 绕过,T1548.002)"))
                .actor(w).target(key).onlySetValue().exemptOs().hard();
        s.reg(Ask, "改写自动提权程序读取的命令键(UAC 绕过,T1548.002)")
            .target(key).onlySetValue().exemptOs().disableSignedAutoAllow();
    }

    // 命令行形态(reg add / New-Item / Set-ItemProperty):只有 ETW 时注册表写入拦不住,得在进程创建时截下。
    // 第三方文件管理器经 API 设为默认,不走命令行;命令行改 Folder 打开命令仍只问。
    // 要带写入动作:reg query / Get-ItemProperty 只读查询和 reg delete 清理都不算。
    const auto writes = [](const char* key) {
        QStringList out;
        for (const char* verb : { "* add ", "*new-item", "*set-item", "*createsubkey" })
            out << u(verb) + u(key);
        out << u(key) + u("setvalue*");
        return out;
    };
    for (const char* key : { "*classes\\ms-settings\\shell\\open\\command*", "*classes\\mscfile\\shell\\open\\command*",
                             "*classes\\exefile\\shell\\open\\command*",
                             "*classes\\launcher.systemsettings\\shell\\open\\command*",
                             "*classes\\appx82a6gwre4fdg3bt635tn5ctqjf8msdd2\\shell\\open\\command*",
                             "*classes\\ms-cxh\\shell\\open\\command*" })
        for (const QString& p : writes(key))
            s.proc(Block, "命令行改写自动提权程序读取的命令键(UAC 绕过,T1548.002)").cmd(p).hard();
    for (const QString& p : writes("*classes\\folder\\shell\\open\\command*"))
        s.proc(Ask, "命令行改写文件夹打开命令(sdclt UAC 绕过,T1548.002)").cmd(p).disableSignedAutoAllow();

    // 这些程序被脚本宿主拉起,通常是刚改完上面的键、在触发提权。
    for (const QString& elevator : exes({ "fodhelper.exe", "computerdefaults.exe", "sdclt.exe",
                                          "eventvwr.exe", "wsreset.exe", "slui.exe", "changepk.exe" }))
        for (const QString& parent : scriptHosts())
            s.proc(Ask, u("脚本宿主拉起自动提权程序 ") + imageNameOf(elevator) + u("(UAC 绕过,T1548.002)"))
                .actor(elevator).parent(parent).disableSignedAutoAllow();
}

void imageHijack(Segment& s) {
    // 给安全软件挂映像劫持:它一启动就被换成别的程序,或根本起不来。
    QStringList guarded = securityProductImages();
    guarded << QStringLiteral("bulwark_service.exe") << QStringLiteral("bulwark_ui.exe");
    for (const QString& img : guarded)
        for (const char* value : { "Debugger", "GlobalFlag" })
            s.reg(Block, u("给安全软件 ") + img + u(" 设置映像劫持 ") + u(value) + u("(T1562.001/T1546.012)"))
                .target(u("*\\Image File Execution Options\\") + img + u("\\") + u(value)).exemptOs().hard();
    // Application Verifier 会把这里列出的 DLL 强行塞进目标进程。
    const char* verifier = "*\\Image File Execution Options\\*\\VerifierDlls";
    s.reg(Block, "通过 IFEO VerifierDlls 向进程注入 DLL(未签名写入者,T1546.012)")
        .target(verifier).unsignedOnly().exemptOs().hard();
    for (const QString& w : scriptedWriters())
        s.reg(Block, u("经 ") + imageNameOf(w) + u(" 通过 IFEO VerifierDlls 注入 DLL(T1546.012)"))
            .actor(w).target(verifier).exemptOs().hard();
}

void hijackableSystemDlls(Segment& s) {
    // 系统服务会按名字加载、但默认并不存在的 DLL:放进 System32 就是服务级代码执行。
    const char* names[] = {
        "wlbsctrl.dll", "wptsextensions.dll", "tsmsisrv.dll", "tsvipsrv.dll", "wow64log.dll",
        "cdpsgshims.dll", "windowscoredeviceinfo.dll", "phoneinfo.dll", "edgegdi.dll",
    };
    for (const char* n : names) {
        const QString target = u("*\\Windows\\System32\\") + u(n);
        s.file(Block, u("向 System32 投放可被系统服务劫持加载的 ") + u(n) + u("(T1574.001)"))
            .target(target).unsignedOnly().hard();
        for (const QString& w : scriptHosts())
            s.file(Block, u("经 ") + imageNameOf(w) + u(" 向 System32 投放 ") + u(n) + u("(T1574.001)"))
                .actor(w).target(target).hard();
    }
}

void tokenAbuseTools(Segment& s) {
    // potato 是普通单词(游戏也会叫这个名字),只认具体的工具名。
    const char* tools[] = {
        "*\\godpotato*.exe", "*\\juicypotato*.exe", "*\\sweetpotato*.exe", "*\\efspotato*.exe",
        "*\\roguepotato*.exe", "*\\rottenpotato*.exe", "*\\genericpotato*.exe", "*\\badpotato*.exe",
        "*\\localpotato*.exe", "*\\printspoofer*.exe", "*\\akagi*.exe", "*\\uacme*.exe", "*\\bypassuac*.exe",
        "*\\fullpwn*.exe",
    };
    for (const char* tool : tools) {
        s.proc(Block, "运行本地提权 / UAC 绕过工具(Potato、UACME 等,T1134.001/T1548.002)")
            .actor(tool).unsignedOnly().hard();
        s.file(Block, "投放本地提权 / UAC 绕过工具(执行前置,T1588.002)").target(tool).unsignedOnly().hard();
    }
    for (const char* p : { "*printspoofer*", "*godpotato*", "*juicypotato*", "*sweetpotato*", "*rottenpotato*",
                           "*roguepotato*", "*genericpotato*", "*akagi*", "*uacme*", "*bypassuac*", "*fullpwn*",
                           "*invoke-privesc*" })
        for (const QString& host : exes({ "powershell.exe", "pwsh.exe", "cmd.exe" }))
            s.proc(Block, "脚本宿主调用本地提权 / UAC 绕过工具(T1134.001/T1548.002)").actor(host).cmd(p).hard();

    // 「C:\Windows \System32」(Windows 后带空格)会被自动提权检查当成系统目录。
    s.file(Block, "创建带空格的假系统目录(UAC 绕过,T1548.002)").target("?:\\windows \\*").hard();
    s.proc(Block, "从带空格的假系统目录运行程序(UAC 绕过,T1548.002)").actor("?:\\windows \\*").hard();

    // 开了 AlwaysInstallElevated,任何用户都能以 SYSTEM 身份装 MSI。
    for (const char* key : { "*\\Policies\\Microsoft\\Windows\\Installer\\AlwaysInstallElevated" }) {
        s.reg(Block, "开启 AlwaysInstallElevated(普通用户可装 SYSTEM 级 MSI,未签名写入者,T1548)")
            .target(key).regDword(1).unsignedOnly().onlySetValue().exemptOs().hard();
        for (const QString& w : scriptedWriters())
            s.reg(Ask, u("经 ") + imageNameOf(w) + u(" 开启 AlwaysInstallElevated(T1548)"))
                .actor(w).target(key).regDword(1).onlySetValue().disableSignedAutoAllow();
    }

    for (const char* p : { "*config*binpath=*", "*config*binpath =*" })
        s.proc(Ask, "改写服务映像路径(服务劫持,T1574.011)").actor("*\\sc.exe").cmd(p).disableSignedAutoAllow();

    // 调整自身特权(AdjustTokenPrivileges)是正常管理操作;复制 / 模拟他人令牌、开调试特权才是窃权。
    // 只提到 SeDebugPrivilege(whoami /priv | findstr SeDebugPrivilege)不算,要和开特权的调用一起出现。
    const char* tokenTheft[] = {
        "*impersonateloggedonuser*", "*duplicatetokenex*", "*setthreadtoken*", "*createprocesswithtokenw*",
        "*adjusttokenprivileges*sedebugprivilege*", "*sedebugprivilege*adjusttokenprivileges*",
        "*lookupprivilegevalue*sedebugprivilege*", "*sedebugprivilege*lookupprivilegevalue*",
        "*enable-privilege*sedebugprivilege*",
    };
    for (const char* p : tokenTheft) {
        s.proc(Block, "未签名程序复制 / 模拟进程令牌或启用调试特权(T1134)").cmd(p).unsignedOnly().hard();
        for (const QString& host : exes({ "powershell.exe", "pwsh.exe", "cmd.exe" }))
            s.proc(Block, "脚本宿主复制 / 模拟进程令牌或启用调试特权(T1134)").actor(host).cmd(p).hard();
    }
}

}

void addPrivilegeEscalationRules(QVector<DefenseRule>& out) {
    Segment s(out, "提权");
    s.noDevToolAutoAllow();
    uacBypassKeys(s);
    imageHijack(s);
    hijackableSystemDlls(s);
    tokenAbuseTools(s);
}

}
