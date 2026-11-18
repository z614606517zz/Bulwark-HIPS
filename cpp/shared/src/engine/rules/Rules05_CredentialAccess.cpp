#include "RuleDsl.h"

namespace bulwark::engine::rules {

namespace {

void lsassDumping(Segment& s) {
    // comsvcs!MiniDump 没有任何正当的命令行用法。
    for (const char* p : { "*comsvcs*minidump*", "*comsvcs*#24*", "*comsvcs*#+24*" })
        s.proc(Block, "经 comsvcs.dll 转储进程内存(LSASS 凭据窃取,T1003.001)").cmd(p).hard();
    for (const char* tool : { "procdump", "sqldumper", "createdump", "rdrleakdiag", "dumpminitool" })
        s.proc(Block, u(tool) + u(" 转储 LSASS(T1003.001)")).cmd(u("*") + u(tool) + u("*lsass*")).hard();

    // lsass 真崩溃时由 WerFault 写转储,放行;其余任何写出 lsass 转储的都是在偷凭据。
    s.file(Allow, "Windows 错误报告写出 LSASS 崩溃转储")
        .actor("*\\Windows\\System32\\WerFault.exe").target("*\\lsass*.dmp");
    s.file(Block, "写出 LSASS 内存转储文件(T1003.001)").target("*\\lsass*.dmp");
    s.reg(Block, "为 LSASS 配置崩溃本地转储(T1003.001)")
        .target("*\\Windows Error Reporting\\LocalDumps\\lsass.exe*").exemptOs().hard();
    s.reg(Block, "为 LSASS 配置静默退出转储(T1003.001)")
        .target("*\\SilentProcessExit\\lsass.exe*").exemptOs().hard();
    // 结束 LSASS 会让系统在一分钟内强制重启。
    s.kill(Block, "结束 LSASS 进程(系统凭据服务,T1489/T1529)").target("*\\lsass.exe").exemptOs().hard();
}

void credentialStores(Segment& s) {
    for (const char* hive : { "sam", "security" })
        for (const char* root : { "hklm\\", "hkey_local_machine\\" })
            for (const char* verb : { "save", "export" })
                s.proc(Block, u("导出 ") + u(hive) + u(" 注册表配置单元(T1003.002)"))
                    .cmd(u("*reg*") + u(verb) + u("*") + u(root) + u(hive) + u("*")).hard();
    for (const char* root : { "hklm\\", "hkey_local_machine\\" })
        s.proc(Ask, "导出 SYSTEM 注册表配置单元(含启动密钥,T1003.002)")
            .actor("*\\reg.exe").cmd(u("*save*") + u(root) + u("system*")).disableSignedAutoAllow();

    for (const char* p : { "*harddiskvolumeshadowcopy*\\config\\sam*",
                           "*harddiskvolumeshadowcopy*\\config\\security*",
                           "*harddiskvolumeshadowcopy*ntds.dit*" })
        s.proc(Block, "从卷影副本复制凭据库(T1003.002/T1003.003)").cmd(p).hard();
    for (const char* p : { "*esentutl*/vss*ntds.dit*", "*esentutl*/vss*\\config\\sam*",
                           "*esentutl*/vss*\\config\\security*" })
        s.proc(Block, "经 esentutl 卷影复制凭据库(T1003.002/T1003.003)").cmd(p).hard();
    for (const char* p : { "*ifm*", "*\"ac i ntds\"*", "*activate instance ntds*" })
        s.proc(Ask, "ntdsutil 导出域数据库(T1003.003)").actor("*\\ntdsutil.exe").cmd(p).disableSignedAutoAllow();

    s.proc(Ask, "列出凭据管理器中的凭据(T1555.004)")
        .actor("*\\vaultcmd.exe").cmd("*/listcreds*").disableSignedAutoAllow();
    s.proc(Ask, "列出已保存的 Windows 凭据(T1555.004)").cmd("*cmdkey*/list*").disableSignedAutoAllow();
    s.proc(Ask, "导出无线网络明文口令(T1555)").cmd("*netsh*wlan*show*key=clear*").disableSignedAutoAllow();
    s.proc(Ask, "查询服务主体名(Kerberoasting 前置,T1558.003)").cmd("*setspn*-q *").disableSignedAutoAllow();
    for (const char* p : { "*vssadmin*create*shadow*", "*shadowcopy*call*create*", "*win32_shadowcopy*).create(*" })
        s.proc(Ask, "创建卷影副本(绕开文件锁读取 SAM / NTDS 的前置,T1003.002)").cmd(p).disableSignedAutoAllow();
    s.proc(Ask, "经 DSInternals 读取域账户哈希(DCSync,T1003.006)").cmd("*get-adreplaccount*").disableSignedAutoAllow();
    s.proc(Block, "PowerShell 执行 DCSync(T1003.006)").cmd("*invoke-dcsync*").hard();
    s.file(Ask, "复制域凭据库 ntds.dit(T1003.003)").target("*\\ntds.dit").exemptOs().disableSignedAutoAllow();

    // DPAPI 主密钥只该由 LSASS 写;被改写意味着有人在为解密凭据做准备。
    s.file(Block, "未签名程序改写 DPAPI 主密钥(T1555)").target("*\\Microsoft\\Protect\\*").unsignedOnly().hard();
    for (const QString& w : scriptHosts())
        s.file(Ask, u("经 ") + imageNameOf(w) + u(" 改写 DPAPI 主密钥(T1555)"))
            .actor(w).target("*\\Microsoft\\Protect\\*").disableSignedAutoAllow();
}

void credentialTools(Segment& s) {
    // Mimikatz 的模块语法在正常软件里不存在。
    for (const char* p : { "*sekurlsa::*", "*lsadump::*", "*kerberos::golden*", "*kerberos::ptt*",
                           "*kerberos::ask*", "*privilege::debug*", "*crypto::capi*", "*dpapi::*",
                           "*token::elevate*", "*misc::memssp*", "*invoke-mimikatz*", "*misc::skeleton*",
                           "*misc::addsid*", "*sid::add*", "*sid::patch*", "*kerberos::silver*" })
        s.proc(Block, "Mimikatz 凭据窃取指令(T1003)").cmd(p).hard();
    // 影子凭据:往账户的 msDS-KeyCredentialLink 写入自己的公钥,之后凭证书拿到该账户的票据。
    s.proc(Ask, "改写账户的 msDS-KeyCredentialLink(影子凭据,T1556)")
        .cmd("*msds-keycredentiallink*").disableSignedAutoAllow();
    s.proc(Block, "运行 Mimikatz(T1003)").actor("*\\mimikatz*.exe").hard();
    s.proc(Block, "PowerShell 请求 Kerberos 服务票据(Kerberoasting,T1558.003)")
        .cmd("*kerberosrequestorsecuritytoken*").hard();

    // 工具名会出现在 git clone、IDE 打开同名仓库等命令行里:只认未签名主体或经脚本宿主 / Python 调用。
    // certify / whisker / seatbelt 这类普通单词另有同名正规软件(如 Certify The Web),只认未签名映像。
    struct Tool { const char* name; bool distinctName; };
    const Tool tools[] = {
        { "lazagne", true }, { "pypykatz", true }, { "nanodump", true }, { "handlekatz", true },
        { "dumpert", true }, { "safetykatz", true }, { "sharpkatz", true }, { "rubeus", true }, { "kekeo", true },
        { "sharpdpapi", true }, { "sharpchrome", true }, { "hackbrowserdata", true }, { "secretsdump", true },
        { "ntlmrelayx", true }, { "inveigh", true }, { "sharphound", true }, { "certipy", true },
        { "petitpotam", true }, { "coercer", true }, { "dfscoerce", true }, { "krbrelayup", true },
        { "kerbrute", true }, { "lsassy", true }, { "pywhisker", true }, { "winpeas", true }, { "sharpup", true },
        { "crackmapexec", true }, { "netexec", true }, { "evil-winrm", true }, { "wmiexec", true },
        { "smbexec", true }, { "atexec", true }, { "dcomexec", true }, { "getuserspns", true },
        { "getnpusers", true }, { "gettgt", true }, { "goldenpac", true },
        { "certify", false }, { "whisker", false }, { "seatbelt", false }, { "bloodhound", false },
        { "ticketer", false }, { "nxc", false },
    };
    QStringList hosts = scriptHosts();
    hosts << exe("python.exe") << exe("pythonw.exe") << exe("py.exe");
    for (const Tool& t : tools) {
        const QString name = u(t.name);
        const QString imagePattern = t.distinctName ? u("*\\") + name + u("*.exe") : u("*\\") + name + u(".exe");
        s.proc(Block, u("运行凭据窃取 / 域渗透工具 ") + name + u("(T1003/T1087/T1558)"))
            .actor(imagePattern).unsignedOnly().hard();
        for (const QString& host : hosts) {
            s.proc(Block, u("经 ") + imageNameOf(host) + u(" 调用凭据窃取 / 域渗透工具 ") + name
                              + u("(T1003/T1087/T1558)"))
                .actor(host).cmd(u("*invoke-") + name + u("*")).hard();
            if (!t.distinctName)
                continue;
            for (const char* form : { ".exe*", ".py*" })
                s.proc(Block, u("经 ") + imageNameOf(host) + u(" 调用凭据窃取 / 域渗透工具 ") + name
                                  + u("(T1003/T1087/T1558)"))
                    .actor(host).cmd(u("*") + name + u(form)).hard();
        }
    }
    // 被未签名程序写到磁盘上就拦,不等它运行;签名的浏览器、解压软件保存同名文件不在此列。
    for (const Tool& t : tools) {
        if (!t.distinctName)
            continue;
        for (const char* x : { ".exe", ".dll", ".ps1", ".py" })
            s.file(Block, u("投放凭据窃取 / 域渗透工具 ") + u(t.name) + u("(执行前置,T1588.002)"))
                .target(u("*\\") + u(t.name) + u("*") + u(x)).unsignedOnly().hard();
    }
    // AD 查询与评估工具管理员也在用,勒索团伙同样爱用:只问。
    for (const char* tool : { "*\\adfind.exe", "*\\pingcastle.exe", "*\\adrecon*.exe" })
        s.proc(Ask, "运行 AD 侦察 / 评估工具(域管排障也用,T1087/T1069)").actor(tool).disableSignedAutoAllow();

    // 微信本地库解密 / 导出:偷通讯录与聊天记录,群发诈骗的前置。
    // WeChatMsg(留痕)是用户导出自己聊天记录的开源工具,只问;其余是纯解密 / 取证工具,直接拦。
    s.proc(Ask, "运行微信聊天记录导出工具 WeChatMsg(留痕,T1005)")
        .actor("*\\wechatmsg*.exe").unsignedOnly().disableSignedAutoAllow();
    for (const QString& host : hosts)
        s.proc(Ask, u("经 ") + imageNameOf(host) + u(" 调用微信聊天记录导出工具 WeChatMsg(留痕,T1005)"))
            .actor(host).cmd("*wechatmsg*").disableSignedAutoAllow();
    for (const char* tool : { "pywxdump", "sharpwxdump", "wxdump", "wechatdecrypt" }) {
        s.proc(Block, u("运行微信本地库解密 / 导出工具 ") + u(tool) + u("(T1005)"))
            .actor(u("*\\") + u(tool) + u("*.exe")).unsignedOnly().hard();
        for (const QString& host : hosts)
            s.proc(Block, u("经 ") + imageNameOf(host) + u(" 调用微信本地库解密 / 导出工具 ") + u(tool) + u("(T1005)"))
                .actor(host).cmd(u("*") + u(tool) + u("*")).hard();
        s.file(Block, u("投放微信本地库解密 / 导出工具 ") + u(tool) + u("(T1005)"))
            .target(u("*\\") + u(tool) + u("*.exe")).unsignedOnly().hard();
    }

    // 浏览器口令库只该由浏览器自己读;脚本复制出来是窃取的前置动作。
    for (const char* store : { "*\\login data*", "*\\cookies*", "*\\key4.db*", "*\\logins.json*" })
        for (const QString& host : exes({ "cmd.exe", "powershell.exe", "pwsh.exe", "esentutl.exe" }))
            for (const char* verb : { "*copy *", "*copy-item*", "*/y *" })
                s.proc(Ask, u("经 ") + imageNameOf(host) + u(" 复制浏览器凭据 / Cookie 数据库(T1555.003)"))
                    .actor(host).cmd(u(verb) + u(store)).disableSignedAutoAllow();

    // 以远程调试端口拉起浏览器、指向真实用户数据目录,可以绕过 Cookie 的应用绑定加密直接读出。
    // 自动化测试(Puppeteer / Playwright)用临时的用户数据目录,不在此列。
    for (const QString& b : browsers()) {
        for (const QString& parent : scriptHosts())
            s.proc(Ask, u("脚本宿主以远程调试端口拉起浏览器 ") + imageNameOf(b) + u("(窃取 Cookie,T1539)"))
                .actor(b).parent(parent).cmd("*--remote-debugging-port*").disableSignedAutoAllow();
        s.proc(Ask, u("以远程调试端口打开真实用户数据目录 ") + imageNameOf(b) + u("(窃取 Cookie,T1539)"))
            .actor(b).cmd("*--remote-debugging-port*\\user data*").disableSignedAutoAllow();
    }
}

void credentialPolicies(Segment& s) {
    s.reg(Block, "开启 WDigest 明文口令缓存(未签名写入者,T1112/T1003.001)")
        .target("*\\SecurityProviders\\WDigest\\UseLogonCredential").regDword(1)
        .unsignedOnly().onlySetValue().exemptOs().hard();
    for (const QString& w : scriptedWriters())
        s.reg(Block, u("经 ") + imageNameOf(w) + u(" 开启 WDigest 明文口令缓存(T1112/T1003.001)"))
            .actor(w).target("*\\SecurityProviders\\WDigest\\UseLogonCredential").regDword(1)
            .onlySetValue().exemptOs().hard();
    s.reg(Ask, "开启 WDigest 明文口令缓存(T1112/T1003.001)")
        .target("*\\SecurityProviders\\WDigest\\UseLogonCredential").regDword(1)
        .onlySetValue().exemptOs().disableSignedAutoAllow();

    struct Toggle { const char* what; const char* key; quint32 value; };
    const Toggle toggles[] = {
        { "关闭 LSA 保护(RunAsPPL,T1562)", "*\\Control\\Lsa\\RunAsPPL", 0 },
        { "允许存储 LM 哈希(T1556)", "*\\Control\\Lsa\\NoLMHash", 0 },
        { "关闭凭据保护(T1562)", "*\\Control\\Lsa\\LsaCfgFlags", 0 },
    };
    for (const Toggle& t : toggles)
        s.reg(Ask, u(t.what)).target(t.key).regDword(t.value).onlySetValue().exemptOs().disableSignedAutoAllow();
}

}

void addCredentialAccessRules(QVector<DefenseRule>& out) {
    Segment s(out, "凭据访问");
    s.noDevToolAutoAllow();
    for (const char* target : { "*\\.ssh\\id_rsa", "*\\.ssh\\id_dsa", "*\\.ssh\\id_ecdsa", "*\\.ssh\\id_ed25519", "*\\.ssh\\identity", "*\\GitHub CLI\\hosts.yml",
        "*\\.aws\\credentials", "*\\.azure\\accessTokens.json", "*\\.azure\\msal_token_cache.json", "*\\.azure\\msal_token_cache.bin",
        "*\\gcloud\\application_default_credentials.json", "*\\gcloud\\credentials.db", "*\\.kube\\config", "*\\.docker\\config.json",
        "*\\.npmrc", "*\\.pypirc", "*\\.git-credentials", "*\\gh\\hosts.yml" })
        s.add(EventType::FileRead, Ask, u("读取开发者或云凭据（仅路径元数据，观测后确认，T1552）"))
            .target(target).exemptOs().disableSignedAutoAllow().disableDevToolAutoAllow();
    lsassDumping(s);
    credentialStores(s);
    credentialTools(s);
    credentialPolicies(s);
}

}
