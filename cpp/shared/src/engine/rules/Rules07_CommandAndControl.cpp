#include "RuleDsl.h"

namespace bulwark::engine::rules {

namespace {

void tunnels(Segment& s) {
    // 开发者也用内网穿透,只询问;签名的(ngrok、cloudflared)要防签名自动放行。
    // 只认精确的发布文件名:npc / gost / venom 这类短词按前缀匹配会撞上 Npcap、同名游戏等。
    for (const char* image : { "*\\ngrok.exe", "*\\frpc.exe", "*\\frps.exe", "*\\npc.exe", "*\\nps.exe",
                               "*\\chisel.exe", "*\\chisel_*.exe", "*\\ligolo-ng*.exe", "*\\gost.exe",
                               "*\\iox.exe", "*\\stowaway*.exe", "*\\ew_for_win*.exe", "*\\venom_agent*.exe",
                               "*\\venom_admin*.exe", "*\\cloudflared*.exe" })
        s.proc(Ask, u("运行内网穿透 / 隧道工具 ") + imageNameOf(u(image)) + u("(T1572/T1090)"))
            .actor(image).disableSignedAutoAllow();

    for (const QString& tool : exes({ "ssh.exe", "plink.exe" }))
        s.proc(Ask, imageNameOf(tool) + u(" 建立反向端口转发(T1572)"))
            .actor(tool).cmd("* -r *").disableSignedAutoAllow();
    s.proc(Ask, "添加端口转发规则(T1090.001)")
        .actor("*\\netsh.exe").cmd("*interface*portproxy*add*").disableSignedAutoAllow();

    for (const char* p : { "* -e *", "* -c *cmd*", "*--exec*", "*--sh-exec*" })
        for (const char* name : { "nc.exe", "nc64.exe", "ncat.exe", "netcat.exe" })
            s.proc(Block, u("netcat 绑定 / 反弹 Shell(T1059/T1095)")).actor(exe(name)).cmd(p).hard();
    s.proc(Ask, "socat 转发并执行命令(T1095)").actor("*\\socat*.exe").cmd("*exec:*").disableSignedAutoAllow();

    // 攻击者部署 AnyDesk 时会设无人值守密码,正常用户在界面里设。
    s.proc(Ask, "命令行为 AnyDesk 设置无人值守访问密码(T1219)")
        .actor("*\\anydesk*.exe").cmd("*--set-password*").disableSignedAutoAllow();
}

void remoteAccessTools(Segment& s) {
    // 远控木马没有正规发行版,未签名的同名映像一律拦。
    for (const char* rat : { "gh0st", "remcos", "njrat", "asyncrat", "darkcomet", "nanocore", "quasarrat", "xworm",
                             "dcrat", "venomrat", "meterpreter", "metsvc" })
        s.proc(Block, u("运行远控木马 ") + u(rat) + u("(T1219)"))
            .actor(u("*\\") + u(rat) + u("*.exe")).unsignedOnly().hard();
    s.proc(Block, "运行 C2 框架投递器(Covenant stager,T1071/T1105)").cmd("*covenant*stager*").hard();
    // 短名字在长 Base64 参数里有可能碰巧出现,命令行只认足够长的名字。
    for (const char* rat : { "njrat", "remcos", "asyncrat", "darkcomet", "nanocore", "quasarrat", "venomrat",
                             "meterpreter" })
        s.proc(Block, u("命令行带远控木马特征 ") + u(rat) + u("(T1219)"))
            .cmd(u("*") + u(rat) + u("*")).unsignedOnly().hard();

    // 合法远控是银狐最常用的驻留通道:用户自己从「下载」里运行不问;被脚本静默部署、
    // 放在临时 / 公共 / 共享数据目录运行、或被改过签名,才问。
    struct Tool { const char* image; bool distinctName; };
    const Tool tools[] = {
        { "anydesk", true }, { "teamviewer", true }, { "todesk", true }, { "sunloginclient", true },
        { "awesun", true }, { "rustdesk", true }, { "meshagent", true }, { "screenconnect", true },
        { "connectwisecontrol", true }, { "splashtop", true }, { "srservice", true }, { "ateraagent", true },
        { "rserver3", true }, { "ammyy", true }, { "supremo", true }, { "dwagent", true }, { "logmein", true },
        { "gotoassist", true }, { "ip-guard", true }, { "ipguard", true }, { "winvnc", true }, { "tvnserver", true },
        { "client32", false },
    };
    const char* stagingDirs[] = { "\\appdata\\local\\temp\\", "\\windows\\temp\\", "\\users\\public\\",
                                  "\\programdata\\", "\\appdata\\roaming\\" };
    for (const Tool& t : tools) {
        const QString name = u(t.image);
        // NetSupport 的 client32 是通用名,只按完整文件名认。
        const QString file = t.distinctName ? name + u("*.exe") : name + u(".exe");
        for (const QString& parent : scriptHosts())
            s.proc(Ask, u("脚本宿主 ") + imageNameOf(parent) + u(" 拉起远控软件 ") + name + u("(无人值守部署,T1219)"))
                .actor(u("*\\") + file).parent(parent).disableSignedAutoAllow();
        for (const char* d : stagingDirs)
            for (const QString& actor : { u("*") + u(d) + file, u("*") + u(d) + u("*\\") + file })
                s.proc(Ask, u("远控软件 ") + name + u(" 从临时 / 公共 / 共享数据目录运行(T1219)"))
                    .actor(actor).disableSignedAutoAllow();
        if (t.distinctName)
            s.proc(Ask, u("运行未签名的远控软件 ") + name + u("(被篡改的发行包,T1219)"))
                .actor(u("*\\") + file).unsignedOnly();
    }
    for (const char* p : { "*anydesk*--install*--silent*", "*rustdesk*--password*", "*rustdesk*--config*",
                           "*teamviewer*assignment*", "*ip-guard*/silent*", "*ipguard*/silent*" })
        s.proc(Ask, "命令行静默部署 / 配置远控软件(T1219)").cmd(p).disableSignedAutoAllow();

    // 被未签名程序写到磁盘上就拦;安全研究员用签名浏览器下载样本不在此列。
    for (const char* family : { "cobaltstrike", "meterpreter", "asyncrat", "nanocore", "darkcomet", "remcos",
                                "agenttesla", "njrat", "dcrat", "orcusrat", "warzonerat", "xtremerat", "quasarrat",
                                "venomrat", "xworm", "gh0st", "lockbit", "cl0p", "babuk", "ryuk", "revil", "sodinokibi",
                                "gandcrab", "mallox" })
        for (const char* x : { ".exe", ".dll" }) {
            // 文件名就是家族名(最多带三个字符的版本号)才硬拦。家族名后面的 * 会跨目录:
            // 7-Zip 没有签名,解压 Ryuk\launcher.exe 这类以动漫角色命名的模组目录只问。
            for (const char* tail : { "", "?", "??", "???" })
                s.file(Block, u("投放远控木马 / 勒索家族载荷 ") + u(family) + u("(执行前置,T1588.001)"))
                    .target(u("*\\") + u(family) + u(tail) + u(x)).unsignedOnly().hard();
            s.file(Ask, u("投放疑似远控木马 / 勒索家族载荷 ") + u(family) + u("(执行前置,T1588.001)"))
                .target(u("*\\") + u(family) + u("*") + u(x)).unsignedOnly();
        }
}

void miningAndExfiltration(Segment& s) {
    // 挖矿程序本身有人主动在用,只问;从投递目录跑矿池命令行才是挖矿木马。
    for (const char* miner : { "xmrig", "nanominer", "phoenixminer", "t-rex", "lolminer", "nbminer", "gminer",
                               "teamredminer", "srbminer", "cpuminer", "ccminer", "ethminer", "nheqminer" })
        s.proc(Ask, u("运行挖矿程序 ") + u(miner) + u("(T1496)"))
            .actor(u("*\\") + u(miner) + u("*.exe")).disableSignedAutoAllow();
    // NiceHash 等正规挖矿软件装在 AppData\Local\Programs 下并从那里拉起矿工,AppData 不算。
    for (const char* p : { "*stratum+tcp://*", "*stratum+ssl://*", "*stratum2+tcp://*", "*--donate-level*" }) {
        s.proc(Ask, "命令行连接矿池(T1496)").cmd(p).disableSignedAutoAllow();
        for (const char* d : { "\\temp\\", "\\users\\public\\", "\\programdata\\", "\\windows\\fonts\\" })
            s.proc(Block, "投递目录中的程序连接矿池(挖矿木马,T1496)")
                .actor(u("*") + u(d) + u("*")).cmd(p).hard();
    }

    // 勒索团伙双重勒索先把文件传走:rclone / MEGA 是最常见的两种。
    for (const char* verb : { " copy ", " sync ", " move " })
        s.proc(Ask, "rclone 向远端复制文件(数据外传,T1567.002)")
            .cmd(u("*rclone*") + u(verb) + u("*:*")).disableSignedAutoAllow();
    for (const char* p : { "*mega-put*", "*megatools*put*", "*megacmd*put*" })
        s.proc(Ask, "上传文件到 MEGA 网盘(数据外传,T1567.002)").cmd(p).disableSignedAutoAllow();
    // 窃密木马最常见的上报方式:把数据直接 POST 给聊天软件的机器人 / Webhook。
    for (const QString& host : scriptHosts() + exes({ "curl.exe", "wget.exe", "bitsadmin.exe" }))
        for (const char* p : { "*discord.com/api/webhooks*", "*discordapp.com/api/webhooks*", "*api.telegram.org/bot*" })
            s.proc(Ask, u("经 ") + imageNameOf(host) + u(" 向聊天软件机器人 / Webhook 发送数据(外传,T1567)"))
                .actor(host).cmd(p).disableSignedAutoAllow();
    // 加密码打包用户文档:外传前的收集。图形界面压缩不经命令行传密码,不在此列。
    for (const char* d : { "\\documents\\", "\\desktop\\", "\\downloads\\" })
        for (const char* p : { "*rar* a *-hp*", "*rar* a *-p*", "*7z* a *-p*" })
            s.proc(Ask, "加密码打包用户文档(外传前收集,T1560.001)")
                .cmd(u(p) + u(d) + u("*")).disableSignedAutoAllow();
}

void suspiciousNetwork(Segment& s) {
    // 这些系统程序没有正当的联网理由,联网多半是被当作下载器或宿主。wscript / cscript 不在此列:
    // 企业登录脚本、slmgr.vbs 激活都会联网,它们只按可疑域名判。
    for (const QString& bin : exes({ "mshta.exe", "regsvr32.exe", "cmstp.exe", "msxsl.exe", "installutil.exe",
                                     "regasm.exe", "regsvcs.exe", "odbcconf.exe", "ieexec.exe" }))
        s.net(Ask, imageNameOf(bin) + u(" 发起网络连接(T1218/T1105)")).actor(bin).disableSignedAutoAllow();
    for (const char* bin : { "*\\windows\\system32\\notepad.exe", "*\\windows\\system32\\calc.exe",
                             "*\\windows\\syswow64\\notepad.exe" })
        s.net(Ask, "记事本 / 计算器发起网络连接(疑似被注入,T1055)").actor(bin).disableSignedAutoAllow();
    for (const char* port : { "*:4444", "*:31337" })
        s.net(Ask, "未签名程序连接常见反弹 Shell 端口(T1571)").target(port).unsignedOnly();

    const char* tunnelDomains[] = {
        "*.ngrok.io", "*.ngrok-free.app", "*.ngrok.app", "*.trycloudflare.com", "*.serveo.net",
        "*.localhost.run", "*.portmap.io", "*.loca.lt", "*.pagekite.me",
    };
    const char* oastDomains[] = {
        "*.burpcollaborator.net", "*.oastify.com", "*.interact.sh", "*.oast.fun", "*.dnslog.cn",
        "*.ceye.io", "*.requestbin.net", "*.pipedream.net",
    };
    for (const char* d : tunnelDomains) {
        s.dns(Ask, "未签名程序解析隧道服务域名(T1572)").target(d).unsignedOnly();
        for (const QString& host : scriptHosts())
            s.dns(Ask, u("经 ") + imageNameOf(host) + u(" 解析隧道服务域名(T1572)"))
                .actor(host).target(d).disableSignedAutoAllow();
    }
    for (const char* d : oastDomains) {
        s.dns(Ask, "解析带外回连测试域名(漏洞利用回显,T1071.004)").target(d).unsignedOnly();
        for (const QString& host : scriptHosts())
            s.dns(Ask, u("经 ") + imageNameOf(host) + u(" 解析带外回连测试域名(T1071.004)"))
                .actor(host).target(d).disableSignedAutoAllow();
    }

    // 动态域名、Telegram 机器人接口、矿池:国产远控与窃密木马最常用的回连 / 上报方式。
    const auto watchDomains = [&s](const char* what, std::initializer_list<const char*> domains) {
        for (const char* d : domains) {
            s.dns(Ask, u("未签名程序解析") + u(what)).target(d).unsignedOnly();
            for (const QString& host : scriptHosts())
                s.dns(Ask, u("经 ") + imageNameOf(host) + u(" 解析") + u(what))
                    .actor(host).target(d).disableSignedAutoAllow();
        }
    };
    watchDomains("动态域名(远控回连,T1568)",
                 { "*.3322.org", "*.f3322.net", "*.f3322.org", "*.8866.org", "*.2288.org", "*.vicp.net", "*.vicp.cc",
                   "*.vicp.io", "*.oicp.net", "*.oicp.io", "*.oicp.vip", "*.zicp.net", "*.zicp.vip", "*.duckdns.org",
                   "*.ddns.net", "*.no-ip.org", "*.no-ip.biz", "*.hopto.org", "*.zapto.org", "*.sytes.net",
                   "*.dynu.net" });
    watchDomains("Telegram 机器人接口(窃密上报,T1102)", { "api.telegram.org" });
    watchDomains("公开粘贴 / 临时文件分享站(载荷托管与数据外传,T1102/T1567)",
                 { "pastebin.com", "paste.ee", "rentry.co", "hastebin.com", "transfer.sh", "file.io", "0x0.st",
                   "temp.sh", "gofile.io", "*.gofile.io", "bashupload.com", "oshi.at", "catbox.moe",
                   "*.catbox.moe", "tmpfiles.org" });
    watchDomains("矿池(挖矿,T1496)",
                 { "*.minexmr.com", "*.supportxmr.com", "*.nanopool.org", "*.f2pool.com", "*.c3pool.com",
                   "*.c3pool.org", "*.2miners.com", "*.moneroocean.stream", "*.hashvault.pro", "*.herominers.com",
                   "*.unmineable.com", "*.xmrpool.eu", "*.kryptex.network", "*.woolypooly.com", "*.zpool.ca" });
    // Tor 浏览器默认装在桌面;独立的 tor.exe 出现在这些目录里多是远控 / 勒索自带的匿名通道。
    for (const char* d : { "\\appdata\\", "\\temp\\", "\\users\\public\\", "\\programdata\\" })
        s.proc(Ask, "从投递目录运行 Tor(匿名回连通道,T1090.003)")
            .actor(u("*") + u(d) + u("*\\tor.exe")).disableSignedAutoAllow();
}

}

void addCommandAndControlRules(QVector<DefenseRule>& out) {
    Segment s(out, "远控与隧道");
    s.noDevToolAutoAllow();
    tunnels(s);
    remoteAccessTools(s);
    miningAndExfiltration(s);
    suspiciousNetwork(s);
}

}
