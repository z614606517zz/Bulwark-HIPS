#include "RuleDsl.h"

namespace bulwark::engine::rules {

namespace {

const QStringList& criticalProcesses() {
    static const QStringList s = exes({ "lsass.exe", "lsaiso.exe", "csrss.exe", "winlogon.exe", "services.exe",
                                        "smss.exe", "wininit.exe" });
    return s;
}

void remoteThreads(Segment& s) {
    // 调试器、辅助工具、游戏覆盖层都带签名;未签名程序或脚本宿主跨进程起线程才是注入形态。
    for (const QString& target : criticalProcesses()) {
        s.thread(Block, u("未签名程序向系统关键进程 ") + imageNameOf(target) + u(" 注入线程(T1055)"))
            .target(target).unsignedOnly().hard();
        s.thread(Ask, u("向系统关键进程 ") + imageNameOf(target) + u(" 注入线程(T1055)"))
            .target(target).exemptOs().disableSignedAutoAllow();
    }
    for (const QString& host : exes({ "powershell.exe", "pwsh.exe", "rundll32.exe", "regsvr32.exe", "mshta.exe",
                                      "wscript.exe", "cscript.exe", "msbuild.exe", "installutil.exe" }))
        s.thread(Block, imageNameOf(host) + u(" 跨进程创建线程(脚本 / 代理宿主注入,T1055)"))
            .actor(host).hard();
    s.thread(Ask, "未签名程序跨进程创建线程(T1055)").unsignedOnly();
}

// 内存扫描的发现以「远程线程」事件上报,target 形如「PID 1234 x.exe · <发现>」;主体是承载方,不一定是写入方。
void memoryFindings(Segment& s) {
    s.thread(Block, "AMSI 扫描接口被内存补丁禁用(T1562.001)").target("*AMSI*内存补丁*").hard();
    s.thread(Block, "ETW 遥测通道被内存补丁禁用(T1562.006)").target("*ETW*内存补丁*").hard();
    s.thread(Block, "进程内存中存在未落地的 PE 映像(反射式 DLL / 手工映射,T1620)").target("*未落地的 PE 映像*").hard();
    s.thread(Block, "waitfor 承载无文件后备的可执行映射节(银狐常驻宿主,T1055)")
        .actor("*\\waitfor.exe").target("*无文件后备的可执行映射节*").hard();
    // 扫描器已排除 JIT 宿主,剩下的仍可能是加壳 / 自解密的正规程序:只问。
    s.thread(Ask, "承载进程内存中存在可写可执行私有内存(RWX,写入方未知,T1055)").target("*可写且可执行的私有内存*");
    s.thread(Ask, "承载进程内存中存在无文件后备的可执行映射节(写入方未知,T1055)").target("*无文件后备的可执行映射节*");
}

void moduleLoads(Segment& s) {
    s.image(Block, "LSASS 加载未签名模块(SSP / 密码筛选器注入,T1547.005)")
        .actor("*\\lsass.exe").targetUnsignedOnly().hard();
    for (const QString& host : exes({ "winlogon.exe", "csrss.exe", "services.exe", "wininit.exe", "smss.exe" }))
        s.image(Ask, imageNameOf(host) + u(" 加载未签名模块(T1055.001)"))
            .actor(host).targetUnsignedOnly().disableSignedAutoAllow();
    // XLL 是 Excel 直接加载的原生 DLL;从邮件附件、下载、临时目录直接打开就是投递。正规插件装在固定目录。
    for (const char* d : { "\\downloads\\", "\\appdata\\local\\temp\\", "\\content.outlook\\", "\\inetcache\\" })
        s.image(Ask, "Excel 加载下载 / 临时 / 邮件附件目录中的未签名 XLL(T1137.006/T1204.002)")
            .actor("*\\excel.exe").target(u("*") + u(d) + u("*.xll")).targetUnsignedOnly().disableSignedAutoAllow();

    // 白加黑:签名宿主与未签名 DLL 一起放在投递目录;安装器按完整路径加载解到子目录的插件,不同目录不命中。
    // 「下载」不算:便携版解压在那里运行,签名主程序配未签名插件是常态。ProgramData 里正规软件也有
    // 这种组合,但它是银狐最常用的落点,只问。
    for (const char* dir : { "\\appdata\\local\\temp\\", "\\windows\\temp\\", "\\programdata\\", "\\users\\public\\",
                             "\\$recycle.bin\\", "\\perflogs\\" })
        s.image(Ask, "签名程序在投递目录加载同目录的未签名 DLL(白加黑侧载,T1574.002)")
            .actor(u("*") + u(dir) + u("*")).target(u("*") + u(dir) + u("*.dll"))
            .hostSignedOnly().targetUnsignedOnly().targetBesideActor().disableSignedAutoAllow();

    for (const char* dll : { "*\\amsi.dll", "*\\wldp.dll" })
        s.image(Block, "加载未签名的同名安全组件(AMSI / WLDP 劫持,T1574.001)")
            .target(dll).targetUnsignedOnly().hard();

    // 没有任何安装器或运行时约定往公共目录解包模块;这里是银狐的常用暂存点,宿主签名与否都问。
    s.image(Ask, "从公共用户目录加载未签名模块(白加黑侧载,T1574.002)")
        .target("*\\users\\public\\*").targetUnsignedOnly().disableSignedAutoAllow();
    // 即时通讯进程从临时 / 下载目录加载未签名模块:群控、消息劫持插件的注入形态。
    // 不扩到所有签名程序:Java / Electron 应用会把自带的原生库解到 %TEMP% 再加载。
    for (const QString& im : exes({ "wechat.exe", "weixin.exe", "wechatappex.exe", "qq.exe", "tim.exe",
                                    "wxwork.exe", "dingtalk.exe", "feishu.exe", "lark.exe", "telegram.exe" }))
        for (const char* dir : { "\\appdata\\local\\temp\\", "\\windows\\temp\\", "\\downloads\\" })
            s.image(Ask, u("即时通讯进程 ") + imageNameOf(im) + u(" 从临时 / 下载目录加载未签名模块(群控 hook,T1055.001)"))
                .actor(im).target(u("*") + u(dir) + u("*")).targetUnsignedOnly().disableSignedAutoAllow();

    // 银狐白加黑载荷的落地名(火绒 2025-09 通报)。
    s.file(Block, "投放银狐侧载载荷 npwzwmc64.dll(白加黑,T1574.002)").target("*\\npwzwmc64.dll").unsignedOnly().hard();
    for (const QString& w : scriptHosts())
        s.file(Block, u("经 ") + imageNameOf(w) + u(" 投放银狐侧载载荷 npwzwmc64.dll(白加黑,T1574.002)"))
            .actor(w).target("*\\npwzwmc64.dll").hard();
    s.image(Block, "加载银狐侧载载荷 npwzwmc64.dll(白加黑,T1574.002)").target("*\\npwzwmc64.dll").hard();
    s.file(Ask, "投放银狐伴生文件 vdi_ipc.dat(与侧载 DLL 同目录,T1574.002)").target("*\\vdi_ipc.dat");
    s.proc(Ask, "运行 zpaqfranz 解包(银狐用它解嵌套的 ZPAQ 载荷,T1140)")
        .actor("*\\zpaqfranz*.exe").disableSignedAutoAllow();

    // 把 DLL 改成 .dat、图片、文档扩展名再加载,躲过按扩展名的扫描。正常程序不会这样加载模块。
    for (const char* d : { "\\appdata\\local\\temp\\", "\\users\\public\\" })
        for (const char* x : { ".dat", ".log", ".bin", ".txt", ".jpg", ".png", ".gif", ".bmp", ".pdf", ".doc", ".ini" })
            s.image(Block, u("加载伪装成 ") + u(x) + u(" 的未签名模块(T1574.002/T1036.008)"))
                .target(u("*") + u(d) + u("*") + u(x)).targetUnsignedOnly().hard();
}

void imClientHooks(Segment& s) {
    // 微信 / QQ 群控、消息劫持插件:具名模块直接拦,泛名(wxapi、qqbot 也是正规 SDK 的名字)只问。
    const char* named[] = {
        "*\\wxhook*.dll", "*\\wxhelper*.dll", "*\\wechatsdk*.dll", "*\\vchat*.dll", "*\\wechathook*.dll",
        "*\\wxdriver*.dll", "*\\wechatwin*hook*.dll", "*\\qqhook*.dll", "*\\wxauto*.dll", "*\\wxbot*.dll",
        "*\\wxsender*.dll", "*\\wxdump*.dll", "*\\wechathelper*.dll", "*\\wechatspy*.dll", "*\\wechatrobot*.dll",
        "*\\wechatpcapi*.dll", "*\\wechatmanager*.dll", "*\\wechatferry*.dll",
    };
    for (const char* m : named) {
        s.image(Block, u("加载即时通讯群控 / 劫持模块 ") + u(m).mid(2) + u("(T1055.001)")).target(m).hard();
        s.file(Block, u("投放即时通讯群控 / 劫持模块 ") + u(m).mid(2) + u("(T1055.001)")).target(m).unsignedOnly().hard();
    }
    for (const char* m : { "*\\*wxapi*.dll", "*\\*imhook*.dll", "*\\qqbot*.dll" })
        s.image(Ask, u("加载疑似即时通讯 hook 模块 ") + u(m).mid(2) + u("(T1055.001)")).target(m);

    // 未签名程序往聊天软件安装目录塞 DLL:下次启动就被侧载。
    for (const char* dir : { "*\\Tencent\\WeChat\\*.dll", "*\\Tencent\\Weixin\\*.dll", "*\\Tencent\\WXWork\\*.dll",
                             "*\\Tencent\\QQ\\*.dll", "*\\Tencent\\QQNT\\*.dll", "*\\DingTalk\\*.dll" })
        s.file(Block, "未签名程序向即时通讯软件安装目录植入 DLL(侧载准备,T1574.002)").target(dir).unsignedOnly().hard();
    // 聊天数据目录是同事互发文件的默认落点,存个 DLL 也常见,只问。
    for (const char* dir : { "*\\WeChat Files\\*.dll", "*\\xwechat_files\\*.dll", "*\\Tencent Files\\*.dll" })
        s.file(Ask, "未签名程序向聊天数据目录写入 DLL(群控侧载暂存点,T1574.002)").target(dir).unsignedOnly();
}

void vulnerableDrivers(Segment& s) {
    // Legitimate products may still ship these drivers, so ask rather than
    // treating installation location or a valid signature as a vulnerability fix.
    const char* inUse[] = {
        "rtcore64.sys", "rtcore32.sys", "gdrv.sys", "gdrv2.sys", "gdrv3.sys", "asrdrv10.sys", "asrdrv101.sys",
        "asrdrv102.sys", "asrdrv103.sys", "asrdrv104.sys", "asrdrv106.sys", "asio.sys", "asio2.sys",
        "asio3.sys", "winring0x64.sys", "winring0x32.sys", "winring0.sys", "dbutil_2_3.sys", "dbutil_2_2.sys",
        "dbutil_2_1.sys", "dbutildrv2.sys", "iqvw64e.sys", "iqvw64.sys", "procexp.sys", "procexp100.sys",
        "procexp150.sys", "procexp151.sys", "procexp152.sys", "kprocesshacker.sys", "kprocesshacker2.sys",
        "aswarpot.sys", "mhyprot2.sys", "mhyprot3.sys", "zamguard64.sys", "zam64.sys", "truesight.sys",
        "viragt64.sys", "echo_driver.sys", "rwdrv.sys", "inpoutx64.sys", "speedfan.sys", "phymemx64.sys",
        "corsairllaccess64.sys", "elrawdsk.sys", "gmer64.sys", "ene.sys", "glckio2.sys", "pcdsrvc_x64.pkms",
        "pcdsrvc.sys", "atillk64.sys", "nvoclock.sys", "bs_def64.sys", "nvflash.sys", "winio64.sys", "winio.sys",
        "amifldrv64.sys", "atszio.sys", "rtkio64.sys", "rtkio32.sys",
    };
    for (const char* d : inUse) {
        const QString target = u("*\\") + u(d);
        // Known vulnerable versions stay reviewable regardless of installation
        // directory and signature. A valid signature does not remove a vulnerability.
        s.image(Ask, u("加载已知可被利用的驱动 ") + u(d) + u("(BYOVD,T1068)"))
            .target(target).disableSignedAutoAllow();
    }
    // 几乎只被攻击者使用的驱动;后七个是银狐(Winos 4.0 / ValleyRAT)用来关杀软的。
    for (const char* d : { "mimidrv.sys", "capcom.sys", "piddrv64.sys", "rentdrv2.sys", "amsdk.sys", "wamsdk.sys",
                           "wsftprm.sys", "bootrepair.sys", "enportv.sys", "wnbios.sys", "wnbios64.sys" }) {
        s.image(Block, u("加载恶意 / 攻击专用驱动 ") + u(d) + u("(T1068/T1014)"))
            .target(u("*\\") + u(d)).hard();
        s.file(Block, u("投放恶意 / 攻击专用驱动 ") + u(d) + u("(BYOVD 前置,T1068)"))
            .target(u("*\\") + u(d)).exemptOs().hard();
    }

    // 驱动应由安装程序放进 System32\drivers 或 Program Files;从可写目录直接加载的都可疑。
    // CPU-Z 一类硬件工具会把签名驱动解到 %TEMP% 加载,这正是 BYOVD 的样子,只问。
    // Defender 从 ProgramData 的特征库目录加载自己的 MpKsl 驱动,签名驱动不认 ProgramData。
    for (const char* dir : { "\\appdata\\", "\\temp\\", "\\users\\public\\", "\\programdata\\", "\\downloads\\",
                             "\\$recycle.bin\\" }) {
        const QString target = u("*") + u(dir) + u("*.sys");
        s.image(Block, u("从可写目录加载验不出签名的驱动(T1068/T1014)")).target(target).targetUnsignedOnly().hard();
        if (qstrcmp(dir, "\\programdata\\") != 0)
            s.image(Ask, u("从可写目录加载签名驱动(自带易受攻击驱动,T1068)"))
                .target(target).targetSignedOnly().disableSignedAutoAllow();
        s.file(Ask, "未签名程序向可写目录投放驱动(BYOVD 前置,T1068)").target(target).unsignedOnly();
        for (const QString& w : scriptHosts())
            s.file(Ask, u("经 ") + imageNameOf(w) + u(" 向可写目录投放驱动(BYOVD 前置,T1068)"))
                .actor(w).target(target).disableSignedAutoAllow();
    }
    s.proc(Ask, "创建内核驱动服务(T1543.003)").cmd("*sc*create*type=*kernel*").disableSignedAutoAllow();
}

}

void addInjectionAndDriverRules(QVector<DefenseRule>& out) {
    Segment s(out, "注入与驱动");
    s.noDevToolAutoAllow();
    remoteThreads(s);
    memoryFindings(s);
    moduleLoads(s);
    imClientHooks(s);
    vulnerableDrivers(s);
}

}
