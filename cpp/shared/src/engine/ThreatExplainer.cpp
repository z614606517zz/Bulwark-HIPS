#include "bulwark/engine/ThreatExplainer.h"
#include "bulwark/engine/EngineCommon.h"
#include "bulwark/engine/ThreatDetector.h"
#include "bulwark/models/SecurityEvent.h"
#include <QStringList>
#include <iterator>

namespace bulwark::engine {
using detail::u;
using detail::fileNameLower;

using Tone = ThreatExplanation::Tone;

namespace {

// techniques 里存的是 AttackCatalog::describe() 的结果,形如 "T1003.001 LSASS 内存转储",
// 所以按前缀判断即可同时命中父技术与子技术。
bool hasTechnique(const SecurityEvent& e, const char* prefix) {
    const QLatin1String p(prefix);
    for (const QString& t : e.techniques)
        if (t.startsWith(p, Qt::CaseInsensitive))
            return true;
    return false;
}

bool inSet(const QString& nameLower, const char* const* names, int n) {
    for (int i = 0; i < n; ++i)
        if (nameLower == QLatin1String(names[i]))
            return true;
    return false;
}

bool isBrowser(const QString& nameLower) {
    static const char* k[] = { "chrome.exe", "msedge.exe", "firefox.exe", "iexplore.exe",
                               "opera.exe", "brave.exe", "360se.exe", "360chrome.exe",
                               "sogouexplorer.exe", "qqbrowser.exe", "ucbrowser.exe" };
    return inSet(nameLower, k, int(std::size(k)));
}

bool isOffice(const QString& nameLower) {
    static const char* k[] = { "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe",
                               "msaccess.exe", "visio.exe", "wps.exe", "et.exe", "wpp.exe" };
    return inSet(nameLower, k, int(std::size(k)));
}

bool isMessenger(const QString& nameLower) {
    static const char* k[] = { "wechat.exe", "weixin.exe", "qq.exe", "tim.exe",
                               "dingtalk.exe", "telegram.exe", "whatsapp.exe", "feishu.exe" };
    return inSet(nameLower, k, int(std::size(k)));
}

bool isArchiver(const QString& nameLower) {
    static const char* k[] = { "7z.exe", "7zg.exe", "7zfm.exe", "winrar.exe", "rar.exe",
                               "winzip32.exe", "bandizip.exe" };
    return inSet(nameLower, k, int(std::size(k)));
}

// 「这类行为是什么」。按决定性程度排序,取第一条命中的:弹窗只有两三行篇幅,只放最能帮用户下决心的那一条。
// 身份问题排在最前:签名健康是最主要的放行依据(TrustSignedActors),它不可信时别的判断都失去了地基。
QString pickMeaning(const SecurityEvent& e) {
    if (e.signatureTampered)
        return u("这个文件带着数字签名,但内容在签名之后被改动过 —— 正常发布的软件不会这样。"
                 "常见手法是拿一个有正规签名的程序当外壳,把恶意代码塞进去,好让「有签名就放行」"
                 "这条判断失效。");

    if (e.certRevoked)
        return u("给这个文件签名的证书已被颁发机构吊销,通常意味着签名私钥被盗。"
                 "攻击者拿偷来的证书签名,目的就是骗过「有签名就放行」这条判断 —— "
                 "签名本身看起来是完整的,但它不再能证明来源。");

    if (e.signedAfterCertExpiry)
        return u("签名时间晚于证书的有效期,正常的签发流程不会出现这种情况,"
                 "常见于盗用已过期的旧证书、或伪造签名时间戳。");

    // 安装管控弹窗拿到的往往是 Allow 裁决:它不是检出了威胁,而是改动系统之前确认一次,
    // 不能落到末尾的兜底文案被说成「行为组合达到了提示阈值」。带硬指标的安装包不走这条,那时该说清手法。
    if (e.isInstaller && !e.hasThreatIndicator)
        return u("安装程序本来就要做很多看起来敏感的事:写入 Program Files、注册服务、"
                 "添加开机启动项。本产品并不拦这些,只是在动手之前让你确认一次 —— "
                 "因为「把木马伪装成安装包」正是最常见的一种投递方式。");

    if (e.yaraLevel == SecurityEvent::YaraMalicious && !e.yaraRule.isEmpty())
        return u("这个程序文件的内容命中了已验证的恶意软件家族规则「") + e.yaraRule
             + u("」。这类规则描述的是某个已知家族在文件里留下的固定特征,"
                 "并且事先在正常软件上核对过不会误中 —— 它说明的是「这个文件是什么」,"
                 "而不只是「它此刻做了什么」。");

    if (e.ransomwareContainmentRequired || hasTechnique(e, "T1486"))
        return u("这个程序正在短时间内大量改写你的文档,这是勒索软件加密文件时的典型形态。"
                 "勒索的破坏是不可逆的:一旦文件被加密,没有密钥就恢复不了,所以这里不能等看清楚再说。");

    if (hasTechnique(e, "T1490"))
        return u("这个操作在删除系统的卷影副本 / 备份,也就是在拆掉「文件被改坏之后还能还原」"
                 "的那条退路。勒索软件在开始加密之前几乎都会先做这一步 —— 正常的软件没有理由删你的备份。");

    if (hasTechnique(e, "T1003"))
        return u("这个操作在读取系统保存登录凭据的地方(账号密码、登录票据)。"
                 "拿到这些就能冒充你登录本机和同一网络里的其它机器,"
                 "所以它通常是攻击从「一台机器」扩散到「整个网络」的那一步。");

    if (hasTechnique(e, "T1555"))
        return u("这个操作在读取浏览器或系统凭据库里保存的密码。"
                 "这类数据一旦被取走,改本机密码也挡不住 —— 攻击者已经拿到的是明文。");

    if (e.memoryInjection || hasTechnique(e, "T1055"))
        return u("这个程序正在把自己的代码塞进另一个正在运行的程序里执行。"
                 "这样做之后,后续的恶意动作会以那个正常程序的身份发生 —— "
                 "在任务管理器里看到的是一个合法进程,实际在跑的是别人的代码。");

    if (!e.tamperedModulePath.isEmpty() || !e.sideloadedUnsignedModulePath.isEmpty())
        return u("一个有签名的正常程序,正在加载同目录下一个来源不明的模块(DLL)。"
                 "这是「白加黑」:外壳是正规软件、签名也查得过,真正干事的是被放在它旁边的那个文件。"
                 "单看进程名和签名完全看不出问题。");

    if (!e.selfCopyTargetPath.isEmpty())
        return u("这个程序正在把自己复制到系统里长期存放程序的目录。"
                 "正常软件靠安装程序落地,不会自己复制自己 —— 这是投放器(dropper)为了"
                 "在你重启之后还能活下来而做的准备动作。");

    if (hasTechnique(e, "T1105"))
        return u("这个操作正在从网上取回一段内容并直接执行,中间不落盘或只短暂落盘。"
                 "真正要跑什么由对面的服务器当时给什么决定,所以现在看到的命令行"
                 "并不能说明它最终会做什么。");

    if (hasTechnique(e, "T1547") || hasTechnique(e, "T1543")
        || hasTechnique(e, "T1546") || hasTechnique(e, "T1053"))
        return u("这个操作在给自己安排「开机 / 登录后自动运行」。"
                 "本身不是破坏动作,但它决定了这个程序能不能在你重启之后继续存在 —— "
                 "恶意程序落地后的第一件事通常就是这个。");

    if (hasTechnique(e, "T1562"))
        return u("这个操作在关闭或削弱系统自带的防护(防火墙、Defender、日志、更新)。"
                 "正常软件不需要动这些;攻击者动它们是为了让后面的动作不被发现、也不被拦。");

    if (e.scriptContainmentRequired || e.type == EventType::ScriptScan)
        return u("这是一段正在被执行的脚本,内容带有恶意脚本的典型特征。"
                 "脚本不需要安装、不留可执行文件,查杀时也没有固定的文件特征可比对,"
                 "因此常被用来做第一步投递。");

    if (hasTechnique(e, "T1027") || hasTechnique(e, "T1140")) {
        QString s = u("这条命令被刻意写成了人读不出来的形式(转义拆字、字符串拼接、Base64 编码)。"
                      "正常软件没有理由隐藏自己要执行什么 —— 这么写的目的通常就是绕过按命令行"
                      "内容匹配的检测。");
        if (e.commandDeobfuscationReported)
            s += u("本产品已经把它还原,见上方「还原后的命令行」。");
        return s;
    }

    if (hasTechnique(e, "T1218") || hasTechnique(e, "T1127") || hasTechnique(e, "T1202"))
        return u("这是在借系统自带的、本身有微软签名的工具去执行外部代码"
                 "(业内叫 LOLBin)。借刀的好处是:跑起来的进程是正规系统组件,"
                 "白名单和签名检查都挡不住,真正的恶意内容在参数里。");

    if (hasTechnique(e, "T1036") || hasTechnique(e, "T1564"))
        return u("这个文件在把自己伪装成别的东西 —— 系统组件的名字、文档的图标或扩展名、"
                 "或者藏在不会被直接看到的位置。伪装的唯一目的就是让你或防护软件不把它当成程序。");

    if (hasTechnique(e, "T1059.001"))
        return u("这是在用 PowerShell 执行一段命令。PowerShell 是系统自带的管理工具,"
                 "本身正常,但它能直接从内存里跑代码、不需要落下可执行文件,"
                 "因此也是最常被借用的一条执行通道。");

    if (hasTechnique(e, "T1071") || e.type == EventType::NetworkConnect
        || e.type == EventType::DnsQuery)
        return u("这个程序正在以可疑的形态对外联网(固定周期的心跳、随机生成的域名、"
                 "或异常的外发流量)。这类通信的用途通常是等待远端下发指令,或把本机数据传出去。");

    // 既没有具体手法、也没凑到可疑线:这一档不得说成「检出了威胁」。Allow 裁决常走到这里
    // (如未签名 + Temp + 首见,风险分 40),说法必须和裁决一致,不能劝用户去拦本产品判定无害的程序。
    if (!e.hasThreatIndicator && e.riskScore < ThreatDetector::Suspicious)
        return u("目前没有发现可以定性的恶意行为特征。这条提示属于「先问一声」"
                 "而不是「检出了威胁」:具体依据见上方「为什么提示」。");

    if (e.yaraLevel == SecurityEvent::YaraSuspicious && !e.yaraRule.isEmpty())
        return u("这个程序文件命中了特征规则「") + e.yaraRule
             + u("」。这条规则没有在正常软件上核对过,单凭它不能定性;"
                 "是它和其他可疑迹象叠在一起,才让这次操作需要你确认。");

    // 兜不住具体手法时,按事件类型给一个不过度解读的说法。宁可笼统,也不编。
    switch (e.type) {
        case EventType::RegistryWrite:
            return u("这个操作在改写系统的关键注册表位置。这些位置决定开机运行什么、"
                     "以及部分安全设置,因此既是正常软件会用的地方,也是恶意程序优先争取的地方。");
        case EventType::FileWrite:
        case EventType::FileDelete:
            return u("这个操作在改写或删除受保护的位置里的文件。"
                     "之所以盯这些位置,是因为它们能影响系统启动与安全设置。");
        case EventType::RemoteThread:
            return u("这个程序正在另一个进程里创建线程 —— 也就是让别的程序替它执行代码。"
                     "少数调试和兼容性场景会这么做,其余情况下这是注入。");
        case EventType::ImageLoad:
            return u("一个进程正在加载来源可疑的模块(DLL)。"
                     "模块一旦加载进去,它的代码就以宿主进程的身份运行。");
        case EventType::SelfProtect:
            return u("这个操作在试图停止或删除本防护软件自身的组件。"
                     "正常的软件不会这么做;恶意程序这么做是为了先把防护关掉再动手。");
        default:
            return u("这个程序的行为组合达到了提示阈值 —— 单独每一条都不足以定性,"
                     "但它们同时出现在一个未经确认的程序身上。具体依据见上方「为什么提示」。");
    }
}

// 「怎么判断这是不是你自己的操作」:用户分不清技术细节,但分得清自己刚才有没有在装东西。
// 只用事件上已有的结构化字段(originKind / parentPath / isInstaller / isFirstSeen),不猜;
// 推不出来就返回空,界面上那一行不显示。
QString pickRecognize(const SecurityEvent& e) {
    QStringList cues;

    if (e.isInstaller) {
        // 开头不写「这看起来是一次软件安装」:弹窗标题已经是「是否允许安装「X」?」。
        cues << u("如果这个安装包是你自己下载并双击的,这些改动属于正常;"
                  "如果你没在装任何东西,就不该出现这个动作。");
    } else {
        switch (e.originKind) {
            case ProcessOriginKind::LogonAutostart:
                cues << u("它是你登录后自动启动的,不是你刚才的某个操作触发的 —— "
                          "也就是说,它早前已经被装进了开机自启动项。");
                break;
            case ProcessOriginKind::SystemBoot:
                cues << u("它是开机时自动启动的,与你刚才的操作无关。");
                break;
            case ProcessOriginKind::ScheduledTask:
                cues << u("它是由一个计划任务按时触发的,不是你刚才的操作。"
                          "计划任务是常见的隐蔽持久化方式,因为它不出现在启动项列表里。");
                break;
            case ProcessOriginKind::Service:
                cues << u("它以系统服务的身份在后台运行,不需要你登录就会启动。");
                break;
            case ProcessOriginKind::WmiProvider:
                cues << u("它是通过 WMI 订阅触发的。这是一种很隐蔽的持久化方式:"
                          "既不在启动项里,也不在计划任务里。");
                break;
            case ProcessOriginKind::Interactive:
            case ProcessOriginKind::Unknown:
                break;
        }

        const QString parent = fileNameLower(e.parentPath);
        if (!parent.isEmpty()) {
            if (isOffice(parent))
                cues << u("它是由 ") + parent + u(" 启动的。正常的文档不会启动程序 —— "
                          "这种链条通常来自文档里的宏,或是针对该软件的漏洞利用。");
            else if (isBrowser(parent))
                cues << u("它是由浏览器 ") + parent + u(" 启动的,通常意味着它刚从网页上"
                          "下载下来就被运行了。请回想这个文件是从哪个页面来的。");
            else if (isMessenger(parent))
                cues << u("它是由聊天软件 ") + parent + u(" 启动的,也就是说这个文件很可能"
                          "是别人发给你的。");
            else if (isArchiver(parent))
                cues << u("它是从压缩包里被直接运行的(父进程是 ") + parent + u(")。"
                          "「解压后立刻双击」是最常见的一种中招方式。");
        }
    }

    if (e.isFirstSeen)
        cues << u("这个程序在本机是首次出现。");

    // 中文句子之间不留空格:每句自带句号,拼接时再加半角空格会在句号后留出一道豁口。
    return cues.join(QString());
}

Tone pickTone(const SecurityEvent& e) {
    // 语气只跟证据强度挂钩,不跟手法种类挂钩:同一手法可能有硬指标,也可能只是软信号。
    // 分档直接用引擎的阈值(ThreatDetector::Suspicious),否则语气会和界面上的风险分档、裁决本身对不上。
    if (e.hasThreatIndicator)
        return Tone::Danger;
    if (e.isInstaller)
        return Tone::Info;   // 安装管控是「确认」,不是「检出」
    if (e.riskScore >= ThreatDetector::Suspicious)
        return Tone::Caution;
    return Tone::Info;
}

QString pickAdvice(Tone tone, const SecurityEvent& e) {
    QStringList s;

    // 弹窗只给几十秒,建议必须一眼看完:动作放第一句。
    // 不复述「证据够不够硬」这类元信息,界面眉标和「为什么提示」里已经有了。
    switch (tone) {
        case Tone::Danger:
            // 这一档不加「拿不准」之类的对冲。证据已经够硬,含糊只会让人犹豫;
            // 对冲属于下面那一档。
            s << u("建议拦截。除非你明确知道这是自己正在做的事,否则不要放行。"
                   "拦错了可以在「信任」页加回来,而放行造成的改动收不回。");
            break;
        case Tone::Caution:
            // 没有硬证据,它确实可能只是个行为激进的正常程序 —— 这句校准必须留着,
            // 否则这一档读起来和上面一样重。
            s << u("没有拿到可以单独定性的硬证据,所以它也可能只是个行为激进的正常程序。"
                   "如果这不是你主动触发的,建议先拦:拦错了可以在「信任」页加回来。");
            break;
        case Tone::Info:
            // 这一档不得出现「建议拦截」:它对应的往往是 Allow 裁决,劝用户拦截
            // 等于让本产品和自己的判断打架。
            s << (e.isInstaller ? u("如果这次安装是你自己发起的,可以放行。")
                                : u("如果这是你自己的操作,放行即可。"));
            break;
    }

    if (!e.actorSigned)
        s << u("该程序没有有效数字签名,无法确认来源。");

    return s.join(QString());
}

}

ThreatExplanation ThreatExplainer::explain(const SecurityEvent& e) {
    ThreatExplanation x;
    x.tone = pickTone(e);
    x.meaning = pickMeaning(e);
    x.recognize = pickRecognize(e);
    x.advice = pickAdvice(x.tone, e);
    return x;
}

}
