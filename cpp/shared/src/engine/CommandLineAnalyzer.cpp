#include "bulwark/engine/CommandLineAnalyzer.h"
#include "bulwark/engine/EngineCommon.h"
#include <QRegularExpression>
#include <QSet>
#include <algorithm>
#include <utility>

namespace bulwark::engine {

using detail::u;

namespace {

constexpr int kMaxGroups = 4;
constexpr int kMaxTokens = 12;

// 一条信号:主体限定(可空)+ 至多 4 组「任一词命中」,组与组之间要求全部满足。
struct Signal {
    const char* id;
    const char* source;
    int score;
    bool hard;
    const char* reason;
    const char* actors[6];
    const char* groups[kMaxGroups][kMaxTokens];
};

const char* const kLolbin = "LolbinAnalyzer";
const char* const kCred = "CredentialAccessAnalyzer";
const char* const kEvasion = "DefenseEvasionAnalyzer";
const char* const kRemote = "RemoteControlAnalyzer";
const char* const kInject = "InjectionAnalyzer";
const char* const kPersist = "PersistenceAnalyzer";
const char* const kGeneric = "ThreatDetector";

const Signal kSignals[] = {
    // 代理执行与下载
    { "mshta-remote", kLolbin, 50, true, "mshta 执行远程或内联脚本(T1218.005)",
      { "mshta.exe" }, { { "http:", "https:", "javascript:", "vbscript:", "about:" } } },
    { "regsvr32-scriptlet", kLolbin, 50, true, "regsvr32 加载远程 / 脚本组件(Squiblydoo,T1218.010)",
      { "regsvr32.exe" }, { { "scrobj", "/i:http", "-i:http" } } },
    { "rundll32-script", kLolbin, 50, true, "rundll32 执行脚本协议(T1218.011)",
      { "rundll32.exe" }, { { "javascript:", "vbscript:", "runhtmlapplication" } } },
    { "certutil-download", kLolbin, 45, true, "certutil 远程下载(T1105)",
      { "certutil.exe" }, { { "urlcache", "verifyctl" }, { "http" } } },
    { "certutil-decode", kLolbin, 20, false, "certutil 解码(证书运维也用,T1140)",
      { "certutil.exe" }, { { "-decode", "/decode", "-decodehex", "/decodehex" } } },
    { "bitsadmin-transfer", kLolbin, 30, false, "bitsadmin 后台下载(T1197)",
      { "bitsadmin.exe" }, { { "/transfer", "/addfile" }, { "http" } } },
    { "wmic-xsl-remote", kLolbin, 45, true, "wmic 加载远程 XSL 样式表(T1220)",
      { "wmic.exe" }, { { "/format:", "-format:" }, { "http" } } },
    { "wmic-process-create", kLolbin, 20, false, "wmic 创建进程(T1047)",
      { "wmic.exe" }, { { "process" }, { "call" }, { "create" } } },
    { "devtool-dropdir", kLolbin, 25, false, "构建 / 安装工具加载投递目录中的项目或程序集(T1127)",
      { "msbuild.exe", "installutil.exe", "regasm.exe", "regsvcs.exe" },
      { { "\\appdata\\local\\temp\\", "\\users\\public\\", "\\windows\\temp\\", "\\downloads\\",
          "\\$recycle.bin\\", "\\perflogs\\" } } },
    { "cmstp-inf", kLolbin, 25, false, "cmstp 静默安装 INF(T1218.003)",
      { "cmstp.exe" }, { { ".inf" }, { "/s", "/ni", "/au" } } },
    { "msdt-follina", kLolbin, 60, true, "msdt 诊断协议注入(Follina,CVE-2022-30190)",
      { "msdt.exe" }, { { "it_browseforfile", "ms-msdt:" } } },
    { "hh-remote", kLolbin, 45, true, "hh 打开远程帮助文件(T1218.001)", { "hh.exe" }, { { "http" } } },
    { "msiexec-remote-quiet", kLolbin, 25, false, "msiexec 静默安装远程包(T1218.007)",
      { "msiexec.exe" }, { { "http" }, { "/q", "-q" } } },
    { "odbcconf-regsvr", kLolbin, 25, false, "odbcconf 注册 DLL(T1218.008)", { "odbcconf.exe" }, { { "regsvr" } } },
    { "pcalua-launch", kLolbin, 15, false, "pcalua 代理启动程序(T1202)", { "pcalua.exe" }, { { "-a " } } },
    { "mavinject", kInject, 60, true, "mavinject 向运行中进程注入 DLL(T1218.013)",
      { "mavinject.exe", "mavinject32.exe", "mavinject64.exe" }, { { "/injectrunning" } } },

    // PowerShell
    // 编码命令与隐藏窗口要看参数值,不在表里,见 scan()。
    { "ps-bypass", kGeneric, 10, false, "绕过执行策略(T1059.001)",
      { "powershell.exe", "pwsh.exe" },
      { { "-ep bypass", "-executionpolicy bypass", "-exec bypass", "-executionpolicy unrestricted" } } },
    { "ps-downgrade", kEvasion, 15, false, "PowerShell 降级到 2.0(绕过 AMSI,T1562.010)",
      { "powershell.exe" }, { { "-version 2", "-v 2 " } } },
    { "download", kGeneric, 20, false, "远程下载(下载本身不定性,需与执行互证,T1105)", {},
      { { "downloadstring", "downloadfile", "downloaddata", "invoke-webrequest", "iwr ", "invoke-restmethod",
          "irm ", "start-bitstransfer", "net.webclient", "system.net.http.httpclient" } } },
    { "dynamic-exec", kGeneric, 15, false, "动态执行字符串(IEX,T1059.001)", {},
      { { "invoke-expression", "iex ", "iex(", "|iex", "| iex", "[scriptblock]::create", ".invokescript(" } } },
    { "reflection-base64", kGeneric, 50, true, "内存加载 Base64 编码的程序集(无文件载荷,T1620)", {},
      { { "reflection.assembly", "assembly]::load" }, { "frombase64string" } } },
    { "base64-decode", kGeneric, 15, false, "Base64 解码(资源还原与载荷解码均可能,T1140)", {},
      { { "frombase64string" } } },
    { "shellcode-runner", kInject, 55, true, "申请可执行内存并起线程(Shellcode 装载器,T1055)", {},
      { { "virtualalloc", "ntallocatevirtualmemory" },
        { "createthread", "queueuserapc", "callwindowproc", "enumdesktopwindows", "createremotethread" } } },
    { "amsi-blinding", kEvasion, 60, true, "AMSI 致盲代码(T1562.001)", {},
      { { "amsiinitfailed", "amsiutils", "amsiscanbuffer", "amsicontext", "amsiopensession" } } },
    { "etw-patch", kEvasion, 50, true, "改写 ETW 写事件函数(致盲遥测,T1562.006)", {},
      { { "etweventwrite", "ntteventwrite" }, { "virtualprotect", "writeprocessmemory", "marshal]::copy" } } },
    { "offensive-framework", kGeneric, 60, true, "公开攻击框架载荷(T1059.001)", {},
      { { "invoke-shellcode", "invoke-reflectivepeinjection", "invoke-dllinjection", "invoke-psinject",
          "invoke-tokenmanipulation", "powersploit", "invoke-powershelltcp", "powercat", "invoke-smbexec",
          "invoke-thehash", "invoke-bloodhound" } } },
    { "reverse-shell", kRemote, 60, true, "反弹 Shell(T1059/T1095)", {},
      { { "net.sockets.tcpclient", "system.net.sockets.tcpclient" }, { "getstream" } } },

    // 凭据访问
    { "comsvcs-minidump", kCred, 70, true, "经 comsvcs.dll 转储进程内存(LSASS 凭据窃取,T1003.001)", {},
      { { "comsvcs" }, { "minidump", "#24", "#+24" } } },
    { "mimikatz", kCred, 70, true, "Mimikatz 凭据窃取指令(T1003)", {},
      { { "sekurlsa::", "lsadump::", "kerberos::", "privilege::debug", "invoke-mimikatz", "dpapi::",
          "crypto::capi", "token::elevate", "misc::memssp" } } },
    { "lsass-dump", kCred, 60, true, "转储 LSASS 进程内存(T1003.001)", {},
      { { "-ma ", "/ma ", "-mm ", "minidumpwritedump" }, { "lsass" } } },
    { "hive-export", kCred, 60, true, "导出 SAM / SECURITY 注册表配置单元(T1003.002)", {},
      { { "save", "export" }, { "hklm\\sam", "hklm\\security", "hkey_local_machine\\sam",
                                "hkey_local_machine\\security" } } },
    { "shadow-credential-copy", kCred, 60, true, "从卷影副本复制凭据库(T1003.002/T1003.003)", {},
      { { "harddiskvolumeshadowcopy" }, { "\\config\\sam", "\\config\\security", "ntds.dit" } } },
    { "ntds-ifm", kCred, 40, false, "导出域数据库(T1003.003)", { "ntdsutil.exe" }, { { "ifm" } } },
    { "kerberoast", kCred, 50, true, "请求 Kerberos 服务票据(Kerberoasting,T1558.003)", {},
      { { "kerberosrequestorsecuritytoken" } } },
    { "vault-list", kCred, 20, false, "列出凭据管理器中的凭据(T1555.004)", { "vaultcmd.exe" }, { { "/listcreds" } } },
    { "password-hunt", kCred, 15, false, "在文件中搜索口令(T1552.001)", { "findstr.exe" },
      { { "password", "passwd", "pwd" }, { "/s", "/si" } } },

    // 防御规避
    { "defender-disable", kEvasion, 40, true, "关闭 Defender 防护项(T1562.001)", {},
      { { "set-mppreference" }, { "disablerealtimemonitoring", "disablebehaviormonitoring", "disableioavprotection",
                                  "disablescriptscanning", "disableblockatfirstseen", "disableintrusionpreventionsystem" },
        { "true" } } },
    { "defender-exclusion", kEvasion, 25, false, "添加 Defender 排除项(开发与构建也常用,T1562.001)", {},
      { { "add-mppreference" }, { "exclusionpath", "exclusionprocess", "exclusionextension" } } },
    { "log-clear", kEvasion, 30, false, "清除事件日志(T1070.001)", {},
      { { "wevtutil" }, { " cl ", " clear-log " } } },
    { "log-clear-ps", kEvasion, 30, false, "清除事件日志(T1070.001)", {},
      { { "clear-eventlog", "remove-eventlog", "globalsession.clearlog" } } },
    { "security-log-clear", kEvasion, 45, true, "清除安全事件日志(T1070.001)", {},
      { { "wevtutil" }, { " cl security", " clear-log security" } } },
    { "audit-disable", kEvasion, 30, false, "清空或关闭审计策略(T1562.002)", { "auditpol.exe" },
      { { "/clear", "/remove", "/success:disable" } } },
    { "firewall-off", kEvasion, 30, false, "关闭 Windows 防火墙(T1562.004)", {},
      { { "netsh" }, { "state off", "opmode disable" } } },
    { "firewall-off-ps", kEvasion, 30, false, "关闭 Windows 防火墙(T1562.004)", {},
      { { "set-netfirewallprofile" }, { "-enabled false", "-enabled $false", "-enabled 0" } } },
    { "driver-signing-off", kEvasion, 30, false, "关闭驱动签名校验(T1553.006)", { "bcdedit.exe" },
      { { "testsigning", "nointegritychecks", "disable_integrity_checks" } } },
    { "usn-delete", kEvasion, 30, false, "删除 USN 变更日志(T1070)", { "fsutil.exe" }, { { "deletejournal" } } },
    { "timestomp", kEvasion, 15, false, "改写文件时间戳(T1070.006)", {},
      { { ".lastwritetime =", ".lastwritetime=", ".creationtime =", ".creationtime=", "setlastwritetime(",
          "setcreationtime(", "timestomp" } } },
    { "token-manipulation", kEvasion, 30, false, "操纵进程令牌(复制 / 模拟令牌、启用调试特权,T1134)", {},
      { { "impersonateloggedonuser", "duplicatetokenex", "sedebugprivilege", "setthreadtoken",
          "createprocesswithtokenw", "createprocessasuser", "invoke-tokenmanipulation" } } },
    { "security-kill", kEvasion, 45, true, "停止 / 结束安全软件(T1562.001)", {},
      { { "taskkill", "stop-process", "net stop", "net1 stop", "sc stop", "sc config", "stop-service",
          "process where" },
        { "msmpeng", "windefend", "wdnissvc", "mssense", "securityhealth", "360tray", "360sd", "360rp",
          "zhudongfangyu", "hipsdaemon", "kxescore" } } },

    // 破坏与勒索前置
    // 管理员会用 /oldest /quiet 清理单个旧快照;一次删光(/all、WMI 枚举删除)才是勒索形态。
    { "shadow-delete-all", kGeneric, 80, true, "删除全部卷影副本(勒索前置,T1490)", {},
      { { "vssadmin" }, { "delete" }, { "shadows" }, { "/all", "-all" } } },
    // 不带 where 子句的 wmic shadowcopy delete 一次删光全部快照。
    { "shadow-delete-wmic", kGeneric, 80, true, "经 WMI 删除卷影副本(勒索前置,T1490)", {},
      { { "wmic" }, { "shadowcopy delete", "shadowcopy call delete" } } },
    { "shadow-delete-wmi", kGeneric, 80, true, "经 WMI 删除卷影副本(勒索前置,T1490)", {},
      { { "win32_shadowcopy" }, { ".delete()", "remove-ciminstance", "remove-wmiobject" } } },
    { "shadow-delete", kGeneric, 30, false, "删除卷影副本(T1490)", {},
      { { "vssadmin" }, { "delete" }, { "shadows" } } },
    { "backup-catalog-delete", kGeneric, 60, true, "删除系统备份目录(勒索前置,T1490)", {},
      { { "wbadmin" }, { "delete catalog" } } },
    { "recovery-off", kGeneric, 35, false, "关闭 Windows 恢复环境(VDI 优化也用,T1490)", {},
      { { "bcdedit" }, { "recoveryenabled no", "recoveryenabled false", "ignoreallfailures" } } },
    { "free-space-wipe", kGeneric, 20, false, "擦除磁盘空闲空间(T1485)", { "cipher.exe" }, { { "/w:" } } },

    // 持久化
    { "task-suspicious", kPersist, 25, false, "计划任务指向临时目录 / 脚本宿主 / 编码命令(T1053.005)",
      { "schtasks.exe" },
      { { "/create" }, { "\\appdata\\", "\\temp\\", "\\users\\public\\", "mshta", "wscript", "cscript",
                         "regsvr32", "rundll32", "-enc", "frombase64string", "http" } } },
    { "service-suspicious", kPersist, 30, false, "服务映像指向临时目录或命令解释器(T1543.003)",
      { "sc.exe" },
      { { "create", "config" }, { "binpath" }, { "\\appdata\\", "\\temp\\", "\\users\\public\\", "cmd /c",
                                                 "cmd.exe /c", "powershell", "mshta", "rundll32" } } },
    { "wmi-consumer", kPersist, 50, true, "创建 WMI 事件消费者(T1546.003)", {},
      { { "commandlineeventconsumer", "activescripteventconsumer" } } },
    { "bits-notify", kPersist, 45, true, "BITS 任务完成后执行命令(T1197)", { "bitsadmin.exe" },
      { { "setnotifycmdline" } } },
    { "run-key-dropdir", kPersist, 25, false, "开机自启动项指向临时 / 公共目录(T1547.001)", { "reg.exe" },
      { { "add" }, { "\\currentversion\\run" }, { "\\appdata\\local\\temp\\", "\\users\\public\\", "\\windows\\temp\\" } } },

    // 横向移动与远控
    { "impacket-output", kRemote, 60, true, "Impacket 远程执行回显痕迹(T1047/T1021.002)", {},
      { { "\\\\127.0.0.1\\admin$\\__", "\\\\127.0.0.1\\c$\\__output", "1> \\\\127.0.0.1\\" } } },
    { "remote-exec", kRemote, 15, false, "在远程主机执行命令(运维也用,T1021)", {},
      { { "/node:", "-computername", "winrs -r:", "psexec" } } },
    { "netcat-exec", kRemote, 50, true, "netcat 绑定 / 反弹 Shell(T1095)",
      { "nc.exe", "nc64.exe", "ncat.exe", "netcat.exe" }, { { " -e ", "--exec", "--sh-exec" } } },
    { "port-proxy", kRemote, 20, false, "添加端口转发规则(T1090.001)", { "netsh.exe" },
      { { "portproxy" }, { "add" } } },
    { "reverse-forward", kRemote, 15, false, "建立反向端口转发(T1572)", { "ssh.exe", "plink.exe" }, { { " -r " } } },
    { "anydesk-password", kRemote, 30, false, "命令行设置远控无人值守密码(T1219)", {},
      { { "anydesk" }, { "--set-password" } } },
};

const char* tokenGroupHit(const char* const* group, const QString& text) {
    for (int k = 0; k < kMaxTokens && group[k] != nullptr; ++k)
        if (text.contains(QLatin1String(group[k])))
            return group[k];
    return nullptr;
}

bool actorAllowed(const Signal& sig, const QString& actorName) {
    if (sig.actors[0] == nullptr)
        return true;
    for (const char* a : sig.actors) {
        if (a == nullptr) break;
        if (actorName == QLatin1String(a))
            return true;
    }
    return false;
}

bool actorMentioned(const Signal& sig, const QString& lowerText) {
    if (sig.actors[0] == nullptr)
        return true;
    for (const char* a : sig.actors) {
        if (a == nullptr) break;
        QString stem = QLatin1String(a);
        stem.chop(4);
        if (lowerText.contains(stem))
            return true;
    }
    return false;
}

// 同族信号里更强的一条命中后,较弱的那条不再重复计分。
const std::pair<const char*, const char*> kSupersedes[] = {
    { "shadow-delete-all", "shadow-delete" },
    { "shadow-delete-wmic", "shadow-delete-wmi" },
    { "reflection-base64", "base64-decode" },
    { "security-log-clear", "log-clear" },
};

template <typename Allowed>
QVector<CommandLineAnalyzer::Hit> runSignals(const QString& lowerText, Allowed allowed) {
    QVector<CommandLineAnalyzer::Hit> hits;
    if (lowerText.isEmpty())
        return hits;
    for (const Signal& sig : kSignals) {
        if (!allowed(sig))
            continue;
        const char* first = nullptr;
        bool ok = true;
        for (int g = 0; ok && g < kMaxGroups && sig.groups[g][0] != nullptr; ++g) {
            const char* t = tokenGroupHit(sig.groups[g], lowerText);
            ok = t != nullptr;
            if (g == 0) first = t;
        }
        if (!ok)
            continue;
        CommandLineAnalyzer::Hit h;
        h.id = sig.id;
        h.source = QLatin1String(sig.source);
        h.score = sig.score;
        h.hard = sig.hard;
        h.reason = u(sig.reason);
        h.token = first ? QString::fromLatin1(first) : QString();
        hits.append(h);
    }
    for (const auto& [strong, weak] : kSupersedes) {
        const bool hasStrong = std::any_of(hits.cbegin(), hits.cend(),
                                           [s = strong](const CommandLineAnalyzer::Hit& h) {
                                               return qstrcmp(h.id, s) == 0;
                                           });
        if (hasStrong)
            hits.erase(std::remove_if(hits.begin(), hits.end(),
                                      [w = weak](const CommandLineAnalyzer::Hit& h) {
                                          return qstrcmp(h.id, w) == 0;
                                      }),
                       hits.end());
    }
    return hits;
}

}

bool CommandLineAnalyzer::isScriptHost(const QString& actorName) {
    static const QSet<QString> hosts = {
        QStringLiteral("powershell.exe"), QStringLiteral("pwsh.exe"), QStringLiteral("powershell_ise.exe"),
        QStringLiteral("cmd.exe"), QStringLiteral("wscript.exe"), QStringLiteral("cscript.exe"),
        QStringLiteral("mshta.exe"),
    };
    return hosts.contains(actorName);
}

QVector<CommandLineAnalyzer::Hit> CommandLineAnalyzer::scan(const QString& lowerText, const QString& actorName) {
    QVector<Hit> hits =
        runSignals(lowerText, [&actorName](const Signal& sig) { return actorAllowed(sig, actorName); });
    const auto add = [&hits](const char* id, const char* source, int score, bool hard, const char* reason) {
        Hit h;
        h.id = id;
        h.source = QLatin1String(source);
        h.score = score;
        h.hard = hard;
        h.reason = u(reason);
        hits.append(h);
    };
    const bool powershell = actorName == QLatin1String("powershell.exe") || actorName == QLatin1String("pwsh.exe");
    if (powershell && hasEncodedCommandArgument(lowerText))
        add("ps-encoded", kGeneric, 25, false, "PowerShell 编码命令(-EncodedCommand,T1027)");
    if (powershell && hasHiddenWindowFlag(lowerText))
        add("ps-hidden", kGeneric, 20, false, "隐藏窗口运行(T1564.003)");
    if (createsHiddenAccount(lowerText))
        add("hidden-account", kPersist, 50, true, "创建以 $ 结尾的隐藏账户(T1136.001)");
    return hits;
}

bool CommandLineAnalyzer::hasHiddenWindowFlag(const QString& lowerText) {
    static const QRegularExpression re(QStringLiteral(
        R"((?:^|[\s"'])[-/]w(?:i(?:n(?:d(?:o(?:w(?:s(?:t(?:y(?:l(?:e)?)?)?)?)?)?)?)?)?)?(?:\s+|:)['"]?)"
        R"(h(?:i(?:d(?:d(?:e(?:n)?)?)?)?)?(?:['"\s]|$))"));
    return re.match(lowerText).hasMatch();
}

bool CommandLineAnalyzer::hasEncodedCommandArgument(const QString& lowerText) {
    static const QRegularExpression re(QStringLiteral(
        R"((?:^|[\s"'])[-/]e(?:c|n(?:c(?:o(?:d(?:e(?:d(?:c(?:o(?:m(?:m(?:a(?:n(?:d)?)?)?)?)?)?)?)?)?)?)?)?)?)"
        R"((?:\s+|:)['"]?([a-z0-9+/=]{8,}))"));
    static const QSet<QString> kEncodingNames = {
        QStringLiteral("bigendianunicode"), QStringLiteral("bigendianutf32"), QStringLiteral("utf8nobom"),
        QStringLiteral("utf8bom"), QStringLiteral("unicode"), QStringLiteral("default"), QStringLiteral("unknown"),
    };
    QRegularExpressionMatchIterator it = re.globalMatch(lowerText);
    while (it.hasNext()) {
        const QString payload = it.next().captured(1);
        if (!kEncodingNames.contains(payload))
            return true;
    }
    return false;
}

bool CommandLineAnalyzer::hasIpLiteralUrl(const QString& lowerText) {
    static const QRegularExpression re(
        QStringLiteral(R"((?:https?|ftp)://(\d{1,3})\.(\d{1,3})\.\d{1,3}\.\d{1,3}(?:[:/'"\s]|$))"));
    QRegularExpressionMatchIterator it = re.globalMatch(lowerText);
    while (it.hasNext()) {
        const QRegularExpressionMatch m = it.next();
        const int a = m.captured(1).toInt();
        const int b = m.captured(2).toInt();
        const bool privateRange = a == 10 || a == 127 || (a == 172 && b >= 16 && b <= 31)
                                  || (a == 192 && b == 168) || (a == 169 && b == 254);
        if (!privateRange)
            return true;
    }
    return false;
}

bool CommandLineAnalyzer::fetchesRemote(const QString& lowerText) {
    static const char* kFetch[] = {
        "downloadfile", "downloadstring", "downloaddata", "webclient", "invoke-webrequest", "invoke-restmethod",
        "start-bitstransfer", "xmlhttp", "winhttprequest", "urlcache", "bitsadmin", "iwr ", "irm ", "curl ",
        "wget ", "http://", "https://", "ftp://",
    };
    for (const char* t : kFetch)
        if (lowerText.contains(QLatin1String(t)))
            return true;
    return false;
}

bool CommandLineAnalyzer::createsHiddenAccount(const QString& lowerText) {
    if (!lowerText.contains(QLatin1String("/add")))
        return false;
    static const QRegularExpression re(
        QStringLiteral(R"((?:^|[\s"'\\/&|])net1?(?:\.exe)?['"]?\s+user\s+['"]?([^\s'"]+)['"]?\s)"));
    QRegularExpressionMatchIterator it = re.globalMatch(lowerText);
    while (it.hasNext())
        if (it.next().captured(1).endsWith(QLatin1Char('$')))
            return true;
    return false;
}

QVector<CommandLineAnalyzer::Hit> CommandLineAnalyzer::scanScript(const QString& lowerText) {
    return runSignals(lowerText, [&lowerText](const Signal& sig) { return actorMentioned(sig, lowerText); });
}

int CommandLineAnalyzer::obfuscationScore(const QString& rawText, QStringList* reasons) {
    if (rawText.size() < 20)
        return 0;
    int score = 0;
    const auto add = [&](int delta, const char* why) {
        score += delta;
        if (reasons) reasons->append(u(why));
    };

    int carets = 0, backticks = 0;
    for (int i = 1; i + 1 < rawText.size(); ++i) {
        const QChar c = rawText.at(i);
        if (c == QLatin1Char('^') && rawText.at(i - 1).isLetter() && rawText.at(i + 1).isLetter())
            ++carets;
        else if (c == QLatin1Char('`') && rawText.at(i - 1).isLetter() && rawText.at(i + 1).isLetter())
            ++backticks;
    }
    if (carets >= 4)
        add(carets >= 12 ? 25 : 15, "词内插入 ^ 转义打散关键字(T1027)");
    if (backticks >= 3)
        add(backticks >= 10 ? 25 : 15, "词内插入反引号打散关键字(T1027)");

    static const QRegularExpression concatRe(
        QStringLiteral(R"(['"][a-z]{1,8}['"]\s*\+\s*['"][a-z]{1,8}['"])"),
        QRegularExpression::CaseInsensitiveOption);
    if (rawText.count(concatRe) >= 2)
        add(15, "拼接字符串片段还原关键字(T1027)");
    static const QRegularExpression charRe(QStringLiteral(R"(\[char\]\s*\d{2,3})"),
                                           QRegularExpression::CaseInsensitiveOption);
    if (rawText.count(charRe) >= 5)
        add(20, "大量 [char] 字符码拼接(T1027)");
    static const QRegularExpression envSliceRe(QStringLiteral(R"(%[a-z_]+:~-?\d+,-?\d+%)"),
                                               QRegularExpression::CaseInsensitiveOption);
    if (rawText.count(envSliceRe) >= 3)
        add(20, "环境变量截取拼出命令(T1027)");
    static const QRegularExpression b64Re(QStringLiteral(R"([A-Za-z0-9+/]{200,}={0,2})"));
    if (b64Re.match(rawText).hasMatch())
        add(15, "命令行内嵌超长 Base64 数据(T1027)");
    if (rawText.size() > 4000)
        add(10, "命令行超长(T1027)");

    return qMin(score, 35);
}

}
