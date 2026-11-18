#include "RuleDsl.h"

namespace bulwark::engine::rules {

namespace {

void recoveryDestruction(Segment& s) {
    // 按命令行匹配:勒索常由释放器 / cmd /c 一并下发,事件主体不一定是 vssadmin 本身。
    // 定时清理脚本用 /oldest /quiet 删单个旧快照是正常运维,/quiet 本身不说明问题;一次删光(/all)才是勒索形态。
    for (const char* p : { "*vssadmin*delete*shadows*/all*", "*vssadmin*delete*shadows*-all*" })
        s.proc(Block, "删除全部卷影副本(勒索前置,T1490)").cmd(p).hard();
    s.proc(Ask, "删除卷影副本(T1490)").actor("*\\vssadmin.exe").cmd("*delete*shadows*").disableSignedAutoAllow();
    s.proc(Ask, "缩小卷影存储空间(可借此清空卷影,T1490)")
        .actor("*\\vssadmin.exe").cmd("*resize*shadowstorage*").disableSignedAutoAllow();
    for (const char* p : { "*wmic*shadowcopy delete*", "*wmic*shadowcopy call delete*" })
        s.proc(Block, "wmic 删除卷影副本(T1490)").cmd(p).hard();
    for (const char* p : { "*win32_shadowcopy*.delete()*", "*win32_shadowcopy*remove-ciminstance*",
                           "*win32_shadowcopy*remove-wmiobject*" })
        s.proc(Block, "PowerShell 删除卷影副本(T1490)").cmd(p).hard();
    s.proc(Ask, "diskshadow 执行脚本(可删除卷影,T1490)").actor("*\\diskshadow.exe").cmd("*/s*").disableSignedAutoAllow();

    s.proc(Block, "删除系统备份目录(T1490)").cmd("*wbadmin*delete*catalog*").hard();
    for (const char* p : { "*wbadmin*delete*systemstatebackup*-keepversions:0*", "*wbadmin*delete*backup*-keepversions:0*" })
        s.proc(Block, "删除全部 Windows 备份(T1490)").cmd(p).hard();
    // 按保留份数清理旧备份是正常运维。
    s.proc(Ask, "删除 Windows 备份(T1490)").actor("*\\wbadmin.exe").cmd("*delete*").disableSignedAutoAllow();

    // VDI 优化脚本会正当执行这两条;内核命令行基线在执行前另有拦截。
    for (const char* p : { "*recoveryenabled*no*", "*bootstatuspolicy*ignoreallfailures*" })
        s.proc(Ask, "关闭 Windows 恢复环境(勒索前置,T1490)").actor("*\\bcdedit.exe").cmd(p).disableSignedAutoAllow();
    s.proc(Ask, "关闭 Windows 恢复环境(T1490)").actor("*\\reagentc.exe").cmd("*/disable*").disableSignedAutoAllow();

    s.proc(Ask, "擦除磁盘空闲空间(T1485)").actor("*\\cipher.exe").cmd("*/w:*").disableSignedAutoAllow();
}

void dataDestruction(Segment& s) {
    // Native disk encryption is legitimate administration and also an impact
    // primitive. Confirm state-changing operations; status/queries remain quiet.
    for (const char* p : { "* -on *", "* -on", "* -lock *", "*-protectors*-delete*",
                           "*-protectors*-disable*", "* -changepassword*", "* -forcerecovery*" })
        s.proc(Ask, "开启磁盘加密或改变恢复保护器(BitLocker 滥用,T1486)")
            .actor("*\\manage-bde.exe").cmd(p).disableSignedAutoAllow();
    for (const QString& host : exes({ "powershell.exe", "pwsh.exe", "powershell_ise.exe" }))
        for (const char* p : { "*enable-bitlocker*", "*remove-bitlockerkeyprotector*",
                               "*add-bitlockerkeyprotector*", "*lock-bitlocker*" })
            s.proc(Ask, "开启磁盘加密或改变恢复保护器(BitLocker 滥用,T1486)")
                .actor(host).cmd(p).disableSignedAutoAllow();
    for (const char* wiper : { "caddywiper", "hermeticwiper", "isaacwiper", "whispergate", "doublezero",
                               "industroyer", "azovwiper" }) {
        s.proc(Block, u("运行擦除器 ") + u(wiper) + u("(T1485/T1561)"))
            .actor(u("*\\") + u(wiper) + u("*.exe")).unsignedOnly().hard();
        s.proc(Block, u("命令行带擦除器特征 ") + u(wiper) + u("(T1485/T1561)"))
            .cmd(u("*") + u(wiper) + u("*")).unsignedOnly().hard();
    }
    s.proc(Block, "把文件内容清零(fsutil file setzerodata,T1485)").cmd("*fsutil*file*setzerodata*").hard();
    for (const char* p : { "*diskpart*/s *", "*format*/fs:*", "*clear-disk*", "*format-volume*" })
        s.proc(Ask, "清空分区 / 格式化卷(T1561/T1485)").cmd(p).disableSignedAutoAllow();

    // 备份软件自己(签名)整理备份集不在此列;未签名程序删备份、改虚拟机磁盘与数据库文件,
    // 是勒索掐断恢复手段、直接加密业务数据的形态。
    for (const char* x : { ".vbk", ".vib", ".vbm", ".tib", ".tibx", ".wbcat", ".bkf", ".gho", ".v2i", ".vrb" })
        s.del(Ask, u("未签名程序删除备份文件 *") + u(x) + u("(T1490)"))
            .target(u("*") + u(x)).unsignedOnly();
    for (const char* x : { ".vmdk", ".vhdx", ".vdi", ".mdf", ".ldf", ".ndf", ".pst", ".ost", ".edb" })
        s.file(Ask, u("未签名程序改写虚拟机磁盘 / 数据库文件 *") + u(x) + u("(T1486)"))
            .target(u("*") + u(x)).unsignedOnly();
}

void serviceSabotage(Segment& s) {
    // 勒索加密前会停掉卷影与备份服务;数据库服务开发者也常手动停,不在此列。
    const QStringList forms = { u("*net stop "), u("*net1 stop "), u("*net.exe stop "), u("*sc stop "),
                                u("*sc.exe stop "), u("*sc config "), u("*sc.exe config "), u("*stop-service ") };
    for (const QString& form : forms) {
        // vss 太短,会撞上 vsserv(Bitdefender)、VSStandardCollectorService 等,要求名字到此为止。
        for (const char* tail : { "vss", "vss *", "vss&*", "vss\"*", "\"vss\"*", "-name vss*" })
            s.proc(Ask, "停止 / 禁用卷影复制服务 VSS(T1489)").cmd(form + u(tail)).disableSignedAutoAllow();
        for (const char* svc : { "swprv", "wbengine", "veeam", "backupexec", "acronis", "sqlwriter" })
            s.proc(Ask, u("停止 / 禁用备份服务 ") + u(svc) + u("(T1489)"))
                .cmd(form + u("*") + u(svc) + u("*")).disableSignedAutoAllow();
    }
}

}

void addImpactRules(QVector<DefenseRule>& out) {
    Segment s(out, "破坏与勒索");
    s.add(EventType::DiskProtectionChange, Ask, u("BitLocker API 改变加密或密钥保护器（变更后观测，T1486）"))
        .disableSignedAutoAllow().disableDevToolAutoAllow();
    s.add(EventType::RemoteShareAccess, Ask, u("共享访问出现敏感读取或批量写入请求（访问检查告警，T1021.002）"))
        .disableSignedAutoAllow().disableDevToolAutoAllow();
    recoveryDestruction(s);
    dataDestruction(s);
    serviceSabotage(s);
}

}
