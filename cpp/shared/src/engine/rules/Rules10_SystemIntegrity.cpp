#include "RuleDsl.h"

namespace bulwark::engine::rules {

namespace {

void hostsAndAccessibility(Segment& s) {
    s.file(Ask, "改写 hosts 文件(未签名写入者,DNS 劫持,T1565.001)")
        .target("*\\System32\\drivers\\etc\\hosts").unsignedOnly();
    for (const QString& w : scriptHosts() + interpreterHosts())
        s.file(Ask, u("经 ") + imageNameOf(w) + u(" 改写 hosts 文件(DNS 劫持,T1565.001)"))
            .actor(w).target("*\\System32\\drivers\\etc\\hosts").disableSignedAutoAllow();

    // 系统更新由 TrustedInstaller 替换这些文件(豁免);其余写入都是在锁屏界面埋后门。
    // 命令行形态另行拦截:只有 ETW 时注册表与文件写入拦不住,得在进程创建这一步截下。
    for (const char* img : { "sethc.exe", "utilman.exe", "osk.exe", "narrator.exe", "magnify.exe",
                             "displayswitch.exe", "atbroker.exe" }) {
        const QString name = u(img);
        s.file(Block, u("替换辅助功能程序 ") + name + u("(锁屏后门,T1546.008)"))
            .target(u("*\\System32\\") + name).exemptOs().hard();
        s.reg(Block, u("为辅助功能程序 ") + name + u(" 设置映像劫持调试器(锁屏后门,T1546.008)"))
            .target(u("*\\Image File Execution Options\\") + name + u("\\Debugger")).exemptOs().hard();
        for (const char* mutation : { " add ", "new-item", "set-item", "createsubkey" })
            s.proc(Block, u("命令行为辅助功能程序 ") + name + u(" 设置映像劫持调试器(锁屏后门,T1546.008)"))
                .cmd(u("*") + u(mutation) + u("*image file execution options\\") + name + u("*debugger*")).hard();
        s.proc(Block, u("命令行为辅助功能程序 ") + name + u(" 设置映像劫持调试器(锁屏后门,T1546.008)"))
            .cmd(u("*image file execution options\\") + name + u("*setvalue*debugger*")).hard();
        // 「copy <某程序>.exe ... <辅助功能程序>」:覆盖它,或先备份(copy sethc.exe sethc.exe.bak)再覆盖,
        // 都是锁屏后门的步骤;正常运维不会动这几个文件。
        for (const char* verb : { "*copy *.exe *", "*move *.exe *", "*xcopy *.exe *" })
            s.proc(Block, u("用其它程序覆盖辅助功能程序 ") + name + u("(锁屏后门,T1546.008)"))
                .cmd(u(verb) + name + u("*")).hard();
        struct Grab { const char* before; const char* after; };
        for (const Grab& g : { Grab{ "*takeown*", "*" }, Grab{ "*icacls*", "*/grant*" },
                               Grab{ "*icacls*", "*/setowner*" } })
            s.proc(Block, u("夺取辅助功能程序 ") + name + u(" 的所有权 / 权限(替换前置,T1546.008)"))
                .cmd(u(g.before) + name + u(g.after)).hard();
    }

    // 直接写物理磁盘 = 覆写 MBR / 分区表,开机即砖;直接写卷设备 = 覆写卷引导区(VBR)。
    // 分区与制盘工具都带签名。末尾不带通配,卷里的普通文件路径不会命中。
    for (const char* disk : { "*\\physicaldrive*", "*\\device\\harddisk?\\dr?", "*\\device\\harddisk?\\partition0",
                              "\\\\.\\?:", "*\\device\\harddiskvolume?", "*\\device\\harddiskvolume??" }) {
        s.file(Block, "未签名程序直接写磁盘引导区(MBR / 分区表,T1561.002/T1542.003)").target(disk).unsignedOnly()
            .exemptRemovableTarget().hard();
        // 制作启动盘、格式化 U 盘的工具(Ventoy、Win32 Disk Imager、fat32format、TestDisk)多未签名:
        // 外接盘只问。本机硬盘上硬拦这条优先。
        s.file(Ask, "未签名程序直接写外接 / 可移动磁盘(制作启动盘也会这样做,T1561.002)").target(disk).unsignedOnly();
        for (const QString& w : scriptHosts())
            s.file(Block, u("经 ") + imageNameOf(w) + u(" 直接写磁盘引导区(T1561.002/T1542.003)"))
                .actor(w).target(disk).hard();
    }
    for (const char* p : { "*bootsect*/nt60*", "*bootsect*/nt52*", "*bootsect*/mbr*" })
        s.proc(Ask, "重写卷引导代码(系统修复也用,T1542.003)").cmd(p).disableSignedAutoAllow();
}

void systemDirectories(Segment& s) {
    s.file(Ask, "向驱动目录写入未签名写入者的文件(T1543.003)")
        .target("*\\System32\\drivers\\*.sys").unsignedOnly();
    for (const QString& w : scriptHosts())
        s.file(Ask, u("经 ") + imageNameOf(w) + u(" 向驱动目录写入驱动(T1543.003)"))
            .actor(w).target("*\\System32\\drivers\\*.sys").disableSignedAutoAllow();

    for (const char* dir : { "*\\Windows\\System32\\*", "*\\Windows\\SysWOW64\\*" })
        for (const char* ext : { ".exe", ".dll", ".sys", ".scr", ".cpl", ".ocx" }) {
            s.file(Ask, "未签名程序向系统目录写入可执行文件(T1036.005)")
                .target(u(dir) + u(ext)).unsignedOnly();
            for (const QString& w : scriptHosts())
                s.file(Ask, u("经 ") + imageNameOf(w) + u(" 向系统目录写入可执行文件(T1036.005)"))
                    .actor(w).target(u(dir) + u(ext)).disableSignedAutoAllow();
        }

    for (const char* boot : { "*\\Windows\\Boot\\*", "?:\\bootmgr", "?:\\Boot\\BCD*", "*\\EFI\\Microsoft\\Boot\\*",
                              "*\\EFI\\Boot\\*" }) {
        s.file(Block, "未签名程序改写引导文件(T1542.003)").target(boot).unsignedOnly().exemptOs().hard();
        for (const QString& w : scriptHosts())
            s.file(Block, u("经 ") + imageNameOf(w) + u(" 改写引导文件(T1542.003)"))
                .actor(w).target(boot).exemptOs().hard();
    }

    for (const char* dir : { "*\\ProgramData\\Microsoft\\Windows Defender\\*",
                             "*\\Program Files\\Windows Defender\\*" }) {
        s.file(Block, "未签名程序改写 Defender 自身文件(T1562.001)").target(dir).unsignedOnly().hard();
        s.del(Block, "未签名程序删除 Defender 自身文件(T1562.001)").target(dir).unsignedOnly().hard();
    }

    // 投递常用的罕见目录:写进可执行内容的多半是下载器。
    for (const QString& d : rareExecutionDirs())
        for (const char* ext : { ".exe", ".dll", ".scr", ".ps1", ".vbs", ".js", ".hta", ".bat" }) {
            const QString target = u("*") + d + u("*") + u(ext);
            s.file(Ask, "未签名程序向罕见目录写入可执行内容(T1105)").target(target).unsignedOnly();
            for (const QString& w : scriptHosts())
                s.file(Ask, u("经 ") + imageNameOf(w) + u(" 向罕见目录写入可执行内容(T1105)"))
                    .actor(w).target(target).disableSignedAutoAllow();
        }
}

}

void addSystemIntegrityRules(QVector<DefenseRule>& out) {
    Segment s(out, "系统完整性");
    hostsAndAccessibility(s);
    systemDirectories(s);
}

}
