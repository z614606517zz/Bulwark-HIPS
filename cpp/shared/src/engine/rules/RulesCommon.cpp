#include "RuleDsl.h"

namespace bulwark::engine::rules {

QString exe(const char* imageName) {
    return QStringLiteral("*\\") + QString::fromUtf8(imageName);
}

QStringList exes(std::initializer_list<const char*> imageNames) {
    QStringList out;
    out.reserve(static_cast<qsizetype>(imageNames.size()));
    for (const char* n : imageNames)
        out << exe(n);
    return out;
}

QString imageNameOf(const QString& pattern) {
    const qsizetype slash = pattern.lastIndexOf(QLatin1Char('\\'));
    return slash >= 0 ? pattern.mid(slash + 1) : pattern;
}

const QStringList& scriptHosts() {
    static const QStringList s = exes({
        "powershell.exe", "pwsh.exe", "powershell_ise.exe", "cmd.exe",
        "wscript.exe", "cscript.exe", "mshta.exe",
    });
    return s;
}

const QStringList& proxyExecutionBinaries() {
    static const QStringList s = exes({
        "rundll32.exe", "regsvr32.exe", "msbuild.exe", "installutil.exe", "regasm.exe",
        "regsvcs.exe", "cmstp.exe", "certutil.exe", "bitsadmin.exe", "wmic.exe",
        "odbcconf.exe", "msxsl.exe", "ieexec.exe", "hh.exe", "infdefaultinstall.exe",
        "msiexec.exe", "pcalua.exe", "mavinject.exe", "msdt.exe", "presentationhost.exe",
    });
    return s;
}

const QStringList& officeApps() {
    static const QStringList s = exes({
        "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "msaccess.exe",
        "mspub.exe", "onenote.exe", "visio.exe", "eqnedt32.exe", "wps.exe", "et.exe",
        "wpp.exe",
    });
    return s;
}

const QStringList& documentReaders() {
    static const QStringList s = exes({
        "acrord32.exe", "acrobat.exe", "foxitreader.exe", "foxitpdfreader.exe",
        "foxitphantompdf.exe",
    });
    return s;
}

const QStringList& browsers() {
    static const QStringList s = exes({
        "chrome.exe", "msedge.exe", "firefox.exe", "iexplore.exe", "brave.exe",
        "opera.exe", "vivaldi.exe", "360se.exe", "360chrome.exe", "qqbrowser.exe",
        "sogouexplorer.exe",
    });
    return s;
}

const QStringList& interpreterHosts() {
    static const QStringList s = exes({
        "python.exe", "pythonw.exe", "node.exe", "java.exe", "javaw.exe",
        "autoit3.exe", "autoit3_x64.exe", "autohotkey.exe", "autohotkey64.exe",
        "autohotkey32.exe", "autohotkeyu64.exe", "autohotkeyu32.exe",
        "perl.exe", "ruby.exe", "rubyw.exe", "php.exe", "deno.exe", "bun.exe",
    });
    return s;
}

const QStringList& scriptedWriters() {
    static const QStringList s = exes({
        "reg.exe", "regedit.exe", "powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe",
        "cscript.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe", "wmic.exe",
    }) + interpreterHosts();
    return s;
}

const QStringList& rareExecutionDirs() {
    static const QStringList s = {
        QStringLiteral("\\users\\public\\"), QStringLiteral("\\$recycle.bin\\"),
        QStringLiteral("\\perflogs\\"), QStringLiteral("\\windows\\fonts\\"),
        QStringLiteral("\\windows\\debug\\"), QStringLiteral("\\windows\\tasks\\"),
        QStringLiteral("\\windows\\tracing\\"), QStringLiteral("\\windows\\help\\"),
        QStringLiteral("\\windows\\media\\"), QStringLiteral("\\windows\\addins\\"),
        QStringLiteral("\\system volume information\\"),
    };
    return s;
}

const QStringList& commonDropDirs() {
    static const QStringList s = {
        QStringLiteral("\\appdata\\local\\temp\\"), QStringLiteral("\\windows\\temp\\"),
        QStringLiteral("\\downloads\\"), QStringLiteral("\\users\\public\\"),
        QStringLiteral("\\$recycle.bin\\"), QStringLiteral("\\perflogs\\"),
    };
    return s;
}

const QStringList& securityProductImages() {
    static const QStringList s = {
        QStringLiteral("msmpeng.exe"), QStringLiteral("nissrv.exe"),
        QStringLiteral("mssense.exe"), QStringLiteral("securityhealthservice.exe"),
        QStringLiteral("360tray.exe"), QStringLiteral("360sd.exe"), QStringLiteral("360rp.exe"),
        QStringLiteral("zhudongfangyu.exe"), QStringLiteral("hipsdaemon.exe"),
        QStringLiteral("hipstray.exe"), QStringLiteral("wsctrl.exe"), QStringLiteral("usysdiag.exe"),
        QStringLiteral("qqpcrtp.exe"), QStringLiteral("qqpctray.exe"), QStringLiteral("kxetray.exe"),
        QStringLiteral("kxescore.exe"), QStringLiteral("kwsprotect64.exe"),
        QStringLiteral("avp.exe"), QStringLiteral("avpui.exe"), QStringLiteral("ekrn.exe"),
        QStringLiteral("egui.exe"), QStringLiteral("bdagent.exe"), QStringLiteral("vsserv.exe"),
        QStringLiteral("mcshield.exe"), QStringLiteral("mfemms.exe"), QStringLiteral("ccsvchst.exe"),
        QStringLiteral("savservice.exe"), QStringLiteral("sophoshealth.exe"),
        QStringLiteral("csfalconservice.exe"), QStringLiteral("sentinelagent.exe"),
        QStringLiteral("cylancesvc.exe"), QStringLiteral("xagt.exe"),
        QStringLiteral("avastsvc.exe"), QStringLiteral("avgsvc.exe"),
        QStringLiteral("mbamservice.exe"), QStringLiteral("ntrtscan.exe"),
        QStringLiteral("tmbmsrv.exe"), QStringLiteral("wrsa.exe"),
    };
    return s;
}

const QStringList& securityServiceNames() {
    static const QStringList s = {
        QStringLiteral("windefend"), QStringLiteral("wdnissvc"), QStringLiteral("sense"),
        QStringLiteral("wdboot"), QStringLiteral("wdfilter"), QStringLiteral("securityhealthservice"),
        QStringLiteral("wscsvc"), QStringLiteral("sysmon"), QStringLiteral("sysmondrv"),
        QStringLiteral("zhudongfangyu"), QStringLiteral("360rp"), QStringLiteral("hipsdaemon"),
        QStringLiteral("ekrn"), QStringLiteral("mcshield"), QStringLiteral("csagent"),
        QStringLiteral("sentinelagent"), QStringLiteral("mbamservice"),
    };
    return s;
}

}
