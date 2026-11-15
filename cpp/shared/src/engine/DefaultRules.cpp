#include "bulwark/engine/DefaultRules.h"
#include "bulwark/engine/EngineCommon.h"
#include "rules/RuleDsl.h"
#include <QSet>
#include <QStringList>
#include <QRegularExpression>

namespace bulwark::engine {

using detail::fileNameLower;

QString DefaultRules::builtInTag() {
    return QString::fromUtf8("[\xe5\x86\x85\xe7\xbd\xae]");
}

namespace {

const QSet<QString>& devToolProcessNames() {
    static const QSet<QString> s = {
        "devenv.exe", "code.exe", "rider64.exe", "idea64.exe", "pycharm64.exe",
        "webstorm64.exe", "clion64.exe", "goland64.exe", "datagrip64.exe",
        "phpstorm64.exe", "rubymine64.exe", "android studio.exe", "notepad++.exe",
        "sublime text.exe", "atom.exe",
        // 不收 msbuild:系统自带的 .NET Framework MSBuild 是白利用宿主,VS 自带的靠路径认。
        // 不收 setup / installer / agent / runner 这类谁都能取的通用名。
        "dotnet.exe", "nuget.exe", "npm.exe", "yarn.exe", "pnpm.exe",
        "node.exe", "python.exe", "pip.exe", "cargo.exe", "gradle.exe", "mvn.exe",
        "ant.exe", "make.exe", "cmake.exe",
        "git.exe", "svn.exe", "hg.exe",
        "docker.exe", "podman.exe", "vagrant.exe",
        "jenkins.exe", "buildkite-agent.exe",
        "testhost.exe", "vstest.console.exe", "nunit-console.exe", "xunit.console.exe",
        "jest.exe", "mocha.exe",
        "choco.exe", "scoop.exe", "winget.exe",
    };
    return s;
}

const QStringList& devToolPathPatterns() {
    static const QStringList s = {
        "\\microsoft visual studio\\", "\\jetbrains\\", "\\vscode\\",
        "\\visual studio code\\", "\\android studio\\", "\\notepad++\\",
        "\\sublime text\\", "\\atom\\", "\\python\\python", "\\nodejs\\",
        // git / docker 只认安装根:任何程序都能在 %TEMP% 下建同名目录。
        // packages / env 这类通用目录名不收:虚拟环境里的 python.exe 已按文件名算。
        "\\dotnet\\", "\\program files\\git\\", "\\program files (x86)\\git\\",
        "\\appdata\\local\\programs\\git\\", "\\program files\\docker\\", "\\jenkins\\",
        "\\gradle\\", "\\maven\\", "\\nuget\\", "\\npm\\", "\\yarn\\", "\\.nuget\\", "\\.cargo\\",
        "\\.gradle\\", "\\.m2\\", "\\node_modules\\", "\\venv\\", "\\.venv\\",
    };
    return s;
}

QDateTime builtInEpochUtc() {
    static const QDateTime t =
        QDateTime::fromString(QStringLiteral("2020-01-01T00:00:00Z"), Qt::ISODate).toUTC();
    return t;
}

QUuid stableIdFor(const DefenseRule& r) {
    QString key;
    key.reserve(256);
    const QChar sep(0x1f);
    key += r.note;               key += sep;
    key += r.actorPath;          key += sep;
    key += r.actorPattern;       key += sep;
    key += r.targetPattern;      key += sep;
    key += r.commandLinePattern; key += sep;
    key += r.parentPattern;      key += sep;
    key += r.type.has_value() ? QString::number(static_cast<int>(*r.type)) : QStringLiteral("-");
    key += sep;
    key += QString::number(static_cast<int>(r.action));
    key += sep;
    key += r.requireUnsigned ? QLatin1Char('1') : QLatin1Char('0');
    key += r.requireSigned ? QLatin1Char('1') : QLatin1Char('0');
    key += r.hardOverride ? QLatin1Char('1') : QLatin1Char('0');
    key += r.exemptTrustedOsComponent ? QLatin1Char('1') : QLatin1Char('0');
    if (r.requireTargetUnsigned) key += QLatin1String("|TU");
    if (r.requireTargetSigned)   key += QLatin1String("|TS");
    if (r.disableDevToolAutoAllow) key += QLatin1String("|NDA");
    if (r.requireHostSigned)       key += QLatin1String("|HS");
    if (r.requireTargetBesideActor) key += QLatin1String("|TBA");
    if (r.exemptRemovableTarget)   key += QLatin1String("|XRT");
    if (r.disableSignedAutoAllow)  key += QLatin1String("|NSA");
    if (r.requireRegOp.has_value()) {
        key += QLatin1String("|RO");
        key += QString::number(static_cast<int>(*r.requireRegOp));
    }
    if (r.requireRegDword.has_value()) {
        key += QLatin1String("|RD");
        key += QString::number(*r.requireRegDword);
    }
    QStringList hashes(r.actorHashes.cbegin(), r.actorHashes.cend());
    hashes.sort(Qt::CaseInsensitive);
    key += sep;
    key += hashes.join(QLatin1Char(',')).toUpper();
    return QUuid::createUuidV5(QUuid{}, key.toUtf8());
}

}

namespace rules {

Segment::Segment(QVector<DefenseRule>& out, const char* category)
    : out_(out),
      prefix_(DefaultRules::builtInTag() + QLatin1Char(' ') + QString::fromUtf8(category) +
              QString::fromUtf8(" \xc2\xb7 "))
{
}

RuleRef Segment::add(EventType type, VerdictAction action, const QString& note) {
    DefenseRule r;
    r.type = type;
    r.action = action;
    r.note = prefix_ + note;
    r.disableDevToolAutoAllow = noDevToolAutoAllow_;
    out_.append(r);
    return RuleRef(out_.last());
}

}

QVector<DefenseRule> DefaultRules::build() {
    QVector<DefenseRule> list;
    list.reserve(1200);

    rules::addExecutionRules(list);
    rules::addPersistenceRules(list);
    rules::addPrivilegeEscalationRules(list);
    rules::addDefenseEvasionRules(list);
    rules::addCredentialAccessRules(list);
    rules::addLateralMovementRules(list);
    rules::addCommandAndControlRules(list);
    rules::addImpactRules(list);
    rules::addInjectionAndDriverRules(list);
    rules::addSystemIntegrityRules(list);

    const QDateTime epoch = builtInEpochUtc();
    for (DefenseRule& r : list) {
        r.createdUtc = epoch;
        r.id = stableIdFor(r);
    }
    return list;
}

QStringList DefaultRules::registryWatchFragments() {
    static const QStringList s = {
        QStringLiteral("\\Windows Defender\\Exclusions"),
        QStringLiteral("\\Policies\\Microsoft\\Windows Defender"),
        QStringLiteral("\\CurrentVersion\\Policies\\System"),
        QStringLiteral("\\CurrentVersion\\SilentProcessExit"),
        QStringLiteral("\\Windows NT\\CurrentVersion\\Windows"),
        QStringLiteral("\\Control\\Lsa"),
        QStringLiteral("\\Control\\SecurityProviders\\WDigest"),
        QStringLiteral("\\Control\\SafeBoot"),
        QStringLiteral("\\Control\\Terminal Server"),
        QStringLiteral("\\Control\\Session Manager\\AppCertDlls"),
        QStringLiteral("\\Control\\Print\\Monitors"),
        QStringLiteral("\\Control\\NetworkProvider\\Order"),
        QStringLiteral("\\Microsoft\\Netsh"),
        QStringLiteral("\\Command Processor"),
        QStringLiteral("\\Active Setup\\Installed Components"),
        QStringLiteral("\\Word\\Security"),
        QStringLiteral("\\Excel\\Security"),
        QStringLiteral("\\SystemRestore"),
        QStringLiteral("\\WindowsFirewall"),
        QStringLiteral("\\Environment"),
        QStringLiteral("\\Explorer\\User Shell Folders"),
        QStringLiteral("\\Explorer\\Shell Folders"),
        QStringLiteral("Classes\\ms-settings\\shell"),
        QStringLiteral("Classes\\exefile\\shell"),
        QStringLiteral("\\Windows\\System\\Scripts"),
        QStringLiteral("\\PowerShell\\ScriptBlockLogging"),
        QStringLiteral("\\InprocServer32"),
        QStringLiteral("\\LocalServer32"),
        QStringLiteral("\\TreatAs"),
        QStringLiteral("\\ShellIconOverlayIdentifiers"),
        QStringLiteral("\\Shell Extensions\\Approved"),
        QStringLiteral("\\Session Manager\\KnownDLLs"),
        QStringLiteral("\\W32Time\\TimeProviders"),
        QStringLiteral("\\Microsoft\\Office test\\"),
        QStringLiteral("Classes\\mscfile\\shell"),
        QStringLiteral("Classes\\Folder\\shell\\open"),
        QStringLiteral("\\Accessibility\\ATs"),
        QStringLiteral("\\Control Panel\\Desktop"),
        QStringLiteral("\\Print Processors"),
        QStringLiteral("\\Schedule\\TaskCache\\Tree"),
        QStringLiteral("\\Real-Time Protection"),
        QStringLiteral("\\Windows Defender\\Spynet"),
        QStringLiteral("\\Windows Defender\\Features"),
        QStringLiteral("\\Windows Defender\\DisableAnti"),
        QStringLiteral("\\Microsoft\\AMSI\\Providers"),
        QStringLiteral("\\Windows Script\\Settings"),
        QStringLiteral("\\Control\\WMI\\Autologger"),
        QStringLiteral("\\PowerShell\\ModuleLogging"),
        QStringLiteral("\\FirewallPolicy"),
        QStringLiteral("\\Policies\\Google\\Chrome"),
        QStringLiteral("\\Policies\\Microsoft\\Edge"),
        QStringLiteral("\\WinSock2\\Parameters"),
        QStringLiteral("\\Explorer\\Browser Helper Objects"),
        QStringLiteral("\\Authentication\\Credential Providers"),
        QStringLiteral("\\Session Manager\\BootExecute"),
        QStringLiteral("\\Windows Error Reporting\\LocalDumps"),
        QStringLiteral("\\Windows NT\\Terminal Services"),
        QStringLiteral("Classes\\Launcher.SystemSettings\\shell"),
        QStringLiteral("Classes\\AppX82a6gwre4fdg3bt635tn5ctqjf8msdd2"),
        QStringLiteral("Classes\\ms-cxh\\shell"),
        QStringLiteral("\\ScriptletURL"),
        QStringLiteral("\\Microsoft\\WAB\\DLLPath"),
        QStringLiteral("\\Services\\DNS\\Parameters"),
        QStringLiteral("\\ShellServiceObjectDelayLoad"),
        QStringLiteral("\\Explorer\\StartupApproved"),
        QStringLiteral("\\Resiliency"),
        QStringLiteral("\\PowerPoint\\Security"),
        QStringLiteral("\\Policies\\Microsoft\\Windows\\Installer"),
        QStringLiteral("\\Policies\\Microsoft\\Windows\\System"),
        QStringLiteral("\\Policies\\Microsoft\\Windows\\Safer"),
        QStringLiteral("\\Policies\\Microsoft\\Windows\\WindowsUpdate"),
        QStringLiteral("\\CurrentVersion\\Policies\\Explorer"),
        QStringLiteral("\\Control\\CI\\Config"),
        QStringLiteral("\\Control\\DeviceGuard"),
        QStringLiteral("\\Windows Defender Security Center"),
        QStringLiteral("\\Windows Defender\\UX Configuration"),
        QStringLiteral("\\Windows Defender\\Threats"),
        QStringLiteral("\\AppCompatFlags\\InstalledSDB"),
        QStringLiteral("\\AppCompatFlags\\Custom"),
        QStringLiteral("\\Excel\\Options"),
        QStringLiteral("\\Addins\\"),
        QStringLiteral("\\Outlook\\WebView"),
        QStringLiteral("\\Outlook\\Today"),
        QStringLiteral("\\SystemCertificates\\Root\\Certificates"),
        QStringLiteral("\\SAM\\SAM\\Domains\\Account\\Users"),
    };
    return s;
}

bool DefaultRules::isDevTool(const QString& processPath) {
    if (processPath.isEmpty()) return false;
    const QString lower = processPath.toLower();
    const QString fileName = fileNameLower(lower);
    if (devToolProcessNames().contains(fileName)) return true;
    for (const QString& pat : devToolPathPatterns())
        if (lower.contains(pat)) return true;
    return false;
}

bool DefaultRules::isCiCdEnvironment() {
    static const char* ciVars[] = {
        "CI", "CONTINUOUS_INTEGRATION", "GITHUB_ACTIONS", "GITLAB_CI", "JENKINS_URL",
        "BUILDKITE", "AZURE_PIPELINES", "TRAVIS", "CIRCLECI", "APPVEYOR",
        "TEAMCITY_VERSION", "TF_BUILD", "bamboo_buildKey", "CODEBUILD_BUILD_ID",
    };
    for (const char* v : ciVars)
        if (!qEnvironmentVariable(v).isEmpty()) return true;
    return false;
}

bool DefaultRules::hasLongEncodedContent(const QString& commandLine) {
    if (commandLine.isEmpty()) return false;
    static const QRegularExpression re(QStringLiteral("[A-Za-z0-9+/]{100,}={0,2}"));
    return re.match(commandLine).hasMatch();
}

bool DefaultRules::isTrustedInstaller(const QString& processPath) {
    if (processPath.isEmpty()) return false;
    const QString fileName = fileNameLower(processPath);
    static const QSet<QString> installerNames = {
        "msiexec.exe", "setup.exe", "installer.exe", "install.exe", "update.exe",
        "updater.exe", "winget.exe", "choco.exe", "scoop.exe", "npm.exe", "pip.exe",
        "dotnet.exe", "nuget.exe",
    };
    return installerNames.contains(fileName);
}

}
