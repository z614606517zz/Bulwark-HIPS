#pragma once
#include "bulwark/models/Enums.h"

#include <QString>
#include <QStringList>

namespace bulwark::service {

using bulwark::VerdictAction;

struct EtwOptions {
    bool Enabled = true;
    bool DnsClient = true;
    bool KernelNetwork = true;
    bool KernelRegistry = true;
    bool KernelFile = true;
    bool KernelFileWriteAttribution = true;
    int AttributionPathMax = 256;
    bool KernelImageLoad = true;
    bool KernelRemoteThread = true;
    // Microsoft-Windows-Kernel-Audit-API-Calls 的 TerminateProcess:「结束进程」类规则唯一的事件来源。
    bool KernelAuditApi = true;
    int PerProcessKillPerMinute = 120;
    bool NetworkUntrustedOnly = true;
    int PerProcessNetPerMinute = 600;
    int PerProcessRegPerMinute = 240;
    int PerProcessFilePerMinute = 240;
    int PerProcessImagePerMinute = 120;
    int PerProcessThreadPerMinute = 60;
    int RemoteThreadMinTargetAgeMs = 500;
    bool SuspiciousOnly = true;
    QString SessionName = QStringLiteral("Bulwark-ETW");
    int RawChannelCapacity = 8192;
    int PerProcessDnsPerMinute = 120;
    int DedupWindowSeconds = 60;
};

struct AiOptions {
    static constexpr const char* ApiKeyEnvVar = "BULWARK_AI_APIKEY";
    QString BaseUrl;   // OpenAI-compatible base (must include /v1)
    QString ApiKey;
    QString Model;
    QString resolveApiKey() const;
};

}

namespace bulwark::service {

struct ThreatFoxFeedOptions {
    static constexpr const char* AuthKeyEnvVar = "BULWARK_ABUSECH_AUTHKEY";
    static QString ruleNoteTag() { return QString::fromUtf8("[\xE6\x83\x85\xE6\x8A\xA5-ThreatFox]"); }
    QString BaseUrl = QStringLiteral("https://threatfox-api.abuse.ch/api/v1/");
    bool Enabled = false;
    QString AuthKey;
    int Days = 3;
    int MinConfidence = 75;
    int MaxRules = 500;
    int RuleTtlDays = 7;
    bool GenerateHashRules = true;
    bool GenerateIpRules = true;
    bool GenerateDomainRules = false;
    int InitialDelaySeconds = 60;
    int RefreshIntervalHours = 12;
    int QueryTimeoutSeconds = 30;
    QString resolveAuthKey() const;
};

// YARA Forge 规则包的自动下载与编译。Enabled 是部署期总开关(关掉则完全不联网);
// AutoUpdate 只是初值,用户在界面上改过后以 %ProgramData%\Bulwark\yara\state.json 为准。
struct YaraRulesOptions {
    bool Enabled = true;
    bool AutoUpdate = true;
    QString Package = QStringLiteral("core");
    QString ReleaseApiUrl = QStringLiteral("https://api.github.com/repos/YARAHQ/yara-forge/releases/latest");
    QString DownloadUrlPrefix = QStringLiteral("https://github.com/YARAHQ/yara-forge/releases/download/");
    int InitialDelaySeconds = 90;
    int CheckIntervalHours = 24;
    int DownloadTimeoutSeconds = 180;
    int MaxDownloadMB = 32;
    int CompileTimeoutSeconds = 900;
    int CompilerMemoryLimitMB = 3072;

    // 进程启动扫描:只扫进程创建事件的主体程序文件,结果按 SHA-256 缓存。
    bool ScanProcesses = true;
    int ScanMaxFileMB = 64;
    int ScanTimeoutSeconds = 10;
    int ScannerMemoryLimitMB = 1024;
    // 在干净样本上验证过的家族规则(规则名,结尾 * 表示前缀):命中判恶意,结束进程并隔离。
    // 其余规则命中一律判可疑,只作弱信号。默认空:没验证过的规则不会让本产品结束或隔离任何程序。
    QStringList MaliciousRules;
    // 误报规则,命中不计(写法同上)。
    QStringList IgnoredRules;
};

struct BulwarkOptions {
    static constexpr const char* SectionName = "Bulwark";

    QString EventSource = QStringLiteral("Wmi");
    bool KernelDriverEnabled = true;
    bool TrustSignedActors = true;
    VerdictAction DefaultAction = VerdictAction::Allow;
    int PromptTimeoutSeconds = 30;
    bool PromptTimeoutBlockHighRisk = true;
    bool ExportEcsAlerts = false;
    bool EnforceUiClientSignature = false;
    QStringList UiClientAllowedThumbprints;
    QStringList UiClientAllowedPublishers;
    bool OnlineCertRevocationCheck = true;

    QStringList AbusedSignerThumbprints;
    QStringList AbusedSignerPublishers;

    bool SelfProtectionAlertEnabled = true;

    bool InstallDirAclSelfCheckEnabled = true;

    int EventDrainIntervalMs = 20;
    int InlineReputationBudgetMs = 800;

    QStringList ProtectedPaths;
    QStringList FileHardBlocks;
    QStringList ProtectedRegistryKeys;
    QStringList RegistryHardBlocks;      // kernel-deny writes (must be precise!)
    QStringList CommandHardBlocks;
    bool CommandHardBlockBaseline = true;
    QStringList MemoryProtectionTargets;
    QStringList BlockedRemoteEndpoints;

    bool RansomGuardSystemBaseline = true;
    bool RansomGuardUserFoldersByDefault = true;
    QStringList RansomGuardDirectories;
    QStringList RansomGuardWriters;

    // 窃密防护:只许指定程序打开浏览器 / 通讯 / 钱包等敏感数据。
    bool SensitiveDataGuardEnabled = true;
    bool SensitiveDataGuardBuiltins = true;       // 内置浏览器 / 通讯 / 钱包条目
    QStringList SensitiveDataGuardEntries;        // 自定义条目 "数据片段|读者;读者"
    QStringList SensitiveDataGuardReaders;        // 全局读者(对所有条目放行)

    ThreatFoxFeedOptions ThreatFoxFeed;
    YaraRulesOptions YaraRules;

    QStringList TrustedDirectories;

    bool UserModeExecBlockEnabled = true;
    int UserModeExecBlockMax = 256;

    int UserModeContainmentMax = 64;
    int UserModeFreezeTtlMs = 120000;
    bool UserModeFreezeOnDetect = true;

    bool FileDenyExecuteEnabled = false;
    bool FileDenyExecuteConfirmedEnabled = true;
    bool RegistryInstantRollbackEnabled = true;
    bool RegistryRollbackWinlogonEnabled = true;
    bool RegistryDenyWriteEnabled = false;

    bool ApplyLsaRunAsPpl = false;
    bool ApplySelfServiceDacl = false;

    bool HardeningUiActionsEnabled = true;
    bool HijackGuardEnabled = true;

    bool AmsiProviderEnabled = true;

    bool UserModeNetworkBlockEnabled = true;
    int UserModeNetworkBlockMax = 256;

    AiOptions Ai;
    EtwOptions Etw;

    bool loadFromFile(const QString& appsettingsPath);
};

}
