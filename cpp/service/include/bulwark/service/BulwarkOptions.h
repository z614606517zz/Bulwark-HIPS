#pragma once
#include "bulwark/models/Enums.h"

#include <QString>
#include <QStringList>

namespace bulwark::service {

using bulwark::VerdictAction;

struct EtwOptions {
    bool Enabled = true;
    bool DnsClient = true;
    bool WmiActivity = true;
    bool KernelNetwork = true;
    bool KernelRegistry = true;
    bool KernelFile = true;
    bool KernelFileWriteAttribution = true;
    bool DeveloperCredentialReads = true;
    int AttributionPathMax = 256;
    bool KernelImageLoad = true;
    bool KernelRemoteThread = true;
    // Microsoft-Windows-Kernel-Audit-API-Calls 的 TerminateProcess:「结束进程」类规则唯一的事件来源。
    bool KernelAuditApi = true;
    int PerProcessKillPerMinute = 120;
    // Legacy noise controls are retained for configuration compatibility. Event
    // collection must not discard signed actors or non-DGA domains before rules.
    bool NetworkUntrustedOnly = false;
    int PerProcessNetPerMinute = 600;
    int PerProcessRegPerMinute = 240;
    int PerProcessFilePerMinute = 240;
    int PerProcessImagePerMinute = 120;
    int PerProcessThreadPerMinute = 60;
    int RemoteThreadMinTargetAgeMs = 500;
    bool SuspiciousOnly = false;
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
    bool SmbAuditEnabled = true;
    bool BitLockerAuditEnabled = true;
    bool WmiRepositoryWatchEnabled = true;

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
