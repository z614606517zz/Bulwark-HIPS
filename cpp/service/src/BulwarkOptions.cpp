#include "bulwark/service/BulwarkOptions.h"

#include <QFile>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonValue>

namespace bulwark::service {
namespace {

QJsonValue jval(const QJsonObject& o, const char* key) {
    const auto it = o.constFind(QLatin1String(key));
    if (it != o.constEnd()) return it.value();
    const QString k = QString::fromLatin1(key);
    for (auto i = o.constBegin(); i != o.constEnd(); ++i)
        if (i.key().compare(k, Qt::CaseInsensitive) == 0) return i.value();
    return QJsonValue(QJsonValue::Undefined);
}

void bindStr(const QJsonObject& o, const char* key, QString& f) {
    const QJsonValue v = jval(o, key);
    if (v.isString()) f = v.toString();
}

void bindBool(const QJsonObject& o, const char* key, bool& f) {
    const QJsonValue v = jval(o, key);
    if (v.isBool()) {
        f = v.toBool();
    } else if (v.isString()) {
        const QString s = v.toString().trimmed();
        if (s.compare(QLatin1String("true"), Qt::CaseInsensitive) == 0) f = true;
        else if (s.compare(QLatin1String("false"), Qt::CaseInsensitive) == 0) f = false;
    }
}

void bindInt(const QJsonObject& o, const char* key, int& f) {
    const QJsonValue v = jval(o, key);
    if (v.isDouble()) {
        f = v.toInt();
    } else if (v.isString()) {
        bool ok = false;
        const int n = v.toString().trimmed().toInt(&ok);
        if (ok) f = n;
    }
}

void bindStrList(const QJsonObject& o, const char* key, QStringList& f) {
    const QJsonValue v = jval(o, key);
    if (!v.isArray()) return;
    QStringList out;
    const QJsonArray a = v.toArray();
    out.reserve(a.size());
    for (const QJsonValue& e : a)
        if (e.isString()) out << e.toString();
    f = out;
}

void bindVerdictAction(const QJsonObject& o, const char* key, VerdictAction& f) {
    const QJsonValue v = jval(o, key);
    if (v.isString()) {
        const QString s = v.toString().trimmed();
        if (s.compare(QLatin1String("Allow"), Qt::CaseInsensitive) == 0) f = VerdictAction::Allow;
        else if (s.compare(QLatin1String("Block"), Qt::CaseInsensitive) == 0) f = VerdictAction::Block;
        else if (s.compare(QLatin1String("Ask"), Qt::CaseInsensitive) == 0) f = VerdictAction::Ask;
    } else if (v.isDouble()) {
        const int n = v.toInt();
        if (n >= 0 && n <= 2) f = static_cast<VerdictAction>(n);
    }
}

}

QString AiOptions::resolveApiKey() const {
    const QString env = qEnvironmentVariable(ApiKeyEnvVar).trimmed();
    if (!env.isEmpty()) return env;
    return ApiKey.trimmed();
}

QString ThreatFoxFeedOptions::resolveAuthKey() const {
    const QString env = qEnvironmentVariable(AuthKeyEnvVar).trimmed();
    if (!env.isEmpty()) return env;
    return AuthKey.trimmed();
}

}

namespace bulwark::service {
namespace {

void bindEtw(const QJsonObject& o, EtwOptions& e) {
    bindBool(o, "Enabled", e.Enabled);
    bindBool(o, "DnsClient", e.DnsClient);
    bindBool(o, "KernelNetwork", e.KernelNetwork);
    bindBool(o, "KernelRegistry", e.KernelRegistry);
    bindBool(o, "KernelFile", e.KernelFile);
    bindBool(o, "KernelImageLoad", e.KernelImageLoad);
    bindBool(o, "KernelRemoteThread", e.KernelRemoteThread);
    bindBool(o, "KernelAuditApi", e.KernelAuditApi);
    bindInt(o, "PerProcessKillPerMinute", e.PerProcessKillPerMinute);
    bindBool(o, "KernelFileWriteAttribution", e.KernelFileWriteAttribution);
    bindBool(o, "DeveloperCredentialReads", e.DeveloperCredentialReads);
    bindInt(o, "AttributionPathMax", e.AttributionPathMax);
    bindBool(o, "NetworkUntrustedOnly", e.NetworkUntrustedOnly);
    bindBool(o, "WmiActivity", e.WmiActivity);
    bindInt(o, "PerProcessNetPerMinute", e.PerProcessNetPerMinute);
    bindInt(o, "PerProcessRegPerMinute", e.PerProcessRegPerMinute);
    bindInt(o, "PerProcessFilePerMinute", e.PerProcessFilePerMinute);
    bindInt(o, "PerProcessImagePerMinute", e.PerProcessImagePerMinute);
    bindInt(o, "PerProcessThreadPerMinute", e.PerProcessThreadPerMinute);
    bindInt(o, "RemoteThreadMinTargetAgeMs", e.RemoteThreadMinTargetAgeMs);
    bindBool(o, "SuspiciousOnly", e.SuspiciousOnly);
    bindStr(o, "SessionName", e.SessionName);
    bindInt(o, "RawChannelCapacity", e.RawChannelCapacity);
    bindInt(o, "PerProcessDnsPerMinute", e.PerProcessDnsPerMinute);
    bindInt(o, "DedupWindowSeconds", e.DedupWindowSeconds);
}

void bindAi(const QJsonObject& o, AiOptions& a) {
    bindStr(o, "BaseUrl", a.BaseUrl);
    bindStr(o, "ApiKey", a.ApiKey);
    bindStr(o, "Model", a.Model);
}

void bindThreatFox(const QJsonObject& o, ThreatFoxFeedOptions& t) {
    bindStr(o, "BaseUrl", t.BaseUrl);
    bindBool(o, "Enabled", t.Enabled);
    bindStr(o, "AuthKey", t.AuthKey);
    bindInt(o, "Days", t.Days);
    bindInt(o, "MinConfidence", t.MinConfidence);
    bindInt(o, "MaxRules", t.MaxRules);
    bindInt(o, "RuleTtlDays", t.RuleTtlDays);
    bindBool(o, "GenerateHashRules", t.GenerateHashRules);
    bindBool(o, "GenerateIpRules", t.GenerateIpRules);
    bindBool(o, "GenerateDomainRules", t.GenerateDomainRules);
    bindInt(o, "InitialDelaySeconds", t.InitialDelaySeconds);
    bindInt(o, "RefreshIntervalHours", t.RefreshIntervalHours);
    bindInt(o, "QueryTimeoutSeconds", t.QueryTimeoutSeconds);
}

}

bool BulwarkOptions::loadFromFile(const QString& appsettingsPath) {
    QFile f(appsettingsPath);
    if (!f.open(QIODevice::ReadOnly)) return true;
    const QByteArray raw = f.readAll();
    f.close();
    if (raw.trimmed().isEmpty()) return true;

    QJsonParseError err{};
    const QJsonDocument doc = QJsonDocument::fromJson(raw, &err);
    if (err.error != QJsonParseError::NoError || !doc.isObject()) return false;

    const QJsonValue sec = jval(doc.object(), SectionName);
    if (!sec.isObject()) return true;
    const QJsonObject o = sec.toObject();

    bindStr(o, "EventSource", EventSource);
    bindBool(o, "KernelDriverEnabled", KernelDriverEnabled);
    bindBool(o, "TrustSignedActors", TrustSignedActors);
    bindVerdictAction(o, "DefaultAction", DefaultAction);
    bindInt(o, "PromptTimeoutSeconds", PromptTimeoutSeconds);
    bindBool(o, "PromptTimeoutBlockHighRisk", PromptTimeoutBlockHighRisk);
    bindBool(o, "ExportEcsAlerts", ExportEcsAlerts);
    bindBool(o, "EnforceUiClientSignature", EnforceUiClientSignature);
    bindStrList(o, "UiClientAllowedThumbprints", UiClientAllowedThumbprints);
    bindStrList(o, "UiClientAllowedPublishers", UiClientAllowedPublishers);
    bindBool(o, "OnlineCertRevocationCheck", OnlineCertRevocationCheck);
    bindStrList(o, "AbusedSignerThumbprints", AbusedSignerThumbprints);
    bindStrList(o, "AbusedSignerPublishers", AbusedSignerPublishers);
    bindBool(o, "SelfProtectionAlertEnabled", SelfProtectionAlertEnabled);
    bindBool(o, "SmbAuditEnabled", SmbAuditEnabled);
    bindBool(o, "BitLockerAuditEnabled", BitLockerAuditEnabled);
    bindBool(o, "WmiRepositoryWatchEnabled", WmiRepositoryWatchEnabled);
    bindBool(o, "InstallDirAclSelfCheckEnabled", InstallDirAclSelfCheckEnabled);
    bindInt(o, "EventDrainIntervalMs", EventDrainIntervalMs);
    bindInt(o, "InlineReputationBudgetMs", InlineReputationBudgetMs);
    bindStrList(o, "ProtectedPaths", ProtectedPaths);
    bindStrList(o, "FileHardBlocks", FileHardBlocks);
    bindStrList(o, "ProtectedRegistryKeys", ProtectedRegistryKeys);
    bindStrList(o, "RegistryHardBlocks", RegistryHardBlocks);
    bindStrList(o, "CommandHardBlocks", CommandHardBlocks);
    bindBool(o, "CommandHardBlockBaseline", CommandHardBlockBaseline);
    bindStrList(o, "MemoryProtectionTargets", MemoryProtectionTargets);
    bindStrList(o, "BlockedRemoteEndpoints", BlockedRemoteEndpoints);
    bindBool(o, "RansomGuardSystemBaseline", RansomGuardSystemBaseline);
    bindBool(o, "RansomGuardUserFoldersByDefault", RansomGuardUserFoldersByDefault);
    bindStrList(o, "RansomGuardDirectories", RansomGuardDirectories);
    bindStrList(o, "RansomGuardWriters", RansomGuardWriters);
    bindBool(o, "SensitiveDataGuardEnabled", SensitiveDataGuardEnabled);
    bindBool(o, "SensitiveDataGuardBuiltins", SensitiveDataGuardBuiltins);
    bindStrList(o, "SensitiveDataGuardEntries", SensitiveDataGuardEntries);
    bindStrList(o, "SensitiveDataGuardReaders", SensitiveDataGuardReaders);
    bindStrList(o, "TrustedDirectories", TrustedDirectories);
    bindBool(o, "UserModeExecBlockEnabled", UserModeExecBlockEnabled);
    bindInt(o, "UserModeExecBlockMax", UserModeExecBlockMax);
    bindInt(o, "UserModeContainmentMax", UserModeContainmentMax);
    bindInt(o, "UserModeFreezeTtlMs", UserModeFreezeTtlMs);
    bindBool(o, "UserModeFreezeOnDetect", UserModeFreezeOnDetect);
    bindBool(o, "FileDenyExecuteEnabled", FileDenyExecuteEnabled);
    bindBool(o, "FileDenyExecuteConfirmedEnabled", FileDenyExecuteConfirmedEnabled);
    bindBool(o, "RegistryInstantRollbackEnabled", RegistryInstantRollbackEnabled);
    bindBool(o, "RegistryRollbackWinlogonEnabled", RegistryRollbackWinlogonEnabled);
    bindBool(o, "RegistryDenyWriteEnabled", RegistryDenyWriteEnabled);
    bindBool(o, "ApplyLsaRunAsPpl", ApplyLsaRunAsPpl);
    bindBool(o, "ApplySelfServiceDacl", ApplySelfServiceDacl);
    bindBool(o, "HardeningUiActionsEnabled", HardeningUiActionsEnabled);
    bindBool(o, "HijackGuardEnabled", HijackGuardEnabled);
    bindBool(o, "AmsiProviderEnabled", AmsiProviderEnabled);
    bindBool(o, "UserModeNetworkBlockEnabled", UserModeNetworkBlockEnabled);
    bindInt(o, "UserModeNetworkBlockMax", UserModeNetworkBlockMax);

    const auto sub = [&](const char* key) -> QJsonObject {
        const QJsonValue v = jval(o, key);
        return v.isObject() ? v.toObject() : QJsonObject();
    };
    bindThreatFox(sub("ThreatFoxFeed"), ThreatFoxFeed);

    bindAi(sub("Ai"), Ai);
    bindEtw(sub("Etw"), Etw);
    return true;
}

}
