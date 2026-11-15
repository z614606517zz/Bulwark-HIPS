#include "bulwark/models/RuntimeSettings.h"
#include "bulwark/json/JsonSupport.h"

namespace bulwark {
using namespace bulwark::json;

QJsonObject RuntimeSettings::toJson() const {
    QJsonObject o;
    o["protectionEnabled"] = protectionEnabled;
    o["protectionFollowsUi"] = protectionFollowsUi;

    o["processProtection"] = processProtection;
    o["fileProtection"] = fileProtection;
    o["registryProtection"] = registryProtection;
    o["selfProtection"] = selfProtection;
    o["networkProtection"] = networkProtection;

    o["memoryProtectionEnabled"] = memoryProtectionEnabled;

    o["trustSignedActors"] = trustSignedActors;
    o["defaultBlock"] = defaultBlock;
    o["silentMode"] = silentMode;
    o["installControlEnabled"] = installControlEnabled;

    o["promptTimeoutSeconds"] = promptTimeoutSeconds;
    o["promptTimeoutBlockHighRisk"] = promptTimeoutBlockHighRisk;

    o["aiBaseUrl"] = aiBaseUrl;
    o["aiApiKey"] = aiApiKey;
    o["aiModel"] = aiModel;

    o["kernelDriverEnabled"] = kernelDriverEnabled;
    o["kernelDriverEnabledAuthoritative"] = kernelDriverEnabledAuthoritative;
    o["userModeBehaviorMonitor"] = userModeBehaviorMonitor;
    o["ransomwareCanaryEnabled"] = ransomwareCanaryEnabled;
    o["behaviorBaselineEnabled"] = behaviorBaselineEnabled;

    o["ransomGuardEnabled"] = ransomGuardEnabled;
    o["ransomGuardDirs"] = strListToJson(ransomGuardDirs);

    o["aiCreditGuardEnabled"] = aiCreditGuardEnabled;
    o["aiMonthlyCreditBudget"] = aiMonthlyCreditBudget;

    o["eventSource"] = eventSource;
    o["kernelConnected"] = kernelConnected;
    o["kernelStatus"] = kernelStatus;

    o["quarantineOnBlock"] = quarantineOnBlock;
    return o;
}

RuntimeSettings RuntimeSettings::fromJson(const QJsonObject& o) {
    RuntimeSettings s;
    s.protectionEnabled = getBool(o, "protectionEnabled", s.protectionEnabled);
    s.protectionFollowsUi = getBool(o, "protectionFollowsUi", s.protectionFollowsUi);

    s.processProtection = getBool(o, "processProtection", s.processProtection);
    s.fileProtection = getBool(o, "fileProtection", s.fileProtection);
    s.registryProtection = getBool(o, "registryProtection", s.registryProtection);
    s.selfProtection = getBool(o, "selfProtection", s.selfProtection);
    s.networkProtection = getBool(o, "networkProtection", s.networkProtection);

    s.memoryProtectionEnabled = getBool(o, "memoryProtectionEnabled", s.memoryProtectionEnabled);

    s.trustSignedActors = getBool(o, "trustSignedActors", s.trustSignedActors);
    s.defaultBlock = getBool(o, "defaultBlock", s.defaultBlock);
    s.silentMode = getBool(o, "silentMode", s.silentMode);
    s.installControlEnabled = getBool(o, "installControlEnabled", s.installControlEnabled);

    s.promptTimeoutSeconds = getInt(o, "promptTimeoutSeconds", s.promptTimeoutSeconds);
    s.promptTimeoutBlockHighRisk = getBool(o, "promptTimeoutBlockHighRisk", s.promptTimeoutBlockHighRisk);

    if (o.contains(QLatin1String("aiBaseUrl"))) s.aiBaseUrl = getStr(o, "aiBaseUrl");
    if (o.contains(QLatin1String("aiApiKey"))) s.aiApiKey = getStr(o, "aiApiKey");
    if (o.contains(QLatin1String("aiModel"))) s.aiModel = getStr(o, "aiModel");

    s.kernelDriverEnabled = getBool(o, "kernelDriverEnabled", s.kernelDriverEnabled);
    s.kernelDriverEnabledAuthoritative =
        getBool(o, "kernelDriverEnabledAuthoritative", s.kernelDriverEnabledAuthoritative);
    s.userModeBehaviorMonitor = getBool(o, "userModeBehaviorMonitor", s.userModeBehaviorMonitor);
    s.ransomwareCanaryEnabled = getBool(o, "ransomwareCanaryEnabled", s.ransomwareCanaryEnabled);
    s.behaviorBaselineEnabled = getBool(o, "behaviorBaselineEnabled", s.behaviorBaselineEnabled);

    s.ransomGuardEnabled = getBool(o, "ransomGuardEnabled", s.ransomGuardEnabled);
    if (o.contains(QLatin1String("ransomGuardDirs")))
        s.ransomGuardDirs = getStrList(o, "ransomGuardDirs");

    s.aiCreditGuardEnabled = getBool(o, "aiCreditGuardEnabled", s.aiCreditGuardEnabled);
    s.aiMonthlyCreditBudget = getI64(o, "aiMonthlyCreditBudget", s.aiMonthlyCreditBudget);

    if (o.contains(QLatin1String("eventSource"))) s.eventSource = getStr(o, "eventSource");
    s.kernelConnected = getBool(o, "kernelConnected", s.kernelConnected);
    if (o.contains(QLatin1String("kernelStatus"))) s.kernelStatus = getStr(o, "kernelStatus");

    s.quarantineOnBlock = getBool(o, "quarantineOnBlock", s.quarantineOnBlock);
    return s;
}

}
