#pragma once
#include <QString>
#include <QStringList>
#include <QJsonObject>

namespace bulwark {

struct RuntimeSettings {
    bool protectionEnabled = true;

    bool protectionFollowsUi = false;

    bool processProtection = true;
    bool fileProtection = true;
    bool registryProtection = true;
    bool selfProtection = true;
    bool networkProtection = true;

    bool memoryProtectionEnabled = true;

    bool trustSignedActors = true;
    bool defaultBlock = false;
    bool silentMode = false;

    bool installControlEnabled = false;

    int  promptTimeoutSeconds = 30;

    bool promptTimeoutBlockHighRisk = true;

    QString aiBaseUrl;
    QString aiApiKey;
    QString aiModel;

    bool kernelDriverEnabled = false;
    bool kernelDriverEnabledAuthoritative = false;
    bool userModeBehaviorMonitor = true;
    bool ransomwareCanaryEnabled = true;
    bool behaviorBaselineEnabled = true;

    bool ransomGuardEnabled = true;
    QStringList ransomGuardDirs;

    bool aiCreditGuardEnabled = true;
    qint64 aiMonthlyCreditBudget = 4100000000LL;

    QString eventSource = QStringLiteral("Wmi");
    bool kernelConnected = false;
    QString kernelStatus;

    bool quarantineOnBlock = false;

    bool aiConfigured() const { return !aiApiKey.trimmed().isEmpty() && !aiBaseUrl.trimmed().isEmpty(); }

    RuntimeSettings clone() const { return *this; }

    QJsonObject toJson() const;
    static RuntimeSettings fromJson(const QJsonObject& o);
};

inline constexpr int kPromptTimeoutBlockMinRisk = 70;

inline bool promptTimeoutShouldBlock(bool defaultBlock, bool blockHighRisk,
                                     bool hasThreatIndicator, int riskScore) {
    return defaultBlock
        || (blockHighRisk && hasThreatIndicator && riskScore >= kPromptTimeoutBlockMinRisk);
}
inline bool promptTimeoutShouldBlock(const RuntimeSettings& s, bool hasThreatIndicator, int riskScore) {
    return promptTimeoutShouldBlock(s.defaultBlock, s.promptTimeoutBlockHighRisk,
                                    hasThreatIndicator, riskScore);
}

}
