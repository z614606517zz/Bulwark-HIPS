#pragma once
#include <QString>

namespace bulwark::engine {
// Classifies path metadata only. Secret contents never enter the event stream.
inline bool isDeveloperCredential(QString path) {
    path.replace(QLatin1Char('/'), QLatin1Char('\\'));
    path = path.toLower();
    static const char* endings[] = {
        "\\.ssh\\id_rsa", "\\.ssh\\id_dsa", "\\.ssh\\id_ecdsa", "\\.ssh\\id_ed25519", "\\.ssh\\identity",
        "\\.aws\\credentials", "\\.azure\\accesstokens.json", "\\.azure\\msal_token_cache.json",
        "\\.azure\\msal_token_cache.bin", "\\gcloud\\application_default_credentials.json",
        "\\gcloud\\credentials.db", "\\.kube\\config", "\\.docker\\config.json", "\\.npmrc",
        "\\.pypirc", "\\.git-credentials", "\\gh\\hosts.yml", "\\github cli\\hosts.yml"
    };
    for (const char* ending : endings) if (path.endsWith(QLatin1String(ending))) return true;
    return false;
}
}
