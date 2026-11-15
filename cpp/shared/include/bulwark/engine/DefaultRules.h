#pragma once
#include <QString>
#include <QStringList>
#include <QVector>
#include "bulwark/models/DefenseRule.h"

namespace bulwark::engine {

struct DefaultRules {
    static QString builtInTag();
    static QVector<DefenseRule> build();

    static QStringList registryWatchFragments();

    static bool isDevTool(const QString& processPath);
    static bool isCiCdEnvironment();
    static bool hasLongEncodedContent(const QString& commandLine);
    static bool isTrustedInstaller(const QString& processPath);
};

}
