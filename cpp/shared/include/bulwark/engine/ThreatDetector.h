#pragma once
#include <QString>
#include "bulwark/models/SecurityEvent.h"

namespace bulwark::engine {

struct ThreatDetector {
    static constexpr int HighRisk = 80;
    static constexpr int Suspicious = 50;

    // 重算 e.riskScore 与 e.hasThreatIndicator,并把每条信号写进证据链。
    static void analyze(SecurityEvent& e);

    static bool isSuspiciousDropDir(const QString& path);

    static bool isSideloadProneModuleName(const QString& pathOrName);
};

}
