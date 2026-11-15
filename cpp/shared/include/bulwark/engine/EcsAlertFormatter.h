#pragma once
#include <QJsonObject>
#include "bulwark/models/SecurityEvent.h"
#include "bulwark/models/Verdict.h"

namespace bulwark::engine {

struct EcsAlertFormatter {
    static constexpr char EcsVersion[] = "8.11.0";

    static QJsonObject format(const bulwark::SecurityEvent& e, const bulwark::Verdict& v);
};

}
