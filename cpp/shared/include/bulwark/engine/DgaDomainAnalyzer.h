#pragma once
#include <QString>
#include "bulwark/engine/EngineCommon.h"

namespace bulwark::engine {

// 只给软信号:CDN、云服务的随机子域名长得和 DGA 一样。
struct DgaDomainAnalyzer {
    static ScoreResult analyze(const QString& domain);
};

}
