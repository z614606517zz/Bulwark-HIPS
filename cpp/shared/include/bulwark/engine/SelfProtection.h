#pragma once
#include <QString>
#include <atomic>

namespace bulwark::engine {

struct SelfProtection {
    inline static std::atomic<bool> enabled{true};

    static bool commandTargetsProduct(const QString& commandLine);
};

}
