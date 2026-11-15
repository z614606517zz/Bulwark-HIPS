#pragma once
#include <QString>

namespace bulwark::service {

class DriverControl {
public:
    static bool ensureLoaded();

    static bool tryStop();

    static bool isRunning();

    static QString locateSys();
};

}
