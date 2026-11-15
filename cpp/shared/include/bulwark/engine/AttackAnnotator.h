#pragma once
#include "bulwark/models/SecurityEvent.h"

namespace bulwark::engine {

struct AttackAnnotator {
    static void annotate(bulwark::SecurityEvent& e);
};

}
