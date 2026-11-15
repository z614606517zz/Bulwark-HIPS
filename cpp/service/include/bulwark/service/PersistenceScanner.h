#pragma once
#include "bulwark/ipc/Payloads.h"

namespace bulwark::service {

struct PersistenceScanner {
    static bulwark::ipc::PersistenceListResponsePayload scan();
};

}
