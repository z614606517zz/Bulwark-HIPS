#pragma once
#include <QString>

namespace bulwark::ipc {

inline QString controlPipe() { return QStringLiteral("Bulwark.Control"); }

}
