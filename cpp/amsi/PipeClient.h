#pragma once
#include <windows.h>
#include "AmsiProtocol.h"

namespace blw {

enum class AskResult { Allow, Blocked };

AskResult askService(BLW_AMSI_REQUEST& head,
                     const wchar_t* appName,
                     const wchar_t* contentName,
                     const unsigned char* content,
                     wchar_t* reasonOut,
                     DWORD reasonChars);

bool breakerOpen();

}
