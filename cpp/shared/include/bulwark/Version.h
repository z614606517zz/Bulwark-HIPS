#pragma once

#include "bulwark/VersionNumbers.h"

#ifndef RC_INVOKED

#include <QString>
#include <QStringList>

namespace bulwark::version {

namespace detail {
#define BULWARK_STRINGIFY_(x) #x
#define BULWARK_STRINGIFY(x)  BULWARK_STRINGIFY_(x)
constexpr const char* kFromNumbers = BULWARK_STRINGIFY(BULWARK_VERSION_MAJOR) "."
                                     BULWARK_STRINGIFY(BULWARK_VERSION_MINOR) "."
                                     BULWARK_STRINGIFY(BULWARK_VERSION_PATCH);
constexpr bool sameString(const char* a, const char* b)
{
    while (*a && *b) {
        if (*a != *b) return false;
        ++a; ++b;
    }
    return *a == *b;
}
static_assert(sameString(kFromNumbers, BULWARK_VERSION_STRING),
              "BULWARK_VERSION_STRING 与 MAJOR/MINOR/PATCH 不一致 —— 两处都要改。"
              "版本号是 exe 属性、界面、安装包三处的唯一来源,不一致会让三处打架。");
}

inline QString current()
{
    return QString::fromLatin1(BULWARK_VERSION_STRING);
}

inline QString displayString()
{
    return QStringLiteral("v") + current()
           + QStringLiteral(" · ") + QString::fromLatin1(BULWARK_VERSION_SUFFIX);
}

}

#endif
