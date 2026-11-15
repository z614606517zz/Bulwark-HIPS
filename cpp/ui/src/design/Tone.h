#pragma once
#include "design/Theme.h"

#include <QColor>
#include <QString>

namespace ui {

enum class Tone { Info, Success, Warning, Danger };

inline QColor toneColor(Tone t)
{
    switch (t) {
    case Tone::Info:    return theme::info();
    case Tone::Success: return theme::success();
    case Tone::Warning: return theme::warning();
    case Tone::Danger:  return theme::danger();
    }
    return theme::info();
}

inline QString toneIcon(Tone t)
{
    switch (t) {
    case Tone::Info:    return QStringLiteral("info");
    case Tone::Success: return QStringLiteral("check-circle");
    case Tone::Warning: return QStringLiteral("alert");
    case Tone::Danger:  return QStringLiteral("x-circle");
    }
    return QStringLiteral("info");
}

}
