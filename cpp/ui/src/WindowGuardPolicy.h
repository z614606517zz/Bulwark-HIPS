#pragma once

namespace bulwark::ui::window_policy {

[[nodiscard]] constexpr bool shouldRestoreHiddenWindow(bool expectedHidden,
                                                       bool minimized,
                                                       bool nativeVisible) noexcept
{
    return !expectedHidden && !minimized && !nativeVisible;
}

[[nodiscard]] constexpr bool shouldClearHiddenIntent(bool expectedHidden,
                                                     bool minimized,
                                                     bool nativeVisible) noexcept
{
    return expectedHidden && !minimized && nativeVisible;
}

[[nodiscard]] constexpr bool shouldAllowCloseMessage(bool quitAllowed,
                                                     bool closeAuthorizationFresh) noexcept
{
    return quitAllowed || closeAuthorizationFresh;
}

[[nodiscard]] constexpr bool isCloseAuthorizationFresh(bool authorized,
                                                       unsigned ageMs,
                                                       unsigned windowMs) noexcept
{
    return authorized && ageMs <= windowMs;
}

}
