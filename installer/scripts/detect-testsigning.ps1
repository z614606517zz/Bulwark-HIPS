#Requires -Version 5.1
<#
.SYNOPSIS
    Detect whether Windows is currently in test-signing mode.

.DESCRIPTION
    Exit codes (the installer reads only the exit code, never stdout):
        10 = test signing is ON
        20 = test signing is OFF, not present, or undetermined

    Why a separate script instead of an inline -Command:
    quoting a regex through nsExec's command line is fragile (the quotes can be
    eaten before PowerShell sees them). A -File invocation has no nested quoting.

    Why this file is pure ASCII:
    bcdedit output is localized -- a Chinese Windows prints the equivalent of
    "Yes" as U+662F. Embedding that character literally would make the result
    depend on how this file happens to be encoded on disk, so the character is
    built with [char] instead.

    "Undetermined" deliberately maps to 20 (treated as OFF). That path still
    runs `bcdedit /set testsigning on`, which is idempotent and harmless; the
    opposite mistake would silently skip enabling test signing and leave the
    driver unable to load.
#>
$ErrorActionPreference = 'SilentlyContinue'

$YES_CN = [char]0x662F   # Chinese "yes"
$NO_CN  = [char]0x5426   # Chinese "no"

try {
    $lines = & bcdedit.exe /enum '{current}' 2>$null
} catch {
    exit 20
}
if (-not $lines) { exit 20 }

foreach ($line in $lines) {
    $text = [string]$line
    if ($text -notmatch 'testsigning') { continue }

    if ($text -match '(?i)\bYes\b' -or $text.Contains($YES_CN)) { exit 10 }
    if ($text -match '(?i)\bNo\b'  -or $text.Contains($NO_CN))   { exit 20 }

    # Row exists but the value is unreadable (unexpected locale / mangled
    # codepage): stay conservative.
    exit 20
}

# No testsigning row at all -> never enabled.
exit 20
