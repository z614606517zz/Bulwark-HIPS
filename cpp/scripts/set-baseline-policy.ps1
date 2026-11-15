[CmdletBinding()]
param(
  [string]   $ServiceName      = 'Bulwark',
  [string[]] $ProtectedPaths   = @(),
  [string[]] $FileHardBlock    = @(),
  [string[]] $FileNoLoad       = @(),
  [string[]] $FileExecBlock    = @(),
  [string[]] $ProtectedRegKeys = @(),
  [string[]] $RegHardBlock     = @('\Services\Bulwark'),
  [string[]] $BlockIps         = @(),
  [string[]] $KnownBadSha256   = @(),
  [string]   $SysPath          = "$env:SystemRoot\System32\drivers\Bulwark.sys",
  [switch]   $Recommended,
  [switch]   $ForceUnload
)
$ErrorActionPreference = 'Stop'

$idn = [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not (New-Object Security.Principal.WindowsPrincipal($idn)).IsInRole(
      [Security.Principal.WindowsBuiltInRole]::Administrator)) {
  throw 'Please run this script as Administrator.'
}

if ($Recommended) {
  $FileHardBlock += @(
    '\System32\drivers\etc\hosts',
    '\System32\sethc.exe',
    '\System32\utilman.exe',
    '\System32\Magnify.exe',
    '\System32\osk.exe',
    '\System32\config\SAM'
  )
  $RegHardBlock += @(
    '\Winlogon\Shell',
    '\Winlogon\Userinit'
  )
  Write-Warning '-Recommended enabled: includes system file/registry hard-blocks that may interfere with Windows Update and legitimate admin. Test first.'
}

$KnownBadSha256 = @($KnownBadSha256 | ForEach-Object {
  $h = "$_".Trim()
  if ($h -match '^[0-9a-fA-F]{64}$') { $h.ToLower() }
  elseif ($h -ne '') { Write-Warning "Ignoring invalid SHA-256 (need 64 hex chars): $h"; $null }
} | Where-Object { $_ })

$svcKey    = "HKLM:\SYSTEM\CurrentControlSet\Services\$ServiceName"
$policyKey = "$svcKey\Policy"

$q = & sc.exe query $ServiceName 2>&1
$registered = -not ($q -match '1060' -or ($q -match 'does not exist'))

if (-not $registered) {
  if (Test-Path $SysPath) {
    Write-Host "== Registering kernel minifilter service $ServiceName ($SysPath) ==" -ForegroundColor Cyan
    $create = & sc.exe create $ServiceName type= filesys binPath= "$SysPath" start= demand depend= FltMgr group= "FSFilter Activity Monitor" 2>&1
    if ($LASTEXITCODE -ne 0 -and ($create -notmatch '1073')) {
      throw "Failed to register driver service (sc create): $create"
    }
    $instances = "$svcKey\Instances"
    & reg.exe add "$instances" /v DefaultInstance /t REG_SZ /d 'Bulwark Instance' /f | Out-Null
    & reg.exe add "$instances\Bulwark Instance" /v Altitude /t REG_SZ /d '385201' /f | Out-Null
    & reg.exe add "$instances\Bulwark Instance" /v Flags /t REG_DWORD /d 0 /f | Out-Null
  } else {
    throw "Driver service $ServiceName is not registered and $SysPath was not found. Deploy Bulwark.sys and pass -SysPath, or run the user-mode service once (it auto-registers the driver), then re-run this script."
  }
}

$filters = & fltmc.exe filters 2>&1
$loaded = ($filters -match [regex]::Escape($ServiceName))
if ($loaded) {
  if ($ForceUnload) {
    Write-Host "Driver is loaded; -ForceUnload: unloading to write baseline (protection briefly drops)..." -ForegroundColor Yellow
    & fltmc.exe unload $ServiceName 2>&1 | Out-Host
    Start-Sleep -Milliseconds 500
  } else {
    Write-Warning "Driver is currently loaded; self-protection (\Services\Bulwark hard-block) will block writing Policy. Run 'fltmc unload $ServiceName' first, or re-run with -ForceUnload."
  }
}

New-Item -Path $policyKey -Force | Out-Null

function Set-MultiSz([string]$Name, [string[]]$Vals) {
  $clean = @($Vals | ForEach-Object { "$_".Trim() } | Where-Object { $_ -ne '' } | Select-Object -Unique)
  try {
    New-ItemProperty -Path $policyKey -Name $Name -PropertyType MultiString -Value $clean -Force | Out-Null
    Write-Host ("  {0,-16} = {1} entrie(s)" -f $Name, $clean.Count) -ForegroundColor Green
  } catch {
    Write-Warning "Failed to write ${Name} (driver self-protection may be active; unload the driver or use -ForceUnload): $($_.Exception.Message)"
  }
}

Write-Host "== Writing self-sufficient baseline to $policyKey ==" -ForegroundColor Cyan
Set-MultiSz 'ProtectedPaths'   $ProtectedPaths
Set-MultiSz 'FileHardBlock'    $FileHardBlock
Set-MultiSz 'FileNoLoad'       $FileNoLoad
Set-MultiSz 'FileExecBlock'    $FileExecBlock
Set-MultiSz 'ProtectedRegKeys' $ProtectedRegKeys
Set-MultiSz 'RegHardBlock'     $RegHardBlock
Set-MultiSz 'BlockIps'         $BlockIps
Set-MultiSz 'KnownBadSha256'   $KnownBadSha256

Write-Host "`nDone. On next driver load (fltmc load $ServiceName) or reboot, the kernel enforces this baseline before the user-mode service starts." -ForegroundColor Green
Write-Host "Note: verdicts learned later at runtime are written back to the same Policy key by the kernel itself; no need to re-run this script." -ForegroundColor DarkGray
