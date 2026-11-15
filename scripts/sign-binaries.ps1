[CmdletBinding()]
param(
    [string]$CertSubject = 'BulwarkTestCert',
    [switch]$FromBuild,
    [switch]$WhatIfOnly,
    [string]$TimestampUrl = 'http://timestamp.digicert.com'
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$dist = Join-Path $root 'cpp\dist'
$targets = @('bulwark_service.exe', 'bulwark_ui.exe', 'BulwarkAmsi.dll', 'BulwarkAmsi32.dll')
# 32 位 AMSI 提供程序单独构建(cpp/amsi/CMakeLists.txt 顶部),没构建时跳过而不是中止。
$optional = @('BulwarkAmsi32.dll')

function Step($m) { Write-Host ''; Write-Host "== $m ==" -ForegroundColor Cyan }
function Ok($m)   { Write-Host "  [OK] $m" -ForegroundColor Green }
function Warn($m) { Write-Host "  [!]  $m" -ForegroundColor Yellow }
function Bad($m)  { Write-Host "  [X]  $m" -ForegroundColor Red }
function Info($m) { Write-Host "       $m" -ForegroundColor DarkGray }
function Die($m)  { throw $m }

$isAdmin = ([Security.Principal.WindowsPrincipal] `
            [Security.Principal.WindowsIdentity]::GetCurrent()
           ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
Step 'preconditions'
if ($isAdmin) { Ok 'running elevated' }
else {
    Bad 'NOT elevated -- the private key lives in LocalMachine\My and cannot be read'
    Info 'signtool would fail with a misleading "no certificates were found" error.'
    if (-not $WhatIfOnly) { Die 'run this from an elevated shell' }
}

$cert = @(Get-ChildItem 'Cert:\LocalMachine\My' -ErrorAction SilentlyContinue |
          Where-Object { $_.Subject -like "*$CertSubject*" -and $_.HasPrivateKey } |
          Sort-Object NotAfter -Descending)
if ($cert.Count -eq 0) { Die "no code-signing cert with a private key matching *$CertSubject* in LocalMachine\My" }
$c = $cert[0]
Ok ("cert: " + $c.Subject)
Info ("thumbprint : " + $c.Thumbprint)
Info ("valid until: " + $c.NotAfter.ToString('yyyy-MM-dd') +
      "  (" + [int]($c.NotAfter - (Get-Date)).TotalDays + " days left)")
if ($c.NotAfter -lt (Get-Date).AddDays(60)) {
    Warn 'cert expires within 60 days -- plan a rotation (update ReleaseTrust.h)'
}

Step 'release thumbprint must match this cert'
$trustH = Join-Path $root 'cpp\shared\include\bulwark\ReleaseTrust.h'
if (-not (Test-Path $trustH)) { Die "missing $trustH" }
$m = [regex]::Match([IO.File]::ReadAllText($trustH),
                    'BULWARK_RELEASE_SIGNER_THUMBPRINT\s+"([0-9A-Fa-f]{40})"')
if (-not $m.Success) { Die 'ReleaseTrust.h does not define BULWARK_RELEASE_SIGNER_THUMBPRINT' }
$pinned = $m.Groups[1].Value.ToUpper()
Info ("pinned in ReleaseTrust.h : " + $pinned)
if ($pinned -ne $c.Thumbprint.ToUpper()) {
    Bad 'MISMATCH -- this is not the configured release signing certificate'
    Info ("  signing cert : " + $c.Thumbprint.ToUpper())
    Info ("  pinned       : " + $pinned)
    Die 'update the pin in cpp\shared\include\bulwark\ReleaseTrust.h, then re-run'
}
Ok 'release thumbprint matches the signing cert'

# The driver must be signed by the same cert, or the pin could cover only one of two signers.
$sys = Join-Path $dist 'Bulwark.sys'
if (Test-Path $sys) {
    $ds = Get-AuthenticodeSignature $sys
    if ($ds.SignerCertificate) {
        if ($ds.SignerCertificate.Thumbprint.ToUpper() -eq $pinned) { Ok 'dist Bulwark.sys signed by the same cert' }
        else { Warn ('dist Bulwark.sys is signed by a DIFFERENT cert: ' + $ds.SignerCertificate.Thumbprint) }
    } else { Warn 'dist Bulwark.sys carries no signature' }
} else { Warn 'no Bulwark.sys in dist (driver not staged yet)' }

$signtool = Get-ChildItem "${env:ProgramFiles(x86)}\Windows Kits\10\bin" -Recurse -Filter signtool.exe `
              -ErrorAction SilentlyContinue |
            Where-Object { $_.FullName -match '\\x64\\' } |
            Sort-Object FullName -Descending | Select-Object -First 1
if (-not $signtool) { Die 'signtool.exe not found (install the Windows SDK)' }
Ok ('signtool: ' + $signtool.FullName)

if ($FromBuild) {
    Step 'sync build output -> dist'
    $map = @{
        'bulwark_service.exe' = Join-Path $root 'cpp\build\service\Release\bulwark_service.exe'
        'bulwark_ui.exe'      = Join-Path $root 'cpp\build\ui\Release\bulwark_ui.exe'
        'BulwarkAmsi.dll'     = Join-Path $root 'cpp\build\amsi\Release\BulwarkAmsi.dll'
        'BulwarkAmsi32.dll'   = Join-Path $root 'cpp\build_amsi_x86\Release\BulwarkAmsi32.dll'
    }
    if (-not (Test-Path $dist)) { New-Item -ItemType Directory -Path $dist -Force | Out-Null }
    foreach ($n in $targets) {
        $src = $map[$n]
        if (-not (Test-Path $src)) {
            if ($optional -contains $n) { Warn "optional build output missing, skipped: $src"; continue }
            Die "build output missing: $src (build first)"
        }
        $dst = Join-Path $dist $n
        if (Test-Path $dst) {
            Copy-Item $dst ($dst + '.presign.bak') -Force
        }
        Copy-Item $src $dst -Force
        Ok ("{0,-22} {1,9} B  <- build" -f $n, (Get-Item $dst).Length)
    }
}

Step 'current signature state'
foreach ($n in $targets) {
    $p = Join-Path $dist $n
    if (-not (Test-Path $p)) {
        if ($optional -contains $n) { Info "not in dist (optional): $n" } else { Bad "missing in dist: $n" }
        continue
    }
    $s = Get-AuthenticodeSignature $p
    Info ("{0,-22} {1,9} B  {2}" -f $n, (Get-Item $p).Length, $s.Status)
}
if ($WhatIfOnly) { Step 'WhatIfOnly -- nothing signed'; return }

Step 'sign'
$signed = 0
foreach ($n in $targets) {
    $p = Join-Path $dist $n
    if (-not (Test-Path $p)) { continue }
    $args = @('sign', '/q', '/sm', '/s', 'My', '/sha1', $c.Thumbprint, '/fd', 'sha256')
    $withTs = $args + @('/tr', $TimestampUrl, '/td', 'sha256', $p)
    & $signtool.FullName @withTs 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) {
        Warn ("timestamping failed for $n (offline?) -- signing without a timestamp")
        Info 'a signature without a timestamp stops verifying once the cert expires'
        & $signtool.FullName @($args + @($p)) 2>&1 | Out-Null
        if ($LASTEXITCODE -ne 0) { Die "signtool failed for $n (exit $LASTEXITCODE)" }
    }
    $signed++
    Ok ("signed $n")
}

Step 'verify'
$bad = 0
foreach ($n in $targets) {
    $p = Join-Path $dist $n
    if (-not (Test-Path $p)) { continue }
    $s = Get-AuthenticodeSignature $p
    $tp = if ($s.SignerCertificate) { $s.SignerCertificate.Thumbprint.ToUpper() } else { '(none)' }
    $okSig = ($s.Status -ne 'NotSigned') -and ($tp -eq $pinned)
    if ($okSig) { Ok ("{0,-22} {1,-12} signer={2}" -f $n, $s.Status, $tp) }
    else { Bad ("{0,-22} {1,-12} signer={2}" -f $n, $s.Status, $tp); $bad++ }
    if ($s.TimeStamperCertificate) { Info '  timestamped: yes' } else { Info '  timestamped: no' }
}
Write-Host ''
if ($bad -gt 0) { Die "$bad binary(ies) are not correctly signed" }
Write-Host "==== $signed binary(ies) signed and verified against the pinned thumbprint ====" -ForegroundColor Green
Write-Host ''
