#Requires -Version 5.1
[CmdletBinding()]
param(
    [string]$QtDir = 'C:\Qt\6.8.3\msvc2022_64',
    [string]$CMake = '',
    [string]$CertSubject = 'BulwarkTestCert',
    [string]$TimestampUrl = 'http://timestamp.digicert.com',
    [switch]$UnsignedForTesting
)

$ErrorActionPreference = 'Stop'
$installerDir = $PSScriptRoot
$repo = Split-Path -Parent $installerDir

function Require-Success([string]$step) {
    if ($LASTEXITCODE -ne 0) { throw "$step failed (exit $LASTEXITCODE)" }
}

Write-Host '== Build complete dist from one build tree ==' -ForegroundColor Cyan
& (Join-Path $repo 'cpp\scripts\package.ps1') -QtDir $QtDir -CMake $CMake
Require-Success 'package.ps1'

Write-Host '== Stage installer payload ==' -ForegroundColor Cyan
& (Join-Path $installerDir 'stage-payload.ps1')
Require-Success 'stage-payload.ps1'

$makensis = Join-Path $installerDir 'tools\nsis\Bin\makensis.exe'
if (-not (Test-Path -LiteralPath $makensis)) { throw "makensis not found: $makensis" }
Write-Host '== Build NSIS installer ==' -ForegroundColor Cyan
Push-Location $installerDir
try {
    & $makensis /V3 'BulwarkSetup.nsi'
    Require-Success 'makensis'
} finally {
    Pop-Location
}

$setup = Join-Path $installerDir 'Bulwark-Setup-1.0.exe'
if (-not (Test-Path -LiteralPath $setup)) { throw "installer was not generated: $setup" }
if ($UnsignedForTesting) {
    Write-Warning 'Generated an unsigned test installer. Never publish this artifact.'
    Get-FileHash -LiteralPath $setup -Algorithm SHA256
    exit 0
}

$isAdmin = ([Security.Principal.WindowsPrincipal] `
            [Security.Principal.WindowsIdentity]::GetCurrent()
           ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) { throw 'Run from an elevated PowerShell; the key is in LocalMachine\My.' }

$cert = @(Get-ChildItem Cert:\LocalMachine\My -ErrorAction SilentlyContinue |
          Where-Object { $_.Subject -like "*$CertSubject*" -and $_.HasPrivateKey } |
          Sort-Object NotAfter -Descending | Select-Object -First 1)
if (-not $cert) { throw "No code-signing certificate matches $CertSubject" }
$cert = $cert[0]

$trustHeader = Join-Path $repo 'cpp\shared\include\bulwark\ReleaseTrust.h'
$match = [regex]::Match([IO.File]::ReadAllText($trustHeader),
                        'BULWARK_RELEASE_SIGNER_THUMBPRINT\s+"([0-9A-Fa-f]{40})"')
if (-not $match.Success) { throw 'ReleaseTrust.h has no valid signer thumbprint.' }
$pinned = $match.Groups[1].Value.ToUpper()
if ($cert.Thumbprint.ToUpper() -ne $pinned) {
    throw "Signer differs from ReleaseTrust.h: cert=$($cert.Thumbprint) pin=$pinned"
}

$signtool = Get-ChildItem "${env:ProgramFiles(x86)}\Windows Kits\10\bin" -Recurse -Filter signtool.exe `
              -ErrorAction SilentlyContinue |
            Where-Object { $_.FullName -match '\\x64\\' } |
            Sort-Object FullName -Descending | Select-Object -First 1
if (-not $signtool) { throw 'signtool.exe not found' }

Write-Host '== Sign installer ==' -ForegroundColor Cyan
$baseArgs = @('sign','/q','/sm','/s','My','/sha1',$cert.Thumbprint,'/fd','sha256')
& $signtool.FullName @($baseArgs + @('/tr',$TimestampUrl,'/td','sha256',$setup))
Require-Success 'installer signing'

$signature = Get-AuthenticodeSignature -LiteralPath $setup
if (-not $signature.SignerCertificate -or
    $signature.SignerCertificate.Thumbprint.ToUpper() -ne $pinned -or
    $signature.Status -eq 'NotSigned') {
    throw "Installer signature validation failed: $($signature.Status)"
}

$hash = Get-FileHash -LiteralPath $setup -Algorithm SHA256
Write-Host "Release installer: $setup" -ForegroundColor Green
Write-Host "SHA-256: $($hash.Hash)" -ForegroundColor Green
