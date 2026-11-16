# Release signature for the Bulwark installer.
#
# A running Bulwark service refuses to stop while protection is on. It stands down for an installer
# only if that installer carries a release signature made with the key whose public half is compiled
# into the service (cpp/service/include/bulwark/service/ReleaseSigningKey.h).
#
# Format: 80 bytes appended to the installer = 16-byte marker "BULWARK-RELSIG1\0" + 64-byte
# ECDSA P-256 signature (r || s) over the SHA-256 of everything before the marker.
#
# The private key is a non-exportable key in the current Windows account's key store. It never
# leaves this machine and is not part of the repository.
#
#   sign-release.ps1 -CreateKey -ShowPublicKey     create the key once, print the public half
#   sign-release.ps1 -File <installer.exe>         sign in place (-Force replaces an existing signature)
#   sign-release.ps1 -Verify <installer.exe>       check a signature against this account's key
param(
    [string]$File,
    [string]$Verify,
    [switch]$CreateKey,
    [switch]$ShowPublicKey,
    [switch]$Force,
    [string]$KeyName = 'BulwarkReleaseSigning'
)
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Core

$marker = [byte[]]([Text.Encoding]::ASCII.GetBytes('BULWARK-RELSIG1') + [byte]0)
$trailerSize = $marker.Length + 64

function Open-SigningKey {
    if ([Security.Cryptography.CngKey]::Exists($KeyName)) {
        return [Security.Cryptography.CngKey]::Open($KeyName)
    }
    if (-not $CreateKey) {
        throw "signing key '$KeyName' is not in this account's key store; run once with -CreateKey"
    }
    $p = New-Object Security.Cryptography.CngKeyCreationParameters
    $p.ExportPolicy = [Security.Cryptography.CngExportPolicies]::None
    $p.KeyUsage = [Security.Cryptography.CngKeyUsages]::Signing
    Write-Output "created signing key '$KeyName'"
    return [Security.Cryptography.CngKey]::Create([Security.Cryptography.CngAlgorithm]::ECDsaP256, $KeyName, $p)
}

function Get-PublicXY($key) {
    $blob = $key.Export([Security.Cryptography.CngKeyBlobFormat]::EccPublicBlob)
    if ($blob.Length -ne 72) { throw 'unexpected public key blob' }
    return , ([byte[]]$blob[8..71])
}

function Split-Signed([byte[]]$bytes) {
    $signed = $false
    if ($bytes.Length -gt $trailerSize) {
        $signed = $true
        $at = $bytes.Length - $trailerSize
        for ($i = 0; $i -lt $marker.Length; $i++) { if ($bytes[$at + $i] -ne $marker[$i]) { $signed = $false; break } }
    }
    $contentLength = $bytes.Length
    if ($signed) { $contentLength = $bytes.Length - $trailerSize }
    return @{ Signed = $signed; ContentLength = $contentLength }
}

function Get-ContentHash([byte[]]$bytes, [int]$length) {
    $sha = [Security.Cryptography.SHA256]::Create()
    try { return , $sha.ComputeHash($bytes, 0, $length) } finally { $sha.Dispose() }
}

$results = @(Open-SigningKey)
$key = $results[$results.Length - 1]
$results | Where-Object { $_ -is [string] } | ForEach-Object { Write-Output $_ }
$ecdsa = New-Object Security.Cryptography.ECDsaCng($key)

if ($ShowPublicKey) {
    $xy = Get-PublicXY $key
    Write-Output ('public key (X || Y, hex): ' + (($xy | ForEach-Object { $_.ToString('x2') }) -join ''))
    for ($i = 0; $i -lt 64; $i += 8) {
        Write-Output ('    ' + ((($xy[$i..($i + 7)]) | ForEach-Object { '0x' + $_.ToString('x2') }) -join ', ') + ',')
    }
}

if ($File) {
    $path = (Resolve-Path -LiteralPath $File).Path
    $bytes = [IO.File]::ReadAllBytes($path)
    $s = Split-Signed $bytes
    if ($s.Signed -and -not $Force) { throw 'file already carries a release signature; use -Force to replace it' }
    $hash = Get-ContentHash $bytes $s.ContentLength
    $sig = $ecdsa.SignHash($hash)
    if ($sig.Length -ne 64) { throw 'unexpected signature length' }
    $fs = [IO.File]::Open($path, [IO.FileMode]::Open, [IO.FileAccess]::Write, [IO.FileShare]::None)
    try {
        $fs.SetLength($s.ContentLength)
        $fs.Position = $s.ContentLength
        $fs.Write($marker, 0, $marker.Length)
        $fs.Write($sig, 0, $sig.Length)
    } finally { $fs.Dispose() }
    Write-Output ('signed: ' + [IO.Path]::GetFileName($path) + ' (' + ($s.ContentLength + $trailerSize) + ' bytes)')
    $Verify = $path
}

if ($Verify) {
    $path = (Resolve-Path -LiteralPath $Verify).Path
    $bytes = [IO.File]::ReadAllBytes($path)
    $s = Split-Signed $bytes
    if (-not $s.Signed) { Write-Output 'verify: NO SIGNATURE'; exit 2 }
    $hash = Get-ContentHash $bytes $s.ContentLength
    $sig = New-Object byte[] 64
    [Array]::Copy($bytes, $bytes.Length - 64, $sig, 0, 64)
    if ($ecdsa.VerifyHash($hash, $sig)) { Write-Output 'verify: OK' } else { Write-Output 'verify: BAD SIGNATURE'; exit 3 }
}
