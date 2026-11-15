[CmdletBinding()]
param(
    [ValidateSet('Debug', 'Release')]
    [string]$Configuration = 'Release',

    [string]$SysPath,
    [string]$PdbPath,

    [string]$CertThumbprint,
    [string]$CertSubject,

    [string]$OutDir,

    [string]$Os = '10_X64',

    [string]$TimestampUrl = 'http://timestamp.digicert.com',

    [switch]$NoPdb,

    [switch]$SkipSign,
    [switch]$CheckOnly
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot

function Step($m) { Write-Host ''; Write-Host "== $m ==" -ForegroundColor Cyan }
function Ok($m)   { Write-Host "  [OK] $m" -ForegroundColor Green }
function Warn($m) { Write-Host "  [!]  $m" -ForegroundColor Yellow }
function Bad($m)  { Write-Host "  [X]  $m" -ForegroundColor Red }
function Info($m) { Write-Host "       $m" -ForegroundColor DarkGray }
function Die($m)  { Bad $m; throw $m }

Step 'tools'

function Find-KitTool([string]$relRoot, [string]$name, [string]$archDir) {
    $base = Join-Path "${env:ProgramFiles(x86)}\Windows Kits\10" $relRoot
    if (-not (Test-Path $base)) { return $null }
    Get-ChildItem $base -Recurse -Filter $name -ErrorAction SilentlyContinue |
        Where-Object { $_.FullName -match [regex]::Escape("\$archDir\") } |
        Sort-Object FullName -Descending | Select-Object -First 1
}

$infverif = Find-KitTool 'tools' 'infverif.exe' 'x64'
$inf2cat  = Find-KitTool 'bin'   'Inf2Cat.exe'  'x86'
$signtool = Find-KitTool 'bin'   'signtool.exe' 'x64'
$makecab  = Join-Path $env:SystemRoot 'System32\makecab.exe'
$expand   = Join-Path $env:SystemRoot 'System32\expand.exe'

if (-not $infverif) { Die 'infverif.exe not found (install the WDK)' }
if (-not $inf2cat)  { Die 'Inf2Cat.exe not found (install the WDK)' }
if (-not (Test-Path $makecab)) { Die "makecab.exe not found at $makecab" }
Ok ('infverif : ' + $infverif.FullName)
Ok ('inf2cat  : ' + $inf2cat.FullName)
if ($signtool) { Ok ('signtool : ' + $signtool.FullName) } else { Warn 'signtool.exe not found -- signing will be skipped' }

Step 'inputs'

$inf = Join-Path $root 'Bulwark.Driver\Bulwark.inf'
if (-not (Test-Path $inf)) { Die "missing INF: $inf" }
Ok ('inf : ' + $inf)

if (-not $SysPath) {
    $candidates = @(
        (Join-Path $root "Bulwark.Driver\build\driver\$Configuration\Bulwark.sys"),
        (Join-Path $root 'cpp\dist\Bulwark.sys')
    )
    $SysPath = $candidates | Where-Object { Test-Path $_ } | Select-Object -First 1
    if (-not $SysPath) { Die ("no Bulwark.sys found. looked in:`n  " + ($candidates -join "`n  ")) }
}
if (-not (Test-Path $SysPath)) { Die "missing driver binary: $SysPath" }
$sysItem = Get-Item $SysPath
Ok ('sys : ' + $sysItem.FullName)
Info ('{0} bytes, built {1}' -f $sysItem.Length, $sysItem.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss'))

if (-not $PdbPath) {
    $PdbPath = [IO.Path]::ChangeExtension($sysItem.FullName, '.pdb')
}
$havePdb = (-not $NoPdb) -and (Test-Path $PdbPath)
if ($NoPdb)          { Info 'pdb : intentionally excluded (-NoPdb)' }
elseif ($havePdb)    { Ok ('pdb : ' + $PdbPath) }
else                 { Warn "pdb not found next to the .sys ($PdbPath) -- submitting without it" }

Step 'driver binary sanity'

$bytes = [IO.File]::ReadAllBytes($sysItem.FullName)
if ($bytes.Length -lt 0x200) { Die 'file is too small to be a PE image' }
$peOff = [BitConverter]::ToInt32($bytes, 0x3C)
if ($peOff -le 0 -or $peOff + 0x100 -ge $bytes.Length) { Die 'not a PE image (bad e_lfanew)' }
if (-not ($bytes[$peOff] -eq 0x50 -and $bytes[$peOff + 1] -eq 0x45)) { Die 'not a PE image (missing PE signature)' }

$machine = [BitConverter]::ToUInt16($bytes, $peOff + 4)
if ($machine -eq 0x8664) { Ok 'architecture: x64' }
else { Die ('architecture is 0x{0:X4}, expected x64 (0x8664). attestation needs every driver folder to be the same arch set.' -f $machine) }

$optOff = $peOff + 24
$magic  = [BitConverter]::ToUInt16($bytes, $optOff)
if ($magic -ne 0x20B) { Die ('optional header magic 0x{0:X} is not PE32+' -f $magic) }
$dllChar = [BitConverter]::ToUInt16($bytes, $optOff + 0x46)
if ($dllChar -band 0x0080) {
    Ok 'Force Integrity bit set (/INTEGRITYCHECK)'
} else {
    Bad 'Force Integrity bit NOT set -- ObRegisterCallbacks() will fail at runtime'
    Info 'self-protection would silently disappear, yet the driver would still sign fine.'
    Info 'the vcxproj passes /INTEGRITYCHECK to the linker; a .sys without it is not a release build.'
    Die 'refusing to package a driver without /INTEGRITYCHECK'
}

$existing = Get-AuthenticodeSignature $sysItem.FullName
if ($existing.Status -ne 'NotSigned') {
    Info ('current .sys signature: {0} ({1})' -f $existing.Status,
          $(if ($existing.SignerCertificate) { $existing.SignerCertificate.Subject } else { 'unknown signer' }))
    Info 'HDC overwrites this embedded signature -- it is here only for local testing.'
}

Step 'INF validation (the exact rulesets HDC runs)'

foreach ($mode in @('/k', '/h')) {
    $label = if ($mode -eq '/k') { 'Desktop (/k)' } else { 'driver isolation (/h)' }
    $out = & $infverif.FullName $mode $inf 2>&1 | Out-String
    $errLines  = ($out -split "`r?`n") | Where-Object { $_ -match '^ERROR\(' }
    $warnLines = ($out -split "`r?`n") | Where-Object { $_ -match '^WARNING\(' }
    foreach ($w in $warnLines) { Warn $w.Trim() }
    if ($errLines) {
        foreach ($e in $errLines) { Bad $e.Trim() }
        Die "INF fails InfVerif $label -- HDC would reject the submission"
    }
    Ok "passes InfVerif $label"
}

Step 'staging'

$stageRoot = Join-Path $env:TEMP 'bulwark-hdc'
$pkgName   = 'Bulwark'
if ($pkgName.Length -ge 40) { Die "package folder name '$pkgName' must be shorter than 40 characters" }
if ($stageRoot.StartsWith('\\')) { Die 'staging path is a UNC path; use a mapped drive letter' }
foreach ($ch in $stageRoot.ToCharArray()) {
    if ([int]$ch -gt 127) { Die "staging path contains non-ASCII characters: $stageRoot" }
}

if (Test-Path $stageRoot) { Remove-Item $stageRoot -Recurse -Force }
$pkgDir = Join-Path $stageRoot $pkgName
New-Item -ItemType Directory -Path $pkgDir -Force | Out-Null

Copy-Item $inf                (Join-Path $pkgDir 'Bulwark.inf') -Force
Copy-Item $sysItem.FullName   (Join-Path $pkgDir 'Bulwark.sys') -Force
if ($havePdb) { Copy-Item $PdbPath (Join-Path $pkgDir 'Bulwark.pdb') -Force }
Ok ("staged in $pkgDir")

Step "Inf2Cat (/os:$Os)"

$catOut = & $inf2cat.FullName "/driver:$pkgDir" "/os:$Os" 2>&1 | Out-String
$catExit = $LASTEXITCODE
$catLines = ($catOut -split "`r?`n") | Where-Object { $_.Trim() -ne '' -and $_ -notmatch '^Testing driver package' }
foreach ($l in $catLines) { Info $l.Trim() }
if ($catExit -ne 0) { Die "Inf2Cat failed (exit $catExit) -- the package is not signable as-is" }

$cat = Get-ChildItem $pkgDir -Filter '*.cat' | Select-Object -First 1
if (-not $cat) { Die 'Inf2Cat reported success but produced no .cat' }
Ok ("catalog: $($cat.Name) ($($cat.Length) bytes)")

Step 'signing certificate'

$cert = $null
if (-not $SkipSign -and $signtool) {
    $stores = @('Cert:\CurrentUser\My', 'Cert:\LocalMachine\My')
    foreach ($s in $stores) {
        $found = @(Get-ChildItem $s -ErrorAction SilentlyContinue | Where-Object {
            $_.HasPrivateKey -and $_.NotAfter -gt (Get-Date) -and
            (($_.EnhancedKeyUsageList | ForEach-Object { $_.ObjectId }) -contains '1.3.6.1.5.5.7.3.3') -and
            (
                ($CertThumbprint -and $_.Thumbprint -eq $CertThumbprint.Replace(' ', '').ToUpper()) -or
                ($CertSubject    -and $_.Subject -like "*$CertSubject*") -or
                (-not $CertThumbprint -and -not $CertSubject)
            )
        } | Sort-Object NotAfter -Descending)
        if ($found.Count -gt 0) {
            $cert = $found[0]
            Ok ("using cert from ${s}: " + $cert.Subject)
            Info ('thumbprint : ' + $cert.Thumbprint)
            Info ('valid until: ' + $cert.NotAfter.ToString('yyyy-MM-dd'))
            if ($s -eq 'Cert:\LocalMachine\My') {
                Info 'LocalMachine private keys need an elevated shell; if signtool later reports'
                Info '"No certificates were found that met all the given criteria", that is why.'
            }
            break
        }
    }
    if (-not $cert) {
        Warn 'no usable code-signing certificate found'
        Info 'HDC requires an EV code signing certificate; the CAB will be produced UNSIGNED.'
        Info 'an unsigned CAB cannot be submitted -- sign it on the machine holding the EV token.'
    }
    if ($cert -and $cert.Subject -like '*BulwarkTestCert*') {
        Warn 'this is the local TEST certificate, not an EV cert -- HDC will reject a CAB signed with it'
        Info 'useful for rehearsing the packaging flow, useless for an actual submission.'
    }
} else {
    Info 'signing skipped by request'
}

if ($cert -and -not $CheckOnly) {
    Step 'sign catalog'
    $args = @('sign', '/q', '/sha1', $cert.Thumbprint, '/fd', 'sha256')
    & $signtool.FullName @($args + @('/tr', $TimestampUrl, '/td', 'sha256', $cat.FullName)) 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) {
        Warn 'timestamping failed (offline?) -- signing the catalog without a timestamp'
        & $signtool.FullName @($args + @($cat.FullName)) 2>&1 | Out-Null
        if ($LASTEXITCODE -ne 0) { Die "signtool failed on $($cat.Name) (exit $LASTEXITCODE)" }
    }
    Ok ("signed $($cat.Name)")
}

if ($CheckOnly) {
    Step 'CheckOnly -- nothing packaged'
    Remove-Item $stageRoot -Recurse -Force -ErrorAction SilentlyContinue
    Write-Host ''
    Write-Host '==== all local checks passed; the package is submittable in shape ====' -ForegroundColor Green
    Write-Host ''
    exit 0
}

Step 'makecab'

$cabName = 'Bulwark.cab'
$ddf = Join-Path $stageRoot 'Bulwark.ddf'
$lines = @(
    ';*** Bulwark.ddf -- generated by scripts\pack-driver-cab.ps1, do not edit by hand',
    '.OPTION EXPLICIT',
    '.Set CabinetFileCountThreshold=0',
    '.Set FolderFileCountThreshold=0',
    '.Set FolderSizeThreshold=0',
    '.Set MaxCabinetSize=0',
    '.Set MaxDiskFileCount=0',
    '.Set MaxDiskSize=0',
    '.Set CompressionType=MSZIP',
    '.Set Cabinet=on',
    '.Set Compress=on',
    ".Set CabinetNameTemplate=$cabName",
    ".Set DestinationDir=$pkgName",
    (Join-Path $pkgDir 'Bulwark.inf'),
    (Join-Path $pkgDir 'Bulwark.sys'),
    $cat.FullName
)
if ($havePdb) { $lines += (Join-Path $pkgDir 'Bulwark.pdb') }
[IO.File]::WriteAllLines($ddf, $lines, [Text.ASCIIEncoding]::new())

Push-Location $stageRoot
try {
    $mcOut = & $makecab '/f' $ddf 2>&1 | Out-String
} finally { Pop-Location }
$cab = Join-Path $stageRoot "Disk1\$cabName"
if (-not (Test-Path $cab)) {
    Info $mcOut
    Die 'makecab did not produce a CAB'
}
$countLine = ($mcOut -split "`r?`n" | Where-Object { $_ -match 'in \d+ files' }) -join ' '
Ok ("$cabName built ($((Get-Item $cab).Length) bytes)")
if ($countLine) { Info $countLine.Trim() }

Step 'verify CAB layout'

$probe = Join-Path $stageRoot 'verify'
New-Item -ItemType Directory -Path $probe -Force | Out-Null
& $expand $cab '-F:*' $probe 2>&1 | Out-Null
if ($LASTEXITCODE -ne 0) { Die "expand failed to extract the CAB (exit $LASTEXITCODE)" }

$got = @(Get-ChildItem $probe -Recurse -File | ForEach-Object { $_.FullName.Substring($probe.Length + 1) })
if ($got.Count -eq 0) { Die 'the CAB extracted to nothing' }
foreach ($g in $got) { Info $g }

$rootFiles = @($got | Where-Object { $_ -notmatch '\\' })
if ($rootFiles.Count -gt 0) {
    Die ('files at the CAB root -- HDC answers "There are files at the root of the cabinet": ' +
         ($rootFiles -join ', '))
}
$topDirs = @($got | ForEach-Object { ($_ -split '\\')[0] } | Sort-Object -Unique)
if ($topDirs.Count -ne 1 -or $topDirs[0] -ne $pkgName) {
    Die ('expected every file under a single "' + $pkgName + '\" folder, got: ' + ($topDirs -join ', '))
}

$expected = @('Bulwark.inf', 'Bulwark.sys', $cat.Name)
if ($havePdb) { $expected += 'Bulwark.pdb' }
$leaves = @($got | ForEach-Object { Split-Path $_ -Leaf })
$missing = @($expected | Where-Object { $leaves -notcontains $_ })
if ($missing.Count -gt 0) { Die ('missing from the CAB: ' + ($missing -join ', ')) }
$extra = @($leaves | Where-Object { $expected -notcontains $_ })
if ($extra.Count -gt 0) { Warn ('unexpected files in the CAB: ' + ($extra -join ', ')) }

Ok ("layout OK: $($got.Count) file(s), all under $pkgName\, nothing at the root")

if ($cert) {
    Step 'sign CAB'
    $args = @('sign', '/q', '/sha1', $cert.Thumbprint, '/fd', 'sha256')
    & $signtool.FullName @($args + @('/tr', $TimestampUrl, '/td', 'sha256', $cab)) 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) {
        Warn 'timestamping failed (offline?) -- signing the CAB without a timestamp'
        & $signtool.FullName @($args + @($cab)) 2>&1 | Out-Null
        if ($LASTEXITCODE -ne 0) { Die "signtool failed on the CAB (exit $LASTEXITCODE)" }
    }
    $cs = Get-AuthenticodeSignature $cab
    if ($cs.Status -eq 'NotSigned') { Die 'CAB still reports NotSigned after signing' }
    Ok ("CAB signed: $($cs.Status), signer=$($cs.SignerCertificate.Subject)")
}

Step 'output'

if (-not $OutDir) { $OutDir = Join-Path $root 'build\hdc' }
if (-not (Test-Path $OutDir)) { New-Item -ItemType Directory -Path $OutDir -Force | Out-Null }
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$final = Join-Path $OutDir ("Bulwark-$stamp.cab")
Copy-Item $cab $final -Force
Ok ("$final")
Remove-Item $stageRoot -Recurse -Force -ErrorAction SilentlyContinue

Write-Host ''
Write-Host '==== next steps ====' -ForegroundColor Green
Write-Host '  1) Partner Center -> Hardware -> Submit new hardware, upload this CAB.' -ForegroundColor Gray
Write-Host '     Leave BOTH test-signing options unchecked. Pick the Windows 10/11 x64' -ForegroundColor Gray
Write-Host '     desktop signatures under "Requested Signatures".' -ForegroundColor Gray
Write-Host '  2) Download the signed package and take Bulwark.sys from it.' -ForegroundColor Gray
Write-Host '  3) The returned .sys is signed by Microsoft (WHCP publisher), NOT by your' -ForegroundColor Yellow
Write-Host '     EV cert -- HDC overwrites the embedded signature. Keep the Microsoft-signed' -ForegroundColor Yellow
Write-Host '     driver separate from the user-mode release-signing certificate checks.' -ForegroundColor Yellow
Write-Host '  4) Windows Server does not load attestation-signed filter drivers. Server' -ForegroundColor Gray
Write-Host '     support needs an HLK/WHCP submission instead.' -ForegroundColor Gray
Write-Host ''
