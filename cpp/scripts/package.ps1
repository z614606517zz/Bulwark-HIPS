[CmdletBinding()]
param(
  [string]$QtDir = 'C:\Qt\6.8.3\msvc2022_64',
  [string]$CMake = '',
  [string]$OutputDir = ''
)
$ErrorActionPreference = 'Stop'

$scriptDir = $PSScriptRoot
if (-not $scriptDir) { $scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path }
$cppDir = Split-Path -Parent $scriptDir
$repoDir = Split-Path -Parent $cppDir
if ([string]::IsNullOrWhiteSpace($OutputDir)) {
  $distDir = Join-Path $cppDir 'dist'
} elseif ([IO.Path]::IsPathRooted($OutputDir)) {
  $distDir = $OutputDir
} else {
  $distDir = Join-Path $repoDir $OutputDir
}
$windeployqt = Join-Path $QtDir 'bin\windeployqt.exe'

if ([string]::IsNullOrWhiteSpace($CMake)) {
  $cmakeCommand = Get-Command cmake.exe -ErrorAction SilentlyContinue
  if (-not $cmakeCommand) { throw '找不到 cmake.exe(请安装 CMake 或用 -CMake 指定绝对路径)' }
  $CMake = $cmakeCommand.Source
}

foreach ($p in @($CMake, $windeployqt)) {
  if (-not (Test-Path $p)) { throw "找不到必需工具: $p(用 -QtDir / -CMake 指定正确路径)" }
}

$buildSrc = $cppDir
$mapped = $null
if ($cppDir -match '[^\u0000-\u007F]') {
  $letter = @('B:','Y:','W:','V:','T:') | Where-Object { -not (Test-Path $_) } | Select-Object -First 1
  if (-not $letter) { throw '没有空闲盘符可用于 subst' }
  $root = Split-Path -Parent $cppDir
  subst $letter $root | Out-Null
  $mapped = $letter
  $buildSrc = Join-Path $letter (Split-Path -Leaf $cppDir)
  Write-Host "非 ASCII 路径,已 subst $letter -> $root" -ForegroundColor Yellow
}

try {
  $buildDir = Join-Path $buildSrc 'build_pkg'
  if (Test-Path $buildDir) { Remove-Item -Recurse -Force $buildDir }

  Write-Host '== 构建内核驱动 (Release) ==' -ForegroundColor Cyan
  & (Join-Path $repoDir 'scripts\build-driver.ps1') -Configuration Release
  if ($LASTEXITCODE -ne 0) { throw "驱动构建失败 ($LASTEXITCODE)" }
  $driverSys = Join-Path $repoDir 'build\driver\Release\Bulwark.sys'
  if (-not (Test-Path $driverSys)) { throw "未找到驱动产物: $driverSys" }

  Write-Host '== 配置 (Release) ==' -ForegroundColor Cyan
  & $CMake -G 'Visual Studio 17 2022' -A x64 -S $buildSrc -B $buildDir "-DCMAKE_PREFIX_PATH=$($QtDir -replace '\\','/')"
  if ($LASTEXITCODE -ne 0) { throw "配置失败 ($LASTEXITCODE)" }

  Write-Host '== 构建 (Release) ==' -ForegroundColor Cyan
  & $CMake --build $buildDir --config Release --target bulwark_service bulwark_ui BulwarkAmsi
  if ($LASTEXITCODE -ne 0) { throw "构建失败 ($LASTEXITCODE)" }

  $svcExe = Join-Path $buildDir 'service\Release\bulwark_service.exe'
  $uiExe  = Join-Path $buildDir 'ui\Release\bulwark_ui.exe'
  $amsiDll = Join-Path $buildDir 'amsi\Release\BulwarkAmsi.dll'
  foreach ($e in @($svcExe, $uiExe, $amsiDll, $driverSys)) {
    if (-not (Test-Path $e)) { throw "未找到产物: $e" }
  }

  Write-Host '== 组装 dist + windeployqt ==' -ForegroundColor Cyan
  if (Test-Path $distDir) { Remove-Item -Recurse -Force $distDir }
  New-Item -ItemType Directory -Force -Path $distDir | Out-Null
  Copy-Item $svcExe $distDir
  Copy-Item $uiExe $distDir
  Copy-Item $amsiDll $distDir
  Copy-Item $driverSys $distDir
  Copy-Item (Join-Path $cppDir 'ui\app.ico') $distDir -Force
  $prevEA = $ErrorActionPreference
  $ErrorActionPreference = 'Continue'
  & $windeployqt --release --no-translations (Join-Path $distDir 'bulwark_service.exe') 2>&1 | Out-Null
  $wdSvc = $LASTEXITCODE
  & $windeployqt --release --no-translations (Join-Path $distDir 'bulwark_ui.exe') 2>&1 | Out-Null
  $wdUi = $LASTEXITCODE
  $ErrorActionPreference = $prevEA
  if ($wdSvc -ne 0) { throw "windeployqt(service) 失败 ($wdSvc)" }
  if ($wdUi -ne 0) { throw "windeployqt(ui) 失败 ($wdUi)" }
  Copy-Item (Join-Path $cppDir 'service\appsettings.json') $distDir -Force

  Write-Host "== 完成 ==`n自包含目录: $distDir" -ForegroundColor Green
  Get-ChildItem $distDir | Select-Object Name, Length | Format-Table -AutoSize
}
finally {
  if ($mapped) { subst $mapped /d | Out-Null }
}
