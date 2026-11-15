[CmdletBinding()]
param([string]$InstallDir = "$env:ProgramFiles\Bulwark")

$scriptDir = $PSScriptRoot
if (-not $scriptDir) { $scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path }
$cppDir = Split-Path -Parent $scriptDir
$candidates = @(
  (Join-Path $InstallDir 'bulwark_ui.exe'),
  (Join-Path $cppDir 'dist\bulwark_ui.exe')
)
$ui = $candidates | Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $ui) {
  Write-Host '未找到 bulwark_ui.exe。请先运行 package.ps1(生成 cpp\dist\)或 install-service.ps1。' -ForegroundColor Red
  exit 1
}

$svc = Get-Service -Name BulwarkService -ErrorAction SilentlyContinue
if (-not $svc -or $svc.Status -ne 'Running') {
  Write-Host '提示:BulwarkService 未运行,UI 将显示"未连接"。可先运行 install-service.ps1。' -ForegroundColor Yellow
}

Write-Host "启动 UI: $ui" -ForegroundColor Green
Start-Process -FilePath $ui
