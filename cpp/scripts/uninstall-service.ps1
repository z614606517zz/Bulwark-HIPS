[CmdletBinding()]
param(
  [string]$InstallDir = "$env:ProgramFiles\Bulwark",
  [switch]$RemoveFiles
)
$ErrorActionPreference = 'Stop'

$id = [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  throw '请以管理员身份运行本脚本。'
}

Write-Host '== 停止服务 ==' -ForegroundColor Cyan
& sc.exe stop BulwarkService 2>&1 | Out-Host
Start-Sleep -Seconds 2

$exe = Join-Path $InstallDir 'bulwark_service.exe'
if (Test-Path $exe) {
  Write-Host '== 注销服务 (--uninstall) ==' -ForegroundColor Cyan
  & $exe --uninstall
} else {
  Write-Host '== 未找到 exe,直接 sc delete 兜底 ==' -ForegroundColor Yellow
  & sc.exe delete BulwarkService 2>&1 | Out-Host
}

Get-Process -Name bulwark_ui -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue

if ($RemoveFiles) {
  Write-Host "== 删除安装目录 $InstallDir ==" -ForegroundColor Cyan
  if (Test-Path $InstallDir) { Remove-Item -Recurse -Force $InstallDir }
  Write-Host '注意:%ProgramData%\Bulwark 下的日志/规则/隔离区已保留(如需彻底清理请手动删除)。' -ForegroundColor Yellow
}

Write-Host "`n完成。BulwarkService 已停止并注销。" -ForegroundColor Green
