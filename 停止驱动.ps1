$ErrorActionPreference = 'Stop'

if (-not [Environment]::Is64BitProcess) {
    $ps64 = Join-Path $env:SystemRoot 'Sysnative\WindowsPowerShell\v1.0\powershell.exe'
    if (Test-Path $ps64) {
        & $ps64 -NoProfile -ExecutionPolicy Bypass -File $PSCommandPath
        exit $LASTEXITCODE
    }
}

$id = [Security.Principal.WindowsIdentity]::GetCurrent()
$isAdmin = (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "正在请求管理员权限..." -ForegroundColor Yellow
    Start-Process powershell -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
    exit
}

Write-Host "=============== 停止 Bulwark 内核驱动 ===============" -ForegroundColor Cyan

$env:Path = "$env:SystemRoot\System32;$env:SystemRoot\System32\WindowsPowerShell\v1.0;$env:Path"

Write-Host "[1/5] 停止用户态服务 BulwarkService ..." -ForegroundColor Yellow
& sc.exe stop BulwarkService 2>&1 | Out-Host

Write-Host "[2/5] fltmc unload Bulwark ..." -ForegroundColor Yellow
& fltmc.exe unload Bulwark 2>&1 | Out-Host

Write-Host "[3/5] sc stop Bulwark ..." -ForegroundColor Yellow
& sc.exe stop Bulwark 2>&1 | Out-Host

Write-Host "[4/5] 清理 fltmc 实例 ..." -ForegroundColor Yellow
$instances = & fltmc.exe instances -f Bulwark 2>&1
if ($LASTEXITCODE -eq 0) {
    fltmc.exe instances -f Bulwark | Select-String -Pattern '^\s+\d+\s+' | ForEach-Object {
        $parts = $_ -split '\s+'
        if ($parts.Count -ge 3) {
            $vol = $parts[2]
            Write-Host "  detach from $vol ..."
            fltmc.exe detach Bulwark -Volume $vol 2>&1 | Out-Null
        }
    }
    & fltmc.exe unload Bulwark 2>&1 | Out-Host
}

Write-Host "[5/5] 最终状态检查 ..." -ForegroundColor Yellow
$svc = Get-Service Bulwark -ErrorAction SilentlyContinue
if ($svc -and $svc.Status -eq 'Running') {
    Write-Host "[!] 驱动仍在运行。尝试禁用后重启电脑:" -ForegroundColor Red
    Write-Host "    sc config Bulwark start= disabled" -ForegroundColor Gray
    Write-Host "    然后重启电脑。" -ForegroundColor Gray
} elseif ($svc) {
    Write-Host "[OK] 驱动已停止(状态: $($svc.Status))" -ForegroundColor Green
} else {
    Write-Host "[OK] 驱动服务已不存在" -ForegroundColor Green
}

Write-Host "======================================================" -ForegroundColor Cyan
pause
