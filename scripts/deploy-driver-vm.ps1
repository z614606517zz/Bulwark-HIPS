[CmdletBinding()]
param(
    [ValidateSet("Debug", "Release")]
    [string]$Configuration = "Debug",
    [string]$CertName = "BulwarkTestCert",
    [switch]$SetServiceMode
)

$ErrorActionPreference = "Stop"

$wi = [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not (New-Object Security.Principal.WindowsPrincipal($wi)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "请以【管理员】身份运行本脚本。"
}

$root = Split-Path -Parent $PSScriptRoot
if (-not $root) { $root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path) }
$sys = Join-Path $root "build\driver\$Configuration\Bulwark.sys"
$serviceName = "Bulwark"
$altitude    = "385201"
$instance    = "Bulwark Instance"
$driversDst  = Join-Path $env:SystemRoot "System32\drivers\Bulwark.sys"

if (-not (Test-Path $sys)) {
    throw "未找到驱动: $sys`n请先运行:  powershell -File scripts\build-driver.ps1 -Configuration $Configuration"
}

Write-Host "==== 磐垒 内核驱动 测试签名 + 加载(Minifilter)====" -ForegroundColor Cyan
Write-Host "⚠ 内核回调出错会蓝屏。请确认已在测试机/已建还原点。" -ForegroundColor Red

$bcdeditExe = if (Test-Path "$env:SystemRoot\Sysnative\bcdedit.exe") { "$env:SystemRoot\Sysnative\bcdedit.exe" } else { "$env:SystemRoot\System32\bcdedit.exe" }
$ts = (& $bcdeditExe | Select-String "testsigning") -join " "
if ($ts -notmatch "Yes") {
    Write-Host "[1/6] 测试签名未开启,正在开启(重启后生效)..." -ForegroundColor Yellow
    & $bcdeditExe /set testsigning on | Out-Host
    Write-Host "    请【重启】后重新运行本脚本。" -ForegroundColor Yellow
    return
}
Write-Host "[1/6] 测试签名已开启。" -ForegroundColor Green

$cert = Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.Subject -eq "CN=$CertName" -and $_.HasPrivateKey -and $_.NotAfter -gt (Get-Date) -and ((($_.EnhancedKeyUsageList | ForEach-Object { $_.ObjectId }) -contains '1.3.6.1.5.5.7.3.3')) } | Select-Object -First 1
if (-not $cert) {
    Write-Host "[2/6] 创建并信任测试证书 CN=$CertName ..." -ForegroundColor Cyan
    Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.Subject -eq "CN=$CertName" } | ForEach-Object { Remove-Item $_.PSPath -Force -ErrorAction SilentlyContinue }
    $cert = New-SelfSignedCertificate -Type CodeSigningCert -Subject "CN=$CertName" `
        -CertStoreLocation Cert:\LocalMachine\My -KeyUsage DigitalSignature `
        -KeySpec Signature -HashAlgorithm SHA256
    foreach ($storeName in @("Root", "TrustedPublisher")) {
        $st = New-Object System.Security.Cryptography.X509Certificates.X509Store($storeName, "LocalMachine")
        $st.Open("ReadWrite"); $st.Add($cert); $st.Close()
    }
} else {
    Write-Host "[2/6] 复用已有测试证书 CN=$CertName(有私钥、未过期、含代码签名用途)。" -ForegroundColor Green
}

$signtool = Get-ChildItem "C:\Program Files (x86)\Windows Kits\10\bin" -Recurse -Filter signtool.exe -ErrorAction SilentlyContinue |
    Where-Object { $_.FullName -match "\\x64\\" } | Sort-Object FullName -Descending | Select-Object -First 1
if (-not $signtool) { throw "未找到 signtool.exe(需安装 WDK/SDK)。" }
Write-Host "[3/6] 签名驱动 ($($signtool.FullName)) 指纹 $($cert.Thumbprint)..." -ForegroundColor Cyan
& $signtool.FullName sign /v /fd SHA256 /sm /s My /sha1 $cert.Thumbprint /t http://timestamp.digicert.com $sys
if ($LASTEXITCODE -ne 0) {
    Write-Host "    带时间戳签名失败,改用无时间戳(测试签名可接受)..." -ForegroundColor Yellow
    & $signtool.FullName sign /v /fd SHA256 /sm /s My /sha1 $cert.Thumbprint $sys
    if ($LASTEXITCODE -ne 0) { throw "signtool 签名失败。" }
}

Write-Host "[4/6] 停止旧实例并复制到 $driversDst ..." -ForegroundColor Cyan
& fltmc unload $serviceName  2>$null | Out-Null
& sc.exe stop $serviceName   2>$null | Out-Null
Start-Sleep -Seconds 1
Copy-Item $sys $driversDst -Force

Write-Host "[5/6] 注册 Minifilter 服务 $serviceName ..." -ForegroundColor Cyan
$existing = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
if ($existing) { & sc.exe delete $serviceName 2>$null | Out-Null; Start-Sleep -Seconds 1 }
& sc.exe create $serviceName type= filesys start= demand `
    binPath= "System32\drivers\Bulwark.sys" depend= FltMgr group= "FSFilter Activity Monitor" | Out-Host

$svcKey = "HKLM\SYSTEM\CurrentControlSet\Services\$serviceName"
& reg.exe add "$svcKey\Instances" /v DefaultInstance /t REG_SZ /d $instance /f | Out-Null
& reg.exe add "$svcKey\Instances\$instance" /v Altitude /t REG_SZ  /d $altitude /f | Out-Null
& reg.exe add "$svcKey\Instances\$instance" /v Flags    /t REG_DWORD /d 0 /f | Out-Null

Write-Host "[6/6] 加载驱动..." -ForegroundColor Cyan
& fltmc load $serviceName | Out-Host
if ($LASTEXITCODE -ne 0) { & sc.exe start $serviceName | Out-Host }

Start-Sleep -Seconds 1
$loaded = (& fltmc filters | Select-String -SimpleMatch $serviceName) -ne $null
if ($loaded) {
    Write-Host "`n✅ 驱动已加载(fltmc filters 可见 $serviceName)。" -ForegroundColor Green
} else {
    Write-Host "`n⚠ 未在 fltmc filters 看到 $serviceName。用 scripts\..\诊断驱动.bat 或 'sc query Bulwark' 排查。" -ForegroundColor Yellow
}

if ($SetServiceMode) {
    $appsettings = Join-Path $root "cpp\service\appsettings.json"
    if (Test-Path $appsettings) {
        $json = Get-Content $appsettings -Raw
        $new = [regex]::Replace($json, '("EventSource"\s*:\s*")[^"]*(")', '${1}Driver${2}')
        Set-Content $appsettings $new -NoNewline -Encoding UTF8
        Write-Host "已把 $appsettings 的 EventSource 改为 Driver。" -ForegroundColor Green
    } else {
        Write-Host "未找到 $appsettings,跳过 EventSource 切换。" -ForegroundColor Yellow
    }
}

Write-Host "`n下一步:以管理员启动用户态服务(EventSource=Driver)后,它会连接 \BulwarkPort," -ForegroundColor Cyan
Write-Host "        做协议握手并下发受保护项;此时才是真正的『行为前』内核拦截。" -ForegroundColor Cyan
Write-Host "查看内核日志:DebugView(勾选 Capture Kernel);卸载:fltmc unload Bulwark; sc delete Bulwark" -ForegroundColor DarkGray
