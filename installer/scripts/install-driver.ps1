#Requires -Version 5.1
<#
.SYNOPSIS
    Bulwark 内核驱动安装助手(安装包在安装阶段调用,也可手动运行)。

.DESCRIPTION
    按顺序完成:
      1) 把 Bulwark.sys 部署到 %SystemRoot%\System32\drivers\
      2) 注册 minifilter 驱动服务(type=filesys + FltMgr 依赖 +
         Instances\DefaultInstance + Altitude=385201 + Flags=0)
      3) 可选:开启测试签名模式(bcdedit /set testsigning on)
      4) 可选:自动个人签名 —— 创建本机个人代码签名证书并签名驱动

    与 cpp/service/src/DriverControl.cpp::ensureRegistered 的注册方式保持一致。

.EXAMPLE
    powershell -NoProfile -ExecutionPolicy Bypass -File install-driver.ps1 `
        -SysSource "C:\Program Files\Bulwark\Bulwark.sys" -EnableTestSigning -SelfSign
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$SysSource,

    [switch]$EnableTestSigning,

    [switch]$SelfSign,

    [string]$CertSubject = 'CN=Bulwark Local Driver Signing'
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

function Write-Step   ($m) { Write-Host "==> $m" -ForegroundColor Cyan }
function Write-Ok     ($m) { Write-Host "    [OK] $m" -ForegroundColor Green }
function Write-Caution($m) { Write-Host "    [!] $m" -ForegroundColor Yellow }
function Write-Bad    ($m) { Write-Host "    [X] $m" -ForegroundColor Red }

$script:failures = New-Object System.Collections.Generic.List[string]
function Fail($m) {
    $script:failures.Add($m) | Out-Null
    Write-Bad $m
}

# 通用签名
# Set-AuthenticodeSignature 对 CNG 私钥证书会报
# "No provider was specified for the store or object"(签名静默不生效),
# 因此证书必须用传统 CSP 创建,见 New-LocalSigner。
#
# 文件被已加载的脚本宿主占用时(典型:AMSI 提供程序被 powershell.exe 加载),
# 直签会抛"文件正由另一进程使用"。此时把副本签好,再用改名交换换上去 ——
# Windows 允许对已加载映像改名,新进程会加载到已签名的那份。
function Invoke-SignFile {
    param([string]$Path, $Cert)

    try {
        $r = Set-AuthenticodeSignature -FilePath $Path -Certificate $Cert -HashAlgorithm SHA256
        if ($r.Status -eq 'Valid') {
            return @{ Ok = $true; Msg = '已签名' }
        }
        $firstMsg = "$($r.Status): $($r.StatusMessage)"
    } catch {
        $firstMsg = $_.Exception.Message
    }

    # 直签失败 → 副本签名 + 改名交换
    try {
        $swapDir = Join-Path $env:TEMP 'bulwark-sign-swap'
        New-Item -ItemType Directory -Path $swapDir -Force | Out-Null
        $tmpCopy = Join-Path $swapDir ([IO.Path]::GetFileName($Path))
        Copy-Item -LiteralPath $Path -Destination $tmpCopy -Force

        $r2 = Set-AuthenticodeSignature -FilePath $tmpCopy -Certificate $Cert -HashAlgorithm SHA256
        if ($r2.Status -ne 'Valid') {
            return @{ Ok = $false; Msg = "直签失败[$firstMsg];副本签名也失败[$($r2.StatusMessage)]" }
        }

        $old = "$Path.old-$(Get-Date -Format 'yyyyMMddHHmmss')"
        Move-Item -LiteralPath $Path -Destination $old -Force
        Copy-Item -LiteralPath $tmpCopy -Destination $Path -Force
        Remove-Item $tmpCopy -Force -ErrorAction SilentlyContinue
        return @{ Ok = $true; Msg = "已签名(文件被占用,已换名交换;旧副本 $old 重启后可删)" }
    } catch {
        return @{ Ok = $false; Msg = "直签失败[$firstMsg];换名交换也失败[$($_.Exception.Message)]" }
    }
}

# 证书
function Resolve-LocalSigner {
    param([string]$Subject)

    # 只有传统 CSP(RSACryptoServiceProvider)私钥才能被 Set-AuthenticodeSignature 使用;
    # New-SelfSignedCertificate 默认生成的 CNG 私钥证书 .PrivateKey 为 $null,不能用。
    $cands = @(Get-ChildItem Cert:\LocalMachine\My -ErrorAction SilentlyContinue |
               Where-Object { $_.Subject -eq $Subject -and $_.HasPrivateKey })
    foreach ($c in $cands) {
        if ($null -ne $c.PrivateKey) {
            if ($c.NotAfter -gt (Get-Date).AddDays(30)) {
                return @{ Cert = $c; Created = $false }
            }
        } else {
            # 不可用的 CNG 证书:清掉,避免下次又误用它
            try { $c | Remove-Item -Force } catch { }
        }
    }

    $cert = New-SelfSignedCertificate -Subject $Subject -Type CodeSigningCert `
                -CertStoreLocation Cert:\LocalMachine\My `
                -KeyExportPolicy NonExportable -KeyLength 2048 `
                -Provider 'Microsoft Enhanced RSA and AES Cryptographic Provider' `
                -NotAfter (Get-Date).AddYears(5) -ErrorAction Stop
    return @{ Cert = $cert; Created = $true }
}

# 权限检查
$id = [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw '请以管理员身份运行本脚本。'
}

# 环境体检
Write-Step '检查系统前置条件'
$secureBoot = $false
try { $secureBoot = [bool](Confirm-SecureBootUEFI) } catch { $secureBoot = $false }
$hvci = $false
try {
    $dg = Get-CimInstance -Namespace root\Microsoft\Windows\DeviceGuard `
                          -ClassName Win32_DeviceGuard -ErrorAction Stop
    if ($dg.SecurityServicesRunning -contains 2) { $hvci = $true }
} catch { }
if ($secureBoot) {
    Write-Caution 'Secure Boot 已开启:测试签名不会生效,请进入 BIOS/UEFI 关闭后重试。'
} else {
    Write-Ok 'Secure Boot 未开启。'
}
if ($hvci) {
    Write-Caution '内存完整性 (HVCI) 已开启:第三方驱动会被拒绝加载,请在 Windows 安全中心 > 设备安全性 > 内核隔离 里关闭。'
} else {
    Write-Ok 'HVCI 未开启。'
}

# 1. 部署驱动文件
Write-Step '部署 Bulwark.sys 到 System32\drivers'
if (-not (Test-Path -LiteralPath $SysSource)) {
    throw "找不到驱动源文件:$SysSource"
}
$dstSys = Join-Path $env:SystemRoot 'System32\drivers\Bulwark.sys'
try {
    Copy-Item -LiteralPath $SysSource -Destination $dstSys -Force
    Write-Ok "已复制到 $dstSys"
} catch {
    Fail "部署驱动文件失败:$($_.Exception.Message)"
}

# 2. 注册驱动服务
Write-Step '注册内核驱动服务 (Bulwark / minifilter Altitude=385201)'
try {
    $svc = Get-Service -Name 'Bulwark' -ErrorAction SilentlyContinue
    if (-not $svc) {
        $create = & sc.exe create Bulwark type= filesys start= demand `
                        binPath= 'System32\drivers\Bulwark.sys' `
                        depend= FltMgr group= 'FSFilter Activity Monitor' 2>&1
        if ($LASTEXITCODE -ne 0) {
            Write-Caution "sc create 未成功(改为直接写注册表):$create"
            $key = 'HKLM:\SYSTEM\CurrentControlSet\Services\Bulwark'
            if (-not (Test-Path $key)) { New-Item -Path $key -Force | Out-Null }
            Set-ItemProperty -Path $key -Name 'Type'         -Value 2 -Type DWord
            Set-ItemProperty -Path $key -Name 'Start'        -Value 3 -Type DWord
            Set-ItemProperty -Path $key -Name 'ErrorControl' -Value 1 -Type DWord
            Set-ItemProperty -Path $key -Name 'ImagePath'    -Value 'System32\drivers\Bulwark.sys' -Type ExpandString
            Set-ItemProperty -Path $key -Name 'DisplayName'  -Value 'Bulwark' -Type String
            Set-ItemProperty -Path $key -Name 'Group'        -Value 'FSFilter Activity Monitor' -Type String
            Set-ItemProperty -Path $key -Name 'DependOnService' -Value @('FltMgr') -Type MultiString
        }
    } else {
        Write-Ok '驱动服务条目已存在,跳过创建。'
    }

    # minifilter 实例配置:少了它驱动不挂载任何卷,文件/注册表防护全部静默失效
    $instKey  = 'HKLM:\SYSTEM\CurrentControlSet\Services\Bulwark\Instances'
    $instName = 'Bulwark Instance'
    if (-not (Test-Path $instKey)) { New-Item -Path $instKey -Force | Out-Null }
    Set-ItemProperty -Path $instKey -Name 'DefaultInstance' -Value $instName -Type String
    $sub = Join-Path $instKey $instName
    if (-not (Test-Path $sub)) { New-Item -Path $sub -Force | Out-Null }
    Set-ItemProperty -Path $sub -Name 'Altitude' -Value '385201' -Type String
    Set-ItemProperty -Path $sub -Name 'Flags'    -Value 0 -Type DWord
    Write-Ok '服务条目 + Instances\DefaultInstance + Altitude=385201 配置完成。'
} catch {
    Fail "注册驱动服务失败:$($_.Exception.Message)"
}

# 3. 测试签名模式
if ($EnableTestSigning) {
    Write-Step '开启测试签名模式 (bcdedit /set testsigning on)'
    $enumOut = & bcdedit.exe /enum '{current}' 2>&1
    $enumExit = $LASTEXITCODE
    if ($enumExit -ne 0) {
        Fail "无法读取 testsigning 原始状态(bcdedit 退出码 $enumExit):$enumOut"
    } else {
        $wasOn = [bool]($enumOut | Select-String -Pattern 'testsigning.*(Yes|是)' -CaseSensitive:$false)
        $bcdOut = & bcdedit.exe /set testsigning on 2>&1
        $bcdExit = $LASTEXITCODE
        if ($bcdExit -ne 0) {
            Fail "开启测试签名模式失败(bcdedit 退出码 $bcdExit):$bcdOut"
        } else {
            $productKey = 'HKLM:\SOFTWARE\Bulwark'
            if (-not (Test-Path $productKey)) { New-Item -Path $productKey -Force | Out-Null }
            if ($wasOn) {
                Remove-ItemProperty -Path $productKey -Name 'TestSigningEnabledByBulwark' -ErrorAction SilentlyContinue
                Write-Ok '测试签名原本已开启;不会把它登记为本产品所有。'
            } else {
                Set-ItemProperty -Path $productKey -Name 'TestSigningEnabledByBulwark' -Value 1 -Type DWord
                Write-Ok '测试签名已开启,并记录为本次安装所启用。'
            }
            Write-Ok '重启电脑后生效(桌面右下角会出现“测试模式”水印)。'
        }
    }
} else {
    Write-Step '跳过测试签名模式(安装时未勾选)'
}

# 4. 自动个人签名
if ($SelfSign) {
    Write-Step "自动个人签名 (证书主题 $CertSubject)"

    $cert = $null
    try {
        $got = Resolve-LocalSigner -Subject $CertSubject
        $cert = $got.Cert
        if ($got.Created) {
            Write-Ok "已创建个人证书(传统 CSP 私钥),指纹 $($cert.Thumbprint)"
        } else {
            Write-Ok "复用本机已有证书,指纹 $($cert.Thumbprint)"
        }
    } catch {
        Fail "创建签名证书失败:$($_.Exception.Message)"
    }

    if ($cert) {
        $productKey = 'HKLM:\SOFTWARE\Bulwark'
        if (-not (Test-Path $productKey)) { New-Item -Path $productKey -Force | Out-Null }
        $existing = Get-ItemProperty -Path $productKey -ErrorAction SilentlyContinue
        $wasPreviouslyOwned = (($existing.DriverSignerCreatedByBulwark -eq 1) -and
                               ($existing.DriverSignerThumbprint -eq $cert.Thumbprint))
        $ownedByBulwark = $got.Created -or $wasPreviouslyOwned
        Set-ItemProperty -Path $productKey -Name 'DriverSignerThumbprint' `
                         -Value $cert.Thumbprint.ToUpper() -Type String
        Set-ItemProperty -Path $productKey -Name 'DriverSignerCreatedByBulwark' `
                         -Value $(if ($ownedByBulwark) { 1 } else { 0 }) -Type DWord

        # 信任链:Root 建链,TrustedPublisher 压掉签名提示
        try {
            $tmpCer = Join-Path $env:TEMP 'bulwark-local-signer.cer'
            [IO.File]::WriteAllBytes($tmpCer, $cert.Export('Cert'))
            foreach ($store in @('Root', 'TrustedPublisher')) {
                $have = Get-ChildItem ("Cert:\LocalMachine\" + $store) -ErrorAction SilentlyContinue |
                        Where-Object { $_.Thumbprint -eq $cert.Thumbprint }
                if ($have) {
                    Write-Ok "信任 store [$store] 已包含该证书。"
                } else {
                    Import-Certificate -FilePath $tmpCer `
                        -CertStoreLocation ("Cert:\LocalMachine\" + $store) -ErrorAction Stop | Out-Null
                    Write-Ok "已导入信任 store:$store"
                }
            }
            Remove-Item $tmpCer -Force -ErrorAction SilentlyContinue
        } catch {
            Fail "导入信任证书失败:$($_.Exception.Message)"
        }

        # 签名 System32 里的驱动副本(真正被内核加载的那一份)
        if (Test-Path -LiteralPath $dstSys) {
            $res = Invoke-SignFile -Path $dstSys -Cert $cert
            if ($res.Ok) {
                Write-Ok "驱动签名:$($res.Msg)"
                $chk = Get-AuthenticodeSignature -LiteralPath $dstSys
                if ($chk.Status -eq 'Valid') {
                    Write-Ok "驱动签名已验证:$(($chk.SignerCertificate).Subject)"
                } else {
                    Fail "驱动签名后校验仍未通过:$($chk.Status) $($chk.StatusMessage)"
                }
            } else {
                Fail "驱动签名失败:$($res.Msg)"
            }
        }

        # 顺带签 AMSI 提供程序(64 位宿主才会加载它);失败不影响驱动,只提示
        $amsi = Join-Path (Split-Path -Parent $PSScriptRoot) 'BulwarkAmsi.dll'
        if (Test-Path -LiteralPath $amsi) {
            $res2 = Invoke-SignFile -Path $amsi -Cert $cert
            if ($res2.Ok) {
                Write-Ok "AMSI 提供程序签名:$($res2.Msg)"
            } else {
                Write-Caution "AMSI 提供程序签名跳过(不影响驱动加载):$($res2.Msg)"
            }
        }
    }
} else {
    Write-Step '跳过自动个人签名(安装时未勾选)'
}

# 总结
Write-Host ''
if ($script:failures.Count -gt 0) {
    Write-Host "=== 驱动安装完成,但有 $($script:failures.Count) 项失败 ===" -ForegroundColor Red
    foreach ($f in $script:failures) { Write-Host "   - $f" -ForegroundColor Red }
    Write-Host '请把上面的失败信息发回排查,或稍后手动以管理员身份重新运行本脚本。' -ForegroundColor Yellow
    exit 1
}
Write-Host '=== 驱动安装流程结束(全部成功) ===' -ForegroundColor Green
if ($EnableTestSigning) {
    Write-Host '提醒:测试签名模式重启后才生效;重启前驱动无法加载。' -ForegroundColor Yellow
}
exit 0
