#Requires -Version 5.1
<#
.SYNOPSIS
    Bulwark 内核驱动卸载助手(卸载程序在卸载阶段调用,也可手动运行)。

.DESCRIPTION
    两项清理均可选(卸载程序按用户勾选传入):
      -RemoveDriver yes|no        停止并注销内核驱动服务、删除 System32\drivers\Bulwark.sys、
                                  移除个人签名证书(证书只服务于驱动签名,随驱动一起清)
      -DisableTestSigning yes|no  退出测试签名模式(bcdedit /set testsigning off)

    两个参数默认 yes(手动裸跑 = 全部清理)。传 no 表示保留该项。

.EXAMPLE
    powershell -NoProfile -ExecutionPolicy Bypass -File uninstall-driver.ps1
.EXAMPLE
    powershell -NoProfile -ExecutionPolicy Bypass -File uninstall-driver.ps1 `
        -RemoveDriver yes -DisableTestSigning no
#>
[CmdletBinding()]
param(
    [ValidateSet('yes', 'no')][string]$RemoveDriver = 'yes',
    [ValidateSet('yes', 'no')][string]$DisableTestSigning = 'yes',
    [string]$CertSubject = 'CN=Bulwark Local Driver Signing'
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

function Write-Step   ($m) { Write-Host "==> $m" -ForegroundColor Cyan }
function Write-Ok     ($m) { Write-Host "    $m" -ForegroundColor Green }
function Write-Note   ($m) { Write-Host "    $m" -ForegroundColor Gray }
function Write-Caution($m) { Write-Host "    [!] $m" -ForegroundColor Yellow }

$script:failures = New-Object System.Collections.Generic.List[string]
function Add-Failure($m) {
    $script:failures.Add([string]$m) | Out-Null
    Write-Caution $m
}

$doDriver = ($RemoveDriver -ne 'no')
$doTest   = ($DisableTestSigning -ne 'no')

# 权限检查
$id = [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw '请以管理员身份运行本脚本。'
}

if (-not $doDriver -and -not $doTest) {
    Write-Host '=== 未选择任何系统级清理项:保留内核驱动与测试模式,只移除程序文件。 ===' -ForegroundColor Yellow
    exit 0
}

# 1. 卸载内核驱动
if ($doDriver) {
    Write-Step '停止内核驱动'
    $fltOut = & fltmc.exe unload Bulwark 2>&1
    $fltExit = $LASTEXITCODE
    $scOut = & sc.exe stop Bulwark 2>&1
    $scExit = $LASTEXITCODE
    Start-Sleep -Seconds 1

    # 解绑所有卷实例后再重试可拒绝的 FilterUnload。
    $instances = & fltmc.exe instances -f Bulwark 2>&1
    if ($LASTEXITCODE -eq 0) {
        $instances | Select-String -Pattern '^\s+\d+\s+' | ForEach-Object {
            $parts = $_ -split '\s+'
            if ($parts.Count -ge 3) {
                & fltmc.exe detach Bulwark -Volume $parts[2] 2>&1 | Out-Null
            }
        }
        $fltOut = & fltmc.exe unload Bulwark 2>&1
        $fltExit = $LASTEXITCODE
    }

    $filters = & fltmc.exe filters 2>&1
    $stillLoaded = ($LASTEXITCODE -eq 0) -and
                   [bool]($filters | Select-String -Pattern '^Bulwark\s' -CaseSensitive:$false)
    if ($stillLoaded) {
        Add-Failure "驱动仍处于加载状态;不会删除服务、文件或签名证书。fltmc=$fltExit sc=$scExit"
    } else {
        Write-Ok '驱动已停止。'
    }

    if (-not $stillLoaded) {
    Write-Step '注销驱动服务'
    $scDeleteOut = & sc.exe delete Bulwark 2>&1
    $scDeleteExit = $LASTEXITCODE
    $key = 'HKLM:\SYSTEM\CurrentControlSet\Services\Bulwark'
    if (Test-Path $key) {
        Remove-Item -Path $key -Recurse -Force -ErrorAction SilentlyContinue
    }
    if (Test-Path $key) {
        Add-Failure "驱动服务注册表键仍残留(sc delete=$scDeleteExit):$scDeleteOut"
    } else {
        Write-Ok '驱动服务条目已删除。'
    }

    Write-Step '删除 System32\drivers\Bulwark.sys'
    $dstSys = Join-Path $env:SystemRoot 'System32\drivers\Bulwark.sys'
    if (Test-Path -LiteralPath $dstSys) {
        try {
            Remove-Item -LiteralPath $dstSys -Force -ErrorAction Stop
            Write-Ok "已删除:$dstSys"
        } catch {
            # 被占用时改名,重启后不会再被加载
            try {
                Rename-Item -LiteralPath $dstSys -NewName 'Bulwark.sys.pending-delete' -Force
                Write-Caution '文件被占用,已改名为 Bulwark.sys.pending-delete,重启后可手动删除。'
            } catch {
                Add-Failure "删除或改名驱动文件失败:$($_.Exception.Message)"
            }
        }
    } else {
        Write-Note '驱动文件不存在,跳过。'
    }

    Write-Step "移除本产品创建的个人签名证书 ($CertSubject)"
    $productKey = 'HKLM:\SOFTWARE\Bulwark'
    $state = Get-ItemProperty -Path $productKey -ErrorAction SilentlyContinue
    $ownedThumbprint = [string]$state.DriverSignerThumbprint
    $owned = ($state.DriverSignerCreatedByBulwark -eq 1) -and ($ownedThumbprint.Length -eq 40)
    if ($owned) {
        foreach ($store in @('My', 'Root', 'TrustedPublisher')) {
            $found = Get-ChildItem ("Cert:\LocalMachine\" + $store) -ErrorAction SilentlyContinue |
                     Where-Object { $_.Thumbprint -eq $ownedThumbprint }
            foreach ($c in $found) {
                try {
                    $c | Remove-Item -Force -ErrorAction Stop
                    Write-Ok "已从 [$store] 移除本产品证书,指纹 $($c.Thumbprint)"
                } catch {
                    Add-Failure "从 [$store] 移除证书失败:$($_.Exception.Message)"
                }
            }
        }
        Remove-ItemProperty -Path $productKey -Name 'DriverSignerThumbprint' -ErrorAction SilentlyContinue
        Remove-ItemProperty -Path $productKey -Name 'DriverSignerCreatedByBulwark' -ErrorAction SilentlyContinue
    } else {
        Write-Note '没有本产品创建证书的受保护指纹记录;不会按 Subject 批量删除任何证书。'
    }
    }
} else {
    Write-Step '保留内核驱动(未勾选卸载)—— 驱动服务、Bulwark.sys 与签名证书保持原样。'
}

# 2. 退出测试模式
if ($doTest) {
    Write-Step '恢复测试签名模式原始状态'
    $productKey = 'HKLM:\SOFTWARE\Bulwark'
    $state = Get-ItemProperty -Path $productKey -ErrorAction SilentlyContinue
    if ($state.TestSigningEnabledByBulwark -ne 1) {
        Write-Note '测试签名不是由本产品开启(或缺少受保护记录),保持当前系统设置不变。'
    } else {
        $bcdOut = & bcdedit.exe /set testsigning off 2>&1
        $bcdExit = $LASTEXITCODE
        if ($bcdExit -ne 0) {
            Add-Failure "退出测试签名模式失败(bcdedit 退出码 $bcdExit):$bcdOut"
        } else {
            Remove-ItemProperty -Path $productKey -Name 'TestSigningEnabledByBulwark' -ErrorAction SilentlyContinue
            Write-Ok '已关闭本产品安装时开启的测试签名模式;重启后生效。'
        }
    }
} else {
    Write-Step '保留测试签名模式(未勾选退出)。'
}

Write-Host ''
if ($script:failures.Count -gt 0) {
    Write-Host "=== 驱动卸载未完成:$($script:failures.Count) 项失败 ===" -ForegroundColor Red
    foreach ($f in $script:failures) { Write-Host "   - $f" -ForegroundColor Red }
    exit 1
}
Write-Host '=== 驱动卸载流程结束(全部成功) ===' -ForegroundColor Green
exit 0
