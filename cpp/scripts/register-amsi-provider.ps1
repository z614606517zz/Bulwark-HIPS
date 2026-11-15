#requires -Version 5.1
[CmdletBinding()]
param(
    [switch] $Unregister,
    [string] $DllPath,
    [switch] $Force
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# 必须与 cpp/amsi/Provider.cpp 的 kProviderClsid 一致。
$Clsid = '{0AAC68C8-BB18-4699-AA9E-B072C407CE6B}'

# 64 位与 32 位脚本宿主各读各的注册表视图:32 位 regsvr32 写 HKLM\SOFTWARE 时会被重定向到 WOW6432Node。
# 32 位宿主(SysWOW64 下的 PowerShell / wscript、32 位 Office 的宏)只加载 32 位提供程序。
$Views = @{
    x64 = @{
        RegSvr  = Join-Path $env:SystemRoot 'System32\regsvr32.exe'
        ClsKey  = "HKLM:\SOFTWARE\Classes\CLSID\$Clsid"
        AmsiKey = "HKLM:\SOFTWARE\Microsoft\AMSI\Providers\$Clsid"
        PsHost  = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    }
    x86 = @{
        RegSvr  = Join-Path $env:SystemRoot 'SysWOW64\regsvr32.exe'
        ClsKey  = "HKLM:\SOFTWARE\Classes\WOW6432Node\CLSID\$Clsid"
        AmsiKey = "HKLM:\SOFTWARE\WOW6432Node\Microsoft\AMSI\Providers\$Clsid"
        PsHost  = Join-Path $env:SystemRoot 'SysWOW64\WindowsPowerShell\v1.0\powershell.exe'
    }
}

function Assert-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($id)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw '需要管理员权限:注册项都在 HKLM 下。请在"以管理员身份运行"的 PowerShell 里重试。'
    }
}

function Get-DllArch {
    param([string] $Path)
    $bytes = [IO.File]::ReadAllBytes($Path)
    $peOff = [BitConverter]::ToInt32($bytes, 0x3C)
    switch ([BitConverter]::ToUInt16($bytes, $peOff + 4)) {
        0x8664 { return 'x64' }
        0xAA64 { return 'x64' }
        0x14C  { return 'x86' }
        default { throw "无法识别的 DLL 架构:$Path" }
    }
}

# 不指定 -DllPath 时:64 位必须有,32 位找到就一并注册。
function Resolve-Dlls {
    param([string] $Explicit)

    if ($Explicit) {
        if (-not (Test-Path -LiteralPath $Explicit)) { throw "找不到 DLL:$Explicit" }
        return @((Resolve-Path -LiteralPath $Explicit).Path)
    }

    $repo = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $x64 = @(
        Join-Path $repo 'cpp\dist\BulwarkAmsi.dll'
        Join-Path $repo 'cpp\build\amsi\Release\BulwarkAmsi.dll'
        Join-Path $repo 'cpp\build\amsi\Debug\BulwarkAmsi.dll'
        Join-Path $repo 'cpp\build\amsi\BulwarkAmsi.dll'
    )
    $x86 = @(
        Join-Path $repo 'cpp\dist\BulwarkAmsi32.dll'
        Join-Path $repo 'cpp\build_amsi_x86\Release\BulwarkAmsi32.dll'
    )
    $found = @()
    $hit = $x64 | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
    if (-not $hit) {
        throw ("没找到 BulwarkAmsi.dll。先构建它(cmake --build cpp\build --config Release --target BulwarkAmsi)," +
               "或用 -DllPath 显式指定。已查找:`n  " + ($x64 -join "`n  "))
    }
    $found += (Resolve-Path -LiteralPath $hit).Path
    $hit = $x86 | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
    if ($hit) {
        $found += (Resolve-Path -LiteralPath $hit).Path
    } else {
        Write-Warning ("没找到 32 位的 BulwarkAmsi32.dll,32 位脚本宿主将不送检。构建方法见 cpp/amsi/CMakeLists.txt 顶部。" +
                       "已查找:`n  " + ($x86 -join "`n  "))
    }
    return $found
}

# 在同架构的 PowerShell 里自查:-Command 的内容送检时提供程序就已加载。
# 不能从 64 位进程枚举 32 位进程的模块 —— 那样只看得到 64 位的那几个模块。
function Test-ProviderLoadable {
    param([string] $PsHost, [string] $ModuleName)
    $cmd = "`$m = [Diagnostics.Process]::GetCurrentProcess().Modules | Where-Object { `$_.ModuleName -ieq '$ModuleName' }; " +
           "if (`$m) { 'BLW_LOADED' } else { 'BLW_MISSING' }"
    $out = & $PsHost -NoProfile -NonInteractive -Command $cmd 2>$null
    return [bool]($out -contains 'BLW_LOADED')
}

function Register-Provider {
    param([string] $Dll)

    $arch = Get-DllArch $Dll
    $v = $Views[$arch]
    Write-Host ''
    Write-Host "提供程序 DLL:$Dll($arch)"

    $sig = Get-AuthenticodeSignature -LiteralPath $Dll
    Write-Host "签名状态:$($sig.Status)"
    if ($sig.Status -ne 'Valid') {
        $msg = @"
$(Split-Path $Dll -Leaf) 没有有效的 Authenticode 签名(当前状态:$($sig.Status))。

自 Windows 10 1903 起,未签名的 AMSI 提供程序【可能根本不被加载】,而且失败是完全静默的:
注册项都在、Bulwark 服务也在跑,但一条脚本送检都收不到 —— 也就是这一维防护看起来开着、
实际什么都没做。这比明确的失败危险得多,所以这里直接拒绝注册。

怎么办:
  · 正式发布:用代码签名证书签名(仓库根目录 scripts\sign-binaries.ps1 可参考);
  · 开发 / 隔离测试机:自建测试证书签名,并把它装进本机的「受信任的根证书颁发机构」
    与「受信任的发布者」,然后重新运行本脚本;
  · 确实只想在隔离虚拟机里先跑通链路:加 -Force 跳过本检查(注册后请务必看自检结果,
    自检会如实告诉你 DLL 到底有没有被宿主加载)。
"@
        if (-not $Force) { throw $msg }
        Write-Warning $msg
    }

    # regsvr32 是窗口程序,用 & 调用时不会等它结束,也不设 $LASTEXITCODE。
    $proc = Start-Process -FilePath $v.RegSvr -ArgumentList @('/s', "`"$Dll`"") -Wait -PassThru
    if ($proc.ExitCode -ne 0) { throw "$($v.RegSvr) 返回 $($proc.ExitCode),注册失败。" }

    $inproc = "$($v.ClsKey)\InprocServer32"
    $problems = @()
    if (-not (Test-Path -LiteralPath $inproc)) {
        $problems += "缺少 $inproc"
    } else {
        $p = Get-ItemProperty -LiteralPath $inproc
        if ($p.'(default)' -ne $Dll) { $problems += "InprocServer32 指向 [$($p.'(default)')],与本次注册的 [$Dll] 不一致" }
        if ($p.ThreadingModel -ne 'Both') { $problems += "ThreadingModel = [$($p.ThreadingModel)],应为 Both" }
    }
    if (-not (Test-Path -LiteralPath $v.AmsiKey)) { $problems += "缺少 $($v.AmsiKey)" }
    if ($problems) { throw ("注册不完整:`n  " + ($problems -join "`n  ")) }

    Write-Host '注册项已写入:' -ForegroundColor Green
    Write-Host "  $inproc"
    Write-Host "  $($v.AmsiKey)"

    Write-Host "自检:在 $arch 的 PowerShell 里检查本 DLL 是否已被加载…"
    if (Test-ProviderLoadable -PsHost $v.PsHost -ModuleName (Split-Path $Dll -Leaf)) {
        Write-Host "✓ $arch 提供程序已被 PowerShell 加载,链路通了。" -ForegroundColor Green
        return $true
    }
    Write-Warning @"
✗ 自检没在 $arch 的 PowerShell 模块表里找到 $(Split-Path $Dll -Leaf)。

注册项是齐的,但宿主没有加载它。按可能性排序:
  · DLL 未签名 / 签名链在本机不受信(最常见,见上面的签名说明);
  · 架构不符(64 位宿主加载不了 32 位 DLL,反之亦然);
  · DLL 缺依赖(本 DLL 刻意静态链接 CRT 以避免这一类问题,若你改过 CMake 请检查);
  · 本机有 WDAC / 代码完整性策略,拦下了这个 DLL。

在排除之前,请不要认为这一架构的脚本内容防护已经生效。
"@
    return $false
}

Assert-Admin

if ($Unregister) {
    foreach ($arch in @('x64', 'x86')) {
        $v = $Views[$arch]
        $inproc = "$($v.ClsKey)\InprocServer32"
        if (Test-Path -LiteralPath $inproc) {
            $registered = (Get-ItemProperty -LiteralPath $inproc).'(default)'
            if ($registered -and (Test-Path -LiteralPath $registered)) {
                Start-Process -FilePath $v.RegSvr -ArgumentList @('/u', '/s', "`"$registered`"") -Wait | Out-Null
            }
        }
        foreach ($k in @($v.AmsiKey, $v.ClsKey)) {
            if (Test-Path -LiteralPath $k) { Remove-Item -LiteralPath $k -Recurse -Force }
        }
        $left = @($v.AmsiKey, $v.ClsKey) | Where-Object { Test-Path -LiteralPath $_ }
        if ($left) { throw ("$arch 注册项未能全部删除,仍存在:`n  " + ($left -join "`n  ")) }
    }
    Write-Host '已反注册 Bulwark AMSI 提供程序(64 位与 32 位)。' -ForegroundColor Green
    Write-Host '注意:已经加载了本 DLL 的进程要重启才会真正卸载它(powershell / wscript / Office)。'
    return
}

$allLoaded = $true
foreach ($dll in (Resolve-Dlls -Explicit $DllPath)) {
    if (-not (Register-Provider -Dll $dll)) { $allLoaded = $false }
}

Write-Host ''
if ($allLoaded) {
    Write-Host '剩下两件事:'
    Write-Host '  1) Bulwark 服务必须在跑(它是裁决方)。服务没跑时提供程序一律放行 —— 这是刻意的'
    Write-Host '     fail-open 设计,见 cpp/amsi/PipeClient.h 顶部说明。'
    Write-Host '  2) appsettings.json 里 AmsiProviderEnabled 不能是 false(默认 true)。'
}
