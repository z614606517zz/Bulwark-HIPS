#requires -Version 5.1
<#
驱动冒烟测试:在本机加载驱动,复测受保护目录、整棵恢复、界面防注入等内核把关,测完卸载并复原。

前提:管理员 PowerShell;本产品服务处于待机或已停止(驱动未加载);本机有 D 盘;
      已构建 driver_smoke_probe(cmake --build <构建目录> --config Release --target driver_smoke_probe)。

会临时改动、测完复原:
  · HKLM\SYSTEM\CurrentControlSet\Services\Bulwark\Policy 的 GuardDirs、ReadGuard、ReadGuardReaders 各加一条测试项,
    测完删掉并逐行核对;
  · D:\BULWARK_KTEST、D:\BULWARK_KTEST_OUT、D:\BULWARK_KTEST_READER(放探针副本)与两个注册表测试键,测完删除;
  · 加 -InstallFromDist 时,把 cpp\dist\Bulwark.sys 覆盖到 System32\drivers(原文件先备份,不自动还原)。

内核代码有问题时加载可能蓝屏,只在可以承受的机器上跑。
#>
[CmdletBinding()]
param(
    [string] $ProbePath,
    [string] $UiPath = 'C:\Program Files\Bulwark\bulwark_ui.exe',
    [switch] $InstallFromDist
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$root      = Split-Path -Parent $PSScriptRoot
$policyKey = 'HKLM:\SYSTEM\CurrentControlSet\Services\Bulwark\Policy'
$policyReg = 'HKLM\SYSTEM\CurrentControlSet\Services\Bulwark\Policy'
$testEntry = '\BULWARK_KTEST\GUARD\'
# 窃密防护:SECRET 目录是敏感数据,读者写成本探针绝不匹配的假目录,所以 guard 跑的原探针会被拒;
# 另把一个副本放进登记为全局读者的目录,reader 跑的副本应当读得到。
$readEntry       = '\BULWARK_KTEST\SECRET\|\NO\SUCH\READER\'
$readerDirEntry  = '\BULWARK_KTEST_READER\'
$readerDir       = 'D:\BULWARK_KTEST_READER'
$fltmc     = Join-Path $env:SystemRoot 'System32\fltmc.exe'

function Step($m) { Write-Host "==> $m" -ForegroundColor Cyan }
function Fail($m) { Write-Host "[失败] $m" -ForegroundColor Red; exit 1 }
function Test-DriverLoaded { return [bool](& $fltmc filters | Select-String -SimpleMatch 'Bulwark') }

function Test-PolicyValue($name) {
    return $null -ne (Get-ItemProperty -Path $policyKey -Name $name -ErrorAction SilentlyContinue)
}

# Policy 里某个 REG_MULTI_SZ 名单加一条测试项。
function Add-PolicyEntry($name, $entry) {
    $cur = @()
    if (Test-PolicyValue $name) { $cur = @((Get-ItemProperty -Path $policyKey -Name $name).$name) }
    if ($cur -notcontains $entry) { $cur += $entry }
    Set-ItemProperty -Path $policyKey -Name $name -Value ([string[]]$cur) -Type MultiString
}

# $had 是测试前这个值是否存在(须在改动前取):存在则只摘掉测试项,不存在则整个值删掉。
function Remove-PolicyEntry($name, $entry, $had) {
    if ($had) {
        $cur = @((Get-ItemProperty -Path $policyKey -Name $name).$name) | Where-Object { $_ -ne $entry }
        Set-ItemProperty -Path $policyKey -Name $name -Value ([string[]]$cur) -Type MultiString
    } else {
        Remove-ItemProperty -Path $policyKey -Name $name -ErrorAction SilentlyContinue
    }
}

# 经 WMI 拉起界面:创建者是 System32\wbem 下的 WmiPrvSE(系统组件),用来核对运行期剥权。
# 进程落在会话 0,连不上服务,也不会出现在桌面上。拉不起或已退出时返回 0,探针跳过这一项。
function Start-UiViaWmi {
    if (-not (Test-Path $UiPath)) { return 0 }
    $r = Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{ CommandLine = "`"$UiPath`"" }
    if ($r.ReturnValue -ne 0) { Write-Host "     WMI 拉起界面失败($($r.ReturnValue)),跳过运行期剥权用例"; return 0 }
    Start-Sleep -Milliseconds 1500
    if (-not (Get-Process -Id $r.ProcessId -ErrorAction SilentlyContinue)) {
        Write-Host '     界面进程已自行退出,跳过运行期剥权用例'
        return 0
    }
    return [int]$r.ProcessId
}

function Stop-Ui([int] $UiPid) {
    if ($UiPid -ne 0) { Stop-Process -Id $UiPid -Force -ErrorAction SilentlyContinue }
}

$id = [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Fail '需要管理员权限。'
}
if (Test-DriverLoaded) {
    Fail '驱动已在加载中:先在界面里关闭实时防护(或退出界面进入待机)让服务卸掉驱动,再运行本脚本。'
}
if (-not (Test-Path 'D:\')) { Fail '测试目录固定在 D 盘,本机没有 D 盘。' }

if (-not $ProbePath) {
    $ProbePath = @(
        Join-Path $root 'cpp\build_verify\tests\Release\driver_smoke_probe.exe'
        Join-Path $root 'cpp\build\tests\Release\driver_smoke_probe.exe'
    ) | Where-Object { Test-Path $_ } | Select-Object -First 1
}
if (-not $ProbePath -or -not (Test-Path $ProbePath)) {
    Fail '找不到 driver_smoke_probe.exe:先构建 driver_smoke_probe,或用 -ProbePath 指定。'
}

$work = Join-Path $env:TEMP ('bulwark-driver-smoke-' + (Get-Date -Format 'yyyyMMdd-HHmmss'))
New-Item -ItemType Directory $work | Out-Null
$before = Join-Path $work 'policy-before.reg'
& reg.exe export $policyReg $before /y | Out-Null
if ($LASTEXITCODE -ne 0) { Fail "导出 $policyReg 失败(驱动从没在本机装过?)" }

if ($InstallFromDist) {
    $dist = Join-Path $root 'cpp\dist\Bulwark.sys'
    $sys  = Join-Path $env:SystemRoot 'System32\drivers\Bulwark.sys'
    if (-not (Test-Path $dist)) { Fail "找不到 $dist" }
    if ((Get-AuthenticodeSignature $dist).Status -ne 'Valid') { Fail "$dist 的签名无效" }
    if (Test-Path $sys) { Copy-Item $sys (Join-Path $work 'Bulwark.sys.before') -Force }
    Copy-Item $dist $sys -Force
    Write-Host "     已把 dist 驱动装到 System32\drivers(原文件备份在 $work)"
}

$hadGuardDirs = Test-PolicyValue 'GuardDirs'
$hadReadGuard = Test-PolicyValue 'ReadGuard'
$hadReaders   = Test-PolicyValue 'ReadGuardReaders'
$loaded   = $false
$guardRc  = -1
$readerRc = -1
try {
    Step 'setup + baseline(无驱动,确认各条绕过本来确实存在)'
    & $ProbePath setup
    if ($LASTEXITCODE -ne 0) { throw 'setup 失败' }
    $uiPid = Start-UiViaWmi
    & $ProbePath baseline $UiPath $uiPid
    $baselineRc = $LASTEXITCODE
    Stop-Ui $uiPid
    if ($baselineRc -ne 0) { throw 'baseline 有失败项:测试环境不对,后面的结论不可信' }

    Step "把测试目录加入受保护名单($testEntry)与窃密防护名单($readEntry,全局读者 $readerDirEntry)"
    Add-PolicyEntry 'GuardDirs' $testEntry
    Add-PolicyEntry 'ReadGuard' $readEntry
    Add-PolicyEntry 'ReadGuardReaders' $readerDirEntry
    New-Item -ItemType Directory $readerDir -Force | Out-Null
    $readerProbe = Join-Path $readerDir 'driver_smoke_probe.exe'
    Copy-Item $ProbePath $readerProbe -Force

    Step '加载驱动'
    & $fltmc load Bulwark
    if ($LASTEXITCODE -ne 0) { throw "fltmc load Bulwark 失败(退出码 $LASTEXITCODE)" }
    $loaded = $true
    & $fltmc instances -f Bulwark | Out-Host

    Step 'guard(驱动在线)'
    $uiPid = Start-UiViaWmi
    & $ProbePath guard $UiPath $uiPid
    $guardRc = $LASTEXITCODE
    Stop-Ui $uiPid

    Step 'reader(全局读者目录里的探针副本应能读敏感数据)'
    & $readerProbe reader
    $readerRc = $LASTEXITCODE
}
finally {
    if ($loaded) {
        Step '卸载驱动'
        & $fltmc unload Bulwark
        if (Test-DriverLoaded) { Write-Host '[!] 驱动仍在加载中,请手工 fltmc unload Bulwark' -ForegroundColor Yellow }
    }

    Step '复原受保护名单与窃密防护名单'
    Remove-PolicyEntry 'GuardDirs' $testEntry $hadGuardDirs
    Remove-PolicyEntry 'ReadGuard' $readEntry $hadReadGuard
    Remove-PolicyEntry 'ReadGuardReaders' $readerDirEntry $hadReaders
    $after = Join-Path $work 'policy-after.reg'
    & reg.exe export $policyReg $after /y | Out-Null
    if (Compare-Object (Get-Content $before) (Get-Content $after)) {
        Write-Host "[!] Policy 键与测试前不一致,测试前的导出在 $before" -ForegroundColor Yellow
    } else {
        Write-Host '     Policy 键与测试前一致'
    }

    Step '清理测试目录与注册表测试键'
    & $ProbePath cleanup | Out-Host
    Remove-Item $readerDir -Recurse -Force -ErrorAction SilentlyContinue
}

if ($guardRc -ne 0) { Fail "guard 有失败项(退出码 $guardRc,详见上方 FAIL 行)" }
if ($readerRc -ne 0) { Fail "reader 有失败项(退出码 $readerRc,详见上方 FAIL 行)" }
Write-Host '驱动冒烟通过。' -ForegroundColor Green
