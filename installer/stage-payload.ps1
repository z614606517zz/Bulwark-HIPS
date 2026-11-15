#Requires -Version 5.1
<#
.SYNOPSIS
    暂存安装包载荷:把要打包的文件整理到 installer\payload\。
.DESCRIPTION
    只收集正式发布需要的文件(排除 .bak / deployment-backups 等开发残留),
    并在暂存完成后打印清单,便于核对。
#>
[CmdletBinding()]
param(
    [string]$Dist = '',
    [string]$Payload = ''
)

$ErrorActionPreference = 'Stop'

$repo = Split-Path -Parent $PSScriptRoot          # 仓库根目录
if ([string]::IsNullOrWhiteSpace($Dist)) {
    $dist = Join-Path $repo 'cpp\dist'
} elseif ([IO.Path]::IsPathRooted($Dist)) {
    $dist = $Dist
} else {
    $dist = Join-Path $repo $Dist
}
if ([string]::IsNullOrWhiteSpace($Payload)) {
    $payload = Join-Path $PSScriptRoot 'payload'
} elseif ([IO.Path]::IsPathRooted($Payload)) {
    $payload = $Payload
} else {
    $payload = Join-Path $repo $Payload
}

if (-not (Test-Path -LiteralPath $dist)) {
    throw "找不到部署目录:$dist"
}

# 重建 payload
if (Test-Path -LiteralPath $payload) {
    Remove-Item -LiteralPath $payload -Recurse -Force
}
New-Item -ItemType Directory -Path $payload | Out-Null

function Copy-Required([string]$src, [string]$rel) {
    if (-not (Test-Path -LiteralPath $src)) {
        throw "缺少必需文件:$src"
    }
    $dst = Join-Path $payload $rel
    $dstDir = Split-Path -Parent $dst
    if (-not (Test-Path -LiteralPath $dstDir)) {
        New-Item -ItemType Directory -Path $dstDir -Force | Out-Null
    }
    Copy-Item -LiteralPath $src -Destination $dst -Force
    Write-Host "  + $rel"
}

Write-Host '== 暂存主程序与运行库 ==' -ForegroundColor Cyan
$rootFiles = @(
    'Bulwark.sys'
    'BulwarkAmsi.dll'
    'bulwark_service.exe'
    'bulwark_ui.exe'
    'bulwark_yarac.exe'
    'rules\yara-forge-core.yarc'
    'rules\yara-forge-core.json'
    'Qt6Core.dll'
    'Qt6Gui.dll'
    'Qt6Network.dll'
    'Qt6Widgets.dll'
    'app.ico'
    'appsettings.json'
)
foreach ($f in $rootFiles) {
    Copy-Required (Join-Path $dist $f) $f
}

# 只收运行时真会加载的 Qt 文件。windeployqt 另外部署的 opengl32sw.dll、D3Dcompiler_47.dll、
# Qt6Svg.dll 与 generic / iconengines / imageformats / networkinformation / styles 插件,
# 在纯 Widgets、Fusion 风格、只用 PNG 图标的界面里一个都不加载;
# 引入 OpenGL / Qt Quick、SVG 等非 PNG 图片或系统原生风格时,要把对应文件加回来。
Write-Host '== 暂存 Qt 插件 ==' -ForegroundColor Cyan
$qtPlugins = @(
    'platforms\qwindows.dll'
    'tls\qschannelbackend.dll'
)
foreach ($p in $qtPlugins) {
    Copy-Required (Join-Path $dist $p) $p
}

Write-Host '== 暂存安装/卸载辅助脚本 ==' -ForegroundColor Cyan
foreach ($s in @('install-driver.ps1', 'uninstall-driver.ps1')) {
    Copy-Required (Join-Path $PSScriptRoot "scripts\$s") "scripts\$s"
}

Write-Host ''
Write-Host "== 暂存完成:$payload ==" -ForegroundColor Green
$total = Get-ChildItem -LiteralPath $payload -Recurse -File
"{0} 个文件,共 {1:N1} MB" -f $total.Count, (($total | Measure-Object Length -Sum).Sum / 1MB)
