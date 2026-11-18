param(
    [ValidateSet("Debug", "Release")]
    [string]$Configuration = "Debug"
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$proj = Join-Path $root "Bulwark.Driver\Bulwark.Driver.vcxproj"

$candidates = @(
    "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\MSBuild\Current\Bin\MSBuild.exe",
    "C:\Program Files\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\MSBuild.exe",
    "C:\Program Files\Microsoft Visual Studio\2022\Professional\MSBuild\Current\Bin\MSBuild.exe",
    "C:\Program Files\Microsoft Visual Studio\2022\Enterprise\MSBuild\Current\Bin\MSBuild.exe"
)
$msb = $candidates | Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $msb) { throw "未找到 MSBuild.exe,请安装 VS2022 + WDK。" }

Write-Host "使用 MSBuild: $msb" -ForegroundColor Cyan

$sys = Join-Path $root "build\driver\$Configuration\Bulwark.sys"
$before = $null
if (Test-Path $sys) { $before = (Get-Item $sys).LastWriteTimeUtc }

$solutionDir = ($root -replace '\\', '/') + '/'
$msbuildArgs = @(
    $proj,
    "/p:Configuration=$Configuration",
    '/p:Platform=x64',
    '/p:SpectreMitigation=false',
    '/p:SignMode=Off',
    "/p:SolutionDir=$solutionDir",
    '/m:1',
    '/nr:false',
    '/nologo',
    '/v:m'
)
# Keep compiler/linker/PDB components from the same installed MSVC toolset.
# Multiple Visual Studio toolsets on PATH can otherwise produce LNK1101.
$vsInstallRoot = [IO.Path]::GetFullPath((Join-Path (Split-Path -Parent $msb) '..\..\..'))
$toolsetRoot = Join-Path $vsInstallRoot 'VC\Tools\MSVC'
$toolset = Get-ChildItem -LiteralPath $toolsetRoot -Directory |
    Where-Object { Test-Path -LiteralPath (Join-Path $_.FullName 'bin\Hostx64\x64\link.exe') } |
    Sort-Object { [version]$_.Name } -Descending | Select-Object -First 1
$previousTaskPath = $env:PATH
try {
    if ($toolset) {
        $env:PATH = (Join-Path $toolset.FullName 'bin\Hostx64\x64') + ';' + $env:PATH
        $msbuildArgs += "/p:VCToolsVersion=$($toolset.Name)"
        $msbuildArgs += '/p:PreferredToolArchitecture=x64'
    }
    & $msb @msbuildArgs
    $msbExit = $LASTEXITCODE
} finally {
    $env:PATH = $previousTaskPath
}

# 必须看 MSBuild 退出码,不能只看产物是否存在:上次构建残留的产物会掩盖失败的构建(如 MSB8020)。
if ($msbExit -ne 0) {
    throw "MSBuild 失败(退出码 $msbExit)。上面的输出里有具体错误;产物【未】更新。"
}
if (-not (Test-Path $sys)) {
    throw "MSBuild 退出码为 0,但找不到驱动产物:$sys"
}
$after = (Get-Item $sys).LastWriteTimeUtc
if ($before -ne $null -and $after -le $before) {
    Write-Host "注意:产物时间戳未前进($after),本次为增量无变更。若预期有改动请检查是否改到了被编译的文件。" -ForegroundColor Yellow
}
Write-Host "驱动已生成: $sys (UTC $after)" -ForegroundColor Green
