[CmdletBinding()]
param(
  [string]$Version = '1.23.0',
  # 与版本一一对应,换版本时必须同时更新(取自 GitHub 发布页给出的 sha256 摘要)。
  [string]$Sha256 = 'C0C0D5D225D97FFA8098B7F71E3AEC2AA3A22A7B39BC21EA7B07D07D2C8605B0',
  [string]$Destination = '',
  [switch]$Force
)
$ErrorActionPreference = 'Stop'

# 下载 YARA-X 官方发布的 Windows C 接口包(头文件 + 静态库),bulwark_yarac 静态链接其中的 yara_x_capi.lib。
# 包不进版本库;校验不过就整包拒绝,不留半成品。

$scriptDir = $PSScriptRoot
if (-not $scriptDir) { $scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path }
$cppDir = Split-Path -Parent $scriptDir
if ([string]::IsNullOrWhiteSpace($Destination)) {
  $Destination = Join-Path $cppDir 'third_party\yara-x'
}

$marker = Join-Path $Destination 'VERSION'
if (-not $Force -and (Test-Path $marker) -and ((Get-Content $marker -Raw).Trim() -eq $Version) `
    -and (Test-Path (Join-Path $Destination 'yara_x_capi.lib'))) {
  Write-Host "YARA-X C API $Version 已就位:$Destination"
  return
}

$name = "yara-x-capi-v$Version-x86_64-pc-windows-msvc.zip"
$url = "https://github.com/VirusTotal/yara-x/releases/download/v$Version/$name"
$tmp = Join-Path ([IO.Path]::GetTempPath()) ("bulwark-yarax-" + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Force -Path $tmp | Out-Null
try {
  $zip = Join-Path $tmp $name
  Write-Host "下载 $url"
  [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
  Invoke-WebRequest -Uri $url -OutFile $zip -UseBasicParsing -TimeoutSec 600
  $actual = (Get-FileHash -LiteralPath $zip -Algorithm SHA256).Hash
  if ($actual -ne $Sha256.ToUpper()) {
    throw "YARA-X 包摘要不符:期望 $Sha256,实际 $actual"
  }
  $unpacked = Join-Path $tmp 'unpacked'
  Expand-Archive -LiteralPath $zip -DestinationPath $unpacked -Force
  foreach ($f in @('yara_x.h', 'yara_x_capi.lib')) {
    if (-not (Test-Path (Join-Path $unpacked $f))) { throw "YARA-X 包缺少 $f" }
  }
  if (Test-Path $Destination) { Remove-Item -Recurse -Force $Destination }
  New-Item -ItemType Directory -Force -Path $Destination | Out-Null
  Get-ChildItem -LiteralPath $unpacked -File | Copy-Item -Destination $Destination -Force
  Set-Content -LiteralPath $marker -Value $Version -Encoding ASCII
  Write-Host "YARA-X C API $Version 已解压到 $Destination" -ForegroundColor Green
}
finally {
  Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
}
