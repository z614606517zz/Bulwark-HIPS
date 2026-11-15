[CmdletBinding()]
param(
  [string]$Tag = '20261103',
  # 与 Tag 一一对应,换版本时必须同时更新(取自 GitHub 发布页给出的 sha256 摘要)。
  [string]$Sha256 = 'BE0D5A49D2A8CD37713F5A8C4E5A3C4235061242BC12240E18C69934FA47BB59',
  [string]$Package = 'core',
  [Parameter(Mandatory = $true)][string]$OutFile
)
$ErrorActionPreference = 'Stop'

# 下载固定版本的 YARA Forge 规则包,供打包时预编译成安装包内置规则(装好后没联网也有规则可用)。
# 校验不过就删掉,不留半成品。

$name = "yara-forge-rules-$Package.zip"
$url = "https://github.com/YARAHQ/yara-forge/releases/download/$Tag/$name"
if ((Test-Path -LiteralPath $OutFile) -and ((Get-FileHash -LiteralPath $OutFile -Algorithm SHA256).Hash -eq $Sha256.ToUpper())) {
  Write-Host "YARA Forge $Tag ($Package) 已就位:$OutFile"
  return
}
$dir = Split-Path -Parent $OutFile
if ($dir) { New-Item -ItemType Directory -Force -Path $dir | Out-Null }
Write-Host "下载 $url"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Invoke-WebRequest -Uri $url -OutFile $OutFile -UseBasicParsing -TimeoutSec 600
$actual = (Get-FileHash -LiteralPath $OutFile -Algorithm SHA256).Hash
if ($actual -ne $Sha256.ToUpper()) {
  Remove-Item -LiteralPath $OutFile -Force -ErrorAction SilentlyContinue
  throw "YARA Forge 规则包摘要不符:期望 $Sha256,实际 $actual"
}
Write-Host "YARA Forge $Tag ($Package) 已下载并校验:$OutFile" -ForegroundColor Green
