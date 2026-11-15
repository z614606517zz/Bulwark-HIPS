param(
    [ValidateSet("Debug", "Release")]
    [string]$Configuration = "Release",
    [string]$CertSubject = "BulwarkTestCert"
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$proj = Join-Path $root "Bulwark.Driver\Bulwark.Driver.vcxproj"
$dist = Join-Path $root "cpp\dist"

function Fail($msg) { Write-Host "[失败] $msg" -ForegroundColor Red; exit 1 }
function Step($msg) { Write-Host "==> $msg" -ForegroundColor Cyan }
function Ok($msg)   { Write-Host "     $msg" -ForegroundColor Green }

$id = [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Fail "需要管理员权限:测试证书装在 LocalMachine\My,读它的私钥必须提权。请在管理员 PowerShell 里重跑。"
}
if (-not (Test-Path $proj)) { Fail "找不到驱动工程:$proj" }
if (-not (Test-Path $dist)) { Fail "找不到便携包目录:$dist" }

$msb = @(
    "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\MSBuild\Current\Bin\MSBuild.exe",
    "C:\Program Files\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\MSBuild.exe",
    "C:\Program Files\Microsoft Visual Studio\2022\Professional\MSBuild\Current\Bin\MSBuild.exe",
    "C:\Program Files\Microsoft Visual Studio\2022\Enterprise\MSBuild\Current\Bin\MSBuild.exe"
) | Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $msb) { Fail "未找到 MSBuild.exe(需 VS2022 + WDK)。" }

# ${env:ProgramFiles(x86)} 在 PowerShell 里解析为空(变量名含括号),受限进程里连 ProgramFiles 都可能不设;
# Get-ChildItem 拿到空路径会静默返回空,表现为「未找到 signtool」,所以取不到时回退到几个已知的 Windows Kits 安装位置。
$kitsRoots = @(
    [Environment]::GetEnvironmentVariable("ProgramFiles(x86)"),
    [Environment]::GetEnvironmentVariable("ProgramFiles"),
    "C:\Program Files (x86)",
    "C:\Program Files"
) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -Unique

$signtool = $null
foreach ($kitsRoot in $kitsRoots) {
    $bin = Join-Path $kitsRoot "Windows Kits\10\bin"
    if (-not (Test-Path $bin)) { continue }
    $signtool = Get-ChildItem $bin -Recurse -Filter signtool.exe -ErrorAction SilentlyContinue |
                Where-Object FullName -like "*x64*" |
                Sort-Object FullName -Descending | Select-Object -First 1
    if ($signtool) { break }
}
if (-not $signtool) { Fail "未找到 signtool.exe(需 Windows SDK)。" }

$cert = Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.Subject -like "*CN=$CertSubject*" }
if (-not $cert)                 { Fail "LocalMachine\My 里找不到证书 CN=$CertSubject。" }
if (-not $cert.HasPrivateKey)   { Fail "证书 CN=$CertSubject 没有私钥,无法签名。" }
if ($cert -is [array])          { $cert = $cert[0] }
Ok "证书 $($cert.Thumbprint)(有效期至 $($cert.NotAfter.ToString('yyyy-MM-dd')))"

$prim = Join-Path $root "build\driver\$Configuration\Bulwark.sys"
$alt  = Join-Path $root "Bulwark.Driver\build\driver\$Configuration\Bulwark.sys"
$before = @{}
foreach ($p in @($prim, $alt)) { if (Test-Path $p) { $before[$p] = (Get-Item $p).LastWriteTimeUtc } }

Step "构建驱动($Configuration)"
& $msb $proj /p:Configuration=$Configuration /p:Platform=x64 `
      /p:SpectreMitigation=false /p:SignMode=Off `
      "/p:SolutionDir=$root\\" /nologo /v:minimal
if ($LASTEXITCODE -ne 0) { Fail "驱动构建失败(退出码 $LASTEXITCODE)。" }

$built = @($prim, $alt) | Where-Object { Test-Path $_ } |
         Sort-Object { (Get-Item $_).LastWriteTimeUtc } -Descending | Select-Object -First 1
if (-not $built) { Fail "构建退出码为 0,但两个候选路径都没有产物:`n  $prim`n  $alt" }

$after = (Get-Item $built).LastWriteTimeUtc
if ($before.ContainsKey($built) -and $after -le $before[$built]) {
    Write-Host "     注意:产物时间戳未前进($after),本次为增量无变更。若预期有改动请检查是否改到了被编译的文件。" -ForegroundColor Yellow
}
Ok "产物 $built ($((Get-Item $built).Length) B,UTC $after)"

Step "测试签名"
$staging = Join-Path $env:TEMP "Bulwark.sys.staging"
Copy-Item $built $staging -Force
& $signtool.FullName sign /v /sm /s My /sha1 $cert.Thumbprint /fd sha256 $staging
if ($LASTEXITCODE -ne 0) { Remove-Item $staging -Force -ErrorAction SilentlyContinue; Fail "签名失败(退出码 $LASTEXITCODE)。dist 未改动。" }

$sig = Get-AuthenticodeSignature $staging
if ($sig.Status -ne 'Valid') { Remove-Item $staging -Force -ErrorAction SilentlyContinue; Fail "签名后校验不通过($($sig.Status))。dist 未改动。" }
Ok "签名有效:$($sig.SignerCertificate.Subject)"

Step "同步到便携包"
$target = Join-Path $dist "Bulwark.sys"
if (Test-Path $target) {
    $stamp = (Get-Item $target).LastWriteTime.ToString('yyyyMMdd-HHmmss')
    $bak = Join-Path $dist "Bulwark.sys.bak-$stamp"
    Copy-Item $target $bak -Force
    Ok "旧驱动已备份为 $(Split-Path $bak -Leaf)"
}
# 跨卷移动(TEMP 在 C:、dist 在 D:)时 PowerShell 5.1 的 Move-Item -Force 不覆盖已存在文件,
# 会报 "The file exists."。改成先复制后删,复制才认 -Force 覆盖。
Copy-Item $staging $target -Force
Remove-Item $staging -Force -ErrorAction SilentlyContinue
Remove-Item (Join-Path $dist "Bulwark.sys.new-unsigned") -Force -ErrorAction SilentlyContinue

$info = Get-Item $target
Ok "dist\Bulwark.sys 已更新($($info.Length) B,$($info.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss')))"

Write-Host ""
Write-Host "完成。若目标机上已部署过旧驱动,记得让新的那份真正生效:" -ForegroundColor Yellow
Write-Host "    sc stop BulwarkService" -ForegroundColor Gray
Write-Host "    fltmc unload Bulwark" -ForegroundColor Gray
Write-Host "    copy /Y cpp\dist\Bulwark.sys %SystemRoot%\System32\drivers\Bulwark.sys" -ForegroundColor Gray
Write-Host "    sc start BulwarkService" -ForegroundColor Gray
Write-Host "  (服务的 stageDriverBinary() 只在目标文件【不存在】时才复制,不会覆盖已部署的旧驱动 —— " -ForegroundColor Gray
Write-Host "   所以升级时必须手工覆盖这一次。之后服务日志里的「内核能力探测」应报告全部维度就绪。)" -ForegroundColor Gray
