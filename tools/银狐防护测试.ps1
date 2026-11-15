[CmdletBinding()]
param(
    [string]$SignedHost = ''
)

$ErrorActionPreference = 'Continue'
$workDir = Join-Path $env:TEMP 'BulwarkTest_SilverFox'
New-Item -ItemType Directory -Force -Path $workDir | Out-Null
$created = New-Object System.Collections.Generic.List[string]

function Test-Case {
    param([string]$Id, [string]$Desc, [string]$Expect, [scriptblock]$Action)
    Write-Host ""
    Write-Host ("[{0}] {1}" -f $Id, $Desc) -ForegroundColor Cyan
    Write-Host ("      期望防护动作: {0}" -f $Expect) -ForegroundColor DarkGray
    try { & $Action } catch { Write-Host ("      (触发时异常: {0})" -f $_.Exception.Message) -ForegroundColor DarkYellow }
}

Write-Host "==== 磐垒 银狐/微信QQ群控 防护测试(无害模拟)====" -ForegroundColor Green
Write-Host "测试目录: $workDir"

Test-Case '1' '落地具名群控模块 wxhook.dll / WeChatSDK64.dll / vchat.dll' 'Block(拦截写入)' {
    foreach ($name in 'wxhook.dll','WeChatSDK64.dll','vchat.dll','WeChatRobotCE.dll','WeWorkHook.dll') {
        $p = Join-Path $workDir $name
        Set-Content -LiteralPath $p -Value 'THIS IS A HARMLESS TEST FILE - NOT A REAL DLL' -ErrorAction SilentlyContinue
        if (Test-Path $p) { $created.Add($p); Write-Host "      已写入: $p" -ForegroundColor DarkGray }
        else { Write-Host "      写入被拦截(未落地): $name" -ForegroundColor Yellow }
    }
}

Test-Case '2' '命令行含 PyWxDump / SharpWxDump / wxdump(仅字符串,不执行导出)' 'Ask(弹窗询问)' {
    foreach ($tool in 'PyWxDump','SharpWxDump','wxdump','WeChatMsg') {
        Start-Process -FilePath 'cmd.exe' -ArgumentList "/c rem $tool  (harmless test)" -WindowStyle Hidden -ErrorAction SilentlyContinue
        Write-Host "      已启动含 '$tool' 命令行的无害进程" -ForegroundColor DarkGray
    }
}

Test-Case '3' '命令行含群发框架 wcferry / ntchat / wxauto' 'Ask(弹窗询问)' {
    foreach ($fw in 'wcferry','ntchat','wxauto') {
        Start-Process -FilePath 'cmd.exe' -ArgumentList "/c rem import $fw  (harmless test)" -WindowStyle Hidden -ErrorAction SilentlyContinue
        Write-Host "      已启动含 '$fw' 命令行的无害进程" -ForegroundColor DarkGray
    }
}

Test-Case '4' '向 微信/企业微信 安装目录写入 DLL(植入模块模拟)' 'Ask 或 Block' {
    $targets = @(
        (Join-Path ${env:ProgramFiles} 'Tencent\WeChat\bulwark_test_plugin.dll'),
        (Join-Path ${env:ProgramFiles} 'Tencent\Weixin\bulwark_test_plugin.dll'),
        (Join-Path ${env:ProgramFiles} 'WXWork\bulwark_test_plugin.dll')
    )
    foreach ($t in $targets) {
        $dir = Split-Path $t
        if (Test-Path $dir) {
            Set-Content -LiteralPath $t -Value 'HARMLESS TEST' -ErrorAction SilentlyContinue
            if (Test-Path $t) { $created.Add($t); Write-Host "      已写入: $t" -ForegroundColor DarkGray }
            else { Write-Host "      写入被拦截: $t" -ForegroundColor Yellow }
        } else {
            Write-Host "      跳过(目录不存在): $dir" -ForegroundColor DarkGray
        }
    }
}

Test-Case '5' '落地银狐惯用的易受攻击驱动 amsdk/wsftprm/BootRepair/EnPortv/wnbios (.sys)' 'Block(拦截写入)' {
    foreach ($name in 'amsdk.sys','wamsdk.sys','wsftprm.sys','BootRepair.sys','EnPortv.sys','wnbios.sys') {
        $p = Join-Path $workDir $name
        Set-Content -LiteralPath $p -Value 'HARMLESS TEST FILE - NOT A REAL DRIVER' -ErrorAction SilentlyContinue
        if (Test-Path $p) { $created.Add($p); Write-Host "      已写入: $p" -ForegroundColor DarkGray }
        else { Write-Host "      写入被拦截(未落地): $name" -ForegroundColor Yellow }
    }
}

Test-Case '6' 'sc create binPath= 指向可写目录(仅命令行字符串,不真的建服务)' 'Block(可写目录)/ Ask(ProgramData)' {
    $zones = @(
        "$env:APPDATA\svc.exe",
        "$env:USERPROFILE\Downloads\svc.exe",
        "$env:ProgramData\svc.exe"
    )
    foreach ($z in $zones) {
        Start-Process -FilePath 'cmd.exe' `
            -ArgumentList "/c rem sc create BulwarkTestSvc binPath= `"$z`"  (harmless test)" `
            -WindowStyle Hidden -ErrorAction SilentlyContinue
        Write-Host "      已启动含 binPath= $z 的无害命令行" -ForegroundColor DarkGray
    }
}

Test-Case '7' '签名宿主 + 同目录未签名 powrprof.dll(银狐主流侧载形态)' 'Ask(弹窗询问,不得静默放行)' {
    $candidates = @()
    if ($SignedHost) { $candidates += $SignedHost }
    $candidates += @(
        (Join-Path $env:LOCALAPPDATA 'Microsoft\OneDrive\OneDriveStandaloneUpdater.exe'),
        (Join-Path ${env:ProgramFiles(x86)} 'Microsoft\Edge\Application\msedge_proxy.exe'),
        (Join-Path ${env:ProgramFiles} 'Git\cmd\git.exe'),
        (Join-Path ${env:ProgramFiles} '7-Zip\7z.exe')
    )
    $hostSrc = $null
    foreach ($c in $candidates) {
        if (-not (Test-Path -LiteralPath $c)) { continue }
        $probe = Join-Path $workDir ([System.IO.Path]::GetFileName($c))
        Copy-Item -LiteralPath $c -Destination $probe -Force -ErrorAction SilentlyContinue
        if (-not (Test-Path -LiteralPath $probe)) { continue }
        $sig = Get-AuthenticodeSignature -LiteralPath $probe -ErrorAction SilentlyContinue
        if ($sig -and $sig.Status -eq 'Valid') { $hostSrc = $probe; $created.Add($probe); break }
        Remove-Item -LiteralPath $probe -Force -ErrorAction SilentlyContinue
    }
    if (-not $hostSrc) {
        Write-Host "      跳过:没找到复制后仍验签通过的内嵌签名程序。" -ForegroundColor DarkYellow
        Write-Host "      可用 -SignedHost '<某个带内嵌签名的 exe>' 重跑本用例。" -ForegroundColor DarkYellow
        return
    }
    Write-Host "      签名宿主: $hostSrc" -ForegroundColor DarkGray
    $evil = Join-Path $workDir 'powrprof.dll'
    Set-Content -LiteralPath $evil -Value 'HARMLESS TEST FILE - NOT A REAL DLL' -ErrorAction SilentlyContinue
    if (Test-Path $evil) { $created.Add($evil); Write-Host "      已放置: $evil" -ForegroundColor DarkGray }
    else { Write-Host "      powrprof.dll 写入即被拦截(落盘即扫也算生效)" -ForegroundColor Yellow }
    $proc = Start-Process -FilePath $hostSrc -ArgumentList '--version' -PassThru `
                          -WindowStyle Hidden -ErrorAction SilentlyContinue
    Write-Host "      已运行签名宿主(3 秒后结束)" -ForegroundColor DarkGray
    Start-Sleep -Seconds 3
    if ($proc -and -not $proc.HasExited) { Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue }
}

Test-Case '8' '未签名的系统同名模块落盘(powrprof.dll / wsc.dll / version.dll)' '产生 FileWrite 事件(落盘可见)' {
    $targets = @(
        (Join-Path $workDir 'wsc.dll'),
        (Join-Path $workDir 'version.dll'),
        (Join-Path $env:ProgramData 'BulwarkTest_payload.dll')
    )
    foreach ($t in $targets) {
        Set-Content -LiteralPath $t -Value 'HARMLESS TEST FILE - NOT A REAL DLL' -ErrorAction SilentlyContinue
        if (Test-Path $t) { $created.Add($t); Write-Host "      已写入: $t" -ForegroundColor DarkGray }
        else { Write-Host "      写入被拦截: $t" -ForegroundColor Yellow }
    }
}

Test-Case '9' '运行改名为 zpaqfranz.exe 的无害程序' 'Ask(弹窗询问)' {
    $fake = Join-Path $workDir 'zpaqfranz.exe'
    Copy-Item -LiteralPath (Join-Path $env:SystemRoot 'System32\cmd.exe') -Destination $fake `
              -Force -ErrorAction SilentlyContinue
    if (-not (Test-Path $fake)) { Write-Host "      跳过:复制 cmd.exe 失败" -ForegroundColor DarkYellow; return }
    $created.Add($fake)
    Start-Process -FilePath $fake -ArgumentList '/c rem harmless test' -WindowStyle Hidden -ErrorAction SilentlyContinue
    Write-Host "      已运行: $fake" -ForegroundColor DarkGray
    Start-Sleep -Seconds 2
}

Write-Host ""
Write-Host "==== 测试触发完毕 ====" -ForegroundColor Green
Write-Host "请查看 Bulwark UI:上述每一步是否产生了弹窗 / 拦截 / 事件记录。" -ForegroundColor White
Write-Host ""
Write-Host "正在清理测试文件..." -ForegroundColor DarkGray
foreach ($f in $created) { Remove-Item -LiteralPath $f -Force -ErrorAction SilentlyContinue }
Remove-Item -LiteralPath $workDir -Recurse -Force -ErrorAction SilentlyContinue
Write-Host "清理完成。" -ForegroundColor DarkGray
