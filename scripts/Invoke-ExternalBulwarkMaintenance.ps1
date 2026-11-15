[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][switch]$AcknowledgeBoundedMaintenance,
    [ValidateRange(5,120)][int]$StepTimeoutSeconds = 30,
    [ValidateRange(60,1800)][int]$OfflineValidationTimeoutSeconds = 900,
    [string]$EvidenceDirectory = ''
)

$ErrorActionPreference = 'Stop'
$repoRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..')).TrimEnd('\')
if ([string]::IsNullOrWhiteSpace($EvidenceDirectory)) {
    $EvidenceDirectory = Join-Path $repoRoot ('.agents\tasks\validation-reconciliation-resume\maintenance-' + [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssZ'))
}
$servicePath = Join-Path $repoRoot 'cpp\dist\bulwark_service.exe'
$uiPath = Join-Path $repoRoot 'cpp\dist\bulwark_ui.exe'
$appsettingsPath = Join-Path $repoRoot 'cpp\dist\appsettings.json'
$controllerPath = Join-Path $repoRoot 'scripts\Invoke-SnapshotReconciliationTransaction.ps1'
$driverCanonicalPath = [IO.Path]::GetFullPath((Join-Path $env:SystemRoot 'System32\drivers\Bulwark.sys'))
$driverReadPath = if ([Environment]::Is64BitOperatingSystem -and -not [Environment]::Is64BitProcess) {
    Join-Path $env:SystemRoot 'Sysnative\drivers\Bulwark.sys'
} else { $driverCanonicalPath }
$policyKey = 'HKLM:\SYSTEM\CurrentControlSet\Services\Bulwark\Policy'
$userManifestPath = Join-Path $env:ProgramData 'Bulwark\usermode_execblock.json'
$expected = [ordered]@{
    driverHash = 'CA4F68AF4BE7D0BB4391487505F469ACD70E7A945AE4431879EB0FD156A60AFD'
    driverThumbprint = '23AB51ED334ABCCBE3715D37DD9EA57837279338'
    serviceHash = '75A935FC03F35E5B9751BB674C57793E5EE3ECEE3321BB6D34DADCFA21E0F29D'
    appsettingsHash = 'ED966784428E686DA430DEDE307C97B87C833504AB5B1017768C9339D1804933'
}

New-Item -ItemType Directory -Path $EvidenceDirectory -Force | Out-Null
$transcriptPath = Join-Path $EvidenceDirectory 'operator-transcript.txt'
$journalPath = Join-Path $EvidenceDirectory 'journal.json'
$reportPath = Join-Path $EvidenceDirectory 'report.json'

function Write-Json([string]$Path, $Object) {
    [IO.File]::WriteAllText($Path, ($Object | ConvertTo-Json -Depth 20), (New-Object Text.UTF8Encoding($false)))
}
function Save-Journal { Write-Json $journalPath $journal }
function Get-Identity([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        return [ordered]@{ path=$Path; exists=$false; size=$null; sha256=$null }
    }
    $item = Get-Item -LiteralPath $Path
    return [ordered]@{ path=$item.FullName; exists=$true; size=$item.Length; sha256=(Get-FileHash -LiteralPath $item.FullName -Algorithm SHA256).Hash; lastWriteTimeUtc=$item.LastWriteTimeUtc.ToString('o') }
}
function Get-DriverServiceSnapshot {
    $driver = Get-CimInstance Win32_SystemDriver -Filter "Name='Bulwark'" -OperationTimeoutSec $StepTimeoutSeconds
    return [ordered]@{ name='Bulwark'; state=$driver.State; startMode=$driver.StartMode; pathName=$driver.PathName }
}
function Get-UserServiceSnapshot {
    $service = Get-CimInstance Win32_Service -Filter "Name='BulwarkService'" -OperationTimeoutSec $StepTimeoutSeconds
    return [ordered]@{ name='BulwarkService'; state=$service.State; startMode=$service.StartMode; processId=$service.ProcessId; pathName=$service.PathName }
}
function Get-Captured([string]$FileName, [string[]]$Arguments, [int]$TimeoutSeconds = $StepTimeoutSeconds) {
    $psi = New-Object Diagnostics.ProcessStartInfo
    $psi.FileName = $FileName
    $psi.Arguments = ($Arguments | ForEach-Object { if ($_ -notmatch '[\s"]') { $_ } else { '"' + ($_ -replace '(\\*)"', '$1$1\"' -replace '(\\+)$', '$1$1') + '"' } }) -join ' '
    $psi.UseShellExecute = $false; $psi.CreateNoWindow = $true
    $psi.RedirectStandardOutput = $true; $psi.RedirectStandardError = $true
    $process = New-Object Diagnostics.Process; $process.StartInfo = $psi
    $startedUtc = [DateTime]::UtcNow.ToString('o')
    try {
        [void]$process.Start()
        $stdoutTask = $process.StandardOutput.ReadToEndAsync(); $stderrTask = $process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit($TimeoutSeconds * 1000)) {
            try { $process.Kill() } catch {}
            throw [TimeoutException]::new("$FileName exceeded the $TimeoutSeconds-second deadline.")
        }
        return [ordered]@{ file=$FileName; argv=@($Arguments); startedUtc=$startedUtc; finishedUtc=[DateTime]::UtcNow.ToString('o'); exitCode=$process.ExitCode; stdout=$stdoutTask.GetAwaiter().GetResult(); stderr=$stderrTask.GetAwaiter().GetResult() }
    } finally { $process.Dispose() }
}
function Wait-ServiceState([string]$Name, [string]$ExpectedState) {
    $deadline = [DateTime]::UtcNow.AddSeconds($StepTimeoutSeconds)
    do {
        $state = (Get-Service -Name $Name -ErrorAction Stop).Status.ToString()
        if ($state -eq $ExpectedState) { return $state }
        Start-Sleep -Milliseconds 250
    } while ([DateTime]::UtcNow -lt $deadline)
    throw "$Name did not reach $ExpectedState within $StepTimeoutSeconds seconds."
}
function Get-MinifilterSnapshot {
    $flt = Join-Path $env:SystemRoot 'System32\fltmc.exe'
    $filters = Get-Captured $flt @('filters')
    $instances = Get-Captured $flt @('instances')
    if ($filters.exitCode -ne 0 -or $instances.exitCode -ne 0) { throw 'fltmc could not capture the Minifilter state.' }
    return [ordered]@{ filters=$filters; instances=$instances; altitudePresent=($filters.stdout -match '(?m)^Bulwark\s+\d+\s+385201\s'); instanceCount=([regex]::Matches($instances.stdout, '(?m)^Bulwark\s+.*385201\s+Bulwark Instance').Count) }
}
function Find-SignTool {
    $command = Get-Command signtool.exe -ErrorAction SilentlyContinue
    if ($command) { return $command.Source }
    $kitRoot = Join-Path ${env:ProgramFiles(x86)} 'Windows Kits\10\bin'
    foreach ($version in @('10.0.26100.0','10.0.22621.0','10.0.22000.0','10.0.19041.0')) {
        $candidate = Join-Path $kitRoot ($version + '\x64\signtool.exe')
        if (Test-Path -LiteralPath $candidate -PathType Leaf) { return $candidate }
    }
    return $null
}
function Get-AuthenticodeSignatureBounded([string]$Path, [int]$TimeoutSeconds = $StepTimeoutSeconds) {
    $job=Start-Job -ScriptBlock { param($candidate) $signature=Get-AuthenticodeSignature -LiteralPath $candidate; [pscustomobject]@{ status=$signature.Status.ToString(); thumbprint=$(if ($signature.SignerCertificate) { $signature.SignerCertificate.Thumbprint } else { $null }); subject=$(if ($signature.SignerCertificate) { $signature.SignerCertificate.Subject } else { $null }) } } -ArgumentList $Path
    try {
        if (-not (Wait-Job -Job $job -Timeout $TimeoutSeconds)) { throw [TimeoutException]::new("Authenticode verification exceeded $TimeoutSeconds seconds.") }
        return Receive-Job -Job $job -ErrorAction Stop
    } finally { if ($job.State -eq 'Running') { Stop-Job -Job $job -ErrorAction SilentlyContinue }; Remove-Job -Job $job -Force -ErrorAction SilentlyContinue }
}
function Get-UiSnapshot {
    $processes = @(Get-Process bulwark_ui -ErrorAction SilentlyContinue | ForEach-Object {
        [ordered]@{ id=$_.Id; path=$_.Path; mainWindowHandle=$_.MainWindowHandle; mainWindowTitle=$_.MainWindowTitle; startTimeUtc=$_.StartTime.ToUniversalTime().ToString('o') }
    })
    return [ordered]@{ count=$processes.Count; processes=$processes }
}
function Get-SelfGuardSnapshot {
    $log = Join-Path $env:ProgramData 'Bulwark\service.log'
    return [ordered]@{ path=$log; identity=Get-Identity $log; tail=$(if (Test-Path -LiteralPath $log) { Get-Content -LiteralPath $log -Tail 100 -Encoding UTF8 | Out-String } else { '' }) }
}
function Record-Action([string]$Name, $Observed) {
    $journal.actions.Add([ordered]@{ name=$Name; utc=[DateTime]::UtcNow.ToString('o'); observed=$Observed })
    Save-Journal
}
function Assert([bool]$Condition, [string]$Message) { if (-not $Condition) { throw $Message } }
function Restore-Protection {
    $restore = [ordered]@{ startedUtc=[DateTime]::UtcNow.ToString('o'); actions=New-Object System.Collections.Generic.List[object]; health=New-Object System.Collections.Generic.List[object]; complete=$false }
    $journal.restore = $restore; Save-Journal
    try {
        $driverStart = Get-Captured (Join-Path $env:SystemRoot 'System32\sc.exe') @('start','Bulwark')
        $restore.actions.Add([ordered]@{ name='start-driver'; result=$driverStart })
        Wait-ServiceState 'Bulwark' 'Running' | Out-Null
        $filter = Get-MinifilterSnapshot
        $restore.health.Add([ordered]@{ name='Minifilter altitude and instance preimage'; pass=($filter.altitudePresent -and $filter.instanceCount -eq $journal.preimage.minifilter.instanceCount); observed=$filter })

        $driverIdentity = Get-Identity $driverReadPath
        $signature = Get-AuthenticodeSignatureBounded $driverReadPath
        $signtool = Find-SignTool
        $pa = if ($signtool) { Get-Captured $signtool @('verify','/pa',$driverReadPath) } else { $null }
        $driverPass = $driverIdentity.sha256 -eq $expected.driverHash -and $signature.status -eq 'Valid' -and $signature.thumbprint -eq $expected.driverThumbprint -and $pa -and $pa.exitCode -eq 0
        $restore.health.Add([ordered]@{ name='pinned driver identity'; pass=$driverPass; observed=[ordered]@{ canonicalPath=$driverCanonicalPath; readPath=$driverReadPath; identity=$driverIdentity; signature=$signature.status; thumbprint=$signature.thumbprint; signtoolPa=$pa } })

        $serviceStart = Get-Captured (Join-Path $env:SystemRoot 'System32\sc.exe') @('start','BulwarkService')
        $restore.actions.Add([ordered]@{ name='start-service'; result=$serviceStart })
        Wait-ServiceState 'BulwarkService' 'Running' | Out-Null
        $serviceIdentity = Get-Identity $servicePath
        $appsettingsIdentity = Get-Identity $appsettingsPath
        $restore.health.Add([ordered]@{ name='service identity'; pass=($serviceIdentity.sha256 -eq $expected.serviceHash); observed=$serviceIdentity })
        $restore.health.Add([ordered]@{ name='appsettings identity'; pass=($appsettingsIdentity.sha256 -eq $expected.appsettingsHash); observed=$appsettingsIdentity })

        $serviceStartUtc = [DateTime]::UtcNow
        Start-Sleep -Seconds 3
        $selfGuard = Get-SelfGuardSnapshot
        $probe = Join-Path (Split-Path $servicePath -Parent) ('.bulwark-maintenance-probe-' + $PID + '.tmp')
        $denied = $false; $cleanupError = $null
        try { [IO.File]::WriteAllText($probe, 'harmless post-maintenance SelfGuard probe') } catch { $denied = $true }
        if (Test-Path -LiteralPath $probe) { try { Remove-Item -LiteralPath $probe -Force } catch { $cleanupError=$_.Exception.ToString() } }
        $selfGuardPass = $selfGuard.identity.exists -and $selfGuard.identity.lastWriteTimeUtc -ge $serviceStartUtc.ToString('o') -and $selfGuard.tail -match 'SelfGuard' -and $denied -and -not $cleanupError
        $restore.health.Add([ordered]@{ name='SelfGuard and harmless foreign write denial'; pass=$selfGuardPass; observed=[ordered]@{ selfGuard=$selfGuard; foreignWriteDenied=$denied; cleanupError=$cleanupError } })

        $uiStart = Start-Process -FilePath $uiPath -PassThru
        $restore.actions.Add([ordered]@{ name='start-ui'; processId=$uiStart.Id })
        $uiDeadline=[DateTime]::UtcNow.AddSeconds($StepTimeoutSeconds); $ui=$null
        do { $ui=Get-UiSnapshot; if ($ui.count -gt 0 -and @($ui.processes | Where-Object { $_.mainWindowHandle -ne 0 -and $_.mainWindowTitle -eq '磐垒主动防御' }).Count -gt 0) { break }; Start-Sleep -Milliseconds 250 } while ([DateTime]::UtcNow -lt $uiDeadline)
        $restore.health.Add([ordered]@{ name='visible titled main window'; pass=($ui -and @($ui.processes | Where-Object { $_.mainWindowHandle -ne 0 -and $_.mainWindowTitle -eq '磐垒主动防御' }).Count -gt 0); observed=$ui })

        $restore.complete=(@($restore.health | Where-Object { -not $_.pass }).Count -eq 0)
        if (-not $restore.complete) { throw 'One or more mandatory restoration health checks failed.' }
    } catch { $restore.failure=$_.Exception.ToString(); $restore.complete=$false; throw }
    finally { $restore.finishedUtc=[DateTime]::UtcNow.ToString('o'); Save-Journal }
}

$journal = [ordered]@{
    schemaVersion=1; startedUtc=[DateTime]::UtcNow.ToString('o'); mode='external-visible-bounded-maintenance'; repositoryRoot=$repoRoot
    acknowledgement=[bool]$AcknowledgeBoundedMaintenance; maintenanceStarted=$false; maintenanceStopped=$false; onlineTransactionExecuted=$false
    prohibited=[ordered]@{ snapshotExecute=$false; appsettingsWrite=$false; policyWrite=$false; driverBinaryWrite=$false; broadProcessKill=$false }
    preimage=[ordered]@{}; actions=New-Object System.Collections.Generic.List[object]; restore=$null; offlineValidation=$null; postRestorePreflight=$null; result='IN_PROGRESS'
}
Save-Journal
Start-Transcript -Path $transcriptPath -Force | Out-Null
$maintenanceStopped = $false
try {
    $principal = [Security.Principal.WindowsPrincipal]([Security.Principal.WindowsIdentity]::GetCurrent())
    Assert $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) 'Run this script from an elevated administrator console.'
    $journal.preimage.serviceRegistration=Get-UserServiceSnapshot
    $journal.preimage.driverService=Get-DriverServiceSnapshot
    $journal.preimage.service=Get-Identity $servicePath; $journal.preimage.ui=Get-Identity $uiPath
    $journal.preimage.driver=[ordered]@{ canonicalPath=$driverCanonicalPath; readPath=$driverReadPath; identity=Get-Identity $driverReadPath }
    $journal.preimage.appsettings=Get-Identity $appsettingsPath
    $journal.preimage.driverSignature=Get-AuthenticodeSignatureBounded $driverReadPath
    $signtool=Find-SignTool; $journal.preimage.driverSigntoolPa=if ($signtool) { Get-Captured $signtool @('verify','/pa',$driverReadPath) } else { $null }
    $journal.preimage.minifilter=Get-MinifilterSnapshot; $journal.preimage.uiState=Get-UiSnapshot; $journal.preimage.selfGuard=Get-SelfGuardSnapshot
    $journal.preimage.fileExecBlock=@((Get-ItemProperty -LiteralPath $policyKey -Name FileExecBlock -ErrorAction Stop).FileExecBlock)
    $journal.preimage.userManifest=Get-Identity $userManifestPath
    Save-Journal
    Assert ($journal.preimage.service.sha256 -eq $expected.serviceHash) 'Installed service identity is not the approved preimage.'
    Assert ($journal.preimage.driver.identity.sha256 -eq $expected.driverHash) 'Pinned driver hash is not present before maintenance.'
    Assert ($journal.preimage.driverSignature.status -eq 'Valid' -and $journal.preimage.driverSignature.thumbprint -eq $expected.driverThumbprint) 'Pinned driver signature is not present before maintenance.'
    Assert ($journal.preimage.appsettings.sha256 -eq $expected.appsettingsHash) 'appsettings identity is not the approved preimage.'
    Assert ($journal.preimage.serviceRegistration.state -eq 'Running' -and $journal.preimage.driverService.state -eq 'Running') 'Protection was not fully running before maintenance.'
    Assert ($journal.preimage.minifilter.altitudePresent -and $journal.preimage.minifilter.instanceCount -gt 0) 'Bulwark Minifilter was not attached before maintenance.'

    Stop-Service -Name BulwarkService -ErrorAction Stop; Wait-ServiceState 'BulwarkService' 'Stopped' | Out-Null; Record-Action 'graceful-stop-service' (Get-UserServiceSnapshot)
    foreach ($ui in @(Get-Process bulwark_ui -ErrorAction SilentlyContinue)) { [void]$ui.CloseMainWindow() }
    $uiDeadline=[DateTime]::UtcNow.AddSeconds($StepTimeoutSeconds); while (@(Get-Process bulwark_ui -ErrorAction SilentlyContinue).Count -gt 0 -and [DateTime]::UtcNow -lt $uiDeadline) { Start-Sleep -Milliseconds 250 }
    Assert (@(Get-Process bulwark_ui -ErrorAction SilentlyContinue).Count -eq 0) 'UI did not exit gracefully; refusing force termination.'; Record-Action 'graceful-stop-ui' (Get-UiSnapshot)
    $unload=Get-Captured (Join-Path $env:SystemRoot 'System32\fltmc.exe') @('unload','Bulwark'); Record-Action 'unload-minifilter' $unload
    Assert ($unload.exitCode -eq 0) 'fltmc unload Bulwark failed; refusing driver force-stop.'
    $driverStop=Get-Captured (Join-Path $env:SystemRoot 'System32\sc.exe') @('stop','Bulwark'); Record-Action 'stop-driver' $driverStop
    Wait-ServiceState 'Bulwark' 'Stopped' | Out-Null
    $filterAfterStop=Get-MinifilterSnapshot; Assert (-not $filterAfterStop.altitudePresent) 'Bulwark remains listed by fltmc after stop.'
    $maintenanceStopped=$true; $journal.maintenanceStarted=$true; $journal.maintenanceStopped=$true; Save-Journal

    $hung=@(Get-CimInstance Win32_Process -Filter "Name='powershell.exe' OR Name='pwsh.exe'" -OperationTimeoutSec $StepTimeoutSeconds | Where-Object { $_.CommandLine -and $_.CommandLine -match 'Invoke-SnapshotReconciliationTransaction\.ps1' -and $_.CommandLine -match '(?i)(?:^|\s)-PreflightOnly(?:\s|$)' })
    foreach ($process in $hung) {
        $target=[ordered]@{ processId=$process.ProcessId; parentProcessId=$process.ParentProcessId; commandLine=$process.CommandLine }
        try { Stop-Process -Id $process.ProcessId -Force -ErrorAction Stop; $target.terminated=$true } catch { $target.terminated=$false; $target.error=$_.Exception.ToString(); throw }
        Record-Action 'terminate-exact-hung-preflight-child' $target
    }

    $offlineDir=Join-Path $EvidenceDirectory 'offline'; New-Item -ItemType Directory -Path $offlineDir -Force | Out-Null
    $offline=@()
    $offline += Get-Captured 'cmake.exe' @('-S',(Join-Path $repoRoot 'cpp'),'-B',(Join-Path $repoRoot 'cpp\build_pkg')) $OfflineValidationTimeoutSeconds
    $offline += Get-Captured 'cmake.exe' @('--build',(Join-Path $repoRoot 'cpp\build_pkg'),'--config','Release','--target','bulwark_service','bulwark_snapshot','bulwark_snapshot_probe','snapshot_repair_unit','defense_policy_unit','driver_match_unit') $OfflineValidationTimeoutSeconds
    $offline += Get-Captured 'ctest.exe' @('--test-dir',(Join-Path $repoRoot 'cpp\build_pkg'),'-C','Release','--output-on-failure') $OfflineValidationTimeoutSeconds
    $offline += Get-Captured (Join-Path $env:SystemRoot 'Sysnative\WindowsPowerShell\v1.0\powershell.exe') @('-NoProfile','-ExecutionPolicy','Bypass','-File',(Join-Path $repoRoot 'bulwark-selftest\Test-BulwarkCompiledRegression.ps1'),'-BuildDir',(Join-Path $repoRoot 'cpp\build_pkg'),'-ReportPath',(Join-Path $offlineDir 'compiled-regression-maintenance.json')) $OfflineValidationTimeoutSeconds
    $journal.offlineValidation=$offline; Save-Journal
    Assert (@($offline | Where-Object { $_.exitCode -ne 0 }).Count -eq 0) 'Offline validation failed; restoration will still run.'
} catch { $journal.failure=$_.Exception.ToString(); $journal.result='FAILED_BEFORE_RESTORE'; Save-Journal }
finally {
    try { Restore-Protection; $journal.result=if ($journal.failure) { 'RESTORED_AFTER_FAILURE' } else { 'RESTORED' }; Save-Journal }
    catch { $journal.restoreFailure=$_.Exception.ToString(); $journal.result='RESTORE_FAILED'; Save-Journal; throw }
    finally { Stop-Transcript | Out-Null }
}

if ($journal.result -eq 'RESTORED') {
    $ps64=Join-Path $env:SystemRoot 'Sysnative\WindowsPowerShell\v1.0\powershell.exe'
    $journal.postRestorePreflight=Get-Captured $ps64 @('-NoProfile','-ExecutionPolicy','Bypass','-File',$controllerPath,'-PreflightOnly','-PreflightStepTimeoutSeconds',[string]$StepTimeoutSeconds,'-EvidenceDirectory',(Join-Path $EvidenceDirectory 'preflight')) ($StepTimeoutSeconds * 20)
    Save-Journal
    if ($journal.postRestorePreflight.exitCode -ne 0) { $journal.result='RESTORED_PREFLIGHT_FAILED'; Save-Journal }
}
Write-Json $reportPath $journal
if ($journal.result -ne 'RESTORED') { exit 2 }
