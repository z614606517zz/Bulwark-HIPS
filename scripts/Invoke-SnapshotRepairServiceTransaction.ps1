[CmdletBinding()]
param(
    [switch]$PreflightOnly,
    [switch]$Execute,
    [switch]$AcknowledgeAuthorizedRepair,
    [switch]$OfflineRollbackSelfTest,
    [string]$OfflineRollbackSelfTestReportPath = '',
    [string]$EvidenceDirectory = '',
    [string]$BuildServicePath = ''
)

$ErrorActionPreference = 'Stop'
$repoRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..')).TrimEnd('\')
if ([string]::IsNullOrWhiteSpace($EvidenceDirectory)) {
    $EvidenceDirectory = Join-Path $repoRoot '.agents\tasks\snapshot-full-regression-fix\evidence\implementation\preflight'
}
if ([string]::IsNullOrWhiteSpace($BuildServicePath)) {
    $BuildServicePath = Join-Path $repoRoot 'cpp\build_pkg\service\Release\bulwark_service.exe'
}
if ($Execute -and -not $AcknowledgeAuthorizedRepair) {
    throw '-Execute requires -AcknowledgeAuthorizedRepair.'
}
if ($PreflightOnly -and $Execute) { throw 'Choose either -PreflightOnly or -Execute.' }
if ($OfflineRollbackSelfTest -and ($PreflightOnly -or $Execute -or $AcknowledgeAuthorizedRepair)) {
    throw '-OfflineRollbackSelfTest cannot be combined with live transaction switches.'
}

$installedService = Join-Path $repoRoot 'cpp\dist\bulwark_service.exe'
$installedUi = Join-Path $repoRoot 'cpp\dist\bulwark_ui.exe'
$appsettings = Join-Path $repoRoot 'cpp\dist\appsettings.json'
$driver = Join-Path $env:SystemRoot 'System32\drivers\Bulwark.sys'
$snapshot = Join-Path $repoRoot 'cpp\build_pkg\tests\Release\bulwark_snapshot.exe'
$snapshotTool = Join-Path $repoRoot 'cpp\tests\SnapshotTool.cpp'
$corpus = Join-Path $repoRoot 'cpp\tests\data\corpus.json'
$golden = Join-Path $repoRoot 'cpp\tests\data\golden.json'
$userManifest = Join-Path $env:ProgramData 'Bulwark\usermode_execblock.json'
$policyKey = 'HKLM:\SYSTEM\CurrentControlSet\Services\Bulwark\Policy'
$targetNeedle = '\' + [IO.Path]::GetFileName($repoRoot) + '\CPP\BUILD_PKG\TESTS\RELEASE\BULWARK_SNAPSHOT.EXE'
$sentinelNeedle = '\BULWARK_REPAIR_SENTINEL_7EA4E5C4\DO_NOT_CREATE.EXE'
$expectedDriverHash = 'CA4F68AF4BE7D0BB4391487505F469ACD70E7A945AE4431879EB0FD156A60AFD'
$expectedThumbprint = '23AB51ED334ABCCBE3715D37DD9EA57837279338'
$expectedSnapshotHashes = [ordered]@{
    SnapshotTool = '928C62554970E80C87BC17DAF5BD19A1E95207321C1644B394251CBA8D746D00'
    Corpus = '3691ACD2ACDDB4C002DC5B469A376182C318D7E68D623EC0FEE131FCA71020CA'
    Golden = 'F4CB168F5266D9669A1234C1E909D0F7283F87A272C6980B716592B1EFF41417'
}

function Get-Identity([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        return [ordered]@{ path=$Path; exists=$false; size=$null; sha256=$null }
    }
    $item = Get-Item -LiteralPath $Path
    return [ordered]@{
        path=$item.FullName; exists=$true; size=$item.Length
        sha256=(Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash
        lastWriteTimeUtc=$item.LastWriteTimeUtc.ToString('o')
    }
}

function Invoke-Captured([string]$FileName, [string[]]$Arguments) {
    $psi = New-Object Diagnostics.ProcessStartInfo
    $psi.FileName = $FileName
    $psi.Arguments = ($Arguments | ForEach-Object {
        if ($_ -notmatch '[\s"]') { $_ } else { '"' + ($_ -replace '(\\*)"', '$1$1\"' -replace '(\\+)$', '$1$1') + '"' }
    }) -join ' '
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $process = New-Object Diagnostics.Process
    $process.StartInfo = $psi
    $startedUtc = [DateTime]::UtcNow.ToString('o')
    [void]$process.Start()
    $stdout = $process.StandardOutput.ReadToEnd()
    $stderr = $process.StandardError.ReadToEnd()
    $process.WaitForExit()
    $result = [ordered]@{ file=$FileName; argv=@($Arguments); startedUtc=$startedUtc; finishedUtc=[DateTime]::UtcNow.ToString('o'); exitCode=$process.ExitCode; stdout=$stdout; stderr=$stderr }
    $process.Dispose()
    return $result
}

function Find-SignTool {
    $command = Get-Command signtool.exe -ErrorAction SilentlyContinue
    if ($command) { return $command.Source }
    $kitRoot = Join-Path ${env:ProgramFiles(x86)} 'Windows Kits\10\bin'
    return Get-ChildItem -LiteralPath $kitRoot -Filter signtool.exe -File -Recurse -ErrorAction SilentlyContinue |
        Where-Object { $_.FullName -match '\\x64\\signtool\.exe$' } |
        Sort-Object FullName -Descending | Select-Object -First 1 -ExpandProperty FullName
}

function Get-ServiceSnapshot([string]$Name) {
    if ($Name -eq 'Bulwark') {
        $driverState = Get-CimInstance Win32_SystemDriver -Filter "Name='Bulwark'"
        return [ordered]@{ name=$Name; state=$driverState.State; startMode=$driverState.StartMode; processId=$null; pathName=$driverState.PathName }
    }
    $service = Get-CimInstance Win32_Service -Filter ("Name='{0}'" -f $Name)
    return [ordered]@{ name=$Name; state=$service.State; startMode=$service.StartMode; processId=$service.ProcessId; pathName=$service.PathName }
}

function Wait-ServiceState([string]$Name, [string]$State, [int]$Seconds=40) {
    $deadline = [DateTime]::UtcNow.AddSeconds($Seconds)
    do {
        $current = (Get-Service -Name $Name).Status.ToString()
        if ($current -eq $State) { return }
        Start-Sleep -Milliseconds 250
    } while ([DateTime]::UtcNow -lt $deadline)
    throw "Service $Name did not reach $State."
}

$utc = [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssZ')
$transactionRoot = Join-Path $repoRoot ('.agents\tasks\driver-deploy-20261023-1652\snapshot-full-regression-fix-' + $utc)
$preimageDir = Join-Path $transactionRoot 'preimage'
if (-not $OfflineRollbackSelfTest) {
    New-Item -ItemType Directory -Path $EvidenceDirectory,$preimageDir -Force | Out-Null
}
$recordPath = Join-Path $EvidenceDirectory ('transaction-' + $utc + '.json')
$record = [ordered]@{
    schemaVersion=1; transactionId=$utc; startedUtc=[DateTime]::UtcNow.ToString('o')
    mode=$(if ($Execute) { 'execute' } else { 'preflight' })
    repositoryRoot=$repoRoot; transactionRoot=$transactionRoot
    normalRoute=[ordered]@{ serviceOnly=$true; driverReplacement=$false; uiReplacement=$false; driverUnload=$false }
    contingency=[ordered]@{
        enabled=$false
        reason='Driver/UI replacement requires separate written technical necessity and explicit authorization.'
        driverBuildCommand=('powershell -NoProfile -ExecutionPolicy Bypass -File "{0}" -Configuration Release -Log <new absolute evidence log>' -f (Join-Path $repoRoot '.agents\tasks\driver-build\build-manual.ps1'))
        requiredImportFloor='IMPORT FLOOR OK: no DDI newer than Windows 10 1703'
        signingThumbprint=$expectedThumbprint
    }
    checks=New-Object System.Collections.Generic.List[object]
    preimage=[ordered]@{}
    actions=New-Object System.Collections.Generic.List[object]
    rollback=[ordered]@{ attempted=$false; complete=$false; reason=$null; verification=New-Object System.Collections.Generic.List[object] }
}

function Normalize-PolicyEntry([string]$Value) {
    if ($null -eq $Value) { return '' }
    return $Value.Normalize([Text.NormalizationForm]::FormC).Trim().Replace('/','\').ToUpperInvariant()
}

function Add-Check([string]$Name, [bool]$Pass, $Observed) {
    $record.checks.Add([ordered]@{ name=$Name; pass=$Pass; observed=$Observed })
    if (-not $Pass) { throw "Preflight failed: $Name" }
}
function Save-Record {
    $record.finishedUtc = [DateTime]::UtcNow.ToString('o')
    [IO.File]::WriteAllText($recordPath, ($record | ConvertTo-Json -Depth 12), (New-Object Text.UTF8Encoding($false)))
}

function Get-FileExecBlock {
    return @((Get-ItemProperty -LiteralPath $policyKey -Name FileExecBlock).FileExecBlock)
}

function Get-NormalizedPolicy([object[]]$Entries) {
    return @($Entries | ForEach-Object { Normalize-PolicyEntry ([string]$_) } | Sort-Object)
}

function Test-StringArrayEqual([object[]]$Left, [object[]]$Right) {
    $leftValues = @($Left)
    $rightValues = @($Right)
    if ($leftValues.Count -ne $rightValues.Count) { return $false }
    for ($i = 0; $i -lt $leftValues.Count; ++$i) {
        if ([string]$leftValues[$i] -cne [string]$rightValues[$i]) { return $false }
    }
    return $true
}

function Test-IdentityEqual($Expected, $Actual) {
    if ([bool]$Expected.exists -ne [bool]$Actual.exists) { return $false }
    if (-not $Expected.exists) { return $true }
    return $Expected.size -eq $Actual.size -and $Expected.sha256 -eq $Actual.sha256
}

function Get-UiProcessSnapshot {
    $processes = @(Get-Process bulwark_ui -ErrorAction SilentlyContinue | ForEach-Object {
        [ordered]@{ id=$_.Id; path=$_.Path }
    })
    return [ordered]@{
        count=$processes.Count
        paths=@($processes | ForEach-Object { ([IO.Path]::GetFullPath($_.path)).ToUpperInvariant() } | Sort-Object)
        processes=$processes
    }
}

function Get-MinifilterSnapshot {
    $filters = (& (Join-Path $env:SystemRoot 'System32\fltmc.exe') filters 2>&1 | Out-String)
    $instances = (& (Join-Path $env:SystemRoot 'System32\fltmc.exe') instances 2>&1 | Out-String)
    return [ordered]@{
        filters=$filters
        instances=$instances
        altitudePresent=($filters -match '(?m)^Bulwark\s+\d+\s+385201\s')
        instanceCount=([regex]::Matches($instances, '(?m)^Bulwark\s+.*385201\s+Bulwark Instance').Count)
    }
}

function Wait-ExactPolicyPreimage([object[]]$Expected, [int]$Seconds=5) {
    $expectedNormalized = Get-NormalizedPolicy $Expected
    $deadline = [DateTime]::UtcNow.AddSeconds($Seconds)
    do {
        $first = Get-NormalizedPolicy (Get-FileExecBlock)
        if (Test-StringArrayEqual $expectedNormalized $first) {
            Start-Sleep -Milliseconds 350
            $second = Get-NormalizedPolicy (Get-FileExecBlock)
            if (Test-StringArrayEqual $expectedNormalized $second) {
                return [ordered]@{ pass=$true; expected=$expectedNormalized; observed=$second }
            }
        }
        Start-Sleep -Milliseconds 100
    } while ([DateTime]::UtcNow -lt $deadline)
    return [ordered]@{ pass=$false; expected=$expectedNormalized; observed=(Get-NormalizedPolicy (Get-FileExecBlock)) }
}

function Test-SelfGuardPostcondition([DateTime]$ServiceStartUtc) {
    Start-Sleep -Seconds 2
    $logPath = Join-Path $env:ProgramData 'Bulwark\service.log'
    $logObserved = $false
    $logLastWriteUtc = $null
    if (Test-Path -LiteralPath $logPath -PathType Leaf) {
        $logItem = Get-Item -LiteralPath $logPath
        $logLastWriteUtc = $logItem.LastWriteTimeUtc.ToString('o')
        $logTail = Get-Content -LiteralPath $logPath -Tail 500 -Encoding UTF8 | Out-String
        $logObserved = $logItem.LastWriteTimeUtc -ge $ServiceStartUtc -and $logTail -match 'SelfGuard'
    }

    $probe = Join-Path (Split-Path $installedService -Parent) ('.bulwark-selfguard-probe-' + $PID + '.tmp')
    $writeDenied = $false
    $writeError = $null
    $cleanupError = $null
    try {
        [IO.File]::WriteAllText($probe, 'harmless selfguard write-denial probe')
    } catch {
        $writeDenied = $true
        $writeError = $_.Exception.Message
    }
    if (Test-Path -LiteralPath $probe -PathType Leaf) {
        try { Remove-Item -LiteralPath $probe -Force } catch { $cleanupError = $_.Exception.Message }
    }
    return [ordered]@{
        pass=($logObserved -and $writeDenied -and [string]::IsNullOrWhiteSpace($cleanupError))
        serviceStartUtc=$ServiceStartUtc.ToString('o')
        logObserved=$logObserved
        logLastWriteUtc=$logLastWriteUtc
        foreignWriteDenied=$writeDenied
        writeError=$writeError
        cleanupError=$cleanupError
    }
}

function Add-RollbackCheck([string]$Name, [bool]$Pass, $Observed) {
    $record.rollback.verification.Add([ordered]@{ name=$Name; pass=$Pass; observed=$Observed })
    if (-not $Pass) { throw "Rollback verification failed: $Name" }
}

$requiredRollbackChecks = @(
    'exact canonical FileExecBlock preimage restored',
    'user-mode exec-block manifest identity restored',
    'service binary identity restored',
    'service registration and Running state restored',
    'driver Running with pinned hash and signature',
    'Minifilter altitude and instances restored',
    'UI state restored to preimage',
    'appsettings identity restored',
    'SelfGuard re-armed and foreign write denied'
)

function Test-RollbackCompletionContract([object[]]$Verification) {
    $missing = New-Object System.Collections.Generic.List[string]
    $failed = New-Object System.Collections.Generic.List[string]
    $duplicate = New-Object System.Collections.Generic.List[string]
    foreach ($required in $requiredRollbackChecks) {
        $matches = @($Verification | Where-Object { $_.name -eq $required })
        if ($matches.Count -eq 0) {
            $missing.Add($required)
        } elseif ($matches.Count -ne 1) {
            $duplicate.Add($required)
        } elseif (-not [bool]$matches[0].pass) {
            $failed.Add($required)
        }
    }
    return [ordered]@{
        pass=($missing.Count -eq 0 -and $failed.Count -eq 0 -and $duplicate.Count -eq 0)
        required=@($requiredRollbackChecks)
        missing=$missing.ToArray()
        failed=$failed.ToArray()
        duplicate=$duplicate.ToArray()
    }
}

if ($OfflineRollbackSelfTest) {
    if ([string]::IsNullOrWhiteSpace($OfflineRollbackSelfTestReportPath)) {
        $OfflineRollbackSelfTestReportPath = Join-Path $repoRoot '.agents\tasks\snapshot-full-regression-fix\evidence\implementation\rollback-verification-selftest.json'
    }
    $reportParent = Split-Path -Parent $OfflineRollbackSelfTestReportPath
    if (-not [string]::IsNullOrWhiteSpace($reportParent)) {
        New-Item -ItemType Directory -Path $reportParent -Force | Out-Null
    }

    $baseline = @($requiredRollbackChecks | ForEach-Object {
        [pscustomobject]@{ name=$_; pass=$true; observed='fake-offline-pass' }
    })
    $cases = New-Object System.Collections.Generic.List[object]
    $allPass = Test-RollbackCompletionContract $baseline
    $cases.Add([ordered]@{ name='all required checks pass'; expected=$true; actual=$allPass.pass; detail=$allPass })

    foreach ($injectedFailure in $requiredRollbackChecks) {
        $verification = @($requiredRollbackChecks | ForEach-Object {
            [pscustomobject]@{ name=$_; pass=($_ -ne $injectedFailure); observed='fake-offline-injection' }
        })
        $result = Test-RollbackCompletionContract $verification
        $cases.Add([ordered]@{
            name=('injected failure: ' + $injectedFailure)
            expected=$false
            actual=$result.pass
            rollbackCompleteWouldRemainFalse=(-not $result.pass)
            detail=$result
        })
    }

    $missingResult = Test-RollbackCompletionContract @($baseline | Select-Object -Skip 1)
    $cases.Add([ordered]@{
        name='missing required evidence'
        expected=$false
        actual=$missingResult.pass
        rollbackCompleteWouldRemainFalse=(-not $missingResult.pass)
        detail=$missingResult
    })
    $duplicateResult = Test-RollbackCompletionContract @($baseline + $baseline[0])
    $cases.Add([ordered]@{
        name='duplicate required evidence'
        expected=$false
        actual=$duplicateResult.pass
        rollbackCompleteWouldRemainFalse=(-not $duplicateResult.pass)
        detail=$duplicateResult
    })

    $failedCases = @($cases | Where-Object { $_.actual -ne $_.expected })
    $selfTest = [ordered]@{
        schemaVersion=1
        generatedUtc=[DateTime]::UtcNow.ToString('o')
        mode='offline-rollback-completion-failure-injection'
        liveStateRead=$false
        serviceLifecycleChanged=$false
        driverOrPolicyChanged=$false
        requiredChecks=@($requiredRollbackChecks)
        cases=$cases.ToArray()
        passed=($failedCases.Count -eq 0)
        failedCases=@($failedCases)
    }
    [IO.File]::WriteAllText(
        $OfflineRollbackSelfTestReportPath,
        ($selfTest | ConvertTo-Json -Depth 12),
        (New-Object Text.UTF8Encoding($false)))
    if (-not $selfTest.passed) { exit 1 }
    Write-Host "Offline rollback verification self-test passed: $OfflineRollbackSelfTestReportPath"
    exit 0
}

$repairCommitted = $false
$serviceReplaced = $false
try {
    $record.preimage.service = Get-Identity $installedService
    $record.preimage.ui = Get-Identity $installedUi
    $record.preimage.driver = Get-Identity $driver
    $record.preimage.appsettings = Get-Identity $appsettings
    $record.preimage.snapshot = Get-Identity $snapshot
    $record.preimage.snapshotTool = Get-Identity $snapshotTool
    $record.preimage.corpus = Get-Identity $corpus
    $record.preimage.golden = Get-Identity $golden
    $record.preimage.candidateService = Get-Identity $BuildServicePath
    $record.preimage.serviceRegistration = Get-ServiceSnapshot 'BulwarkService'
    $record.preimage.driverService = Get-ServiceSnapshot 'Bulwark'
    $record.preimage.uiProcesses = @(Get-Process bulwark_ui -ErrorAction SilentlyContinue | ForEach-Object { [ordered]@{ id=$_.Id; path=$_.Path; startTimeUtc=$_.StartTime.ToUniversalTime().ToString('o') } })
    $record.preimage.fltmcFilters = (& (Join-Path $env:SystemRoot 'System32\fltmc.exe') filters 2>&1 | Out-String)
    $record.preimage.fltmcInstances = (& (Join-Path $env:SystemRoot 'System32\fltmc.exe') instances 2>&1 | Out-String)
    $record.preimage.fileExecBlock = @((Get-ItemProperty -LiteralPath $policyKey -Name FileExecBlock).FileExecBlock)
    $record.preimage.userModeExecBlockManifest = Get-Identity $userManifest

    Add-Check 'candidate Release service exists' $record.preimage.candidateService.exists $record.preimage.candidateService
    Add-Check 'normal service running before transaction' ($record.preimage.serviceRegistration.state -eq 'Running') $record.preimage.serviceRegistration
    Add-Check 'installed driver hash pinned' ($record.preimage.driver.sha256 -eq $expectedDriverHash) $record.preimage.driver.sha256
    $signature = Get-AuthenticodeSignature -LiteralPath $driver
    Add-Check 'installed driver Authenticode valid' ($signature.Status -eq 'Valid') $signature.Status.ToString()
    Add-Check 'installed driver signer pinned' ($signature.SignerCertificate.Thumbprint -eq $expectedThumbprint) $signature.SignerCertificate.Thumbprint
    Add-Check 'driver service running' ($record.preimage.driverService.state -eq 'Running') $record.preimage.driverService
    Add-Check 'Minifilter altitude 385201' ($record.preimage.fltmcFilters -match '(?m)^Bulwark\s+\d+\s+385201\s') $record.preimage.fltmcFilters
    Add-Check 'Minifilter instances attached' ($record.preimage.fltmcInstances -match '(?m)^Bulwark\s+') $record.preimage.fltmcInstances
    Add-Check 'SnapshotTool hash locked' ($record.preimage.snapshotTool.sha256 -eq $expectedSnapshotHashes.SnapshotTool) $record.preimage.snapshotTool.sha256
    Add-Check 'corpus hash locked' ($record.preimage.corpus.sha256 -eq $expectedSnapshotHashes.Corpus) $record.preimage.corpus.sha256
    Add-Check 'golden hash locked' ($record.preimage.golden.sha256 -eq $expectedSnapshotHashes.Golden) $record.preimage.golden.sha256
    Add-Check 'exact target appears once' (@($record.preimage.fileExecBlock | Where-Object { (Normalize-PolicyEntry ([string]$_)) -eq (Normalize-PolicyEntry $targetNeedle) }).Count -eq 1) $record.preimage.fileExecBlock
    Add-Check 'repair sentinel absent' (@($record.preimage.fileExecBlock | Where-Object { (Normalize-PolicyEntry ([string]$_)) -eq (Normalize-PolicyEntry $sentinelNeedle) }).Count -eq 0) $record.preimage.fileExecBlock

    $signtool = Find-SignTool
    Add-Check 'signtool available' (-not [string]::IsNullOrWhiteSpace($signtool)) $signtool
    $pa = Invoke-Captured $signtool @('verify','/pa',$driver)
    $kp = Invoke-Captured $signtool @('verify','/kp',$driver)
    $record.preimage.signtool = [ordered]@{ pa=$pa; kp=$kp; kpExpectedLimitation='Local test certificate is not kernel-production trusted; nonzero /kp is expected.' }
    Add-Check 'signtool verify /pa succeeds' ($pa.exitCode -eq 0) $pa
    Add-Check 'signtool verify /kp has expected local-test-certificate limitation' ($kp.exitCode -ne 0) $kp

    foreach ($item in @(
        @{Name='service';Path=$installedService}, @{Name='ui';Path=$installedUi},
        @{Name='driver';Path=$driver}, @{Name='appsettings';Path=$appsettings},
        @{Name='snapshot';Path=$snapshot}, @{Name='snapshotTool';Path=$snapshotTool},
        @{Name='corpus';Path=$corpus}, @{Name='golden';Path=$golden})) {
        if (Test-Path -LiteralPath $item.Path -PathType Leaf) {
            $copy = Join-Path $preimageDir ($item.Name + [IO.Path]::GetExtension($item.Path))
            Copy-Item -LiteralPath $item.Path -Destination $copy
            Add-Check ("byte backup verified: " + $item.Name) `
                ((Get-FileHash -LiteralPath $copy -Algorithm SHA256).Hash -eq (Get-FileHash -LiteralPath $item.Path -Algorithm SHA256).Hash) `
                (Get-Identity $copy)
        }
    }
    Save-Record
    if (-not $Execute) {
        Write-Host "Preflight passed. Manifest: $recordPath"
        exit 0
    }

    $maintenanceStarted = [DateTime]::UtcNow
    $record.actions.Add([ordered]@{ action='maintenance-window-start'; utc=$maintenanceStarted.ToString('o'); limitSeconds=90 })
    Stop-Service -Name BulwarkService
    Wait-ServiceState 'BulwarkService' 'Stopped'
    $stopped = Get-ServiceSnapshot 'BulwarkService'
    if ($stopped.processId -ne 0) { throw 'BulwarkService port owner is still present after stop.' }
    $record.actions.Add([ordered]@{ action='service-stopped-port-owner-gone'; utc=[DateTime]::UtcNow.ToString('o'); state=$stopped })

    Copy-Item -LiteralPath $BuildServicePath -Destination $installedService -Force
    $serviceReplaced = $true
    $candidateHash = (Get-FileHash -LiteralPath $BuildServicePath -Algorithm SHA256).Hash
    if ((Get-FileHash -LiteralPath $installedService -Algorithm SHA256).Hash -ne $candidateHash) { throw 'Service replacement hash mismatch.' }
    if ((Get-FileHash -LiteralPath $appsettings -Algorithm SHA256).Hash -ne $record.preimage.appsettings.sha256) { throw 'appsettings changed during service replacement.' }
    if ((Get-FileHash -LiteralPath $driver -Algorithm SHA256).Hash -ne $expectedDriverHash) { throw 'Driver changed during service-only transaction.' }

    $repair = Invoke-Captured $installedService @('--repair-full-regression-snapshot','--acknowledge-authorized-repair')
    $record.actions.Add([ordered]@{ action='closed-exact-repair'; result=$repair })
    if ($repair.exitCode -ne 0) { throw 'Closed exact repair failed.' }
    $repairCommitted = $true
    if (([DateTime]::UtcNow - $maintenanceStarted).TotalSeconds -gt 90) { throw 'Repair exceeded the 90-second maintenance deadline.' }

    Start-Service -Name BulwarkService
    Wait-ServiceState 'BulwarkService' 'Running'
    Start-Sleep -Seconds 2
    $logPath = Join-Path $env:ProgramData 'Bulwark\service.log'
    $logTail = if (Test-Path -LiteralPath $logPath) { Get-Content -LiteralPath $logPath -Tail 500 -Encoding UTF8 | Out-String } else { '' }
    if ($logTail -notmatch 'SelfGuard') { throw 'SelfGuard re-arm log was not observed.' }

    $probe = Join-Path (Split-Path $installedService -Parent) ('.bulwark-selfguard-probe-' + $PID + '.tmp')
    $denied = $false
    try { [IO.File]::WriteAllText($probe, 'harmless selfguard write-denial probe'); Remove-Item -LiteralPath $probe -Force } catch { $denied = $true }
    if (-not $denied) { throw 'Harmless foreign installation-directory write was not denied by SelfGuard.' }
    $record.actions.Add([ordered]@{ action='selfguard-verified'; utc=[DateTime]::UtcNow.ToString('o'); logObserved=$true; foreignWriteDenied=$true })

    if ((Get-FileHash -LiteralPath $appsettings -Algorithm SHA256).Hash -ne $record.preimage.appsettings.sha256) { throw 'appsettings post-hash mismatch.' }
    if ((Get-FileHash -LiteralPath $driver -Algorithm SHA256).Hash -ne $expectedDriverHash) { throw 'installed driver post-hash mismatch.' }
    $postPolicy = @((Get-ItemProperty -LiteralPath $policyKey -Name FileExecBlock).FileExecBlock)
    if (@($postPolicy | Where-Object { (Normalize-PolicyEntry ([string]$_)) -eq (Normalize-PolicyEntry $targetNeedle) }).Count -ne 0) { throw 'Exact target still exists after committed repair.' }
    $record.postimage = [ordered]@{ service=$(Get-Identity $installedService); driver=$(Get-Identity $driver); appsettings=$(Get-Identity $appsettings); fileExecBlock=$postPolicy; serviceState=$(Get-ServiceSnapshot 'BulwarkService') }
    Save-Record
    Write-Host "Service-only transaction committed. Record: $recordPath"
    exit 0
} catch {
    $record.rollback.attempted = $Execute
    $record.rollback.reason = $_.Exception.ToString()
    if ($Execute) {
        try {
            if ((Get-Service BulwarkService).Status -ne 'Stopped') { Stop-Service BulwarkService; Wait-ServiceState 'BulwarkService' 'Stopped' }
            if ($repairCommitted) {
                $restore = Invoke-Captured $installedService @('--restore-full-regression-snapshot','--acknowledge-authorized-repair')
                $record.actions.Add([ordered]@{ action='journal-derived-exact-policy-restore'; result=$restore })
                if ($restore.exitCode -ne 0) { throw 'Journal-derived exact target restore failed.' }
            }
            if ($serviceReplaced) {
                Copy-Item -LiteralPath (Join-Path $preimageDir 'service.exe') -Destination $installedService -Force
                if ((Get-FileHash -LiteralPath $installedService -Algorithm SHA256).Hash -ne $record.preimage.service.sha256) { throw 'Service rollback hash mismatch.' }
            }
            $rollbackServiceStartUtc = [DateTime]::UtcNow
            Start-Service BulwarkService
            Wait-ServiceState 'BulwarkService' 'Running'

            $policyVerification = Wait-ExactPolicyPreimage $record.preimage.fileExecBlock
            Add-RollbackCheck 'exact canonical FileExecBlock preimage restored' $policyVerification.pass $policyVerification

            $manifestNow = Get-Identity $userManifest
            Add-RollbackCheck 'user-mode exec-block manifest identity restored' `
                (Test-IdentityEqual $record.preimage.userModeExecBlockManifest $manifestNow) $manifestNow

            $serviceNow = Get-ServiceSnapshot 'BulwarkService'
            $serviceIdentityNow = Get-Identity $installedService
            Add-RollbackCheck 'service binary identity restored' `
                (Test-IdentityEqual $record.preimage.service $serviceIdentityNow) $serviceIdentityNow
            $serviceRegistrationPass = $serviceNow.state -eq 'Running' `
                -and $serviceNow.startMode -eq $record.preimage.serviceRegistration.startMode `
                -and $serviceNow.pathName -eq $record.preimage.serviceRegistration.pathName
            Add-RollbackCheck 'service registration and Running state restored' $serviceRegistrationPass $serviceNow

            $driverNow = Get-ServiceSnapshot 'Bulwark'
            $driverIdentityNow = Get-Identity $driver
            $driverSignatureNow = Get-AuthenticodeSignature -LiteralPath $driver
            $driverPaNow = Invoke-Captured $signtool @('verify','/pa',$driver)
            $driverPass = $driverNow.state -eq 'Running' `
                -and $driverIdentityNow.sha256 -eq $expectedDriverHash `
                -and $driverSignatureNow.Status -eq 'Valid' `
                -and $driverSignatureNow.SignerCertificate.Thumbprint -eq $expectedThumbprint `
                -and $driverPaNow.exitCode -eq 0
            Add-RollbackCheck 'driver Running with pinned hash and signature' $driverPass `
                ([ordered]@{ service=$driverNow; identity=$driverIdentityNow; authenticode=$driverSignatureNow.Status.ToString(); thumbprint=$driverSignatureNow.SignerCertificate.Thumbprint; signtoolPa=$driverPaNow })

            $filterNow = Get-MinifilterSnapshot
            $preimageInstanceCount = [regex]::Matches(
                [string]$record.preimage.fltmcInstances,
                '(?m)^Bulwark\s+.*385201\s+Bulwark Instance').Count
            Add-RollbackCheck 'Minifilter altitude and instances restored' `
                ($filterNow.altitudePresent -and $filterNow.instanceCount -eq $preimageInstanceCount -and $filterNow.instanceCount -gt 0) $filterNow

            $expectedUiPaths = @($record.preimage.uiProcesses | ForEach-Object {
                ([IO.Path]::GetFullPath($_.path)).ToUpperInvariant()
            } | Sort-Object)
            $uiNow = Get-UiProcessSnapshot
            if ($expectedUiPaths.Count -gt 0 -and $uiNow.count -eq 0) {
                Start-Process -FilePath $installedUi
                Start-Sleep -Seconds 2
                $uiNow = Get-UiProcessSnapshot
            }
            Add-RollbackCheck 'UI state restored to preimage' `
                ($uiNow.count -eq $expectedUiPaths.Count -and (Test-StringArrayEqual $expectedUiPaths $uiNow.paths)) $uiNow

            $appsettingsNow = Get-Identity $appsettings
            Add-RollbackCheck 'appsettings identity restored' `
                (Test-IdentityEqual $record.preimage.appsettings $appsettingsNow) $appsettingsNow

            $selfGuardNow = Test-SelfGuardPostcondition $rollbackServiceStartUtc
            Add-RollbackCheck 'SelfGuard re-armed and foreign write denied' $selfGuardNow.pass $selfGuardNow

            $completion = Test-RollbackCompletionContract $record.rollback.verification.ToArray()
            $record.rollback.completionContract = $completion
            if (-not $completion.pass) { throw 'Rollback completion contract rejected the retained evidence.' }
            $record.rollback.complete = $true
        } catch {
            $record.rollback.failure = $_.Exception.ToString()
        }
    }
    Save-Record
    Write-Error ("Snapshot repair transaction failed: " + $record.rollback.reason + " Record: " + $recordPath)
    exit 2
}
