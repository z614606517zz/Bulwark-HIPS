[CmdletBinding()]
param(
    [switch]$PreflightOnly,
    [switch]$Execute,
    [switch]$AcknowledgeAuthorizedReconciliation,
    [string]$SnapshotCandidatePath = '',
    [string]$EvidenceDirectory = '',
    [string]$ApprovalVerdictPath = '',
    [ValidateSet('all-pass','missing-evidence','duplicate-evidence',
        'file-execblock','user-manifest','service-binary','service-registration',
        'snapshot-preimage','driver','minifilter','ui','appsettings','selfguard')]
    [string]$OfflineRollbackFailureInjection = '',
    [ValidateSet('stage-created','service-stop-intent','service-stopped','snapshot-installed','service-restarted')]
    [string]$OfflineInterruptionFailureInjection = '',
    [ValidateSet('all-pass','x86-on-x64-sysnative','x64-on-x64-system32','x86-on-x86-system32','missing-file','redirected-path','wrong-service-image','hash-mismatch','signature-mismatch','thumbprint-mismatch','signtool-failure','service-stopped')]
    [string]$OfflineDriverPathFailureInjection = '',
    [ValidateSet('all-pass','external-timeout','incomplete-preflight','canceled-preflight')]
    [string]$OfflinePreflightFailureInjection = '',
    [ValidateRange(5,120)][int]$PreflightStepTimeoutSeconds = 30,
    [switch]$OfflineRollbackAggregate,
    [string]$OfflineRollbackReportPath = ''
)

$ErrorActionPreference = 'Stop'
$script:preflightCancellationRequested = $false
$repoRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..')).TrimEnd('\')
$canonicalSnapshot = Join-Path $repoRoot 'cpp\dist\bulwark_snapshot.exe'
$servicePath = Join-Path $repoRoot 'cpp\dist\bulwark_service.exe'
$uiPath = Join-Path $repoRoot 'cpp\dist\bulwark_ui.exe'
$appsettingsPath = Join-Path $repoRoot 'cpp\dist\appsettings.json'
$expectedDriverInstallPath = [IO.Path]::GetFullPath((Join-Path $env:SystemRoot 'System32\drivers\Bulwark.sys'))
$driverServiceKey = 'HKLM:\SYSTEM\CurrentControlSet\Services\Bulwark'
$policyKey = 'HKLM:\SYSTEM\CurrentControlSet\Services\Bulwark\Policy'
$userManifestPath = Join-Path $env:ProgramData 'Bulwark\usermode_execblock.json'
$protectedInputs = [ordered]@{
    snapshotTool = [ordered]@{ path=(Join-Path $repoRoot 'cpp\tests\SnapshotTool.cpp'); sha256='928C62554970E80C87BC17DAF5BD19A1E95207321C1644B394251CBA8D746D00' }
    corpus = [ordered]@{ path=(Join-Path $repoRoot 'cpp\tests\data\corpus.json'); sha256='3691ACD2ACDDB4C002DC5B469A376182C318D7E68D623EC0FEE131FCA71020CA' }
    golden = [ordered]@{ path=(Join-Path $repoRoot 'cpp\tests\data\golden.json'); sha256='F4CB168F5266D9669A1234C1E909D0F7283F87A272C6980B716592B1EFF41417' }
}
$expectedDriverHash = 'CA4F68AF4BE7D0BB4391487505F469ACD70E7A945AE4431879EB0FD156A60AFD'
$expectedDriverThumbprint = '23AB51ED334ABCCBE3715D37DD9EA57837279338'
$rollbackGates = @(
    'canonical FileExecBlock preimage restored',
    'user-mode exec-block manifest identity restored',
    'service binary identity restored',
    'service registration and Running state restored',
    'Snapshot artifact preimage and identity restored',
    'driver Running hash Authenticode thumbprint and signtool-pa restored',
    'Minifilter altitude and preimage instance count restored',
    'exact UI process and path preimage restored',
    'appsettings identity restored',
    'fresh SelfGuard log and harmless foreign-write denial restored'
)
$gateByInjection = [ordered]@{
    'file-execblock'='canonical FileExecBlock preimage restored'
    'user-manifest'='user-mode exec-block manifest identity restored'
    'service-binary'='service binary identity restored'
    'service-registration'='service registration and Running state restored'
    'snapshot-preimage'='Snapshot artifact preimage and identity restored'
    'driver'='driver Running hash Authenticode thumbprint and signtool-pa restored'
    'minifilter'='Minifilter altitude and preimage instance count restored'
    'ui'='exact UI process and path preimage restored'
    'appsettings'='appsettings identity restored'
    'selfguard'='fresh SelfGuard log and harmless foreign-write denial restored'
}

function Get-Identity([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        return [ordered]@{ path=$Path; exists=$false; size=$null; sha256=$null }
    }
    $item = Get-Item -LiteralPath $Path
    return [ordered]@{ path=$item.FullName; exists=$true; size=$item.Length; sha256=(Get-FileHash -LiteralPath $item.FullName -Algorithm SHA256).Hash; lastWriteTimeUtc=$item.LastWriteTimeUtc.ToString('o') }
}

function Test-IdentityEqual($Expected, $Actual) {
    if ([bool]$Expected.exists -ne [bool]$Actual.exists) { return $false }
    if (-not [bool]$Expected.exists) { return $true }
    return $Expected.size -eq $Actual.size -and $Expected.sha256 -eq $Actual.sha256
}

function Normalize-PolicyEntry([string]$Value) {
    if ($null -eq $Value) { return '' }
    return $Value.Normalize([Text.NormalizationForm]::FormC).Trim().Replace('/','\\').ToUpperInvariant()
}

function Get-NormalizedPolicy([object[]]$Entries) {
    return @($Entries | ForEach-Object { Normalize-PolicyEntry ([string]$_) } | Sort-Object)
}

function Test-StringArrayEqual([object[]]$Left, [object[]]$Right) {
    $leftValues = @($Left); $rightValues = @($Right)
    if ($leftValues.Count -ne $rightValues.Count) { return $false }
    for ($index = 0; $index -lt $leftValues.Count; ++$index) {
        if ([string]$leftValues[$index] -cne [string]$rightValues[$index]) { return $false }
    }
    return $true
}

function Test-UiSnapshotEqual($Expected, $Actual) {
    $expectedProcesses = @($Expected.processes | ForEach-Object {
        ('{0}|{1}|{2}' -f [int]$_.id, ([string]$_.path).ToUpperInvariant(), [string]$_.startTimeUtc)
    } | Sort-Object)
    $actualProcesses = @($Actual.processes | ForEach-Object {
        ('{0}|{1}|{2}' -f [int]$_.id, ([string]$_.path).ToUpperInvariant(), [string]$_.startTimeUtc)
    } | Sort-Object)
    return Test-StringArrayEqual $expectedProcesses $actualProcesses
}

function Get-TextSha256([string]$Text) {
    $bytes = [Text.Encoding]::UTF8.GetBytes($Text)
    $sha256 = [Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($sha256.ComputeHash($bytes))).Replace('-','') }
    finally { $sha256.Dispose() }
}

function Get-ServiceSnapshot([string]$Name) {
    if ($Name -eq 'Bulwark') {
        $driver = Get-CimInstance Win32_SystemDriver -Filter "Name='Bulwark'" -OperationTimeoutSec $PreflightStepTimeoutSeconds
        return [ordered]@{ name=$Name; state=$driver.State; startMode=$driver.StartMode; processId=$null; pathName=$driver.PathName }
    }
    $service = Get-CimInstance Win32_Service -Filter "Name='$Name'" -OperationTimeoutSec $PreflightStepTimeoutSeconds
    return [ordered]@{ name=$Name; state=$service.State; startMode=$service.StartMode; processId=$service.ProcessId; pathName=$service.PathName }
}

function ConvertTo-NormalizedDriverImagePath([string]$ImagePath) {
    if ([string]::IsNullOrWhiteSpace($ImagePath)) { throw 'Bulwark driver ImagePath is empty.' }
    $candidate = $ImagePath.Trim()
    if ($candidate.StartsWith('"')) {
        if ($candidate -notmatch '^"([^"]+)"$') { throw 'Bulwark driver ImagePath must name exactly one binary.' }
        $candidate = $Matches[1]
    } elseif ($candidate -match '\s') {
        throw 'Bulwark driver ImagePath must not contain arguments.'
    }
    $candidate = [Environment]::ExpandEnvironmentVariables($candidate).Replace('/','\')
    if ($candidate.StartsWith('\??\')) { $candidate = $candidate.Substring(4) }
    if ($candidate.StartsWith('\SystemRoot\', [StringComparison]::OrdinalIgnoreCase)) {
        $candidate = Join-Path $env:SystemRoot $candidate.Substring(12)
    } elseif ($candidate.StartsWith('SystemRoot\', [StringComparison]::OrdinalIgnoreCase)) {
        $candidate = Join-Path $env:SystemRoot $candidate.Substring(11)
    } elseif ($candidate.StartsWith('System32\', [StringComparison]::OrdinalIgnoreCase)) {
        $candidate = Join-Path $env:SystemRoot $candidate
    }
    if (-not [regex]::IsMatch($candidate, '^[A-Za-z]:\\')) { throw 'Bulwark driver ImagePath is not an absolute SystemRoot path.' }
    return [IO.Path]::GetFullPath($candidate)
}

function Get-DriverImagePathResolution([string]$ImagePath, [string]$ExpectedPath = $expectedDriverInstallPath,
    [bool]$UseSysnative = ([Environment]::Is64BitOperatingSystem -and -not [Environment]::Is64BitProcess)) {
    $normalized = ConvertTo-NormalizedDriverImagePath $ImagePath
    $expected = [IO.Path]::GetFullPath($ExpectedPath)
    $pathMatches = [string]::Equals($normalized, $expected, [StringComparison]::OrdinalIgnoreCase)
    $verificationPath = $expected
    $view = 'System32'
    if ($pathMatches -and $UseSysnative) {
        $verificationPath = Join-Path $env:SystemRoot 'Sysnative\drivers\Bulwark.sys'
        $view = 'Sysnative'
    }
    return [ordered]@{ rawImagePath=$ImagePath; normalizedImagePath=$normalized; expectedInstallPath=$expected
        pathMatchesExpected=$pathMatches; verificationPath=$verificationPath; verificationView=$view }
}

function Get-DriverBinarySnapshot {
    $registration = Get-ItemProperty -LiteralPath $driverServiceKey -Name ImagePath -ErrorAction Stop
    $service = Get-ServiceSnapshot 'Bulwark'
    $resolution = Get-DriverImagePathResolution ([string]$registration.ImagePath)
    $servicePathResolution = ConvertTo-NormalizedDriverImagePath ([string]$service.pathName)
    $servicePathMatches = [string]::Equals($servicePathResolution, $expectedDriverInstallPath, [StringComparison]::OrdinalIgnoreCase)
    $identity = if ($resolution.pathMatchesExpected) { Get-Identity $resolution.verificationPath } else { [ordered]@{ path=$resolution.verificationPath; exists=$false; size=$null; sha256=$null; notReadBecauseImagePathMismatch=$true } }
    return [ordered]@{ service=$service; registrationImagePath=[string]$registration.ImagePath
        registrationNormalizedPath=$resolution.normalizedImagePath; serviceNormalizedPath=$servicePathResolution
        expectedInstallPath=$expectedDriverInstallPath; registrationPathMatchesExpected=$resolution.pathMatchesExpected
        servicePathMatchesExpected=$servicePathMatches; verificationPath=$resolution.verificationPath
        verificationView=$resolution.verificationView; is64BitOperatingSystem=([Environment]::Is64BitOperatingSystem)
        is64BitProcess=([Environment]::Is64BitProcess); identity=$identity }
}

function Get-UiSnapshot {
    $processes = @(Get-Process bulwark_ui -ErrorAction SilentlyContinue | ForEach-Object {
        [ordered]@{ id=$_.Id; path=[IO.Path]::GetFullPath($_.Path).ToUpperInvariant(); startTimeUtc=$_.StartTime.ToUniversalTime().ToString('o') }
    })
    return [ordered]@{ count=$processes.Count; processes=$processes; paths=@($processes | ForEach-Object { $_.path } | Sort-Object) }
}

function Get-MinifilterSnapshot {
    $flt = Join-Path $env:SystemRoot 'System32\fltmc.exe'
    $filtersCapture = Invoke-Captured $flt @('filters') $PreflightStepTimeoutSeconds
    $instancesCapture = Invoke-Captured $flt @('instances') $PreflightStepTimeoutSeconds
    if ($filtersCapture.timedOut -or $instancesCapture.timedOut) { throw [TimeoutException]::new('fltmc timed out during read-only Minifilter preflight.') }
    if ($filtersCapture.exitCode -ne 0 -or $instancesCapture.exitCode -ne 0) { throw 'fltmc failed during read-only Minifilter preflight.' }
    $filters = $filtersCapture.stdout
    $instances = $instancesCapture.stdout
    return [ordered]@{
        filters=$filters; instances=$instances; filtersCapture=$filtersCapture; instancesCapture=$instancesCapture
        altitudePresent=($filters -match '(?m)^Bulwark\s+\d+\s+385201\s')
        instanceCount=([regex]::Matches($instances, '(?m)^Bulwark\s+.*385201\s+Bulwark Instance').Count)
    }
}

function Find-SignTool {
    $command = Get-Command signtool.exe -ErrorAction SilentlyContinue
    if ($command) { return $command.Source }
    $root = Join-Path ${env:ProgramFiles(x86)} 'Windows Kits\10\bin'
    foreach ($version in @('10.0.26100.0','10.0.22621.0','10.0.22000.0','10.0.19041.0')) {
        $candidate = Join-Path $root ($version + '\x64\signtool.exe')
        if (Test-Path -LiteralPath $candidate -PathType Leaf) { return $candidate }
    }
    return $null
}

function Test-PreflightCancellation {
    if ($script:preflightCancellationRequested) { throw [OperationCanceledException]::new('Read-only preflight canceled by the parent console.') }
}

function Get-AuthenticodeSignatureBounded([string]$Path, [int]$TimeoutSeconds = $PreflightStepTimeoutSeconds) {
    $job = Start-Job -ScriptBlock {
        param($candidate)
        $signature = Get-AuthenticodeSignature -LiteralPath $candidate
        [pscustomobject]@{ status=$signature.Status.ToString(); thumbprint=$(if ($signature.SignerCertificate) { $signature.SignerCertificate.Thumbprint } else { $null }) }
    } -ArgumentList $Path
    try {
        $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
        while ($job.State -eq 'Running' -or $job.State -eq 'NotStarted') {
            Test-PreflightCancellation
            if ([DateTime]::UtcNow -ge $deadline) { throw [TimeoutException]::new("Authenticode verification timed out after $TimeoutSeconds seconds.") }
            Start-Sleep -Milliseconds 200
        }
        if ($job.State -ne 'Completed') { throw "Authenticode verification job ended as $($job.State)." }
        return Receive-Job -Job $job -ErrorAction Stop
    } finally {
        if ($job.State -eq 'Running' -or $job.State -eq 'NotStarted') { Stop-Job -Job $job -ErrorAction SilentlyContinue }
        Remove-Job -Job $job -Force -ErrorAction SilentlyContinue
    }
}

function Invoke-Captured([string]$FileName, [string[]]$Arguments, [int]$TimeoutSeconds = 30) {
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
        $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
        $timedOut = $false
        while (-not $process.HasExited) {
            Test-PreflightCancellation
            if ([DateTime]::UtcNow -ge $deadline) { $timedOut = $true; break }
            Start-Sleep -Milliseconds 200
        }
        if ($timedOut) { try { $process.Kill() } catch {} ; [void]$process.WaitForExit(5000) }
        $stdout = $stdoutTask.GetAwaiter().GetResult(); $stderr = $stderrTask.GetAwaiter().GetResult()
        return [ordered]@{ file=$FileName; argv=@($Arguments); timeoutSeconds=$TimeoutSeconds; timedOut=$timedOut; startedUtc=$startedUtc; finishedUtc=[DateTime]::UtcNow.ToString('o'); exitCode=$(if ($timedOut) { $null } else { $process.ExitCode }); stdout=$stdout; stderr=$stderr }
    } catch {
        if ($process -and -not $process.HasExited) { try { $process.Kill() } catch {} }
        throw
    } finally { $process.Dispose() }
}

function Write-Json([string]$Path, $Object) {
    $parent = Split-Path -Parent $Path
    if (-not (Test-Path -LiteralPath $parent)) { New-Item -ItemType Directory -Path $parent -Force | Out-Null }
    [IO.File]::WriteAllText($Path, ($Object | ConvertTo-Json -Depth 16), (New-Object Text.UTF8Encoding($false)))
}

function Test-RollbackCompletionContract([object[]]$Evidence) {
    $missing = New-Object System.Collections.Generic.List[string]
    $duplicate = New-Object System.Collections.Generic.List[string]
    $failed = New-Object System.Collections.Generic.List[string]
    foreach ($gate in $rollbackGates) {
        $matches = @($Evidence | Where-Object { $_.name -eq $gate })
        if ($matches.Count -eq 0) { $missing.Add($gate) }
        elseif ($matches.Count -ne 1) { $duplicate.Add($gate) }
        elseif (-not [bool]$matches[0].pass) { $failed.Add($gate) }
    }
    return [ordered]@{ pass=($missing.Count -eq 0 -and $duplicate.Count -eq 0 -and $failed.Count -eq 0); required=@($rollbackGates); missing=$missing.ToArray(); duplicate=$duplicate.ToArray(); failed=$failed.ToArray() }
}

function Invoke-OfflineRollbackInjection([string]$Injection, [string]$ReportPath) {
    $evidence = @($rollbackGates | ForEach-Object { [pscustomobject][ordered]@{ name=$_; pass=$true; observed='isolated-offline-baseline' } })
    $expectedPass = $Injection -eq 'all-pass'
    if ($gateByInjection.Contains($Injection)) {
        $target = $gateByInjection[$Injection]
        $evidence = @($evidence | ForEach-Object { [pscustomobject][ordered]@{ name=$_.name; pass=($_.name -ne $target); observed='isolated-offline-failure-injection' } })
    } elseif ($Injection -eq 'missing-evidence') {
        $evidence = @($evidence | Select-Object -Skip 1)
    } elseif ($Injection -eq 'duplicate-evidence') {
        $evidence = @($evidence + $evidence[0])
    }
    $contract = Test-RollbackCompletionContract $evidence
    $result = [ordered]@{
        schemaVersion=1; generatedUtc=[DateTime]::UtcNow.ToString('o'); mode='isolated-offline-rollback-failure-injection'
        injection=$Injection; expectedContractPass=$expectedPass; contract=$contract
        rollbackCompleteWouldRemainFalse=(-not $contract.pass)
        liveStateRead=$false; serviceLifecycleChanged=$false; driverOrMinifilterChanged=$false; policyOrAppsettingsChanged=$false
        passed=($contract.pass -eq $expectedPass)
    }
    Write-Json $ReportPath $result
    return $result
}

function Test-InterruptedPhaseRequiresRecovery([string]$Phase) {
    return $Phase -in @('service-stop-intent','service-stopped','snapshot-install-intent','snapshot-installed',
        'service-restart-intent','service-restarted','postimage-validating','recovery-started',
        'recovery-snapshot-restored','recovery-service-restarted','rollback-incomplete')
}

function Invoke-OfflineInterruptionInjection([string]$Injection, [string]$ReportPath) {
    $scenarios = New-Object System.Collections.Generic.List[object]
    foreach ($preimageKind in @('absent','present')) {
        $root = Join-Path ([IO.Path]::GetTempPath()) ('bulwark-reconciliation-interruption-' + [guid]::NewGuid().ToString('N'))
        $installed = Join-Path $root 'bulwark_snapshot.exe'
        $backup = Join-Path $root 'snapshot-preimage.bin'
        $candidate = Join-Path $root 'candidate.exe'
        $journalPath = Join-Path $root 'journal.json'
        New-Item -ItemType Directory -Path $root -Force | Out-Null
        try {
            if ($preimageKind -eq 'present') {
                [IO.File]::WriteAllText($installed, 'offline-exact-preimage', [Text.Encoding]::UTF8)
                [IO.File]::Copy($installed, $backup, $false)
            }
            $preimage = Get-Identity $installed
            [IO.File]::WriteAllText($candidate, 'offline-candidate', [Text.Encoding]::UTF8)
            $durablePhase = $Injection
            $serviceState = 'Running'
            if ($Injection -eq 'service-stop-intent' -or $Injection -eq 'service-stopped') {
                $serviceState = 'Stopped'
            } elseif ($Injection -eq 'snapshot-installed') {
                $serviceState = 'Stopped'
                [IO.File]::Copy($candidate, $installed, $true)
            } elseif ($Injection -eq 'service-restarted') {
                [IO.File]::Copy($candidate, $installed, $true)
            }
            $journal = [ordered]@{
                mode='execute'; committed=$false; phase=$durablePhase; preimage=[ordered]@{ snapshot=$preimage }
                actions=@([ordered]@{ action='snapshot-stage-created'; stage=$candidate })
                rollback=[ordered]@{ attempted=$false; complete=$false; evidence=@() }
            }
            Write-Json $journalPath $journal
            $recovered = Get-Content -LiteralPath $journalPath -Raw -Encoding UTF8 | ConvertFrom-Json
            $recoveryRequired = Test-InterruptedPhaseRequiresRecovery ([string]$recovered.phase)
            $recovered.rollback.attempted = $recoveryRequired
            $recovered.rollback.complete = $false
            if ($recoveryRequired) {
                $recovered.phase = 'recovery-started'
                Write-Json $journalPath $recovered
                if ($serviceState -ne 'Stopped') { $serviceState = 'Stopped' }
                if ([bool]$recovered.preimage.snapshot.exists) { [IO.File]::Copy($backup, $installed, $true) }
                elseif (Test-Path -LiteralPath $installed) { Remove-Item -LiteralPath $installed -Force }
                $serviceState = 'Running'
                $recovered.phase = 'recovered-without-live-contract'
            } else {
                if (Test-Path -LiteralPath $candidate) { Remove-Item -LiteralPath $candidate -Force }
                $recovered.phase = 'recovered-no-live-change'
            }
            Write-Json $journalPath $recovered
            $persisted = Get-Content -LiteralPath $journalPath -Raw -Encoding UTF8 | ConvertFrom-Json
            $restored = Test-IdentityEqual $preimage (Get-Identity $installed)
            $scenarios.Add([ordered]@{
                snapshotPreimage=$preimageKind; durableJournalRoundTrip=($persisted.phase -eq $recovered.phase)
                durablePhase=$durablePhase; recoveryRequired=$recoveryRequired
                exactSnapshotPreimageRestored=$restored; serviceRestoredRunning=($serviceState -eq 'Running')
            })
        } finally { Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue }
    }
    $contract = Test-RollbackCompletionContract @()
    $expectedRecovery = Test-InterruptedPhaseRequiresRecovery $Injection
    $passed = @($scenarios | Where-Object {
        -not $_.durableJournalRoundTrip -or $_.recoveryRequired -ne $expectedRecovery -or
        -not $_.exactSnapshotPreimageRestored -or -not $_.serviceRestoredRunning
    }).Count -eq 0 -and -not $contract.pass
    $result = [ordered]@{
        schemaVersion=1; generatedUtc=[DateTime]::UtcNow.ToString('o'); mode='isolated-offline-durable-journal-interruption-recovery'
        injection=$Injection; durablePhase=$Injection; scenarios=$scenarios.ToArray()
        rollbackCompleteWouldRemainFalse=(-not $contract.pass); completionContract=$contract
        liveStateRead=$false; serviceLifecycleChanged=$false; driverOrMinifilterChanged=$false; policyOrAppsettingsChanged=$false
        passed=$passed
    }
    Write-Json $ReportPath $result
    return $result
}

function Invoke-OfflineDriverPathInjection([string]$Injection, [string]$ReportPath) {
    $fixtureRoot = 'C:\Windows'
    $expected = Join-Path $fixtureRoot 'System32\drivers\Bulwark.sys'
    $imagePath = 'System32\drivers\Bulwark.sys'
    $useSysnative = $true
    $architecture = 'x86-on-x64'
    $fileExists = $true; $hashMatches = $true; $signatureValid = $true; $thumbprintMatches = $true; $signtoolPasses = $true; $serviceRunning = $true
    switch ($Injection) {
        'x64-on-x64-system32' { $useSysnative = $false; $architecture = 'x64-on-x64' }
        'x86-on-x86-system32' { $useSysnative = $false; $architecture = 'x86-on-x86' }
        'missing-file' { $fileExists = $false }
        'redirected-path' { $imagePath = 'C:\Windows\SysWOW64\drivers\Bulwark.sys' }
        'wrong-service-image' { $imagePath = 'D:\unexpected\Bulwark.sys' }
        'hash-mismatch' { $hashMatches = $false }
        'signature-mismatch' { $signatureValid = $false }
        'thumbprint-mismatch' { $thumbprintMatches = $false }
        'signtool-failure' { $signtoolPasses = $false }
        'service-stopped' { $serviceRunning = $false }
    }
    $resolution = Get-DriverImagePathResolution -ImagePath $imagePath -ExpectedPath $expected -UseSysnative $useSysnative
    $expectedView = if ($useSysnative) { 'Sysnative' } else { 'System32' }
    $contractPass = $resolution.pathMatchesExpected -and $resolution.verificationView -eq $expectedView -and
        $fileExists -and $hashMatches -and $signatureValid -and $thumbprintMatches -and $signtoolPasses -and $serviceRunning
    $expectedPass = $Injection -in @('all-pass','x86-on-x64-sysnative','x64-on-x64-system32','x86-on-x86-system32')
    $result = [ordered]@{
        schemaVersion=1; generatedUtc=[DateTime]::UtcNow.ToString('o'); mode='isolated-offline-driver-path-failure-injection'
        injection=$Injection; expectedContractPass=$expectedPass; architecture=$architecture; expectedVerificationView=$expectedView; resolution=$resolution
        simulated=[ordered]@{ fileExists=$fileExists; hashMatches=$hashMatches; signatureValid=$signatureValid
            thumbprintMatches=$thumbprintMatches; signtoolPasses=$signtoolPasses; serviceRunning=$serviceRunning }
        contractPass=$contractPass; failedClosed=(-not $contractPass); passed=($contractPass -eq $expectedPass)
        liveStateRead=$false; serviceLifecycleChanged=$false; driverOrMinifilterChanged=$false; policyOrAppsettingsChanged=$false
    }
    Write-Json $ReportPath $result
    return $result
}

function Invoke-OfflinePreflightFailureInjection([string]$Injection, [string]$ReportPath) {
    $root = Join-Path ([IO.Path]::GetTempPath()) ('bulwark-reconciliation-preflight-' + [guid]::NewGuid().ToString('N'))
    $journalPath = Join-Path $root 'journal.json'
    New-Item -ItemType Directory -Path $root -Force | Out-Null
    try {
        $step = [ordered]@{ name='driver-signtool-pa'; status='passed'; startedUtc=[DateTime]::UtcNow.ToString('o'); deadlineUtc=[DateTime]::UtcNow.AddSeconds(5).ToString('o') }
        $journal = [ordered]@{ mode='preflight'; phase='preflight-complete'; transactionComplete=$true; committed=$false
            preflight=[ordered]@{ currentStep=$null; steps=@($step); timeout=$null; canceled=$false; incomplete=$false }
            guarantees=[ordered]@{ driverOrMinifilterLifecycle=$false; policyWrite=$false; appsettingsWrite=$false }
        }
        if ($Injection -eq 'external-timeout') {
            $step.status='timeout'; $step.finishedUtc=[DateTime]::UtcNow.ToString('o')
            $journal.phase='preflight-driver-signtool-pa-timeout'; $journal.transactionComplete=$false; $journal.preflight.incomplete=$true
            $journal.preflight.timeout=[ordered]@{ step='driver-signtool-pa'; error='simulated bounded external timeout' }
        } elseif ($Injection -eq 'incomplete-preflight') {
            $step.status='running'; $journal.phase='preflight-driver-signtool-pa-running'; $journal.transactionComplete=$false; $journal.preflight.incomplete=$true
        } elseif ($Injection -eq 'canceled-preflight') {
            $step.status='canceled'; $step.finishedUtc=[DateTime]::UtcNow.ToString('o')
            $journal.phase='preflight-canceled'; $journal.transactionComplete=$false; $journal.preflight.incomplete=$true; $journal.preflight.canceled=$true
        }
        Write-Json $journalPath $journal
        $persisted = Get-Content -LiteralPath $journalPath -Raw -Encoding UTF8 | ConvertFrom-Json
        $expectedPass = $Injection -eq 'all-pass'
        $contractPass = [bool]$persisted.transactionComplete -and -not [bool]$persisted.preflight.incomplete -and -not $persisted.preflight.timeout -and -not [bool]$persisted.preflight.canceled
        $result = [ordered]@{ schemaVersion=1; generatedUtc=[DateTime]::UtcNow.ToString('o'); mode='isolated-offline-preflight-timeout-injection'; injection=$Injection
            journal=$persisted; expectedContractPass=$expectedPass; contractPass=$contractPass; failClosed=(-not $contractPass); passed=($contractPass -eq $expectedPass)
            liveStateRead=$false; serviceLifecycleChanged=$false; driverOrMinifilterChanged=$false; policyOrAppsettingsChanged=$false }
        Write-Json $ReportPath $result
        return $result
    } finally { Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue }
}

if ($OfflineRollbackFailureInjection -or $OfflineInterruptionFailureInjection -or $OfflineDriverPathFailureInjection -or $OfflinePreflightFailureInjection -or $OfflineRollbackAggregate) {
    if ($PreflightOnly -or $Execute -or $AcknowledgeAuthorizedReconciliation) { throw 'Offline rollback modes cannot be combined with transaction switches.' }
    $selectedOfflineModes = @($OfflineRollbackFailureInjection, $OfflineInterruptionFailureInjection, $OfflineDriverPathFailureInjection, $OfflinePreflightFailureInjection)
    if (@($selectedOfflineModes | Where-Object { -not [string]::IsNullOrEmpty($_) }).Count -gt 1) { throw 'Choose one offline injection mode.' }
    if ($OfflinePreflightFailureInjection) {
        if ([string]::IsNullOrWhiteSpace($OfflineRollbackReportPath)) { $OfflineRollbackReportPath = Join-Path $env:TEMP ('bulwark-reconciliation-preflight-' + $PID + '-' + $OfflinePreflightFailureInjection + '.json') }
        $preflightResult = Invoke-OfflinePreflightFailureInjection $OfflinePreflightFailureInjection $OfflineRollbackReportPath
        if (-not $preflightResult.passed) { exit 1 }
        exit 0
    }
    if ($OfflineDriverPathFailureInjection) {
        if ([string]::IsNullOrWhiteSpace($OfflineRollbackReportPath)) { $OfflineRollbackReportPath = Join-Path $env:TEMP ('bulwark-reconciliation-driver-path-' + $PID + '-' + $OfflineDriverPathFailureInjection + '.json') }
        $driverPathResult = Invoke-OfflineDriverPathInjection $OfflineDriverPathFailureInjection $OfflineRollbackReportPath
        if (-not $driverPathResult.passed) { exit 1 }
        exit 0
    }
    if ($OfflineInterruptionFailureInjection) {
        if ([string]::IsNullOrWhiteSpace($OfflineRollbackReportPath)) { $OfflineRollbackReportPath = Join-Path $env:TEMP ('bulwark-reconciliation-interruption-' + $PID + '-' + $OfflineInterruptionFailureInjection + '.json') }
        $interruption = Invoke-OfflineInterruptionInjection $OfflineInterruptionFailureInjection $OfflineRollbackReportPath
        if (-not $interruption.passed) { exit 1 }
        exit 0
    }
    if ($OfflineRollbackAggregate) {
        $cases = New-Object System.Collections.Generic.List[object]
        $names = @('all-pass') + @($gateByInjection.Keys) + @('missing-evidence','duplicate-evidence')
        foreach ($name in $names) {
            $casePath = if ([string]::IsNullOrWhiteSpace($OfflineRollbackReportPath)) { Join-Path $env:TEMP ('bulwark-reconciliation-' + $PID + '-' + $name + '.json') } else { Join-Path (Split-Path -Parent $OfflineRollbackReportPath) ('rollback-' + $name + '.json') }
            $cases.Add((Invoke-OfflineRollbackInjection $name $casePath))
        }
        $aggregate = [ordered]@{ schemaVersion=1; generatedUtc=[DateTime]::UtcNow.ToString('o'); mode='offline-rollback-aggregate'; liveStateRead=$false; cases=$cases.ToArray(); passed=(@($cases | Where-Object { -not $_.passed }).Count -eq 0) }
        if ([string]::IsNullOrWhiteSpace($OfflineRollbackReportPath)) { $OfflineRollbackReportPath = Join-Path $env:TEMP ('bulwark-reconciliation-aggregate-' + $PID + '.json') }
        Write-Json $OfflineRollbackReportPath $aggregate
        if (-not $aggregate.passed) { exit 1 }
        exit 0
    }
    if ([string]::IsNullOrWhiteSpace($OfflineRollbackReportPath)) { $OfflineRollbackReportPath = Join-Path $env:TEMP ('bulwark-reconciliation-' + $PID + '-' + $OfflineRollbackFailureInjection + '.json') }
    $one = Invoke-OfflineRollbackInjection $OfflineRollbackFailureInjection $OfflineRollbackReportPath
    if (-not $one.passed) { exit 1 }
    exit 0
}

if ($Execute -and -not $AcknowledgeAuthorizedReconciliation) { throw '-Execute requires -AcknowledgeAuthorizedReconciliation.' }
if ($PreflightOnly -and $Execute) { throw 'Choose either -PreflightOnly or -Execute.' }
if ([string]::IsNullOrWhiteSpace($EvidenceDirectory)) { $EvidenceDirectory = Join-Path $repoRoot '.agents\tasks\validation-reconciliation-resume\evidence\preflight' }
if ([string]::IsNullOrWhiteSpace($SnapshotCandidatePath)) { $SnapshotCandidatePath = Join-Path $repoRoot 'cpp\build_pkg\deploy\Release\bulwark_snapshot.exe' }
if ([string]::IsNullOrWhiteSpace($ApprovalVerdictPath)) { $ApprovalVerdictPath = Join-Path $repoRoot '.agents\tasks\validation-reconciliation-resume\reconciliation-verdict.json' }

Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class BulwarkMoveFile {
  [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
  public static extern bool MoveFileEx(string existingName, string newName, int flags);
}
'@
$MOVEFILE_REPLACE_EXISTING = 0x1
$MOVEFILE_WRITE_THROUGH = 0x8
function Move-InstalledArtifact([string]$Stage, [string]$Destination) {
    if (-not [BulwarkMoveFile]::MoveFileEx($Stage, $Destination, ($MOVEFILE_REPLACE_EXISTING -bor $MOVEFILE_WRITE_THROUGH))) {
        throw ('MoveFileEx failed with Win32 error ' + [Runtime.InteropServices.Marshal]::GetLastWin32Error())
    }
}
function Remove-InstalledArtifact([string]$Destination) {
    if ((Test-Path -LiteralPath $Destination) -and -not [BulwarkMoveFile]::MoveFileEx($Destination, $null, $MOVEFILE_WRITE_THROUGH)) {
        throw ('MoveFileEx removal failed with Win32 error ' + [Runtime.InteropServices.Marshal]::GetLastWin32Error())
    }
}
function Save-Journal([string]$Path, $Journal) { Write-Json $Path $Journal }
function Set-JournalPhase([string]$Phase) {
    $journal.phase = $Phase
    $journal.phaseUpdatedUtc = [DateTime]::UtcNow.ToString('o')
    Save-Journal $journalPath $journal
}

$transactionId = [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfffZ')
$transactionDir = Join-Path $EvidenceDirectory ('transaction-' + $transactionId)
$journalPath = Join-Path $transactionDir 'journal.json'
$journal = [ordered]@{
    schemaVersion=1; transactionId=$transactionId; startedUtc=[DateTime]::UtcNow.ToString('o')
    mode=$(if ($Execute) { 'execute' } else { 'preflight' }); phase='initializing'; committed=$false; transactionComplete=$false
    canonicalInstalledSnapshot=$canonicalSnapshot; candidate=$SnapshotCandidatePath
    controller=Get-Identity $PSCommandPath
    immutableInputs=[ordered]@{}; preimage=[ordered]@{}; actions=New-Object System.Collections.Generic.List[object]
    rollback=[ordered]@{ attempted=$false; complete=$false; evidence=New-Object System.Collections.Generic.List[object] }
    preflight=[ordered]@{ currentStep=$null; steps=New-Object System.Collections.Generic.List[object]; timeout=$null; canceled=$false; incomplete=$true }
    guarantees=[ordered]@{ noRecord=$true; driverOrMinifilterLifecycle=$false; appsettingsWrite=$false; policyWrite=$false; historicalRollbackScriptInvoked=$false }
}

$preflightCancellationHandler = [ConsoleCancelEventHandler]{ param($sender, $eventArgs); $eventArgs.Cancel = $true; $script:preflightCancellationRequested = $true }
[Console]::add_CancelKeyPress($preflightCancellationHandler)

function Invoke-PreflightStep([string]$Name, [scriptblock]$Action) {
    Test-PreflightCancellation
    $startedUtc = [DateTime]::UtcNow.ToString('o')
    $deadlineUtc = [DateTime]::UtcNow.AddSeconds($PreflightStepTimeoutSeconds).ToString('o')
    $journal.preflight.currentStep = $Name
    $journal.preflight.steps.Add([ordered]@{ name=$Name; status='running'; startedUtc=$startedUtc; deadlineUtc=$deadlineUtc })
    $journal.phase = 'preflight-' + $Name + '-running'; $journal.phaseUpdatedUtc = $startedUtc
    Save-Journal $journalPath $journal
    Write-Host "Preflight [$Name] started; deadline $deadlineUtc" -ForegroundColor Cyan
    try {
        $value = & $Action
        Test-PreflightCancellation
        $step = $journal.preflight.steps[$journal.preflight.steps.Count - 1]
        $step.status = 'passed'; $step.finishedUtc = [DateTime]::UtcNow.ToString('o')
        $journal.phase = 'preflight-' + $Name + '-passed'; $journal.phaseUpdatedUtc = $step.finishedUtc
        Save-Journal $journalPath $journal
        Write-Host "Preflight [$Name] passed" -ForegroundColor Green
        return $value
    } catch {
        $step = $journal.preflight.steps[$journal.preflight.steps.Count - 1]
        $step.status = if ($_.Exception -is [TimeoutException]) { 'timeout' } elseif ($_.Exception -is [OperationCanceledException]) { 'canceled' } else { 'failed' }
        $step.finishedUtc = [DateTime]::UtcNow.ToString('o'); $step.error = $_.Exception.ToString()
        if ($step.status -eq 'timeout') { $journal.preflight.timeout = [ordered]@{ step=$Name; deadlineUtc=$deadlineUtc; observedUtc=$step.finishedUtc; error=$step.error } }
        if ($step.status -eq 'canceled') { $journal.preflight.canceled = $true }
        $journal.phase = 'preflight-' + $Name + '-' + $step.status; $journal.phaseUpdatedUtc = $step.finishedUtc
        Save-Journal $journalPath $journal
        throw
    }
}

function Add-RollbackEvidence($TargetJournal, [string]$Name, [bool]$Pass, $Observed) { $TargetJournal.rollback.evidence.Add([ordered]@{ name=$Name; pass=$Pass; observed=$Observed }) }
function Wait-ServiceState([string]$Name, [string]$State, [int]$Seconds=40) {
    $deadline = [DateTime]::UtcNow.AddSeconds($Seconds)
    do { if ((Get-Service -Name $Name).Status.ToString() -eq $State) { return }; Start-Sleep -Milliseconds 250 } while ([DateTime]::UtcNow -lt $deadline)
    throw "Service $Name did not reach $State."
}
function Test-SelfGuard([DateTime]$NotBefore) {
    Start-Sleep -Seconds 2
    $log = Join-Path $env:ProgramData 'Bulwark\service.log'
    $logObserved = $false; $lastWrite = $null
    if (Test-Path -LiteralPath $log -PathType Leaf) {
        $item = Get-Item -LiteralPath $log; $lastWrite = $item.LastWriteTimeUtc.ToString('o')
        $logObserved = $item.LastWriteTimeUtc -ge $NotBefore -and ((Get-Content -LiteralPath $log -Tail 500 -Encoding UTF8 | Out-String) -match 'SelfGuard')
    }
    $probe = Join-Path (Split-Path $servicePath -Parent) ('.bulwark-reconciliation-probe-' + $PID + '.tmp')
    $denied = $false; $cleanupError = $null
    try { [IO.File]::WriteAllText($probe, 'harmless reconciliation selfguard probe') } catch { $denied = $true }
    if (Test-Path -LiteralPath $probe) { try { Remove-Item -LiteralPath $probe -Force } catch { $cleanupError = $_.Exception.ToString() } }
    return [ordered]@{ pass=($logObserved -and $denied -and $null -eq $cleanupError); logObserved=$logObserved; logLastWriteUtc=$lastWrite; foreignWriteDenied=$denied; cleanupError=$cleanupError }
}

function Complete-RollbackVerification($TargetJournal, [DateTime]$ServiceStartUtc) {
    $TargetJournal.rollback.evidence = New-Object System.Collections.Generic.List[object]
    $currentPolicy = @(Get-NormalizedPolicy @(Get-ItemProperty -LiteralPath $policyKey -Name FileExecBlock | Select-Object -ExpandProperty FileExecBlock))
    Add-RollbackEvidence $TargetJournal $rollbackGates[0] (Test-StringArrayEqual $TargetJournal.preimage.normalizedFileExecBlock $currentPolicy) $currentPolicy
    Add-RollbackEvidence $TargetJournal $rollbackGates[1] (Test-IdentityEqual $TargetJournal.preimage.userManifest (Get-Identity $userManifestPath)) (Get-Identity $userManifestPath)
    Add-RollbackEvidence $TargetJournal $rollbackGates[2] (Test-IdentityEqual $TargetJournal.preimage.service (Get-Identity $servicePath)) (Get-Identity $servicePath)
    $service = Get-ServiceSnapshot 'BulwarkService'
    $serviceOk = $service.state -eq 'Running' -and $service.startMode -eq $TargetJournal.preimage.serviceRegistration.startMode -and $service.pathName -eq $TargetJournal.preimage.serviceRegistration.pathName
    Add-RollbackEvidence $TargetJournal $rollbackGates[3] $serviceOk $service
    Add-RollbackEvidence $TargetJournal $rollbackGates[4] (Test-IdentityEqual $TargetJournal.preimage.snapshot (Get-Identity $canonicalSnapshot)) (Get-Identity $canonicalSnapshot)
    $driverSnapshot = Get-DriverBinarySnapshot
    $signature = if ($driverSnapshot.identity.exists) { Get-AuthenticodeSignatureBounded $driverSnapshot.verificationPath } else { $null }
    $signTool = Find-SignTool
    $pa = if ($driverSnapshot.identity.exists -and $signTool) { Invoke-Captured $signTool @('verify','/pa',$driverSnapshot.verificationPath) } else { $null }
    $driverOk = $driverSnapshot.service.state -eq 'Running' -and $driverSnapshot.registrationPathMatchesExpected -and
        $driverSnapshot.servicePathMatchesExpected -and $driverSnapshot.identity.exists -and $driverSnapshot.identity.sha256 -eq $expectedDriverHash -and
        $signature -and $signature.status -eq 'Valid' -and $signature.thumbprint -eq $expectedDriverThumbprint -and $pa -and $pa.exitCode -eq 0
    Add-RollbackEvidence $TargetJournal $rollbackGates[5] $driverOk ([ordered]@{ snapshot=$driverSnapshot; signature=$(if ($signature) { $signature.status } else { $null }); thumbprint=$(if ($signature) { $signature.thumbprint } else { $null }); signtoolPa=$pa })
    $filter = Get-MinifilterSnapshot
    Add-RollbackEvidence $TargetJournal $rollbackGates[6] ($filter.altitudePresent -and $filter.instanceCount -eq $TargetJournal.preimage.minifilter.instanceCount) $filter
    $ui = Get-UiSnapshot
    Add-RollbackEvidence $TargetJournal $rollbackGates[7] (Test-UiSnapshotEqual $TargetJournal.preimage.ui $ui) $ui
    Add-RollbackEvidence $TargetJournal $rollbackGates[8] (Test-IdentityEqual $TargetJournal.preimage.appsettings (Get-Identity $appsettingsPath)) (Get-Identity $appsettingsPath)
    $selfGuardRollback = Test-SelfGuard $ServiceStartUtc
    Add-RollbackEvidence $TargetJournal $rollbackGates[9] $selfGuardRollback.pass $selfGuardRollback
    $completion = Test-RollbackCompletionContract $TargetJournal.rollback.evidence.ToArray()
    $TargetJournal.rollback.completionContract = $completion
    $TargetJournal.rollback.complete = [bool]$completion.pass
    return $completion
}

function Get-UnfinishedExecuteJournals([string]$Root) {
    if (-not (Test-Path -LiteralPath $Root -PathType Container)) { return @() }
    return @(
        Get-ChildItem -LiteralPath $Root -Directory -Filter 'transaction-*' -ErrorAction SilentlyContinue | ForEach-Object {
            $path = Join-Path $_.FullName 'journal.json'
            if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { return }
            try {
                $candidateJournal = Get-Content -LiteralPath $path -Raw -Encoding UTF8 | ConvertFrom-Json
                if ($candidateJournal.mode -eq 'execute' -and -not [bool]$candidateJournal.committed -and
                    $candidateJournal.phase -in @('snapshot-preimage-captured','stage-created','service-stop-intent','service-stopped','snapshot-install-intent','snapshot-installed','service-restart-intent','service-restarted','postimage-validating','recovery-started','recovery-snapshot-restored','recovery-service-restarted','rollback-incomplete')) {
                    [pscustomobject]@{ path=$path; journal=$candidateJournal }
                }
            } catch { throw "Could not read reconciliation journal ${path}: $($_.Exception.Message)" }
        }
    )
}

function Invoke-UnfinishedExecuteJournalRecovery($Pending) {
    $recovered = $Pending.journal
    $recovered.rollback.attempted = $true
    $recovered.rollback.complete = $false
    $interruptedPhase = [string]$recovered.phase
    $recovered.recovery = [ordered]@{ startedUtc=[DateTime]::UtcNow.ToString('o'); source='startup-unfinished-journal-recovery'; interruptedPhase=$interruptedPhase; journalPath=$Pending.path }
    $recovered.phase = 'recovery-started'
    Save-Journal $Pending.path $recovered
    try {
        if (-not (Test-InterruptedPhaseRequiresRecovery $interruptedPhase)) {
            foreach ($action in @($recovered.actions | Where-Object { $_.action -eq 'snapshot-stage-created' })) {
                if ($action.stage -and (Test-Path -LiteralPath $action.stage)) { Remove-Item -LiteralPath $action.stage -Force }
            }
            $recovered.recovery.completedUtc = [DateTime]::UtcNow.ToString('o')
            $recovered.phase = 'recovered-no-live-change'
            $recovered.transactionComplete = $true
            Save-Journal $Pending.path $recovered
            return
        }
        if ((Get-Service -Name BulwarkService).Status.ToString() -ne 'Stopped') { Stop-Service -Name BulwarkService; Wait-ServiceState 'BulwarkService' 'Stopped' }
        if ([bool]$recovered.preimage.snapshot.exists) {
            $backup = Join-Path (Split-Path -Parent $Pending.path) 'snapshot-preimage.bin'
            if (-not (Test-Path -LiteralPath $backup -PathType Leaf)) { throw 'Interrupted transaction is missing its Snapshot preimage backup.' }
            $restoreStage = Join-Path (Split-Path $canonicalSnapshot -Parent) ('.bulwark_snapshot.recovery-' + $recovered.transactionId + '.exe')
            [IO.File]::Copy($backup, $restoreStage, $false)
            Move-InstalledArtifact $restoreStage $canonicalSnapshot
        } else { Remove-InstalledArtifact $canonicalSnapshot }
        $recovered.phase = 'recovery-snapshot-restored'
        Save-Journal $Pending.path $recovered
        $restartUtc = [DateTime]::UtcNow
        Start-Service -Name BulwarkService
        Wait-ServiceState 'BulwarkService' 'Running'
        $recovered.phase = 'recovery-service-restarted'
        Save-Journal $Pending.path $recovered
        $completion = Complete-RollbackVerification $recovered $restartUtc
        $recovered.recovery.completedUtc = [DateTime]::UtcNow.ToString('o')
        $recovered.phase = if ($completion.pass) { 'recovered' } else { 'rollback-incomplete' }
        $recovered.transactionComplete = [bool]$completion.pass
        Save-Journal $Pending.path $recovered
        if (-not $completion.pass) { throw 'Interrupted transaction recovery did not satisfy every rollback gate.' }
    } catch {
        $recovered.rollback.failure = $_.Exception.ToString()
        $recovered.phase = 'rollback-incomplete'
        $recovered.transactionComplete = $false
        Save-Journal $Pending.path $recovered
        throw
    }
}

$unfinishedJournals = @(Get-UnfinishedExecuteJournals $EvidenceDirectory)
if ($unfinishedJournals.Count -gt 0) {
    if (-not $Execute) { throw 'An unfinished execute journal requires acknowledged -Execute recovery before another reconciliation transaction.' }
    foreach ($pending in $unfinishedJournals) { Invoke-UnfinishedExecuteJournalRecovery $pending }
}

try {
    New-Item -ItemType Directory -Path $transactionDir -Force | Out-Null
    $null = Invoke-PreflightStep 'immutable-inputs' {
        foreach ($input in $protectedInputs.GetEnumerator()) {
            $identity = Get-Identity $input.Value.path
            $journal.immutableInputs[$input.Key] = $identity
            if ($identity.sha256 -ne $input.Value.sha256) { throw "Protected input hash mismatch: $($input.Key)" }
        }
    }
    $journal.preimage.snapshot = Invoke-PreflightStep 'snapshot-preimage' { Get-Identity $canonicalSnapshot }
    $journal.preimage.candidate = Invoke-PreflightStep 'candidate-identity' { Get-Identity $SnapshotCandidatePath }
    $journal.preimage.service = Invoke-PreflightStep 'service-binary' { Get-Identity $servicePath }
    $journal.preimage.serviceRegistration = Invoke-PreflightStep 'service-registration' { Get-ServiceSnapshot 'BulwarkService' }
    $journal.preimage.driver = Invoke-PreflightStep 'driver-binary' { Get-DriverBinarySnapshot }
    $journal.preimage.driverService = $journal.preimage.driver.service
    $journal.preimage.driverSignature = Invoke-PreflightStep 'driver-authenticode' {
        if ($journal.preimage.driver.identity.exists) { Get-AuthenticodeSignatureBounded $journal.preimage.driver.verificationPath } else { $null }
    }
    $journal.preimage.signtool = Invoke-PreflightStep 'signtool-discovery' { Find-SignTool }
    $journal.preimage.driverSigntoolPa = Invoke-PreflightStep 'driver-signtool-pa' {
        if ($journal.preimage.driver.identity.exists -and $journal.preimage.signtool) {
            $capture = Invoke-Captured $journal.preimage.signtool @('verify','/pa',$journal.preimage.driver.verificationPath) $PreflightStepTimeoutSeconds
            if ($capture.timedOut) { throw [TimeoutException]::new("signtool verify /pa timed out after $PreflightStepTimeoutSeconds seconds.") }
            $capture
        } else { $null }
    }
    $journal.preimage.minifilter = Invoke-PreflightStep 'minifilter' { Get-MinifilterSnapshot }
    $journal.preimage.ui = Invoke-PreflightStep 'ui-preimage' { Get-UiSnapshot }
    $journal.preimage.appsettings = Invoke-PreflightStep 'appsettings-identity' { Get-Identity $appsettingsPath }
    $journal.preimage.userManifest = Invoke-PreflightStep 'user-manifest' { Get-Identity $userManifestPath }
    $journal.preimage.fileExecBlock = Invoke-PreflightStep 'file-execblock' {
        @(Get-ItemProperty -LiteralPath $policyKey -Name FileExecBlock -ErrorAction Stop | Select-Object -ExpandProperty FileExecBlock)
    }
    $journal.preimage.normalizedFileExecBlock = Get-NormalizedPolicy $journal.preimage.fileExecBlock
    $nonTargetPolicy = (($journal.preimage.normalizedFileExecBlock | Where-Object { $_ -notmatch 'BULWARK_SNAPSHOT\.EXE$' }) -join "`n")
    $journal.preimage.nonTargetPolicyDigest = Get-TextSha256 $nonTargetPolicy
    if (-not $journal.preimage.candidate.exists) { throw 'Snapshot probe candidate does not exist.' }
    if ($journal.preimage.serviceRegistration.state -ne 'Running') { throw 'BulwarkService must be Running before reconciliation.' }
    if ($journal.preimage.driverService.state -ne 'Running') { throw 'Bulwark driver must be Running before reconciliation.' }
    if (-not $journal.preimage.minifilter.altitudePresent -or $journal.preimage.minifilter.instanceCount -le 0) { throw 'Bulwark Minifilter preimage is not attached at altitude 385201.' }
    if (-not $journal.preimage.driver.registrationPathMatchesExpected -or -not $journal.preimage.driver.servicePathMatchesExpected) { throw 'Bulwark driver ImagePath does not resolve to the pinned System32 installation path.' }
    if (-not $journal.preimage.driver.identity.exists) { throw 'Pinned Bulwark driver binary is missing from the verified System32 or controlled Sysnative view.' }
    if ($journal.preimage.driver.identity.sha256 -ne $expectedDriverHash) { throw 'Installed driver hash is not pinned identity.' }
    if (-not $journal.preimage.driverSignature -or $journal.preimage.driverSignature.status -ne 'Valid' -or $journal.preimage.driverSignature.thumbprint -ne $expectedDriverThumbprint) { throw 'Installed driver signature is not the pinned identity.' }
    if (-not $journal.preimage.driverSigntoolPa -or $journal.preimage.driverSigntoolPa.exitCode -ne 0) { throw 'signtool verify /pa did not validate the installed driver.' }
    if ($journal.preimage.appsettings.sha256 -ne 'ED966784428E686DA430DEDE307C97B87C833504AB5B1017768C9339D1804933') { throw 'appsettings hash is not pinned identity.' }
    Save-Journal $journalPath $journal
    if (-not $Execute) {
        $journal.preflight.currentStep = $null; $journal.preflight.incomplete = $false; $journal.preflight.completedUtc = [DateTime]::UtcNow.ToString('o')
        $journal.phase = 'preflight-complete'; $journal.transactionComplete = $true
        Save-Journal $journalPath $journal
        Write-Host "Read-only reconciliation preflight complete: $journalPath"
        exit 0
    }

    $verdict = Get-Content -LiteralPath $ApprovalVerdictPath -Raw -Encoding UTF8 | ConvertFrom-Json
    if ($verdict.verdict -ne 'APPROVED') { throw 'Fresh reconciliation verdict is not APPROVED.' }
    if (-not $verdict.candidate -or $verdict.candidate.sha256 -ne $journal.preimage.candidate.sha256) { throw 'Approval verdict does not name the exact Snapshot candidate hash.' }
    $snapshotBackup = Join-Path $transactionDir 'snapshot-preimage.bin'
    if ($journal.preimage.snapshot.exists) {
        [IO.File]::Copy($canonicalSnapshot, $snapshotBackup, $false)
        if (-not (Test-IdentityEqual $journal.preimage.snapshot (Get-Identity $snapshotBackup))) { throw 'Snapshot preimage backup identity mismatch.' }
    }
    $journal.actions.Add([ordered]@{ action='snapshot-preimage-captured'; backup=$(if ($journal.preimage.snapshot.exists) { $snapshotBackup } else { $null }); utc=[DateTime]::UtcNow.ToString('o') })
    Set-JournalPhase 'snapshot-preimage-captured'
    $stage = Join-Path (Split-Path $canonicalSnapshot -Parent) ('.bulwark_snapshot.stage-' + $transactionId + '.exe')
    [IO.File]::Copy($SnapshotCandidatePath, $stage, $false)
    if ((Get-FileHash -LiteralPath $stage -Algorithm SHA256).Hash -ne $journal.preimage.candidate.sha256) { throw 'Staged Snapshot hash mismatch.' }
    $journal.actions.Add([ordered]@{ action='snapshot-stage-created'; stage=$stage; utc=[DateTime]::UtcNow.ToString('o') })
    Set-JournalPhase 'stage-created'
    Set-JournalPhase 'service-stop-intent'
    Stop-Service -Name BulwarkService
    Wait-ServiceState 'BulwarkService' 'Stopped'
    $journal.actions.Add([ordered]@{ action='service-stopped-for-installed-asset-replace'; utc=[DateTime]::UtcNow.ToString('o') })
    Set-JournalPhase 'service-stopped'
    Set-JournalPhase 'snapshot-install-intent'
    Move-InstalledArtifact $stage $canonicalSnapshot
    $journal.actions.Add([ordered]@{ action='snapshot-installed-atomic'; installed=Get-Identity $canonicalSnapshot; utc=[DateTime]::UtcNow.ToString('o') })
    if ((Get-FileHash -LiteralPath $canonicalSnapshot -Algorithm SHA256).Hash -ne $journal.preimage.candidate.sha256) { throw 'Installed Snapshot hash mismatch.' }
    Set-JournalPhase 'snapshot-installed'
    $restartUtc = [DateTime]::UtcNow
    Set-JournalPhase 'service-restart-intent'
    Start-Service -Name BulwarkService
    Wait-ServiceState 'BulwarkService' 'Running'
    Set-JournalPhase 'service-restarted'
    $selfGuard = Test-SelfGuard $restartUtc
    if (-not $selfGuard.pass) { throw 'SelfGuard did not re-arm after Snapshot installation.' }
    $journal.postimage = [ordered]@{ snapshot=Get-Identity $canonicalSnapshot; service=Get-ServiceSnapshot 'BulwarkService'; selfGuard=$selfGuard; driver=Get-DriverBinarySnapshot; appsettings=Get-Identity $appsettingsPath }
    $journal.committed = $true
    $journal.transactionComplete = $true
    Set-JournalPhase 'committed'
    Write-Host "Reconciliation transaction committed: $journalPath"; exit 0
} catch {
    $journal.failure = $_.Exception.ToString()
    if (-not $Execute) {
        $journal.preflight.incomplete = $true
        if ($_.Exception -is [OperationCanceledException]) { $journal.preflight.canceled = $true; $journal.phase = 'preflight-canceled' }
        elseif ($_.Exception -is [TimeoutException]) { $journal.phase = 'preflight-timeout' }
    }
    $recoveryRequired = $Execute -and (Test-InterruptedPhaseRequiresRecovery ([string]$journal.phase))
    $journal.rollback.attempted = $recoveryRequired
    $journal.committed = $false
    $journal.transactionComplete = $false
    if ($recoveryRequired) {
        try {
            Set-JournalPhase 'rollback-started'
            if ((Get-Service -Name BulwarkService).Status.ToString() -ne 'Stopped') { Stop-Service -Name BulwarkService; Wait-ServiceState 'BulwarkService' 'Stopped' }
            if ($journal.preimage.snapshot.exists) {
                $backup = Join-Path $transactionDir 'snapshot-preimage.bin'
                if (-not (Test-Path -LiteralPath $backup -PathType Leaf)) { throw 'Snapshot preimage backup is missing.' }
                $restoreStage = Join-Path (Split-Path $canonicalSnapshot -Parent) ('.bulwark_snapshot.restore-' + $transactionId + '.exe')
                [IO.File]::Copy($backup, $restoreStage, $false)
                Move-InstalledArtifact $restoreStage $canonicalSnapshot
            } else { Remove-InstalledArtifact $canonicalSnapshot }
            Set-JournalPhase 'rollback-snapshot-restored'
            $restartUtc = [DateTime]::UtcNow
            Start-Service -Name BulwarkService
            Wait-ServiceState 'BulwarkService' 'Running'
            Set-JournalPhase 'rollback-service-restarted'
            $completion = Complete-RollbackVerification $journal $restartUtc
            $journal.phase = if ($completion.pass) { 'rolled-back' } else { 'rollback-incomplete' }
            $journal.transactionComplete = [bool]$completion.pass
        } catch {
            $journal.rollback.failure = $_.Exception.ToString()
            $journal.phase = 'rollback-incomplete'
            $journal.transactionComplete = $false
        }
    }
    if ($Execute -and -not $recoveryRequired -and ([string]$journal.phase -in @('snapshot-preimage-captured','stage-created','service-stop-intent'))) {
        foreach ($action in @($journal.actions | Where-Object { $_.action -eq 'snapshot-stage-created' })) {
            if ($action.stage -and (Test-Path -LiteralPath $action.stage)) { Remove-Item -LiteralPath $action.stage -Force }
        }
        $journal.phase = 'failed-no-live-change'
    }
    Save-Journal $journalPath $journal
    Write-Error "Snapshot reconciliation failed: $($journal.failure). Journal: $journalPath"
    exit 2
}
