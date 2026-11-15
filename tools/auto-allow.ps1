[CmdletBinding()]
param(
    [string]$Process = 'Kiro',
    [string]$ButtonName = 'Allow',
    [int]$IntervalMs = 500,
    [switch]$DryRun,
    [switch]$Inspect
)

$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName UIAutomationClient
Add-Type -AssemblyName UIAutomationTypes

$AE = [System.Windows.Automation.AutomationElement]
$TS = [System.Windows.Automation.TreeScope]
$CT = [System.Windows.Automation.ControlType]

function Get-TargetPids {
    @((Get-Process -Name $Process -ErrorAction SilentlyContinue).Id)
}

function Get-TopWindows {
    $root = $AE::RootElement
    $cond = New-Object System.Windows.Automation.PropertyCondition($AE::ControlTypeProperty, $CT::Window)
    $root.FindAll($TS::Children, $cond)
}

function Find-AllowButtons([int[]]$procIds) {
    $result = @()
    foreach ($w in Get-TopWindows) {
        try {
            if ($procIds -notcontains $w.Current.ProcessId) { continue }
            $btnCond = New-Object System.Windows.Automation.PropertyCondition($AE::ControlTypeProperty, $CT::Button)
            foreach ($b in $w.FindAll($TS::Descendants, $btnCond)) {
                if ($b.Current.Name -eq $ButtonName) { $result += $b }
            }
        } catch { }
    }
    ,$result
}

function Invoke-ButtonUia($btn) {
    try {
        $p = $btn.GetCurrentPattern([System.Windows.Automation.InvokePattern]::Pattern)
        if ($p) { $p.Invoke(); return 'Invoke' }
    } catch { }
    return $null
}

if ($Inspect) {
    $pids = Get-TargetPids
    Write-Host ("Target '{0}' pids: [{1}]" -f $Process, ($pids -join ',')) -ForegroundColor Cyan
    if ($pids.Count -eq 0) { Write-Host "  (target process not running)" -ForegroundColor Yellow; return }
    Write-Host "Buttons found in its windows:" -ForegroundColor Cyan
    foreach ($w in Get-TopWindows) {
        try {
            if ($pids -notcontains $w.Current.ProcessId) { continue }
            $btnCond = New-Object System.Windows.Automation.PropertyCondition($AE::ControlTypeProperty, $CT::Button)
            foreach ($b in $w.FindAll($TS::Descendants, $btnCond)) {
                Write-Host ("  [{0}]" -f $b.Current.Name)
            }
        } catch { }
    }
    return
}

Write-Host ("auto-allow v2 (pure UIA) watching process='{0}' button='{1}' every {2}ms. Ctrl+C to stop." -f $Process, $ButtonName, $IntervalMs) -ForegroundColor Cyan
if ($DryRun) { Write-Host "DRY RUN: will only report, will NOT click." -ForegroundColor Yellow }

$lastAction = [datetime]::MinValue
while ($true) {
    try {
        $pids = Get-TargetPids
        if ($pids.Count -gt 0) {
            $btns = Find-AllowButtons $pids
            if ($btns.Count -gt 0 -and ((Get-Date) - $lastAction).TotalMilliseconds -ge 1000) {
                $now = Get-Date
                if ($DryRun) {
                    Write-Host ("[{0:HH:mm:ss}] WOULD click '{1}' (found in Kiro)" -f $now, $ButtonName) -ForegroundColor Yellow
                }
                else {
                    $how = Invoke-ButtonUia $btns[0]
                    Start-Sleep -Milliseconds 300
                    $still = (Find-AllowButtons $pids).Count -gt 0
                    if ($how -and -not $still) {
                        Write-Host ("[{0:HH:mm:ss}] clicked '{1}' via {2}" -f (Get-Date), $ButtonName, $how) -ForegroundColor Green
                    }
                    elseif ($how -and $still) {
                        Write-Host ("[{0:HH:mm:ss}] invoked via {1} but dialog still open - tell me, I'll add a stronger method." -f (Get-Date), $how) -ForegroundColor Yellow
                    }
                    else {
                        Write-Host ("[{0:HH:mm:ss}] found '{1}' but no UIA pattern worked - tell me this line." -f (Get-Date), $ButtonName) -ForegroundColor Red
                    }
                }
                $lastAction = Get-Date
            }
        }
    } catch { }
    Start-Sleep -Milliseconds $IntervalMs
}
