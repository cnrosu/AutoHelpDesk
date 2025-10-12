$ErrorActionPreference = 'Stop'

$testsRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$parsersRoot = Split-Path -Parent $testsRoot
$analyzersRoot = Split-Path -Parent $parsersRoot

. (Join-Path -Path $analyzersRoot -ChildPath 'AnalyzerCommon.ps1')
. (Join-Path -Path $parsersRoot -ChildPath 'IntuneParsers.ps1')
. (Join-Path -Path $analyzersRoot -ChildPath 'Heuristics/Intune.ps1')

function New-TestIntuneContext {
    param(
        [string[]]$TaskLines,
        [object[]]$ServiceEntries
    )

    $artifacts = @{}

    if ($TaskLines) {
        $taskArtifact = [pscustomobject]@{
            Path = 'scheduled-tasks.json'
            Data = [pscustomobject]@{
                Payload = [pscustomobject]@{
                    Tasks = $TaskLines
                }
            }
        }
        $artifacts['scheduled-tasks'] = $taskArtifact
    }

    if ($ServiceEntries) {
        $serviceArtifact = [pscustomobject]@{
            Path = 'services.json'
            Data = [pscustomobject]@{
                Payload = [pscustomobject]@{
                    Services = $ServiceEntries
                }
            }
        }
        $artifacts['services'] = $serviceArtifact
    }

    return [pscustomobject]@{
        InputFolder = '/tmp/autotest'
        Artifacts   = $artifacts
    }
}

$failures = [System.Collections.Generic.List[string]]::new()

if ((Normalize-IntuneTaskResult -Value '0') -ne 'success') {
    $null = $failures.Add("Normalize-IntuneTaskResult should return 'success' for '0'.")
}

if ((Normalize-IntuneTaskResult -Value '0 (0x0)') -ne 'success') {
    $null = $failures.Add("Normalize-IntuneTaskResult should return 'success' for '0 (0x0)'.")
}

$healthyService = [pscustomobject]@{
    Name       = 'dmwappushservice'
    DisplayName = 'Windows Push Notification Service'
    StartMode  = 'Automatic'
    Status     = 'Running'
}

$unhealthyService = [pscustomobject]@{
    Name        = 'dmwappushservice'
    DisplayName = 'Windows Push Notification Service'
    StartMode   = 'Disabled'
    Status      = 'Stopped'
}

$taskContextZero = New-TestIntuneContext -TaskLines @(
    'Folder: \Microsoft\Windows\PushToInstall',
    'TaskName: \Microsoft\Windows\PushToInstall\PushLaunch',
    'Status: Ready',
    'Last Result: 0'
) -ServiceEntries @($healthyService)

$zeroStatus = Get-IntunePushLaunchTaskStatus -Context $taskContextZero
if ($zeroStatus.LastResult -ne '0') {
    $null = $failures.Add("Expected raw LastResult '0' for decimal fixture but received '$($zeroStatus.LastResult)'.")
}
if ($zeroStatus.LastResultNormalized -ne 'success') {
    $null = $failures.Add("Expected LastResultNormalized 'success' for decimal fixture but received '$($zeroStatus.LastResultNormalized)'.")
}

$taskContextMixed = New-TestIntuneContext -TaskLines @(
    'Folder: \Microsoft\Windows\PushToInstall',
    'TaskName: \Microsoft\Windows\PushToInstall\PushLaunch',
    'Status: Ready',
    'Last Result: 0 (0x0)'
) -ServiceEntries @($healthyService)

$mixedStatus = Get-IntunePushLaunchTaskStatus -Context $taskContextMixed
if ($mixedStatus.LastResult -ne '0 (0x0)') {
    $null = $failures.Add("Expected raw LastResult '0 (0x0)' for mixed-format fixture but received '$($mixedStatus.LastResult)'.")
}
if ($mixedStatus.LastResultNormalized -ne 'success') {
    $null = $failures.Add("Expected LastResultNormalized 'success' for mixed-format fixture but received '$($mixedStatus.LastResultNormalized)'.")
}

$category = Invoke-IntuneHeuristics -Context $taskContextMixed
$pushIssues = @($category.Issues | Where-Object { $_.Title -like 'Intune quick sync*' })
if ($pushIssues.Count -gt 0) {
    $details = $pushIssues | ForEach-Object { "{0} (Severity={1})" -f $_.Title, $_.Severity }
    $null = $failures.Add('Intune heuristic produced unexpected push notification issues: ' + ($details -join '; '))
}

$enrollmentGuid = '12345678-90ab-cdef-1234-567890abcdef'
$brokenContext = New-TestIntuneContext -TaskLines @(
    "Folder: \\Microsoft\\Windows\\EnterpriseMgmt\\$enrollmentGuid",
    "TaskName: \\Microsoft\\Windows\\EnterpriseMgmt\\$enrollmentGuid\\PushLaunch",
    'Status: Disabled',
    'Scheduled Task State: Disabled',
    'Last Result: 0 (0x0)'
) -ServiceEntries @($unhealthyService)

$brokenCategory = Invoke-IntuneHeuristics -Context $brokenContext
$brokenIssue = @($brokenCategory.Issues | Where-Object { $_.Title -like 'Intune quick sync never wakes*' }) | Select-Object -First 1
if (-not $brokenIssue) {
    $null = $failures.Add('Expected an Intune push notification issue for disabled dependencies, but none was created.')
} else {
    if ($brokenIssue.Remediation -notmatch '\\EnterpriseMgmt\\') {
        $null = $failures.Add('Remediation guidance should mention the EnterpriseMgmt PushLaunch path.')
    }

    if ($brokenIssue.RemediationScript -notmatch '\\EnterpriseMgmt\\') {
        $null = $failures.Add('Remediation script should reference the EnterpriseMgmt PushLaunch task.')
    }

    if ($brokenIssue.RemediationScript -match 'PushToInstall') {
        $null = $failures.Add('Remediation script should no longer reference the legacy PushToInstall path.')
    }

    if ($brokenIssue.RemediationScript -notmatch [regex]::Escape($enrollmentGuid)) {
        $null = $failures.Add('Remediation script should include the reported enrollment GUID when available.')
    }
}

if ($failures.Count -gt 0) {
    Write-Host 'Intune parser tests failed:'
    foreach ($failure in $failures) {
        Write-Host " - $failure"
    }
    exit 1
}

Write-Host 'Intune parser tests passed.'
