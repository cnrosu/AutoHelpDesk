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
        $rows = New-Object System.Collections.Generic.List[pscustomobject]
        foreach ($entry in $ServiceEntries) {
            if (-not $entry) { continue }

            $rowData = [ordered]@{
                'Service Name' = if ($entry.PSObject.Properties['Name']) { [string]$entry.Name } else { $null }
                ServiceName    = if ($entry.PSObject.Properties['Name']) { [string]$entry.Name } else { $null }
                'Display Name' = if ($entry.PSObject.Properties['DisplayName']) { [string]$entry.DisplayName } else { $null }
                DisplayName    = if ($entry.PSObject.Properties['DisplayName']) { [string]$entry.DisplayName } else { $null }
                Status         = if ($entry.PSObject.Properties['Status']) { [string]$entry.Status } else { $null }
                State          = if ($entry.PSObject.Properties['Status']) { [string]$entry.Status } else { $null }
                'Startup Type' = if ($entry.PSObject.Properties['StartMode']) { [string]$entry.StartMode } else { $null }
                StartupType    = if ($entry.PSObject.Properties['StartMode']) { [string]$entry.StartMode } else { $null }
                StartMode      = if ($entry.PSObject.Properties['StartMode']) { [string]$entry.StartMode } else { $null }
            }

            $rows.Add([pscustomobject]$rowData) | Out-Null
        }

        $sectionName = 'Software Environment\Services'
        $section = [pscustomobject]@{
            Name     = $sectionName
            Keys     = @('Service Name','Display Name','Status','Startup Type')
            Rows     = $rows.ToArray()
            RowCount = $rows.Count
        }

        $index = [ordered]@{}
        $fullKey = ConvertTo-MsinfoSectionKey -Name $sectionName
        if ($fullKey) { $index[$fullKey] = @($sectionName) }
        $shortKey = ConvertTo-MsinfoSectionKey -Name 'Services'
        if ($shortKey) { $index[$shortKey] = @($sectionName) }

        $serviceArtifact = [pscustomobject]@{
            Path = 'msinfo32.json'
            Data = [pscustomobject]@{
                Payload = [pscustomobject]@{
                    Source   = 'msinfo32'
                    Sections = [ordered]@{ $sectionName = $section }
                    Index    = $index
                }
            }
        }
        $artifacts['msinfo32'] = $serviceArtifact
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

if ($failures.Count -gt 0) {
    Write-Host 'Intune parser tests failed:'
    foreach ($failure in $failures) {
        Write-Host " - $failure"
    }
    exit 1
}

Write-Host 'Intune parser tests passed.'
