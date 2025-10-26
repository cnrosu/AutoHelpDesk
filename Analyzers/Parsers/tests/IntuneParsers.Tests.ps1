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
        [object[]]$ServiceEntries,
        [object]$PushPayload,
        [string]$DsregText,
        [switch]$SkipDsreg
    )

    $artifacts = @{}

    if (-not $SkipDsreg) {
        if (-not $PSBoundParameters.ContainsKey('DsregText')) {
            $DsregText = @'
AzureAdJoined : YES
PRT : YES
MdmUrl : https://enrollment.manage.microsoft.com/EnrollmentServer/Discovery.svc
MdmComplianceUrl : https://portal.manage.microsoft.com/?portalAction=Compliance
'@
        }

        $identityArtifact = [pscustomobject]@{
            Path = 'identity.json'
            Data = [pscustomobject]@{
                Payload = [pscustomobject]@{
                    DsRegCmd = $DsregText
                }
            }
        }
        $artifacts['identity'] = $identityArtifact
    }

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

    if ($PushPayload) {
        $pushArtifact = [pscustomobject]@{
            Path = 'intune-push.json'
            Data = $PushPayload
        }
        $artifacts['intune-push'] = $pushArtifact
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

$recentRunUtc = (Get-Date).ToUniversalTime().AddDays(-1).ToString('yyyy-MM-ddTHH:mm:ssZ')
$collectedAtUtc = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
$healthyPushPayload = [pscustomobject]@{
    CollectedAtUtc    = $collectedAtUtc
    RecencyWindowDays = 7
    Service           = [pscustomobject]@{
        Name      = 'dmwappushservice'
        Exists    = $true
        StartType = 'AutomaticDelayedStart'
        State     = 'Stopped'
    }
    Task              = [pscustomobject]@{
        Path           = '\\Microsoft\\Windows\\PushToInstall\\PushLaunch'
        Exists         = $true
        Enabled        = $true
        LastResult     = 0
        LastRunTimeUtc = $recentRunUtc
        State          = 'Ready'
    }
    Logs              = [pscustomobject]@{
        DMEDP = [pscustomobject]@{ RecentErrors = 0; LastErrorUtc = $null }
        Push  = [pscustomobject]@{ RecentErrors = 0; LastErrorUtc = $null }
    }
}

$healthyContext = New-TestIntuneContext -ServiceEntries @($healthyService) -PushPayload $healthyPushPayload
$category = Invoke-IntuneHeuristics -Context $healthyContext
$pushIssues = @($category.Issues | Where-Object { $_.Title -like 'Intune/Push Wake*' })
if ($pushIssues.Count -gt 0) {
    $details = $pushIssues | ForEach-Object { "{0} (Severity={1})" -f $_.Title, $_.Severity }
    $null = $failures.Add('Intune heuristic produced unexpected push notification issues: ' + ($details -join '; '))
}

$pushNormals = @($category.Normals | Where-Object { $_.Title -like 'Intune push wake prerequisites are ready*' })
if ($pushNormals.Count -eq 0) {
    $null = $failures.Add('Expected a healthy Intune push wake normal check but none was recorded.')
}

$disabledPushPayload = [pscustomobject]@{
    CollectedAtUtc    = $collectedAtUtc
    RecencyWindowDays = 7
    Service           = [pscustomobject]@{
        Name      = 'dmwappushservice'
        Exists    = $true
        StartType = 'Disabled'
        State     = 'Stopped'
    }
}

$disabledContext = New-TestIntuneContext -ServiceEntries @($healthyService) -PushPayload $disabledPushPayload
$disabledCategory = Invoke-IntuneHeuristics -Context $disabledContext
$disabledIssues = @($disabledCategory.Issues | Where-Object { $_.Title -like 'Intune/Push Wake*' })
if ($disabledIssues.Count -ne 1) {
    $null = $failures.Add('Expected a single Intune push wake issue when the service is disabled.')
} else {
    $disabledIssue = $disabledIssues[0]
    if ($disabledIssue.Severity -ne 'high') {
        $null = $failures.Add('Expected disabled service issue severity to be high.')
    }
    if ($disabledIssue.Explanation -notmatch 'Service is disabled, so push wake requests from Intune will not arrive') {
        $null = $failures.Add('Disabled service explanation did not describe the push wake impact.')
    }
    $disabledEvidence = $disabledIssue.Evidence | Where-Object { $_ -like 'Service: dmwappushservice*' } | Select-Object -First 1
    if ($disabledEvidence -notmatch 'StartType=Disabled') {
        $null = $failures.Add('Disabled service evidence did not include the Disabled start type.')
    }
}

$failedPushPayload = [pscustomobject]@{
    CollectedAtUtc    = $collectedAtUtc
    RecencyWindowDays = 7
    Service           = [pscustomobject]@{
        Name      = 'dmwappushservice'
        Exists    = $true
        StartType = 'AutomaticDelayedStart'
        State     = 'Stopped'
        Error     = '0x8007041D: The service did not respond to the start request.'
    }
}

$failedContext = New-TestIntuneContext -ServiceEntries @($healthyService) -PushPayload $failedPushPayload
$failedCategory = Invoke-IntuneHeuristics -Context $failedContext
$failedIssues = @($failedCategory.Issues | Where-Object { $_.Title -like 'Intune/Push Wake*' })
if ($failedIssues.Count -ne 1) {
    $null = $failures.Add('Expected a single Intune push wake issue when the service fails to start.')
} else {
    $failedIssue = $failedIssues[0]
    if ($failedIssue.Severity -ne 'high') {
        $null = $failures.Add('Expected failed start issue severity to be high.')
    }
    if ($failedIssue.Explanation -notmatch 'failed to start \(LastStartError=0x8007041D') {
        $null = $failures.Add('Failed start explanation did not include the last start error.')
    }
}

$missingPushPayload = [pscustomobject]@{
    CollectedAtUtc    = $collectedAtUtc
    RecencyWindowDays = 7
    Service           = [pscustomobject]@{
        Name      = 'dmwappushservice'
        Exists    = $false
    }
}

$missingContext = New-TestIntuneContext -ServiceEntries @($healthyService) -PushPayload $missingPushPayload
$missingCategory = Invoke-IntuneHeuristics -Context $missingContext
$missingIssues = @($missingCategory.Issues | Where-Object { $_.Title -like 'Intune/Push Wake*' })
if ($missingIssues.Count -ne 1) {
    $null = $failures.Add('Expected a single Intune push wake issue when the service is missing.')
} else {
    $missingIssue = $missingIssues[0]
    if ($missingIssue.Severity -ne 'high') {
        $null = $failures.Add('Expected missing service issue severity to be high.')
    }
    if ($missingIssue.Explanation -notmatch 'Service is missing, so push wake requests from Intune will not arrive') {
        $null = $failures.Add('Missing service explanation did not describe the push wake impact.')
    }
}

$workgroupDsreg = @'
AzureAdJoined : NO
PRT : NO
MdmUrl : (Not set)
MdmEnrollmentUrl : (Not set)
'

$workgroupContext = New-TestIntuneContext -DsregText $workgroupDsreg
$workgroupResult = Invoke-IntuneHeuristics -Context $workgroupContext
if ($workgroupResult) {
    $null = $failures.Add('Expected Intune heuristics to be skipped when Intune MDM enrollment is not detected.')
}

if ($failures.Count -gt 0) {
    Write-Host 'Intune parser tests failed:'
    foreach ($failure in $failures) {
        Write-Host " - $failure"
    }
    exit 1
}

Write-Host 'Intune parser tests passed.'
