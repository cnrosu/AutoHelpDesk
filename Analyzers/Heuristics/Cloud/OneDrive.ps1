<#!
.SYNOPSIS
    Evaluates collected OneDrive state and records impact-focused findings.
#>

function Invoke-OneDriveHeuristic {
    param(
        [Parameter(Mandatory)]
        $Context,

        [Parameter(Mandatory)]
        $Result
    )

    $artifact = Get-AnalyzerArtifact -Context $Context -Name 'cloud-onedrive'
    Write-HeuristicDebug -Source 'Cloud.OneDrive' -Message 'Resolved OneDrive artifact' -Data ([ordered]@{
        Found = [bool]$artifact
    })

    if (-not $artifact) {
        Add-CategoryIssue -CategoryResult $Result -Severity 'warning' -Title 'OneDrive collector missing, so cloud file sync health is unknown.' -Subcategory 'OneDrive' -Remediation 'Re-run collectors with OneDrive signed in to capture sync health signals.'
        return
    }

    $payload = Resolve-SinglePayload -Payload (Get-ArtifactPayload -Artifact $artifact)
    if (-not $payload) {
        Add-CategoryIssue -CategoryResult $Result -Severity 'warning' -Title 'OneDrive payload missing, so cloud file sync health is unknown.' -Subcategory 'OneDrive' -Remediation 'Re-run collectors with OneDrive signed in to capture sync health signals.'
        return
    }

    $state = $payload.OneDrive
    Write-HeuristicDebug -Source 'Cloud.OneDrive' -Message 'Evaluating OneDrive state payload' -Data ([ordered]@{
        HasState = [bool]$state
    })

    if (-not $state) {
        Add-CategoryIssue -CategoryResult $Result -Severity 'warning' -Title 'OneDrive state unavailable, so cloud file sync health is unknown.' -Subcategory 'OneDrive' -Remediation 'Re-run collectors with OneDrive signed in to capture sync health signals.'
        return
    }

    if ($state.PSObject.Properties['Error']) {
        Add-CategoryIssue -CategoryResult $Result -Severity 'warning' -Title 'OneDrive state collection failed, so cloud file sync health is unknown.' -Evidence $state.Error -Subcategory 'OneDrive' -Remediation 'Re-run collectors with OneDrive signed in to capture sync health signals.'
        return
    }

    $notesEvidence = if ($state.Notes -and $state.Notes.Count -gt 0) { $state.Notes -join '; ' } else { $null }

    if (-not $state.Installed) {
        Add-CategoryIssue -CategoryResult $Result -Severity 'medium' -Title 'OneDrive is not installed, so files cannot sync to Microsoft 365 storage.' -Evidence 'OneDrive.exe not found in per-user or per-machine locations.' -Subcategory 'OneDrive' -Remediation 'Install Microsoft OneDrive. For managed devices, deploy the latest OneDrive sync app via Intune or your software management tool.'
        return
    }

    $installSource = if ($state.PSObject.Properties['InstallSource'] -and $state.InstallSource) { [string]$state.InstallSource } else { 'Unknown' }
    $installPath = if ($state.PSObject.Properties['InstallPath'] -and $state.InstallPath) { [string]$state.InstallPath } else { 'n/a' }
    $installVersion = if ($state.PSObject.Properties['Version'] -and $state.Version) { [string]$state.Version } else { 'n/a' }
    $installEvidence = "Source=$installSource; Path=$installPath; Version=$installVersion"
    Add-CategoryNormal -CategoryResult $Result -Title 'OneDrive is installed, so the sync client is available on this device.' -Evidence $installEvidence -Subcategory 'OneDrive'

    if (-not $state.AutoStartEnabled) {
        $autoEvidence = if ($notesEvidence) { "Auto-start sources missing. Notes: $notesEvidence" } else { 'Auto-start sources missing (RunKey/ScheduledTask/StartupFolder).' }
        Add-CategoryIssue -CategoryResult $Result -Severity 'low' -Title 'OneDrive is not set to start with Windows, so users may miss automatic file sync after sign-in.' -Evidence $autoEvidence -Subcategory 'OneDrive' -Remediation 'Enable OneDrive auto-start: Settings → OneDrive → General → “Start OneDrive automatically…” or add the Run key value. For managed devices, enforce via policy.'
    }

    if (-not $state.Running) {
        Add-CategoryIssue -CategoryResult $Result -Severity 'medium' -Title 'The OneDrive process is not running, so files are not actively syncing.' -Evidence 'Get-Process OneDrive returned no instances.' -Subcategory 'OneDrive' -Remediation 'Launch OneDrive (Win+R → OneDrive) or sign out and back in. If it keeps exiting, repair the app, clear cache, or reinstall the client.'
    }

    if ($state.Accounts -and $state.Accounts.Count -gt 0) {
        $accountSummaries = $state.Accounts | ForEach-Object {
            $type = $_.Type
            $email = if ($_.UserEmail) { $_.UserEmail } else { 'no-email' }
            $folder = if ($_.UserFolder) { $_.UserFolder } else { 'no-folder' }
            $status = if ($_.Exists) { 'OK' } else { 'MISSING' }
            "{0} ({1}) → {2} [{3}]" -f $type, $email, $folder, $status
        } | Sort-Object

        $missingFolders = $state.Accounts | Where-Object { -not $_.Exists }
        if ($missingFolders.Count -gt 0) {
            Add-CategoryIssue -CategoryResult $Result -Severity 'low' -Title 'OneDrive account folders are missing, so affected profiles cannot sync files.' -Evidence ($accountSummaries -join '; ') -Subcategory 'OneDrive' -Remediation 'If a OneDrive folder path is missing on disk, re-run OneDrive setup or unlink and relink the account.'
        } else {
            Add-CategoryNormal -CategoryResult $Result -Title 'OneDrive accounts detected, so sync folders are configured for this user.' -Evidence ($accountSummaries -join '; ') -Subcategory 'OneDrive'
        }
    } else {
        Add-CategoryIssue -CategoryResult $Result -Severity 'medium' -Title 'No OneDrive accounts are signed in, so user files will not sync to the cloud.' -Evidence 'No Business or Personal OneDrive account keys found under HKCU.' -Subcategory 'OneDrive' -Remediation 'Open OneDrive and sign in with your work or personal account. For work, confirm the device and user are licensed and personal sync is not blocked by policy.'
    }

    $kfmStatus = if ($state.KFM) { $state.KFM } else { $null }
    if ($kfmStatus) {
        $policy = $kfmStatus.EffectivePolicy
        $status = $kfmStatus.EffectiveStatus
        $redirected = @()
        if ($status.DesktopRedirected) { $redirected += 'Desktop' }
        if ($status.DocumentsRedirected) { $redirected += 'Documents' }
        if ($status.PicturesRedirected) { $redirected += 'Pictures' }

        $policySilentOptIn = if ($policy -and $policy.PSObject.Properties['KFMSilentOptIn'] -and $null -ne $policy.KFMSilentOptIn) { $policy.KFMSilentOptIn } else { 'n/a' }
        $policySilentDesktop = if ($policy -and $policy.PSObject.Properties['KFMSilentOptInDesktop'] -and $null -ne $policy.KFMSilentOptInDesktop) { $policy.KFMSilentOptInDesktop } else { 'n/a' }
        $policyBlockOptIn = if ($policy -and $policy.PSObject.Properties['KFMBlockOptIn'] -and $null -ne $policy.KFMBlockOptIn) { $policy.KFMBlockOptIn } else { 'n/a' }
        $policyDisablePersonal = if ($policy -and $policy.PSObject.Properties['DisablePersonalSync'] -and $null -ne $policy.DisablePersonalSync) { $policy.DisablePersonalSync } else { 'n/a' }
        $policySummary = "SilentOptIn=$policySilentOptIn; SilentOptInDesktop=$policySilentDesktop; BlockOptIn=$policyBlockOptIn; DisablePersonalSync=$policyDisablePersonal"

        if ($redirected.Count -gt 0) {
            Add-CategoryNormal -CategoryResult $Result -Title ("Known Folder Backup is enabled for {0}, so key folders sync to OneDrive." -f ($redirected -join ', ')) -Evidence ("Redirected={0}. Policy: {1}" -f ($redirected -join ', '), $policySummary) -Subcategory 'OneDrive'
        } else {
            if ($policy.KFMBlockOptIn -eq 1) {
                Add-CategoryIssue -CategoryResult $Result -Severity 'info' -Title 'Known Folder Backup is blocked by policy, so Desktop, Documents, and Pictures stay local.' -Evidence ("Policy: {0}" -f $policySummary) -Subcategory 'OneDrive' -Remediation 'This is expected when the organization blocks KFM. Update policy if redirection should be allowed.'
            } else {
                Add-CategoryIssue -CategoryResult $Result -Severity 'low' -Title 'Known Folder Backup is not enabled, so Desktop, Documents, and Pictures stay local.' -Evidence ("Policy: {0}" -f $policySummary) -Subcategory 'OneDrive' -Remediation 'Enable OneDrive backup for Desktop, Documents, and Pictures (OneDrive → Settings → Sync and backup). In managed tenants, configure KFM Silent Opt-In in Intune or Group Policy.'
            }
        }

        if ($policy.DisablePersonalSync -eq 1) {
            Add-CategoryIssue -CategoryResult $Result -Severity 'info' -Title 'Personal OneDrive accounts are blocked by policy, so users can only sync work accounts.' -Evidence 'HKLM\\SOFTWARE\\Policies\\Microsoft\\OneDrive\\DisablePersonalSync=1' -Subcategory 'OneDrive' -Remediation 'Use a work account or request a policy exception if personal sync is required.'
        }
    }

}
