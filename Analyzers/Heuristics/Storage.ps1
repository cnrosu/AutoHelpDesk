<#!
.SYNOPSIS
    Storage heuristics evaluating disk health and free space thresholds.
#>

. (Join-Path -Path (Split-Path $PSScriptRoot -Parent) -ChildPath 'AnalyzerCommon.ps1')

. (Join-Path -Path $PSScriptRoot -ChildPath 'Storage/Storage.Helpers.ps1')
. (Join-Path -Path $PSScriptRoot -ChildPath 'Storage/Storage.DiskHealth.ps1')
. (Join-Path -Path $PSScriptRoot -ChildPath 'Storage/Storage.Volumes.ps1')
. (Join-Path -Path $PSScriptRoot -ChildPath 'Storage/Storage.Wear.ps1')
. (Join-Path -Path $PSScriptRoot -ChildPath 'Storage/Storage.Snapshot.ps1')

function Invoke-StorageHeuristics {
    param(
        [Parameter(Mandatory)]
        $Context
    )

    Write-HeuristicDebug -Source 'Storage' -Message 'Starting storage heuristics' -Data ([ordered]@{
        ArtifactCount = if ($Context -and $Context.Artifacts) { $Context.Artifacts.Count } else { 0 }
    })

    $result = New-CategoryResult -Name 'Storage'

    $storageArtifact = Get-AnalyzerArtifact -Context $Context -Name 'storage'
    $snapshotArtifact = Get-AnalyzerArtifact -Context $Context -Name 'storage-snapshot'
    Write-HeuristicDebug -Source 'Storage' -Message 'Resolved storage artifacts' -Data ([ordered]@{
        StorageFound  = [bool]$storageArtifact
        SnapshotFound = [bool]$snapshotArtifact
    })

    if ($storageArtifact) {
        $payload = Resolve-SinglePayload -Payload (Get-ArtifactPayload -Artifact $storageArtifact)
        Write-HeuristicDebug -Source 'Storage' -Message 'Evaluating storage payload' -Data ([ordered]@{
            HasPayload = [bool]$payload
        })

        Invoke-StorageDiskHealthEvaluation -CategoryResult $result -Payload $payload

        $thresholdConfig = Resolve-StorageThresholdConfig -Context $Context
        Invoke-StorageVolumeEvaluation -CategoryResult $result -Payload $payload -ThresholdConfig $thresholdConfig

        Invoke-StorageWearEvaluation -CategoryResult $result -Payload $payload
    }

    if ($snapshotArtifact) {
        $snapshotPayload = Resolve-SinglePayload -Payload (Get-ArtifactPayload -Artifact $snapshotArtifact)
        Write-HeuristicDebug -Source 'Storage' -Message 'Evaluating storage snapshot payload' -Data ([ordered]@{
            HasPayload = [bool]$snapshotPayload
        })
        Invoke-StorageSnapshotEvaluation -CategoryResult $result -SnapshotPayload $snapshotPayload
    }

    if (-not $storageArtifact) {
        Add-CategoryIssue -CategoryResult $result -Severity 'warning' -Title 'Storage inventory artifact missing, so storage health and wear cannot be evaluated.' -Subcategory 'Collection'
    }

    if (-not $snapshotArtifact) {
        Add-CategoryIssue -CategoryResult $result -Severity 'warning' -Title 'Storage snapshot artifact missing, so SMART status cannot be evaluated.' -Subcategory 'Collection' -Remediation $script:StorageHealthAndSpaceRemediation
    }

    return $result
}
