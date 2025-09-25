<#!
.SYNOPSIS
    Storage heuristics evaluating disk health and free space thresholds.
#>

. (Join-Path -Path (Split-Path $PSScriptRoot -Parent) -ChildPath 'AnalyzerCommon.ps1')

function Invoke-StorageHeuristics {
    param(
        [Parameter(Mandatory)]
        $Context
    )

    $result = New-CategoryResult -Name 'Storage'

    $storageArtifact = Get-AnalyzerArtifact -Context $Context -Name 'storage'
    if ($storageArtifact) {
        $payload = Resolve-SinglePayload -Payload (Get-ArtifactPayload -Artifact $storageArtifact)
        if ($payload -and $payload.Disks -and -not $payload.Disks.Error) {
            $unhealthy = $payload.Disks | Where-Object { $_.HealthStatus -and $_.HealthStatus -ne 'Healthy' }
            if ($unhealthy.Count -gt 0) {
                $details = $unhealthy | ForEach-Object { "Disk $($_.Number): $($_.HealthStatus) ($($_.OperationalStatus))" }
                Add-CategoryIssue -CategoryResult $result -Severity 'high' -Title 'Disks reporting degraded health' -Evidence ($details -join "`n")
            } else {
                Add-CategoryNormal -CategoryResult $result -Title 'Disk health reports healthy'
            }
        }

        if ($payload -and $payload.Volumes -and -not $payload.Volumes.Error) {
            $lowSpace = @()
            foreach ($volume in $payload.Volumes) {
                if (-not $volume.Size -or -not $volume.SizeRemaining) { continue }
                $size = [double]$volume.Size
                $free = [double]$volume.SizeRemaining
                if ($size -le 0) { continue }
                $freePct = ($free / $size) * 100
                $label = if ($volume.DriveLetter) { $volume.DriveLetter } elseif ($volume.FileSystemLabel) { $volume.FileSystemLabel } else { 'Unknown' }
                Add-CategoryCheck -CategoryResult $result -Name ("Volume {0}" -f $label) -Status ([string][math]::Round($freePct,1)) -Details 'Free space percent'
                if ($freePct -lt 10) {
                    $lowSpace += ("{0} ({1}% free)" -f $label, [math]::Round($freePct,1))
                }
            }
            if ($lowSpace.Count -gt 0) {
                Add-CategoryIssue -CategoryResult $result -Severity 'high' -Title 'Volumes critically low on space' -Evidence ($lowSpace -join ', ')
            }
        }
    } else {
        Add-CategoryIssue -CategoryResult $result -Severity 'info' -Title 'Storage artifact missing'
    }

    return $result
}
