<#!
.SYNOPSIS
    Printing heuristics that mirror AutoL1 diagnostics for spooler health, queue posture, and event volume.
#>

. (Join-Path -Path (Split-Path $PSScriptRoot -Parent) -ChildPath 'AnalyzerCommon.ps1')
. (Join-Path -Path $PSScriptRoot -ChildPath 'Printing/Common.ps1')
. (Join-Path -Path $PSScriptRoot -ChildPath 'Printing/Platform.ps1')
. (Join-Path -Path $PSScriptRoot -ChildPath 'Printing/Spooler.ps1')
. (Join-Path -Path $PSScriptRoot -ChildPath 'Printing/Inventory.ps1')
. (Join-Path -Path $PSScriptRoot -ChildPath 'Printing/Events.ps1')
. (Join-Path -Path $PSScriptRoot -ChildPath 'Printing/NetworkTests.ps1')

function Invoke-PrintingHeuristics {
    param(
        [Parameter(Mandatory)]
        $Context
    )

    Write-HeuristicDebug -Source 'Printing' -Message 'Starting printing heuristics' -Data ([ordered]@{
        ArtifactCount = if ($Context -and $Context.Artifacts) { $Context.Artifacts.Count } else { 0 }
    })

    $result = New-CategoryResult -Name 'Printing'
    $platform = Get-PrintingPlatformInfo -Context $Context
    $isWorkstation = ($platform.IsWorkstation -eq $true)
    Write-HeuristicDebug -Source 'Printing' -Message 'Resolved platform information' -Data ([ordered]@{
        IsServer      = $platform.IsWindowsServer
        IsWorkstation = $platform.IsWorkstation
    })

    $printingArtifact = Get-AnalyzerArtifact -Context $Context -Name 'printing'
    Write-HeuristicDebug -Source 'Printing' -Message 'Resolved printing artifact' -Data ([ordered]@{
        Found = [bool]$printingArtifact
    })
    if (-not $printingArtifact) {
        Add-CategoryIssue -CategoryResult $result -Severity 'info' -Title "Printing artifact not collected, so printing security and reliability risks can't be evaluated." -Subcategory 'Collection'
        return $result
    }

    $payload = Resolve-SinglePayload -Payload (Get-ArtifactPayload -Artifact $printingArtifact)
    Write-HeuristicDebug -Source 'Printing' -Message 'Resolved printing payload' -Data ([ordered]@{
        HasPayload = [bool]$payload
    })
    if (-not $payload) {
        Add-CategoryIssue -CategoryResult $result -Severity 'info' -Title "Printing payload missing, so printing security and reliability risks can't be evaluated." -Subcategory 'Collection'
        return $result
    }

    if ($payload.Errors) {
        foreach ($error in $payload.Errors) {
            if ($error) {
                Add-CategoryIssue -CategoryResult $result -Severity 'info' -Title 'Printing data collection warning, so printing security and reliability risks may be hidden.' -Evidence $error -Subcategory 'Collection'
            }
        }
    }

    Invoke-PrintingSpoolerChecks -Result $result -Spooler $payload.Spooler -IsWorkstation $isWorkstation

    $inventorySummary = Invoke-PrinterInventoryChecks -Result $result -Payload $payload

    Invoke-PrinterEventChecks -Result $result -Events $payload.Events
    Invoke-PrinterNetworkTestChecks -Result $result -NetworkTests $payload.NetworkTests

    if ($inventorySummary) {
        Write-HeuristicDebug -Source 'Printing' -Message 'Printer analysis summary' -Data ([ordered]@{
            OfflineCount = $inventorySummary.OfflinePrinters.Count
            WsdCount     = $inventorySummary.WsdPrinters.Count
            StaleJobs    = $inventorySummary.StuckJobs.Count
        })

        if ($inventorySummary.Printers.Count -gt 0 -and $inventorySummary.OfflinePrinters.Count -eq 0) {
            Add-CategoryNormal -CategoryResult $result -Title ('Printers online ({0})' -f $inventorySummary.Printers.Count) -Subcategory 'Printers'
        }
    }

    return $result
}
