<#!
.SYNOPSIS
    Collects Microsoft Defender Attack Surface Reduction configuration and exclusions.
#>
[CmdletBinding()]
param(
    [Parameter()]
    [string]$OutputDirectory = (Join-Path -Path (Split-Path -Parent $PSCommandPath) -ChildPath '..\\output')
)

. (Join-Path -Path $PSScriptRoot -ChildPath '..\\CollectorCommon.ps1')

function Convert-AsrRules {
    param(
        [Parameter()]$Rules
    )

    $result = @()
    if ($Rules) {
        foreach ($entry in $Rules.GetEnumerator()) {
            $result += [PSCustomObject]@{
                RuleId = $entry.Key
                Action = $entry.Value
            }
        }
    }

    return $result
}

function Get-AsrPolicy {
    try {
        $prefs = Get-MpPreference -ErrorAction Stop
        return [PSCustomObject]@{
            Rules          = Convert-AsrRules -Rules $prefs.AttackSurfaceReductionRules_Actions
            OnlyExclusions = $prefs.AttackSurfaceReductionOnlyExclusions
            ProcessExclusions = $prefs.AttackSurfaceReductionRules_Ids
        }
    } catch {
        return [PSCustomObject]@{
            Source = 'Get-MpPreference'
            Error  = $_.Exception.Message
        }
    }
}

function Invoke-Main {
    $payload = [ordered]@{
        Policy = Get-AsrPolicy
    }

    $result = New-CollectorMetadata -Payload $payload
    $outputPath = Export-CollectorResult -OutputDirectory $OutputDirectory -FileName 'asr.json' -Data $result -Depth 6
    Write-Output $outputPath
}

Invoke-Main
