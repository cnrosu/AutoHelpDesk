<#!
.SYNOPSIS
    Collects startup program inventory via Win32_StartupCommand for analyzer fallback scenarios.
#>
[CmdletBinding()]
param(
    [Parameter()]
    [string]$OutputDirectory = (Join-Path -Path (Split-Path -Parent $PSCommandPath) -ChildPath '..\output')
)

. (Join-Path -Path $PSScriptRoot -ChildPath '..\CollectorCommon.ps1')

function ConvertTo-StartupEntry {
    param(
        [Parameter(Mandatory)]
        $Instance
    )

    $entry = [ordered]@{}

    foreach ($property in @('Name', 'Command', 'Location', 'User', 'Description', 'Caption')) {
        if ($Instance.PSObject.Properties[$property]) {
            $value = $Instance.$property
            if ($null -ne $value) {
                $stringValue = [string]$value
                if (-not [string]::IsNullOrWhiteSpace($stringValue)) {
                    $entry[$property] = $stringValue
                }
            }
        }
    }

    if ($Instance.PSObject.Properties['SettingID'] -and $Instance.SettingID) {
        $entry['SettingID'] = [string]$Instance.SettingID
    }

    if ($entry.Count -eq 0) { return $null }

    return [pscustomobject]$entry
}

function Get-StartupInventory {
    $candidates = @(
        @{ Label = 'Win32_StartupCommand (CIM)'; Script = { Get-CimInstance -ClassName Win32_StartupCommand -ErrorAction Stop } }
    )

    if (Get-Command -Name Get-WmiObject -ErrorAction SilentlyContinue) {
        $candidates += @{ Label = 'Win32_StartupCommand (WMI)'; Script = { Get-WmiObject -Class Win32_StartupCommand -ErrorAction Stop } }
    }

    $entries = [System.Collections.Generic.List[pscustomobject]]::new()
    $errors = [System.Collections.Generic.List[string]]::new()
    $sourceLabel = $null

    foreach ($candidate in $candidates) {
        if ($entries.Count -gt 0) { break }

        try {
            $items = & $candidate.Script
            if (-not $items) { continue }

            foreach ($item in @($items)) {
                if (-not $item) { continue }
                $converted = ConvertTo-StartupEntry -Instance $item
                if ($converted) { $entries.Add($converted) | Out-Null }
            }

            if ($entries.Count -gt 0) {
                $sourceLabel = $candidate.Label
            }
        } catch {
            $errors.Add($_.Exception.Message) | Out-Null
        }
    }

    return [pscustomobject]@{
        Source = $sourceLabel
        Entries = $entries
        Errors = $errors
    }
}

function Invoke-Main {
    $inventory = Get-StartupInventory

    $entries = $inventory.Entries
    $errors = $inventory.Errors
    $source = if ($inventory.Source) { $inventory.Source } else { 'Win32_StartupCommand' }

    $payloadEntries = @()
    if ($entries -and $entries.Count -gt 0) {
        $payloadEntries = $entries.ToArray()
    } elseif ($errors -and $errors.Count -gt 0) {
        $errorEntries = [System.Collections.Generic.List[pscustomobject]]::new()
        foreach ($error in $errors) {
            if ([string]::IsNullOrWhiteSpace($error)) { continue }
            $errorEntries.Add([pscustomobject]@{ Error = $error; Source = $source }) | Out-Null
        }
        if ($errorEntries.Count -gt 0) {
            $payloadEntries = $errorEntries.ToArray()
        }
    }

    $payload = [ordered]@{
        Source           = $source
        StartupCommands  = $payloadEntries
        CollectionErrors = if ($errors -and $errors.Count -gt 0) { $errors.ToArray() } else { @() }
    }

    $result = New-CollectorMetadata -Payload $payload
    $outputPath = Export-CollectorResult -OutputDirectory $OutputDirectory -FileName 'startup.json' -Data $result -Depth 6
    Write-Output $outputPath
}

Invoke-Main
