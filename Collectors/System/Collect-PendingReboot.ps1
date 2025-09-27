<#!
.SYNOPSIS
    Collects registry indicators that signal a pending reboot requirement.
#>
[CmdletBinding()]
param(
    [Parameter()]
    [string]$OutputDirectory = (Join-Path -Path (Split-Path -Parent $PSCommandPath) -ChildPath '..\output')
)

. (Join-Path -Path $PSScriptRoot -ChildPath '..\CollectorCommon.ps1')

function Get-PendingRebootRegistryStatus {
    $checks = @(
        @{ Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending' },
        @{ Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired' },
        @{ Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager'; ValueName = 'PendingFileRenameOperations' }
    )

    $results = @()

    foreach ($check in $checks) {
        $entry = [ordered]@{
            Path = $check.Path
        }

        if ($check.ContainsKey('ValueName') -and $check.ValueName) {
            $entry['ValueName'] = $check.ValueName
        }

        try {
            if ($entry.ValueName) {
                $item = Get-ItemProperty -Path $entry.Path -Name $entry.ValueName -ErrorAction Stop
                $value = $item.PSObject.Properties[$entry.ValueName].Value
                $lastWrite = (Get-Item -LiteralPath $entry.Path -ErrorAction Stop).LastWriteTime

                $normalizedValue = $null
                if ($null -ne $value) {
                    if ($value -is [System.Collections.IEnumerable] -and -not ($value -is [string])) {
                        $normalizedValue = @($value | ForEach-Object { $_ })
                    } else {
                        $normalizedValue = @([string]$value)
                    }
                }

                $hasEntries = $false
                if ($normalizedValue) {
                    $nonEmpty = $normalizedValue | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) }
                    if ($nonEmpty.Count -gt 0) {
                        $hasEntries = $true
                    }
                }

                $entry['Present'] = $hasEntries
                $entry['LastWriteTime'] = if ($lastWrite) { $lastWrite.ToString('o') } else { $null }
                if ($normalizedValue) {
                    $entry['Values'] = $normalizedValue
                }
            } else {
                $item = Get-Item -LiteralPath $entry.Path -ErrorAction Stop
                $entry['Present'] = $true
                if ($item.PSObject.Properties['LastWriteTime']) {
                    $entry['LastWriteTime'] = $item.LastWriteTime.ToString('o')
                }

                try {
                    $values = Get-ItemProperty -Path $entry.Path -ErrorAction Stop | Select-Object * -ExcludeProperty PS*, CIM*, PSEdition
                    if ($values) {
                        $entry['Values'] = $values
                    }
                } catch {
                    $entry['ValueReadError'] = $_.Exception.Message
                }
            }
        } catch {
            $entry['Present'] = $false
            $entry['Error'] = $_.Exception.Message
        }

        $results += [pscustomobject]$entry
    }

    return $results
}

function Invoke-Main {
    $payload = [ordered]@{
        Registry = Get-PendingRebootRegistryStatus
    }

    $result = New-CollectorMetadata -Payload $payload
    $outputPath = Export-CollectorResult -OutputDirectory $OutputDirectory -FileName 'pending-reboot.json' -Data $result -Depth 6
    Write-Output $outputPath
}

Invoke-Main
