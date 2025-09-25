<#!
.SYNOPSIS
    Collects running process snapshot with resource usage.
#>
[CmdletBinding()]
param(
    [Parameter()]
    [string]$OutputDirectory = (Join-Path -Path (Split-Path -Parent $PSCommandPath) -ChildPath '..\\output')
)

. (Join-Path -Path $PSScriptRoot -ChildPath '..\\CollectorCommon.ps1')

function Get-ProcessSnapshot {
    try {
        return Get-Process | Select-Object Name, Id, CPU, WorkingSet, StartTime, Path
    } catch {
        return [PSCustomObject]@{
            Source = 'Get-Process'
            Error  = $_.Exception.Message
        }
    }
}

function Get-TaskListVerbose {
    try {
        return tasklist.exe /v 2>$null
    } catch {
        return [PSCustomObject]@{
            Source = 'tasklist /v'
            Error  = $_.Exception.Message
        }
    }
}

function Invoke-Main {
    $payload = [ordered]@{
        Processes = Get-ProcessSnapshot
        Tasklist  = Get-TaskListVerbose
    }

    $result = New-CollectorMetadata -Payload $payload
    $outputPath = Export-CollectorResult -OutputDirectory $OutputDirectory -FileName 'processes.json' -Data $result -Depth 6
    Write-Output $outputPath
}

Invoke-Main
