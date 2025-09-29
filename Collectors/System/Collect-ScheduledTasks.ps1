<#!
.SYNOPSIS
    Collects scheduled task inventory and run status.
#>
[CmdletBinding()]
param(
    [Parameter()]
    [string]$OutputDirectory = (Join-Path -Path (Split-Path -Parent $PSCommandPath) -ChildPath '..\\output')
)

. (Join-Path -Path $PSScriptRoot -ChildPath '..\\CollectorCommon.ps1')

function ConvertTo-TaskTriggerSummary {
    param(
        [object]$Trigger
    )

    if (-not $Trigger) { return $null }

    $summary = [ordered]@{
        Type          = $null
        ExecutionTime = $null
        DaysOfWeek    = $null
        Interval      = $null
    }

    if ($Trigger.PSObject.Properties['TriggerType']) {
        $summary.Type = [string]$Trigger.TriggerType
    }

    if ($Trigger.PSObject.Properties['StartBoundary']) {
        $summary.ExecutionTime = [string]$Trigger.StartBoundary
    }

    if ($Trigger.PSObject.Properties['DaysOfWeek']) {
        $days = $Trigger.DaysOfWeek
        if ($days -is [System.Array]) {
            $summary.DaysOfWeek = @($days | ForEach-Object { [string]$_ })
        } elseif ($days) {
            $summary.DaysOfWeek = @([string]$days)
        }
    }

    if ($Trigger.PSObject.Properties['Repetition']) {
        $rep = $Trigger.Repetition
        if ($rep -and $rep.PSObject.Properties['Interval']) {
            $summary.Interval = [string]$rep.Interval
        }
    }

    return $summary
}

function ConvertTo-TaskActionSummary {
    param(
        [object]$Action
    )

    if (-not $Action) { return $null }

    $summary = [ordered]@{
        Type      = $null
        Execute   = $null
        Arguments = $null
    }

    if ($Action.PSObject.Properties['ActionType']) {
        $summary.Type = [string]$Action.ActionType
    }

    if ($Action.PSObject.Properties['Execute']) {
        $summary.Execute = [string]$Action.Execute
    }

    if ($Action.PSObject.Properties['Arguments']) {
        $summary.Arguments = [string]$Action.Arguments
    }

    return $summary
}

function Get-TaskInventory {
    $result = [ordered]@{
        Tasks  = @()
        Errors = @()
    }

    $tasks = @()
    try {
        $tasks = Get-ScheduledTask -ErrorAction Stop
    } catch {
        $result.Errors += "Get-ScheduledTask failed: $($_.Exception.Message)"
    }

    if (-not $tasks -or $tasks.Count -eq 0) {
        return $result
    }

    foreach ($task in $tasks) {
        if (-not $task) { continue }

        $info = $null
        $infoError = $null
        try {
            $info = $task | Get-ScheduledTaskInfo -ErrorAction Stop
        } catch {
            $infoError = $_.Exception.Message
        }

        $actions = @()
        if ($task.PSObject.Properties['Actions'] -and $task.Actions) {
            foreach ($action in $task.Actions) {
                $summary = ConvertTo-TaskActionSummary -Action $action
                if ($summary) { $actions += $summary }
            }
        }

        $triggers = @()
        if ($task.PSObject.Properties['Triggers'] -and $task.Triggers) {
            foreach ($trigger in $task.Triggers) {
                $summary = ConvertTo-TaskTriggerSummary -Trigger $trigger
                if ($summary) { $triggers += $summary }
            }
        }

        $taskRecord = [ordered]@{
            TaskName        = if ($task.PSObject.Properties['TaskName']) { [string]$task.TaskName } else { $null }
            TaskPath        = if ($task.PSObject.Properties['TaskPath']) { [string]$task.TaskPath } else { $null }
            Description     = if ($task.PSObject.Properties['Description']) { [string]$task.Description } else { $null }
            Author          = if ($task.PSObject.Properties['Author']) { [string]$task.Author } else { $null }
            State           = if ($info -and $info.PSObject.Properties['State']) { [string]$info.State } else { $null }
            Enabled         = if ($task.PSObject.Properties['Enabled']) { [bool]$task.Enabled } else { $null }
            LastRunTime     = if ($info -and $info.PSObject.Properties['LastRunTime'] -and $info.LastRunTime) { ($info.LastRunTime).ToString('o') } else { $null }
            NextRunTime     = if ($info -and $info.PSObject.Properties['NextRunTime'] -and $info.NextRunTime) { ($info.NextRunTime).ToString('o') } else { $null }
            LastTaskResult  = if ($info -and $info.PSObject.Properties['LastTaskResult']) { [int]$info.LastTaskResult } else { $null }
            MissedRuns      = if ($info -and $info.PSObject.Properties['NumberOfMissedRuns']) { [int]$info.NumberOfMissedRuns } else { $null }
            Triggers        = $triggers
            Actions         = $actions
            InfoError       = $infoError
        }

        $result.Tasks += $taskRecord
    }

    return $result
}

function Invoke-Main {
    $payload = [ordered]@{
        Tasks = Get-TaskInventory
    }

    $result = New-CollectorMetadata -Payload $payload
    $outputPath = Export-CollectorResult -OutputDirectory $OutputDirectory -FileName 'scheduled-tasks.json' -Data $result -Depth 6
    Write-Output $outputPath
}

Invoke-Main
