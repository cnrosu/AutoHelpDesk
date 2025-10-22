function ConvertTo-PrintingArray {
    param($Value)

    if ($null -eq $Value) { return @() }
    if ($Value -is [string]) { return @($Value) }
    if ($Value -is [System.Collections.IEnumerable] -and -not ($Value -is [hashtable])) {
        $itemsList = New-Object System.Collections.Generic.List[object]
        foreach ($item in $Value) { $itemsList.Add($item) | Out-Null }
        return $itemsList.ToArray()
    }
    return @($Value)
}

function Normalize-PrintingServiceState {
    param([string]$Value)

    if (-not $Value) { return 'unknown' }
    $trimmed = $Value.Trim()
    if (-not $trimmed) { return 'unknown' }

    $lower = $trimmed.ToLowerInvariant()
    if ($lower -like 'run*') { return 'running' }
    if ($lower -like 'stop*') { return 'stopped' }
    return 'other'
}

function Get-PrintingQueueRemediation {
    if ($script:PrintingQueueRemediation) {
        return $script:PrintingQueueRemediation
    }

    $steps = @(
        @{
            type    = 'text'
            title   = 'Common quick fixes'
            content = 'Restart the Print Spooler, clear stale jobs, and move printers onto stable ports and drivers before retrying documents.'
        }
        @{
            type    = 'code'
            title   = 'Restart spooler & clear stale jobs'
            lang    = 'powershell'
            content = @"
Stop-Service Spooler
Remove-Item "C:\Windows\System32\spool\PRINTERS\*" -Force -ErrorAction SilentlyContinue
Start-Service Spooler
"@.Trim()
        }
        @{
            type    = 'text'
            content = 'Replace WSD printer ports with Standard TCP/IP ports.'
        }
        @{
            type    = 'text'
            content = 'For troublesome printers, prefer Type 4 Class Drivers or vendor-signed v4 packages.'
        }
        @{
            type    = 'note'
            content = 'Update the sample printer name before running the command to set a new default.'
        }
        @{
            type    = 'code'
            title   = 'Set a healthy default printer'
            lang    = 'powershell'
            content = "(Get-Printer | Where-Object Name -eq 'HP-01').IsDefault -or (Set-Printer -Name 'HP-01' -IsDefault `$true)"
        }
        @{
            type    = 'text'
            content = 'Print a test page to confirm the queue is healthy.'
        }
    )

    $script:PrintingQueueRemediation = $steps | ConvertTo-Json -Depth 5
    return $script:PrintingQueueRemediation
}
