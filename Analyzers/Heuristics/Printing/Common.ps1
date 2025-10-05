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
