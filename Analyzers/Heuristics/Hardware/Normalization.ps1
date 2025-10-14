function Normalize-DriverStatus {
    param([string]$Value)

    if (-not $Value) { return 'unknown' }
    $lower = $Value.Trim().ToLowerInvariant()
    if (-not $lower) { return 'unknown' }

    if ($lower -eq 'ok' -or $lower -eq 'okay') { return 'ok' }
    if ($lower -match 'error|fail|problem|fault') { return 'error' }
    if ($lower -match 'degrad|warn|issue') { return 'degraded' }
    if ($lower -match 'unknown|n/a|na') { return 'unknown' }
    return 'other'
}

function Normalize-DriverState {
    param([string]$Value)

    if (-not $Value) { return 'unknown' }
    $lower = $Value.Trim().ToLowerInvariant()
    if (-not $lower) { return 'unknown' }

    if ($lower -like 'run*') { return 'running' }
    if ($lower -like 'stop*') { return 'stopped' }
    if ($lower -like 'start*pend*') { return 'pending' }
    if ($lower -like 'pause*') { return 'paused' }
    return 'other'
}

function Normalize-DriverStartMode {
    param([string]$Value)

    if (-not $Value) { return 'unknown' }
    $lower = $Value.Trim().ToLowerInvariant()
    if (-not $lower) { return 'unknown' }

    if ($lower -match 'boot') { return 'boot' }
    if ($lower -match 'system') { return 'system' }
    if ($lower -match 'auto') { return 'auto' }
    if ($lower -match 'manual') { return 'manual' }
    if ($lower -match 'disabled|disable') { return 'disabled' }
    return 'other'
}

function Normalize-DriverType {
    param([string]$Value)

    if (-not $Value) { return 'unknown' }
    $lower = $Value.Trim().ToLowerInvariant()
    if (-not $lower) { return 'unknown' }

    if ($lower -match 'kernel') { return 'kernel' }
    if ($lower -match 'file\\s*system') { return 'filesystem' }
    if ($lower -match 'filter') { return 'filter' }
    if ($lower -match 'driver') { return 'driver' }
    return 'other'
}

function Normalize-DriverErrorControl {
    param([string]$Value)

    if (-not $Value) { return 'unknown' }
    $lower = $Value.Trim().ToLowerInvariant()
    if (-not $lower) { return 'unknown' }

    if ($lower -match 'critical') { return 'critical' }
    if ($lower -match 'normal') { return 'normal' }
    if ($lower -match 'ignore') { return 'ignore' }
    return 'other'
}
