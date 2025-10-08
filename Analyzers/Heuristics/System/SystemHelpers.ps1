function Get-StartupCommandPath {
    param(
        [string]$Command
    )

    if ([string]::IsNullOrWhiteSpace($Command)) { return $null }

    $expanded = [System.Environment]::ExpandEnvironmentVariables($Command).Trim()
    if ([string]::IsNullOrWhiteSpace($expanded)) { return $null }

    if ($expanded.StartsWith('"')) {
        $closing = $expanded.IndexOf('"', 1)
        if ($closing -gt 1) {
            return $expanded.Substring(1, $closing - 1)
        }
    }

    $parts = $expanded -split '\s+', 2
    if ($parts.Count -gt 0 -and -not [string]::IsNullOrWhiteSpace($parts[0])) {
        return $parts[0]
    }

    return $expanded
}

function Test-IsMicrosoftStartupEntry {
    param(
        $Entry
    )

    if (-not $Entry) { return $false }

    $command = $null
    if ($Entry.PSObject.Properties['Command']) {
        $command = [string]$Entry.Command
    }

    if ($command) {
        $commandLower = $command.ToLowerInvariant().Trim('"')
        if ($commandLower -eq 'rundll32.exe' -or $commandLower -eq 'rundll32.exe,' -or $commandLower -eq 'explorer.exe') {
            return $true
        }
    }

    $path = Get-StartupCommandPath -Command $command
    if ($path) {
        $pathLower = $path.ToLowerInvariant()
        if ($pathLower -match '\\windows\\system32\\' -or $pathLower -match '^c:\\windows\\') {
            return $true
        }
        if ($pathLower -match '\\microsoft\\') {
            return $true
        }
    }

    foreach ($prop in @('Name', 'Description')) {
        if ($Entry.PSObject.Properties[$prop]) {
            $value = [string]$Entry.$prop
            if (-not [string]::IsNullOrWhiteSpace($value)) {
                $lower = $value.ToLowerInvariant()
                if ($lower -match 'microsoft' -or $lower -match 'windows defender' -or $lower -match 'onedrive') {
                    return $true
                }
            }
        }
    }

    return $false
}

function Get-SystemInfoTextFromPayload {
    param($Payload)

    if (-not $Payload) { return $null }
    if (-not $Payload.SystemInfoText) { return $null }
    if ($Payload.SystemInfoText -and $Payload.SystemInfoText.PSObject.Properties['Error'] -and $Payload.SystemInfoText.Error) {
        return $null
    }

    $text = $Payload.SystemInfoText
    if ($text -is [System.Collections.IEnumerable] -and -not ($text -is [string])) {
        $lines = foreach ($item in $text) { if ($item) { [string]$item } }
        return ($lines -join "`n")
    }

    return [string]$text
}

function Get-SystemInfoLines {
    param($Payload)

    $text = Get-SystemInfoTextFromPayload -Payload $Payload
    if (-not $text) { return @() }

    return $text -split "\r?\n"
}

function Get-SystemInfoValue {
    param(
        [string[]]$Lines,
        [string]$Label
    )

    if (-not $Lines -or -not $Label) { return $null }

    $pattern = '^(?i)\s*{0}\s*:\s*(?<value>.+)$' -f [regex]::Escape($Label)
    foreach ($line in $Lines) {
        if (-not $line) { continue }
        $match = [regex]::Match($line, $pattern)
        if ($match.Success) {
            $value = $match.Groups['value'].Value.Trim()
            if ($value) { return $value }
        }
    }

    return $null
}
