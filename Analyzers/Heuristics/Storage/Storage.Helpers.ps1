# Structured remediation steps derived from the legacy block:
# - The heading becomes a text step that summarizes when to use the playbook.
# - The "Checks" section turns into a code step listing the discovery commands.
# - The bullet list under "Fix" is captured as a text step with newline-separated guidance.
# - The cleanup script stays a code step with comments preserved.
$script:StorageHealthAndSpaceRemediation = @'
[
  {
    "type": "text",
    "title": "Storage disk health and free space recovery",
    "content": "Run these checks and fixes to address disk health warnings and low free space."
  },
  {
    "type": "code",
    "lang": "powershell",
    "content": "Get-PhysicalDisk | Select FriendlyName, MediaType, HealthStatus, OperationalStatus, Usage\nGet-Volume | Sort SizeRemaining | Format-Table DriveLetter, FileSystemLabel, SizeRemaining, Size, AllocationUnitSize -Auto"
  },
  {
    "type": "text",
    "title": "Fix",
    "content": "- Degraded disks: replace the disk; if using a USB/NVMe enclosure, update the bridge firmware.\n- SMART unavailable: re-run as admin and ensure NVMe/RAID vendor drivers are installed.\n- Low space (automatable): run the cleanup script."
  },
  {
    "type": "code",
    "lang": "powershell",
    "content": "# Clean component store\nDism.exe /Online /Cleanup-Image /StartComponentCleanup /ResetBase\n# Temp + recycle bin\nRemove-Item \"$env:TEMP\\*\" -Recurse -Force -ErrorAction SilentlyContinue\nClear-RecycleBin -Force"
  }
]
'@

function ConvertTo-StorageArray {
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

function Get-StorageWearLabel {
    param(
        $Entry
    )

    if ($null -eq $Entry) { return 'Unknown disk' }

    if ($Entry.PSObject.Properties['FriendlyName'] -and -not [string]::IsNullOrWhiteSpace([string]$Entry.FriendlyName)) {
        return [string]$Entry.FriendlyName
    }
    if ($Entry.PSObject.Properties['SerialNumber'] -and -not [string]::IsNullOrWhiteSpace([string]$Entry.SerialNumber)) {
        return "Serial $($Entry.SerialNumber)"
    }
    if ($Entry.PSObject.Properties['DeviceId']) {
        return "Disk $($Entry.DeviceId)"
    }

    return 'Unknown disk'
}

function Format-StorageWearDetails {
    param(
        [Parameter(Mandatory)]
        $Entry,
        [double]$Wear
    )

    $parts = @()
    $parts += ("Wear used {0}%" -f ([math]::Round($Wear, 1)))

    $remaining = 100 - $Wear
    if ($remaining -ge 0) {
        $parts += ("~{0}% life remaining" -f ([math]::Round([math]::Max($remaining, 0), 1)))
    }

    if ($Entry.PSObject.Properties['MediaType'] -and -not [string]::IsNullOrWhiteSpace([string]$Entry.MediaType)) {
        $parts += ("Media type: {0}" -f $Entry.MediaType)
    }

    if ($Entry.PSObject.Properties['SerialNumber'] -and -not [string]::IsNullOrWhiteSpace([string]$Entry.SerialNumber)) {
        $parts += ("Serial {0}" -f $Entry.SerialNumber)
    }

    if ($Entry.PSObject.Properties['DeviceId']) {
        $parts += ("DeviceId {0}" -f $Entry.DeviceId)
    }

    if ($Entry.PSObject.Properties['TemperatureCelsius']) {
        $temperature = $Entry.TemperatureCelsius
        if ($temperature -is [double] -or $temperature -is [single] -or $temperature -is [int]) {
            $parts += ("Temperature {0}°C" -f ([math]::Round([double]$temperature, 1)))
        } elseif ($temperature) {
            $parts += ("Temperature {0}" -f $temperature)
        }
    }

    return ($parts -join '; ')
}

function Get-StoragePreview {
    param(
        [string]$Text,
        [int]$MaxLines = 12
    )

    if (-not $Text) { return $null }

    $lines = [regex]::Split($Text, '\r?\n')
    $preview = $lines | Where-Object { $_ -and $_.Trim() } | Select-Object -First $MaxLines
    if (-not $preview -or $preview.Count -eq 0) {
        $preview = $lines | Select-Object -First $MaxLines
    }

    if (-not $preview -or $preview.Count -eq 0) { return $null }

    return ($preview -join "`n").TrimEnd()
}
