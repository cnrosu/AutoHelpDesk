<#!
.SYNOPSIS
    Collects a comprehensive hardware and software snapshot via msinfo32.exe and
    normalizes the output into structured JSON tables.
#>
[CmdletBinding()]
param(
    [Parameter()]
    [string]$OutputDirectory = (Join-Path -Path (Split-Path -Parent $PSCommandPath) -ChildPath '..\output')
)

. (Join-Path -Path $PSScriptRoot -ChildPath '..\CollectorCommon.ps1')

$ErrorActionPreference = 'Stop'

$script:reportTimeoutSec = 420

function Get-Msinfo32ExePath {
    if ($env:PROCESSOR_ARCHITEW6432) {
        $candidate = Join-Path $env:WINDIR 'Sysnative\msinfo32.exe'
        if (Test-Path -LiteralPath $candidate) { return $candidate }
    }

    return Join-Path $env:WINDIR 'System32\msinfo32.exe'
}

function Stop-Msinfo32Process {
    try {
        foreach ($process in [System.Diagnostics.Process]::GetProcessesByName('msinfo32')) {
            try { $process.Kill() } catch {}
            try { $null = $process.WaitForExit(1500) } catch {}
            try { $process.Dispose() } catch {}
        }
    } catch {}
}

function Invoke-Msinfo32Report {
    param(
        [Parameter(Mandatory)][string]$OutputPath,
        [int]$TimeoutSeconds = $script:reportTimeoutSec
    )

    $exePath = Get-Msinfo32ExePath
    if (-not (Test-Path -LiteralPath $exePath)) {
        throw "msinfo32.exe not found at '$exePath'."
    }

    $directory = [System.IO.Path]::GetDirectoryName($OutputPath)
    if ($directory -and -not (Test-Path -LiteralPath $directory)) {
        [System.IO.Directory]::CreateDirectory($directory) | Out-Null
    }

    if (Test-Path -LiteralPath $OutputPath) {
        try { Remove-Item -LiteralPath $OutputPath -Force -ErrorAction Stop } catch {}
    }

    Stop-Msinfo32Process

    $startInfo = [System.Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $exePath
    $startInfo.Arguments = "/report `"$OutputPath`""
    $startInfo.CreateNoWindow = $true
    $startInfo.UseShellExecute = $false
    $startInfo.WindowStyle = [System.Diagnostics.ProcessWindowStyle]::Hidden

    $process = [System.Diagnostics.Process]::Start($startInfo)
    if (-not $process) {
        throw 'Failed to launch msinfo32.exe.'
    }

    try {
        $milliseconds = [Math]::Max(1000, $TimeoutSeconds * 1000)
        $null = $process.WaitForExit($milliseconds)
        if (-not $process.HasExited) {
            try { $process.Kill() } catch {}
            $null = $process.WaitForExit(1500)
        }
    } finally {
        try { $process.Dispose() } catch {}
    }

    Start-Sleep -Milliseconds 1200

    $deadline = (Get-Date).AddSeconds(5)
    while (-not (Test-Path -LiteralPath $OutputPath) -and (Get-Date) -lt $deadline) {
        Start-Sleep -Milliseconds 150
    }

    if (-not (Test-Path -LiteralPath $OutputPath)) {
        throw "msinfo32.exe completed but did not create the report at '$OutputPath'."
    }
}

function ConvertTo-MsinfoIndexKey {
    param([string]$Name)

    if ([string]::IsNullOrWhiteSpace($Name)) { return $null }
    $normalized = $Name.Trim().ToLowerInvariant()
    if (-not $normalized) { return $null }

    $normalized = [System.Text.RegularExpressions.Regex]::Replace($normalized, '[^a-z0-9]+', '-',
        [System.Text.RegularExpressions.RegexOptions]::Compiled)
    $normalized = $normalized.Trim('-')
    if (-not $normalized) { return $null }
    return $normalized
}

function Add-MsinfoIndexEntry {
    param(
        [Parameter(Mandatory)][hashtable]$Index,
        [string]$Key,
        [string]$SectionName
    )

    if (-not $Index -or [string]::IsNullOrWhiteSpace($Key) -or [string]::IsNullOrWhiteSpace($SectionName)) { return }

    if ($Index.ContainsKey($Key)) {
        $existing = @($Index[$Key])
        if (-not ($existing -contains $SectionName)) {
            $Index[$Key] = $existing + ,$SectionName
        }
    } else {
        $Index[$Key] = @($SectionName)
    }
}

function Split-TsvTokens {
    param([Parameter(Mandatory)][string]$Line)

    $tab = [char]9
    $tokens = $Line.Split($tab)
    $list = New-Object System.Collections.Generic.List[string]
    foreach ($token in $tokens) {
        $list.Add($token.Trim()) | Out-Null
    }

    for ($i = $list.Count - 1; $i -ge 0; $i--) {
        if ([string]::IsNullOrWhiteSpace($list[$i])) { $list.RemoveAt($i) } else { break }
    }

    return ,$list
}

function Parse-MsinfoReport {
    param([Parameter(Mandatory)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) {
        throw "msinfo32 report not found at '$Path'."
    }

    $result = [ordered]@{}
    $headerPattern = [System.Text.RegularExpressions.Regex]::new('^\[(?<name>.+?)\]\s*$',
        [System.Text.RegularExpressions.RegexOptions]::Compiled)

    $reader = [System.IO.StreamReader]::new($Path, [System.Text.Encoding]::Unicode, $true)
    try {
        $pending = $null
        while ($true) {
            $line = if ($pending -ne $null) { $value = $pending; $pending = $null; $value } else { $reader.ReadLine() }
            if ($null -eq $line) { break }

            $trimmed = $line.Trim()
            if ([string]::IsNullOrWhiteSpace($trimmed)) { continue }

            $match = $headerPattern.Match($trimmed)
            if (-not $match.Success) { continue }

            $sectionName = $match.Groups['name'].Value
            if (-not $sectionName) { continue }

            $next = $null
            while ($true) {
                $next = $reader.ReadLine()
                if ($null -eq $next) { break }
                if (-not [string]::IsNullOrWhiteSpace($next)) { break }
            }

            if ($null -eq $next) {
                $result[$sectionName] = [pscustomobject]@{ Keys = @(); Values = @() }
                break
            }

            $nextTrim = $next.Trim()
            if ($headerPattern.IsMatch($nextTrim)) {
                $result[$sectionName] = [pscustomobject]@{ Keys = @(); Values = @() }
                $pending = $next
                continue
            }

            $headers = Split-TsvTokens -Line $next
            $headerCount = $headers.Count
            if ($headerCount -eq 0) {
                $result[$sectionName] = [pscustomobject]@{ Keys = @(); Values = @() }
                continue
            }

            $rows = New-Object System.Collections.Generic.List[object]

            while ($true) {
                $rowLine = $reader.ReadLine()
                if ($null -eq $rowLine) { break }

                $rowTrim = $rowLine.Trim()
                if ([string]::IsNullOrWhiteSpace($rowTrim)) { break }
                if ($headerPattern.IsMatch($rowTrim)) { $pending = $rowLine; break }

                $values = Split-TsvTokens -Line $rowLine
                $array = New-Object string[] ($headerCount)
                for ($i = 0; $i -lt $headerCount; $i++) {
                    $array[$i] = if ($i -lt $values.Count) { $values[$i] } else { $null }
                }
                $rows.Add($array) | Out-Null
            }

            $keysArray = New-Object string[] ($headerCount)
            for ($i = 0; $i -lt $headerCount; $i++) { $keysArray[$i] = $headers[$i] }

            $result[$sectionName] = [pscustomobject]@{ Keys = $keysArray; Values = $rows }
        }
    } finally {
        $reader.Dispose()
    }

    return [pscustomobject]$result
}

function ConvertTo-MsinfoTable {
    param(
        [Parameter(Mandatory)][string]$SectionName,
        [string[]]$Keys,
        [System.Collections.IEnumerable]$Rows
    )

    $keysArray = @()
    if ($Keys) {
        $keysArray = @($Keys | ForEach-Object { if ($_ -ne $null) { [string]$_ } else { '' } })
    }

    $rowObjects = New-Object System.Collections.Generic.List[pscustomobject]
    if ($Rows) {
        foreach ($row in $Rows) {
            if (-not $row) { continue }

            $ordered = [ordered]@{}
            for ($i = 0; $i -lt $keysArray.Count; $i++) {
                $header = $keysArray[$i]
                $value = $null
                if ($row -is [System.Collections.IList] -and $row.Count -gt $i) {
                    $value = $row[$i]
                } elseif ($row -is [object[]] -and $row.Length -gt $i) {
                    $value = $row[$i]
                }

                if ($null -ne $value -and -not ($value -is [string])) {
                    $value = [string]$value
                }

                if ($header) {
                    $ordered[$header] = if ([string]::IsNullOrEmpty($value)) { $null } else { $value }

                    $alias = ($header -replace '[^A-Za-z0-9]', '')
                    if ($alias -and -not $ordered.Contains($alias)) {
                        $ordered[$alias] = $ordered[$header]
                    }
                }
            }

            $rowObjects.Add([pscustomobject]$ordered) | Out-Null
        }
    }

    return [pscustomobject]@{
        Name     = $SectionName
        Keys     = $keysArray
        Rows     = $rowObjects.ToArray()
        RowCount = $rowObjects.Count
    }
}

function ConvertTo-MsinfoPayload {
    param(
        [Parameter(Mandatory)]$RawSections,
        [double]$DurationSeconds
    )

    $sections = [ordered]@{}
    $index = [ordered]@{}

    foreach ($property in $RawSections.PSObject.Properties) {
        if (-not $property -or -not $property.Name) { continue }
        $name = [string]$property.Name
        $value = $property.Value
        $keys = $null
        $rows = $null
        if ($value -and $value.PSObject.Properties['Keys']) { $keys = $value.Keys }
        if ($value -and $value.PSObject.Properties['Values']) { $rows = $value.Values }

        $table = ConvertTo-MsinfoTable -SectionName $name -Keys $keys -Rows $rows
        $sections[$name] = $table

        $fullKey = ConvertTo-MsinfoIndexKey -Name $name
        Add-MsinfoIndexEntry -Index $index -Key $fullKey -SectionName $name

        $segments = $name -split '[\\/]'
        foreach ($segment in $segments) {
            $segmentKey = ConvertTo-MsinfoIndexKey -Name $segment
            Add-MsinfoIndexEntry -Index $index -Key $segmentKey -SectionName $name
        }
    }

    return [ordered]@{
        Source     = 'msinfo32'
        Version    = 1
        Sections   = $sections
        Index      = $index
        Diagnostics = [ordered]@{
            SectionCount    = $sections.Count
            DurationSeconds = [Math]::Round($DurationSeconds, 3)
        }
    }
}

function Invoke-Main {
    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    $reportPath = Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath (([guid]::NewGuid()).ToString() + '.txt')
    $payload = $null
    $errors = New-Object System.Collections.Generic.List[string]

    try {
        Invoke-Msinfo32Report -OutputPath $reportPath
        $rawSections = Parse-MsinfoReport -Path $reportPath
        $payload = ConvertTo-MsinfoPayload -RawSections $rawSections -DurationSeconds $stopwatch.Elapsed.TotalSeconds
    } catch {
        $message = $_.Exception.Message
        if ($_.InvocationInfo) {
            $message += "`nAt: " + $_.InvocationInfo.PositionMessage
        }
        $errors.Add($message) | Out-Null
    } finally {
        $stopwatch.Stop()
        if (Test-Path -LiteralPath $reportPath) {
            try { Remove-Item -LiteralPath $reportPath -Force } catch {}
        }
    }

    if (-not $payload) {
        $payload = [ordered]@{
            Source  = 'msinfo32'
            Version = 1
            Sections = @{}
            Index    = @{}
            Diagnostics = [ordered]@{
                SectionCount    = 0
                DurationSeconds = [Math]::Round($stopwatch.Elapsed.TotalSeconds, 3)
            }
        }
    }

    if ($errors.Count -gt 0) {
        $payload['Errors'] = $errors.ToArray()
    }

    $result = New-CollectorMetadata -Payload $payload
    $outputPath = Export-CollectorResult -OutputDirectory $OutputDirectory -FileName 'msinfo32.json' -Data $result -Depth 6
    Write-Output $outputPath
}

Invoke-Main
