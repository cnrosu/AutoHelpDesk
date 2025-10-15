<# msinfo.ps1 (PS 5.1)
   - Runs msinfo32 silently to a text report
   - Parses into { section: { keys:[...], values:[[...]] } }
   - Writes JSON to %TEMP%\msinfo_report.json (UTF-8)
#>

using namespace System
using namespace System.Text
using namespace System.Collections.Generic
using namespace System.Diagnostics
using namespace System.IO

$ErrorActionPreference = 'Stop'

# ---- Config ----
$ReportPath = Join-Path $env:TEMP 'msinfo_report.txt'
$JsonPath   = Join-Path $env:TEMP 'msinfo_report.json'
[int]$TimeoutSec = 420

# ---- Helpers ----
function Get-Msinfo32ExePath {
    if ($env:PROCESSOR_ARCHITEW6432) {
        $p = Join-Path $env:WINDIR 'Sysnative\msinfo32.exe'
        if (Test-Path $p) { return $p }
    }
    Join-Path $env:WINDIR 'System32\msinfo32.exe'
}

function Stop-Msinfo32 {
    try {
        foreach ($p in [Process]::GetProcessesByName('msinfo32')) {
            try { $p.Kill(); $null = $p.WaitForExit(1500) } catch {}
            try { $p.Dispose() } catch {}
        }
    } catch {}
}

function Run-Msinfo32Report([string]$OutPath, [int]$TimeoutSec) {
    $exe = Get-Msinfo32ExePath
    if (-not (Test-Path $exe)) { throw "msinfo32.exe not found at $exe" }

    # ensure directory exists
    $dir = [Path]::GetDirectoryName($OutPath)
    if ($dir -and -not (Test-Path $dir)) { [Directory]::CreateDirectory($dir) | Out-Null }

    # clean old file
    if (Test-Path $OutPath) { try { Remove-Item -LiteralPath $OutPath -Force -ErrorAction Stop } catch {} }

    # kill any existing (single-instance app)
    Stop-Msinfo32

    # start process (pure .NET)
    $psi = [ProcessStartInfo]::new()
    $psi.FileName = $exe
    $psi.Arguments = "/report `"$OutPath`""
    $psi.CreateNoWindow = $true
    $psi.UseShellExecute = $false
    $psi.WindowStyle = [ProcessWindowStyle]::Hidden

    $proc = [Process]::Start($psi)
    if (-not $proc) { throw "Failed to launch msinfo32.exe" }

    try {
        $ms = [Math]::Max(1000, $TimeoutSec * 1000)
        $null = $proc.WaitForExit($ms)
        if (-not $proc.HasExited) {
            try { $proc.Kill() } catch {}
            $null = $proc.WaitForExit(1500)
        }
    } finally {
        try { $proc.Dispose() } catch {}
    }

    Start-Sleep -Milliseconds 1200  # allow file flush

    # lightweight poll in case the file appears just-after exit
    $deadline = (Get-Date).AddSeconds(5)
    while (-not (Test-Path $OutPath) -and (Get-Date) -lt $deadline) { Start-Sleep -Milliseconds 150 }

    if (-not (Test-Path $OutPath)) {
        throw "msinfo32 did not produce the report at $OutPath"
    }
}

# === Only change requested: bullet-proof literal TAB splitter ===
function Split-TsvTokens {
    param([Parameter(Mandatory)][string]$Line)

    $tab = [char]9  # literal TAB
    $raw = $Line.Split($tab)  # no regex, no surprises
    $out = New-Object 'System.Collections.Generic.List[string]'
    foreach ($t in $raw) { $out.Add($t.Trim()) }

    # Trim trailing empties (caused by dangling TABs)
    for ($i = $out.Count - 1; $i -ge 0; $i--) {
        if ([string]::IsNullOrWhiteSpace($out[$i])) { $out.RemoveAt($i) } else { break }
    }
    ,$out
}

function Parse-MsinfoReportAsMatrix([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path)) { throw "File not found: $Path" }

    $model = @{}
    $sectionHeader = [regex]::new('^\[(?<name>.+?)\]\s*$')

    # msinfo text export is UTF-16 LE with BOM
    $sr = [StreamReader]::new($Path, [Encoding]::Unicode, $true)
    try {
        $pushBack = $null
        while ($true) {
            $line = if ($pushBack -ne $null) { $tmp=$pushBack; $pushBack=$null; $tmp } else { $sr.ReadLine() }
            if ($line -eq $null) { break }
            $trim = $line.Trim()
            if ([string]::IsNullOrWhiteSpace($trim)) { continue }

            $m = $sectionHeader.Match($trim)
            if (-not $m.Success) { continue }

            $sectionName = $m.Groups['name'].Value

            # consume blank lines → TSV header
            $next = $null
            while ($true) {
                $next = $sr.ReadLine()
                if ($next -eq $null) { break }
                if (-not [string]::IsNullOrWhiteSpace($next)) { break }
            }
            if ($next -eq $null) {
                $model[$sectionName] = [pscustomobject]@{ keys=@(); values=@() }
                break
            }

            if ($sectionHeader.IsMatch($next.Trim())) {
                $model[$sectionName] = [pscustomobject]@{ keys=@(); values=@() }
                $pushBack = $next
                continue
            }

            $headers = Split-TsvTokens $next
            $hCount  = $headers.Count
            if ($hCount -eq 0) {
                $model[$sectionName] = [pscustomobject]@{ keys=@(); values=@() }
                continue
            }

            $rows = New-Object 'System.Collections.Generic.List[object]'  # each row: string[]

            while ($true) {
                $rowLine = $sr.ReadLine()
                if ($rowLine -eq $null) { break }
                $rt = $rowLine.Trim()
                if ([string]::IsNullOrWhiteSpace($rt)) { break }
                if ($sectionHeader.IsMatch($rt)) { $pushBack = $rowLine; break }

                $vals = Split-TsvTokens $rowLine
                $arr = New-Object string[] ($hCount)
                for ($i=0; $i -lt $hCount; $i++) { $arr[$i] = if ($i -lt $vals.Count) { $vals[$i] } else { $null } }
                $rows.Add($arr)
            }

            $keysArray = New-Object string[] ($hCount)
            for ($i=0; $i -lt $hCount; $i++) { $keysArray[$i] = $headers[$i] }
            $model[$sectionName] = [pscustomobject]@{ keys=$keysArray; values=$rows }
        }
    } finally {
        $sr.Close(); $sr.Dispose()
    }

    $ordered = [ordered]@{}
    foreach ($k in $model.Keys) { $ordered[$k] = $model[$k] }
    [pscustomobject]$ordered
}

# ---- Main ----
try {
    Run-Msinfo32Report -OutPath $ReportPath -TimeoutSec $TimeoutSec

    $obj  = Parse-MsinfoReportAsMatrix -Path $ReportPath
    $json = $obj | ConvertTo-Json -Depth 6

    # Write JSON (pure .NET)
    [File]::WriteAllText($JsonPath, $json, [UTF8Encoding]::new($false))

    Write-Host "JSON written: $JsonPath"
    exit 0
}
catch {
    $msg = ($_ | Select-Object -Expand Exception).Message
    if ($_.InvocationInfo) { $msg += "`nAt: " + $_.InvocationInfo.PositionMessage }
    try {
        $ms = Get-Msinfo32ExePath
        $msg += "`nmsinfo32 path: $ms"
    } catch { $msg += "`nmsinfo32 path: (not found)" }
    $msg += "`nTEMP: $env:TEMP"
    Write-Error $msg
    exit 1
}
