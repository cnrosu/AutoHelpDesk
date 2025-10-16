function Get-PrintingPlatformInfo {
    param($Context)

    $isWindowsServer = $null
    $msinfoIdentity = Get-MsinfoSystemIdentity -Context $Context
    if ($msinfoIdentity -and $msinfoIdentity.PSObject.Properties['OSName']) {
        $caption = [string]$msinfoIdentity.OSName
        if ($caption) {
            $isWindowsServer = ($caption -match '(?i)windows\s+server')
        }
    }

    $isWorkstation = $null
    if ($isWindowsServer -eq $true) { $isWorkstation = $false }
    elseif ($isWindowsServer -eq $false) { $isWorkstation = $true }

    return [pscustomobject]@{
        IsWindowsServer = $isWindowsServer
        IsWorkstation   = $isWorkstation
    }
}
