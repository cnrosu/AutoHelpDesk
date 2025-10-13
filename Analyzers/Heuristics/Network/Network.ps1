<#!
.SYNOPSIS
    Network diagnostics heuristics covering connectivity, DNS, proxy, and Outlook health.
#>

$analyzersRoot = Split-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -Parent
. (Join-Path -Path $analyzersRoot -ChildPath 'AnalyzerCommon.ps1')

$vpnAnalyzerPath = Join-Path -Path $analyzersRoot -ChildPath 'Network/Analyze-Vpn.ps1'
if (Test-Path -LiteralPath $vpnAnalyzerPath) {
    . $vpnAnalyzerPath
}

$modulePaths = @(
    'Modules/Network.Helpers.ps1'
    'Modules/Network.Converters.ps1'
    'Modules/Network.Dhcp.ps1'
    'Modules/Network.Wlan.ps1'
    'Modules/Network.Heuristics.ps1'
)

foreach ($modulePath in $modulePaths) {
    $resolved = Join-Path -Path $PSScriptRoot -ChildPath $modulePath
    if (-not (Test-Path -LiteralPath $resolved)) {
        throw ("Network module missing: {0}" -f $modulePath)
    }
    . $resolved
}
