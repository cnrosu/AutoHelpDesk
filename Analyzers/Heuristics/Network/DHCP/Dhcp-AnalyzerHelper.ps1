<#!
.SYNOPSIS
    Ensures DHCP analyzer dependencies are loaded.
.DESCRIPTION
    Walks up from the DHCP analyzer directory to locate Modules/Common.psm1 and imports
    it if it is not already available so DHCP-specific helper functions exposed by the
    common module are ready for use.
#>

function Import-DhcpAnalyzerDependencies {
    param(
        [Parameter(Mandatory)]
        [string]$ScriptRoot
    )

    $commonModuleLoaded = Get-Module | Where-Object { $_.Path -and (Split-Path -Path $_.Path -Leaf) -eq 'Common.psm1' }

    if (-not $commonModuleLoaded) {
        $current = $ScriptRoot
        while ($current) {
            $candidate = Join-Path -Path $current -ChildPath 'Modules/Common.psm1'
            if (Test-Path -Path $candidate) {
                Import-Module -Name $candidate -Force
                $commonModuleLoaded = Get-Module | Where-Object { $_.Path -eq (Resolve-Path -Path $candidate) }
                break
            }

            $parent = Split-Path -Path $current -Parent
            if (-not $parent -or $parent -eq $current) { break }
            $current = $parent
        }
    }

    if (-not $commonModuleLoaded -and -not (Get-Command -Name 'Get-DhcpCollectorPayload' -ErrorAction SilentlyContinue)) {
        throw "Unable to locate Modules/Common.psm1 relative to '$ScriptRoot'."
    }
}

Import-DhcpAnalyzerDependencies -ScriptRoot $PSScriptRoot
