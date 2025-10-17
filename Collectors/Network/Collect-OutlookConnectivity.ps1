<#!
.SYNOPSIS
    Collects Outlook connectivity diagnostics including HTTPS tests, OST inventory, and Autodiscover SCP entries.
#>
[CmdletBinding()]
param(
    [Parameter()]
    [string]$OutputDirectory = (Join-Path -Path (Split-Path -Parent $PSCommandPath) -ChildPath '..\\output')
)

. (Join-Path -Path $PSScriptRoot -ChildPath '..\\CollectorCommon.ps1')

function Test-Outlook443 {
    param([string]$Target = 'outlook.office365.com')
    try {
        return Test-NetConnection -ComputerName $Target -Port 443 -WarningAction SilentlyContinue
    } catch {
        return [PSCustomObject]@{
            Target = $Target
            Error  = $_.Exception.Message
        }
    }
}

function Get-OstInventory {
    try {
        $profilesPath = Join-Path -Path $env:LOCALAPPDATA -ChildPath 'Microsoft\Outlook'
        if (Test-Path -Path $profilesPath) {
            return Get-ChildItem -Path $profilesPath -Filter '*.ost' -Recurse -ErrorAction Stop | Select-Object Name, FullName, Length, LastWriteTime
        }
        return @()
    } catch {
        return [PSCustomObject]@{
            Source = 'OSTInventory'
            Error  = $_.Exception.Message
        }
    }
}

function Get-RegistryAutodiscoverSettings {
    try {
        $regPath = 'HKLM:\SOFTWARE\Microsoft\Office\16.0\Outlook\AutoDiscover'
        if (Test-Path -Path $regPath) {
            return Get-ItemProperty -Path $regPath | Select-Object * -ExcludeProperty PS*, CIM*, PSEdition
        }
    } catch {
        return [PSCustomObject]@{
            Source = 'AutodiscoverSCPRegistry'
            Error  = $_.Exception.Message
        }
    }

    return $null
}

function Get-DirectoryAutodiscoverScp {
    $cs = Get-CollectorComputerSystem
    if (Test-CollectorResultHasError -Value $cs) { return @() }
    if (-not ($cs -and $cs.PartOfDomain -eq $true)) { return @() }

    try {
        $null = [System.Reflection.Assembly]::Load('System.DirectoryServices')
    } catch {
    }

    try {
        $root = [ADSI]'LDAP://RootDSE'
        $configContext = $root.configurationNamingContext
        if (-not $configContext) { return @() }

        $searchRoot = "LDAP://$configContext"
        $searcher = New-Object System.DirectoryServices.DirectorySearcher
        $searcher.SearchRoot = $searchRoot
        $searcher.Filter = '(&(objectClass=serviceConnectionPoint)(keywords=77378F46-2C66-4aa9-A6A6-3E7A48B19596))'
        $null = $searcher.PropertiesToLoad.Clear()
        foreach ($property in @('serviceBindingInformation', 'keywords', 'name')) {
            $null = $searcher.PropertiesToLoad.Add($property)
        }
        $searcher.PageSize = 200

        $results = $searcher.FindAll()
        if (-not $results) { return @() }

        $entries = New-Object System.Collections.Generic.List[pscustomobject]
        foreach ($result in $results) {
            if (-not $result) { continue }
            $properties = $result.Properties
            $binding = $null
            if ($properties['servicebindinginformation'] -and $properties['servicebindinginformation'].Count -gt 0) {
                $binding = [string]$properties['servicebindinginformation'][0]
            }

            $keywords = @()
            if ($properties['keywords']) {
                $keywords = @($properties['keywords'] | ForEach-Object { [string]$_ })
            }

            $domain = $null
            $site = $null
            foreach ($keyword in $keywords) {
                if (-not $keyword) { continue }
                if (-not $domain -and $keyword -match '^(?i)Domain=(.+)$') {
                    $domain = $matches[1]
                    continue
                }
                if (-not $site -and $keyword -match '^(?i)Site=(.+)$') {
                    $site = $matches[1]
                }
            }

            $entries.Add([pscustomobject]@{
                Url      = $binding
                Keywords = $keywords
                Domain   = $domain
                Site     = $site
            }) | Out-Null
        }

        return $entries.ToArray()
    } catch {
        return @([pscustomobject]@{
            Source = 'AutodiscoverSCPDirectory'
            Error  = $_.Exception.Message
        })
    }
}

function Get-AutodiscoverScp {
    $registryData = Get-RegistryAutodiscoverSettings
    $directoryEntries = Get-DirectoryAutodiscoverScp

    if (-not $registryData -and (-not $directoryEntries -or $directoryEntries.Count -eq 0)) {
        return $null
    }

    return [pscustomobject]@{
        Registry  = $registryData
        Directory = $directoryEntries
    }
}

function Invoke-Main {
    $payload = [ordered]@{
        Connectivity = Test-Outlook443
        OstFiles     = Get-OstInventory
        Autodiscover = Get-AutodiscoverScp
    }

    $result = New-CollectorMetadata -Payload $payload
    $outputPath = Export-CollectorResult -OutputDirectory $OutputDirectory -FileName 'outlook-connectivity.json' -Data $result -Depth 6
    Write-Output $outputPath
}

Invoke-Main
