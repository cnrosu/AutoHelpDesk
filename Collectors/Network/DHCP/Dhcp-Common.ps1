<#!
.SYNOPSIS
    Shared helper functions for DHCP-focused collectors.
#>

function ConvertTo-Iso8601String {
    param([object]$Value)

    if ($null -eq $Value) { return $null }

    try {
        $dt = [datetime]::Parse($Value.ToString())
        return $dt.ToString('o')
    } catch {
        try {
            if ($Value -is [datetime]) { return $Value.ToString('o') }
        } catch { }
    }

    return $null
}

function Get-DhcpAdapterConfigurations {
    try {
        $instances = Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration -Filter "IPEnabled = True" -ErrorAction Stop
    } catch {
        return @([pscustomobject]@{
            Source = 'Get-CimInstance Win32_NetworkAdapterConfiguration'
            Error  = $_.Exception.Message
        })
    }

    $results = [System.Collections.Generic.List[pscustomobject]]::new()
    foreach ($instance in $instances) {
        $results.Add([pscustomobject]@{
            Description            = $instance.Description
            Caption                 = $instance.Caption
            InterfaceIndex          = $instance.InterfaceIndex
            Index                   = $instance.Index
            MACAddress              = $instance.MACAddress
            DHCPEnabled             = [bool]$instance.DHCPEnabled
            DHCPServer              = [string]$instance.DHCPServer
            DHCPLeaseObtained       = ConvertTo-Iso8601String -Value $instance.DHCPLeaseObtained
            DHCPLeaseExpires        = ConvertTo-Iso8601String -Value $instance.DHCPLeaseExpires
            IPAddress               = @($instance.IPAddress)
            IPSubnet                = @($instance.IPSubnet)
            DefaultIPGateway        = @($instance.DefaultIPGateway)
            DNSServerSearchOrder    = @($instance.DNSServerSearchOrder)
            WinsPrimaryServer       = [string]$instance.WINSPrimaryServer
            WinsSecondaryServer     = [string]$instance.WINSSecondaryServer
            ServiceName             = [string]$instance.ServiceName
            SettingID               = [string]$instance.SettingID
        })
    }

    return $results.ToArray()
}

function Get-DhcpIpconfigAll {
    $result = Invoke-IpconfigAll

    if ($null -eq $result) { return '' }

    if ($result -is [psobject]) {
        if ($result.PSObject.Properties.Name -contains 'Error') {
            $message = $result.Error
            if (-not $message) { $message = 'Unknown error' }
            return "ipconfig.exe /all failed: $message"
        }

        if ($result.PSObject.Properties.Name -contains 'Raw') {
            return ([string]$result.Raw).TrimEnd("`r", "`n")
        }

        if ($result.PSObject.Properties.Name -contains 'Lines') {
            $joined = [string]::Join([Environment]::NewLine, @($result.Lines))
            return $joined.TrimEnd("`r", "`n")
        }
    }

    if ($result -is [string]) {
        return $result.TrimEnd("`r", "`n")
    }

    if ($result -is [System.Collections.IEnumerable]) {
        $joined = [string]::Join([Environment]::NewLine, $result)
        return $joined.TrimEnd("`r", "`n")
    }

    return ([string]$result).TrimEnd("`r", "`n")
}

function Get-DhcpClientEvents {
    param(
        [int[]]$EventIds = @(),
        [int]$MaxEvents = 200
    )

    try {
        $filter = @{ LogName = 'System'; ProviderName = 'Microsoft-Windows-Dhcp-Client' }
        if ($EventIds -and $EventIds.Count -gt 0) {
            $filter['Id'] = $EventIds
        }
        $events = Get-WinEvent -FilterHashtable $filter -MaxEvents $MaxEvents -ErrorAction Stop
    } catch {
        return @([pscustomobject]@{
            Source = 'Get-WinEvent Microsoft-Windows-Dhcp-Client'
            Error  = $_.Exception.Message
        })
    }

    $results = [System.Collections.Generic.List[pscustomobject]]::new()
    foreach ($event in $events) {
        $results.Add([pscustomobject]@{
            Id           = $event.Id
            ProviderName = $event.ProviderName
            Level        = $event.LevelDisplayName
            RecordId     = $event.RecordId
            TimeCreated  = if ($event.TimeCreated) { $event.TimeCreated.ToString('o') } else { $null }
            Message      = $event.Message
        })
    }

    return $results.ToArray()
}

function New-DhcpBasePayload {
    param(
        [switch]$IncludeEvents,
        [int[]]$EventIds = @(),
        [int]$MaxEvents = 200
    )

    $payload = [ordered]@{
        CapturedAt            = (Get-Date).ToString('o')
        AdapterConfigurations = Get-DhcpAdapterConfigurations
        IpconfigText          = Get-DhcpIpconfigAll
    }

    if ($IncludeEvents) {
        $payload['Events'] = Get-DhcpClientEvents -EventIds $EventIds -MaxEvents $MaxEvents
    }

    return $payload
}
