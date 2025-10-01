<#!
.SYNOPSIS
    Collects recent Application and System event log entries.
#>
[CmdletBinding()]
param(
    [Parameter()]
    [string]$OutputDirectory = (Join-Path -Path (Split-Path -Parent $PSCommandPath) -ChildPath '..\\output')
)

. (Join-Path -Path $PSScriptRoot -ChildPath '..\\CollectorCommon.ps1')

function Get-RecentEvents {
    param(
        [Parameter(Mandatory)]
        [string]$LogName,

        [int]$MaxEvents = 100
    )

    try {
        return Get-WinEvent -LogName $LogName -MaxEvents $MaxEvents -ErrorAction Stop | Select-Object TimeCreated, Id, LevelDisplayName, ProviderName, Message
    } catch {
        return [PSCustomObject]@{
            LogName = $LogName
            Error   = $_.Exception.Message
        }
    }
}

function Get-DnsClientTimeoutEvents {
    param(
        [datetime]$StartTime = (Get-Date).AddDays(-14),

        [int]$MaxEvents = 400
    )

    $filter = @{ LogName = 'Microsoft-Windows-DNS-Client/Operational'; Id = 1014 }
    if ($StartTime) { $filter['StartTime'] = $StartTime }

    try {
        $events = Get-WinEvent -FilterHashtable $filter -ErrorAction Stop | Sort-Object TimeCreated -Descending
        if ($MaxEvents -gt 0) {
            $events = $events | Select-Object -First $MaxEvents
        }
    } catch {
        return [PSCustomObject]@{
            LogName = 'Microsoft-Windows-DNS-Client/Operational'
            Error   = $_.Exception.Message
        }
    }

    $results = New-Object System.Collections.Generic.List[pscustomobject]
    foreach ($event in $events) {
        if (-not $event) { continue }

        $queryName = $null
        $serverAddress = $null

        try {
            $xml = [xml]$event.ToXml()
        } catch {
            $xml = $null
        }

        if ($xml -and $xml.Event -and $xml.Event.EventData) {
            foreach ($dataNode in $xml.Event.EventData.Data) {
                if (-not $dataNode) { continue }

                $nameAttr = $null
                if ($dataNode.PSObject.Properties['Name']) {
                    $nameAttr = [string]$dataNode.Name
                }

                $textValue = $null
                if ($dataNode.PSObject.Properties['#text']) {
                    $textValue = [string]$dataNode.'#text'
                } elseif ($dataNode.PSObject.Properties['InnerText']) {
                    $textValue = [string]$dataNode.InnerText
                } else {
                    $textValue = [string]$dataNode
                }

                if ($textValue) {
                    $textValue = $textValue.Trim()
                }

                if (-not $nameAttr) { continue }

                switch -Regex ($nameAttr) {
                    '^Query(Name)?$' {
                        if (-not $queryName -and $textValue) { $queryName = $textValue }
                        continue
                    }
                    '^Name$' {
                        if (-not $queryName -and $textValue) { $queryName = $textValue }
                        continue
                    }
                    'Server(Address|IP|IPAddress)?$' {
                        if (-not $serverAddress -and $textValue) { $serverAddress = $textValue }
                        continue
                    }
                }
            }
        }

        $messageSnippet = $null
        if ($event.Message) {
            $messageSnippet = [string]$event.Message
            if ($messageSnippet) {
                $messageSnippet = $messageSnippet.Trim()
                if ($messageSnippet.Length -gt 150) {
                    $messageSnippet = $messageSnippet.Substring(0, 150)
                }
            }
        }

        $results.Add([PSCustomObject]@{
            TimeCreated    = $event.TimeCreated
            Id             = $event.Id
            LevelDisplayName = $event.LevelDisplayName
            ProviderName   = $event.ProviderName
            Message        = $event.Message
            QueryName      = $queryName
            ServerAddress  = $serverAddress
            MessageSnippet = $messageSnippet
        }) | Out-Null
    }

    return $results.ToArray()
}

function Invoke-Main {
    $payload = [ordered]@{
        System      = Get-RecentEvents -LogName 'System'
        Application = Get-RecentEvents -LogName 'Application'
        GroupPolicy = Get-RecentEvents -LogName 'Microsoft-Windows-GroupPolicy/Operational' -MaxEvents 200
        DnsClientOperational = Get-DnsClientTimeoutEvents
    }

    $result = New-CollectorMetadata -Payload $payload
    $outputPath = Export-CollectorResult -OutputDirectory $OutputDirectory -FileName 'events.json' -Data $result -Depth 6
    Write-Output $outputPath
}

Invoke-Main
