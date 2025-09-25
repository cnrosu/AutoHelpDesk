<#!
.SYNOPSIS
    Provides shared helper functions for collector scripts.
#>

function Resolve-CollectorOutputDirectory {
    param(
        [Parameter(Mandatory)]
        [string]$RequestedPath
    )

    if (-not (Test-Path -Path $RequestedPath)) {
        $null = New-Item -Path $RequestedPath -ItemType Directory -Force
    }

    return (Resolve-Path -Path $RequestedPath).ProviderPath
}

function Export-CollectorResult {
    param(
        [Parameter(Mandatory)]
        [string]$OutputDirectory,

        [Parameter(Mandatory)]
        [string]$FileName,

        [Parameter(Mandatory)]
        [object]$Data,

        [int]$Depth = 6
    )

    $resolved = Resolve-CollectorOutputDirectory -RequestedPath $OutputDirectory
    $path = Join-Path -Path $resolved -ChildPath $FileName
    $Data | ConvertTo-Json -Depth $Depth | Out-File -FilePath $path -Encoding UTF8
    return $path
}

function New-CollectorMetadata {
    param(
        [Parameter(Mandatory)]
        [object]$Payload
    )

    return [ordered]@{
        CollectedAt = (Get-Date).ToString('o')
        Payload     = $Payload
    }
}
