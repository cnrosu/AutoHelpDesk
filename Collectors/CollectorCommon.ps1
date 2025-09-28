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

function Invoke-CollectorNativeCommand {
    param(
        [Parameter(Mandatory)]
        [string]$FilePath,

        [string[]]$ArgumentList = @(),

        [string]$SourceLabel,

        [hashtable]$ErrorMetadata
    )

    try {
        return & $FilePath @ArgumentList 2>$null
    } catch {
        $metadata = [ordered]@{}

        if ($PSBoundParameters.ContainsKey('ErrorMetadata') -and $ErrorMetadata) {
            foreach ($key in $ErrorMetadata.Keys) {
                $metadata[$key] = $ErrorMetadata[$key]
            }
        } elseif ($PSBoundParameters.ContainsKey('SourceLabel') -and $SourceLabel) {
            $metadata['Source'] = $SourceLabel
        } else {
            $commandName = [System.IO.Path]::GetFileName($FilePath)
            if ($ArgumentList.Count -gt 0) {
                $commandName = "$commandName $($ArgumentList -join ' ')"
            }
            $metadata['Source'] = $commandName
        }

        $metadata['Error'] = $_.Exception.Message

        return [PSCustomObject]$metadata
    }
}
