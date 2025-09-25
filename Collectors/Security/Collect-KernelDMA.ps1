<#!
.SYNOPSIS
    Collects Kernel DMA protection configuration.
#>
[CmdletBinding()]
param(
    [Parameter()]
    [string]$OutputDirectory = (Join-Path -Path (Split-Path -Parent $PSCommandPath) -ChildPath '..\\output')
)

. (Join-Path -Path $PSScriptRoot -ChildPath '..\\CollectorCommon.ps1')

function Get-KernelDMAConfiguration {
    $paths = @(
        'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\KernelDMAProtection',
        'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard'
    )

    $result = @()
    foreach ($path in $paths) {
        try {
            $values = Get-ItemProperty -Path $path -ErrorAction Stop | Select-Object * -ExcludeProperty PS*, CIM*, PSEdition
            $result += [PSCustomObject]@{
                Path   = $path
                Values = $values
            }
        } catch {
            $result += [PSCustomObject]@{
                Path  = $path
                Error = $_.Exception.Message
            }
        }
    }

    return $result
}

function Get-MsInfoKernelDmaSection {
    try {
        $tempPath = Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath ([System.Guid]::NewGuid().ToString() + '.txt')
        $process = Start-Process -FilePath 'msinfo32.exe' -ArgumentList '/report', $tempPath, '/categories', 'Hardware Resources\DMA' -PassThru -WindowStyle Hidden
        $process.WaitForExit()
        $content = Get-Content -Path $tempPath -ErrorAction SilentlyContinue
        Remove-Item -Path $tempPath -ErrorAction SilentlyContinue
        return $content
    } catch {
        return [PSCustomObject]@{
            Source = 'msinfo32.exe'
            Error  = $_.Exception.Message
        }
    }
}

function Invoke-Main {
    $payload = [ordered]@{
        Registry = Get-KernelDMAConfiguration
        MsInfo   = Get-MsInfoKernelDmaSection
    }

    $result = New-CollectorMetadata -Payload $payload
    $outputPath = Export-CollectorResult -OutputDirectory $OutputDirectory -FileName 'kerneldma.json' -Data $result -Depth 6
    Write-Output $outputPath
}

Invoke-Main
