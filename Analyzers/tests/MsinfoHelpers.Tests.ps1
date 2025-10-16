$ErrorActionPreference = 'Stop'

$testsRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$analyzersRoot = Split-Path -Parent $testsRoot

. (Join-Path -Path $analyzersRoot -ChildPath 'AnalyzerCommon.ps1')

function New-TestMsinfoContext {
    $sections = [ordered]@{}
    $index = [ordered]@{}

    function Add-MsinfoSection {
        param(
            [string]$Name,
            [array]$Rows,
            [string[]]$Aliases
        )

        if (-not $Rows) { $Rows = @() }

        $section = [pscustomobject]@{
            Name     = $Name
            Rows     = $Rows
            RowCount = $Rows.Count
        }

        $sections[$Name] = $section

        $namesToIndex = @($Name)
        if ($Aliases) { $namesToIndex += $Aliases }

        foreach ($candidate in $namesToIndex) {
            if ([string]::IsNullOrWhiteSpace($candidate)) { continue }
            $key = ConvertTo-MsinfoSectionKey -Name $candidate
            if ($key) { $index[$key] = @($Name) }
        }
    }

    $summaryRows = @(
        [pscustomobject]@{ Item = 'System Name'; Value = 'CONTOSO-PC' },
        [pscustomobject]@{ Item = 'OS Name'; Value = 'Microsoft Windows 11 Pro' },
        [pscustomobject]@{ Item = 'Version'; Value = '10.0.22631 Build 22631' },
        [pscustomobject]@{ Item = 'Display Version'; Value = '23H2' },
        [pscustomobject]@{ Item = 'System Manufacturer'; Value = 'Contoso' },
        [pscustomobject]@{ Item = 'System Model'; Value = 'FabrikamBook' },
        [pscustomobject]@{ Item = 'System SKU Number'; Value = 'ABC-123' },
        [pscustomobject]@{ Item = 'BIOS Version/Date'; Value = 'Contoso 1.0, 1/1/2024' },
        [pscustomobject]@{ Item = 'BIOS Mode'; Value = 'UEFI' },
        [pscustomobject]@{ Item = 'Original Install Date'; Value = '1/1/2024, 12:00:00 PM' },
        [pscustomobject]@{ Item = 'Domain'; Value = 'CONTOSO' },
        [pscustomobject]@{ Item = 'Domain Role'; Value = 'Member Workstation' },
        [pscustomobject]@{ Item = 'Total Physical Memory'; Value = '16.0 GB' },
        [pscustomobject]@{ Item = 'Installed Physical Memory (RAM)'; Value = '16.0 GB' },
        [pscustomobject]@{ Item = 'Secure Boot State'; Value = 'On' },
        [pscustomobject]@{ Item = 'Kernel DMA Protection'; Value = 'On' },
        [pscustomobject]@{ Item = 'Virtualization-based security'; Value = 'Running' },
        [pscustomobject]@{ Item = 'Virtualization-based Security Services Running'; Value = 'Credential Guard' },
        [pscustomobject]@{ Item = 'Virtualization-based Security Services Configured'; Value = 'Credential Guard' },
        [pscustomobject]@{ Item = 'Virtualization-based Security Required Security Properties'; Value = 'Base Virtualization Support' },
        [pscustomobject]@{ Item = 'Virtualization-based Security Available Security Properties'; Value = 'Secure Boot; DMA Protection' },
        [pscustomobject]@{ Item = 'Device Guard Security Services Running'; Value = 'Credential Guard' },
        [pscustomobject]@{ Item = 'Device Guard Security Services Configured'; Value = 'Credential Guard' },
        [pscustomobject]@{ Item = 'Device Guard Required Security Properties'; Value = 'Secure Boot; DMA Protection' },
        [pscustomobject]@{ Item = 'Device Guard Available Security Properties'; Value = 'Secure Boot; DMA Protection' },
        [pscustomobject]@{ Item = 'Device Guard Code Integrity Policy'; Value = 'Enforced' },
        [pscustomobject]@{ Item = 'Device Guard User Mode Code Integrity Policy'; Value = 'Audit' },
        [pscustomobject]@{ Item = 'Windows Defender Application Control policy'; Value = 'Enforced' },
        [pscustomobject]@{ Item = 'Windows Defender Application Control user mode policy'; Value = 'Audit' }
    )

    Add-MsinfoSection -Name 'System Summary' -Rows $summaryRows -Aliases @('system summary', 'summary')

    $diskRows = @(
        [pscustomobject]@{ Name = 'Disk #0'; Model = 'Contoso SSD'; Size = '476.94 GB'; Partitions = '3' }
    )
    Add-MsinfoSection -Name 'Components\Storage\Disks' -Rows $diskRows -Aliases @('storage\disks', 'disks')

    $driveRows = @(
        [pscustomobject]@{ Name = 'C:'; Size = '237.96 GB'; 'Free Space' = '120.00 GB'; 'File System' = 'NTFS' }
    )
    Add-MsinfoSection -Name 'Components\Storage\Drives' -Rows $driveRows -Aliases @('storage\drives', 'drives')

    $adapterRows = @(
        [pscustomobject]@{ Name = 'Ethernet Adapter'; Description = 'Intel(R) Ethernet Connection'; 'Adapter Type' = 'Ethernet'; 'MAC Address' = '00-11-22-33-44-55'; 'Connection Status' = 'Connected' }
    )
    Add-MsinfoSection -Name 'Components\Network\Adapter' -Rows $adapterRows -Aliases @('network\adapter', 'adapter')

    $printerRows = @(
        [pscustomobject]@{ Name = 'Microsoft Print to PDF'; 'Driver Name' = 'Microsoft Print To PDF'; 'Port Name' = 'PORTPROMPT:' }
    )
    Add-MsinfoSection -Name 'Components\Printer' -Rows $printerRows -Aliases @('printer', 'printers')

    $processorRows = @(
        [pscustomobject]@{ Name = 'Intel(R) Core(TM) i7-8650U CPU @ 1.90GHz'; 'Number Of Cores' = '4'; 'Number Of Logical Processors' = '8' }
    )
    Add-MsinfoSection -Name 'Components\Processor' -Rows $processorRows -Aliases @('processor', 'processors')

    $payload = [pscustomobject]@{
        Source   = 'msinfo32'
        Sections = $sections
        Index    = $index
    }

    $artifact = [pscustomobject]@{
        Path = 'msinfo32.json'
        Data = [pscustomobject]@{ Payload = $payload }
    }

    return [pscustomobject]@{
        InputFolder = '/tmp/msinfo-test'
        Artifacts   = @{ 'msinfo32' = $artifact }
    }
}

$context = New-TestMsinfoContext
$failures = [System.Collections.Generic.List[string]]::new()

$identity = Get-MsinfoSystemIdentity -Context $context
if (-not $identity) {
    $null = $failures.Add('Get-MsinfoSystemIdentity returned null for sample payload.')
} else {
    if ($identity.DeviceName -ne 'CONTOSO-PC') {
        $null = $failures.Add("Expected DeviceName 'CONTOSO-PC' but received '$($identity.DeviceName)'.")
    }
    if ($identity.OSName -ne 'Microsoft Windows 11 Pro') {
        $null = $failures.Add("Expected OSName 'Microsoft Windows 11 Pro' but received '$($identity.OSName)'.")
    }
    if ($identity.OSBuild -ne '22631') {
        $null = $failures.Add("Expected OSBuild '22631' but received '$($identity.OSBuild)'.")
    }
    if ($identity.PartOfDomain -ne $true) {
        $null = $failures.Add('Expected PartOfDomain $true for member workstation domain role.')
    }
    if ($identity.BiosMode -ne 'UEFI') {
        $null = $failures.Add("Expected BiosMode 'UEFI' but received '$($identity.BiosMode)'.")
    }
    if ($identity.TotalPhysicalMemoryBytes -ne 17179869184) {
        $null = $failures.Add("Expected TotalPhysicalMemoryBytes 17179869184 but received '$($identity.TotalPhysicalMemoryBytes)'.")
    }
}

$security = Get-MsinfoSecuritySummary -Context $context
if (-not $security) {
    $null = $failures.Add('Get-MsinfoSecuritySummary returned null for sample payload.')
} else {
    if ($security.SecureBootState -ne 'On') {
        $null = $failures.Add("Expected SecureBootState 'On' but received '$($security.SecureBootState)'.")
    }
    if ($security.KernelDmaProtection -ne 'On') {
        $null = $failures.Add("Expected Kernel DMA protection 'On' but received '$($security.KernelDmaProtection)'.")
    }
    if ($security.VirtualizationBasedSecurity -ne 'Running') {
        $null = $failures.Add('Expected Virtualization-based security to be Running.')
    }
    if ($security.WindowsDefenderApplicationControlPolicy -ne 'Enforced') {
        $null = $failures.Add('Expected WDAC policy to be Enforced.')
    }
}

$disksSection = Get-MsinfoStorageDisksSection -Context $context
if (-not $disksSection -or $disksSection.RowCount -ne 1) {
    $null = $failures.Add('Expected storage disks section with one row.')
} elseif ($disksSection.Rows[0].Model -ne 'Contoso SSD') {
    $null = $failures.Add("Expected disk model 'Contoso SSD' but received '$($disksSection.Rows[0].Model)'.")
}

$drivesSection = Get-MsinfoStorageDrivesSection -Context $context
if (-not $drivesSection -or $drivesSection.RowCount -ne 1) {
    $null = $failures.Add('Expected storage drives section with one row.')
} elseif ($drivesSection.Rows[0].Name -ne 'C:') {
    $null = $failures.Add("Expected drive name 'C:' but received '$($drivesSection.Rows[0].Name)'.")
}

$adapterSection = Get-MsinfoNetworkAdapterSection -Context $context
if (-not $adapterSection -or $adapterSection.RowCount -ne 1) {
    $null = $failures.Add('Expected network adapter section with one row.')
} elseif ($adapterSection.Rows[0].Name -ne 'Ethernet Adapter') {
    $null = $failures.Add("Expected adapter name 'Ethernet Adapter' but received '$($adapterSection.Rows[0].Name)'.")
}

$printerSection = Get-MsinfoPrinterSection -Context $context
if (-not $printerSection -or $printerSection.RowCount -ne 1) {
    $null = $failures.Add('Expected printer section with one row.')
} elseif ($printerSection.Rows[0].Name -ne 'Microsoft Print to PDF') {
    $null = $failures.Add("Expected printer name 'Microsoft Print to PDF' but received '$($printerSection.Rows[0].Name)'.")
}

$processors = Get-MsinfoProcessors -Context $context
if (-not $processors -or $processors.Count -ne 1) {
    $null = $failures.Add('Expected one processor row from msinfo payload.')
} elseif ($processors[0].Name -notmatch 'i7-8650U') {
    $null = $failures.Add('Expected processor name to mention i7-8650U.')
}

if ($failures.Count -gt 0) {
    Write-Host 'Msinfo helper tests failed:'
    foreach ($failure in $failures) {
        Write-Host " - $failure"
    }
    exit 1
}

Write-Host 'Msinfo helper tests passed.'
