<#!
.SYNOPSIS
    Shared helper functions for analyzer modules.
#>

function New-AnalyzerContext {
    param(
        [Parameter(Mandatory)]
        [string]$InputFolder
    )

    if (-not (Test-Path -LiteralPath $InputFolder)) {
        throw "Input folder '$InputFolder' not found."
    }

    $resolved = (Resolve-Path -LiteralPath $InputFolder).ProviderPath
    $artifactMap = @{}

    $files = Get-ChildItem -Path $resolved -File -Recurse -ErrorAction SilentlyContinue
    foreach ($file in $files) {
        $data = $null
        if ($file.Extension -ieq '.json') {
            $content = Get-Content -Path $file.FullName -Raw -ErrorAction SilentlyContinue
            if ($content) {
                try {
                    $data = $content | ConvertFrom-Json -ErrorAction Stop
                } catch {
                    $data = [pscustomobject]@{ Error = $_.Exception.Message }
                }
            }
        }

        $entry = [pscustomobject]@{
            Path = $file.FullName
            Data = $data
        }

        $key = $file.Name.ToLowerInvariant()
        if ($artifactMap.ContainsKey($key)) {
            $artifactMap[$key] = @($artifactMap[$key]) + ,$entry
        } else {
            $artifactMap[$key] = @($entry)
        }
    }

    $jsonFiles = @($files | Where-Object { $_.Extension -ieq '.json' })
    if ($jsonFiles.Count -gt 0) {
        $paths = $jsonFiles | ForEach-Object { $_.FullName }
        Write-HeuristicDebug -Source 'Context' -Message ("Discovered artifacts ({0}): {1}" -f $paths.Count, ($paths -join ', '))
    } else {
        Write-HeuristicDebug -Source 'Context' -Message 'Discovered artifacts (0): (none)'
    }

    return [pscustomobject]@{
        InputFolder = $resolved
        Artifacts   = $artifactMap
    }
}

function Write-HeuristicDebug {
    param(
        [Parameter(Mandatory)]
        [string]$Source,

        [Parameter(Mandatory)]
        [string]$Message,

        [hashtable]$Data
    )

    $formatted = "DBG [{0}] {1}" -f $Source, $Message

    if ($PSBoundParameters.ContainsKey('Data') -and $Data) {
        $detailEntries = $Data.GetEnumerator() | Sort-Object Name
        $details = [System.Collections.Generic.List[string]]::new()
        foreach ($entry in $detailEntries) {
            if ($entry -is [System.Collections.DictionaryEntry]) {
                $null = $details.Add(("{0}={1}" -f $entry.Key, $entry.Value))
            } else {
                $null = $details.Add(("{0}={1}" -f $entry.Name, $entry.Value))
            }
        }

        if ($details) {
            $formatted = "{0} :: {1}" -f $formatted, ($details -join '; ')
        }
    }

    Write-Host $formatted
}

function Get-HeuristicSourceMetadata {
    param(
        [string[]]$SkipCommands = @(
            'Get-HeuristicSourceMetadata',
            'New-CategoryResult',
            'Add-CategoryIssue',
            'Add-CategoryNormal',
            'Add-CategoryCheck'
        )
    )

    try {
        $stack = Get-PSCallStack
    } catch {
        return $null
    }

    if (-not $stack) { return $null }

    foreach ($frame in $stack) {
        if (-not $frame) { continue }

        $command = if ($frame.PSObject.Properties['Command']) { [string]$frame.Command } else { $null }
        if ($command -and $SkipCommands -contains $command) { continue }

        $script = if ($frame.PSObject.Properties['ScriptName']) { [string]$frame.ScriptName } else { $null }
        if (-not $script) { continue }

        $resolvedScript = $script
        try {
            if (Test-Path -LiteralPath $script) {
                $resolvedScript = (Resolve-Path -LiteralPath $script -ErrorAction Stop).ProviderPath
            }
        } catch {
        }

        if ($resolvedScript -and $resolvedScript.EndsWith('AnalyzerCommon.ps1', [System.StringComparison]::OrdinalIgnoreCase)) {
            continue
        }

        $functionName = if ($frame.PSObject.Properties['FunctionName'] -and $frame.FunctionName) {
            [string]$frame.FunctionName
        } elseif ($command) {
            $command
        } else {
            $null
        }

        $lineNumber = $null
        if ($frame.PSObject.Properties['ScriptLineNumber'] -and $frame.ScriptLineNumber -gt 0) {
            $lineNumber = [int]$frame.ScriptLineNumber
        }

        return [pscustomobject]@{
            Script   = $resolvedScript
            Function = $functionName
            Command  = $command
            Line     = $lineNumber
        }
    }

    return $null
}

function Get-AnalyzerArtifact {
    param(
        [Parameter(Mandatory)]
        $Context,

        [Parameter(Mandatory)]
        [string]$Name
    )

    if (-not $Context -or -not $Context.Artifacts) { return $null }

    $key = $Name.ToLowerInvariant()
    $lookupKeys = [System.Collections.Generic.List[string]]::new()
    $lookupKeys.Add($key) | Out-Null
    if ($key -notmatch '\.') {
        $builder = [System.Text.StringBuilder]::new($key)
        $null = $builder.Append('.json')
        $lookupKeys.Add($builder.ToString()) | Out-Null
    }

    $entries = $null
    foreach ($candidate in $lookupKeys) {
        if ($Context.Artifacts.ContainsKey($candidate)) {
            $entries = $Context.Artifacts[$candidate]
            break
        }
    }

    if (-not $entries) { return $null }

    if ($entries.Count -gt 1) { return $entries }
    return $entries[0]
}

function New-CategoryResult {
    param(
        [Parameter(Mandatory)]
        [string]$Name
    )

    $source = Get-HeuristicSourceMetadata

    return [pscustomobject]@{
        Name    = $Name
        Issues  = New-Object System.Collections.Generic.List[pscustomobject]
        Normals = New-Object System.Collections.Generic.List[pscustomobject]
        Checks  = New-Object System.Collections.Generic.List[pscustomobject]
        Source  = $source
    }
}

function Add-CategoryIssue {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        $CategoryResult,

        [string]$Category,

        [string]$Subcategory,

        [Parameter(Mandatory)]
        [string]$Title,

        [ValidateSet('critical','high','medium','low','warning','info')]
        [string]$Severity,

        [string]$Area,

        [object]$Evidence,

        [object]$Data,

        [string]$CheckId,

        [string]$Remediation,

        [string]$RemediationScript
    )

    if (-not $CategoryResult) { throw 'CategoryResult is required.' }

    if (-not $Category -and $CategoryResult.PSObject.Properties['Name']) {
        $Category = [string]$CategoryResult.Name
    }

    if (-not $Area -and $Category) { $Area = $Category }

    if (Get-Command ConvertTo-AnalyzerDataDictionary -ErrorAction SilentlyContinue) {
        $Data = if ($Data) { ConvertTo-AnalyzerDataDictionary -InputObject $Data } else { $null }
    }

    if (-not $Severity) { $Severity = 'info' }

    $source = Get-HeuristicSourceMetadata

    if ($PSBoundParameters.ContainsKey('Evidence')) {
        if ($Evidence -is [System.Collections.IEnumerable] -and -not ($Evidence -is [string])) {
            $sanitizedEvidence = @($Evidence | Where-Object { $_ })
            if ($sanitizedEvidence.Count -gt 0) {
                $Evidence = $sanitizedEvidence
            } else {
                $Evidence = $null
            }
        }
    }

    $entry = [ordered]@{
        Severity    = $Severity
        Title       = $Title
        Evidence    = $Evidence
        Subcategory = $Subcategory
    }

    if ($Area) { $entry['Area'] = $Area }

    if ($PSBoundParameters.ContainsKey('Data') -or $null -ne $Data) {
        $entry['Data'] = $Data
    }

    if (-not [string]::IsNullOrWhiteSpace($CheckId)) { $entry['CheckId'] = $CheckId }

    if ($PSBoundParameters.ContainsKey('Remediation') -and -not [string]::IsNullOrWhiteSpace($Remediation)) {
        $entry['Remediation'] = $Remediation.Trim()
    }

    if ($PSBoundParameters.ContainsKey('RemediationScript') -and -not [string]::IsNullOrWhiteSpace($RemediationScript)) {
        $entry['RemediationScript'] = $RemediationScript
    }

    if ($source) { $entry['Source'] = $source }

    $CategoryResult.Issues.Add([pscustomobject]$entry) | Out-Null
}

function Add-CategoryNormal {
    param(
        [Parameter(Mandatory)]
        $CategoryResult,

        [Parameter(Mandatory)]
        [string]$Title,

        [object]$Evidence = $null,

        [string]$Subcategory = $null,

        [string]$CheckId = $null
    )

    $source = Get-HeuristicSourceMetadata

    $entry = [ordered]@{
        Title    = $Title
        Evidence = $Evidence
    }

    if ($PSBoundParameters.ContainsKey('Subcategory') -and $Subcategory) {
        $entry['Subcategory'] = $Subcategory
    }

    if ($PSBoundParameters.ContainsKey('CheckId') -and -not [string]::IsNullOrWhiteSpace($CheckId)) {
        $entry['CheckId'] = $CheckId
    }

    if ($source) { $entry['Source'] = $source }

    $CategoryResult.Normals.Add([pscustomobject]$entry) | Out-Null
}

function Add-CategoryCheck {
    param(
        [Parameter(Mandatory)]
        $CategoryResult,

        [Parameter(Mandatory)]
        [string]$Name,

        [Parameter(Mandatory)]
        [string]$Status,

        [string]$Details = ''
    )

    $source = Get-HeuristicSourceMetadata

    $entry = [ordered]@{
        Name    = $Name
        Status  = $Status
        Details = $Details
    }

    if ($source) { $entry['Source'] = $source }

    $CategoryResult.Checks.Add([pscustomobject]$entry) | Out-Null
}

function Merge-AnalyzerResults {
    param(
        [Parameter(Mandatory)]
        [System.Collections.Generic.IEnumerable[object]]$Categories
    )

    $issues = New-Object System.Collections.Generic.List[pscustomobject]
    $normals = New-Object System.Collections.Generic.List[pscustomobject]
    $checks = New-Object System.Collections.Generic.List[pscustomobject]

    foreach ($category in $Categories) {
        if (-not $category) { continue }
        foreach ($item in $category.Issues) { $issues.Add($item) | Out-Null }
        foreach ($item in $category.Normals) { $normals.Add($item) | Out-Null }
        foreach ($item in $category.Checks) { $checks.Add($item) | Out-Null }
    }

    return [pscustomobject]@{
        Issues  = $issues
        Normals = $normals
        Checks  = $checks
    }
}

function Get-ArtifactPayload {
    param(
        [Parameter(Mandatory)]
        $Artifact
    )

    if (-not $Artifact) { return $null }

    if ($Artifact -is [System.Collections.IEnumerable] -and -not ($Artifact -is [string])) {
        $payloads = [System.Collections.Generic.List[object]]::new()
        foreach ($item in $Artifact) {
            $null = $payloads.Add($item.Data.Payload)
        }

        return $payloads
    }

    if ($Artifact.Data -and $Artifact.Data.PSObject.Properties['Payload']) {
        return $Artifact.Data.Payload
    }

    return $null
}

function Resolve-SinglePayload {
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        $Payload
    )

    if ($null -eq $Payload) { return $null }

    if ($Payload -is [System.Collections.IEnumerable] -and -not ($Payload -is [string])) {
        return ($Payload | Select-Object -First 1)
    }

    return $Payload
}

function ConvertTo-MsinfoSectionKey {
    param([string]$Name)

    if ([string]::IsNullOrWhiteSpace($Name)) { return $null }

    $normalized = $Name.Trim().ToLowerInvariant()
    if (-not $normalized) { return $null }

    $normalized = [System.Text.RegularExpressions.Regex]::Replace(
        $normalized,
        '[^a-z0-9]+',
        '-',
        [System.Text.RegularExpressions.RegexOptions]::Compiled
    )

    $normalized = $normalized.Trim('-')
    if (-not $normalized) { return $null }

    return $normalized
}

function Get-MsinfoArtifactPayload {
    param(
        [Parameter(Mandatory)]
        $Context
    )

    if (-not $Context) { return $null }

    $artifact = Get-AnalyzerArtifact -Context $Context -Name 'msinfo32'
    if (-not $artifact) {
        $artifact = Get-AnalyzerArtifact -Context $Context -Name 'msinfo'
    }

    if (-not $artifact) { return $null }

    return Resolve-SinglePayload -Payload (Get-ArtifactPayload -Artifact $artifact)
}

function Get-MsinfoSectionTable {
    param(
        [Parameter(Mandatory)]
        $Payload,

        [Parameter(Mandatory)]
        [string[]]$Names
    )

    if (-not $Payload) { return $null }
    if (-not $Payload.PSObject.Properties['Sections']) { return $null }

    $sections = $Payload.Sections
    if (-not $sections) { return $null }

    $index = $null
    if ($Payload.PSObject.Properties['Index']) { $index = $Payload.Index }

    $candidateKeys = New-Object System.Collections.Generic.List[string]
    foreach ($name in $Names) {
        if ([string]::IsNullOrWhiteSpace($name)) { continue }

        $candidateKeys.Add($name) | Out-Null

        $normalized = ConvertTo-MsinfoSectionKey -Name $name
        if ($normalized) { $candidateKeys.Add($normalized) | Out-Null }
    }

    $visited = New-Object System.Collections.Generic.HashSet[string]([System.StringComparer]::OrdinalIgnoreCase)

    foreach ($candidate in $candidateKeys) {
        if ([string]::IsNullOrWhiteSpace($candidate)) { continue }
        if (-not $visited.Add($candidate)) { continue }

        if ($sections.ContainsKey($candidate)) {
            $table = $sections[$candidate]
            if ($table) { return $table }
        }

        $normalized = ConvertTo-MsinfoSectionKey -Name $candidate
        if ($normalized -and $sections.ContainsKey($normalized)) {
            $table = $sections[$normalized]
            if ($table) { return $table }
        }

        if ($index -and $normalized -and $index.ContainsKey($normalized)) {
            $targets = @($index[$normalized])
            foreach ($target in $targets) {
                if (-not $target) { continue }
                if ($sections.ContainsKey($target)) {
                    $table = $sections[$target]
                    if ($table) { return $table }
                }
            }
        }

        if ($index -and $index.ContainsKey($candidate)) {
            $targets = @($index[$candidate])
            foreach ($target in $targets) {
                if (-not $target) { continue }
                if ($sections.ContainsKey($target)) {
                    $table = $sections[$target]
                    if ($table) { return $table }
                }
            }
        }

        foreach ($sectionName in $sections.Keys) {
            if (-not $sectionName) { continue }

            $sectionKey = ConvertTo-MsinfoSectionKey -Name $sectionName
            if ($sectionKey -and ($sectionKey -eq $candidate -or $sectionKey -eq $normalized)) {
                $table = $sections[$sectionName]
                if ($table) { return $table }
            }
        }
    }

    return $null
}

function Get-MsinfoRowValue {
    param(
        [Parameter(Mandatory)]
        $Row,

        [Parameter(Mandatory)]
        [string[]]$Names
    )

    if (-not $Row) { return $null }

    foreach ($name in $Names) {
        if ([string]::IsNullOrWhiteSpace($name)) { continue }

        $property = $Row.PSObject.Properties[$name]
        if ($property -and $null -ne $property.Value -and $property.Value -ne '') {
            $value = [string]$property.Value
            if (-not [string]::IsNullOrWhiteSpace($value)) { return $value.Trim() }
        }

        $trimmedName = ($name -replace '[^A-Za-z0-9]', '')
        if ($trimmedName -and $Row.PSObject.Properties[$trimmedName]) {
            $candidateValue = $Row.$trimmedName
            if ($null -ne $candidateValue -and $candidateValue -ne '') {
                $value = [string]$candidateValue
                if (-not [string]::IsNullOrWhiteSpace($value)) { return $value.Trim() }
            }
        }

        foreach ($prop in $Row.PSObject.Properties) {
            if (-not $prop -or -not $prop.Name) { continue }
            if ($prop.Name.Equals($name, [System.StringComparison]::OrdinalIgnoreCase)) {
                $candidate = $prop.Value
                if ($null -ne $candidate -and $candidate -ne '') {
                    $value = [string]$candidate
                    if (-not [string]::IsNullOrWhiteSpace($value)) { return $value.Trim() }
                }
            }
        }
    }

    return $null
}

function Get-MsinfoServicesPayload {
    param(
        [Parameter(Mandatory)]
        $Context
    )

    $msinfoPayload = Get-MsinfoArtifactPayload -Context $Context
    if (-not $msinfoPayload) { return $null }

    $table = Get-MsinfoSectionTable -Payload $msinfoPayload -Names @('software environment\services', 'services')
    if (-not $table -or -not $table.Rows -or $table.RowCount -eq 0) { return $null }

    $services = New-Object System.Collections.Generic.List[pscustomobject]
    $errors = New-Object System.Collections.Generic.List[string]

    foreach ($row in $table.Rows) {
        if (-not $row) { continue }

        $name = Get-MsinfoRowValue -Row $row -Names @('ServiceName', 'Service Name', 'Name')
        if (-not $name) {
            $errors.Add('Service entry missing Service Name.') | Out-Null
            continue
        }

        $displayName = Get-MsinfoRowValue -Row $row -Names @('DisplayName', 'Display Name', 'Name')
        $status = Get-MsinfoRowValue -Row $row -Names @('Status', 'State')
        $state = Get-MsinfoRowValue -Row $row -Names @('State', 'Status')
        $startMode = Get-MsinfoRowValue -Row $row -Names @('StartMode', 'StartupType', 'Startup Type', 'Start Type')
        $logOnAs = Get-MsinfoRowValue -Row $row -Names @('LogOnAs', 'Log On As', 'User', 'StartName')
        $serviceType = Get-MsinfoRowValue -Row $row -Names @('ServiceType', 'Service Type', 'Type')
        $path = Get-MsinfoRowValue -Row $row -Names @('Path', 'BinaryPath', 'ImagePath')

        $entry = [ordered]@{
            Name        = $name
            DisplayName = if ($displayName) { $displayName } else { $name }
            Status      = if ($status) { $status } else { $null }
            State       = if ($state) { $state } else { $status }
            StartMode   = if ($startMode) { $startMode } else { $null }
            StartType   = if ($startMode) { $startMode } else { $null }
            StartName   = if ($logOnAs) { $logOnAs } else { $null }
            ServiceType = if ($serviceType) { $serviceType } else { $null }
            Path        = if ($path) { $path } else { $null }
        }

        $services.Add([pscustomobject]$entry) | Out-Null
    }

    if ($services.Count -eq 0) { return $null }

    return [pscustomobject]@{
        Source           = 'msinfo32'
        SectionName      = $table.Name
        Services         = $services.ToArray()
        CollectionErrors = if ($errors.Count -gt 0) { $errors.ToArray() } else { @() }
    }
}

function Get-MsinfoStartupPayload {
    param(
        [Parameter(Mandatory)]
        $Context
    )

    $msinfoPayload = Get-MsinfoArtifactPayload -Context $Context
    if (-not $msinfoPayload) { return $null }

    $table = Get-MsinfoSectionTable -Payload $msinfoPayload -Names @('software environment\startup programs', 'startup programs')
    if (-not $table -or -not $table.Rows -or $table.RowCount -eq 0) { return $null }

    $startupItems = New-Object System.Collections.Generic.List[pscustomobject]

    foreach ($row in $table.Rows) {
        if (-not $row) { continue }

        $name = Get-MsinfoRowValue -Row $row -Names @('Item', 'Name')
        $command = Get-MsinfoRowValue -Row $row -Names @('Command')
        $location = Get-MsinfoRowValue -Row $row -Names @('Location', 'Path')
        $user = Get-MsinfoRowValue -Row $row -Names @('User')
        $description = Get-MsinfoRowValue -Row $row -Names @('Description')
        $disabled = Get-MsinfoRowValue -Row $row -Names @('Disabled')

        $entry = [ordered]@{
            Name        = $name
            Command     = $command
            Location    = $location
            User        = $user
            Description = $description
            Disabled    = $disabled
        }

        $startupItems.Add([pscustomobject]$entry) | Out-Null
    }

    if ($startupItems.Count -eq 0) { return $null }

    return [pscustomobject]@{
        Source          = 'msinfo32'
        SectionName     = $table.Name
        StartupCommands = $startupItems.ToArray()
    }
}

function Get-MsinfoDriverEntries {
    param(
        [Parameter(Mandatory)]
        $Context
    )

    $msinfoPayload = Get-MsinfoArtifactPayload -Context $Context
    if (-not $msinfoPayload) { return $null }

    $table = Get-MsinfoSectionTable -Payload $msinfoPayload -Names @('software environment\system drivers', 'system drivers')
    if (-not $table -or -not $table.Rows -or $table.RowCount -eq 0) { return $null }

    $entries = New-Object System.Collections.Generic.List[pscustomobject]

    foreach ($row in $table.Rows) {
        if (-not $row) { continue }

        $moduleName = Get-MsinfoRowValue -Row $row -Names @('Name', 'ModuleName', 'Module Name')
        $displayName = Get-MsinfoRowValue -Row $row -Names @('DisplayName', 'Display Name', 'Description')
        $type = Get-MsinfoRowValue -Row $row -Names @('Type', 'DriverType', 'Driver Type')
        $startMode = Get-MsinfoRowValue -Row $row -Names @('StartMode', 'Start Mode', 'StartupType', 'Startup Type')
        $state = Get-MsinfoRowValue -Row $row -Names @('State')
        $status = Get-MsinfoRowValue -Row $row -Names @('Status')
        $errorControl = Get-MsinfoRowValue -Row $row -Names @('ErrorControl', 'Error Control')
        $path = Get-MsinfoRowValue -Row $row -Names @('Path', 'ImagePath', 'BinaryPath')
        $startName = Get-MsinfoRowValue -Row $row -Names @('StartedBy', 'Started By')

        $entry = [ordered]@{
            ModuleName   = $moduleName
            DisplayName  = $displayName
            DriverType   = $type
            StartMode    = $startMode
            State        = $state
            Status       = $status
            ErrorControl = $errorControl
            Path         = $path
            StartName    = $startName
        }

        $entries.Add([pscustomobject]$entry) | Out-Null
    }

    if ($entries.Count -eq 0) { return $null }

    return $entries.ToArray()
}
