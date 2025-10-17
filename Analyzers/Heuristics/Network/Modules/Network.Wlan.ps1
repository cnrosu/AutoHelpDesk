function Get-WlanLines {
    param($Value)

    $lines = @()
    foreach ($item in (ConvertTo-NetworkArray $Value)) {
        if ($null -ne $item) {
            $lines += [string]$item
        }
    }

    return $lines
}

function ConvertTo-WlanInterfaces {
    param($Raw)

    $interfaces = [System.Collections.Generic.List[object]]::new()
    $lines = Get-WlanLines $Raw
    $current = $null

    foreach ($line in $lines) {
        if (-not $line) { continue }
        $trimmed = $line.Trim()
        if (-not $trimmed) { continue }

        if ($trimmed -match '^Name\s*:\s*(.+)$') {
            $rawLines = New-Object System.Collections.Generic.List[string]
            $rawLines.Add($trimmed) | Out-Null
            $current = [pscustomobject]([ordered]@{
                Name     = $Matches[1].Trim()
                RawLines = $rawLines
            })
            $interfaces.Add($current) | Out-Null
            continue
        }

        if (-not $current) { continue }

        if ($current.PSObject.Properties['RawLines'] -and $current.RawLines) {
            $current.RawLines.Add($trimmed) | Out-Null
        }

        if ($trimmed -match '^([^:]+)\s*:\s*(.*)$') {
            $key = $Matches[1].Trim()
            $value = $Matches[2].Trim()

            switch -Regex ($key) {
                '^Description$'        { $current | Add-Member -NotePropertyName 'Description' -NotePropertyValue $value -Force; continue }
                '^GUID$'               { $current | Add-Member -NotePropertyName 'Guid' -NotePropertyValue $value -Force; continue }
                '^Physical address$'   { $current | Add-Member -NotePropertyName 'Mac' -NotePropertyValue $value -Force; continue }
                '^State$'              { $current | Add-Member -NotePropertyName 'State' -NotePropertyValue $value -Force; continue }
                '^SSID(\s+name)?$'    { $current | Add-Member -NotePropertyName 'Ssid' -NotePropertyValue $value -Force; continue }
                '^BSSID(\s+\d+)?$'   { $current | Add-Member -NotePropertyName 'Bssid' -NotePropertyValue $value -Force; continue }
                '^Authentication$'     { $current | Add-Member -NotePropertyName 'Authentication' -NotePropertyValue $value -Force; continue }
                '^Cipher$'             { $current | Add-Member -NotePropertyName 'Cipher' -NotePropertyValue $value -Force; continue }
                '^Connection mode$'    { $current | Add-Member -NotePropertyName 'ConnectionMode' -NotePropertyValue $value -Force; continue }
                '^Radio type$'         { $current | Add-Member -NotePropertyName 'RadioType' -NotePropertyValue $value -Force; continue }
                '^Profile$'            { $current | Add-Member -NotePropertyName 'Profile' -NotePropertyValue $value -Force; continue }
            }
        }
    }

    foreach ($interface in $interfaces) {
        if ($interface -and $interface.PSObject.Properties['RawLines'] -and $interface.RawLines -is [System.Collections.IEnumerable]) {
            try {
                $interface.RawLines = @($interface.RawLines.ToArray())
            } catch {
                $interface.RawLines = @(ConvertTo-NetworkArray $interface.RawLines)
            }
        }
    }

    return $interfaces.ToArray()
}

function Test-WlanInterfaceConnected {
    param(
        [Parameter(Mandatory)]
        $Interface
    )

    if (-not $Interface) { return $false }

    $stateValues = New-Object System.Collections.Generic.List[string]

    if ($Interface.PSObject.Properties['State'] -and $Interface.State) {
        $stateValues.Add([string]$Interface.State) | Out-Null
    }

    if ($Interface.PSObject.Properties['RawLines'] -and $Interface.RawLines) {
        foreach ($rawLine in (ConvertTo-NetworkArray $Interface.RawLines)) {
            if (-not $rawLine) { continue }
            $text = [string]$rawLine
            if (-not $text) { continue }
            if ($text -match ':[\s]*(.+)$') {
                $stateValues.Add($Matches[1].Trim()) | Out-Null
            }
        }
    }

    $connectedPattern = '(?i)\b(connected|verbunden|conectad[oa]|connect[ée]|conness[oa]|collegat[oa]|ligad[oa]|verbonden|anslutet|ansluten|tilsluttet|tilkoblet|yhdistetty|připojeno|połączono|подключен(?:о|а)?|bağland[ıi]|bağl[ıi]|已连接|已連線|已連接|接続済み|연결됨|đã\s*kết\s*nối)\b'
    foreach ($candidate in $stateValues) {
        if ($candidate -and $candidate -match $connectedPattern) {
            return $true
        }
    }

    if ($Interface.PSObject.Properties['Ssid'] -and $Interface.Ssid) { return $true }
    if ($Interface.PSObject.Properties['Bssid'] -and $Interface.Bssid) { return $true }
    if ($Interface.PSObject.Properties['Profile'] -and $Interface.Profile) { return $true }
    if ($Interface.PSObject.Properties['Authentication'] -and $Interface.Authentication) { return $true }
    if ($Interface.PSObject.Properties['Cipher'] -and $Interface.Cipher) { return $true }

    return $false
}

function ConvertTo-WlanNetworks {
    param($Raw)

    $entries = [System.Collections.Generic.List[object]]::new()
    $lines = Get-WlanLines $Raw
    $current = $null

    foreach ($line in $lines) {
        if (-not $line) { continue }
        $trimmed = $line.Trim()
        if (-not $trimmed) { continue }

        if ($trimmed -match '^SSID\s+\d+\s*:\s*(.*)$') {
            $ssid = $Matches[1].Trim()
            $current = [ordered]@{
                Ssid            = $ssid
                Authentications = New-Object System.Collections.Generic.List[string]
                Encryptions     = New-Object System.Collections.Generic.List[string]
            }
            $entries.Add([pscustomobject]$current) | Out-Null
            continue
        }

        if (-not $current) { continue }

        if ($trimmed -match '^Authentication\s*:\s*(.+)$') {
            $value = $Matches[1].Trim()
            if ($value -and -not $current.Authentications.Contains($value)) {
                $current.Authentications.Add($value) | Out-Null
            }
            continue
        }

        if ($trimmed -match '^Encryption\s*:\s*(.+)$') {
            $value = $Matches[1].Trim()
            if ($value -and -not $current.Encryptions.Contains($value)) {
                $current.Encryptions.Add($value) | Out-Null
            }
            continue
        }
    }

    return $entries.ToArray()
}

function ConvertTo-WlanProfileInfo {
    param($Detail)

    if (-not $Detail) { return $null }

    $info = [ordered]@{
        Name                    = $Detail.Name
        Authentication          = $null
        AuthenticationFallback  = $null
        Encryption              = $null
        EncryptionFallback      = $null
        UseOneX                 = $null
        PassphraseMetrics       = $null
        PassphraseMetricsError  = $null
        EapConfigPresent        = $false
        XmlError                = $null
        PmfSetting              = $null
    }

    $xmlText = $null
    if ($Detail.PSObject.Properties['Xml'] -and $Detail.Xml) {
        $xmlText = [string]$Detail.Xml
    } elseif ($Detail.PSObject.Properties['XmlError'] -and $Detail.XmlError) {
        $info.XmlError = [string]$Detail.XmlError
    }

    if ($xmlText) {
        try {
            $xml = [xml]$xmlText
            $profileNode = $xml.WLANProfile
            if ($profileNode -and $profileNode.MSM -and $profileNode.MSM.security) {
                $security = $profileNode.MSM.security
                if ($security.authEncryption) {
                    $auth = $security.authEncryption
                    if ($auth.authentication) { $info.Authentication = [string]$auth.authentication }
                    if ($auth.encryption) { $info.Encryption = [string]$auth.encryption }
                    if ($auth.useOneX -ne $null) {
                        try {
                            $info.UseOneX = [System.Convert]::ToBoolean($auth.useOneX)
                        } catch {
                            $text = [string]$auth.useOneX
                            if ($text) {
                                $info.UseOneX = ($text.Trim().ToLowerInvariant() -eq 'true')
                            }
                        }
                    }
                }
                if ($security.mfp) {
                    try {
                        $info.PmfSetting = [string]$security.mfp
                    } catch {
                        $info.PmfSetting = [string]$security.mfp.InnerText
                    }
                }
            }

            if (-not $info.PmfSetting) {
                $mfpNode = $profileNode.SelectSingleNode("//*[local-name()='mfp']")
                if ($mfpNode -and $mfpNode.InnerText) {
                    $info.PmfSetting = [string]$mfpNode.InnerText
                }
            }

            $eapNode = $xml.SelectSingleNode("//*[local-name()='EAPConfig']")
            if ($eapNode) {
                $info.EapConfigPresent = $true
            }
        } catch {
            $info.XmlError = $_.Exception.Message
        }
    }

    $profileLines = Get-WlanLines ($Detail.PSObject.Properties['ShowProfile'] ? $Detail.ShowProfile : $null)
    foreach ($line in $profileLines) {
        if (-not $line) { continue }
        $trimmed = $line.Trim()
        if (-not $trimmed) { continue }

        if (-not $info.AuthenticationFallback -and $trimmed -match '^Authentication\s*:\s*(.+)$') {
            $info.AuthenticationFallback = $Matches[1].Trim()
            continue
        }

        if (-not $info.EncryptionFallback -and $trimmed -match '^Cipher\s*:\s*(.+)$') {
            $info.EncryptionFallback = $Matches[1].Trim()
            continue
        }

        if (-not $info.PmfSetting -and $trimmed -match '^(PMF|802\.11w).*:\s*(.+)$') {
            $info.PmfSetting = $Matches[2].Trim()
            continue
        }

        if ($info.UseOneX -eq $null -and $trimmed -match '^Security key\s*:\s*(.+)$') {
            $keyType = $Matches[1].Trim()
            if ($keyType -match '802\.1X|EAP') { $info.UseOneX = $true }
        }
    }

    if ($info.UseOneX -eq $null -and $info.EapConfigPresent) {
        $info.UseOneX = $true
    }
    
    if ($Detail.PSObject.Properties['PassphraseMetrics'] -and $Detail.PassphraseMetrics) {
        $info.PassphraseMetrics = $Detail.PassphraseMetrics
    }
    if ($Detail.PSObject.Properties['PassphraseMetricsError'] -and $Detail.PassphraseMetricsError) {
        $info.PassphraseMetricsError = [string]$Detail.PassphraseMetricsError
    }

    return [pscustomobject]$info
}

function ConvertTo-WlanProfileInfos {
    param($Profiles)

    $results = [System.Collections.Generic.List[object]]::new()
    if (-not $Profiles) { return $results.ToArray() }

    $details = $null
    if ($Profiles.PSObject -and $Profiles.PSObject.Properties['Details']) {
        $details = $Profiles.Details
    } elseif ($Profiles -is [System.Collections.IEnumerable]) {
        $details = $Profiles
    }

    foreach ($detail in (ConvertTo-NetworkArray $details)) {
        $info = ConvertTo-WlanProfileInfo $detail
        if ($info) { $results.Add($info) | Out-Null }
    }

    return $results.ToArray()
}

function Normalize-WlanAuthToken {
    param([string]$Text)

    if (-not $Text) { return $null }
    $token = $Text.Trim()
    if (-not $token) { return $null }

    try {
        $token = $token.ToUpperInvariant()
    } catch {
        $token = ([string]$token).ToUpperInvariant()
    }

    return ($token -replace '[^A-Z0-9]', '')
}

function Get-WlanSecurityCategoryFromToken {
    param(
        [string]$Token,
        [Nullable[bool]]$UseOneX
    )

    if (-not $Token) { return $null }

    if ($Token -match 'WPA3' -and $Token -match 'SAE' -and $Token -match 'TRANS') { return 'WPA3PersonalTransition' }
    if ($Token -match 'WPA3' -and $Token -match 'SAE') { return 'WPA3Personal' }
    if ($Token -match 'WPA3' -and ($Token -match 'ENT' -or $Token -match 'ENTERPRISE')) {
        if ($Token -match '192') { return 'WPA3Enterprise192' }
        if ($Token -match 'TRANS') { return 'WPA3EnterpriseTransition' }
        return 'WPA3Enterprise'
    }
    if ($Token -match 'WPA2' -and ($Token -match 'PSK' -or $Token -match 'PERSONAL')) { return 'WPA2Personal' }
    if ($Token -match 'WPA2' -and ($Token -match 'ENT' -or $Token -match 'ENTERPRISE')) { return 'WPA2Enterprise' }
    if ($Token -eq 'WPA2') {
        if ($UseOneX -ne $null) {
            if ($UseOneX) { return 'WPA2Enterprise' }
            return 'WPA2Personal'
        }
        return 'WPA2'
    }
    if ($Token -match 'WPA' -and ($Token -match 'PSK' -or $Token -match 'PERSONAL')) { return 'WPAPersonal' }
    if ($Token -match 'WPA' -and ($Token -match 'ENT' -or $Token -match 'ENTERPRISE')) { return 'WPAEnterprise' }
    if ($Token -match 'WEP') { return 'WEP' }
    if ($Token -match 'OPEN' -or $Token -match 'NONE') { return 'Open' }
    if ($Token -match 'SAE') { return 'WPA3Personal' }

    return $null
}

function Get-WlanSecurityCategory {
    param(
        [string[]]$AuthTexts,
        [Nullable[bool]]$UseOneX
    )

    foreach ($auth in $AuthTexts) {
        $token = Normalize-WlanAuthToken $auth
        $category = Get-WlanSecurityCategoryFromToken -Token $token -UseOneX $UseOneX
        if ($category) { return $category }
    }

    if ($UseOneX -ne $null) {
        if ($UseOneX) { return 'WPA2Enterprise' }
        return 'WPA2Personal'
    }

    return $null
}

function Test-WlanCipherIncludesTkip {
    param([string[]]$CipherTexts)

    foreach ($cipher in $CipherTexts) {
        if (-not $cipher) { continue }
        $token = Normalize-WlanAuthToken $cipher
        if ($token -match 'TKIP') { return $true }
    }

    return $false
}
