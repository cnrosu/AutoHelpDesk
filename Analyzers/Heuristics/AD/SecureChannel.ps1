function Add-AdSecureChannelFindings {
    param(
        [Parameter(Mandatory)]
        $Result,
        $SecureInfo
    )

    $scBroken = $false
    if ($SecureInfo) {
        $scTest = $SecureInfo.TestComputerSecureChannel
        if ($scTest) {
            if ($scTest.Succeeded -eq $true -and $scTest.IsSecure -eq $false) {
                $scBroken = $true
            } elseif ($scTest.Succeeded -eq $true -and $scTest.IsSecure -eq $true) {
                Add-CategoryNormal -CategoryResult $Result -Title 'GOOD SecureChannel (verified)' -Subcategory 'Secure Channel'
            }
        }
        if ($SecureInfo.NltestScQuery) {
            $outputText = $SecureInfo.NltestScQuery.Output -join ' '
            if ($outputText -match 'NO_LOGON_SERVERS' -or $outputText -match 'TRUST_FAILURE' -or $outputText -match 'STATUS=\s*0xC000018D') {
                $scBroken = $true
            }
        }
        if ($scTest -and $scTest.Succeeded -eq $false -and $scTest.Error) {
            Add-CategoryIssue -CategoryResult $Result -Severity 'medium' -Title 'Secure channel verification failed to run, so machine trust status is unknown.' -Evidence $scTest.Error -Subcategory 'Secure Channel' -Remediation (Get-AdKerberosSecureChannelTimeRemediation)
        }
    }

    if ($scBroken) {
        Add-CategoryIssue -CategoryResult $Result -Severity 'high' -Title 'Broken machine secure channel, blocking domain authentication.' -Subcategory 'Secure Channel' -Remediation (Get-AdKerberosSecureChannelTimeRemediation)
    }

    [pscustomobject]@{
        SecureChannelBroken = $scBroken
    }
}
