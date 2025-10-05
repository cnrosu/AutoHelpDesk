$script:PasswordStrengthCache = @{
    CommonPasswords = $null
}

function Get-PasswordStrengthCommonPasswords {
    if ($null -ne $script:PasswordStrengthCache.CommonPasswords) {
        return $script:PasswordStrengthCache.CommonPasswords
    }

    $moduleRoot = Split-Path -Path $PSCommandPath -Parent
    $dataPath = Join-Path -Path $moduleRoot -ChildPath 'Data/10k-most-common.txt'

    $list = @()
    if (Test-Path -LiteralPath $dataPath) {
        try {
            $list = Get-Content -LiteralPath $dataPath -ErrorAction Stop |
                ForEach-Object { $_.Trim() } |
                Where-Object { $_ }
        } catch {
            $list = @()
        }
    }

    $script:PasswordStrengthCache.CommonPasswords = $list
    return $list
}

function Test-PasswordStrength {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Password,

        [string[]]$KnownBadPasswords = @(),

        [double]$OnlineGuessesPerSecond  = 1.0,
        [double]$OfflineGuessesPerSecond = 1e10,

        [switch]$IncludePassword
    )

    $passwordText = [string]$Password
    if (-not $passwordText) {
        return [pscustomobject]@{
            Score              = 0
            Category           = 'Very Weak'
            EstimatedBits      = 0
            EstimatedGuesses   = '0'
            CrackTimeOnline_s  = 0
            CrackTimeOffline_s = 0
            AlphabetSizeUsed   = 0
            Length             = 0
            Warnings           = @('Empty password.')
            Suggestions        = @('Use a passphrase of 3–4+ uncommon words (14–20+ chars).')
            Signals            = @('Empty')
            BaselineBits       = 0
            PenaltyBits        = 0
            Notes              = 'Password was empty. Metrics defaulted to zero.'
        }
    }

    $common = Get-PasswordStrengthCommonPasswords
    $knownBad = ($common + $KnownBadPasswords) | Select-Object -Unique

    $leetMap = @{
        '0'='o'; '1'='l'; '2'='z'; '3'='e'; '4'='a'; '5'='s'; '6'='g'; '7'='t'; '8'='b'; '9'='g';
        '$'='s'; '@'='a'; '!'='i'
    }

    function Normalize-Leet {
        param([string]$Input)
        if (-not $Input) { return $Input }
        ($Input.ToCharArray() | ForEach-Object {
            $ch = $_
            if ($leetMap.ContainsKey($ch)) { $leetMap[$ch] } else { $ch }
        }) -join ''
    }

    $pwLower = $passwordText.ToLowerInvariant()
    $pwLeetLower = Normalize-Leet -Input $pwLower

    $warnings = New-Object System.Collections.Generic.List[string]
    $suggestions = New-Object System.Collections.Generic.List[string]
    $signals = New-Object System.Collections.Generic.List[string]

    if ($knownBad -contains $pwLower -or $knownBad -contains $pwLeetLower) {
        $warnings.Add('This password (or leetspeak variant) appears in common/compromised lists.') | Out-Null
        $suggestions.Add('Use a passphrase of 3–4+ uncommon words (14–20+ chars).') | Out-Null
        $suggestions.Add('Avoid common words, years, and keyboard patterns.') | Out-Null

        $result = [ordered]@{
            Score              = 0
            Category           = 'Very Weak'
            EstimatedBits      = 0
            EstimatedGuesses   = '1.00E+02'
            CrackTimeOnline_s  = if ($OnlineGuessesPerSecond -le 0) { [double]::PositiveInfinity } else { 1e2 / $OnlineGuessesPerSecond }
            CrackTimeOffline_s = if ($OfflineGuessesPerSecond -le 0) { [double]::PositiveInfinity } else { 1e2 / $OfflineGuessesPerSecond }
            AlphabetSizeUsed   = 0
            Length             = $passwordText.Length
            Warnings           = $warnings.ToArray()
            Suggestions        = $suggestions.ToArray()
            Signals            = @('Blocklisted')
            BaselineBits       = 0
            PenaltyBits        = 0
            Notes              = 'Password is in the blocklist; treated as very weak regardless of length.'
        }
        if ($IncludePassword) {
            $result['Password'] = $Password
        }
        return [pscustomobject]$result
    }

    $len = $passwordText.Length
    $lower = ($passwordText -cmatch '[a-z]')
    $upper = ($passwordText -cmatch '[A-Z]')
    $digit = ($passwordText -match '\d')
    $space = ($passwordText -match '\s')
    $symbol = ($passwordText -match '[^A-Za-z0-9\s]')

    $alphabet = 0
    if ($lower)  { $alphabet += 26 }
    if ($upper)  { $alphabet += 26 }
    if ($digit)  { $alphabet += 10 }
    if ($space)  { $alphabet += 1 }
    if ($symbol) { $alphabet += 33 }
    if ($alphabet -eq 0) { $alphabet = 1 }

    $baselineBits = $len * [math]::Log([double]$alphabet, 2)

    $penaltyBits = 0.0

    $repeatMatches = [regex]::Matches($passwordText, '(.)\1{2,}')
    if ($repeatMatches.Count -gt 0) {
        $repeatPenalty = [math]::Min($len * 0.5, ($repeatMatches.Count * 4))
        $penaltyBits += $repeatPenalty
        $signals.Add("Repeated runs (-$repeatPenalty bits)") | Out-Null
    }

    function Test-Sequence {
        param([string]$Sequence)
        if ($Sequence.Length -lt 3) { return $false }
        $asc = $true
        $desc = $true
        for ($i = 0; $i -lt $Sequence.Length - 1; $i++) {
            $cur = [int][char]$Sequence[$i]
            $next = [int][char]$Sequence[$i + 1]
            if ($next -ne ($cur + 1)) { $asc = $false }
            if ($next -ne ($cur - 1)) { $desc = $false }
        }
        return ($asc -or $desc)
    }

    $seqHits = 0
    for ($window = 3; $window -le [math]::Min($len, 8); $window++) {
        for ($i = 0; $i -le $len - $window; $i++) {
            $chunk = $pwLower.Substring($i, $window)
            if ($chunk -match '^[a-z]+$' -or $chunk -match '^\d+$') {
                if (Test-Sequence -Sequence $chunk) { $seqHits++ }
            }
        }
    }
    if ($seqHits -gt 0) {
        $seqPenalty = [math]::Min($len, 2 * $seqHits)
        $penaltyBits += $seqPenalty
        $signals.Add("Straight sequences x$seqHits (-$seqPenalty bits)") | Out-Null
    }

    $rows = @("`~1234567890-= ", "qwertyuiop[]\\ ", "asdfghjkl;' ", "zxcvbnm,./ ")
    $rowSeqHits = 0
    foreach ($row in $rows) {
        $reverse = ($row.ToCharArray()[-1..-($row.Length)] -join '')
        for ($window = 3; $window -le [math]::Min($len, 8); $window++) {
            for ($i = 0; $i -le $len - $window; $i++) {
                $chunk = $pwLower.Substring($i, $window)
                if ($chunk -notmatch '^[ -~]+$') { continue }
                if ($row.Contains($chunk) -or $reverse.Contains($chunk)) {
                    $rowSeqHits++
                }
            }
        }
    }
    if ($rowSeqHits -gt 0) {
        $kbPenalty = [math]::Min($len, 2 * $rowSeqHits)
        $penaltyBits += $kbPenalty
        $signals.Add("Keyboard walks x$rowSeqHits (-$kbPenalty bits)") | Out-Null
    }

    if ($len -ge 6) {
        for ($window = 2; $window -le [math]::Floor($len / 2); $window++) {
            $pattern = $pwLower.Substring(0, $window)
            $repeatCount = 0
            $position = 0
            while (($position + $window) -le $len) {
                if ($pwLower.Substring($position, $window) -eq $pattern) {
                    $repeatCount++
                    $position += $window
                } else {
                    break
                }
            }
            if ($repeatCount -ge 3) {
                $repPenalty = [math]::Min($len, 4 + 2 * ($repeatCount - 2))
                $penaltyBits += $repPenalty
                $signals.Add("Repeated substring '$pattern' x$repeatCount (-$repPenalty bits)") | Out-Null
                break
            }
        }
    }

    $dictionary = @(
        'password','welcome','admin','login','secret','qwerty','ilove','love','money',
        'summer','winter','spring','autumn','football','baseball','dragon','princess',
        'letmein','trustno1','master','shadow','sunshine','flower','pokemon','starwars',
        'microsoft','google','apple','orange','banana','cristian','bing','lee','store'
    )
    $dictHits = 0
    for ($window = 3; $window -le [math]::Min($len, 12); $window++) {
        for ($i = 0; $i -le $len - $window; $i++) {
            $chunk = $pwLower.Substring($i, $window)
            if ($dictionary -contains $chunk) {
                $dictHits++
            } else {
                $chunkLeet = Normalize-Leet -Input $chunk
                if ($dictionary -contains $chunkLeet) { $dictHits++ }
            }
        }
    }
    if ($dictHits -gt 0) {
        $dictPenalty = [math]::Min($len + 10, 5 * $dictHits)
        $penaltyBits += $dictPenalty
        $signals.Add("Dictionary/leet words x$dictHits (-$dictPenalty bits)") | Out-Null
    }

    $adjustedBits = [math]::Max(0.0, $baselineBits - $penaltyBits)
    $maxDoubleBits = [math]::Log([double]::MaxValue, 2)
    if ($adjustedBits -gt $maxDoubleBits) {
        $estimatedGuessesDouble = [double]::PositiveInfinity
    } else {
        $estimatedGuessesDouble = [math]::Pow(2, $adjustedBits)
    }

    if ([double]::IsInfinity($estimatedGuessesDouble)) {
        $estimatedGuessesDisplay = 'Inf'
        $onlineTimeSec  = [double]::PositiveInfinity
        $offlineTimeSec = [double]::PositiveInfinity
    } else {
        $estimatedGuessesDisplay = [string]([System.Globalization.CultureInfo]::InvariantCulture, '{0:0.###E+0}' -f $estimatedGuessesDouble)
        $onlineTimeSec  = if ($OnlineGuessesPerSecond -le 0) { [double]::PositiveInfinity } else { $estimatedGuessesDouble / $OnlineGuessesPerSecond }
        $offlineTimeSec = if ($OfflineGuessesPerSecond -le 0) { [double]::PositiveInfinity } else { $estimatedGuessesDouble / $OfflineGuessesPerSecond }
    }

    $score = 0
    if (-not [double]::IsInfinity($estimatedGuessesDouble)) {
        if     ($estimatedGuessesDouble -lt 1e3)  { $score = 0 }
        elseif ($estimatedGuessesDouble -lt 1e6)  { $score = 1 }
        elseif ($estimatedGuessesDouble -lt 1e8)  { $score = 2 }
        elseif ($estimatedGuessesDouble -lt 1e10) { $score = 3 }
        else                                      { $score = 4 }
    } else {
        $score = 4
    }

    $category = @('Very Weak','Weak','Fair','Strong','Very Strong')[$score]

    if ($len -lt 12) {
        $warnings.Add("Short length ($len). Length dominates strength.") | Out-Null
        $suggestions.Add('Use 14–20+ characters.') | Out-Null
    }
    if ($dictHits -gt 0) {
        $warnings.Add('Contains common word(s) or leetspeak words.') | Out-Null
        $suggestions.Add('Avoid common words, names, brands, and years.') | Out-Null
    }
    if ($rowSeqHits -gt 0 -or $seqHits -gt 0) {
        $warnings.Add('Contains sequences/keyboard walks.') | Out-Null
        $suggestions.Add('Break up straight runs (e.g., a→x, 1→7).') | Out-Null
    }
    if ($repeatMatches.Count -gt 0) {
        $warnings.Add('Contains repeated character runs.') | Out-Null
        $suggestions.Add("Avoid long runs like 'aaaa' or '1111'.") | Out-Null
    }
    if (-not $space -and -not $symbol -and -not $upper) {
        $suggestions.Add('Consider a multi-word passphrase with spaces for easier length.') | Out-Null
    }
    if ($score -lt 4 -and $len -lt 16) {
        $suggestions.Add('Add one or two uncommon words to lengthen.') | Out-Null
    }

    $result = [ordered]@{
        Score              = $score
        Category           = $category
        EstimatedBits      = [math]::Round($adjustedBits, 1)
        EstimatedGuesses   = $estimatedGuessesDisplay
        CrackTimeOnline_s  = $onlineTimeSec
        CrackTimeOffline_s = $offlineTimeSec
        AlphabetSizeUsed   = $alphabet
        Length             = $len
        Warnings           = $warnings.ToArray()
        Suggestions        = $suggestions.ToArray()
        Signals            = $signals.ToArray()
        BaselineBits       = [math]::Round($baselineBits, 1)
        PenaltyBits        = [math]::Round($penaltyBits, 1)
        Notes              = 'Estimates combine NIST blocklist guidance with zxcvbn-style guess counting.'
    }

    if ($IncludePassword) {
        $result['Password'] = $Password
    }

    return [pscustomobject]$result
}

Export-ModuleMember -Function Test-PasswordStrength -Verbose:$false
