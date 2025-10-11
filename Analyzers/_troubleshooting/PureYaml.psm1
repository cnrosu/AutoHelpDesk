# PureYaml.psm1
<#
.SYNOPSIS
  Pure PowerShell YAML -> PSObject parser.

.DESCRIPTION
  A dependency-free YAML 1.2-oriented reader for everyday configs:
  - Multi-doc (--- / ...)
  - Mappings, Sequences (block & flow)
  - Scalars (quoted/unquoted), block scalars (| and > with chomp/indent)
  - Comments (#), anchors & aliases (basic), null/bool/num/float/datetime coercion
  - Line/column-aware errors

.LIMITATIONS
  - No merge keys (<<)
  - No custom tags beyond !!str|!!int|!!float|!!bool|!!null (others pass-through as strings)
  - No JSON schema/tag resolution, no binary, set, or ordered map types
  - Tabs are forbidden in indentation (as per YAML). Use spaces.

.EXPORTS
  ConvertFrom-Yaml
  Test-Yaml
  Measure-Yaml (structure preview)

#>

Set-StrictMode -Version Latest

#region: Helpers ----------------------------------------------------------------

function New-YamlError {
  param(
    [string]$Message,
    [int]$Line = 0,
    [int]$Column = 0,
    [string]$LineText = ''
  )
  $err = [System.Management.Automation.ErrorRecord]::new(
    ([System.Exception]::new(
      ("YAML parse error at L{0}:C{1}: {2}`n  >> {3}" -f $Line, $Column, $Message, $LineText)
    )),
    "PureYaml.ParseError",
    [System.Management.Automation.ErrorCategory]::InvalidData,
    $null
  )
  $err
}

function _Is-BlankLine([string]$s) { $null -ne $s -and ($s.Trim() -eq '' -or $s -match '^\s*#') }

function _Detab {
  param([string[]]$Lines)
  # Tabs are invalid in indentation; fail fast if used for indent
  for ($i=0; $i -lt $Lines.Count; $i++) {
    $line = $Lines[$i]
    if ($line -match '^\t+') {
      throw (New-YamlError -Message "Tabs are not allowed for indentation." -Line ($i+1) -Column 1 -LineText $line)
    }
    # Keep inner tabs (inside quotes or scalar text) as-is; only guard leftmost run.
  }
  ,$Lines
}

function _Strip-Comment {
  param([string]$s)
  if ($null -eq $s) { return $null }
  # Respect quotes; only cut '#' when not inside quotes
  $inS = $false; $inD = $false
  for ($i=0; $i -lt $s.Length; $i++) {
    $ch = $s[$i]
    if ($ch -eq "'" -and -not $inD) {
      $inS = -not $inS
    } elseif ($ch -eq '"' -and -not $inS) {
      # handle \" escape
      if ($i -gt 0 -and $s[$i-1] -eq '\') { } else { $inD = -not $inD }
    } elseif ($ch -eq '#' -and -not $inS -and -not $inD) {
      return ($s.Substring(0,$i)).TrimEnd()
    }
  }
  $s.TrimEnd()
}

function _Unquote {
  param([string]$s, [int]$line = 0, [string]$lineText = '')
  if ($null -eq $s) { return $null }
  if ($s.Length -ge 2 -and $s[0] -eq '"' -and $s[-1] -eq '"') {
    # Double-quoted: unescape
    $inner = $s.Substring(1, $s.Length-2)
    $inner = $inner -replace '\\n', "`n"
    $inner = $inner -replace '\\r', "`r"
    $inner = $inner -replace '\\t', "`t"
    $inner = $inner -replace '\\"', '"'
    $inner = $inner -replace '\\\\', '\'
    return $inner
  }
  if ($s.Length -ge 2 -and $s[0] -eq "'" -and $s[-1] -eq "'") {
    # Single-quoted: '' => '
    $inner = $s.Substring(1, $s.Length-2)
    return ($inner -replace "''","'")
  }
  $s
}

function _Try-CoerceScalar {
  param([string]$s)
  if ($null -eq $s) { return $null }

  # explicit tags (simple subset)
  if ($s -match '^\s*!!(str|int|float|bool|null)\s+(.*)$') {
    $tag = $Matches[1]; $rest = $Matches[2]
    switch ($tag) {
      'str' { return [string](_Unquote $rest) }
      'int' {
        if ($rest -match '^[+-]?\d+$') { return [int64]$rest }
        return $rest
      }
      'float' {
        if ($rest -match '^[+-]?(\d+(\.\d*)?|\.\d+)([eE][+-]?\d+)?$') { return [double]$rest }
        return $rest
      }
      'bool' {
        if ($rest -match '^(true|false)$') { return [bool]::Parse($rest.ToLowerInvariant()) }
        return $rest
      }
      'null' { return $null }
    }
  }

  $t = $s.Trim()

  # Nulls
  if ($t -match '^(~|null)$') { return $null }

  # Booleans
  if ($t -match '^(true|false)$') { return [bool]::Parse($t.ToLowerInvariant()) }

  # Inf/NaN
  if ($t -match '^[+-]?\.inf$') { return [double]::PositiveInfinity * ([math]::Sign(($t -like '-*') ? -1 : 1)) }
  if ($t -match '^\.nan$') { return [double]::NaN }

  # Integers (no underscores per spec subset)
  if ($t -match '^[+-]?\d+$') {
    # Use Int64 to be safe; PowerShell auto-widens where needed
    try { return [int64]$t } catch { }
  }

  # Floats
  if ($t -match '^[+-]?(\d+(\.\d*)?|\.\d+)([eE][+-]?\d+)?$') {
    try { return [double]$t } catch { }
  }

  # Timestamp (best-effort ISO 8601)
  # Examples: 2025-10-11, 2025-10-11T14:23:10Z, 2025-10-11 14:23:10+11:00
  if ($t -match '^\d{4}-\d{2}-\d{2}([Tt ]\d{2}:\d{2}:\d{2}(\.\d+)?([Zz]|[+-]\d{2}:\d{2})?)?$') {
    try { return [datetime]::Parse($t, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::RoundtripKind) } catch { }
  }

  # Quoted -> unquote
  if (($t.StartsWith('"') -and $t.EndsWith('"')) -or ($t.StartsWith("'") -and $t.EndsWith("'"))) {
    return _Unquote -s $t
  }

  # Plain string
  $t
}

class _YamlCursor {
  [string[]]$Lines
  [int]$Index
  _YamlCursor([string[]]$lines) {
    $this.Lines = $lines
    $this.Index = 0
  }
  [bool] End() { return $this.Index -ge $this.Lines.Count }
  [string] Peek() {
    if ($this.End()) { return $null }
    return $this.Lines[$this.Index]
  }
  [string] Read() {
    if ($this.End()) { return $null }
    $l = $this.Lines[$this.Index]
    $this.Index++
    return $l
  }
  [int] LineNo() { return [Math]::Min($this.Index+1, $this.Lines.Count) }
}

function _Count-Indent([string]$s) {
  $n=0; for ($i=0;$i -lt $s.Length -and $s[$i] -eq ' ';$i++){ $n++ }
  $n
}

function _TrimStartN([string]$s, [int]$n) {
  if ($n -le 0) { return $s }
  if ($n -ge $s.Length) { return '' }
  return $s.Substring($n)
}

function _Parse-Documents {
  param([string[]]$Lines)
  $cur = [ _YamlCursor ]::new( (_Detab $Lines) )

  $docs = New-Object System.Collections.ArrayList
  while (-not $cur.End()) {
    # Skip blank lines & leading end markers
    while (-not $cur.End() -and _Is-BlankLine($cur.Peek())) { [void]$cur.Read() }
    if ($cur.End()) { break }

    # Optional '---'
    if ($cur.Peek().Trim() -eq '---') { [void]$cur.Read() }

    # Collect until '...' or file end
    $buf = New-Object System.Collections.Generic.List[string]
    while (-not $cur.End()) {
      $line = $cur.Peek()
      if ($line.Trim() -eq '...') { [void]$cur.Read(); break }
      $buf.Add($line) | Out-Null
      [void]$cur.Read()
    }

    $node = _Parse-NodeBlock -Lines $buf.ToArray() -BaseLine 1
    [void]$docs.Add($node)
  }

  if ($docs.Count -eq 0) { $null } elseif ($docs.Count -eq 1) { $docs[0] } else { ,$docs.ToArray() }
}

function _Parse-NodeBlock {
  param(
    [string[]]$Lines,
    [int]$BaseLine = 1
  )

  # Strip leading blanks
  $i=0
  while ($i -lt $Lines.Count -and _Is-BlankLine($Lines[$i])) { $i++ }
  if ($i -ge $Lines.Count) { return $null }
  $sub = $Lines[$i..($Lines.Count-1)]

  # Decide top node: sequence, mapping, or flow/scalar
  $first = $sub[0]
  $indent0 = _Count-Indent $first
  $firstStripped = _TrimStartN $first $indent0

  if ($firstStripped -match '^- ') {
    return _Parse-SequenceBlock -Lines $sub -Indent $indent0 -BaseLine ($BaseLine+$i)
  }
  if ($firstStripped -match '^(?:["''].*["'']|[^\[\{].*?):') {
    return _Parse-MappingBlock -Lines $sub -Indent $indent0 -BaseLine ($BaseLine+$i)
  }

  # Flow or scalar or block scalar
  return _Parse-FlowOrScalar -Lines $sub -BaseLine ($BaseLine+$i)
}

function _Parse-SequenceBlock {
  param([string[]]$Lines,[int]$Indent,[int]$BaseLine)
  $items = New-Object System.Collections.ArrayList
  for ($i=0; $i -lt $Lines.Count;) {
    $line = $Lines[$i]
    if (_Is-BlankLine $line) { $i++; continue }
    $ind = _Count-Indent $line
    if ($ind -lt $Indent) { break }
    if ($ind -gt $Indent) {
      # Continuation of previous item's nested block
      # Shouldn't happen at a new dash; handled inside item parse
      $i++
      continue
    }
    $text = _TrimStartN $line $Indent
    if ($text -notmatch '^- ') {
      # End of this sequence block
      break
    }
    $afterDash = $text.Substring(2)

    if ($afterDash.Trim() -eq '') {
      # Item is nested block on following lines
      # Collect child block (indent > Indent)
      $start = $i+1
      $j = $start
      while ($j -lt $Lines.Count) {
        $l2 = $Lines[$j]
        if (_Is-BlankLine $l2) { $j++; continue }
        $ind2 = _Count-Indent $l2
        if ($ind2 -le $Indent) { break }
        $j++
      }
      $childLines = @()
      if ($j -gt $start) { $childLines = $Lines[$start..($j-1)] }
      $val = if ($childLines.Count -gt 0) { _Parse-NodeBlock -Lines $childLines -BaseLine ($BaseLine+$start) } else { $null }
      [void]$items.Add($val)
      $i = $j
    } else {
      # Item with inline value
      $inline = _Strip-Comment $afterDash
      if ($inline -match '^\[|^\{') {
        $val = _Parse-Flow -Text $inline -LineNo ($BaseLine+$i) -LineText $line
        [void]$items.Add($val)
        $i++
      } elseif ($inline.TrimStart().StartsWith('|') -or $inline.TrimStart().StartsWith('>')) {
        # block scalar attached to item
        $block = _Parse-BlockScalar -Lines $Lines -IndexRef ([ref]$i) -Indent $Indent -BaseLine $BaseLine
        [void]$items.Add($block)
      } else {
        $val = _Try-CoerceScalar (_Unquote $inline)
        [void]$items.Add($val)
        $i++
      }
    }
  }
  ,$items
}

function _Parse-MappingBlock {
  param([string[]]$Lines,[int]$Indent,[int]$BaseLine)

  $map = [ordered]@{}
  $anchors = @{} # basic anchor registry at current mapping scope

  for ($i=0; $i -lt $Lines.Count;) {
    $line = $Lines[$i]
    if (_Is-BlankLine $line) { $i++; continue }
    $ind = _Count-Indent $line
    if ($ind -lt $Indent) { break }
    if ($ind -gt $Indent) {
      # Continuation of previous key's nested block
      $i++; continue
    }

    $text = _TrimStartN $line $Indent
    # Key parse: respect quotes; split at first ':' not in quotes / flow
    $split = _Find-KeyValueSplit -Text $text -LineNo ($BaseLine+$i) -LineText $line
    if ($split.Index -lt 0) {
      # Not a key line -> end mapping block
      break
    }
    $kRaw = $text.Substring(0, $split.Index).Trim()
    $vRaw = $text.Substring($split.Index+1)  # retain trailing for nested vs inline

    $key = _Unquote $kRaw
    if ([string]::IsNullOrWhiteSpace($key)) {
      throw (New-YamlError -Message "Empty key not allowed." -Line ($BaseLine+$i) -Column 1 -LineText $line)
    }

    # Anchors on key line (rare): ignore, but support &name after value; aliases on value handled below
    $vTrim = (_Strip-Comment $vRaw).Trim()

    if ($vTrim -eq '') {
      # Nested block follows
      $start = $i+1
      $j = $start
      while ($j -lt $Lines.Count) {
        $l2 = $Lines[$j]
        if (_Is-BlankLine $l2) { $j++; continue }
        $ind2 = _Count-Indent $l2
        if ($ind2 -le $Indent) { break }
        $j++
      }
      $childLines = @()
      if ($j -gt $start) { $childLines = $Lines[$start..($j-1)] }
      $val = if ($childLines.Count -gt 0) { _Parse-NodeBlock -Lines $childLines -BaseLine ($BaseLine+$start) } else { $null }
      $map[$key] = $val
      $i = $j
      continue
    }

    # Inline value on same line
    # Handle alias first: *anchor
    if ($vTrim -match '^\*(\w+)$') {
      $name = $Matches[1]
      if (-not $script:__yaml_anchors.ContainsKey($name)) {
        throw (New-YamlError -Message "Unknown alias '*$name'." -Line ($BaseLine+$i) -Column ($split.Index+2) -LineText $line)
      }
      $map[$key] = $script:__yaml_anchors[$name]
      $i++; continue
    }

    # Block scalar indicator (| or >) on same line
    if ($vTrim.StartsWith('|') -or $vTrim.StartsWith('>')) {
      $indexRef = [ref]$i
      $scalar = _Parse-BlockScalar -Lines $Lines -IndexRef $indexRef -Indent $Indent -BaseLine $BaseLine -InlineIndicator $vTrim
      $map[$key] = $scalar
      $i = $indexRef.Value
      continue
    }

    # Flow collection inline
    if ($vTrim -match '^\[|^\{') {
      $val = _Parse-Flow -Text $vTrim -LineNo ($BaseLine+$i) -LineText $line
      $map[$key] = $val
      $i++; continue
    }

    # Scalar (possibly with anchor)
    if ($vTrim -match '^&(\w+)\s+(.*)$') {
      $an = $Matches[1]; $rest = $Matches[2]
      $val = _Try-CoerceScalar (_Unquote $rest)
      $map[$key] = $val
      $script:__yaml_anchors[$an] = $val
      $i++; continue
    }

    $map[$key] = _Try-CoerceScalar (_Unquote $vTrim)
    $i++
  }

  [pscustomobject]$map
}

function _Find-KeyValueSplit {
  param([string]$Text,[int]$LineNo,[string]$LineText)
  $inS=$false;$inD=$false;$depth=0
  for ($i=0; $i -lt $Text.Length; $i++) {
    $ch = $Text[$i]
    if ($ch -eq "'" -and -not $inD) { $inS = -not $inS; continue }
    if ($ch -eq '"' -and -not $inS) {
      if ($i -gt 0 -and $Text[$i-1] -eq '\') { } else { $inD = -not $inD }
      continue
    }
    if ($inS -or $inD) { continue }
    if ($ch -eq '[' -or $ch -eq '{') { $depth++ ; continue }
    if ($ch -eq ']' -or $ch -eq '}') { if ($depth -gt 0) { $depth-- } ; continue }
    if ($ch -eq ':' -and $depth -eq 0) {
      return @{ Index = $i }
    }
  }
  return @{ Index = -1 }
}

function _Parse-FlowOrScalar {
  param([string[]]$Lines,[int]$BaseLine)

  $first = $Lines[0]
  $indent = _Count-Indent $first
  $text = (_Strip-Comment (_TrimStartN $first $indent))

  # block scalar introduced alone
  if ($text -match '^[|>].*$') {
    $i = 0
    return _Parse-BlockScalar -Lines $Lines -IndexRef ([ref]$i) -Indent $indent -BaseLine $BaseLine
  }

  if ($text -match '^\[|^\{') {
    return _Parse-Flow -Text $text -LineNo $BaseLine -LineText $first
  }

  # Plain scalar
  return _Try-CoerceScalar (_Unquote $text)
}

function _Parse-Flow {
  param([string]$Text,[int]$LineNo,[string]$LineText)

  $t = _Strip-Comment $Text
  $t = $t.Trim()
  if ($t.StartsWith('[')) {
    # Flow sequence
    $content = $t.TrimStart('[').TrimEnd(']')
    $parts = _Flow-SplitCSV $content $LineNo $LineText
    $arr = New-Object System.Collections.ArrayList
    foreach ($p in $parts) {
      $p2 = $p.Trim()
      if ($p2 -match '^\[|^\{') {
        [void]$arr.Add( _Parse-Flow -Text $p2 -LineNo $LineNo -LineText $LineText )
      } else {
        [void]$arr.Add( _Try-CoerceScalar (_Unquote $p2) )
      }
    }
    ,$arr
  } elseif ($t.StartsWith('{')) {
    # Flow mapping
    $content = $t.TrimStart('{').TrimEnd('}')
    $pairs = _Flow-SplitCSV $content $LineNo $LineText
    $map = [ordered]@{}
    foreach ($kv in $pairs) {
      if ([string]::IsNullOrWhiteSpace($kv)) { continue }
      $split = _Find-KeyValueSplit -Text $kv -LineNo $LineNo -LineText $LineText
      if ($split.Index -lt 0) {
        throw (New-YamlError -Message "Expected ':' in flow mapping entry." -Line $LineNo -Column 1 -LineText $LineText)
      }
      $k = _Unquote ($kv.Substring(0,$split.Index).Trim())
      $v = ($kv.Substring($split.Index+1)).Trim()
      if ($v -match '^\[|^\{') {
        $map[$k] = _Parse-Flow -Text $v -LineNo $LineNo -LineText $LineText
      } else {
        $map[$k] = _Try-CoerceScalar (_Unquote $v)
      }
    }
    [pscustomobject]$map
  } else {
    throw (New-YamlError -Message "Invalid flow collection." -Line $LineNo -Column 1 -LineText $LineText)
  }
}

function _Flow-SplitCSV {
  param([string]$Text,[int]$LineNo,[string]$LineText)
  # Split on commas not in quotes or nested flow
  $parts = @()
  $inS=$false;$inD=$false;$depth=0;$start=0
  for ($i=0; $i -lt $Text.Length; $i++) {
    $ch = $Text[$i]
    if ($ch -eq "'" -and -not $inD) { $inS = -not $inS; continue }
    if ($ch -eq '"' -and -not $inS) {
      if ($i -gt 0 -and $Text[$i-1] -eq '\') { } else { $inD = -not $inD }
      continue
    }
    if ($inS -or $inD) { continue }
    if ($ch -eq '[' -or $ch -eq '{') { $depth++; continue }
    if ($ch -eq ']' -or $ch -eq '}') { if ($depth -gt 0) { $depth-- } ; continue }
    if ($ch -eq ',' -and $depth -eq 0) {
      $parts += $Text.Substring($start, $i-$start)
      $start = $i+1
    }
  }
  $parts += $Text.Substring($start)
  $parts
}

function _Parse-BlockScalar {
  param(
    [string[]]$Lines,
    [ref]$IndexRef,
    [int]$Indent,
    [int]$BaseLine,
    [string]$InlineIndicator
  )
  # If indicator is on same line (InlineIndicator) use that; else read current line's indicator
  $i = $IndexRef.Value
  $line = $Lines[$i]
  $ind = _Count-Indent $line
  $header = if ($InlineIndicator) { $InlineIndicator } else { _TrimStartN $line $ind }
  $header = _Strip-Comment $header

  if ($header -notmatch '^[|>][+-]?\d?$') {
    # If had extra trailing, allow but trim after indicator
    if ($header -match '^([|>][+-]?\d?)\s+.*$') {
      $header = $Matches[1]
    } else {
      throw (New-YamlError -Message "Invalid block scalar header '$header'." -Line ($BaseLine+$i) -Column 1 -LineText $line)
    }
  }

  $fold = $header[0] -eq '>'
  $chomp = 'keep'  # default: clip (no explicit), but easier: treat as 'clip' unless + or -
  $chomp = if ($header -match '^[|>]\+$') { 'keep' } elseif ($header -match '^[|>]-$') { 'strip' } elseif ($header -match '^[|>][+-]\d$') { if ($header[1] -eq '+') {'keep'} else {'strip'} } else { 'clip' }
  $indentIndicator = $null
  if ($header -match '\d$') { $indentIndicator = [int]$header[-1].ToString() }

  # Move to next line; collect lines with indent > base indent (or specified indentIndicator)
  $i++
  $content = New-Object System.Collections.Generic.List[string]
  $minIndent = $null
  for (; $i -lt $Lines.Count; $i++) {
    $l = $Lines[$i]
    if (_Is-BlankLine $l) {
      $content.Add('') | Out-Null
      continue
    }
    $ind2 = _Count-Indent $l
    if ($ind2 -le $Indent) { break }
    $content.Add($l) | Out-Null
    if ($null -eq $minIndent -or $ind2 -lt $minIndent) { $minIndent = $ind2 }
  }

  if ($content.Count -eq 0) {
    $IndexRef.Value = $i
    return ''
  }

  $stripBy = if ($indentIndicator) { $Indent + $indentIndicator } else { $minIndent }
  $textLines = foreach ($cl in $content) {
    if ($cl.Length -ge $stripBy) { _TrimStartN $cl $stripBy } else { '' }
  }

  # Apply folding / chomping
  $result = if ($fold) {
    # Fold: lines separated by single newline unless blank lines (become newlines)
    $buf = New-Object System.Text.StringBuilder
    for ($k=0; $k -lt $textLines.Count; $k++) {
      $t = $textLines[$k]
      if ($k -gt 0) {
        if ($t -eq '' -or $textLines[$k-1] -eq '') {
          [void]$buf.Append("`n")
        } else {
          [void]$buf.Append(' ')
        }
      }
      [void]$buf.Append($t)
    }
    $buf.ToString()
  } else {
    ($textLines -join "`n")
  }

  # Chomp
  switch ($chomp) {
    'strip' { $result = $result.TrimEnd("`r","`n") }
    'clip'  {
      # Ensure exactly one trailing newline
      $result = $result.TrimEnd("`r","`n") + "`n"
    }
    'keep' { # leave as-is
    }
  }

  $IndexRef.Value = $i
  $result
}

# Global anchor table across a document parse
$script:__yaml_anchors = @{}

#endregion ----------------------------------------------------------------------

#region: Public API -------------------------------------------------------------

function ConvertFrom-Yaml {
<#
.SYNOPSIS
  Parses YAML text into native PowerShell objects (Hashtable/ArrayList/PSCustomObject).

.PARAMETER Yaml
  YAML text (string) or path to a YAML file.

.PARAMETER AsHashtable
  Return mappings as Hashtable rather than PSCustomObject.

.EXAMPLE
  $obj = ConvertFrom-Yaml -Yaml (Get-Content .\config.yaml -Raw)

.EXAMPLE
  ConvertFrom-Yaml -Yaml .\multi-doc.yaml
#>
  [CmdletBinding()]
  param(
    [Parameter(Mandatory, Position=0, ValueFromPipeline)]
    [Alias('Path')]
    [string]$Yaml,
    [switch]$AsHashtable
  )
  begin { }
  process {
    $text = if (Test-Path -LiteralPath $Yaml) { Get-Content -LiteralPath $Yaml -Raw } else { $Yaml }
    if ([string]::IsNullOrWhiteSpace($text)) { return $null }

    # Normalize line endings
    $lines = $text -replace "`r`n","`n" -replace "`r","`n" -split "`n"

    # Reset anchors per document set
    $script:__yaml_anchors = @{}

    $doc = _Parse-Documents -Lines $lines

    if ($AsHashtable) {
      return _To-Hashtable $doc
    }
    $doc
  }
}

function _To-Hashtable {
  param($obj)
  if ($null -eq $obj) { return $null }
  if ($obj -is [System.Collections.IList]) {
    $al = New-Object System.Collections.ArrayList
    foreach ($v in $obj) { [void]$al.Add( (_To-Hashtable $v) ) }
    return ,$al
  }
  if ($obj -is [pscustomobject]) {
    $ht = [ordered]@{}
    foreach ($p in $obj.PSObject.Properties) {
      $ht[$p.Name] = _To-Hashtable $p.Value
    }
    return $ht
  }
  $obj
}

function Test-Yaml {
<#
.SYNOPSIS
  Validates YAML and returns $true or $false with detailed errors.

.PARAMETER Yaml
  YAML content or file path.

.EXAMPLE
  Test-Yaml .\config.yaml
#>
  [CmdletBinding()]
  param(
    [Parameter(Mandatory, Position=0, ValueFromPipeline)]
    [Alias('Path')]
    [string]$Yaml
  )
  try {
    [void](ConvertFrom-Yaml -Yaml $Yaml) ; $true
  } catch {
    Write-Error $_.Exception.Message
    $false
  }
}

function Measure-Yaml {
<#
.SYNOPSIS
  Quick structure preview of a YAML document.

.DESCRIPTION
  Prints a compact outline for sanity-checking the parse tree.

.PARAMETER Yaml
  YAML content or file path.
#>
  [CmdletBinding()]
  param(
    [Parameter(Mandatory, Position=0)]
    [Alias('Path')]
    [string]$Yaml
  )
  $doc = ConvertFrom-Yaml -Yaml $Yaml
  _Outline $doc 0
}

function _Outline {
  param($obj,[int]$depth)
  $pad = '  ' * $depth
  switch -Regex ($obj.GetType().FullName) {
    'ArrayList' {
      "{0}- seq[{1}]" -f $pad, $obj.Count
      $i=0; foreach ($v in $obj) { "{0}  [{1}]" -f $pad, $i; _Outline $v ($depth+2); $i++ }
    }
    'System.Collections.Hashtable' {
      "{0}- map#{1}" -f $pad, $obj.Keys.Count
      foreach ($k in $obj.Keys) { "{0}  {1}:" -f $pad, $k; _Outline $obj[$k] ($depth+2) }
    }
    'System.Management.Automation.PSCustomObject' {
      $props = $_ = $obj.PSObject.Properties
      "{0}- map#{1}" -f $pad, $props.Count
      foreach ($p in $props) { "{0}  {1}:" -f $pad, $p.Name; _Outline $p.Value ($depth+2) }
    }
    default {
      "{0}- {1} :: {2}" -f $pad, $obj.GetType().Name, ($obj -replace "`n",'⏎')
    }
  }
}

Export-ModuleMember -Function ConvertFrom-Yaml,Test-Yaml,Measure-Yaml

#endregion ----------------------------------------------------------------------
