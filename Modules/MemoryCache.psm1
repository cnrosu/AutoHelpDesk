# Provides shared access to an application-domain wide MemoryCache instance.

try {
    Add-Type -AssemblyName 'System.Runtime.Caching' -ErrorAction Stop
} catch {
    # The assembly may already be loaded or unavailable on the current platform.
}

$script:CacheInstance = [System.Runtime.Caching.MemoryCache]::Default
$script:WrapperFlagName = '__AhdCacheWrapperSentinel'

function Get-AhdCacheValue {
    <#
        .SYNOPSIS
            Retrieves a cached value from the shared MemoryCache instance.

        .PARAMETER Key
            Unique identifier for the cached item. Keys are case-sensitive.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Key
    )

    $item = $script:CacheInstance.Get($Key)

    if ($item -is [psobject] -and $item.PSObject.Properties[$script:WrapperFlagName]) {
        return $item.Value
    }

    return $item
}

function Test-AhdCacheItem {
    <#
        .SYNOPSIS
            Determines whether the shared MemoryCache contains the specified key.

        .PARAMETER Key
            Unique identifier for the cached item. Keys are case-sensitive.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Key
    )

    return $script:CacheInstance.Contains($Key)
}

function Set-AhdCacheValue {
    <#
        .SYNOPSIS
            Stores a value in the shared MemoryCache with optional expiration policies.

        .PARAMETER Key
            Unique identifier for the cached item. Keys are case-sensitive.

        .PARAMETER Value
            Object to cache. Accepts null.

        .PARAMETER SlidingExpiration
            Duration that resets after each access. Defaults to 30 minutes when no expiration is specified.

        .PARAMETER AbsoluteExpiration
            Absolute expiration timestamp. When provided, overrides SlidingExpiration.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Key,

        [Parameter()]
        [AllowNull()]
        $Value,

        [Parameter()]
        [Nullable[System.TimeSpan]]$SlidingExpiration,

        [Parameter()]
        [Nullable[System.DateTimeOffset]]$AbsoluteExpiration
    )

    $policy = [System.Runtime.Caching.CacheItemPolicy]::new()

    if ($AbsoluteExpiration) {
        $policy.AbsoluteExpiration = $AbsoluteExpiration.Value
    } elseif ($SlidingExpiration) {
        $policy.SlidingExpiration = $SlidingExpiration.Value
    } else {
        $policy.SlidingExpiration = [System.TimeSpan]::FromMinutes(30)
    }

    $cacheValue = $Value
    if ($null -eq $Value) {
        $cacheValue = [pscustomobject]@{
            ($script:WrapperFlagName) = $true
            Value                     = $null
        }
    }

    $script:CacheInstance.Set($Key, $cacheValue, $policy) | Out-Null
}

function Remove-AhdCacheValue {
    <#
        .SYNOPSIS
            Removes a cached value from the shared MemoryCache instance.

        .PARAMETER Key
            Unique identifier for the cached item. Keys are case-sensitive.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Key
    )

    $null = $script:CacheInstance.Remove($Key)
}

function Clear-AhdCache {
    <#
        .SYNOPSIS
            Clears the shared MemoryCache instance.
    #>
    [CmdletBinding()]
    param()

    # Trim removes a percentage of cache entries. Passing 100 clears all items.
    $script:CacheInstance.Trim(100) | Out-Null
}

Export-ModuleMember -Function @(
    'Get-AhdCacheValue',
    'Test-AhdCacheItem',
    'Set-AhdCacheValue',
    'Remove-AhdCacheValue',
    'Clear-AhdCache'
)
