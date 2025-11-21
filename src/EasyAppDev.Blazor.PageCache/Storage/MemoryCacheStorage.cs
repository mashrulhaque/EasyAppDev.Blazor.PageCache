using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Options;
using System.Collections.Concurrent;
using System.Text.RegularExpressions;
using EasyAppDev.Blazor.PageCache.Abstractions;
using EasyAppDev.Blazor.PageCache.Configuration;
using MemoryCacheEntryOptions = Microsoft.Extensions.Caching.Memory.MemoryCacheEntryOptions;
using MsEvictionReason = Microsoft.Extensions.Caching.Memory.EvictionReason;

namespace EasyAppDev.Blazor.PageCache.Storage;

/// <summary>
/// In-memory cache storage implementation using <see cref="IMemoryCache"/>.
/// </summary>
public sealed class MemoryCacheStorage : ICacheStorage
{
    private readonly IMemoryCache _cache;
    private readonly PageCacheOptions _options;
    private readonly ConcurrentDictionary<string, long> _cacheKeys = new(); // Track insertion order for LRU
    private readonly object _evictionLock = new(); // Ensure thread-safe eviction
    private long _sequence = 0; // Monotonic sequence for LRU ordering

    public MemoryCacheStorage(IMemoryCache cache, IOptions<PageCacheOptions> options)
    {
        _cache = cache ?? throw new ArgumentNullException(nameof(cache));
        _options = options?.Value ?? throw new ArgumentNullException(nameof(options));
    }

    /// <inheritdoc />
    public ValueTask<T?> GetAsync<T>(string key, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(key);
        cancellationToken.ThrowIfCancellationRequested();

        var result = _cache.TryGetValue<T>(key, out var value) && value != null
            ? value
            : default;

        // Update access time for LRU tracking when MaxCacheEntryCount is enabled
        if (result != null && _options.Security.MaxCacheEntryCount.HasValue && _cacheKeys.ContainsKey(key))
        {
            var newSequence = Interlocked.Increment(ref _sequence);
            _cacheKeys[key] = newSequence;
        }

        return ValueTask.FromResult(result);
    }

    /// <inheritdoc />
    public ValueTask SetAsync<T>(string key, T value, CacheEntryOptions options, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(key);
        ArgumentNullException.ThrowIfNull(value);
        ArgumentNullException.ThrowIfNull(options);
        cancellationToken.ThrowIfCancellationRequested();

        var entryOptions = new MemoryCacheEntryOptions();

        if (options.AbsoluteExpirationRelativeToNow.HasValue)
        {
            entryOptions.AbsoluteExpirationRelativeToNow = options.AbsoluteExpirationRelativeToNow.Value;
        }

        if (options.SlidingExpiration.HasValue)
        {
            entryOptions.SlidingExpiration = options.SlidingExpiration.Value;
        }

        if (options.Size.HasValue)
        {
            entryOptions.Size = options.Size.Value;
        }

        // Always register a callback to track removals in _cacheKeys
        // If user provided a callback, invoke it as well
        var userCallback = options.PostEvictionCallback;
        entryOptions.RegisterPostEvictionCallback((key, value, reason, state) =>
        {
            if (key is string cacheKey)
            {
                _cacheKeys.TryRemove(cacheKey, out _);

                // Invoke user callback if provided
                userCallback?.Invoke(cacheKey, value, MapEvictionReason(reason));
            }
        });

        // Allocate sequence number for this operation (before lock to minimize lock time)
        var newSequence = Interlocked.Increment(ref _sequence);

        // PHASE 2 SECURITY FIX: Enforce maximum entry count to prevent DoS
        if (_options.Security.MaxCacheEntryCount.HasValue)
        {
            var maxEntries = _options.Security.MaxCacheEntryCount.Value;

            lock (_evictionLock)
            {
                var isNewEntry = !_cacheKeys.ContainsKey(key);

                // Only evict if we're at the limit and adding a new entry (not updating)
                if (isNewEntry && _cacheKeys.Count >= maxEntries)
                {
                    // Need to evict one entry to make room
                    // Find the oldest entry based on insertion/access time
                    var oldestEntry = _cacheKeys.OrderBy(kvp => kvp.Value).FirstOrDefault();

                    if (!string.IsNullOrEmpty(oldestEntry.Key))
                    {
                        // Remove from cache - this will trigger the eviction callback
                        _cache.Remove(oldestEntry.Key);

                        // Ensure the key is removed from tracking even if callback is deferred
                        // This is idempotent with the callback's TryRemove
                        _cacheKeys.TryRemove(oldestEntry.Key, out _);
                    }
                }

                // Add to cache and update tracking
                _cache.Set(key, value, entryOptions);
                _cacheKeys[key] = newSequence;
            }
        }
        else
        {
            // No limit - just add to cache
            _cache.Set(key, value, entryOptions);
            _cacheKeys[key] = newSequence;
        }

        return ValueTask.CompletedTask;
    }

    /// <inheritdoc />
    public ValueTask RemoveAsync(string key, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(key);
        cancellationToken.ThrowIfCancellationRequested();

        _cache.Remove(key);
        _cacheKeys.TryRemove(key, out _);

        return ValueTask.CompletedTask;
    }

    /// <summary>
    /// Validates a cache invalidation pattern to prevent ReDoS attacks.
    /// </summary>
    /// <param name="pattern">The pattern to validate.</param>
    /// <exception cref="ArgumentException">Thrown when the pattern is invalid or dangerous.</exception>
    private void ValidateInvalidationPattern(string pattern)
    {
        // Validate pattern length
        if (pattern.Length > _options.MaxPatternLength)
        {
            throw new ArgumentException(
                $"Pattern length ({pattern.Length}) exceeds maximum allowed length ({_options.MaxPatternLength}). " +
                $"This restriction helps prevent ReDoS (Regular Expression Denial of Service) attacks.",
                nameof(pattern));
        }

        // Count wildcards in the pattern
        var wildcardCount = pattern.Count(c => c == '*');
        if (wildcardCount > _options.MaxWildcardsInPattern)
        {
            throw new ArgumentException(
                $"Pattern contains {wildcardCount} wildcards, which exceeds the maximum allowed ({_options.MaxWildcardsInPattern}). " +
                $"This restriction helps prevent ReDoS (Regular Expression Denial of Service) attacks. " +
                $"Consider using more specific patterns or multiple simpler patterns.",
                nameof(pattern));
        }
    }

    /// <inheritdoc />
    public ValueTask<int> RemoveByPatternAsync(string pattern, int maxCount, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(pattern);
        cancellationToken.ThrowIfCancellationRequested();

        // Validate pattern for ReDoS protection
        ValidateInvalidationPattern(pattern);

        var removed = 0;
        var isWildcard = pattern.Contains('*');

        if (!isWildcard)
        {
            // Exact match
            if (_cacheKeys.ContainsKey(pattern))
            {
                _cache.Remove(pattern);
                _cacheKeys.TryRemove(pattern, out _);
                removed = 1;
            }
        }
        else
        {
            // Optimize common pattern: prefix matching (e.g., "page:*")
            if (pattern.EndsWith("*") && !pattern[..^1].Contains('*'))
            {
                // Simple prefix match - much faster than regex
                var prefix = pattern[..^1];
                var keysToRemove = _cacheKeys.Keys
                    .Where(key => key.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
                    .Take(maxCount)
                    .ToList();

                foreach (var key in keysToRemove)
                {
                    _cache.Remove(key);
                    _cacheKeys.TryRemove(key, out _);
                    removed++;
                }
            }
            else if (pattern.StartsWith("*") && !pattern[1..].Contains('*'))
            {
                // Simple suffix match
                var suffix = pattern[1..];
                var keysToRemove = _cacheKeys.Keys
                    .Where(key => key.EndsWith(suffix, StringComparison.OrdinalIgnoreCase))
                    .Take(maxCount)
                    .ToList();

                foreach (var key in keysToRemove)
                {
                    _cache.Remove(key);
                    _cacheKeys.TryRemove(key, out _);
                    removed++;
                }
            }
            else if (pattern.StartsWith("*") && pattern.EndsWith("*") && pattern.Count(c => c == '*') == 2)
            {
                // Simple contains match (e.g., "*value*")
                var containsValue = pattern[1..^1];
                var keysToRemove = _cacheKeys.Keys
                    .Where(key => key.Contains(containsValue, StringComparison.OrdinalIgnoreCase))
                    .Take(maxCount)
                    .ToList();

                foreach (var key in keysToRemove)
                {
                    _cache.Remove(key);
                    _cacheKeys.TryRemove(key, out _);
                    removed++;
                }
            }
            else
            {
                // Complex wildcard pattern - use regex with timeout protection
                var regexPattern = "^" + Regex.Escape(pattern)
                    .Replace("\\*", ".*") + "$";

                var keysToRemove = _cacheKeys.Keys
                    .Where(key =>
                    {
                        try
                        {
                            return Regex.IsMatch(key, regexPattern,
                                RegexOptions.IgnoreCase | RegexOptions.Compiled,
                                TimeSpan.FromSeconds(1));
                        }
                        catch (RegexMatchTimeoutException)
                        {
                            return false;
                        }
                    })
                    .Take(maxCount)
                    .ToList();

                foreach (var key in keysToRemove)
                {
                    _cache.Remove(key);
                    _cacheKeys.TryRemove(key, out _);
                    removed++;
                }
            }
        }

        return ValueTask.FromResult(removed);
    }

    /// <inheritdoc />
    public ValueTask ClearAsync(CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        foreach (var key in _cacheKeys.Keys.ToList())
        {
            _cache.Remove(key);
        }

        _cacheKeys.Clear();

        return ValueTask.CompletedTask;
    }

    /// <summary>
    /// Gets all currently cached keys.
    /// </summary>
    /// <returns>A collection of cache keys.</returns>
    public IReadOnlyCollection<string> GetAllKeys()
    {
        return _cacheKeys.Keys.ToList();
    }

    /// <summary>
    /// Gets the number of cached entries.
    /// </summary>
    public int Count => _cacheKeys.Count;

    /// <summary>
    /// Maps Microsoft.Extensions.Caching.Memory.EvictionReason to our abstraction.
    /// </summary>
    private static Abstractions.EvictionReason MapEvictionReason(MsEvictionReason reason)
    {
        return reason switch
        {
            MsEvictionReason.Removed => Abstractions.EvictionReason.Removed,
            MsEvictionReason.Replaced => Abstractions.EvictionReason.Replaced,
            MsEvictionReason.Expired => Abstractions.EvictionReason.Expired,
            MsEvictionReason.Capacity => Abstractions.EvictionReason.Capacity,
            MsEvictionReason.TokenExpired => Abstractions.EvictionReason.TokenExpired,
            _ => Abstractions.EvictionReason.None
        };
    }
}
