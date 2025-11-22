using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using System.Collections.Concurrent;
using System.Text.RegularExpressions;
using EasyAppDev.Blazor.PageCache.Configuration;

namespace EasyAppDev.Blazor.PageCache.Services;

/// <summary>
/// Implementation of <see cref="IPageCacheInvalidator"/>.
/// </summary>
public sealed partial class PageCacheInvalidator : IPageCacheInvalidator
{
    // FIX: Made non-readonly to allow SetCacheService to break circular dependency
    private IPageCacheService _cacheService;
    private readonly PageCacheOptions _options;
    private readonly ILogger<PageCacheInvalidator> _logger;

    private readonly ConcurrentDictionary<string, HashSet<string>> _routeToCacheKeys = new();
    private readonly ConcurrentDictionary<string, HashSet<string>> _tagToCacheKeys = new();

    // Reverse lookup: cache key -> tags for cleanup
    // This prevents memory leaks in _tagToCacheKeys when entries are invalidated by route/pattern
    private readonly ConcurrentDictionary<string, HashSet<string>> _cacheKeyToTags = new();

    // Statistics tracking with Interlocked for thread-safety
    private long _totalRouteInvalidations;
    private long _totalTagInvalidations;
    private long _totalPatternInvalidations;
    private long _totalInvalidatedEntries;
    private DateTimeOffset? _lastInvalidationTime;

    public PageCacheInvalidator(
        IOptions<PageCacheOptions> options,
        ILogger<PageCacheInvalidator> logger)
    {
        // FIX: Removed IPageCacheService from constructor to break circular dependency
        // The service will be set via SetCacheService() method after both services are constructed
        _cacheService = null!; // Will be set via SetCacheService
        _options = options?.Value ?? throw new ArgumentNullException(nameof(options));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    /// <summary>
    /// Sets the cache service reference. This is called during service registration
    /// to break the circular dependency between PageCacheInvalidator and PageCacheService.
    /// </summary>
    public void SetCacheService(IPageCacheService cacheService)
    {
        _cacheService = cacheService ?? throw new ArgumentNullException(nameof(cacheService));
    }

    /// <inheritdoc />
    public bool InvalidateRoute(string route)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(route);

        var normalizedRoute = NormalizeRoute(route);
        var pattern = $"{_options.CacheKeyPrefix}{normalizedRoute}*";

        // Atomically remove route entry and get cache keys for cleanup
        HashSet<string>? cacheKeys = null;
        if (_routeToCacheKeys.TryRemove(normalizedRoute, out var keys))
        {
            lock (keys)
            {
                // Take snapshot inside lock to ensure no concurrent modifications
                cacheKeys = new HashSet<string>(keys);
            }
        }

        var removed = _cacheService.RemoveByPattern(pattern);

        if (removed > 0)
        {
            // Clean up reverse lookup: remove tags associated with these cache keys
            if (cacheKeys != null)
            {
                CleanupTagsForCacheKeys(cacheKeys);
            }

            // Update statistics with thread-safe operations
            Interlocked.Increment(ref _totalRouteInvalidations);
            Interlocked.Add(ref _totalInvalidatedEntries, removed);
            _lastInvalidationTime = DateTimeOffset.UtcNow;

            LogRouteInvalidated(normalizedRoute, removed);
            return true;
        }

        LogRouteNotFound(normalizedRoute);
        return false;
    }

    /// <inheritdoc />
    public int InvalidatePattern(string pattern)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(pattern);

        var normalizedPattern = NormalizeRoute(pattern);
        var cachePattern = $"{_options.CacheKeyPrefix}{normalizedPattern}";

        // Atomically collect and remove all cache keys from matching routes
        var allCacheKeys = new HashSet<string>();
        var routesToRemove = _routeToCacheKeys.Keys
            .Where(route => PatternMatches(route, normalizedPattern))
            .ToList();

        foreach (var route in routesToRemove)
        {
            // Atomically remove each route and collect its keys
            if (_routeToCacheKeys.TryRemove(route, out var keys))
            {
                lock (keys)
                {
                    allCacheKeys.UnionWith(keys);
                }
            }
        }

        var removed = _cacheService.RemoveByPattern(cachePattern);

        if (removed > 0)
        {
            // Clean up reverse lookup: remove tags associated with these cache keys
            CleanupTagsForCacheKeys(allCacheKeys);

            // Update statistics with thread-safe operations
            Interlocked.Increment(ref _totalPatternInvalidations);
            Interlocked.Add(ref _totalInvalidatedEntries, removed);
            _lastInvalidationTime = DateTimeOffset.UtcNow;
        }

        LogPatternInvalidated(pattern, removed);
        return removed;
    }

    /// <inheritdoc />
    public int InvalidateByTag(string tag)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(tag);

        if (!_tagToCacheKeys.TryGetValue(tag, out var cacheKeys))
        {
            LogTagNotFound(tag);
            return 0;
        }

        var removed = 0;
        List<string> keysSnapshot;

        // Atomically take snapshot and clear the tag's cache key set to prevent new additions
        lock (cacheKeys)
        {
            // Take snapshot inside lock to ensure no concurrent modifications
            keysSnapshot = cacheKeys.ToList();
            // Clear the set so no new entries can be added during invalidation
            cacheKeys.Clear();
        }

        // Remove tag entry after we've captured the snapshot and cleared it
        _tagToCacheKeys.TryRemove(tag, out _);

        foreach (var cacheKey in keysSnapshot)
        {
            _cacheService.Remove(cacheKey);
            removed++;

            // Clean up reverse lookup for this specific cache key
            if (_cacheKeyToTags.TryRemove(cacheKey, out var tags))
            {
                // Remove this cache key from all other tags it was associated with
                foreach (var otherTag in tags)
                {
                    if (otherTag != tag && _tagToCacheKeys.TryGetValue(otherTag, out var otherTagKeys))
                    {
                        lock (otherTagKeys)
                        {
                            otherTagKeys.Remove(cacheKey);

                            // If the other tag has no more entries, remove it entirely
                            if (otherTagKeys.Count == 0)
                            {
                                // Try to remove empty tag collection, but only if it's still empty
                                // (another thread might have added entries)
                                _tagToCacheKeys.TryRemove(otherTag, out _);
                            }
                        }
                    }
                }
            }
        }

        // Update statistics with thread-safe operations
        if (removed > 0)
        {
            Interlocked.Increment(ref _totalTagInvalidations);
            Interlocked.Add(ref _totalInvalidatedEntries, removed);
            _lastInvalidationTime = DateTimeOffset.UtcNow;
        }

        LogTagInvalidated(tag, removed);
        return removed;
    }

    /// <inheritdoc />
    public int ClearAll()
    {
        _cacheService.Clear();

        var count = _routeToCacheKeys.Count;
        _routeToCacheKeys.Clear();
        _tagToCacheKeys.Clear();
        _cacheKeyToTags.Clear(); // Also clear reverse lookup

        // Update statistics - treating ClearAll as a pattern invalidation
        if (count > 0)
        {
            Interlocked.Increment(ref _totalPatternInvalidations);
            Interlocked.Add(ref _totalInvalidatedEntries, count);
            _lastInvalidationTime = DateTimeOffset.UtcNow;
        }

        LogCacheCleared(count);
        return count;
    }

    /// <inheritdoc />
    public IReadOnlyCollection<string> GetCachedRoutes()
    {
        return _routeToCacheKeys.Keys.ToList().AsReadOnly();
    }

    /// <summary>
    /// Registers a cache key for route tracking.
    /// </summary>
    /// <param name="route">The route being cached.</param>
    /// <param name="cacheKey">The cache key used for storage.</param>
    /// <param name="tags">Optional tags for grouping cache entries.</param>
    /// <remarks>
    /// Called internally by PageCacheService when caching a page.
    /// This must be called BEFORE or ATOMICALLY WITH cache storage to prevent orphaned entries.
    /// </remarks>
    internal void RegisterCacheKey(string route, string cacheKey, string[]? tags = null)
    {
        var normalizedRoute = NormalizeRoute(route);

        _routeToCacheKeys.AddOrUpdate(
            normalizedRoute,
            _ => new HashSet<string> { cacheKey },
            (_, existing) =>
            {
                lock (existing) // Thread-safe HashSet modification
                {
                    existing.Add(cacheKey);
                }
                return existing;
            });

        if (tags != null && tags.Length > 0)
        {
            // Store reverse lookup: cache key -> tags
            _cacheKeyToTags.AddOrUpdate(
                cacheKey,
                _ => new HashSet<string>(tags),
                (_, existing) =>
                {
                    lock (existing)
                    {
                        foreach (var tag in tags)
                        {
                            existing.Add(tag);
                        }
                    }
                    return existing;
                });

            // Store forward lookup: tag -> cache keys
            foreach (var tag in tags)
            {
                _tagToCacheKeys.AddOrUpdate(
                    tag,
                    _ => new HashSet<string> { cacheKey },
                    (_, existing) =>
                    {
                        lock (existing) // Thread-safe HashSet modification
                        {
                            existing.Add(cacheKey);
                        }
                        return existing;
                    });
            }
        }
    }

    /// <summary>
    /// Cleans up tag associations for a set of cache keys.
    /// This prevents memory leaks by removing cache keys from all tag mappings when those keys are invalidated.
    /// </summary>
    /// <param name="cacheKeys">The cache keys to clean up.</param>
    private void CleanupTagsForCacheKeys(HashSet<string> cacheKeys)
    {
        foreach (var cacheKey in cacheKeys)
        {
            // Get all tags associated with this cache key
            if (_cacheKeyToTags.TryRemove(cacheKey, out var tags))
            {
                // Remove this cache key from each tag's collection
                foreach (var tag in tags)
                {
                    if (_tagToCacheKeys.TryGetValue(tag, out var tagKeys))
                    {
                        lock (tagKeys)
                        {
                            tagKeys.Remove(cacheKey);
                        }

                        // If tag has no more cache keys, remove the tag entry entirely
                        if (tagKeys.Count == 0)
                        {
                            _tagToCacheKeys.TryRemove(tag, out _);
                        }
                    }
                }
            }
        }
    }

    /// <summary>
    /// Normalizes a route for consistent matching.
    /// </summary>
    private static string NormalizeRoute(string route)
    {
        var normalized = route.Trim().ToLowerInvariant();

        // Ensure starts with / unless it's a wildcard pattern
        if (!normalized.StartsWith('/') && !normalized.StartsWith('*'))
        {
            normalized = "/" + normalized;
        }

        // Remove trailing slash except for root
        if (normalized.Length > 1 && normalized.EndsWith('/') && !normalized.EndsWith("*/"))
        {
            normalized = normalized[..^1];
        }

        return normalized;
    }

    /// <summary>
    /// Checks if a route matches a pattern.
    /// </summary>
    private static bool PatternMatches(string route, string pattern)
    {
        // If no wildcard, just do exact comparison
        if (!pattern.Contains('*'))
        {
            return route.Equals(pattern, StringComparison.OrdinalIgnoreCase);
        }

        try
        {
            var regexPattern = "^" + Regex.Escape(pattern)
                .Replace("\\*", ".*") + "$";

            return Regex.IsMatch(
                route,
                regexPattern,
                RegexOptions.IgnoreCase,
                TimeSpan.FromSeconds(1));
        }
        catch (RegexMatchTimeoutException)
        {
            // If regex times out, assume no match
            return false;
        }
    }

    /// <summary>
    /// Gets the current invalidation statistics.
    /// </summary>
    /// <returns>A snapshot of invalidation statistics.</returns>
    internal (long RouteInvalidations, long TagInvalidations, long PatternInvalidations, long InvalidatedEntries, DateTimeOffset? LastInvalidationTime) GetInvalidationStatistics()
    {
        return (
            Interlocked.Read(ref _totalRouteInvalidations),
            Interlocked.Read(ref _totalTagInvalidations),
            Interlocked.Read(ref _totalPatternInvalidations),
            Interlocked.Read(ref _totalInvalidatedEntries),
            _lastInvalidationTime
        );
    }

    // Source-generated logging methods
    [LoggerMessage(EventId = 4001, Level = LogLevel.Information,
        Message = "Invalidated route: {Route}, {Count} entries removed")]
    private partial void LogRouteInvalidated(string route, int count);

    [LoggerMessage(EventId = 4002, Level = LogLevel.Debug,
        Message = "Route not found in cache: {Route}")]
    private partial void LogRouteNotFound(string route);

    [LoggerMessage(EventId = 4003, Level = LogLevel.Information,
        Message = "Invalidated pattern: {Pattern}, {Count} entries removed")]
    private partial void LogPatternInvalidated(string pattern, int count);

    [LoggerMessage(EventId = 4004, Level = LogLevel.Information,
        Message = "Invalidated tag: {Tag}, {Count} entries removed")]
    private partial void LogTagInvalidated(string tag, int count);

    [LoggerMessage(EventId = 4005, Level = LogLevel.Debug,
        Message = "Tag not found in cache: {Tag}")]
    private partial void LogTagNotFound(string tag);

    [LoggerMessage(EventId = 4006, Level = LogLevel.Warning,
        Message = "Cache cleared: {Count} routes removed")]
    private partial void LogCacheCleared(int count);
}
