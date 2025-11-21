namespace EasyAppDev.Blazor.PageCache.Services;

/// <summary>
/// Service for managing cached HTML responses.
/// </summary>
public interface IPageCacheService
{
    /// <summary>
    /// Gets cached HTML for the specified cache key.
    /// </summary>
    /// <param name="cacheKey">The cache key.</param>
    /// <returns>The cached HTML if found; otherwise, <c>null</c>.</returns>
    string? GetCachedHtml(string cacheKey);

    /// <summary>
    /// Stores HTML in the cache with the specified duration.
    /// </summary>
    /// <param name="cacheKey">The cache key.</param>
    /// <param name="html">The HTML content to cache.</param>
    /// <param name="durationSeconds">The cache duration in seconds.</param>
    /// <returns>A task representing the asynchronous operation.</returns>
    Task SetCachedHtmlAsync(string cacheKey, string html, int durationSeconds);

    /// <summary>
    /// Removes a specific cache entry.
    /// </summary>
    /// <param name="cacheKey">The cache key to remove.</param>
    void Remove(string cacheKey);

    /// <summary>
    /// Removes all cache entries matching the specified pattern.
    /// </summary>
    /// <param name="pattern">The pattern to match (supports * wildcard).</param>
    /// <param name="maxRemovalCount">Maximum number of entries to remove (default: 10000).</param>
    /// <returns>The number of entries removed.</returns>
    int RemoveByPattern(string pattern, int maxRemovalCount = 10000);

    /// <summary>
    /// Clears all cached entries.
    /// </summary>
    void Clear();

    /// <summary>
    /// Acquires a lock for the specified cache key to prevent stampede.
    /// </summary>
    /// <param name="cacheKey">The cache key.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>A disposable lock that should be released after cache generation.</returns>
    Task<IDisposable> AcquireLockAsync(string cacheKey, CancellationToken cancellationToken = default);

    /// <summary>
    /// Resets all cache statistics counters to zero and restarts the statistics collection timer.
    /// </summary>
    /// <remarks>
    /// <para>
    /// This method is thread-safe and can be called while the cache is actively serving requests.
    /// All counters (hits, misses, evictions, bytes) are atomically reset to zero.
    /// </para>
    /// <para>
    /// Use this method to:
    /// </para>
    /// <list type="bullet">
    /// <item><description>Prevent counter overflow (though overflow would take centuries under normal usage)</description></item>
    /// <item><description>Start fresh statistics collection after a maintenance window</description></item>
    /// <item><description>Clear statistics after configuration changes</description></item>
    /// </list>
    /// <para>
    /// Note: This does not clear the cached content, only the statistics counters.
    /// </para>
    /// </remarks>
    void ResetStatistics();
}
