using System.Text;

namespace EasyAppDev.Blazor.PageCache.Diagnostics;

/// <summary>
/// Statistics and diagnostic information about the page cache.
/// </summary>
/// <remarks>
/// <para>
/// <strong>Counter Overflow Behavior:</strong>
/// </para>
/// <para>
/// All statistical counters (HitCount, MissCount, EvictionCount, etc.) are implemented as <see cref="long"/>
/// values and use unchecked arithmetic. This means:
/// </para>
/// <list type="bullet">
/// <item><description>Counters will wrap around from <see cref="long.MaxValue"/> (9,223,372,036,854,775,807) to <see cref="long.MinValue"/> (-9,223,372,036,854,775,808) on overflow</description></item>
/// <item><description>At typical request rates, overflow would take centuries to occur naturally (e.g., at 1 million requests/sec, it would take ~292,000 years to overflow)</description></item>
/// <item><description>Derived metrics (HitRate, RequestsPerSecond) are calculated from raw counter values and will be affected if overflow occurs</description></item>
/// <item><description>If overflow is a concern, reset counters periodically</description></item>
/// <item><description>Overflow events are logged for monitoring and detection purposes</description></item>
/// </list>
/// <para>
/// <strong>Thread Safety:</strong>
/// </para>
/// <para>
/// This class is an immutable snapshot of statistics at a point in time. Thread-safe counter operations
/// use <see cref="System.Threading.Interlocked"/> operations.
/// </para>
/// </remarks>
public sealed class PageCacheStats
{
    /// <summary>
    /// Gets the number of cache hits.
    /// </summary>
    /// <remarks>
    /// This counter uses unchecked arithmetic and will wrap on overflow from <see cref="long.MaxValue"/> to <see cref="long.MinValue"/>.
    /// At 1 million cache hits per second, overflow would occur after approximately 292,000 years.
    /// </remarks>
    public long HitCount { get; init; }

    /// <summary>
    /// Gets the number of cache misses.
    /// </summary>
    /// <remarks>
    /// This counter uses unchecked arithmetic and will wrap on overflow from <see cref="long.MaxValue"/> to <see cref="long.MinValue"/>.
    /// At 1 million cache misses per second, overflow would occur after approximately 292,000 years.
    /// </remarks>
    public long MissCount { get; init; }

    /// <summary>
    /// Gets the total number of cache requests (hits + misses).
    /// </summary>
    /// <remarks>
    /// This value is calculated from HitCount + MissCount. If either counter overflows, this value will be affected.
    /// </remarks>
    public long TotalRequests { get; init; }

    /// <summary>
    /// Gets the cache hit rate (0.0 to 1.0, where 1.0 = 100% hit rate).
    /// </summary>
    /// <remarks>
    /// Calculated as HitCount / TotalRequests. Returns 0.0 if TotalRequests is 0.
    /// If counters have overflowed, this value may be incorrect until statistics are reset.
    /// </remarks>
    public double HitRate { get; init; }

    /// <summary>
    /// Gets the number of currently cached entries.
    /// </summary>
    public int CachedEntries { get; init; }

    /// <summary>
    /// Gets the total size of cached content in bytes.
    /// </summary>
    /// <remarks>
    /// This counter uses unchecked arithmetic and will wrap on overflow.
    /// The counter can become negative if many evictions cause it to wrap around.
    /// </remarks>
    public long CacheSizeBytes { get; init; }

    /// <summary>
    /// Gets the cache size in megabytes.
    /// </summary>
    public double CacheSizeMB => CacheSizeBytes / 1024.0 / 1024.0;

    /// <summary>
    /// Gets the average cached page size in bytes.
    /// </summary>
    public double AveragePageSizeBytes => CachedEntries > 0
        ? (double)CacheSizeBytes / CachedEntries
        : 0;

    /// <summary>
    /// Gets the number of cache evictions.
    /// </summary>
    /// <remarks>
    /// This counter uses unchecked arithmetic and will wrap on overflow from <see cref="long.MaxValue"/> to <see cref="long.MinValue"/>.
    /// At 1 million evictions per second, overflow would occur after approximately 292,000 years.
    /// </remarks>
    public long EvictionCount { get; init; }

    /// <summary>
    /// Gets the total number of route invalidations performed.
    /// </summary>
    /// <remarks>
    /// This counter tracks invalidations performed via InvalidateRoute() method.
    /// Uses unchecked arithmetic and will wrap on overflow.
    /// </remarks>
    public long TotalRouteInvalidations { get; init; }

    /// <summary>
    /// Gets the total number of tag invalidations performed.
    /// </summary>
    /// <remarks>
    /// This counter tracks invalidations performed via InvalidateByTag() method.
    /// Uses unchecked arithmetic and will wrap on overflow.
    /// </remarks>
    public long TotalTagInvalidations { get; init; }

    /// <summary>
    /// Gets the total number of pattern invalidations performed.
    /// </summary>
    /// <remarks>
    /// This counter tracks invalidations performed via InvalidatePattern() method.
    /// Uses unchecked arithmetic and will wrap on overflow.
    /// </remarks>
    public long TotalPatternInvalidations { get; init; }

    /// <summary>
    /// Gets the total number of cache entries removed by all invalidation operations.
    /// </summary>
    /// <remarks>
    /// This represents the sum of all entries removed via invalidation operations.
    /// Uses unchecked arithmetic and will wrap on overflow.
    /// </remarks>
    public long TotalInvalidatedEntries { get; init; }

    /// <summary>
    /// Gets the timestamp of the last invalidation operation.
    /// </summary>
    /// <remarks>
    /// Returns null if no invalidation operations have been performed since service startup.
    /// </remarks>
    public DateTimeOffset? LastInvalidationTime { get; init; }

    /// <summary>
    /// Gets the total number of invalidations across all types.
    /// </summary>
    /// <remarks>
    /// This is the sum of route, tag, and pattern invalidations.
    /// </remarks>
    public long TotalInvalidations => TotalRouteInvalidations + TotalTagInvalidations + TotalPatternInvalidations;

    /// <summary>
    /// Gets the timestamp when statistics collection started.
    /// </summary>
    public DateTimeOffset StartTime { get; init; }

    /// <summary>
    /// Gets the duration for which statistics have been collected.
    /// </summary>
    public TimeSpan Duration => DateTimeOffset.UtcNow - StartTime;

    /// <summary>
    /// Gets requests per second.
    /// </summary>
    public double RequestsPerSecond => Duration.TotalSeconds > 0
        ? TotalRequests / Duration.TotalSeconds
        : 0;

    /// <summary>
    /// Returns a formatted string representation of the statistics.
    /// </summary>
    public override string ToString()
    {
        return $"Cache Stats: {HitCount} hits, {MissCount} misses, " +
               $"{HitRate:P2} hit rate, {CachedEntries} entries, " +
               $"{CacheSizeMB:F2} MB, {TotalInvalidations} invalidations";
    }

    /// <summary>
    /// Gets a detailed diagnostic report.
    /// </summary>
    /// <returns>A formatted report of cache statistics.</returns>
    public string GetDetailedReport()
    {
        var sb = new StringBuilder();
        sb.AppendLine("=== Page Cache Statistics ===");
        sb.AppendLine($"Hit Rate:          {HitRate:P2}");
        sb.AppendLine($"Total Requests:    {TotalRequests:N0}");
        sb.AppendLine($"Cache Hits:        {HitCount:N0}");
        sb.AppendLine($"Cache Misses:      {MissCount:N0}");
        sb.AppendLine($"Cached Entries:    {CachedEntries:N0}");
        sb.AppendLine($"Cache Size:        {CacheSizeMB:F2} MB");
        sb.AppendLine($"Avg Page Size:     {AveragePageSizeBytes:F0} bytes");
        sb.AppendLine($"Evictions:         {EvictionCount:N0}");
        sb.AppendLine();
        sb.AppendLine("=== Invalidation Statistics ===");
        sb.AppendLine($"Route Invalidations:   {TotalRouteInvalidations:N0}");
        sb.AppendLine($"Tag Invalidations:     {TotalTagInvalidations:N0}");
        sb.AppendLine($"Pattern Invalidations: {TotalPatternInvalidations:N0}");
        sb.AppendLine($"Total Invalidations:   {TotalInvalidations:N0}");
        sb.AppendLine($"Entries Invalidated:   {TotalInvalidatedEntries:N0}");
        sb.AppendLine($"Last Invalidation:     {(LastInvalidationTime.HasValue ? LastInvalidationTime.Value.ToString("yyyy-MM-dd HH:mm:ss") : "Never")}");
        sb.AppendLine();
        sb.AppendLine($"Uptime:            {Duration}");
        sb.AppendLine($"Requests/Second:   {RequestsPerSecond:F2}");
        return sb.ToString();
    }
}
