namespace EasyAppDev.Blazor.PageCache.Configuration;

/// <summary>
/// Configuration options for the Blazor page cache.
/// </summary>
public sealed class PageCacheOptions
{
    /// <summary>
    /// Gets or sets a value indicating whether page caching is enabled globally.
    /// Default is <c>true</c>.
    /// </summary>
    public bool Enabled { get; set; } = true;

    /// <summary>
    /// Gets or sets the default cache duration in seconds.
    /// Default is 300 seconds (5 minutes).
    /// </summary>
    public int DefaultDurationSeconds { get; set; } = 300;

    /// <summary>
    /// Gets or sets the maximum size of the cache in megabytes.
    /// Default is 100 MB. Set to null for no limit.
    /// </summary>
    public int? MaxCacheSizeMB { get; set; } = 100;

    /// <summary>
    /// Gets or sets the sliding expiration duration in seconds.
    /// Default is null (no sliding expiration).
    /// </summary>
    public int? SlidingExpirationSeconds { get; set; }

    /// <summary>
    /// Gets or sets a value indicating whether to compress cached HTML.
    /// Default is <c>false</c>.
    /// </summary>
    public bool CompressCachedContent { get; set; } = false;

    /// <summary>
    /// Gets or sets the type of compression strategy to use.
    /// Default is null (uses GZipCompressionStrategy when CompressCachedContent is true).
    /// </summary>
    public Type? CompressionStrategyType { get; set; }

    /// <summary>
    /// Gets or sets a value indicating whether to enable cache statistics tracking.
    /// Default is <c>true</c>.
    /// </summary>
    public bool EnableStatistics { get; set; } = true;

    /// <summary>
    /// Gets or sets a value indicating whether to automatically reset statistics counters
    /// when they approach overflow thresholds.
    /// Default is <c>false</c>.
    /// </summary>
    /// <remarks>
    /// <para>
    /// When enabled, statistics counters are automatically reset to zero when any counter
    /// reaches 90% of <see cref="long.MaxValue"/>. This prevents counter overflow but
    /// results in loss of historical statistics.
    /// </para>
    /// <para>
    /// At typical usage rates (1 million operations/second), overflow would take approximately
    /// 292,000 years to occur naturally, so automatic reset is generally not necessary.
    /// Manual reset via <see cref="Services.IPageCacheService.ResetStatistics"/> is usually preferred.
    /// </para>
    /// </remarks>
    public bool AutoResetStatisticsOnOverflow { get; set; } = false;

    /// <summary>
    /// Gets or sets the interval in hours for periodic statistics reset.
    /// Set to null to disable periodic reset. Default is <c>null</c> (disabled).
    /// </summary>
    /// <remarks>
    /// <para>
    /// When set to a positive value, statistics will be automatically reset at the specified
    /// interval. This is useful for generating periodic statistics reports or preventing
    /// long-term counter accumulation.
    /// </para>
    /// <para>
    /// Example: Set to 24 to reset statistics daily, or 168 for weekly resets.
    /// </para>
    /// <para>
    /// The reset is performed during the next cache operation after the interval has elapsed,
    /// not at an exact scheduled time.
    /// </para>
    /// </remarks>
    public int? StatisticsResetIntervalHours { get; set; } = null;

    /// <summary>
    /// Gets or sets the cache key prefix.
    /// Default is "PageCache:".
    /// </summary>
    public string CacheKeyPrefix { get; set; } = "PageCache:";

    /// <summary>
    /// Gets or sets a value indicating whether to vary cache by culture.
    /// Default is <c>true</c>.
    /// </summary>
    public bool VaryByCulture { get; set; } = true;

    /// <summary>
    /// Gets or sets the maximum number of concurrent cache generation operations
    /// per cache key. Default is 1 (prevents cache stampede).
    /// </summary>
    public int MaxConcurrentCacheGenerations { get; set; } = 1;

    /// <summary>
    /// Gets or sets the timeout in seconds for waiting for a cache generation
    /// operation to complete. Default is 30 seconds.
    /// </summary>
    public int CacheGenerationTimeoutSeconds { get; set; } = 30;

    /// <summary>
    /// Gets or sets query string parameters that should be ignored when
    /// generating cache keys (case-insensitive).
    /// </summary>
    public HashSet<string> IgnoredQueryParameters { get; set; } = new(StringComparer.OrdinalIgnoreCase)
    {
        "utm_source",
        "utm_medium",
        "utm_campaign",
        "utm_term",
        "utm_content",
        "fbclid",
        "gclid"
    };

    /// <summary>
    /// Gets or sets a value indicating whether to cache pages only for successful
    /// responses (HTTP 200). Default is <c>true</c>.
    /// </summary>
    public bool CacheOnlySuccessfulResponses { get; set; } = true;

    /// <summary>
    /// Gets or sets HTTP status codes that should be cached.
    /// Default is { 200 }. Only used if CacheOnlySuccessfulResponses is false.
    /// </summary>
    public HashSet<int> CacheableStatusCodes { get; set; } = new() { 200 };

    /// <summary>
    /// Gets or sets the maximum number of wildcards allowed in a cache invalidation pattern.
    /// This helps prevent ReDoS (Regular Expression Denial of Service) attacks.
    /// Default is 3.
    /// </summary>
    public int MaxWildcardsInPattern { get; set; } = 3;

    /// <summary>
    /// Gets or sets the maximum length of a cache invalidation pattern in characters.
    /// This helps prevent ReDoS (Regular Expression Denial of Service) attacks.
    /// Default is 256.
    /// </summary>
    public int MaxPatternLength { get; set; } = 256;

    /// <summary>
    /// Gets or sets the security-related configuration options.
    /// </summary>
    public SecurityOptions Security { get; set; } = new SecurityOptions();
}
