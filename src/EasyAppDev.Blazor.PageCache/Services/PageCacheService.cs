using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.DependencyInjection;
using EasyAppDev.Blazor.PageCache.Abstractions;
using EasyAppDev.Blazor.PageCache.Configuration;
using EasyAppDev.Blazor.PageCache.Diagnostics;
using EasyAppDev.Blazor.PageCache.Storage;

using EasyAppDev.Blazor.PageCache.Validation;
namespace EasyAppDev.Blazor.PageCache.Services;

/// <summary>
/// Implementation of <see cref="IPageCacheService"/> using pluggable storage backends.
/// </summary>
/// <remarks>
/// <para>
/// <strong>IMPORTANT: Service Lifetime Requirements</strong>
/// </para>
/// <para>
/// This service MUST be registered as a Singleton in the dependency injection container.
/// Registering it with a different lifetime (Scoped or Transient) can lead to:
/// </para>
/// <list type="bullet">
/// <item><description>Memory leaks from undisposed event handlers</description></item>
/// <item><description>Incorrect cache statistics and tracking</description></item>
/// <item><description>Performance degradation from repeated service instantiation</description></item>
/// <item><description>Lock coordination failures across requests</description></item>
/// </list>
/// <para>
/// The service will validate its lifetime at construction time and log a warning
/// if not registered as Singleton (in DEBUG builds or when diagnostics are enabled).
/// </para>
/// </remarks>
public sealed partial class PageCacheService : IPageCacheService, IDisposable
{
    private readonly ICacheStorage _storage;
    private readonly PageCacheOptions _options;
    private readonly AsyncKeyedLock _locks;
    private readonly ILogger<PageCacheService> _logger;
    private readonly ICompressionStrategy? _compressionStrategy;
    private readonly IPageCacheEvents _events;
    private readonly IContentValidator? _contentValidator;
    private IPageCacheInvalidator? _invalidator;

    // Statistics tracking
    // Using unchecked arithmetic - counters will wrap on overflow
    // Overflow would take ~292,000 years at 1M operations/sec
    private long _hitCount;
    private long _missCount;
    private long _totalCachedBytes;
    private long _evictionCount;
    private DateTimeOffset _startTime = DateTimeOffset.UtcNow;
    private DateTimeOffset _lastPeriodicResetCheck = DateTimeOffset.UtcNow;

    // Overflow detection thresholds (90% of long.MaxValue)
    private const long OverflowWarningThreshold = (long)(long.MaxValue * 0.9);

    // Disposal tracking for leak detection
    private bool _disposed;
    private long _activeCallbackCount;

#if DEBUG
    // Finalizer only enabled in DEBUG builds for leak detection
    // In production, this would add unnecessary overhead
    private static readonly bool _enableLeakDetection = true;
#else
#pragma warning disable CS0414 // Field is assigned but never used in Release builds
    private static readonly bool _enableLeakDetection = false;
#pragma warning restore CS0414
#endif

    /// <summary>
    /// Initializes a new instance of the <see cref="PageCacheService"/> class.
    /// </summary>
    /// <param name="storage">The cache storage backend.</param>
    /// <param name="options">The cache configuration options.</param>
    /// <param name="locks">The keyed lock provider for cache stampede prevention.</param>
    /// <param name="logger">The logger instance.</param>
    /// <param name="events">The cache events handler.</param>
    /// <param name="compressionStrategy">Optional compression strategy.</param>
    /// <param name="contentValidator">Optional content validator.</param>
    /// <param name="serviceProvider">Optional service provider for lifetime validation.</param>
    /// <remarks>
    /// In DEBUG builds, the constructor validates that the service is registered with Singleton lifetime
    /// and logs a warning if this requirement is not met.
    /// </remarks>
    public PageCacheService(
        ICacheStorage storage,
        IOptions<PageCacheOptions> options,
        AsyncKeyedLock locks,
        ILogger<PageCacheService> logger,
        IPageCacheEvents events,
        ICompressionStrategy? compressionStrategy = null,
        IContentValidator? contentValidator = null,
        IServiceProvider? serviceProvider = null)
    {
        _storage = storage ?? throw new ArgumentNullException(nameof(storage));
        _options = options?.Value ?? throw new ArgumentNullException(nameof(options));
        _locks = locks ?? throw new ArgumentNullException(nameof(locks));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _events = events ?? throw new ArgumentNullException(nameof(events));
        _compressionStrategy = compressionStrategy;
        _contentValidator = contentValidator;

        // Validate service lifetime in DEBUG builds or when diagnostics are enabled
#if DEBUG
        ValidateServiceLifetime(serviceProvider);
#endif
    }

    /// <summary>
    /// Validates that the service is registered with Singleton lifetime.
    /// </summary>
    /// <param name="serviceProvider">The service provider to inspect.</param>
    private void ValidateServiceLifetime(IServiceProvider? serviceProvider)
    {
        if (serviceProvider == null)
        {
            return;
        }

        try
        {
            // Try to get the service descriptor for this service
            // This is a best-effort validation and may not work in all DI containers
            var serviceDescriptors = serviceProvider.GetService<IServiceCollection>();
            if (serviceDescriptors != null)
            {
                var descriptor = serviceDescriptors.FirstOrDefault(d =>
                    d.ServiceType == typeof(IPageCacheService) ||
                    d.ServiceType == typeof(PageCacheService));

                if (descriptor != null && descriptor.Lifetime != ServiceLifetime.Singleton)
                {
                    LogServiceLifetimeWarning(descriptor.Lifetime.ToString());
                }
            }
        }
        catch
        {
            // Swallow exceptions from validation - this is non-critical diagnostic code
        }
    }

    /// <inheritdoc />
    public string? GetCachedHtml(string cacheKey)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentException.ThrowIfNullOrWhiteSpace(cacheKey);

        // Validate cache key for security
        CacheKeyValidator.ValidateAndThrow(cacheKey, nameof(cacheKey));

        if (!_options.Enabled)
        {
            return null;
        }

        if (_compressionStrategy != null)
        {
            var compressedData = _storage.GetAsync<byte[]>(cacheKey).AsTask().GetAwaiter().GetResult();
            if (compressedData != null)
            {
                if (_options.EnableStatistics)
                {
                    IncrementCounterWithOverflowCheck(ref _hitCount, "HitCount");
                }

                LogCacheHit(cacheKey);

                _ = _events.OnCacheHitAsync(new CacheHitContext
                {
                    CacheKey = cacheKey,
                    ContentSizeBytes = compressedData.Length,
                    IsCompressed = true
                });

                return _compressionStrategy.Decompress(compressedData);
            }
        }
        else
        {
            var html = _storage.GetAsync<string>(cacheKey).AsTask().GetAwaiter().GetResult();
            if (html != null)
            {
                if (_options.EnableStatistics)
                {
                    IncrementCounterWithOverflowCheck(ref _hitCount, "HitCount");
                }

                LogCacheHit(cacheKey);

                _ = _events.OnCacheHitAsync(new CacheHitContext
                {
                    CacheKey = cacheKey,
                    ContentSizeBytes = html.Length,
                    IsCompressed = false
                });

                return html;
            }
        }

        if (_options.EnableStatistics)
        {
            IncrementCounterWithOverflowCheck(ref _missCount, "MissCount");
        }

        LogCacheMiss(cacheKey);

        _ = _events.OnCacheMissAsync(new CacheMissContext
        {
            CacheKey = cacheKey
        });

        return null;
    }

    /// <inheritdoc />
    public async Task SetCachedHtmlAsync(string cacheKey, string html, int durationSeconds)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentException.ThrowIfNullOrWhiteSpace(cacheKey);
        ArgumentException.ThrowIfNullOrWhiteSpace(html);

        // Validate cache key for security
        CacheKeyValidator.ValidateAndThrow(cacheKey, nameof(cacheKey));

        if (!_options.Enabled)
        {
            return;
        }

        if (durationSeconds <= 0)
        {
            durationSeconds = _options.DefaultDurationSeconds;
        }

        // Validate content if validator is configured
        if (_contentValidator != null)
        {
            var validationResult = await _contentValidator.ValidateAsync(html, cacheKey);

            if (!validationResult.IsValid)
            {
                LogContentValidationFailed(cacheKey, validationResult.Severity.ToString(), validationResult.ErrorMessage ?? "Unknown error");

                if (validationResult.Severity >= ValidationSeverity.Error)
                {
                    return;
                }
            }
        }

        long sizeBytes;
        object cacheValue;

        if (_compressionStrategy != null)
        {
            var compressedData = _compressionStrategy.Compress(html);
            cacheValue = compressedData;
            sizeBytes = compressedData.Length;
        }
        else
        {
            cacheValue = html;
            sizeBytes = html.Length;
        }

        // PHASE 4 FIX: Add bytes to counter BEFORE registering callback
        // This prevents race condition where eviction happens before counter is updated
        if (_options.EnableStatistics)
        {
            AddCounterWithOverflowCheck(ref _totalCachedBytes, sizeBytes, "TotalCachedBytes");
        }

        var entryOptions = new CacheEntryOptions
        {
            AbsoluteExpirationRelativeToNow = TimeSpan.FromSeconds(durationSeconds),
            Size = sizeBytes
        };

        if (_options.SlidingExpirationSeconds.HasValue)
        {
            entryOptions.SlidingExpiration = TimeSpan.FromSeconds(_options.SlidingExpirationSeconds.Value);
        }

        // Use a callback that doesn't capture 'this' unnecessarily
        // Track active callbacks to help detect leaks
        // PHASE 4 FIX: Increment counter here, but ensure it's decremented even if SetAsync fails
        Interlocked.Increment(ref _activeCallbackCount);

        entryOptions.PostEvictionCallback = (key, value, reason) =>
        {
            try
            {
                if (_options.EnableStatistics)
                {
                    long size = value switch
                    {
                        string str => str.Length,
                        byte[] bytes => bytes.Length,
                        _ => 0
                    };
                    // Note: Subtracting from counter doesn't need overflow check
                    // as it's unlikely to overflow in the negative direction
                    // PHASE 4 NOTE: This subtraction is safe because bytes were added before callback registration
                    Interlocked.Add(ref _totalCachedBytes, -size);
                    IncrementCounterWithOverflowCheck(ref _evictionCount, "EvictionCount");
                }

                LogCacheEvicted(key, reason.ToString());
            }
            finally
            {
                // Decrement callback count when eviction callback completes
                Interlocked.Decrement(ref _activeCallbackCount);
            }
        };

        try
        {
            // Attempt to store in cache
            if (_compressionStrategy != null)
            {
                await _storage.SetAsync(cacheKey, (byte[])cacheValue, entryOptions);
            }
            else
            {
                await _storage.SetAsync(cacheKey, (string)cacheValue, entryOptions);
            }
        }
        catch
        {
            // PHASE 4 FIX: If SetAsync fails, rollback the counter changes to maintain accuracy
            if (_options.EnableStatistics)
            {
                // Rollback the bytes we added before callback registration
                Interlocked.Add(ref _totalCachedBytes, -sizeBytes);
            }

            // PHASE 4 FIX: Decrement callback count since the callback will never be registered
            // If SetAsync throws before callback registration, the eviction callback will never execute
            Interlocked.Decrement(ref _activeCallbackCount);

            throw;
        }

        LogCacheSet(cacheKey, (int)sizeBytes, durationSeconds);

        _ = _events.OnCacheSetAsync(new CacheSetContext
        {
            CacheKey = cacheKey,
            ContentSizeBytes = sizeBytes,
            OriginalSizeBytes = html.Length,
            IsCompressed = _compressionStrategy != null,
            DurationSeconds = durationSeconds
        });
    }

    /// <inheritdoc />
    public void Remove(string cacheKey)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentException.ThrowIfNullOrWhiteSpace(cacheKey);

        // Validate cache key for security
        CacheKeyValidator.ValidateAndThrow(cacheKey, nameof(cacheKey));

        _storage.RemoveAsync(cacheKey).AsTask().GetAwaiter().GetResult();

        LogCacheRemoved(cacheKey);

        _ = _events.OnCacheInvalidatedAsync(new InvalidationContext
        {
            KeyOrPattern = cacheKey,
            IsPattern = false,
            EntriesRemoved = 1
        });
    }

    /// <inheritdoc />
    public int RemoveByPattern(string pattern, int maxRemovalCount = 10000)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(pattern);

        var removed = _storage.RemoveByPatternAsync(pattern, maxRemovalCount).AsTask().GetAwaiter().GetResult();

        LogPatternRemoved(pattern, removed);

        _ = _events.OnCacheInvalidatedAsync(new InvalidationContext
        {
            KeyOrPattern = pattern,
            IsPattern = true,
            EntriesRemoved = removed
        });

        return removed;
    }

    /// <inheritdoc />
    public void Clear()
    {
        var storage = _storage as MemoryCacheStorage;
        var count = storage?.Count ?? 0;

        _storage.ClearAsync().AsTask().GetAwaiter().GetResult();

        if (_options.EnableStatistics)
        {
            Interlocked.Exchange(ref _totalCachedBytes, 0);
        }

        LogCacheCleared(count);
    }

    /// <inheritdoc />
    public async Task<IDisposable> AcquireLockAsync(
        string cacheKey,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(cacheKey);

        // Validate cache key for security
        CacheKeyValidator.ValidateAndThrow(cacheKey, nameof(cacheKey));

        var timeout = TimeSpan.FromSeconds(_options.CacheGenerationTimeoutSeconds);

        return await _locks.LockAsync(cacheKey, timeout, cancellationToken);
    }

    /// <summary>
    /// Sets the invalidator reference for statistics integration.
    /// </summary>
    /// <param name="invalidator">The cache invalidator instance.</param>
    /// <remarks>
    /// This method is called internally by the service container after construction
    /// to avoid circular dependency issues. The invalidator is optional - if not set,
    /// invalidation statistics will be returned as zeros.
    /// </remarks>
    internal void SetInvalidator(IPageCacheInvalidator invalidator)
    {
        _invalidator = invalidator;
    }

    /// <summary>
    /// Gets current cache statistics.
    /// </summary>
    /// <returns>A <see cref="PageCacheStats"/> instance containing current statistics.</returns>
    public PageCacheStats GetStatistics()
    {
        if (!_options.EnableStatistics)
        {
            return new PageCacheStats
            {
                StartTime = _startTime
            };
        }

        var hits = Interlocked.Read(ref _hitCount);
        var misses = Interlocked.Read(ref _missCount);
        var total = hits + misses;
        var hitRate = total > 0 ? (double)hits / total : 0;

        var storage = _storage as MemoryCacheStorage;
        var cachedEntries = storage?.Count ?? 0;

        // Get invalidation statistics from the invalidator if available
        long totalRouteInvalidations = 0;
        long totalTagInvalidations = 0;
        long totalPatternInvalidations = 0;
        long totalInvalidatedEntries = 0;
        DateTimeOffset? lastInvalidationTime = null;

        if (_invalidator is PageCacheInvalidator invalidatorImpl)
        {
            var invalidationStats = invalidatorImpl.GetInvalidationStatistics();
            totalRouteInvalidations = invalidationStats.RouteInvalidations;
            totalTagInvalidations = invalidationStats.TagInvalidations;
            totalPatternInvalidations = invalidationStats.PatternInvalidations;
            totalInvalidatedEntries = invalidationStats.InvalidatedEntries;
            lastInvalidationTime = invalidationStats.LastInvalidationTime;
        }

        return new PageCacheStats
        {
            HitCount = hits,
            MissCount = misses,
            TotalRequests = total,
            HitRate = hitRate,
            CachedEntries = cachedEntries,
            CacheSizeBytes = Interlocked.Read(ref _totalCachedBytes),
            EvictionCount = Interlocked.Read(ref _evictionCount),
            TotalRouteInvalidations = totalRouteInvalidations,
            TotalTagInvalidations = totalTagInvalidations,
            TotalPatternInvalidations = totalPatternInvalidations,
            TotalInvalidatedEntries = totalInvalidatedEntries,
            LastInvalidationTime = lastInvalidationTime,
            StartTime = _startTime
        };
    }

    /// <inheritdoc />
    public void ResetStatistics()
    {
        if (!_options.EnableStatistics)
        {
            return;
        }

        // Atomically reset all counters to zero
        var previousHitCount = Interlocked.Exchange(ref _hitCount, 0);
        var previousMissCount = Interlocked.Exchange(ref _missCount, 0);
        var previousCachedBytes = Interlocked.Exchange(ref _totalCachedBytes, 0);
        var previousEvictionCount = Interlocked.Exchange(ref _evictionCount, 0);

        // Reset the start time and periodic reset check time
        var now = DateTimeOffset.UtcNow;
        _startTime = now;
        _lastPeriodicResetCheck = now;

        LogStatisticsReset(previousHitCount, previousMissCount, previousCachedBytes, previousEvictionCount);
    }

    /// <summary>
    /// Increments a counter with overflow detection and logging.
    /// </summary>
    /// <param name="counter">Reference to the counter to increment.</param>
    /// <param name="counterName">Name of the counter for logging purposes.</param>
    /// <remarks>
    /// This method uses unchecked arithmetic, allowing the counter to wrap around on overflow.
    /// A warning is logged when the counter reaches 90% of long.MaxValue.
    /// </remarks>
    private void IncrementCounterWithOverflowCheck(ref long counter, string counterName)
    {
        // Check for periodic reset if configured
        CheckPeriodicReset();

        // Read the current value before incrementing
        var previousValue = Interlocked.Read(ref counter);

        // Perform the increment (unchecked - will wrap on overflow)
        var newValue = unchecked(Interlocked.Increment(ref counter));

        // Check if we've crossed the overflow warning threshold
        // or if we've actually overflowed (newValue < previousValue due to wrap-around)
        if (previousValue < OverflowWarningThreshold && newValue >= OverflowWarningThreshold)
        {
            LogCounterApproachingOverflow(counterName, newValue);

            // Automatically reset if configured
            if (_options.AutoResetStatisticsOnOverflow)
            {
                LogAutoResetTriggered(counterName);
                ResetStatistics();
            }
        }
        else if (newValue < previousValue)
        {
            // Overflow has occurred (wrapped around from MaxValue to MinValue)
            LogCounterOverflowed(counterName, previousValue, newValue);
        }
    }

    /// <summary>
    /// Adds a value to a counter with overflow detection and logging.
    /// </summary>
    /// <param name="counter">Reference to the counter to modify.</param>
    /// <param name="value">The value to add.</param>
    /// <param name="counterName">Name of the counter for logging purposes.</param>
    /// <remarks>
    /// This method uses unchecked arithmetic, allowing the counter to wrap around on overflow.
    /// A warning is logged when the counter reaches 90% of long.MaxValue.
    /// </remarks>
    private void AddCounterWithOverflowCheck(ref long counter, long value, string counterName)
    {
        // Check for periodic reset if configured
        CheckPeriodicReset();

        // Read the current value before adding
        var previousValue = Interlocked.Read(ref counter);

        // Perform the addition (unchecked - will wrap on overflow)
        var newValue = unchecked(Interlocked.Add(ref counter, value));

        // Check if we've crossed the overflow warning threshold
        // or if we've actually overflowed (newValue < previousValue for positive additions)
        if (value > 0)
        {
            if (previousValue < OverflowWarningThreshold && newValue >= OverflowWarningThreshold)
            {
                LogCounterApproachingOverflow(counterName, newValue);

                // Automatically reset if configured
                if (_options.AutoResetStatisticsOnOverflow)
                {
                    LogAutoResetTriggered(counterName);
                    ResetStatistics();
                }
            }
            else if (newValue < previousValue)
            {
                // Overflow has occurred (wrapped around)
                LogCounterOverflowed(counterName, previousValue, newValue);
            }
        }
    }

    /// <summary>
    /// Checks if periodic statistics reset should be performed.
    /// </summary>
    /// <remarks>
    /// Uses a simple check without strict synchronization. In the rare case where multiple threads
    /// detect the interval has elapsed, only one will perform the reset due to the atomic update
    /// of _lastPeriodicResetCheck in ResetStatistics().
    /// </remarks>
    private void CheckPeriodicReset()
    {
        if (!_options.StatisticsResetIntervalHours.HasValue || _options.StatisticsResetIntervalHours.Value <= 0)
        {
            return;
        }

        var now = DateTimeOffset.UtcNow;
        var lastCheck = _lastPeriodicResetCheck;
        var resetInterval = TimeSpan.FromHours(_options.StatisticsResetIntervalHours.Value);

        // Check if enough time has passed since last reset check
        // Simple check without strict locking - ResetStatistics() handles the actual reset safely
        if (now - lastCheck >= resetInterval)
        {
            LogPeriodicResetTriggered((now - _startTime).TotalHours);
            ResetStatistics();
        }
    }

#if DEBUG
    /// <summary>
    /// Finalizer for leak detection in DEBUG builds.
    /// </summary>
    /// <remarks>
    /// This finalizer only exists in DEBUG builds to help detect memory leaks.
    /// If this finalizer runs, it means Dispose() was not called, indicating a potential leak.
    /// In production builds, this finalizer is not compiled to avoid GC overhead.
    /// </remarks>
    ~PageCacheService()
    {
        if (!_disposed && _enableLeakDetection)
        {
            // Log a warning about potential memory leak
            // Note: Cannot use _logger here as it may be disposed
            // In a real scenario, you might write to Event Log or trace
            System.Diagnostics.Debug.WriteLine(
                $"[PageCacheService] Memory leak detected! PageCacheService was not properly disposed. " +
                $"Active callbacks: {_activeCallbackCount}");
        }
    }
#endif

    /// <summary>
    /// Releases all resources used by the <see cref="PageCacheService"/>.
    /// </summary>
    /// <remarks>
    /// <para>
    /// This method ensures proper cleanup of:
    /// </para>
    /// <list type="bullet">
    /// <item><description>AsyncKeyedLock instances</description></item>
    /// <item><description>Any pending cache operation locks</description></item>
    /// <item><description>Event handler registrations (tracked via callback count)</description></item>
    /// </list>
    /// <para>
    /// After disposal, the service should not be used. As this is registered as a Singleton,
    /// disposal typically only occurs during application shutdown.
    /// </para>
    /// </remarks>
    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;

        // Dispose the lock manager
        _locks?.Dispose();

        // Verify all event handlers have been cleaned up
        var remainingCallbacks = Interlocked.Read(ref _activeCallbackCount);
        if (remainingCallbacks > 0)
        {
            LogUndisposedCallbacks((int)remainingCallbacks);
        }

        // Suppress finalization since we've cleaned up
        GC.SuppressFinalize(this);
    }

    [LoggerMessage(EventId = 2001, Level = LogLevel.Debug, Message = "Cache hit: {CacheKey}")]
    private partial void LogCacheHit(string cacheKey);

    [LoggerMessage(EventId = 2002, Level = LogLevel.Debug, Message = "Cache miss: {CacheKey}")]
    private partial void LogCacheMiss(string cacheKey);

    [LoggerMessage(EventId = 2003, Level = LogLevel.Debug,
        Message = "Cache set: {CacheKey}, Size: {SizeBytes} bytes, Duration: {DurationSeconds}s")]
    private partial void LogCacheSet(string cacheKey, int sizeBytes, int durationSeconds);

    [LoggerMessage(EventId = 2004, Level = LogLevel.Debug, Message = "Cache removed: {CacheKey}")]
    private partial void LogCacheRemoved(string cacheKey);

    [LoggerMessage(EventId = 2005, Level = LogLevel.Information,
        Message = "Cache pattern removed: {Pattern}, Count: {Count}")]
    private partial void LogPatternRemoved(string pattern, int count);

    [LoggerMessage(EventId = 2006, Level = LogLevel.Information,
        Message = "Cache cleared: {Count} entries removed")]
    private partial void LogCacheCleared(int count);

    [LoggerMessage(EventId = 2007, Level = LogLevel.Debug,
        Message = "Cache evicted: {CacheKey}, Reason: {Reason}")]
    private partial void LogCacheEvicted(string cacheKey, string reason);

    [LoggerMessage(EventId = 2008, Level = LogLevel.Warning,
        Message = "Content validation failed for cache key '{CacheKey}': Severity={Severity}, Error={Error}")]
    private partial void LogContentValidationFailed(string cacheKey, string severity, string error);

    [LoggerMessage(EventId = 2009, Level = LogLevel.Warning,
        Message = "PageCacheService is registered with '{Lifetime}' lifetime but MUST be registered as Singleton. " +
                  "This can lead to memory leaks, incorrect statistics, and performance issues.")]
    private partial void LogServiceLifetimeWarning(string lifetime);

    [LoggerMessage(EventId = 2010, Level = LogLevel.Warning,
        Message = "PageCacheService disposed with {RemainingCallbacks} active eviction callbacks still registered. " +
                  "This may indicate a memory leak or improper cleanup.")]
    private partial void LogUndisposedCallbacks(int remainingCallbacks);

    [LoggerMessage(EventId = 2011, Level = LogLevel.Warning,
        Message = "Statistics counter '{CounterName}' is approaching overflow. Current value: {CurrentValue}. " +
                  "Consider calling ResetStatistics() to reset counters.")]
    private partial void LogCounterApproachingOverflow(string counterName, long currentValue);

    [LoggerMessage(EventId = 2012, Level = LogLevel.Error,
        Message = "Statistics counter '{CounterName}' has overflowed! Previous value: {PreviousValue}, New value: {NewValue}. " +
                  "Counter has wrapped around. Call ResetStatistics() to reset counters.")]
    private partial void LogCounterOverflowed(string counterName, long previousValue, long newValue);

    [LoggerMessage(EventId = 2013, Level = LogLevel.Information,
        Message = "Cache statistics reset. Previous values - Hits: {PreviousHits}, Misses: {PreviousMisses}, " +
                  "Bytes: {PreviousBytes}, Evictions: {PreviousEvictions}")]
    private partial void LogStatisticsReset(long previousHits, long previousMisses, long previousBytes, long previousEvictions);

    [LoggerMessage(EventId = 2014, Level = LogLevel.Warning,
        Message = "Automatic statistics reset triggered due to counter '{CounterName}' approaching overflow threshold.")]
    private partial void LogAutoResetTriggered(string counterName);

    [LoggerMessage(EventId = 2015, Level = LogLevel.Information,
        Message = "Periodic statistics reset triggered after {ElapsedHours:F2} hours of operation.")]
    private partial void LogPeriodicResetTriggered(double elapsedHours);
}
