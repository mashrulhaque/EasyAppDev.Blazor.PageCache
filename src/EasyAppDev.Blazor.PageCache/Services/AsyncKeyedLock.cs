using System.Collections.Concurrent;
using System.Diagnostics;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace EasyAppDev.Blazor.PageCache.Services;

/// <summary>
/// Provides keyed asynchronous locks to prevent cache stampede with enhanced safety and diagnostics.
/// </summary>
/// <remarks>
/// This implementation provides:
/// <list type="bullet">
/// <item>Thread-safe lock acquisition and release with proper disposal guards</item>
/// <item>Automatic cleanup of unused semaphores to prevent memory leaks</item>
/// <item>Lock contention tracking and performance metrics</item>
/// <item>Comprehensive diagnostic logging</item>
/// <item>Protection against race conditions during cleanup</item>
/// </list>
/// </remarks>
public sealed class AsyncKeyedLock : IDisposable
{
    private readonly ConcurrentDictionary<string, SemaphoreSlim> _locks = new();
    private readonly ConcurrentDictionary<string, int> _lockCounts = new();
    private readonly ConcurrentDictionary<string, SemaphoreMetrics> _metrics = new();
    private readonly ILogger<AsyncKeyedLock> _logger;

    // Disposal state tracking - volatile ensures visibility across threads
    private volatile bool _disposed;
    private volatile bool _disposing;

    // Global metrics
    private long _totalLocksAcquired;
    private long _totalLocksReleased;
    private long _totalTimeouts;
    private long _totalCleanups;
    private long _activeSemaphores;

    /// <summary>
    /// Initializes a new instance of the <see cref="AsyncKeyedLock"/> class.
    /// </summary>
    /// <param name="logger">Optional logger for diagnostics. If null, a null logger is used.</param>
    public AsyncKeyedLock(ILogger<AsyncKeyedLock>? logger = null)
    {
        _logger = logger ?? NullLogger<AsyncKeyedLock>.Instance;
    }

    /// <summary>
    /// Acquires a lock for the specified key with enhanced safety and diagnostics.
    /// </summary>
    /// <param name="key">The key to lock on.</param>
    /// <param name="timeout">Maximum time to wait for lock acquisition.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>A disposable lock that must be released.</returns>
    /// <exception cref="ObjectDisposedException">Thrown if the lock manager has been disposed.</exception>
    /// <exception cref="ArgumentException">Thrown if the key is null or whitespace.</exception>
    /// <exception cref="TimeoutException">Thrown if the lock could not be acquired within the timeout period.</exception>
    public async Task<IDisposable> LockAsync(
        string key,
        TimeSpan timeout,
        CancellationToken cancellationToken = default)
    {
        // Pre-acquisition checks
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentException.ThrowIfNullOrWhiteSpace(key);

        // Prevent new acquisitions during disposal
        if (_disposing)
        {
            _logger.LogWarning("Lock acquisition attempted for key '{Key}' during disposal", key);
            throw new ObjectDisposedException(nameof(AsyncKeyedLock), "Cannot acquire lock during disposal");
        }

        var stopwatch = Stopwatch.StartNew();
        SemaphoreSlim? semaphore = null;
        bool semaphoreAcquired = false;

        try
        {
            // Get or create semaphore for this key
            semaphore = _locks.GetOrAdd(key, _ =>
            {
                Interlocked.Increment(ref _activeSemaphores);
                _logger.LogDebug("Created new semaphore for key '{Key}'. Active semaphores: {Count}",
                    key, _activeSemaphores);
                return new SemaphoreSlim(1, 1);
            });

            // Track metrics for this key
            var metrics = _metrics.GetOrAdd(key, _ => new SemaphoreMetrics());
            Interlocked.Increment(ref metrics.WaitingThreads);

            // Increment reference count before waiting
            _lockCounts.AddOrUpdate(key, 1, (_, count) => count + 1);

            _logger.LogDebug("Attempting to acquire lock for key '{Key}'. Waiting threads: {WaitingThreads}",
                key, metrics.WaitingThreads);

            // Wait for lock with timeout and cancellation support
            semaphoreAcquired = await semaphore.WaitAsync(timeout, cancellationToken);

            // Post-acquisition disposal check - critical safety check
            if (_disposed || _disposing)
            {
                _logger.LogWarning("Lock manager disposed while acquiring lock for key '{Key}'", key);

                // Release the semaphore if we acquired it
                if (semaphoreAcquired)
                {
                    semaphore.Release();
                    semaphoreAcquired = false;
                }

                DecrementLockCount(key);
                throw new ObjectDisposedException(nameof(AsyncKeyedLock),
                    "Lock manager was disposed during lock acquisition");
            }

            if (!semaphoreAcquired)
            {
                // Timeout - decrement count and track timeout
                DecrementLockCount(key);
                Interlocked.Decrement(ref metrics.WaitingThreads);
                Interlocked.Increment(ref _totalTimeouts);
                Interlocked.Increment(ref metrics.TimeoutCount);

                stopwatch.Stop();
                _logger.LogWarning("Lock acquisition timeout for key '{Key}' after {Elapsed}ms. " +
                    "Timeout: {Timeout}ms, Waiting threads: {WaitingThreads}, Total timeouts: {TotalTimeouts}",
                    key, stopwatch.ElapsedMilliseconds, timeout.TotalMilliseconds,
                    metrics.WaitingThreads, _totalTimeouts);

                throw new TimeoutException($"Failed to acquire lock for key '{key}' within {timeout}");
            }

            // Successfully acquired
            stopwatch.Stop();
            Interlocked.Increment(ref _totalLocksAcquired);
            Interlocked.Increment(ref metrics.AcquisitionCount);
            Interlocked.Decrement(ref metrics.WaitingThreads);

            // Track wait time
            var waitTime = stopwatch.ElapsedMilliseconds;
            UpdateAverageWaitTime(metrics, waitTime);

            if (waitTime > 100) // Log if wait time is significant
            {
                _logger.LogInformation("Lock acquired for key '{Key}' after {WaitTime}ms. " +
                    "Acquisitions: {Acquisitions}, Avg wait: {AvgWait}ms",
                    key, waitTime, metrics.AcquisitionCount, metrics.AverageWaitTimeMs);
            }
            else
            {
                _logger.LogDebug("Lock acquired for key '{Key}' in {WaitTime}ms", key, waitTime);
            }

            return new LockReleaser(this, key, semaphore);
        }
        catch (OperationCanceledException)
        {
            // Cancellation - clean up and rethrow
            if (semaphoreAcquired && semaphore != null)
            {
                semaphore.Release();
            }
            DecrementLockCount(key);

            if (_metrics.TryGetValue(key, out var metrics))
            {
                Interlocked.Decrement(ref metrics.WaitingThreads);
            }

            _logger.LogDebug("Lock acquisition cancelled for key '{Key}'", key);
            throw;
        }
        catch (Exception ex) when (ex is not TimeoutException && ex is not ObjectDisposedException)
        {
            // Unexpected error - clean up
            if (semaphoreAcquired && semaphore != null)
            {
                semaphore.Release();
            }
            DecrementLockCount(key);

            if (_metrics.TryGetValue(key, out var metrics))
            {
                Interlocked.Decrement(ref metrics.WaitingThreads);
            }

            _logger.LogError(ex, "Unexpected error acquiring lock for key '{Key}'", key);
            throw;
        }
    }

    /// <summary>
    /// Releases a lock and performs cleanup if needed with enhanced safety.
    /// </summary>
    /// <param name="key">The key to release the lock for.</param>
    /// <param name="semaphore">The semaphore to release.</param>
    private void ReleaseLock(string key, SemaphoreSlim semaphore)
    {
        try
        {
            // Release the semaphore first - this allows waiting threads to proceed
            semaphore.Release();

            Interlocked.Increment(ref _totalLocksReleased);
            _logger.LogDebug("Lock released for key '{Key}'. Total released: {TotalReleased}",
                key, _totalLocksReleased);

            // Decrement reference count and potentially clean up
            DecrementLockCount(key);
        }
        catch (SemaphoreFullException ex)
        {
            // This should not happen in normal operation - indicates a bug
            _logger.LogError(ex, "Semaphore full exception for key '{Key}' - possible double release", key);
        }
        catch (ObjectDisposedException ex)
        {
            // Semaphore was disposed - this can happen during shutdown
            _logger.LogWarning(ex, "Attempted to release disposed semaphore for key '{Key}'", key);

            // Still need to decrement the count for cleanup
            DecrementLockCount(key);
        }
    }

    /// <summary>
    /// Decrements the reference count for a lock and cleans up if needed.
    /// Uses atomic operations and exponential backoff to prevent race conditions.
    /// </summary>
    /// <param name="key">The key to decrement the count for.</param>
    private void DecrementLockCount(string key)
    {
        const int maxRetries = 3;
        const int baseDelayMs = 1;

        for (int retry = 0; retry <= maxRetries; retry++)
        {
            // Atomically decrement the count
            var newCount = _lockCounts.AddOrUpdate(
                key,
                0, // Should not happen, but safe default
                (_, currentCount) => Math.Max(0, currentCount - 1));

            _logger.LogTrace("Decremented lock count for key '{Key}' to {Count}", key, newCount);

            // If count is now zero, try to clean up
            if (newCount == 0)
            {
                // Double-check with TryRemove to ensure atomicity
                // This might fail if another thread incremented between AddOrUpdate and here
                if (_lockCounts.TryRemove(key, out var finalCount))
                {
                    if (finalCount == 0)
                    {
                        // Successfully removed and count is still 0, safe to dispose semaphore
                        if (_locks.TryRemove(key, out var semaphore))
                        {
                            CleanupSemaphore(key, semaphore);
                            return; // Successfully cleaned up
                        }
                        else
                        {
                            _logger.LogTrace("Failed to remove semaphore for key '{Key}' - already removed", key);
                            return;
                        }
                    }
                    else
                    {
                        // Race condition: count was incremented after our check
                        // Restore the count and retry
                        _lockCounts.TryAdd(key, finalCount);
                        _logger.LogTrace("Race condition detected for key '{Key}', count is now {Count}. Retry {Retry}",
                            key, finalCount, retry);

                        if (retry < maxRetries)
                        {
                            // Exponential backoff before retry
                            Thread.Sleep(baseDelayMs * (1 << retry));
                        }
                    }
                }
                else
                {
                    // Another thread removed it - that's fine
                    _logger.LogTrace("Lock count already removed for key '{Key}'", key);
                    return;
                }
            }
            else if (newCount > 0)
            {
                // Still in use - no cleanup needed
                return;
            }
        }

        _logger.LogWarning("Failed to clean up semaphore for key '{Key}' after {MaxRetries} retries",
            key, maxRetries);
    }

    /// <summary>
    /// Safely disposes a semaphore and updates metrics.
    /// </summary>
    /// <param name="key">The key associated with the semaphore.</param>
    /// <param name="semaphore">The semaphore to dispose.</param>
    private void CleanupSemaphore(string key, SemaphoreSlim semaphore)
    {
        try
        {
            semaphore.Dispose();
            Interlocked.Increment(ref _totalCleanups);
            Interlocked.Decrement(ref _activeSemaphores);

            // Clean up metrics for this key
            _metrics.TryRemove(key, out _);

            _logger.LogDebug("Cleaned up semaphore for key '{Key}'. " +
                "Active semaphores: {ActiveSemaphores}, Total cleanups: {TotalCleanups}",
                key, _activeSemaphores, _totalCleanups);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error disposing semaphore for key '{Key}'", key);
        }
    }

    /// <summary>
    /// Updates the average wait time for lock acquisition.
    /// </summary>
    /// <param name="metrics">The metrics object to update.</param>
    /// <param name="waitTimeMs">The wait time in milliseconds.</param>
    private static void UpdateAverageWaitTime(SemaphoreMetrics metrics, long waitTimeMs)
    {
        // Simple moving average calculation
        lock (metrics)
        {
            var count = metrics.AcquisitionCount;
            var oldAvg = metrics.AverageWaitTimeMs;
            var newAvg = ((oldAvg * (count - 1)) + waitTimeMs) / count;
            metrics.AverageWaitTimeMs = newAvg;
        }
    }

    /// <summary>
    /// Gets diagnostic information about the lock manager's current state.
    /// </summary>
    /// <returns>A dictionary containing diagnostic metrics.</returns>
    public Dictionary<string, object> GetDiagnostics()
    {
        return new Dictionary<string, object>
        {
            ["ActiveSemaphores"] = _activeSemaphores,
            ["TotalLocksAcquired"] = _totalLocksAcquired,
            ["TotalLocksReleased"] = _totalLocksReleased,
            ["TotalTimeouts"] = _totalTimeouts,
            ["TotalCleanups"] = _totalCleanups,
            ["ActiveKeys"] = _locks.Count,
            ["TrackedMetrics"] = _metrics.Count,
            ["IsDisposed"] = _disposed,
            ["IsDisposing"] = _disposing
        };
    }

    /// <summary>
    /// Gets metrics for a specific key if available.
    /// </summary>
    /// <param name="key">The key to get metrics for.</param>
    /// <returns>The metrics for the key, or null if not available.</returns>
    public SemaphoreMetrics? GetKeyMetrics(string key)
    {
        return _metrics.TryGetValue(key, out var metrics) ? metrics : null;
    }

    /// <inheritdoc />
    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _logger.LogInformation("Disposing AsyncKeyedLock. Active semaphores: {ActiveSemaphores}, " +
            "Total acquired: {TotalAcquired}, Total released: {TotalReleased}",
            _activeSemaphores, _totalLocksAcquired, _totalLocksReleased);

        // Set disposing flag first to prevent new acquisitions
        _disposing = true;

        try
        {
            // Wait a brief moment for any in-flight acquisitions to complete
            Thread.Sleep(50);

            // Dispose all semaphores
            var disposedCount = 0;
            foreach (var kvp in _locks.ToArray()) // ToArray to avoid collection modified exception
            {
                try
                {
                    kvp.Value.Dispose();
                    disposedCount++;
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "Error disposing semaphore for key '{Key}'", kvp.Key);
                }
            }

            _logger.LogDebug("Disposed {DisposedCount} semaphores during cleanup", disposedCount);

            // Clear all collections
            _locks.Clear();
            _lockCounts.Clear();
            _metrics.Clear();

            // Mark as fully disposed
            _disposed = true;

            _logger.LogInformation("AsyncKeyedLock disposal complete. " +
                "Final statistics - Cleanups: {TotalCleanups}, Timeouts: {TotalTimeouts}",
                _totalCleanups, _totalTimeouts);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error during AsyncKeyedLock disposal");
            _disposed = true; // Still mark as disposed even if cleanup fails
            throw;
        }
    }

    /// <summary>
    /// Lock releaser that implements IDisposable.
    /// </summary>
    private sealed class LockReleaser : IDisposable
    {
        private readonly AsyncKeyedLock _parent;
        private readonly string _key;
        private readonly SemaphoreSlim _semaphore;
        private bool _disposed;

        public LockReleaser(AsyncKeyedLock parent, string key, SemaphoreSlim semaphore)
        {
            _parent = parent;
            _key = key;
            _semaphore = semaphore;
        }

        public void Dispose()
        {
            if (_disposed)
            {
                return;
            }

            _disposed = true;
            _parent.ReleaseLock(_key, _semaphore);
        }
    }

    /// <summary>
    /// Tracks metrics for a specific semaphore/lock key.
    /// Uses fields instead of properties for Interlocked operations.
    /// </summary>
    public sealed class SemaphoreMetrics
    {
        /// <summary>
        /// The number of threads currently waiting for this lock.
        /// </summary>
        public long WaitingThreads;

        /// <summary>
        /// The total number of times this lock has been acquired.
        /// </summary>
        public long AcquisitionCount;

        /// <summary>
        /// The number of times lock acquisition timed out.
        /// </summary>
        public long TimeoutCount;

        /// <summary>
        /// The average wait time in milliseconds for acquiring this lock.
        /// </summary>
        public double AverageWaitTimeMs;

        /// <summary>
        /// Gets the contention ratio (timeouts / total acquisitions).
        /// </summary>
        public double ContentionRatio =>
            AcquisitionCount > 0 ? (double)TimeoutCount / AcquisitionCount : 0;

        /// <summary>
        /// Returns a string representation of the metrics.
        /// </summary>
        public override string ToString()
        {
            return $"Waiting: {WaitingThreads}, Acquisitions: {AcquisitionCount}, " +
                   $"Timeouts: {TimeoutCount}, Avg Wait: {AverageWaitTimeMs:F2}ms, " +
                   $"Contention: {ContentionRatio:P2}";
        }
    }
}
