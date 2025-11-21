using System.Collections.Concurrent;

namespace EasyAppDev.Blazor.PageCache.Security;

/// <summary>
/// Thread-safe rate limiter using a sliding window algorithm.
/// </summary>
/// <remarks>
/// This implementation uses a sliding window to track request timestamps.
/// It automatically cleans up expired entries to prevent memory leaks.
/// </remarks>
public sealed class SlidingWindowRateLimiter : IRateLimiter, IDisposable
{
    private readonly ConcurrentDictionary<string, RateLimitState> _state = new();
    private readonly Timer _cleanupTimer;
    private readonly TimeSpan _cleanupInterval = TimeSpan.FromMinutes(5);
    private readonly TimeSpan _maxWindowAge = TimeSpan.FromHours(1);
    private bool _disposed;

    /// <summary>
    /// Initializes a new instance of the <see cref="SlidingWindowRateLimiter"/> class.
    /// </summary>
    public SlidingWindowRateLimiter()
    {
        // Set up periodic cleanup to prevent memory leaks
        _cleanupTimer = new Timer(
            CleanupExpiredEntries,
            null,
            _cleanupInterval,
            _cleanupInterval);
    }

    /// <inheritdoc />
    public bool IsAllowed(
        string key,
        int maxAttempts,
        int windowSeconds,
        out int remainingAttempts,
        out DateTimeOffset resetTime)
    {
        if (string.IsNullOrEmpty(key))
        {
            throw new ArgumentException("Key cannot be null or empty.", nameof(key));
        }

        if (maxAttempts <= 0)
        {
            throw new ArgumentException("Max attempts must be greater than zero.", nameof(maxAttempts));
        }

        if (windowSeconds <= 0)
        {
            throw new ArgumentException("Window seconds must be greater than zero.", nameof(windowSeconds));
        }

        ObjectDisposedException.ThrowIf(_disposed, this);

        var now = DateTimeOffset.UtcNow;
        var windowDuration = TimeSpan.FromSeconds(windowSeconds);

        // Get or create the rate limit state for this key
        var state = _state.GetOrAdd(key, _ => new RateLimitState());

        lock (state.Lock)
        {
            // Remove timestamps that are outside the sliding window
            var cutoffTime = now - windowDuration;
            while (state.Timestamps.Count > 0 && state.Timestamps.Peek() < cutoffTime)
            {
                state.Timestamps.Dequeue();
            }

            // Calculate remaining attempts
            var currentCount = state.Timestamps.Count;
            remainingAttempts = Math.Max(0, maxAttempts - currentCount);

            // Calculate reset time (when the oldest entry expires)
            if (state.Timestamps.Count > 0)
            {
                resetTime = state.Timestamps.Peek() + windowDuration;
            }
            else
            {
                resetTime = now + windowDuration;
            }

            // Check if request is allowed
            if (currentCount >= maxAttempts)
            {
                return false;
            }

            // Record this request
            state.Timestamps.Enqueue(now);
            state.LastAccessTime = now;
            remainingAttempts--;

            return true;
        }
    }

    /// <inheritdoc />
    public void Reset(string key)
    {
        if (string.IsNullOrEmpty(key))
        {
            throw new ArgumentException("Key cannot be null or empty.", nameof(key));
        }

        ObjectDisposedException.ThrowIf(_disposed, this);

        _state.TryRemove(key, out _);
    }

    /// <inheritdoc />
    public void Clear()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        _state.Clear();
    }

    /// <summary>
    /// Cleans up expired entries that haven't been accessed recently.
    /// </summary>
    private void CleanupExpiredEntries(object? state)
    {
        if (_disposed)
        {
            return;
        }

        try
        {
            var now = DateTimeOffset.UtcNow;
            var keysToRemove = new List<string>();

            // Find keys that haven't been accessed in a while
            foreach (var kvp in _state)
            {
                var rateLimitState = kvp.Value;
                lock (rateLimitState.Lock)
                {
                    // If no access for a long time, remove the entry
                    if (now - rateLimitState.LastAccessTime > _maxWindowAge)
                    {
                        keysToRemove.Add(kvp.Key);
                    }
                }
            }

            // Remove expired entries
            foreach (var key in keysToRemove)
            {
                _state.TryRemove(key, out _);
            }
        }
        catch
        {
            // Suppress exceptions in background cleanup
            // The next cleanup cycle will retry
        }
    }

    /// <summary>
    /// Disposes the rate limiter and cleans up resources.
    /// </summary>
    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        _cleanupTimer?.Dispose();
        _state.Clear();
    }

    /// <summary>
    /// Internal state for tracking rate limits per key.
    /// </summary>
    private sealed class RateLimitState
    {
        /// <summary>
        /// Lock object for thread-safe access to this state.
        /// </summary>
        public object Lock { get; } = new object();

        /// <summary>
        /// Queue of request timestamps within the current window.
        /// </summary>
        public Queue<DateTimeOffset> Timestamps { get; } = new Queue<DateTimeOffset>();

        /// <summary>
        /// Last time this key was accessed.
        /// </summary>
        public DateTimeOffset LastAccessTime { get; set; } = DateTimeOffset.UtcNow;
    }
}
