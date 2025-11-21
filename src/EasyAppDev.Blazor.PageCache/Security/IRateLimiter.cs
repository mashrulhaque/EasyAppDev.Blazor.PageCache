namespace EasyAppDev.Blazor.PageCache.Security;

/// <summary>
/// Defines a rate limiter for controlling request frequency.
/// </summary>
public interface IRateLimiter
{
    /// <summary>
    /// Checks if a request is allowed for the specified key.
    /// </summary>
    /// <param name="key">The unique identifier for the resource being rate limited (e.g., cache key, IP address).</param>
    /// <param name="maxAttempts">Maximum number of attempts allowed within the time window.</param>
    /// <param name="windowSeconds">Time window in seconds.</param>
    /// <param name="remainingAttempts">Output parameter indicating how many attempts remain in the current window.</param>
    /// <param name="resetTime">Output parameter indicating when the rate limit window will reset.</param>
    /// <returns><c>true</c> if the request is allowed; otherwise, <c>false</c>.</returns>
    bool IsAllowed(
        string key,
        int maxAttempts,
        int windowSeconds,
        out int remainingAttempts,
        out DateTimeOffset resetTime);

    /// <summary>
    /// Resets the rate limit state for a specific key.
    /// </summary>
    /// <param name="key">The key to reset.</param>
    void Reset(string key);

    /// <summary>
    /// Clears all rate limit state.
    /// </summary>
    void Clear();
}
