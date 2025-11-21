using Microsoft.Extensions.Logging;
using System.Collections.Concurrent;
using System.Diagnostics;

namespace EasyAppDev.Blazor.PageCache.Security;

/// <summary>
/// Provides security audit logging and metrics tracking for cache security events.
/// </summary>
/// <remarks>
/// This logger captures security-relevant events such as validation failures, rate limit violations,
/// cache key injection attempts, and suspicious patterns. It uses structured logging and tracks
/// metrics that can be exported for monitoring and alerting.
///
/// IMPORTANT: This logger is designed to NOT log PII (Personally Identifiable Information) or
/// sensitive data. All logged content is sanitized to remove or truncate potentially sensitive information.
/// </remarks>
public sealed partial class SecurityAuditLogger : ISecurityAuditLogger
{
    private readonly ILogger<SecurityAuditLogger> _logger;
    private readonly bool _enabled;

    // Metrics tracking
    private long _validationFailureCount;
    private long _rateLimitViolationCount;
    private long _injectionAttemptCount;
    private long _suspiciousPatternCount;
    private long _xssDetectionCount;
    private long _sizeViolationCount;

    // Thread-safe collection of recent security events for metrics
    private readonly ConcurrentQueue<SecurityEvent> _recentEvents = new();
    private const int MaxRecentEvents = 1000;

    // Correlation ID storage (thread-local for async contexts)
    private static readonly AsyncLocal<string?> _correlationId = new();

    public SecurityAuditLogger(ILogger<SecurityAuditLogger> logger, bool enabled = true)
    {
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _enabled = enabled;
    }

    /// <summary>
    /// Sets the correlation ID for the current async context.
    /// </summary>
    /// <param name="correlationId">The correlation ID to set.</param>
    public void SetCorrelationId(string correlationId)
    {
        _correlationId.Value = correlationId;
    }

    /// <summary>
    /// Gets the current correlation ID, or generates a new one if not set.
    /// </summary>
    public string GetOrCreateCorrelationId()
    {
        if (string.IsNullOrEmpty(_correlationId.Value))
        {
            _correlationId.Value = Guid.NewGuid().ToString("N");
        }
        return _correlationId.Value;
    }

    /// <summary>
    /// Logs a validation failure event.
    /// </summary>
    /// <param name="context">The validation failure context.</param>
    public void LogValidationFailure(ValidationFailureContext context)
    {
        if (!_enabled) return;

        Interlocked.Increment(ref _validationFailureCount);

        var correlationId = GetOrCreateCorrelationId();
        var sanitizedContent = SanitizeContent(context.MatchedContent);

        LogValidationFailureEvent(
            correlationId,
            SanitizeCacheKey(context.CacheKey),
            context.ValidatorType,
            context.Severity,
            context.ErrorMessage,
            sanitizedContent,
            context.RequestPath,
            context.ElapsedMs);

        RecordSecurityEvent(SecurityEventType.ValidationFailure, context.Severity, correlationId);
    }

    /// <summary>
    /// Logs a rate limit violation event.
    /// </summary>
    /// <param name="context">The rate limit violation context.</param>
    public void LogRateLimitViolation(RateLimitViolationContext context)
    {
        if (!_enabled) return;

        Interlocked.Increment(ref _rateLimitViolationCount);

        var correlationId = GetOrCreateCorrelationId();

        LogRateLimitViolationEvent(
            correlationId,
            SanitizeCacheKey(context.CacheKey),
            context.ClientIdentifier,
            context.AttemptCount,
            context.MaxAttempts,
            context.WindowSeconds,
            context.ResetTime,
            context.RequestPath);

        RecordSecurityEvent(SecurityEventType.RateLimitViolation, "Warning", correlationId);
    }

    /// <summary>
    /// Logs a cache key injection attempt.
    /// </summary>
    /// <param name="context">The injection attempt context.</param>
    public void LogInjectionAttempt(InjectionAttemptContext context)
    {
        if (!_enabled) return;

        Interlocked.Increment(ref _injectionAttemptCount);

        var correlationId = GetOrCreateCorrelationId();
        var sanitizedInput = SanitizeContent(context.SuspiciousInput);

        LogInjectionAttemptEvent(
            correlationId,
            context.InputType,
            sanitizedInput,
            context.DetectedPattern,
            context.RequestPath,
            context.ClientIdentifier);

        RecordSecurityEvent(SecurityEventType.InjectionAttempt, "Critical", correlationId);
    }

    /// <summary>
    /// Logs a suspicious pattern detection event.
    /// </summary>
    /// <param name="context">The suspicious pattern context.</param>
    public void LogSuspiciousPattern(SuspiciousPatternContext context)
    {
        if (!_enabled) return;

        Interlocked.Increment(ref _suspiciousPatternCount);

        var correlationId = GetOrCreateCorrelationId();
        var sanitizedContent = SanitizeContent(context.MatchedContent);

        LogSuspiciousPatternEvent(
            correlationId,
            SanitizeCacheKey(context.CacheKey),
            context.PatternName,
            sanitizedContent,
            context.RequestPath);

        RecordSecurityEvent(SecurityEventType.SuspiciousPattern, context.Severity, correlationId);
    }

    /// <summary>
    /// Logs an XSS detection event.
    /// </summary>
    /// <param name="context">The XSS detection context.</param>
    public void LogXssDetection(XssDetectionContext context)
    {
        if (!_enabled) return;

        Interlocked.Increment(ref _xssDetectionCount);

        var correlationId = GetOrCreateCorrelationId();
        var sanitizedContent = SanitizeContent(context.MatchedContent);

        LogXssDetectionEvent(
            correlationId,
            SanitizeCacheKey(context.CacheKey),
            context.PatternName,
            context.PatternCategory,
            sanitizedContent,
            context.RequestPath,
            context.ValidationTimeMs);

        RecordSecurityEvent(SecurityEventType.XssDetection, "Critical", correlationId);
    }

    /// <summary>
    /// Logs a content size violation event.
    /// </summary>
    /// <param name="context">The size violation context.</param>
    public void LogSizeViolation(SizeViolationContext context)
    {
        if (!_enabled) return;

        Interlocked.Increment(ref _sizeViolationCount);

        var correlationId = GetOrCreateCorrelationId();

        LogSizeViolationEvent(
            correlationId,
            SanitizeCacheKey(context.CacheKey),
            context.ActualSize,
            context.MaxSize,
            context.RequestPath);

        RecordSecurityEvent(SecurityEventType.SizeViolation, "Warning", correlationId);
    }

    /// <summary>
    /// Gets current security metrics.
    /// </summary>
    /// <returns>A snapshot of current security metrics.</returns>
    public SecurityMetrics GetMetrics()
    {
        return new SecurityMetrics
        {
            ValidationFailureCount = Interlocked.Read(ref _validationFailureCount),
            RateLimitViolationCount = Interlocked.Read(ref _rateLimitViolationCount),
            InjectionAttemptCount = Interlocked.Read(ref _injectionAttemptCount),
            SuspiciousPatternCount = Interlocked.Read(ref _suspiciousPatternCount),
            XssDetectionCount = Interlocked.Read(ref _xssDetectionCount),
            SizeViolationCount = Interlocked.Read(ref _sizeViolationCount),
            RecentEventCount = _recentEvents.Count,
            Timestamp = DateTimeOffset.UtcNow
        };
    }

    /// <summary>
    /// Resets all security metrics counters.
    /// </summary>
    /// <remarks>
    /// This should only be called during testing or when intentionally resetting metrics.
    /// </remarks>
    public void ResetMetrics()
    {
        Interlocked.Exchange(ref _validationFailureCount, 0);
        Interlocked.Exchange(ref _rateLimitViolationCount, 0);
        Interlocked.Exchange(ref _injectionAttemptCount, 0);
        Interlocked.Exchange(ref _suspiciousPatternCount, 0);
        Interlocked.Exchange(ref _xssDetectionCount, 0);
        Interlocked.Exchange(ref _sizeViolationCount, 0);
        _recentEvents.Clear();
    }

    /// <summary>
    /// Gets recent security events for analysis.
    /// </summary>
    /// <param name="maxEvents">Maximum number of events to return.</param>
    /// <returns>A list of recent security events.</returns>
    public IReadOnlyList<SecurityEvent> GetRecentEvents(int maxEvents = 100)
    {
        return _recentEvents.Take(Math.Min(maxEvents, MaxRecentEvents)).ToList();
    }

    /// <summary>
    /// Sanitizes cache key to remove potentially sensitive information.
    /// </summary>
    /// <remarks>
    /// This method removes user-specific data while preserving enough information
    /// for security analysis.
    /// </remarks>
    private static string SanitizeCacheKey(string cacheKey)
    {
        if (string.IsNullOrEmpty(cacheKey))
            return "[empty]";

        // Limit length to prevent log flooding
        if (cacheKey.Length > 200)
            return cacheKey.Substring(0, 200) + "...[truncated]";

        // Remove potential PII patterns (email, user IDs, etc.)
        // For now, just truncate - could be enhanced with regex
        return cacheKey;
    }

    /// <summary>
    /// Sanitizes content to remove PII and limit size.
    /// </summary>
    private static string SanitizeContent(string? content)
    {
        if (string.IsNullOrEmpty(content))
            return "[empty]";

        // Limit to first 100 characters to prevent log flooding
        // and reduce risk of logging sensitive data
        if (content.Length > 100)
            return content.Substring(0, 100) + "...[truncated]";

        return content;
    }

    /// <summary>
    /// Records a security event in the recent events queue.
    /// </summary>
    private void RecordSecurityEvent(SecurityEventType eventType, string severity, string correlationId)
    {
        var securityEvent = new SecurityEvent
        {
            EventType = eventType,
            Severity = severity,
            CorrelationId = correlationId,
            Timestamp = DateTimeOffset.UtcNow
        };

        _recentEvents.Enqueue(securityEvent);

        // Trim queue if it exceeds max size
        while (_recentEvents.Count > MaxRecentEvents)
        {
            _recentEvents.TryDequeue(out _);
        }
    }

    // Structured logging methods using LoggerMessage source generation

    [LoggerMessage(EventId = 5001, Level = LogLevel.Warning,
        Message = "[SECURITY][ValidationFailure] CorrelationId={CorrelationId}, CacheKey={CacheKey}, Validator={ValidatorType}, Severity={Severity}, Error={ErrorMessage}, MatchedContent={MatchedContent}, Path={RequestPath}, Duration={ElapsedMs}ms")]
    private partial void LogValidationFailureEvent(
        string correlationId,
        string cacheKey,
        string validatorType,
        string severity,
        string errorMessage,
        string matchedContent,
        string requestPath,
        long elapsedMs);

    [LoggerMessage(EventId = 5002, Level = LogLevel.Warning,
        Message = "[SECURITY][RateLimitViolation] CorrelationId={CorrelationId}, CacheKey={CacheKey}, Client={ClientIdentifier}, Attempts={AttemptCount}/{MaxAttempts}, Window={WindowSeconds}s, ResetTime={ResetTime}, Path={RequestPath}")]
    private partial void LogRateLimitViolationEvent(
        string correlationId,
        string cacheKey,
        string clientIdentifier,
        int attemptCount,
        int maxAttempts,
        int windowSeconds,
        DateTimeOffset resetTime,
        string requestPath);

    [LoggerMessage(EventId = 5003, Level = LogLevel.Error,
        Message = "[SECURITY][InjectionAttempt] CorrelationId={CorrelationId}, InputType={InputType}, SuspiciousInput={SuspiciousInput}, Pattern={DetectedPattern}, Path={RequestPath}, Client={ClientIdentifier}")]
    private partial void LogInjectionAttemptEvent(
        string correlationId,
        string inputType,
        string suspiciousInput,
        string detectedPattern,
        string requestPath,
        string clientIdentifier);

    [LoggerMessage(EventId = 5004, Level = LogLevel.Warning,
        Message = "[SECURITY][SuspiciousPattern] CorrelationId={CorrelationId}, CacheKey={CacheKey}, Pattern={PatternName}, MatchedContent={MatchedContent}, Path={RequestPath}")]
    private partial void LogSuspiciousPatternEvent(
        string correlationId,
        string cacheKey,
        string patternName,
        string matchedContent,
        string requestPath);

    [LoggerMessage(EventId = 5005, Level = LogLevel.Error,
        Message = "[SECURITY][XssDetection] CorrelationId={CorrelationId}, CacheKey={CacheKey}, Pattern={PatternName}, Category={PatternCategory}, MatchedContent={MatchedContent}, Path={RequestPath}, ValidationTime={ValidationTimeMs}ms")]
    private partial void LogXssDetectionEvent(
        string correlationId,
        string cacheKey,
        string patternName,
        string patternCategory,
        string matchedContent,
        string requestPath,
        long validationTimeMs);

    [LoggerMessage(EventId = 5006, Level = LogLevel.Warning,
        Message = "[SECURITY][SizeViolation] CorrelationId={CorrelationId}, CacheKey={CacheKey}, ActualSize={ActualSize} bytes, MaxSize={MaxSize} bytes, Path={RequestPath}")]
    private partial void LogSizeViolationEvent(
        string correlationId,
        string cacheKey,
        long actualSize,
        long maxSize,
        string requestPath);
}

/// <summary>
/// Defines the contract for security audit logging.
/// </summary>
public interface ISecurityAuditLogger
{
    /// <summary>
    /// Sets the correlation ID for the current async context.
    /// </summary>
    void SetCorrelationId(string correlationId);

    /// <summary>
    /// Gets the current correlation ID, or generates a new one if not set.
    /// </summary>
    string GetOrCreateCorrelationId();

    /// <summary>
    /// Logs a validation failure event.
    /// </summary>
    void LogValidationFailure(ValidationFailureContext context);

    /// <summary>
    /// Logs a rate limit violation event.
    /// </summary>
    void LogRateLimitViolation(RateLimitViolationContext context);

    /// <summary>
    /// Logs a cache key injection attempt.
    /// </summary>
    void LogInjectionAttempt(InjectionAttemptContext context);

    /// <summary>
    /// Logs a suspicious pattern detection event.
    /// </summary>
    void LogSuspiciousPattern(SuspiciousPatternContext context);

    /// <summary>
    /// Logs an XSS detection event.
    /// </summary>
    void LogXssDetection(XssDetectionContext context);

    /// <summary>
    /// Logs a content size violation event.
    /// </summary>
    void LogSizeViolation(SizeViolationContext context);

    /// <summary>
    /// Gets current security metrics.
    /// </summary>
    SecurityMetrics GetMetrics();

    /// <summary>
    /// Resets all security metrics counters.
    /// </summary>
    void ResetMetrics();

    /// <summary>
    /// Gets recent security events for analysis.
    /// </summary>
    IReadOnlyList<SecurityEvent> GetRecentEvents(int maxEvents = 100);
}

/// <summary>
/// Context for validation failure events.
/// </summary>
public sealed class ValidationFailureContext
{
    public required string CacheKey { get; init; }
    public required string ValidatorType { get; init; }
    public required string Severity { get; init; }
    public required string ErrorMessage { get; init; }
    public string? MatchedContent { get; init; }
    public required string RequestPath { get; init; }
    public long ElapsedMs { get; init; }
}

/// <summary>
/// Context for rate limit violation events.
/// </summary>
public sealed class RateLimitViolationContext
{
    public required string CacheKey { get; init; }
    public required string ClientIdentifier { get; init; }
    public required int AttemptCount { get; init; }
    public required int MaxAttempts { get; init; }
    public required int WindowSeconds { get; init; }
    public required DateTimeOffset ResetTime { get; init; }
    public required string RequestPath { get; init; }
}

/// <summary>
/// Context for injection attempt events.
/// </summary>
public sealed class InjectionAttemptContext
{
    public required string InputType { get; init; }
    public required string SuspiciousInput { get; init; }
    public required string DetectedPattern { get; init; }
    public required string RequestPath { get; init; }
    public required string ClientIdentifier { get; init; }
}

/// <summary>
/// Context for suspicious pattern events.
/// </summary>
public sealed class SuspiciousPatternContext
{
    public required string CacheKey { get; init; }
    public required string PatternName { get; init; }
    public required string Severity { get; init; }
    public string? MatchedContent { get; init; }
    public required string RequestPath { get; init; }
}

/// <summary>
/// Context for XSS detection events.
/// </summary>
public sealed class XssDetectionContext
{
    public required string CacheKey { get; init; }
    public required string PatternName { get; init; }
    public required string PatternCategory { get; init; }
    public string? MatchedContent { get; init; }
    public required string RequestPath { get; init; }
    public long ValidationTimeMs { get; init; }
}

/// <summary>
/// Context for size violation events.
/// </summary>
public sealed class SizeViolationContext
{
    public required string CacheKey { get; init; }
    public required long ActualSize { get; init; }
    public required long MaxSize { get; init; }
    public required string RequestPath { get; init; }
}

/// <summary>
/// Represents security metrics that can be exported for monitoring.
/// </summary>
public sealed class SecurityMetrics
{
    public long ValidationFailureCount { get; init; }
    public long RateLimitViolationCount { get; init; }
    public long InjectionAttemptCount { get; init; }
    public long SuspiciousPatternCount { get; init; }
    public long XssDetectionCount { get; init; }
    public long SizeViolationCount { get; init; }
    public int RecentEventCount { get; init; }
    public DateTimeOffset Timestamp { get; init; }

    /// <summary>
    /// Gets the total number of security events.
    /// </summary>
    public long TotalSecurityEvents =>
        ValidationFailureCount +
        RateLimitViolationCount +
        InjectionAttemptCount +
        SuspiciousPatternCount +
        XssDetectionCount +
        SizeViolationCount;

    /// <summary>
    /// Gets the validation failure rate (0.0 to 1.0).
    /// </summary>
    public double ValidationFailureRate
    {
        get
        {
            var total = TotalSecurityEvents;
            return total > 0 ? (double)ValidationFailureCount / total : 0.0;
        }
    }

    /// <summary>
    /// Gets the rate limit hit rate (0.0 to 1.0).
    /// </summary>
    public double RateLimitHitRate
    {
        get
        {
            var total = TotalSecurityEvents;
            return total > 0 ? (double)RateLimitViolationCount / total : 0.0;
        }
    }

    /// <summary>
    /// Gets the injection attempt rate (0.0 to 1.0).
    /// </summary>
    public double InjectionAttemptRate
    {
        get
        {
            var total = TotalSecurityEvents;
            return total > 0 ? (double)InjectionAttemptCount / total : 0.0;
        }
    }
}

/// <summary>
/// Represents a security event for tracking and analysis.
/// </summary>
public sealed class SecurityEvent
{
    public required SecurityEventType EventType { get; init; }
    public required string Severity { get; init; }
    public required string CorrelationId { get; init; }
    public required DateTimeOffset Timestamp { get; init; }
}

/// <summary>
/// Types of security events.
/// </summary>
public enum SecurityEventType
{
    ValidationFailure,
    RateLimitViolation,
    InjectionAttempt,
    SuspiciousPattern,
    XssDetection,
    SizeViolation
}
