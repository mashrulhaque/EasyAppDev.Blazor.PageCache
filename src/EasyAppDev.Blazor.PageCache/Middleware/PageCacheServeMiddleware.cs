using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Hosting;
using EasyAppDev.Blazor.PageCache.Abstractions;
using EasyAppDev.Blazor.PageCache.Attributes;
using EasyAppDev.Blazor.PageCache.Configuration;
using EasyAppDev.Blazor.PageCache.Services;
using EasyAppDev.Blazor.PageCache.Security;
using System.Security.Cryptography;

namespace EasyAppDev.Blazor.PageCache.Middleware;

/// <summary>
/// Middleware that serves pre-rendered HTML from cache when available.
/// Implements cache stampede prevention and rate limiting for both cache hits and misses.
/// </summary>
public class PageCacheServeMiddleware
{
    private readonly RequestDelegate _next;
    private readonly IPageCacheService _cacheService;
    private readonly ICacheKeyGenerator _keyGenerator;
    private readonly ILogger<PageCacheServeMiddleware> _logger;
    private readonly PageCacheOptions _options;
    private readonly IHostEnvironment? _hostEnvironment;
    private readonly AsyncKeyedLock _asyncKeyedLock;
    private readonly IRateLimiter? _rateLimiter;
    private readonly ISecurityAuditLogger? _auditLogger;
    private bool _productionHeaderWarningLogged = false;

    public PageCacheServeMiddleware(
        RequestDelegate next,
        IPageCacheService cacheService,
        ICacheKeyGenerator keyGenerator,
        IOptions<PageCacheOptions> options,
        ILogger<PageCacheServeMiddleware> logger,
        AsyncKeyedLock asyncKeyedLock,
        IRateLimiter? rateLimiter = null,
        IHostEnvironment? hostEnvironment = null,
        ISecurityAuditLogger? auditLogger = null)
    {
        _next = next ?? throw new ArgumentNullException(nameof(next));
        _cacheService = cacheService ?? throw new ArgumentNullException(nameof(cacheService));
        _keyGenerator = keyGenerator ?? throw new ArgumentNullException(nameof(keyGenerator));
        _options = options?.Value ?? throw new ArgumentNullException(nameof(options));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _asyncKeyedLock = asyncKeyedLock ?? throw new ArgumentNullException(nameof(asyncKeyedLock));
        _rateLimiter = rateLimiter;
        _hostEnvironment = hostEnvironment;
        _auditLogger = auditLogger;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        // Only process GET requests
        if (!HttpMethods.IsGet(context.Request.Method))
        {
            await _next(context);
            return;
        }

        if (!_keyGenerator.IsCacheable(context))
        {
            await _next(context);
            return;
        }

        // Check if endpoint has PageCacheAttribute - only serve cache for attributed pages
        var endpoint = context.GetEndpoint();
        var pageCacheAttr = endpoint?.Metadata.GetMetadata<PageCacheAttribute>();

        if (pageCacheAttr == null)
        {
            _logger.LogTrace(
                "Skipping cache lookup for route {Route}: No PageCacheAttribute found",
                context.Request.Path);
            await _next(context);
            return;
        }

        // SECURITY FIX (Issue 1.3): Pass PageCacheAttribute to GenerateKey() so VaryByQueryKeys/VaryByHeader are included
        var cacheKey = _keyGenerator.GenerateKey(context, pageCacheAttr);

        var cachedHtml = _cacheService.GetCachedHtml(cacheKey);

        if (cachedHtml != null)
        {
            // Cache hit - serve cached content
            _logger.LogDebug("Cache HIT for key: {CacheKey}", cacheKey);

            // CRITICAL SECURITY FIX (Issue 5.2): Rate limiting on cache hits
            // Check rate limit BEFORE serving cached content to prevent abuse
            if (_options.Security.EnableRateLimiting && _rateLimiter != null)
            {
                var clientIp = GetClientIpAddress(context);
                var rateLimitKey = $"{clientIp}:{cacheKey}";

                var isAllowed = _rateLimiter.IsAllowed(
                    rateLimitKey,
                    _options.Security.RateLimitMaxAttempts,
                    _options.Security.RateLimitWindowSeconds,
                    out var remainingAttempts,
                    out var resetTime);

                // Conditionally add rate limit headers
                if (_options.Security.ExposeDebugHeaders)
                {
                    // Log warning if exposing headers in production (only once)
                    if (_hostEnvironment != null &&
                        _hostEnvironment.IsProduction() &&
                        !_productionHeaderWarningLogged)
                    {
                        _logger.LogWarning(
                            "Debug headers (X-RateLimit-*) are exposed in production environment. " +
                            "This may leak rate limiting information. " +
                            "Set ExposeDebugHeaders = false in production.");
                        _productionHeaderWarningLogged = true;
                    }

                    context.Response.Headers["X-RateLimit-Limit"] =
                        _options.Security.RateLimitMaxAttempts.ToString();
                    context.Response.Headers["X-RateLimit-Remaining"] =
                        remainingAttempts.ToString();
                    context.Response.Headers["X-RateLimit-Reset"] =
                        resetTime.ToUnixTimeSeconds().ToString();
                }

                if (!isAllowed)
                {
                    _logger.LogWarning(
                        "Rate limit exceeded for cache hit. Client: {ClientIp}, CacheKey: {CacheKey}, Reset at: {ResetTime}",
                        clientIp,
                        cacheKey,
                        resetTime);

                    // Log to security audit logger
                    _auditLogger?.LogRateLimitViolation(new RateLimitViolationContext
                    {
                        CacheKey = cacheKey,
                        ClientIdentifier = clientIp,
                        AttemptCount = _options.Security.RateLimitMaxAttempts + 1,
                        MaxAttempts = _options.Security.RateLimitMaxAttempts,
                        WindowSeconds = _options.Security.RateLimitWindowSeconds,
                        ResetTime = resetTime,
                        RequestPath = context.Request.Path.Value ?? "/"
                    });

                    // Return 429 Too Many Requests
                    context.Response.StatusCode = StatusCodes.Status429TooManyRequests;
                    context.Response.Headers["Retry-After"] =
                        ((int)(resetTime - DateTimeOffset.UtcNow).TotalSeconds).ToString();

                    await context.Response.WriteAsync(
                        "Rate limit exceeded. Please try again later.");
                    return;
                }
            }

            // Add timing jitter to mitigate timing attacks
            if (_options.Security.AddTimingJitter && _options.Security.MaxJitterMilliseconds > 0)
            {
                var jitterMs = GenerateCryptographicJitter(_options.Security.MaxJitterMilliseconds);
                if (jitterMs > 0)
                {
                    await Task.Delay(jitterMs);
                }
            }

            context.Response.ContentType = "text/html; charset=utf-8";

            // Conditionally add debug headers
            if (_options.Security.ExposeDebugHeaders)
            {
                // Log warning if exposing headers in production
                if (_hostEnvironment != null &&
                    _hostEnvironment.IsProduction() &&
                    !_productionHeaderWarningLogged)
                {
                    _logger.LogWarning(
                        "Debug headers (X-Page-Cache) are exposed in production environment. " +
                        "This may leak cache information and enable timing attacks. " +
                        "Set ExposeDebugHeaders = false in production.");
                    _productionHeaderWarningLogged = true;
                }

                context.Response.Headers["X-Page-Cache"] = "HIT";
            }

            // Add Content Security Policy header if enabled
            if (_options.Security.EnableContentSecurityPolicy &&
                !string.IsNullOrWhiteSpace(_options.Security.ContentSecurityPolicy))
            {
                var headerName = _options.Security.CspReportOnlyMode
                    ? "Content-Security-Policy-Report-Only"
                    : "Content-Security-Policy";

                context.Response.Headers[headerName] = _options.Security.ContentSecurityPolicy;

                _logger.LogTrace(
                    "Added CSP header '{HeaderName}' to cached response for key: {CacheKey}",
                    headerName,
                    cacheKey);
            }

            await context.Response.WriteAsync(cachedHtml);
            return; // Short-circuit the pipeline
        }

        // Cache miss - implement cache stampede prevention (Issue 2.1)
        _logger.LogTrace("Cache MISS for key: {CacheKey}", cacheKey);

        // Acquire lock to prevent multiple concurrent renders for the same cache key
        var lockTimeout = TimeSpan.FromSeconds(_options.CacheGenerationTimeoutSeconds);

        try
        {
            _logger.LogDebug(
                "Attempting to acquire cache generation lock for key: {CacheKey} with timeout: {Timeout}s",
                cacheKey,
                _options.CacheGenerationTimeoutSeconds);

            using (var lockHandle = await _asyncKeyedLock.LockAsync(cacheKey, lockTimeout, context.RequestAborted))
            {
                _logger.LogDebug("Cache generation lock acquired for key: {CacheKey}", cacheKey);

                // Double-check cache after acquiring lock
                // Another thread might have cached it while we were waiting
                cachedHtml = _cacheService.GetCachedHtml(cacheKey);

                if (cachedHtml != null)
                {
                    // Cache was populated by another thread while we were waiting
                    _logger.LogInformation(
                        "Cache populated by another thread while waiting for lock. Key: {CacheKey}",
                        cacheKey);

                    // Serve the cached content (no rate limiting on this path since we already waited)
                    context.Response.ContentType = "text/html; charset=utf-8";

                    if (_options.Security.ExposeDebugHeaders)
                    {
                        context.Response.Headers["X-Page-Cache"] = "HIT-AFTER-WAIT";
                    }

                    // Add CSP header if enabled
                    if (_options.Security.EnableContentSecurityPolicy &&
                        !string.IsNullOrWhiteSpace(_options.Security.ContentSecurityPolicy))
                    {
                        var headerName = _options.Security.CspReportOnlyMode
                            ? "Content-Security-Policy-Report-Only"
                            : "Content-Security-Policy";

                        context.Response.Headers[headerName] = _options.Security.ContentSecurityPolicy;
                    }

                    await context.Response.WriteAsync(cachedHtml);
                    return;
                }

                // Still a cache miss after double-check, proceed with rendering
                _logger.LogDebug(
                    "Proceeding with cache generation for key: {CacheKey}",
                    cacheKey);

                await _next(context);
                // Lock will be released when lockHandle is disposed
            }
        }
        catch (TimeoutException ex)
        {
            // Lock acquisition timed out - log and render without waiting
            _logger.LogWarning(ex,
                "Cache generation lock timeout for key: {CacheKey} after {Timeout}s. " +
                "Proceeding with uncached render to maintain responsiveness.",
                cacheKey,
                _options.CacheGenerationTimeoutSeconds);

            // Render without caching to maintain responsiveness
            // The PageCacheCaptureMiddleware will handle rate limiting on cache generation
            await _next(context);
        }
        catch (OperationCanceledException) when (context.RequestAborted.IsCancellationRequested)
        {
            // Request was cancelled - log and exit gracefully
            _logger.LogDebug(
                "Request cancelled while waiting for cache generation lock. Key: {CacheKey}",
                cacheKey);

            // Don't call next middleware if request was cancelled
            throw;
        }
    }

    /// <summary>
    /// Generates a cryptographically secure random jitter value.
    /// </summary>
    /// <param name="maxJitterMs">Maximum jitter in milliseconds.</param>
    /// <returns>Random jitter value between 0 and maxJitterMs.</returns>
    private static int GenerateCryptographicJitter(int maxJitterMs)
    {
        if (maxJitterMs <= 0)
            return 0;

        // Use cryptographically secure random number generator
        return RandomNumberGenerator.GetInt32(0, maxJitterMs + 1);
    }

    /// <summary>
    /// Gets the client IP address from the HTTP context for rate limiting.
    /// </summary>
    /// <remarks>
    /// <para>
    /// This method extracts the client IP address with proper proxy header support.
    /// It checks X-Forwarded-For and X-Real-IP headers for proxied requests,
    /// but validates them to prevent header injection attacks.
    /// </para>
    /// <para>
    /// Security considerations:
    /// - Only uses proxy headers if they contain valid IP addresses
    /// - Falls back to RemoteIpAddress if proxy headers are invalid or missing
    /// - Returns "unknown" if no IP address can be determined
    /// - Handles IPv6 addresses correctly
    /// </para>
    /// </remarks>
    private static string GetClientIpAddress(HttpContext context)
    {
        // Check X-Forwarded-For header (most common in load balancer/proxy scenarios)
        // Format: X-Forwarded-For: client, proxy1, proxy2
        // We want the first (leftmost) IP which is the original client
        if (context.Request.Headers.TryGetValue("X-Forwarded-For", out var forwardedFor))
        {
            var firstIp = forwardedFor.ToString().Split(',', StringSplitOptions.RemoveEmptyEntries).FirstOrDefault();
            if (!string.IsNullOrWhiteSpace(firstIp))
            {
                firstIp = firstIp.Trim();
                // Validate it's a valid IP address to prevent injection
                if (System.Net.IPAddress.TryParse(firstIp, out var parsedIp))
                {
                    return parsedIp.ToString();
                }
            }
        }

        // Check X-Real-IP header (used by some reverse proxies like nginx)
        if (context.Request.Headers.TryGetValue("X-Real-IP", out var realIp))
        {
            var ip = realIp.ToString().Trim();
            // Validate it's a valid IP address
            if (!string.IsNullOrWhiteSpace(ip) && System.Net.IPAddress.TryParse(ip, out var parsedIp))
            {
                return parsedIp.ToString();
            }
        }

        // Fall back to RemoteIpAddress from the connection
        var remoteIp = context.Connection.RemoteIpAddress;
        if (remoteIp != null)
        {
            // Handle IPv6 loopback and IPv4-mapped IPv6 addresses
            if (remoteIp.IsIPv4MappedToIPv6)
            {
                return remoteIp.MapToIPv4().ToString();
            }
            return remoteIp.ToString();
        }

        // Last resort: use connection ID hash if no IP is available
        // This can happen in some testing or unusual deployment scenarios
        var connectionId = context.Connection.Id ?? "unknown";
        return $"conn-{connectionId.GetHashCode():X8}";
    }
}
