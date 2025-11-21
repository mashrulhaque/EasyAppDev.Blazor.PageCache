using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Hosting;
using System.Text;
using EasyAppDev.Blazor.PageCache.Abstractions;
using EasyAppDev.Blazor.PageCache.Configuration;
using EasyAppDev.Blazor.PageCache.Services;
using EasyAppDev.Blazor.PageCache.Attributes;
using EasyAppDev.Blazor.PageCache.Security;

namespace EasyAppDev.Blazor.PageCache.Middleware;

/// <summary>
/// Middleware that captures rendered HTML output and stores it in the cache.
/// </summary>
public class PageCacheCaptureMiddleware
{
    private readonly RequestDelegate _next;
    private readonly IPageCacheService _cacheService;
    private readonly IPageCacheInvalidator _invalidator;
    private readonly ICacheKeyGenerator _keyGenerator;
    private readonly ILogger<PageCacheCaptureMiddleware> _logger;
    private readonly PageCacheOptions _options;
    private readonly IRateLimiter? _rateLimiter;
    private readonly IHostEnvironment? _hostEnvironment;
    private readonly ISecurityAuditLogger? _auditLogger;
    private bool _productionHeaderWarningLogged = false;

    public PageCacheCaptureMiddleware(
        RequestDelegate next,
        IPageCacheService cacheService,
        IPageCacheInvalidator invalidator,
        ICacheKeyGenerator keyGenerator,
        IOptions<PageCacheOptions> options,
        ILogger<PageCacheCaptureMiddleware> logger,
        IRateLimiter? rateLimiter,
        IHostEnvironment? hostEnvironment = null,
        ISecurityAuditLogger? auditLogger = null)
    {
        _next = next ?? throw new ArgumentNullException(nameof(next));
        _cacheService = cacheService ?? throw new ArgumentNullException(nameof(cacheService));
        _invalidator = invalidator ?? throw new ArgumentNullException(nameof(invalidator));
        _keyGenerator = keyGenerator ?? throw new ArgumentNullException(nameof(keyGenerator));
        _options = options?.Value ?? throw new ArgumentNullException(nameof(options));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
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

        // Get endpoint metadata to extract PageCache attribute EARLY
        // We need this to generate the cache key and check rate limits BEFORE rendering
        var endpoint = context.GetEndpoint();
        var pageCacheAttr = endpoint?.Metadata.GetMetadata<PageCacheAttribute>();

        // ONLY cache pages that have the PageCacheAttribute
        if (pageCacheAttr == null)
        {
            await _next(context);
            return;
        }

        // SECURITY FIX (Issue 1.3): Pass PageCacheAttribute to GenerateKey() so VaryByQueryKeys/VaryByHeader are included
        var cacheKey = _keyGenerator.GenerateKey(context, pageCacheAttr);
        var route = context.Request.Path.Value ?? "/";

        // CRITICAL FIX (Issue 2.2 & 5.1): Check rate limit BEFORE rendering
        // This prevents DoS attacks where rendering happens even when rate limited
        // Also implements per-client rate limiting to prevent one attacker from exhausting
        // the rate limit for all users on a page
        if (_options.Security.EnableRateLimiting && _rateLimiter != null)
        {
            // Get client IP address for per-client rate limiting
            var clientIp = GetClientIpAddress(context);

            // Use combination of client IP + cache key for rate limiting
            // This ensures each client has independent rate limit per page
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
                // Log warning if exposing headers in production
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
                    "Rate limit exceeded for client {ClientIp} on cache key: {CacheKey}. Reset at: {ResetTime}",
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
                    RequestPath = route
                });

                // Return 429 Too Many Requests BEFORE rendering
                // This prevents resource exhaustion attacks
                context.Response.StatusCode = StatusCodes.Status429TooManyRequests;
                context.Response.ContentType = "text/plain";

                // Add Retry-After header (in seconds)
                var retryAfterSeconds = (int)(resetTime - DateTimeOffset.UtcNow).TotalSeconds;
                if (retryAfterSeconds > 0)
                {
                    context.Response.Headers["Retry-After"] = retryAfterSeconds.ToString();
                }

                await context.Response.WriteAsync(
                    $"Rate limit exceeded. Please retry after {resetTime:u}");
                return;
            }
        }

        // Save the original response body stream
        var originalBodyStream = context.Response.Body;

        try
        {
            // Create a new memory stream to capture the response
            using var captureStream = new MemoryStream();

            // Replace the response body with our capture stream
            context.Response.Body = captureStream;

            // Call the next middleware in the pipeline (rendering happens here)
            // At this point, we've already verified:
            // 1. This is a GET request
            // 2. The page is cacheable
            // 3. The page has PageCacheAttribute
            // 4. Rate limit has not been exceeded (if enabled)
            await _next(context);

            // After rendering, check if we should cache the response
            // Only cache successful responses (200 OK)
            if (context.Response.StatusCode == StatusCodes.Status200OK)
            {
                // Check if Content-Type is text/html
                var contentType = context.Response.ContentType ?? string.Empty;
                if (contentType.Contains("text/html", StringComparison.OrdinalIgnoreCase))
                {
                    // Read the captured HTML from the memory stream
                    captureStream.Position = 0;
                    string capturedHtml;

                    using (var reader = new StreamReader(captureStream, Encoding.UTF8, leaveOpen: true))
                    {
                        capturedHtml = await reader.ReadToEndAsync();
                    }

                    // Only cache if we captured some content
                    if (!string.IsNullOrWhiteSpace(capturedHtml))
                    {
                        try
                        {
                            int duration = _options.DefaultDurationSeconds;
                            string[]? tags = null;

                            // Use duration from attribute if specified
                            if (pageCacheAttr.Duration > 0)
                            {
                                duration = pageCacheAttr.Duration;
                            }

                            tags = pageCacheAttr.Tags;

                            // CRITICAL SECURITY FIX (Issue 6.1): Register cache key BEFORE storing
                            // This prevents race condition where invalidation could happen between
                            // storage and registration, creating orphaned cache entries that can
                            // never be invalidated (stale data served indefinitely)
                            if (_invalidator is PageCacheInvalidator invalidatorImpl)
                            {
                                invalidatorImpl.RegisterCacheKey(route, cacheKey, tags);
                            }

                            // Now store the cached HTML
                            // Even if invalidation happens now, the entry is already registered and can be found
                            await _cacheService.SetCachedHtmlAsync(cacheKey, capturedHtml, duration);

                            // Conditionally add debug header
                            if (_options.Security.ExposeDebugHeaders)
                            {
                                context.Response.Headers["X-Page-Cache"] = "MISS";
                            }

                            _logger.LogDebug(
                                "Captured and cached HTML for route: {Route} ({Size} bytes, {Duration}s TTL)",
                                route,
                                capturedHtml.Length,
                                duration);
                        }
                        catch (Exception ex)
                        {
                            // Log error but don't prevent response from being sent
                            _logger.LogError(ex, "Failed to cache HTML for route: {Route}", context.Request.Path);
                        }
                    }
                }
            }

            // Add Content Security Policy header if enabled
            // This ensures CSP is applied consistently for both cache hits and misses
            if (!context.Response.HasStarted &&
                _options.Security.EnableContentSecurityPolicy &&
                !string.IsNullOrWhiteSpace(_options.Security.ContentSecurityPolicy))
            {
                var headerName = _options.Security.CspReportOnlyMode
                    ? "Content-Security-Policy-Report-Only"
                    : "Content-Security-Policy";

                context.Response.Headers[headerName] = _options.Security.ContentSecurityPolicy;

                _logger.LogTrace(
                    "Added CSP header '{HeaderName}' to cache miss response for route: {Route}",
                    headerName,
                    route);
            }

            // Copy the captured content back to the original response stream
            captureStream.Position = 0;
            await captureStream.CopyToAsync(originalBodyStream);
        }
        finally
        {
            // Always restore the original response body stream
            context.Response.Body = originalBodyStream;
        }
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
