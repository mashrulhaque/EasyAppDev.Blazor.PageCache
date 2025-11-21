using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using System.Globalization;
using System.Security.Claims;
using System.Text;
using EasyAppDev.Blazor.PageCache.Abstractions;
using EasyAppDev.Blazor.PageCache.Attributes;
using EasyAppDev.Blazor.PageCache.Configuration;
using EasyAppDev.Blazor.PageCache.Validation;

namespace EasyAppDev.Blazor.PageCache.Services;

/// <summary>
/// Default implementation of <see cref="ICacheKeyGenerator"/> that generates cache keys based on request characteristics.
/// </summary>
public sealed class DefaultCacheKeyGenerator : ICacheKeyGenerator
{
    private readonly PageCacheOptions _options;
    private readonly ILogger<DefaultCacheKeyGenerator> _logger;

    public DefaultCacheKeyGenerator(
        IOptions<PageCacheOptions> options,
        ILogger<DefaultCacheKeyGenerator> logger)
    {
        _options = options?.Value ?? throw new ArgumentNullException(nameof(options));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    /// <inheritdoc />
    public string GenerateKey(HttpContext context, PageCacheAttribute? attribute = null)
    {
        ArgumentNullException.ThrowIfNull(context);

        var keyBuilder = new StringBuilder(_options.CacheKeyPrefix);

        var path = NormalizePath(context.Request.Path);
        keyBuilder.Append(path);

        AppendRouteValues(context, keyBuilder);

        if (attribute?.VaryByQueryKeys?.Length > 0)
        {
            AppendQueryStringVariations(context, keyBuilder, attribute.VaryByQueryKeys);
        }

        if (!string.IsNullOrWhiteSpace(attribute?.VaryByHeader))
        {
            AppendHeaderVariation(context, keyBuilder, attribute.VaryByHeader);
        }

        if (_options.VaryByCulture)
        {
            AppendCultureVariation(keyBuilder);
        }

        // SECURITY FIX (Issue 3.1): Capture RequireAuthenticatedUsers state ONCE to prevent race condition
        // We use the attribute passed in (if available) OR retrieve from endpoint metadata exactly once.
        // This prevents TOCTOU vulnerability where metadata could change between IsCacheable() and GenerateKey() calls.
        bool requireAuthenticatedUsers = false;
        if (attribute != null)
        {
            requireAuthenticatedUsers = attribute.CacheForAuthenticatedUsers;
        }
        else if (context.User?.Identity?.IsAuthenticated == true)
        {
            // Only retrieve endpoint metadata if we don't have the attribute already
            var endpoint = context.GetEndpoint();
            var pageCacheAttr = endpoint?.Metadata.GetMetadata<PageCacheAttribute>();
            requireAuthenticatedUsers = pageCacheAttr?.CacheForAuthenticatedUsers == true;
        }

        // SECURITY: Include user identity in cache key when caching authenticated users
        if (context.User?.Identity?.IsAuthenticated == true && requireAuthenticatedUsers)
        {
            AppendUserIdentity(context, keyBuilder);
        }

        var cacheKey = keyBuilder.ToString();

        // SECURITY FIX (Issue 1.1): Validate generated cache key before returning
        var validationResult = CacheKeyValidator.Validate(cacheKey);
        if (!validationResult.IsValid)
        {
            _logger.LogError(
                "Generated cache key failed validation: {ErrorMessage}. Key: {CacheKey}",
                validationResult.ErrorMessage,
                cacheKey);

            throw new InvalidOperationException(
                $"Generated cache key failed security validation: {validationResult.ErrorMessage}");
        }

        _logger.LogDebug("Generated cache key: {CacheKey} for path: {Path}", cacheKey, path);

        return cacheKey;
    }

    /// <inheritdoc />
    public bool IsCacheable(HttpContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        var request = context.Request;

        // Only cache GET requests
        if (!HttpMethods.IsGet(request.Method))
        {
            _logger.LogDebug("Request not cacheable: Method is {Method}", request.Method);
            return false;
        }

        // Check if user is authenticated
        if (context.User?.Identity?.IsAuthenticated == true)
        {
            // Check if endpoint has PageCacheAttribute with CacheForAuthenticatedUsers = true
            var endpoint = context.GetEndpoint();
            var pageCacheAttr = endpoint?.Metadata.GetMetadata<PageCacheAttribute>();

            if (pageCacheAttr?.CacheForAuthenticatedUsers != true)
            {
                _logger.LogDebug("Request not cacheable: User is authenticated and CacheForAuthenticatedUsers is not enabled");
                return false;
            }

            // SECURITY VALIDATION: Verify we can get a user identifier before allowing caching
            // This prevents silent data leakage if the authentication system doesn't provide user IDs
            var userId = context.User.FindFirst(ClaimTypes.NameIdentifier)?.Value
                      ?? context.User.FindFirst(ClaimTypes.Name)?.Value
                      ?? context.User.Identity?.Name;

            if (string.IsNullOrWhiteSpace(userId))
            {
                _logger.LogWarning(
                    "Request not cacheable: User is authenticated but has no user identifier. " +
                    "Cannot safely cache without NameIdentifier claim, Name claim, or Identity.Name. " +
                    "This prevents data leakage between users.");
                return false;
            }
        }

        return true;
    }

    /// <summary>
    /// Normalizes a path by converting to lowercase and ensuring consistent format.
    /// </summary>
    private static string NormalizePath(PathString path)
    {
        var normalized = path.Value ?? "/";

        // SECURITY FIX (Issue 13): Apply Unicode normalization to prevent cache key variations
        // This must be done BEFORE ToLowerInvariant() to ensure proper case folding
        normalized = normalized.Normalize(NormalizationForm.FormC);

        // Convert to lowercase for case-insensitive comparison
        normalized = normalized.ToLowerInvariant();

        // SECURITY FIX (Issue 1.2): Remove path traversal patterns (../ and ..\)
        // Replace multiple slashes with single slash, and remove path traversal sequences
        normalized = System.Text.RegularExpressions.Regex.Replace(normalized, @"\.\.[\\/]", "",
            System.Text.RegularExpressions.RegexOptions.None,
            TimeSpan.FromMilliseconds(100));
        normalized = System.Text.RegularExpressions.Regex.Replace(normalized, @"//+", "/",
            System.Text.RegularExpressions.RegexOptions.None,
            TimeSpan.FromMilliseconds(100));

        // Remove trailing slash except for root
        if (normalized.Length > 1 && normalized.EndsWith('/'))
        {
            normalized = normalized[..^1];
        }

        // SECURITY FIX (Issue 13): URL-encode non-ASCII characters after normalization
        // This ensures Unicode characters are represented as percent-encoded ASCII,
        // which passes cache key validation while preserving the normalized form
        var builder = new StringBuilder(normalized.Length * 3); // Worst case: all chars need encoding
        foreach (var ch in normalized)
        {
            if (ch > 127) // Non-ASCII character
            {
                // URL-encode the character
                var bytes = System.Text.Encoding.UTF8.GetBytes(new[] { ch });
                foreach (var b in bytes)
                {
                    builder.Append('%');
                    builder.Append(b.ToString("X2"));
                }
            }
            else
            {
                builder.Append(ch);
            }
        }

        return builder.ToString();
    }

    /// <summary>
    /// Appends route values to the cache key for dynamic routes.
    /// </summary>
    private static void AppendRouteValues(HttpContext context, StringBuilder keyBuilder)
    {
        var routeValues = context.GetRouteData()?.Values;
        if (routeValues == null || routeValues.Count == 0)
        {
            return;
        }

        // Sort route values for consistent key generation
        var sortedRouteValues = routeValues
            .Where(kvp => kvp.Key != "page" && kvp.Value != null) // Exclude 'page' (Blazor internal)
            .OrderBy(kvp => kvp.Key, StringComparer.OrdinalIgnoreCase)
            .ToList();

        if (sortedRouteValues.Count == 0)
        {
            return;
        }

        keyBuilder.Append(":rv:");
        foreach (var kvp in sortedRouteValues)
        {
            // SECURITY: Sanitize route values to prevent cache key injection
            var sanitizedKey = CacheKeySanitizer.SanitizeKeySegment(kvp.Key.ToLowerInvariant());
            var sanitizedValue = CacheKeySanitizer.SanitizeKeySegment(kvp.Value?.ToString()?.ToLowerInvariant());

            keyBuilder.Append(sanitizedKey);
            keyBuilder.Append(':');
            keyBuilder.Append(sanitizedValue);
            keyBuilder.Append(':');
        }

        // Remove trailing ':' (defensive check)
        if (keyBuilder.Length > 0 && keyBuilder[keyBuilder.Length - 1] == ':')
        {
            keyBuilder.Length--;
        }
    }

    /// <summary>
    /// Appends specified query string parameters to the cache key.
    /// </summary>
    private void AppendQueryStringVariations(
        HttpContext context,
        StringBuilder keyBuilder,
        string[] varyByQueryKeys)
    {
        var query = context.Request.Query;
        if (query.Count == 0)
        {
            return;
        }

        var relevantParams = new List<(string Key, string Value)>();

        foreach (var queryKey in varyByQueryKeys)
        {
            // SECURITY FIX (Issue 1.5): Check ignored parameters BEFORE sanitization
            // This ensures parameters with special characters in their names are properly excluded
            // when they appear in the IgnoredQueryParameters list
            if (_options.IgnoredQueryParameters.Contains(queryKey))
            {
                continue; // Skip this parameter - it's in the ignore list
            }

            if (query.TryGetValue(queryKey, out var values))
            {
                var value = values.ToString();
                if (!string.IsNullOrEmpty(value))
                {
                    // SECURITY: Sanitize query parameters to prevent cache key injection
                    var sanitizedKey = CacheKeySanitizer.SanitizeKeySegment(queryKey.ToLowerInvariant());
                    var sanitizedValue = CacheKeySanitizer.SanitizeKeySegment(value.ToLowerInvariant());
                    relevantParams.Add((sanitizedKey, sanitizedValue));
                }
            }
        }

        // Sort parameters for consistent key generation
        relevantParams = relevantParams
            .OrderBy(p => p.Key, StringComparer.OrdinalIgnoreCase)
            .ToList();

        if (relevantParams.Count == 0)
        {
            return;
        }

        keyBuilder.Append(":qs:");
        foreach (var (key, value) in relevantParams)
        {
            keyBuilder.Append(key);
            keyBuilder.Append(':');
            keyBuilder.Append(value);
            keyBuilder.Append(':');
        }

        // Remove trailing ':' (defensive check)
        if (keyBuilder.Length > 0 && keyBuilder[keyBuilder.Length - 1] == ':')
        {
            keyBuilder.Length--;
        }
    }

    /// <summary>
    /// Appends header value to the cache key.
    /// </summary>
    private static void AppendHeaderVariation(
        HttpContext context,
        StringBuilder keyBuilder,
        string headerName)
    {
        if (context.Request.Headers.TryGetValue(headerName, out var headerValue))
        {
            var value = headerValue.ToString();
            if (!string.IsNullOrWhiteSpace(value))
            {
                // SECURITY: Sanitize header values to prevent cache key injection
                var sanitizedName = CacheKeySanitizer.SanitizeKeySegment(headerName.ToLowerInvariant());
                var sanitizedValue = CacheKeySanitizer.SanitizeKeySegment(value.ToLowerInvariant());

                keyBuilder.Append(":h:");
                keyBuilder.Append(sanitizedName);
                keyBuilder.Append(':');
                keyBuilder.Append(sanitizedValue);
            }
        }
    }

    /// <summary>
    /// Appends current culture to the cache key.
    /// </summary>
    private static void AppendCultureVariation(StringBuilder keyBuilder)
    {
        var culture = CultureInfo.CurrentCulture.Name;

        // SECURITY FIX (Issue 1.4): Sanitize culture string to prevent cache key injection
        var sanitizedCulture = CacheKeySanitizer.SanitizeKeySegment(culture.ToLowerInvariant());

        keyBuilder.Append(":c:");
        keyBuilder.Append(sanitizedCulture);
    }

    /// <summary>
    /// Appends user identity to the cache key for authenticated users.
    /// </summary>
    /// <remarks>
    /// This is critical for security when caching authenticated user content.
    /// Without this, User A's cached content would be served to User B.
    /// </remarks>
    private void AppendUserIdentity(HttpContext context, StringBuilder keyBuilder)
    {
        // Try to get user identifier in order of preference:
        // 1. NameIdentifier claim (most common for authentication systems)
        // 2. Name claim (fallback)
        // 3. Identity.Name property (last resort)
        var userId = context.User.FindFirst(ClaimTypes.NameIdentifier)?.Value
                  ?? context.User.FindFirst(ClaimTypes.Name)?.Value
                  ?? context.User.Identity?.Name;

        if (string.IsNullOrWhiteSpace(userId))
        {
            // SECURITY: We cannot safely cache content for an authenticated user without a user identifier
            // This would cause data leakage between users
            _logger.LogError(
                "Cannot generate cache key for authenticated user without user identifier. " +
                "User is authenticated but has no NameIdentifier, Name claim, or Identity.Name. " +
                "Caching will fail for this request to prevent data leakage.");

            throw new InvalidOperationException(
                "Cannot cache content for authenticated user: No user identifier found. " +
                "The authenticated user must have a NameIdentifier claim, Name claim, or Identity.Name. " +
                "This is required to prevent serving cached content from one user to another.");
        }

        // SECURITY FIX (Issue 3.2): Use case-sensitive user IDs to prevent collisions
        // Different users with IDs like "Admin" and "admin" must get different cache keys
        // SECURITY: Sanitize user identity to prevent cache key injection
        var sanitizedUserId = CacheKeySanitizer.SanitizeKeySegment(userId);

        keyBuilder.Append(":uid:");
        keyBuilder.Append(sanitizedUserId);

        _logger.LogDebug("Including user identity in cache key: {UserId}", userId);
    }
}
