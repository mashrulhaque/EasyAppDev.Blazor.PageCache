namespace EasyAppDev.Blazor.PageCache.Configuration;

/// <summary>
/// Security-related configuration options for page caching.
/// </summary>
public sealed class SecurityOptions
{
    /// <summary>
    /// Gets or sets a value indicating whether HTML validation is enabled.
    /// Default is <c>true</c> (security-by-default).
    /// </summary>
    /// <remarks>
    /// When enabled, cached HTML will be scanned for potentially malicious patterns
    /// like inline scripts, event handlers, and javascript: URLs.
    /// Set to false to disable validation if you have other security measures in place.
    /// </remarks>
    public bool EnableHtmlValidation { get; set; } = true;

    /// <summary>
    /// Gets or sets the HTML validation sampling rate (1 in N requests).
    /// Default is 1 (validate every request).
    /// </summary>
    /// <remarks>
    /// <para>
    /// DEPRECATED: This property is deprecated and no longer used as of the Phase 1 security fixes.
    /// Sampling was removed because it created a critical security vulnerability where 90% of requests
    /// could bypass XSS validation entirely with samplingRate=10.
    /// </para>
    /// <para>
    /// ALL requests are now validated to ensure comprehensive XSS protection.
    /// This property is kept for backward compatibility but has no effect.
    /// It will be removed in a future major version.
    /// </para>
    /// <para>
    /// If performance is a concern, consider:
    /// - Optimizing your HTML generation
    /// - Using Content Security Policy (CSP) headers
    /// - Disabling validation entirely (not recommended) via EnableHtmlValidation = false
    /// </para>
    /// </remarks>
    [Obsolete("Sampling has been removed for security reasons. All requests are now validated. This property will be removed in a future version.")]
    public int HtmlValidationSamplingRate { get; set; } = 1;

    /// <summary>
    /// Gets or sets a value indicating whether content size validation is enabled.
    /// Default is <c>true</c>.
    /// </summary>
    public bool EnableSizeValidation { get; set; } = true;

    /// <summary>
    /// Gets or sets the maximum allowed size per cache entry in bytes.
    /// Default is 5 MB (5,242,880 bytes). Set to null for no limit.
    /// </summary>
    /// <remarks>
    /// This helps prevent DoS attacks where an attacker tries to exhaust
    /// cache memory by causing the server to cache very large responses.
    /// </remarks>
    public int? MaxEntrySizeBytes { get; set; } = 5 * 1024 * 1024; // 5 MB

    /// <summary>
    /// Gets or sets the threshold for warning about large cache entries in bytes.
    /// Default is 1 MB (1,048,576 bytes). Set to null to disable warnings.
    /// </summary>
    public int? WarnOnLargeEntrySizeBytes { get; set; } = 1024 * 1024; // 1 MB

    /// <summary>
    /// Gets or sets the maximum number of script tags allowed in cached content.
    /// Default is 50.
    /// </summary>
    /// <remarks>
    /// An unusually high number of script tags may indicate compromised content.
    /// This check only applies when EnableHtmlValidation is true.
    /// </remarks>
    public int MaxScriptTagsAllowed { get; set; } = 50;

    /// <summary>
    /// Gets or sets a value indicating whether to enable rate limiting per cache key.
    /// Default is <c>true</c>.
    /// </summary>
    /// <remarks>
    /// Prevents abuse where an attacker repeatedly requests cache regeneration
    /// to cause resource exhaustion.
    /// </remarks>
    public bool EnableRateLimiting { get; set; } = true;

    /// <summary>
    /// Gets or sets the maximum number of cache regeneration attempts per key within the time window.
    /// Default is 10.
    /// </summary>
    public int RateLimitMaxAttempts { get; set; } = 10;

    /// <summary>
    /// Gets or sets the rate limit time window in seconds.
    /// Default is 60 seconds.
    /// </summary>
    public int RateLimitWindowSeconds { get; set; } = 60;

    /// <summary>
    /// Gets or sets the maximum number of cache entries allowed.
    /// Default is null (no limit). Set to a positive value to prevent unbounded cache growth.
    /// </summary>
    /// <remarks>
    /// <para>
    /// This helps prevent DoS attacks where an attacker tries to exhaust memory
    /// by forcing the server to cache many unique pages. When the limit is reached,
    /// the oldest entries are evicted based on LRU (Least Recently Used) policy.
    /// </para>
    /// <para>
    /// Example: Setting to 1000 means the cache will hold at most 1000 entries.
    /// This works in conjunction with MaxEntrySizeBytes and MaxCacheSizeMB to
    /// provide comprehensive memory protection.
    /// </para>
    /// </remarks>
    public int? MaxCacheEntryCount { get; set; } = null;

    /// <summary>
    /// Gets or sets a value indicating whether to cache content for authenticated users.
    /// Default is <c>false</c> for security reasons.
    /// </summary>
    /// <remarks>
    /// <para>
    /// DEPRECATED: This setting is deprecated. Use the <c>CacheForAuthenticatedUsers</c> property
    /// on the <see cref="Attributes.PageCacheAttribute"/> instead for per-page control.
    /// </para>
    /// <para>
    /// When <c>CacheForAuthenticatedUsers</c> is enabled on a page attribute, the library automatically
    /// includes the user's identity (NameIdentifier claim, Name claim, or Identity.Name) in the cache key
    /// to ensure each user gets their own cached version. If no user identifier is found, caching is refused
    /// to prevent data leakage between users.
    /// </para>
    /// </remarks>
    [Obsolete("Use CacheForAuthenticatedUsers on PageCacheAttribute instead. This property is no longer used.")]
    public bool CacheForAuthenticatedUsers { get; set; } = false;

    /// <summary>
    /// Gets or sets a value indicating whether to log security validation failures.
    /// Default is <c>true</c>.
    /// </summary>
    public bool LogSecurityEvents { get; set; } = true;

    /// <summary>
    /// Gets or sets a value indicating whether to block caching on validation failure.
    /// Default is <c>true</c>.
    /// </summary>
    /// <remarks>
    /// When true, content that fails validation will not be cached.
    /// When false, validation warnings are logged but caching proceeds.
    /// Critical validation failures always block caching regardless of this setting.
    /// </remarks>
    public bool BlockOnValidationFailure { get; set; } = true;

    /// <summary>
    /// Gets or sets a value indicating whether to expose debug headers (X-Page-Cache, X-RateLimit-*).
    /// Default is <c>false</c> (security-by-default).
    /// </summary>
    /// <remarks>
    /// <para>
    /// When enabled, responses will include debug headers showing cache hit/miss status
    /// and rate limit information. These headers can leak information about the caching
    /// strategy and potentially be used for timing attacks.
    /// </para>
    /// <para>
    /// In production environments, these headers should be disabled unless you have
    /// specific monitoring requirements. A warning will be logged if headers are
    /// exposed in production.
    /// </para>
    /// </remarks>
    public bool ExposeDebugHeaders { get; set; } = false;

    /// <summary>
    /// Gets or sets a value indicating whether to add random timing jitter to cache responses.
    /// Default is <c>true</c> (security-by-default).
    /// </summary>
    /// <remarks>
    /// <para>
    /// Adding random delays to cache responses helps mitigate timing attacks where
    /// attackers could infer cache hit/miss status based on response times.
    /// </para>
    /// <para>
    /// The jitter is cryptographically random and ranges from 0 to MaxJitterMilliseconds.
    /// This normalizes response times between cache hits and misses, making timing-based
    /// attacks significantly more difficult.
    /// </para>
    /// </remarks>
    public bool AddTimingJitter { get; set; } = true;

    /// <summary>
    /// Gets or sets the maximum random delay in milliseconds for timing jitter.
    /// Default is 50 milliseconds.
    /// </summary>
    /// <remarks>
    /// <para>
    /// This value represents the upper bound for random delays added to cache responses.
    /// The actual delay is a cryptographically random value between 0 and this maximum.
    /// </para>
    /// <para>
    /// Higher values provide better security against timing attacks but may impact
    /// perceived performance. Lower values reduce performance impact but provide
    /// less protection. The default of 50ms provides a good balance for most applications.
    /// </para>
    /// </remarks>
    public int MaxJitterMilliseconds { get; set; } = 50;

    /// <summary>
    /// Gets or sets a value indicating whether Content Security Policy (CSP) headers should be added
    /// to cached responses. Default is <c>false</c>.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Content Security Policy is a powerful security feature that helps prevent cross-site scripting (XSS),
    /// clickjacking, and other code injection attacks by restricting the sources from which content can be loaded.
    /// </para>
    /// <para>
    /// When enabled, the CSP header specified in <see cref="ContentSecurityPolicy"/> will be added to all
    /// cached responses served by the PageCacheServeMiddleware.
    /// </para>
    /// <para>
    /// Use the <see cref="Security.CspBuilder"/> class to construct a CSP policy programmatically,
    /// or set the <see cref="ContentSecurityPolicy"/> property directly with your policy string.
    /// </para>
    /// </remarks>
    public bool EnableContentSecurityPolicy { get; set; } = false;

    /// <summary>
    /// Gets or sets the Content Security Policy (CSP) header value to add to cached responses.
    /// Default is <c>null</c> (no CSP header).
    /// </summary>
    /// <remarks>
    /// <para>
    /// This property specifies the CSP policy directives that will be included in the response header.
    /// The policy should be a properly formatted CSP directive string.
    /// </para>
    /// <para>
    /// Example:
    /// <code>
    /// ContentSecurityPolicy = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline';"
    /// </code>
    /// </para>
    /// <para>
    /// For easier policy construction, use the <see cref="Security.CspBuilder"/> class:
    /// <code>
    /// var policy = new CspBuilder()
    ///     .WithDefaultSrc("'self'")
    ///     .WithScriptSrc("'self'", "'unsafe-inline'")
    ///     .WithStyleSrc("'self'", "'unsafe-inline'")
    ///     .Build();
    /// </code>
    /// </para>
    /// <para>
    /// This property is only used when <see cref="EnableContentSecurityPolicy"/> is <c>true</c>.
    /// </para>
    /// </remarks>
    public string? ContentSecurityPolicy { get; set; }

    /// <summary>
    /// Gets or sets a value indicating whether the CSP should be enforced in report-only mode.
    /// Default is <c>false</c> (enforcement mode).
    /// </summary>
    /// <remarks>
    /// <para>
    /// In report-only mode, the CSP policy is not enforced, but violations are reported.
    /// This is useful for testing CSP policies without breaking existing functionality.
    /// </para>
    /// <para>
    /// When <c>true</c>, the header name will be "Content-Security-Policy-Report-Only" instead
    /// of "Content-Security-Policy". Browsers will report violations but will not block resources
    /// that violate the policy.
    /// </para>
    /// <para>
    /// Use this mode to:
    /// <list type="bullet">
    /// <item>Test new CSP policies before enforcing them</item>
    /// <item>Monitor violations in production without impacting users</item>
    /// <item>Gradually roll out CSP policies</item>
    /// </list>
    /// </para>
    /// </remarks>
    public bool CspReportOnlyMode { get; set; } = false;
}
