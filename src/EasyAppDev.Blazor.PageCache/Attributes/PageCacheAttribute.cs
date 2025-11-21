namespace EasyAppDev.Blazor.PageCache.Attributes;

/// <summary>
/// Marks a Razor component for page caching.
/// </summary>
/// <example>
/// <code>
/// // Simple caching with default duration
/// [PageCache]
/// @page "/about"
///
/// // Custom duration (1 hour)
/// [PageCache(Duration = 3600)]
/// @page "/features"
///
/// // Vary by query parameters
/// [PageCache(Duration = 1800, VaryByQueryKeys = new[] { "page", "category" })]
/// @page "/blog"
///
/// // With tags for grouped invalidation
/// [PageCache(Duration = 3600, Tags = new[] { "products", "catalog" })]
/// @page "/products"
/// </code>
/// </example>
[AttributeUsage(AttributeTargets.Class, AllowMultiple = false, Inherited = true)]
public sealed class PageCacheAttribute : Attribute
{
    /// <summary>
    /// Gets or sets the cache duration in seconds.
    /// If not specified, uses the default from <see cref="Configuration.PageCacheOptions.DefaultDurationSeconds"/>.
    /// </summary>
    public int Duration { get; set; }

    /// <summary>
    /// Gets or sets query string keys to vary the cache by.
    /// When specified, different query parameter values create separate cache entries.
    /// </summary>
    /// <example>
    /// <code>
    /// [PageCache(VaryByQueryKeys = new[] { "page", "category" })]
    /// </code>
    /// </example>
    public string[]? VaryByQueryKeys { get; set; }

    /// <summary>
    /// Gets or sets the header name to vary the cache by.
    /// When specified, different header values create separate cache entries.
    /// </summary>
    /// <example>
    /// <code>
    /// [PageCache(VaryByHeader = "Accept-Language")]
    /// </code>
    /// </example>
    public string? VaryByHeader { get; set; }

    /// <summary>
    /// Gets or sets tags for grouping related cache entries.
    /// Useful for bulk invalidation.
    /// </summary>
    /// <example>
    /// <code>
    /// [PageCache(Tags = new[] { "products", "catalog" })]
    /// public class ProductList : ComponentBase { }
    ///
    /// // Later, invalidate all product-related pages
    /// _invalidator.InvalidateByTag("products");
    /// </code>
    /// </example>
    public string[]? Tags { get; set; }

    /// <summary>
    /// Gets or sets a value indicating whether to cache this page even for
    /// authenticated users. Default is <c>false</c>.
    /// </summary>
    /// <remarks>
    /// <para>
    /// When enabled, the library automatically includes the user's identity in the cache key
    /// to ensure each user gets their own cached version. The user identifier is obtained from:
    /// 1. NameIdentifier claim (ClaimTypes.NameIdentifier)
    /// 2. Name claim (ClaimTypes.Name)
    /// 3. Identity.Name property
    /// </para>
    /// <para>
    /// If no user identifier is found, caching will be refused to prevent data leakage.
    /// </para>
    /// <para>
    /// WARNING: Only enable this if the page content is the same for all requests by a specific user.
    /// Do not cache pages with time-sensitive data or user-specific information that changes frequently.
    /// </para>
    /// </remarks>
    public bool CacheForAuthenticatedUsers { get; set; }
}
