using EasyAppDev.Blazor.PageCache.Abstractions;
using EasyAppDev.Blazor.PageCache.Attributes;
using Microsoft.AspNetCore.Http;

namespace EasyAppDev.Blazor.PageCache.Tests.Services;

/// <summary>
/// Test helper extensions for ICacheKeyGenerator to simplify test code.
/// </summary>
internal static class CacheKeyGeneratorTestExtensions
{
    /// <summary>
    /// Generates a cache key with specified query parameter variations.
    /// </summary>
    public static string GenerateKey(
        this ICacheKeyGenerator generator,
        HttpContext context,
        string[]? varyByQueryKeys = null,
        string? varyByHeader = null,
        bool cacheForAuthenticatedUsers = false)
    {
        var attribute = new PageCacheAttribute
        {
            VaryByQueryKeys = varyByQueryKeys,
            VaryByHeader = varyByHeader,
            CacheForAuthenticatedUsers = cacheForAuthenticatedUsers
        };

        return generator.GenerateKey(context, attribute);
    }
}
