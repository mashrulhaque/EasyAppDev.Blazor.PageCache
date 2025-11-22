using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using EasyAppDev.Blazor.PageCache.Abstractions;
using EasyAppDev.Blazor.PageCache.Configuration;
using EasyAppDev.Blazor.PageCache.Services;
using EasyAppDev.Blazor.PageCache.Storage;
using EasyAppDev.Blazor.PageCache.Events;
using EasyAppDev.Blazor.PageCache.Compression;
using EasyAppDev.Blazor.PageCache.Security;

namespace EasyAppDev.Blazor.PageCache.Extensions;

/// <summary>
/// Extension methods for <see cref="IServiceCollection"/> to add page caching services.
/// </summary>
public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Adds Blazor page caching services to the service collection.
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <returns>The service collection for chaining.</returns>
    public static IServiceCollection AddPageCache(this IServiceCollection services)
    {
        return services.AddPageCache(_ => { });
    }

    /// <summary>
    /// Adds Blazor page caching services to the service collection with configuration.
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <param name="configure">Configuration action for <see cref="PageCacheOptions"/>.</param>
    /// <returns>The service collection for chaining.</returns>
    public static IServiceCollection AddPageCache(
        this IServiceCollection services,
        Action<PageCacheOptions> configure)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configure);

        services.Configure(configure);
        services.TryAddEnumerable(
            ServiceDescriptor.Singleton<IValidateOptions<PageCacheOptions>, PageCacheOptionsValidator>());

        services.AddMemoryCache();

        services.TryAddSingleton<ICacheStorage, MemoryCacheStorage>();

        // Register DefaultCacheKeyGenerator both as interface and concrete type
        // so it can be resolved directly for testing purposes
        services.TryAddSingleton<DefaultCacheKeyGenerator>();
        services.TryAddSingleton<ICacheKeyGenerator>(sp => sp.GetRequiredService<DefaultCacheKeyGenerator>());

        services.TryAddSingleton<IPageCacheEvents, DefaultPageCacheEvents>();

        services.TryAddSingleton<ICompressionStrategy>(sp =>
        {
            var options = sp.GetRequiredService<IOptions<PageCacheOptions>>().Value;

            // Check if explicit type is set
            if (options.CompressionStrategyType != null)
            {
                return (ICompressionStrategy)ActivatorUtilities.CreateInstance(sp, options.CompressionStrategyType);
            }

            if (options.CompressCachedContent)
            {
                return new GZipCompressionStrategy();
            }

            return null!;
        });

        services.TryAddSingleton<AsyncKeyedLock>();

        services.TryAddSingleton<IRateLimiter, SlidingWindowRateLimiter>();

        // Register security audit logger (optional, enabled by default)
        services.TryAddSingleton<ISecurityAuditLogger>(sp =>
        {
            var logger = sp.GetRequiredService<ILogger<SecurityAuditLogger>>();
            var options = sp.GetRequiredService<IOptions<PageCacheOptions>>().Value;
            // Enable audit logging if security logging is enabled in options
            return new SecurityAuditLogger(logger, options.Security.LogSecurityEvents);
        });

        // CRITICAL SECURITY FIX (Issue 4.1): Auto-register HtmlSanitizerValidator when HTML validation is enabled
        // This ensures XSS protection is active by default without requiring manual registration
        services.TryAddSingleton<IContentValidator>(sp =>
        {
            var options = sp.GetRequiredService<IOptions<PageCacheOptions>>().Value;

            // Only register if HTML validation is enabled (default is true for security-by-default)
            if (options.Security.EnableHtmlValidation)
            {
                var logger = sp.GetRequiredService<ILogger<Validation.HtmlSanitizerValidator>>();
                var securityOptions = Options.Create(options.Security);
                var auditLogger = sp.GetService<ISecurityAuditLogger>();

                return new Validation.HtmlSanitizerValidator(securityOptions, logger, auditLogger);
            }

            // If validation is explicitly disabled, return a no-op validator
            return new Validation.NoOpValidator();
        });

        // FIX: Register PageCacheInvalidator with factory to break circular dependency
        // The invalidator is created without the cache service, then the cache service is set later
        services.TryAddSingleton<IPageCacheInvalidator>(sp =>
        {
            var options = sp.GetRequiredService<IOptions<PageCacheOptions>>();
            var logger = sp.GetRequiredService<ILogger<PageCacheInvalidator>>();
            var invalidator = new PageCacheInvalidator(options, logger);
            return invalidator;
        });

        // IMPORTANT: PageCacheService MUST be registered as Singleton
        // Rationale:
        // 1. Event Handler Memory: The service registers PostEvictionCallback handlers for each cached item.
        //    If registered as Scoped/Transient, these handlers would accumulate and never be cleaned up,
        //    causing memory leaks as they hold references to disposed service instances.
        // 2. Statistics Accuracy: Cache statistics (_hitCount, _missCount, etc.) are instance fields.
        //    Multiple instances would fragment these statistics making them meaningless.
        // 3. Lock Coordination: The AsyncKeyedLock prevents cache stampede by coordinating across requests.
        //    This only works correctly when all requests share the same lock instance.
        // 4. Performance: Creating new instances per request/scope would be wasteful for a caching service.
        //
        // FIX: Create service and wire up bidirectional dependencies to break circular dependency
        services.TryAddSingleton<IPageCacheService>(sp =>
        {
            var storage = sp.GetRequiredService<ICacheStorage>();
            var options = sp.GetRequiredService<IOptions<PageCacheOptions>>();
            var locks = sp.GetRequiredService<AsyncKeyedLock>();
            var logger = sp.GetRequiredService<ILogger<PageCacheService>>();
            var events = sp.GetRequiredService<IPageCacheEvents>();
            var compression = sp.GetService<ICompressionStrategy>();
            var validator = sp.GetService<IContentValidator>();

            var service = new PageCacheService(storage, options, locks, logger, events, compression, validator, sp);

            // Wire up bidirectional dependencies after both services are constructed
            var invalidator = sp.GetRequiredService<IPageCacheInvalidator>();

            // Set invalidator in service for statistics integration
            service.SetInvalidator(invalidator);

            // Set cache service in invalidator to break circular dependency
            if (invalidator is PageCacheInvalidator concreteInvalidator)
            {
                concreteInvalidator.SetCacheService(service);
            }

            return service;
        });

        services.TryAddScoped<Filters.PageCacheEndpointFilter>();

        return services;
    }

    /// <summary>
    /// Adds Blazor page caching services to the service collection using a fluent builder.
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <param name="configure">Configuration action for the builder.</param>
    /// <returns>The builder for further configuration.</returns>
    public static PageCacheBuilder AddPageCacheBuilder(
        this IServiceCollection services,
        Action<PageCacheBuilder>? configure = null)
    {
        ArgumentNullException.ThrowIfNull(services);

        // Create builder
        var builder = new PageCacheBuilder(services);

        // Configure using builder if provided
        configure?.Invoke(builder);

        // Build all services using existing AddPageCache
        services.AddPageCache(options => { });

        // Apply builder-specific registrations
        builder.Build();

        return builder;
    }
}
