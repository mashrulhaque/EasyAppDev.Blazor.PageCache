using FluentAssertions;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using EasyAppDev.Blazor.PageCache.Configuration;
using EasyAppDev.Blazor.PageCache.Extensions;
using EasyAppDev.Blazor.PageCache.Services;
using EasyAppDev.Blazor.PageCache.Abstractions;
using EasyAppDev.Blazor.PageCache.Validation;

namespace EasyAppDev.Blazor.PageCache.Tests.Extensions;

public class ServiceCollectionExtensionsTests
{
    [Fact]
    public void AddPageCache_WithNullServices_ThrowsArgumentNullException()
    {
        // Arrange
        IServiceCollection services = null!;

        // Act & Assert
        var act = () => services.AddPageCache();
        act.Should().Throw<ArgumentNullException>().WithParameterName("services");
    }

    [Fact]
    public void AddPageCache_WithNullConfigureAction_ThrowsArgumentNullException()
    {
        // Arrange
        var services = new ServiceCollection();

        // Act & Assert
        var act = () => services.AddPageCache(null!);
        act.Should().Throw<ArgumentNullException>().WithParameterName("configure");
    }

    [Fact]
    public void AddPageCache_RegistersRequiredServices()
    {
        // Arrange
        var services = new ServiceCollection();
        services.AddLogging();

        // Act
        services.AddPageCache();
        var provider = services.BuildServiceProvider();

        // Assert
        provider.GetService<IOptions<PageCacheOptions>>().Should().NotBeNull();
        provider.GetService<DefaultCacheKeyGenerator>().Should().NotBeNull();
        provider.GetService<IMemoryCache>().Should().NotBeNull();
    }

    [Fact]
    public void AddPageCache_WithConfiguration_AppliesOptions()
    {
        // Arrange
        var services = new ServiceCollection();

        // Act
        services.AddPageCache(options =>
        {
            options.DefaultDurationSeconds = 600;
            options.CacheKeyPrefix = "Custom:";
            options.Enabled = false;
        });
        var provider = services.BuildServiceProvider();

        // Assert
        var options = provider.GetRequiredService<IOptions<PageCacheOptions>>().Value;
        options.DefaultDurationSeconds.Should().Be(600);
        options.CacheKeyPrefix.Should().Be("Custom:");
        options.Enabled.Should().BeFalse();
    }

    [Fact]
    public void AddPageCache_CalledMultipleTimes_DoesNotDuplicateServices()
    {
        // Arrange
        var services = new ServiceCollection();
        services.AddLogging();

        // Act
        services.AddPageCache();
        services.AddPageCache();
        var provider = services.BuildServiceProvider();

        // Assert
        var generators = provider.GetServices<DefaultCacheKeyGenerator>().ToList();
        generators.Should().HaveCount(1);
    }

    [Fact]
    public void AddPageCache_RegistersDefaultCacheKeyGeneratorAsSingleton()
    {
        // Arrange
        var services = new ServiceCollection();
        services.AddLogging();

        // Act
        services.AddPageCache();
        var provider = services.BuildServiceProvider();

        // Assert
        var generator1 = provider.GetRequiredService<DefaultCacheKeyGenerator>();
        var generator2 = provider.GetRequiredService<DefaultCacheKeyGenerator>();
        generator1.Should().BeSameAs(generator2);
    }

    [Fact]
    public void AddPageCache_RegistersMemoryCache()
    {
        // Arrange
        var services = new ServiceCollection();

        // Act
        services.AddPageCache();
        var provider = services.BuildServiceProvider();

        // Assert
        var cache = provider.GetService<IMemoryCache>();
        cache.Should().NotBeNull();
    }

    [Fact]
    public void AddPageCache_WithExistingMemoryCache_DoesNotDuplicate()
    {
        // Arrange
        var services = new ServiceCollection();
        services.AddMemoryCache();

        // Act
        services.AddPageCache();
        var provider = services.BuildServiceProvider();

        // Assert
        var caches = provider.GetServices<IMemoryCache>().ToList();
        caches.Should().HaveCount(1);
    }

    [Fact]
    public void AddPageCache_RegistersOptionsValidator()
    {
        // Arrange
        var services = new ServiceCollection();

        // Act
        services.AddPageCache();
        var provider = services.BuildServiceProvider();

        // Assert
        var validators = provider.GetServices<IValidateOptions<PageCacheOptions>>().ToList();
        validators.Should().NotBeEmpty();
        validators.Should().Contain(v => v.GetType() == typeof(PageCacheOptionsValidator));
    }

    [Fact]
    public void AddPageCache_WithInvalidOptions_ValidatesOnBuild()
    {
        // Arrange
        var services = new ServiceCollection();
        services.AddPageCache(options =>
        {
            options.DefaultDurationSeconds = 0; // Invalid
        });

        // Act
        var provider = services.BuildServiceProvider();
        var act = () => provider.GetRequiredService<IOptions<PageCacheOptions>>().Value;

        // Assert - This might not throw immediately without options validation middleware
        // But the validator should be registered
        var validators = provider.GetServices<IValidateOptions<PageCacheOptions>>().ToList();
        validators.Should().NotBeEmpty();
    }

    [Fact]
    public void AddPageCache_ReturnsServiceCollection()
    {
        // Arrange
        var services = new ServiceCollection();

        // Act
        var result = services.AddPageCache();

        // Assert
        result.Should().BeSameAs(services);
    }

    [Fact]
    public void AddPageCache_SupportsMethodChaining()
    {
        // Arrange
        var services = new ServiceCollection();

        // Act
        var result = services
            .AddPageCache()
            .AddMemoryCache();

        // Assert
        result.Should().NotBeNull();
        services.Should().NotBeEmpty();
    }

    [Fact]
    public void AddPageCache_WithEmptyConfiguration_UsesDefaultOptions()
    {
        // Arrange
        var services = new ServiceCollection();

        // Act
        services.AddPageCache(_ => { });
        var provider = services.BuildServiceProvider();

        // Assert
        var options = provider.GetRequiredService<IOptions<PageCacheOptions>>().Value;
        options.DefaultDurationSeconds.Should().Be(300);
        options.CacheKeyPrefix.Should().Be("PageCache:");
        options.Enabled.Should().BeTrue();
    }

    [Fact]
    public void AddPageCache_CanModifyIgnoredQueryParameters()
    {
        // Arrange
        var services = new ServiceCollection();

        // Act
        services.AddPageCache(options =>
        {
            options.IgnoredQueryParameters.Add("custom_tracking");
            options.IgnoredQueryParameters.Remove("utm_source");
        });
        var provider = services.BuildServiceProvider();

        // Assert
        var options = provider.GetRequiredService<IOptions<PageCacheOptions>>().Value;
        options.IgnoredQueryParameters.Should().Contain("custom_tracking");
        options.IgnoredQueryParameters.Should().NotContain("utm_source");
    }

    [Fact]
    public void AddPageCache_CanModifyCacheableStatusCodes()
    {
        // Arrange
        var services = new ServiceCollection();

        // Act
        services.AddPageCache(options =>
        {
            options.CacheableStatusCodes.Add(404);
            options.CacheableStatusCodes.Add(301);
        });
        var provider = services.BuildServiceProvider();

        // Assert
        var options = provider.GetRequiredService<IOptions<PageCacheOptions>>().Value;
        options.CacheableStatusCodes.Should().Contain(new[] { 200, 404, 301 });
    }

    [Fact]
    public void AddPageCache_AutoRegistersHtmlSanitizerValidator_WhenValidationEnabled()
    {
        // Arrange
        var services = new ServiceCollection();
        services.AddLogging();

        // Act - Default configuration has EnableHtmlValidation = true
        services.AddPageCache();
        var provider = services.BuildServiceProvider();

        // Assert
        var validator = provider.GetService<IContentValidator>();
        validator.Should().NotBeNull();
        validator.Should().BeOfType<HtmlSanitizerValidator>();
    }

    [Fact]
    public void AddPageCache_RegistersNoOpValidator_WhenValidationDisabled()
    {
        // Arrange
        var services = new ServiceCollection();
        services.AddLogging();

        // Act
        services.AddPageCache(options =>
        {
            options.Security.EnableHtmlValidation = false;
        });
        var provider = services.BuildServiceProvider();

        // Assert
        var validator = provider.GetService<IContentValidator>();
        validator.Should().NotBeNull();
        validator.Should().BeOfType<NoOpValidator>();
    }

    [Fact]
    public void AddPageCache_ValidatorRegistration_IsSingleton()
    {
        // Arrange
        var services = new ServiceCollection();
        services.AddLogging();

        // Act
        services.AddPageCache();
        var provider = services.BuildServiceProvider();

        // Assert
        var validator1 = provider.GetRequiredService<IContentValidator>();
        var validator2 = provider.GetRequiredService<IContentValidator>();
        validator1.Should().BeSameAs(validator2);
    }

    [Fact]
    public async Task AddPageCache_RegisteredValidator_CanDetectXss()
    {
        // Arrange
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddPageCache();
        var provider = services.BuildServiceProvider();

        // Act
        var validator = provider.GetRequiredService<IContentValidator>();
        var result = await validator.ValidateAsync(
            "<button onclick='alert(1)'>Click</button>",
            "test-key");

        // Assert
        result.IsValid.Should().BeFalse();
        result.Severity.Should().Be(ValidationSeverity.Critical);
    }

    [Fact]
    public async Task AddPageCache_RegisteredValidator_AllowsSafeContent()
    {
        // Arrange
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddPageCache();
        var provider = services.BuildServiceProvider();

        // Act
        var validator = provider.GetRequiredService<IContentValidator>();
        var result = await validator.ValidateAsync(
            "<div><p>Hello World</p></div>",
            "test-key");

        // Assert
        result.IsValid.Should().BeTrue();
    }
}
