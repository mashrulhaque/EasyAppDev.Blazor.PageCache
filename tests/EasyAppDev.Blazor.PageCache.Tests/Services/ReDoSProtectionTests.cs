using EasyAppDev.Blazor.PageCache.Abstractions;
using EasyAppDev.Blazor.PageCache.Configuration;
using EasyAppDev.Blazor.PageCache.Storage;
using FluentAssertions;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Options;
using Xunit;

namespace EasyAppDev.Blazor.PageCache.Tests.Services;

/// <summary>
/// Security tests to verify ReDoS (Regular Expression Denial of Service) protection
/// in pattern-based cache invalidation.
/// </summary>
[Trait("Category", TestCategories.Security)]
[Trait("Category", TestCategories.Unit)]
public class ReDoSProtectionTests
{
    private readonly MemoryCache _memoryCache;
    private readonly PageCacheOptions _options;

    public ReDoSProtectionTests()
    {
        _memoryCache = new MemoryCache(new MemoryCacheOptions());
        _options = new PageCacheOptions
        {
            MaxWildcardsInPattern = 3,
            MaxPatternLength = 256
        };
    }

    #region Pattern Length Validation Tests

    [Fact]
    public async Task RemoveByPatternAsync_PatternExceedsMaxLength_ThrowsArgumentException()
    {
        // Arrange
        var storage = CreateStorage();
        var longPattern = new string('a', 257) + "*"; // Exceeds default 256 limit

        // Act
        Func<Task> act = async () => await storage.RemoveByPatternAsync(longPattern, 100);

        // Assert
        await act.Should().ThrowAsync<ArgumentException>()
            .WithMessage("*exceeds maximum allowed length*")
            .WithMessage("*ReDoS*");
    }

    [Fact]
    public async Task RemoveByPatternAsync_PatternAtMaxLength_Succeeds()
    {
        // Arrange
        var storage = CreateStorage();
        var maxLengthPattern = new string('a', 255) + "*"; // Exactly at limit

        // Act
        Func<Task> act = async () => await storage.RemoveByPatternAsync(maxLengthPattern, 100);

        // Assert
        await act.Should().NotThrowAsync();
    }

    [Fact]
    public async Task RemoveByPatternAsync_CustomMaxLength_RespectsConfiguration()
    {
        // Arrange
        _options.MaxPatternLength = 50;
        var storage = CreateStorage();
        var pattern = new string('a', 51); // Just over custom limit

        // Act
        Func<Task> act = async () => await storage.RemoveByPatternAsync(pattern, 100);

        // Assert
        await act.Should().ThrowAsync<ArgumentException>()
            .WithMessage($"*exceeds maximum allowed length (50)*");
    }

    #endregion

    #region Wildcard Count Validation Tests

    [Fact]
    public async Task RemoveByPatternAsync_ExcessiveWildcards_ThrowsArgumentException()
    {
        // Arrange
        var storage = CreateStorage();
        var maliciousPattern = "*a*b*c*d*"; // 5 wildcards, exceeds default limit of 3

        // Act
        Func<Task> act = async () => await storage.RemoveByPatternAsync(maliciousPattern, 100);

        // Assert
        await act.Should().ThrowAsync<ArgumentException>()
            .WithMessage("*exceeds the maximum allowed (3)*")
            .WithMessage("*ReDoS*");
    }

    [Fact]
    public async Task RemoveByPatternAsync_AtWildcardLimit_Succeeds()
    {
        // Arrange
        var storage = CreateStorage();
        await AddTestKeys(storage, "page:user:123", "page:admin:456", "cache:data:789");
        var pattern = "*user*123*"; // Exactly 3 wildcards

        // Act
        Func<Task> act = async () => await storage.RemoveByPatternAsync(pattern, 100);

        // Assert
        await act.Should().NotThrowAsync();
    }

    [Fact]
    public async Task RemoveByPatternAsync_ComplexMaliciousPattern_RejectedBeforeRegex()
    {
        // Arrange
        var storage = CreateStorage();
        // Potentially catastrophic backtracking pattern
        var maliciousPattern = "*a*b*c*d*e*f*g*h*i*j*k*";

        // Act
        Func<Task> act = async () => await storage.RemoveByPatternAsync(maliciousPattern, 100);

        // Assert
        await act.Should().ThrowAsync<ArgumentException>()
            .WithMessage("*wildcards*")
            .WithMessage("*ReDoS*");
    }

    [Fact]
    public async Task RemoveByPatternAsync_CustomWildcardLimit_RespectsConfiguration()
    {
        // Arrange
        _options.MaxWildcardsInPattern = 5;
        var storage = CreateStorage();
        var pattern = "*a*b*c*d*e*"; // 6 wildcards, exceeds custom limit of 5

        // Act
        Func<Task> act = async () => await storage.RemoveByPatternAsync(pattern, 100);

        // Assert
        await act.Should().ThrowAsync<ArgumentException>()
            .WithMessage("*exceeds the maximum allowed (5)*");
    }

    #endregion

    #region Valid Pattern Tests

    [Fact]
    public async Task RemoveByPatternAsync_SimplePrefix_WorksWithoutValidationError()
    {
        // Arrange
        var storage = CreateStorage();
        await AddTestKeys(storage, "page:home", "page:about", "cache:data");

        // Act
        var removed = await storage.RemoveByPatternAsync("page:*", 100);

        // Assert
        removed.Should().Be(2);
    }

    [Fact]
    public async Task RemoveByPatternAsync_SimpleSuffix_WorksWithoutValidationError()
    {
        // Arrange
        var storage = CreateStorage();
        await AddTestKeys(storage, "home:cache", "about:cache", "data:store");

        // Act
        var removed = await storage.RemoveByPatternAsync("*:cache", 100);

        // Assert
        removed.Should().Be(2);
    }

    [Fact]
    public async Task RemoveByPatternAsync_SimpleContains_WorksWithoutValidationError()
    {
        // Arrange
        var storage = CreateStorage();
        await AddTestKeys(storage, "page:user:123", "cache:user:456", "data:admin:789");

        // Act
        var removed = await storage.RemoveByPatternAsync("*user*", 100);

        // Assert
        removed.Should().Be(2);
    }

    [Fact]
    public async Task RemoveByPatternAsync_ModerateComplexPattern_WorksWithinLimits()
    {
        // Arrange
        var storage = CreateStorage();
        await AddTestKeys(storage, "page:en:home", "page:fr:home", "cache:en:data");
        var pattern = "page:*:*"; // 2 wildcards, within limit

        // Act
        var removed = await storage.RemoveByPatternAsync(pattern, 100);

        // Assert
        removed.Should().Be(2);
    }

    #endregion

    #region Pattern Optimization Tests

    [Fact]
    public async Task RemoveByPatternAsync_PrefixPattern_UsesOptimizedPath()
    {
        // Arrange
        var storage = CreateStorage();
        var keys = Enumerable.Range(0, 1000)
            .Select(i => $"page:{i}")
            .ToArray();
        await AddTestKeys(storage, keys);

        // Act - Should complete quickly using optimized prefix match
        var stopwatch = System.Diagnostics.Stopwatch.StartNew();
        var removed = await storage.RemoveByPatternAsync("page:*", 1000);
        stopwatch.Stop();

        // Assert
        removed.Should().Be(1000);
        stopwatch.ElapsedMilliseconds.Should().BeLessThan(500,
            "prefix optimization should be fast even with 1000 keys");
    }

    [Fact]
    public async Task RemoveByPatternAsync_SuffixPattern_UsesOptimizedPath()
    {
        // Arrange
        var storage = CreateStorage();
        var keys = Enumerable.Range(0, 1000)
            .Select(i => $"{i}:cache")
            .ToArray();
        await AddTestKeys(storage, keys);

        // Act - Should complete quickly using optimized suffix match
        var stopwatch = System.Diagnostics.Stopwatch.StartNew();
        var removed = await storage.RemoveByPatternAsync("*:cache", 1000);
        stopwatch.Stop();

        // Assert
        removed.Should().Be(1000);
        stopwatch.ElapsedMilliseconds.Should().BeLessThan(500,
            "suffix optimization should be fast even with 1000 keys");
    }

    [Fact]
    public async Task RemoveByPatternAsync_ContainsPattern_UsesOptimizedPath()
    {
        // Arrange
        var storage = CreateStorage();
        var keys = new[] { "page:user:123", "cache:user:456", "data:admin:789", "user:profile" };
        await AddTestKeys(storage, keys);

        // Act - Should use optimized contains path for *value* pattern
        var removed = await storage.RemoveByPatternAsync("*user*", 100);

        // Assert
        removed.Should().Be(3);
    }

    #endregion

    #region Timeout Protection Tests

    [Fact]
    public async Task RemoveByPatternAsync_ComplexValidPattern_CompletesWithinTimeout()
    {
        // Arrange
        var storage = CreateStorage();
        var keys = Enumerable.Range(0, 100)
            .Select(i => $"page:{i}:user:{i}")
            .ToArray();
        await AddTestKeys(storage, keys);

        // Pattern with 2 wildcards (within limit) but still requires regex
        var pattern = "page:*:user:5*";

        // Act
        var stopwatch = System.Diagnostics.Stopwatch.StartNew();
        var removed = await storage.RemoveByPatternAsync(pattern, 100);
        stopwatch.Stop();

        // Assert
        removed.Should().BeGreaterThan(0);
        stopwatch.ElapsedMilliseconds.Should().BeLessThan(2000,
            "regex timeout protection should prevent excessive processing");
    }

    [Fact]
    public async Task RemoveByPatternAsync_RegexTimeout_DoesNotCrash()
    {
        // Arrange
        var storage = CreateStorage();
        // Create keys that might cause regex backtracking
        var keys = Enumerable.Range(0, 50)
            .Select(i => new string('a', 20) + i.ToString())
            .ToArray();
        await AddTestKeys(storage, keys);

        var pattern = "a*a*a*"; // 3 wildcards, valid but potentially slow

        // Act
        Func<Task> act = async () => await storage.RemoveByPatternAsync(pattern, 100);

        // Assert
        await act.Should().NotThrowAsync("timeout should be handled gracefully");
    }

    #endregion

    #region Edge Cases

    [Fact]
    public async Task RemoveByPatternAsync_EmptyPattern_ThrowsArgumentException()
    {
        // Arrange
        var storage = CreateStorage();

        // Act
        Func<Task> act = async () => await storage.RemoveByPatternAsync("", 100);

        // Assert
        await act.Should().ThrowAsync<ArgumentException>();
    }

    [Fact]
    public async Task RemoveByPatternAsync_WhitespacePattern_ThrowsArgumentException()
    {
        // Arrange
        var storage = CreateStorage();

        // Act
        Func<Task> act = async () => await storage.RemoveByPatternAsync("   ", 100);

        // Assert
        await act.Should().ThrowAsync<ArgumentException>();
    }

    [Fact]
    public async Task RemoveByPatternAsync_SingleWildcard_WorksCorrectly()
    {
        // Arrange
        var storage = CreateStorage();
        await AddTestKeys(storage, "a", "b", "c");

        // Act
        var removed = await storage.RemoveByPatternAsync("*", 100);

        // Assert
        removed.Should().Be(3, "single wildcard should match all keys");
    }

    [Fact]
    public async Task RemoveByPatternAsync_NoWildcard_ExactMatch()
    {
        // Arrange
        var storage = CreateStorage();
        await AddTestKeys(storage, "exact:key", "other:key");

        // Act
        var removed = await storage.RemoveByPatternAsync("exact:key", 100);

        // Assert
        removed.Should().Be(1, "no wildcard should perform exact match");
    }

    #endregion

    #region Security Attack Simulation Tests

    [Theory]
    [InlineData("*a*b*c*d*e*")]
    [InlineData("*1*2*3*4*5*6*")]
    [InlineData("****")]
    [InlineData("*x*y*z*w*")]
    public async Task RemoveByPatternAsync_VariousMaliciousPatterns_AllRejected(string maliciousPattern)
    {
        // Arrange
        var storage = CreateStorage();

        // Act
        Func<Task> act = async () => await storage.RemoveByPatternAsync(maliciousPattern, 100);

        // Assert
        await act.Should().ThrowAsync<ArgumentException>()
            .WithMessage("*ReDoS*");
    }

    [Fact]
    public async Task RemoveByPatternAsync_ExtremelyLongPattern_RejectedImmediately()
    {
        // Arrange
        var storage = CreateStorage();
        var extremePattern = new string('a', 10000) + "*"; // Way over limit

        // Act
        var stopwatch = System.Diagnostics.Stopwatch.StartNew();
        Func<Task> act = async () => await storage.RemoveByPatternAsync(extremePattern, 100);
        await act.Should().ThrowAsync<ArgumentException>();
        stopwatch.Stop();

        // Assert
        stopwatch.ElapsedMilliseconds.Should().BeLessThan(100,
            "validation should reject immediately without regex processing");
    }

    [Fact]
    public async Task RemoveByPatternAsync_CombinedAttack_LongAndManyWildcards_Rejected()
    {
        // Arrange
        var storage = CreateStorage();
        var attackPattern = string.Join("*", Enumerable.Repeat("abc", 100)); // Long + many wildcards

        // Act
        Func<Task> act = async () => await storage.RemoveByPatternAsync(attackPattern, 100);

        // Assert
        await act.Should().ThrowAsync<ArgumentException>()
            .WithMessage("*ReDoS*");
    }

    #endregion

    #region Configuration Validation Tests

    [Fact]
    public void Constructor_ValidOptions_CreatesInstance()
    {
        // Act
        Action act = () => CreateStorage();

        // Assert
        act.Should().NotThrow();
    }

    [Fact]
    public void Constructor_NullCache_ThrowsArgumentNullException()
    {
        // Arrange
        var options = Options.Create(_options);

        // Act
        Action act = () => new MemoryCacheStorage(null!, options);

        // Assert
        act.Should().Throw<ArgumentNullException>()
            .WithParameterName("cache");
    }

    [Fact]
    public void Constructor_NullOptions_ThrowsArgumentNullException()
    {
        // Act
        Action act = () => new MemoryCacheStorage(_memoryCache, null!);

        // Assert
        act.Should().Throw<ArgumentNullException>()
            .WithParameterName("options");
    }

    #endregion

    #region Helper Methods

    private MemoryCacheStorage CreateStorage()
    {
        var options = Options.Create(_options);
        return new MemoryCacheStorage(_memoryCache, options);
    }

    private async Task AddTestKeys(MemoryCacheStorage storage, params string[] keys)
    {
        var cacheOptions = new CacheEntryOptions
        {
            AbsoluteExpirationRelativeToNow = TimeSpan.FromMinutes(10)
        };

        foreach (var key in keys)
        {
            await storage.SetAsync(key, "test-value", cacheOptions);
        }
    }

    #endregion
}
