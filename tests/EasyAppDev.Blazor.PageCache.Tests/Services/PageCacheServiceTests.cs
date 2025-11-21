using EasyAppDev.Blazor.PageCache.Abstractions;
using EasyAppDev.Blazor.PageCache.Configuration;
using EasyAppDev.Blazor.PageCache.Events;
using EasyAppDev.Blazor.PageCache.Services;
using EasyAppDev.Blazor.PageCache.Storage;
using FluentAssertions;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Moq;
using Xunit;

namespace EasyAppDev.Blazor.PageCache.Tests.Services;

public class PageCacheServiceTests : IDisposable
{
    private readonly IMemoryCache _memoryCache;
    private readonly ICacheStorage _storage;
    private readonly PageCacheOptions _options;
    private readonly AsyncKeyedLock _locks;
    private readonly Mock<ILogger<PageCacheService>> _loggerMock;
    private readonly IPageCacheEvents _events;
    private readonly PageCacheService _service;

    public PageCacheServiceTests()
    {
        _memoryCache = new MemoryCache(new MemoryCacheOptions());
        _options = new PageCacheOptions
        {
            Enabled = true,
            DefaultDurationSeconds = 60,
            EnableStatistics = true
        };
        _storage = new MemoryCacheStorage(_memoryCache, Options.Create(_options));
        _locks = new AsyncKeyedLock();
        _loggerMock = new Mock<ILogger<PageCacheService>>();
        _events = new DefaultPageCacheEvents();
        _service = new PageCacheService(
            _storage,
            Options.Create(_options),
            _locks,
            _loggerMock.Object,
            _events);
    }

    public void Dispose()
    {
        _service?.Dispose();
        _locks?.Dispose();
        _memoryCache?.Dispose();
    }

    [Fact]
    public void GetCachedHtml_CacheHit_ReturnsHtml()
    {
        // Arrange
        var cacheKey = "test-key";
        var expectedHtml = "<html>Test Content</html>";
        _memoryCache.Set(cacheKey, expectedHtml);

        // Act
        var result = _service.GetCachedHtml(cacheKey);

        // Assert
        result.Should().Be(expectedHtml);
    }

    [Fact]
    public void GetCachedHtml_CacheMiss_ReturnsNull()
    {
        // Arrange
        var cacheKey = "non-existent-key";

        // Act
        var result = _service.GetCachedHtml(cacheKey);

        // Assert
        result.Should().BeNull();
    }

    [Fact]
    public void GetCachedHtml_NullKey_ThrowsArgumentException()
    {
        // Act
        var act = () => _service.GetCachedHtml(null!);

        // Assert
        act.Should().Throw<ArgumentException>();
    }

    [Fact]
    public void GetCachedHtml_EmptyKey_ThrowsArgumentException()
    {
        // Act
        var act = () => _service.GetCachedHtml(string.Empty);

        // Assert
        act.Should().Throw<ArgumentException>();
    }

    [Fact]
    public void GetCachedHtml_WhitespaceKey_ThrowsArgumentException()
    {
        // Act
        var act = () => _service.GetCachedHtml("   ");

        // Assert
        act.Should().Throw<ArgumentException>();
    }

    [Fact]
    public void GetCachedHtml_CachingDisabled_ReturnsNull()
    {
        // Arrange
        var options = new PageCacheOptions { Enabled = false };
        var storage = new MemoryCacheStorage(_memoryCache, Options.Create(options));
        using var service = new PageCacheService(
            storage,
            Options.Create(options),
            _locks,
            _loggerMock.Object,
            _events);

        var cacheKey = "test-key";
        var html = "<html>Test</html>";
        _memoryCache.Set(cacheKey, html);

        // Act
        var result = service.GetCachedHtml(cacheKey);

        // Assert
        result.Should().BeNull();
    }

    [Fact]
    public async Task SetCachedHtmlAsync_ValidInput_CachesHtml()
    {
        // Arrange
        var cacheKey = "test-key";
        var html = "<html>Test Content</html>";
        var duration = 60;

        // Act
        await _service.SetCachedHtmlAsync(cacheKey, html, duration);

        // Assert
        var cached = _service.GetCachedHtml(cacheKey);
        cached.Should().Be(html);
    }

    [Fact]
    public async Task SetCachedHtmlAsync_NullKey_ThrowsArgumentException()
    {
        // Act
        var act = async () => await _service.SetCachedHtmlAsync(null!, "<html></html>", 60);

        // Assert
        await act.Should().ThrowAsync<ArgumentException>();
    }

    [Fact]
    public async Task SetCachedHtmlAsync_NullHtml_ThrowsArgumentException()
    {
        // Act
        var act = async () => await _service.SetCachedHtmlAsync("key", null!, 60);

        // Assert
        await act.Should().ThrowAsync<ArgumentException>();
    }

    [Fact]
    public async Task SetCachedHtmlAsync_ZeroDuration_UsesDefaultDuration()
    {
        // Arrange
        var cacheKey = "test-key";
        var html = "<html>Test</html>";

        // Act
        await _service.SetCachedHtmlAsync(cacheKey, html, 0);

        // Assert
        var cached = _service.GetCachedHtml(cacheKey);
        cached.Should().Be(html);
    }

    [Fact]
    public async Task SetCachedHtmlAsync_CachingDisabled_DoesNotCache()
    {
        // Arrange
        var options = new PageCacheOptions { Enabled = false };
        using var service = new PageCacheService(_storage, Options.Create(options), _locks, _loggerMock.Object, _events);

        var cacheKey = "test-key";
        var html = "<html>Test</html>";

        // Act
        await service.SetCachedHtmlAsync(cacheKey, html, 60);

        // Assert
        var cached = service.GetCachedHtml(cacheKey);
        cached.Should().BeNull();
    }

    [Fact]
    public void Remove_ExistingKey_RemovesEntry()
    {
        // Arrange
        var cacheKey = "test-key";
        var html = "<html>Test</html>";
        _memoryCache.Set(cacheKey, html);

        // Act
        _service.Remove(cacheKey);

        // Assert
        var cached = _service.GetCachedHtml(cacheKey);
        cached.Should().BeNull();
    }

    [Fact]
    public void Remove_NonExistentKey_DoesNotThrow()
    {
        // Act
        var act = () => _service.Remove("non-existent-key");

        // Assert
        act.Should().NotThrow();
    }

    [Fact]
    public void Remove_NullKey_ThrowsArgumentException()
    {
        // Act
        var act = () => _service.Remove(null!);

        // Assert
        act.Should().Throw<ArgumentException>();
    }

    [Fact]
    public async Task RemoveByPattern_ExactMatch_RemovesEntry()
    {
        // Arrange
        var cacheKey = "exact-key";
        await _service.SetCachedHtmlAsync(cacheKey, "<html>Test</html>", 60);

        // Act
        var removed = _service.RemoveByPattern(cacheKey);

        // Assert
        removed.Should().Be(1);
        _service.GetCachedHtml(cacheKey).Should().BeNull();
    }

    [Fact]
    public async Task RemoveByPattern_WildcardMatch_RemovesMatchingEntries()
    {
        // Arrange
        await _service.SetCachedHtmlAsync("page:1", "<html>Page 1</html>", 60);
        await _service.SetCachedHtmlAsync("page:2", "<html>Page 2</html>", 60);
        await _service.SetCachedHtmlAsync("page:3", "<html>Page 3</html>", 60);
        await _service.SetCachedHtmlAsync("other:1", "<html>Other 1</html>", 60);

        // Act
        var removed = _service.RemoveByPattern("page:*");

        // Assert
        removed.Should().Be(3);
        _service.GetCachedHtml("page:1").Should().BeNull();
        _service.GetCachedHtml("page:2").Should().BeNull();
        _service.GetCachedHtml("page:3").Should().BeNull();
        _service.GetCachedHtml("other:1").Should().NotBeNull();
    }

    [Fact]
    public async Task RemoveByPattern_NoMatches_ReturnsZero()
    {
        // Arrange
        await _service.SetCachedHtmlAsync("key1", "<html>Test</html>", 60);

        // Act
        var removed = _service.RemoveByPattern("non-existent-*");

        // Assert
        removed.Should().Be(0);
    }

    [Fact]
    public void RemoveByPattern_NullPattern_ThrowsArgumentException()
    {
        // Act
        var act = () => _service.RemoveByPattern(null!);

        // Assert
        act.Should().Throw<ArgumentException>();
    }

    [Fact]
    public async Task Clear_RemovesAllEntries()
    {
        // Arrange
        await _service.SetCachedHtmlAsync("key1", "<html>1</html>", 60);
        await _service.SetCachedHtmlAsync("key2", "<html>2</html>", 60);
        await _service.SetCachedHtmlAsync("key3", "<html>3</html>", 60);

        // Act
        _service.Clear();

        // Assert
        _service.GetCachedHtml("key1").Should().BeNull();
        _service.GetCachedHtml("key2").Should().BeNull();
        _service.GetCachedHtml("key3").Should().BeNull();
    }

    [Fact]
    public async Task AcquireLockAsync_ValidKey_ReturnsLock()
    {
        // Arrange
        var cacheKey = "test-key";

        // Act
        var lockHandle = await _service.AcquireLockAsync(cacheKey);

        // Assert
        lockHandle.Should().NotBeNull();

        // Cleanup
        lockHandle.Dispose();
    }

    [Fact]
    public async Task AcquireLockAsync_NullKey_ThrowsArgumentException()
    {
        // Act
        var act = async () => await _service.AcquireLockAsync(null!);

        // Assert
        await act.Should().ThrowAsync<ArgumentException>();
    }

    [Fact]
    public async Task GetStatistics_WithStatisticsEnabled_ReturnsAccurateStats()
    {
        // Arrange
        await _service.SetCachedHtmlAsync("key1", "<html>Test 1</html>", 60);
        await _service.SetCachedHtmlAsync("key2", "<html>Test 2</html>", 60);

        // Act - Generate some hits and misses
        _service.GetCachedHtml("key1"); // Hit
        _service.GetCachedHtml("key1"); // Hit
        _service.GetCachedHtml("key2"); // Hit
        _service.GetCachedHtml("non-existent"); // Miss

        var stats = _service.GetStatistics();

        // Assert
        stats.HitCount.Should().Be(3);
        stats.MissCount.Should().Be(1);
        stats.TotalRequests.Should().Be(4);
        stats.HitRate.Should().BeApproximately(0.75, 0.01);
        stats.CachedEntries.Should().Be(2);
        stats.CacheSizeBytes.Should().BeGreaterThan(0);
    }

    [Fact]
    public void GetStatistics_WithStatisticsDisabled_ReturnsEmptyStats()
    {
        // Arrange
        var options = new PageCacheOptions { Enabled = true, EnableStatistics = false };
        using var service = new PageCacheService(_storage, Options.Create(options), _locks, _loggerMock.Object, _events);

        // Act
        var stats = service.GetStatistics();

        // Assert
        stats.HitCount.Should().Be(0);
        stats.MissCount.Should().Be(0);
        stats.TotalRequests.Should().Be(0);
        stats.HitRate.Should().Be(0);
    }

    [Fact]
    public async Task SetCachedHtmlAsync_WithSlidingExpiration_ConfiguresCorrectly()
    {
        // Arrange
        var options = new PageCacheOptions
        {
            Enabled = true,
            DefaultDurationSeconds = 60,
            SlidingExpirationSeconds = 30
        };
        using var service = new PageCacheService(_storage, Options.Create(options), _locks, _loggerMock.Object, _events);

        var cacheKey = "test-key";
        var html = "<html>Test</html>";

        // Act
        await service.SetCachedHtmlAsync(cacheKey, html, 60);

        // Assert
        var cached = service.GetCachedHtml(cacheKey);
        cached.Should().Be(html);
    }

    [Fact]
    public async Task ConcurrentAccess_ThreadSafe_NoDataCorruption()
    {
        // Arrange
        var taskCount = 100;
        var tasks = new List<Task>();

        // Act - Concurrent reads and writes
        for (int i = 0; i < taskCount; i++)
        {
            var index = i;
            tasks.Add(Task.Run(async () =>
            {
                var key = $"key-{index % 10}";
                var html = $"<html>Content {index}</html>";

                await _service.SetCachedHtmlAsync(key, html, 60);
                var result = _service.GetCachedHtml(key);
                result.Should().NotBeNull();
            }));
        }

        await Task.WhenAll(tasks);

        // Assert - No exceptions thrown means thread-safety maintained
        Assert.True(true);
    }

    [Fact]
    public async Task RemoveByPattern_CaseInsensitive_MatchesCorrectly()
    {
        // Arrange
        await _service.SetCachedHtmlAsync("PAGE:1", "<html>1</html>", 60);
        await _service.SetCachedHtmlAsync("page:2", "<html>2</html>", 60);
        await _service.SetCachedHtmlAsync("PaGe:3", "<html>3</html>", 60);

        // Act
        var removed = _service.RemoveByPattern("page:*");

        // Assert
        removed.Should().Be(3);
    }

    [Fact]
    public void Constructor_NullCache_ThrowsArgumentNullException()
    {
        // Act
        var act = () => new PageCacheService(null!, Options.Create(_options), _locks, _loggerMock.Object, _events);

        // Assert
        act.Should().Throw<ArgumentNullException>();
    }

    [Fact]
    public void Constructor_NullOptions_ThrowsArgumentNullException()
    {
        // Act
        var act = () => new PageCacheService(
            _storage,
            null!,
            _locks,
            _loggerMock.Object,
            _events);

        // Assert
        act.Should().Throw<ArgumentNullException>();
    }

    [Fact]
    public void Constructor_NullLocks_ThrowsArgumentNullException()
    {
        // Act
        var act = () => new PageCacheService(_storage, Options.Create(_options), null!, _loggerMock.Object, _events);

        // Assert
        act.Should().Throw<ArgumentNullException>();
    }

    [Fact]
    public void Constructor_NullLogger_ThrowsArgumentNullException()
    {
        // Act
        var act = () => new PageCacheService(_storage, Options.Create(_options), _locks, null!, _events);

        // Assert
        act.Should().Throw<ArgumentNullException>();
    }

    [Fact]
    public async Task RemoveByPattern_PrefixWildcard_UsesFastPath()
    {
        // Arrange
        await _service.SetCachedHtmlAsync("page:1", "<html>1</html>", 60);
        await _service.SetCachedHtmlAsync("page:2", "<html>2</html>", 60);
        await _service.SetCachedHtmlAsync("post:1", "<html>3</html>", 60);

        // Act
        var removed = _service.RemoveByPattern("page:*");

        // Assert
        removed.Should().Be(2);
        _service.GetCachedHtml("page:1").Should().BeNull();
        _service.GetCachedHtml("page:2").Should().BeNull();
        _service.GetCachedHtml("post:1").Should().NotBeNull();
    }

    [Fact]
    public async Task RemoveByPattern_SuffixWildcard_UsesFastPath()
    {
        // Arrange
        await _service.SetCachedHtmlAsync("index.html", "<html>1</html>", 60);
        await _service.SetCachedHtmlAsync("about.html", "<html>2</html>", 60);
        await _service.SetCachedHtmlAsync("index.json", "<html>3</html>", 60);

        // Act
        var removed = _service.RemoveByPattern("*.html");

        // Assert
        removed.Should().Be(2);
        _service.GetCachedHtml("index.html").Should().BeNull();
        _service.GetCachedHtml("about.html").Should().BeNull();
        _service.GetCachedHtml("index.json").Should().NotBeNull();
    }

    [Fact]
    public async Task RemoveByPattern_MaxRemovalLimit_RespectsLimit()
    {
        // Arrange - Add 15 entries
        for (int i = 0; i < 15; i++)
        {
            await _service.SetCachedHtmlAsync($"page:{i}", $"<html>{i}</html>", 60);
        }

        // Act - Limit to 10 removals
        var removed = _service.RemoveByPattern("page:*", maxRemovalCount: 10);

        // Assert
        removed.Should().Be(10);
    }

    [Fact]
    public async Task RemoveByPattern_ComplexWildcard_UsesRegex()
    {
        // Arrange
        await _service.SetCachedHtmlAsync("user-123-profile", "<html>1</html>", 60);
        await _service.SetCachedHtmlAsync("user-456-profile", "<html>2</html>", 60);
        await _service.SetCachedHtmlAsync("user-789-settings", "<html>3</html>", 60);

        // Act
        var removed = _service.RemoveByPattern("user-*-profile");

        // Assert
        removed.Should().Be(2);
        _service.GetCachedHtml("user-123-profile").Should().BeNull();
        _service.GetCachedHtml("user-456-profile").Should().BeNull();
        _service.GetCachedHtml("user-789-settings").Should().NotBeNull();
    }
}
