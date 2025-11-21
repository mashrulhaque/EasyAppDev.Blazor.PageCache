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

/// <summary>
/// Tests for Phase 4 statistics fixes - race condition and accuracy issues.
/// </summary>
public class PageCacheServiceStatisticsTests : IDisposable
{
    private readonly IMemoryCache _memoryCache;
    private readonly ICacheStorage _storage;
    private readonly PageCacheOptions _options;
    private readonly AsyncKeyedLock _locks;
    private readonly Mock<ILogger<PageCacheService>> _loggerMock;
    private readonly IPageCacheEvents _events;
    private readonly PageCacheService _service;

    public PageCacheServiceStatisticsTests()
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
    public async Task SetCachedHtmlAsync_WithMemoryPressure_TotalBytesRemainPositive()
    {
        // Arrange
        var options = new PageCacheOptions
        {
            Enabled = true,
            EnableStatistics = true,
            DefaultDurationSeconds = 1 // Short duration to trigger evictions
        };
        using var memoryCache = new MemoryCache(new MemoryCacheOptions
        {
            SizeLimit = 50000 // Limit cache size to trigger evictions
        });
        var storage = new MemoryCacheStorage(memoryCache, Options.Create(options));
        using var locks = new AsyncKeyedLock();
        using var service = new PageCacheService(
            storage,
            Options.Create(options),
            locks,
            _loggerMock.Object,
            _events);

        // Act - Add many items to trigger evictions
        for (int i = 0; i < 100; i++)
        {
            await service.SetCachedHtmlAsync(
                $"key{i}",
                new string('x', 10000),
                1);
        }

        // Wait a bit for evictions to occur
        await Task.Delay(100);

        var stats = service.GetStatistics();

        // Assert
        stats.CacheSizeBytes.Should().BeGreaterThanOrEqualTo(0,
            "Total cached bytes should never be negative even with memory pressure and evictions");
    }

    [Fact]
    public async Task SetCachedHtmlAsync_ConcurrentOperationsWithEvictions_StatisticsAccurate()
    {
        // Arrange
        var options = new PageCacheOptions
        {
            Enabled = true,
            EnableStatistics = true,
            DefaultDurationSeconds = 1
        };
        using var memoryCache = new MemoryCache(new MemoryCacheOptions
        {
            SizeLimit = 30000
        });
        var storage = new MemoryCacheStorage(memoryCache, Options.Create(options));
        using var locks = new AsyncKeyedLock();
        using var service = new PageCacheService(
            storage,
            Options.Create(options),
            locks,
            _loggerMock.Object,
            _events);

        // Act - Concurrent writes that will trigger evictions
        var tasks = new List<Task>();
        for (int i = 0; i < 50; i++)
        {
            var index = i;
            tasks.Add(Task.Run(async () =>
            {
                await service.SetCachedHtmlAsync(
                    $"concurrent-key-{index}",
                    new string('y', 5000),
                    1);
            }));
        }

        await Task.WhenAll(tasks);

        // Wait for evictions
        await Task.Delay(200);

        var stats = service.GetStatistics();

        // Assert
        stats.CacheSizeBytes.Should().BeGreaterThanOrEqualTo(0,
            "Total bytes should never go negative under concurrent operations");
        stats.CacheSizeBytes.Should().BeLessThan(int.MaxValue,
            "Total bytes should be reasonable");
    }

    [Fact]
    public async Task SetCachedHtmlAsync_EvictionCallback_DecrementsCounterCorrectly()
    {
        // Arrange
        var options = new PageCacheOptions
        {
            Enabled = true,
            EnableStatistics = true,
            DefaultDurationSeconds = 1
        };
        using var memoryCache = new MemoryCache(new MemoryCacheOptions());
        var storage = new MemoryCacheStorage(memoryCache, Options.Create(options));
        using var locks = new AsyncKeyedLock();
        using var service = new PageCacheService(
            storage,
            Options.Create(options),
            locks,
            _loggerMock.Object,
            _events);

        // Act - Set a cache entry
        var testContent = "<html>Test Content</html>";
        await service.SetCachedHtmlAsync("test-key", testContent, 1);

        var statsAfterSet = service.GetStatistics();
        var bytesAfterSet = statsAfterSet.CacheSizeBytes;

        bytesAfterSet.Should().BeGreaterThan(0, "Bytes should be tracked after setting");

        // Wait for expiration and eviction
        await Task.Delay(1500);

        // Force eviction by triggering garbage collection
        GC.Collect();
        GC.WaitForPendingFinalizers();
        await Task.Delay(100);

        var statsAfterEviction = service.GetStatistics();

        // Assert - The counter should have been decremented
        statsAfterEviction.CacheSizeBytes.Should().BeLessThanOrEqualTo(bytesAfterSet,
            "Bytes should be decremented after eviction");
        statsAfterEviction.CacheSizeBytes.Should().BeGreaterThanOrEqualTo(0,
            "Bytes should never be negative after eviction");
    }

    [Fact]
    public async Task SetCachedHtmlAsync_MultipleEvictions_CounterStaysAccurate()
    {
        // Arrange
        var options = new PageCacheOptions
        {
            Enabled = true,
            EnableStatistics = true,
            DefaultDurationSeconds = 1
        };
        using var memoryCache = new MemoryCache(new MemoryCacheOptions
        {
            SizeLimit = 20000
        });
        var storage = new MemoryCacheStorage(memoryCache, Options.Create(options));
        using var locks = new AsyncKeyedLock();
        using var service = new PageCacheService(
            storage,
            Options.Create(options),
            locks,
            _loggerMock.Object,
            _events);

        // Act - Add entries that will cause evictions
        for (int i = 0; i < 20; i++)
        {
            await service.SetCachedHtmlAsync(
                $"eviction-test-{i}",
                new string('z', 5000),
                1);
        }

        await Task.Delay(100);

        var stats = service.GetStatistics();

        // Assert
        stats.CacheSizeBytes.Should().BeGreaterThanOrEqualTo(0,
            "Counter should remain accurate after multiple evictions");
        stats.EvictionCount.Should().BeGreaterThan(0,
            "Evictions should have occurred");
    }

    [Fact]
    public async Task GetStatistics_AfterClear_ResetsBytes()
    {
        // Arrange
        await _service.SetCachedHtmlAsync("key1", "<html>Content 1</html>", 60);
        await _service.SetCachedHtmlAsync("key2", "<html>Content 2</html>", 60);

        var statsBeforeClear = _service.GetStatistics();
        statsBeforeClear.CacheSizeBytes.Should().BeGreaterThan(0);

        // Act
        _service.Clear();

        // Assert
        var statsAfterClear = _service.GetStatistics();
        statsAfterClear.CacheSizeBytes.Should().Be(0,
            "Cache size bytes should be reset to 0 after clear");
    }

    [Fact]
    public async Task GetStatistics_ConcurrentReadsAndWrites_NoNegativeCounters()
    {
        // Arrange & Act - Concurrent reads and writes
        var tasks = new List<Task>();
        for (int i = 0; i < 100; i++)
        {
            var index = i;
            tasks.Add(Task.Run(async () =>
            {
                // Write
                await _service.SetCachedHtmlAsync(
                    $"concurrent-{index}",
                    $"<html>Content {index}</html>",
                    60);

                // Read (hit)
                _service.GetCachedHtml($"concurrent-{index}");

                // Read (miss)
                _service.GetCachedHtml($"missing-{index}");

                // Get statistics
                var stats = _service.GetStatistics();

                // Verify no negative values
                stats.HitCount.Should().BeGreaterThanOrEqualTo(0);
                stats.MissCount.Should().BeGreaterThanOrEqualTo(0);
                stats.CacheSizeBytes.Should().BeGreaterThanOrEqualTo(0);
                stats.EvictionCount.Should().BeGreaterThanOrEqualTo(0);
            }));
        }

        await Task.WhenAll(tasks);

        // Assert - Final statistics check
        var finalStats = _service.GetStatistics();
        finalStats.HitCount.Should().BeGreaterThanOrEqualTo(0);
        finalStats.MissCount.Should().BeGreaterThanOrEqualTo(0);
        finalStats.TotalRequests.Should().Be(finalStats.HitCount + finalStats.MissCount);
        finalStats.CacheSizeBytes.Should().BeGreaterThanOrEqualTo(0);
    }

    [Fact]
    public async Task GetStatistics_EvictionCount_IncrementsCorrectly()
    {
        // Arrange - Use memory pressure to force evictions (more reliable than time-based)
        var options = new PageCacheOptions
        {
            Enabled = true,
            EnableStatistics = true,
            DefaultDurationSeconds = 60
        };
        using var memoryCache = new MemoryCache(new MemoryCacheOptions
        {
            SizeLimit = 15000 // Small limit to force evictions
        });
        var storage = new MemoryCacheStorage(memoryCache, Options.Create(options));
        using var locks = new AsyncKeyedLock();
        using var service = new PageCacheService(
            storage,
            Options.Create(options),
            locks,
            _loggerMock.Object,
            _events);

        // Act - Add entries that will exceed memory limit and trigger evictions
        for (int i = 0; i < 10; i++)
        {
            await service.SetCachedHtmlAsync($"evict{i}", new string('x', 5000), 60);
        }

        // Give callbacks time to execute
        await Task.Delay(200);
        GC.Collect();
        GC.WaitForPendingFinalizers();
        await Task.Delay(100);

        // Assert
        var stats = service.GetStatistics();
        stats.EvictionCount.Should().BeGreaterThan(0,
            "Eviction count should increment when memory pressure causes evictions");
    }

    [Fact]
    public async Task GetStatistics_HitRateCalculation_IsAccurate()
    {
        // Arrange
        await _service.SetCachedHtmlAsync("hit-test", "<html>Test</html>", 60);

        // Act
        _service.GetCachedHtml("hit-test"); // Hit
        _service.GetCachedHtml("hit-test"); // Hit
        _service.GetCachedHtml("miss-test"); // Miss

        var stats = _service.GetStatistics();

        // Assert
        stats.HitCount.Should().Be(2);
        stats.MissCount.Should().Be(1);
        stats.TotalRequests.Should().Be(3);
        stats.HitRate.Should().BeApproximately(2.0 / 3.0, 0.01,
            "Hit rate should be calculated correctly as hits / total requests");
    }

    [Fact]
    public void GetStatistics_NoRequests_ReturnsZeroHitRate()
    {
        // Act
        var stats = _service.GetStatistics();

        // Assert
        stats.HitCount.Should().Be(0);
        stats.MissCount.Should().Be(0);
        stats.TotalRequests.Should().Be(0);
        stats.HitRate.Should().Be(0, "Hit rate should be 0 when there are no requests");
    }

    [Fact]
    public void ResetStatistics_ResetsAllCounters()
    {
        // Arrange
        _service.GetCachedHtml("key1"); // Miss
        _service.GetCachedHtml("key2"); // Miss

        var statsBeforeReset = _service.GetStatistics();
        statsBeforeReset.MissCount.Should().Be(2);

        // Act
        _service.ResetStatistics();

        // Assert
        var statsAfterReset = _service.GetStatistics();
        statsAfterReset.HitCount.Should().Be(0);
        statsAfterReset.MissCount.Should().Be(0);
        statsAfterReset.EvictionCount.Should().Be(0);
        statsAfterReset.CacheSizeBytes.Should().Be(0);
    }

    [Fact]
    public async Task GetStatistics_WithCompression_TracksBytesCorrectly()
    {
        // Arrange
        var compressionMock = new Mock<ICompressionStrategy>();
        var testHtml = "<html>Test Content</html>";
        var compressedData = new byte[] { 1, 2, 3, 4, 5 };

        compressionMock.Setup(x => x.Compress(testHtml)).Returns(compressedData);
        compressionMock.Setup(x => x.Decompress(compressedData)).Returns(testHtml);

        var options = new PageCacheOptions
        {
            Enabled = true,
            EnableStatistics = true
        };
        using var memoryCache = new MemoryCache(new MemoryCacheOptions());
        var storage = new MemoryCacheStorage(memoryCache, Options.Create(options));
        using var locks = new AsyncKeyedLock();
        using var service = new PageCacheService(
            storage,
            Options.Create(options),
            locks,
            _loggerMock.Object,
            _events,
            compressionMock.Object);

        // Act
        await service.SetCachedHtmlAsync("compressed-key", testHtml, 60);

        var stats = service.GetStatistics();

        // Assert
        stats.CacheSizeBytes.Should().Be(compressedData.Length,
            "Should track compressed byte size when compression is enabled");
    }

    [Fact]
    public void GetStatistics_WithStatisticsDisabled_ReturnsDefaultValues()
    {
        // Arrange
        var options = new PageCacheOptions
        {
            Enabled = true,
            EnableStatistics = false
        };
        using var memoryCache = new MemoryCache(new MemoryCacheOptions());
        var storage = new MemoryCacheStorage(memoryCache, Options.Create(options));
        using var locks = new AsyncKeyedLock();
        using var service = new PageCacheService(
            storage,
            Options.Create(options),
            locks,
            _loggerMock.Object,
            _events);

        // Act
        service.GetCachedHtml("test"); // This would normally increment miss count

        var stats = service.GetStatistics();

        // Assert
        stats.HitCount.Should().Be(0);
        stats.MissCount.Should().Be(0);
        stats.CacheSizeBytes.Should().Be(0);
        stats.EvictionCount.Should().Be(0);
    }

    [Fact]
    public async Task GetStatistics_CachedEntries_ReflectsCurrentCount()
    {
        // Arrange & Act
        await _service.SetCachedHtmlAsync("entry1", "<html>1</html>", 60);
        await _service.SetCachedHtmlAsync("entry2", "<html>2</html>", 60);
        await _service.SetCachedHtmlAsync("entry3", "<html>3</html>", 60);

        var stats = _service.GetStatistics();

        // Assert
        stats.CachedEntries.Should().Be(3, "Should reflect the current number of cached entries");

        // Remove one
        _service.Remove("entry2");

        var statsAfterRemove = _service.GetStatistics();
        statsAfterRemove.CachedEntries.Should().Be(2, "Should reflect updated count after removal");
    }
}
