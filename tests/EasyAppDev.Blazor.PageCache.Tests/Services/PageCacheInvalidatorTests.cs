using FluentAssertions;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Moq;
using EasyAppDev.Blazor.PageCache.Configuration;
using EasyAppDev.Blazor.PageCache.Services;

namespace EasyAppDev.Blazor.PageCache.Tests.Services;

public class PageCacheInvalidatorTests
{
    private readonly Mock<IPageCacheService> _mockCacheService;
    private readonly PageCacheOptions _options;
    private readonly PageCacheInvalidator _invalidator;

    public PageCacheInvalidatorTests()
    {
        _mockCacheService = new Mock<IPageCacheService>();
        _options = new PageCacheOptions
        {
            CacheKeyPrefix = "page:"
        };

        _invalidator = new PageCacheInvalidator(
            _mockCacheService.Object,
            Options.Create(_options),
            NullLogger<PageCacheInvalidator>.Instance);
    }

    [Fact]
    public void InvalidateRoute_ExactMatch_RemovesEntry()
    {
        // Arrange
        const string route = "/about";
        _mockCacheService
            .Setup(x => x.RemoveByPattern("page:/about*", It.IsAny<int>()))
            .Returns(1);

        // Act
        var result = _invalidator.InvalidateRoute(route);

        // Assert
        result.Should().BeTrue();
        _mockCacheService.Verify(x => x.RemoveByPattern("page:/about*", It.IsAny<int>()), Times.Once);
    }

    [Fact]
    public void InvalidateRoute_NotFound_ReturnsFalse()
    {
        // Arrange
        const string route = "/nonexistent";
        _mockCacheService
            .Setup(x => x.RemoveByPattern("page:/nonexistent*", It.IsAny<int>()))
            .Returns(0);

        // Act
        var result = _invalidator.InvalidateRoute(route);

        // Assert
        result.Should().BeFalse();
    }

    [Fact]
    public void InvalidateRoute_NormalizesRoute_RemovesTrailingSlash()
    {
        // Arrange
        const string route = "/about/";
        _mockCacheService
            .Setup(x => x.RemoveByPattern("page:/about*", It.IsAny<int>()))
            .Returns(1);

        // Act
        var result = _invalidator.InvalidateRoute(route);

        // Assert
        result.Should().BeTrue();
        _mockCacheService.Verify(x => x.RemoveByPattern("page:/about*", It.IsAny<int>()), Times.Once);
    }

    [Fact]
    public void InvalidateRoute_NormalizesRoute_AddsLeadingSlash()
    {
        // Arrange
        const string route = "about";
        _mockCacheService
            .Setup(x => x.RemoveByPattern("page:/about*", It.IsAny<int>()))
            .Returns(1);

        // Act
        var result = _invalidator.InvalidateRoute(route);

        // Assert
        result.Should().BeTrue();
        _mockCacheService.Verify(x => x.RemoveByPattern("page:/about*", It.IsAny<int>()), Times.Once);
    }

    [Fact]
    public void InvalidatePattern_Wildcard_RemovesMatches()
    {
        // Arrange
        const string pattern = "/blog/*";
        _mockCacheService
            .Setup(x => x.RemoveByPattern("page:/blog/*", It.IsAny<int>()))
            .Returns(2);

        // Act
        var removed = _invalidator.InvalidatePattern(pattern);

        // Assert
        removed.Should().Be(2);
        _mockCacheService.Verify(x => x.RemoveByPattern("page:/blog/*", It.IsAny<int>()), Times.Once);
    }

    [Fact]
    public void InvalidatePattern_AllPages_RemovesAll()
    {
        // Arrange
        const string pattern = "*";
        _mockCacheService
            .Setup(x => x.RemoveByPattern("page:*", It.IsAny<int>()))
            .Returns(10);

        // Act
        var removed = _invalidator.InvalidatePattern(pattern);

        // Assert
        removed.Should().Be(10);
    }

    [Fact]
    public void InvalidateByTag_ExistingTag_RemovesTaggedEntries()
    {
        // Arrange
        const string tag = "products";
        const string route1 = "/products/1";
        const string route2 = "/products/2";
        const string cacheKey1 = "page:/products/1";
        const string cacheKey2 = "page:/products/2";

        // Register cache keys with tags
        _invalidator.RegisterCacheKey(route1, cacheKey1, new[] { tag });
        _invalidator.RegisterCacheKey(route2, cacheKey2, new[] { tag });

        // Act
        var removed = _invalidator.InvalidateByTag(tag);

        // Assert
        removed.Should().Be(2);
        _mockCacheService.Verify(x => x.Remove(cacheKey1), Times.Once);
        _mockCacheService.Verify(x => x.Remove(cacheKey2), Times.Once);
    }

    [Fact]
    public void InvalidateByTag_NonexistentTag_ReturnsZero()
    {
        // Arrange
        const string tag = "nonexistent";

        // Act
        var removed = _invalidator.InvalidateByTag(tag);

        // Assert
        removed.Should().Be(0);
        _mockCacheService.Verify(x => x.Remove(It.IsAny<string>()), Times.Never);
    }

    [Fact]
    public void InvalidateByTag_MultipleTagsOnSameEntry_RemovesCorrectly()
    {
        // Arrange
        const string route = "/products/1";
        const string cacheKey = "page:/products/1";
        const string tag1 = "products";
        const string tag2 = "catalog";

        // Register cache key with multiple tags
        _invalidator.RegisterCacheKey(route, cacheKey, new[] { tag1, tag2 });

        // Act - invalidate by first tag
        var removed1 = _invalidator.InvalidateByTag(tag1);

        // Assert
        removed1.Should().Be(1);
        _mockCacheService.Verify(x => x.Remove(cacheKey), Times.Once);

        // Act - try invalidating by second tag (should be cleaned up already)
        var removed2 = _invalidator.InvalidateByTag(tag2);

        // Assert - tag should be cleaned up (entry was already removed by first tag)
        removed2.Should().Be(0, "entry and all its tag associations should have been cleaned up by first invalidation");
    }

    [Fact]
    public void ClearAll_RemovesAllEntries()
    {
        // Arrange
        _invalidator.RegisterCacheKey("/about", "page:/about", null);
        _invalidator.RegisterCacheKey("/contact", "page:/contact", null);
        _invalidator.RegisterCacheKey("/blog/post-1", "page:/blog/post-1", new[] { "blog" });

        // Act
        var removed = _invalidator.ClearAll();

        // Assert
        removed.Should().Be(3);
        _mockCacheService.Verify(x => x.Clear(), Times.Once);
    }

    [Fact]
    public void ClearAll_ClearsTagTracking()
    {
        // Arrange
        const string tag = "products";
        _invalidator.RegisterCacheKey("/products/1", "page:/products/1", new[] { tag });

        // Act
        _invalidator.ClearAll();

        // Try to invalidate by tag after clear
        var removed = _invalidator.InvalidateByTag(tag);

        // Assert
        removed.Should().Be(0);
    }

    [Fact]
    public void GetCachedRoutes_ReturnsRegisteredRoutes()
    {
        // Arrange
        _invalidator.RegisterCacheKey("/about", "page:/about", null);
        _invalidator.RegisterCacheKey("/contact", "page:/contact", null);
        _invalidator.RegisterCacheKey("/blog/post-1", "page:/blog/post-1", null);

        // Act
        var routes = _invalidator.GetCachedRoutes();

        // Assert
        routes.Should().HaveCount(3);
        routes.Should().Contain("/about");
        routes.Should().Contain("/contact");
        routes.Should().Contain("/blog/post-1");
    }

    [Fact]
    public void GetCachedRoutes_NormalizesRoutes()
    {
        // Arrange - register with variations
        _invalidator.RegisterCacheKey("/About/", "page:/about", null);
        _invalidator.RegisterCacheKey("contact", "page:/contact", null);

        // Act
        var routes = _invalidator.GetCachedRoutes();

        // Assert
        routes.Should().HaveCount(2);
        routes.Should().Contain("/about");
        routes.Should().Contain("/contact");
    }

    [Fact]
    public void RegisterCacheKey_ThreadSafe_HandlesMultipleRegistrations()
    {
        // Arrange
        const string route = "/products/1";
        const string cacheKey1 = "page:/products/1?v=1";
        const string cacheKey2 = "page:/products/1?v=2";

        // Act - register same route with different cache keys
        _invalidator.RegisterCacheKey(route, cacheKey1, null);
        _invalidator.RegisterCacheKey(route, cacheKey2, null);

        // Assert
        var routes = _invalidator.GetCachedRoutes();
        routes.Should().HaveCount(1);
        routes.Should().Contain("/products/1");
    }

    [Theory]
    [InlineData("", "")]
    [InlineData(null, null)]
    public void InvalidateRoute_NullOrEmpty_ThrowsException(string? route, string? _)
    {
        // Act & Assert
        if (route == null)
        {
            Assert.Throws<ArgumentNullException>(() => _invalidator.InvalidateRoute(route!));
        }
        else
        {
            Assert.Throws<ArgumentException>(() => _invalidator.InvalidateRoute(route));
        }
    }

    [Theory]
    [InlineData("", "")]
    [InlineData(null, null)]
    public void InvalidatePattern_NullOrEmpty_ThrowsException(string? pattern, string? _)
    {
        // Act & Assert
        if (pattern == null)
        {
            Assert.Throws<ArgumentNullException>(() => _invalidator.InvalidatePattern(pattern!));
        }
        else
        {
            Assert.Throws<ArgumentException>(() => _invalidator.InvalidatePattern(pattern));
        }
    }

    [Theory]
    [InlineData("", "")]
    [InlineData(null, null)]
    public void InvalidateByTag_NullOrEmpty_ThrowsException(string? tag, string? _)
    {
        // Act & Assert
        if (tag == null)
        {
            Assert.Throws<ArgumentNullException>(() => _invalidator.InvalidateByTag(tag!));
        }
        else
        {
            Assert.Throws<ArgumentException>(() => _invalidator.InvalidateByTag(tag));
        }
    }
}
