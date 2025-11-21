using FluentAssertions;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Moq;
using System.Globalization;
using System.Text;
using EasyAppDev.Blazor.PageCache.Configuration;
using EasyAppDev.Blazor.PageCache.Services;

namespace EasyAppDev.Blazor.PageCache.Tests.Services;

/// <summary>
/// Tests for Unicode normalization in cache key generation (Issue 13).
/// Ensures that different Unicode representations of the same logical string
/// produce the same cache key, preventing cache key collisions and homoglyph attacks.
/// </summary>
public class UnicodeNormalizationTests
{
    private readonly Mock<ILogger<DefaultCacheKeyGenerator>> _loggerMock;
    private readonly PageCacheOptions _options;
    private readonly DefaultCacheKeyGenerator _generator;

    public UnicodeNormalizationTests()
    {
        _loggerMock = new Mock<ILogger<DefaultCacheKeyGenerator>>();
        _options = new PageCacheOptions { VaryByCulture = false };
        var optionsMock = new Mock<IOptions<PageCacheOptions>>();
        optionsMock.Setup(o => o.Value).Returns(_options);
        _generator = new DefaultCacheKeyGenerator(optionsMock.Object, _loggerMock.Object);
    }

    #region Path Normalization Tests

    [Fact]
    public void GenerateKey_WithComposedAndDecomposedCafe_GeneratesSameKey()
    {
        // Arrange - "café" in two different Unicode forms
        // Composed form (NFC): U+0063 U+0061 U+0066 U+00E9
        var composedPath = "/caf\u00e9";

        // Decomposed form (NFD): U+0063 U+0061 U+0066 U+0065 U+0301
        var decomposedPath = "/cafe\u0301";

        var contextComposed = CreateHttpContext(composedPath);
        var contextDecomposed = CreateHttpContext(decomposedPath);

        // Act
        var keyComposed = _generator.GenerateKey(contextComposed);
        var keyDecomposed = _generator.GenerateKey(contextDecomposed);

        // Assert
        keyComposed.Should().Be(keyDecomposed,
            "composed and decomposed forms of 'café' should generate the same cache key");
    }

    [Fact]
    public void GenerateKey_WithDifferentAccentRepresentations_GeneratesSameKey()
    {
        // Arrange - Testing various diacritics that can be composed/decomposed
        // "résumé" with composed accents
        var composed = "/r\u00e9sum\u00e9";

        // "résumé" with decomposed accents
        var decomposed = "/re\u0301sume\u0301";

        var contextComposed = CreateHttpContext(composed);
        var contextDecomposed = CreateHttpContext(decomposed);

        // Act
        var keyComposed = _generator.GenerateKey(contextComposed);
        var keyDecomposed = _generator.GenerateKey(contextDecomposed);

        // Assert
        keyComposed.Should().Be(keyDecomposed,
            "different accent representations should normalize to the same cache key");
    }

    [Fact]
    public void GenerateKey_WithCombiningDiacritics_NormalizesCorrectly()
    {
        // Arrange - Testing combining diacritics
        // "naïve" with combining diaeresis
        var combining = "/nai\u0308ve";

        // "naïve" with precomposed character
        var precomposed = "/na\u00efve";

        var contextCombining = CreateHttpContext(combining);
        var contextPrecomposed = CreateHttpContext(precomposed);

        // Act
        var keyCombining = _generator.GenerateKey(contextCombining);
        var keyPrecomposed = _generator.GenerateKey(contextPrecomposed);

        // Assert
        keyCombining.Should().Be(keyPrecomposed,
            "combining diacritics should normalize to the same cache key as precomposed characters");
    }

    #endregion

    #region Route Value Normalization Tests

    [Fact]
    public void GenerateKey_WithUnicodeRouteValues_NormalizesCorrectly()
    {
        // Arrange - Route value with composed vs decomposed Unicode
        var composed = "caf\u00e9"; // café (composed)
        var decomposed = "cafe\u0301"; // café (decomposed)

        var contextComposed = CreateHttpContext("/blog");
        var routeDataComposed = new RouteData();
        routeDataComposed.Values["slug"] = composed;
        contextComposed.Features.Set<IRoutingFeature>(new RoutingFeature { RouteData = routeDataComposed });

        var contextDecomposed = CreateHttpContext("/blog");
        var routeDataDecomposed = new RouteData();
        routeDataDecomposed.Values["slug"] = decomposed;
        contextDecomposed.Features.Set<IRoutingFeature>(new RoutingFeature { RouteData = routeDataDecomposed });

        // Act
        var keyComposed = _generator.GenerateKey(contextComposed);
        var keyDecomposed = _generator.GenerateKey(contextDecomposed);

        // Assert
        keyComposed.Should().Be(keyDecomposed,
            "route values with different Unicode forms should generate the same cache key");
    }

    #endregion

    #region Query String Normalization Tests

    [Fact]
    public void GenerateKey_WithUnicodeQueryParameters_NormalizesCorrectly()
    {
        // Arrange - Query parameter with composed vs decomposed Unicode
        var composed = "caf\u00e9"; // café (composed)
        var decomposed = "cafe\u0301"; // café (decomposed)

        var contextComposed = CreateHttpContext("/search");
        contextComposed.Request.QueryString = new QueryString($"?q={Uri.EscapeDataString(composed)}");

        var contextDecomposed = CreateHttpContext("/search");
        contextDecomposed.Request.QueryString = new QueryString($"?q={Uri.EscapeDataString(decomposed)}");

        // Act
        var keyComposed = _generator.GenerateKey(contextComposed,
            varyByQueryKeys: new[] { "q" });
        var keyDecomposed = _generator.GenerateKey(contextDecomposed,
            varyByQueryKeys: new[] { "q" });

        // Assert
        keyComposed.Should().Be(keyDecomposed,
            "query parameters with different Unicode forms should generate the same cache key");
    }

    #endregion

    #region Header Normalization Tests

    [Fact]
    public void GenerateKey_WithUnicodeHeaders_NormalizesCorrectly()
    {
        // Arrange - Header value with composed vs decomposed Unicode
        var composed = "caf\u00e9"; // café (composed)
        var decomposed = "cafe\u0301"; // café (decomposed)

        var contextComposed = CreateHttpContext("/api/data");
        contextComposed.Request.Headers["X-Custom"] = composed;

        var contextDecomposed = CreateHttpContext("/api/data");
        contextDecomposed.Request.Headers["X-Custom"] = decomposed;

        // Act
        var keyComposed = _generator.GenerateKey(contextComposed,
            varyByHeader: "X-Custom");
        var keyDecomposed = _generator.GenerateKey(contextDecomposed,
            varyByHeader: "X-Custom");

        // Assert
        keyComposed.Should().Be(keyDecomposed,
            "header values with different Unicode forms should generate the same cache key");
    }

    #endregion

    #region Idempotency Tests

    [Fact]
    public void GenerateKey_NormalizationIsIdempotent()
    {
        // Arrange - Apply normalization multiple times
        var original = "/caf\u00e9";
        var context1 = CreateHttpContext(original);
        var context2 = CreateHttpContext(original);

        // Act
        var key1 = _generator.GenerateKey(context1);
        var key2 = _generator.GenerateKey(context2);

        // Assert
        key1.Should().Be(key2, "normalization should be idempotent");
    }

    [Fact]
    public void SanitizeKeySegment_NormalizationIsIdempotent()
    {
        // Arrange
        var composed = "caf\u00e9"; // café (composed)
        var decomposed = "cafe\u0301"; // café (decomposed)

        // Act - Apply sanitization multiple times
        var sanitized1 = CacheKeySanitizer.SanitizeKeySegment(composed);
        var sanitized2 = CacheKeySanitizer.SanitizeKeySegment(sanitized1);
        var sanitized3 = CacheKeySanitizer.SanitizeKeySegment(decomposed);

        // Assert
        sanitized1.Should().Be(sanitized2, "sanitization should be idempotent");
        sanitized1.Should().Be(sanitized3, "different forms should normalize to same result");
    }

    #endregion

    #region Ligature Tests (NFC vs NFKC)

    [Fact]
    public void GenerateKey_WithLigatures_PreservesLigatures()
    {
        // Arrange - Testing that we use NFC, not NFKC
        // Ligature "ﬁ" (U+FB01) should be preserved in NFC
        var withLigature = "/\ufb01le"; // "ﬁle" with ligature
        var withoutLigature = "/file"; // "file" without ligature

        var contextWithLigature = CreateHttpContext(withLigature);
        var contextWithoutLigature = CreateHttpContext(withoutLigature);

        // Act
        var keyWithLigature = _generator.GenerateKey(contextWithLigature);
        var keyWithoutLigature = _generator.GenerateKey(contextWithoutLigature);

        // Assert
        keyWithLigature.Should().NotBe(keyWithoutLigature,
            "NFC should preserve ligatures, making them distinct from expanded forms");
    }

    #endregion

    #region Case Folding Tests

    [Fact]
    public void GenerateKey_WithMixedCaseUnicode_NormalizesAndLowerCases()
    {
        // Arrange
        var uppercase = "/CAF\u00c9"; // CAFÉ (composed, uppercase)
        var lowercase = "/caf\u00e9"; // café (composed, lowercase)

        var contextUppercase = CreateHttpContext(uppercase);
        var contextLowercase = CreateHttpContext(lowercase);

        // Act
        var keyUppercase = _generator.GenerateKey(contextUppercase);
        var keyLowercase = _generator.GenerateKey(contextLowercase);

        // Assert
        keyUppercase.Should().Be(keyLowercase,
            "Unicode normalization should work with case folding");
    }

    #endregion

    #region Multiple Combining Characters Tests

    [Fact]
    public void GenerateKey_WithMultipleCombiningCharacters_NormalizesCorrectly()
    {
        // Arrange - Testing complex combining sequences
        // Vietnamese "ệ" can be represented as:
        // 1. Single precomposed character: U+1EC7
        // 2. Base + combining: e + circumflex + dot below
        var precomposed = "/vi\u1ec7t"; // "việt" with precomposed ệ
        var combining = "/vie\u0302\u0323t"; // "việt" with combining marks

        var contextPrecomposed = CreateHttpContext(precomposed);
        var contextCombining = CreateHttpContext(combining);

        // Act
        var keyPrecomposed = _generator.GenerateKey(contextPrecomposed);
        var keyCombining = _generator.GenerateKey(contextCombining);

        // Assert
        keyPrecomposed.Should().Be(keyCombining,
            "multiple combining characters should normalize correctly");
    }

    #endregion

    #region CacheKeySanitizer Direct Tests

    [Fact]
    public void SanitizeKeySegment_WithComposedUnicode_ProducesSameOutputAsDecomposed()
    {
        // Arrange
        var composed = "caf\u00e9";
        var decomposed = "cafe\u0301";

        // Act
        var sanitizedComposed = CacheKeySanitizer.SanitizeKeySegment(composed);
        var sanitizedDecomposed = CacheKeySanitizer.SanitizeKeySegment(decomposed);

        // Assert
        sanitizedComposed.Should().Be(sanitizedDecomposed);
    }

    [Fact]
    public void SanitizeKeySegment_WithNullOrEmpty_ReturnsEmpty()
    {
        // Act & Assert
        CacheKeySanitizer.SanitizeKeySegment(null).Should().BeEmpty();
        CacheKeySanitizer.SanitizeKeySegment("").Should().BeEmpty();
    }

    [Fact]
    public void SanitizeKeySegment_WithVariousUnicodeScripts_NormalizesCorrectly()
    {
        // Arrange - Testing various scripts
        var greek = "\u03b1\u0301"; // Greek alpha with combining acute
        var cyrillic = "\u0430\u0301"; // Cyrillic a with combining acute
        var hebrew = "\u05d0\u05b0"; // Hebrew alef with combining mark

        // Act
        var sanitizedGreek = CacheKeySanitizer.SanitizeKeySegment(greek);
        var sanitizedCyrillic = CacheKeySanitizer.SanitizeKeySegment(cyrillic);
        var sanitizedHebrew = CacheKeySanitizer.SanitizeKeySegment(hebrew);

        // Assert - Should complete without errors and produce normalized output
        sanitizedGreek.Should().NotBeNullOrEmpty();
        sanitizedCyrillic.Should().NotBeNullOrEmpty();
        sanitizedHebrew.Should().NotBeNullOrEmpty();
    }

    #endregion

    #region Performance and Edge Cases

    [Fact]
    public void SanitizeKeySegment_WithLongUnicodeString_HandlesCorrectly()
    {
        // Arrange - String with many combining characters
        var sb = new StringBuilder();
        for (int i = 0; i < 100; i++)
        {
            sb.Append("cafe\u0301"); // Repeat "café" with decomposed accent
        }
        var longString = sb.ToString();

        // Act
        var action = () => CacheKeySanitizer.SanitizeKeySegment(longString);

        // Assert - Should complete without errors
        action.Should().NotThrow();
        var result = action();
        result.Should().NotBeNullOrEmpty();
    }

    [Fact]
    public void SanitizeKeySegment_WithAlreadyNormalizedString_RemainsUnchanged()
    {
        // Arrange - String already in NFC form
        var nfcString = "caf\u00e9"; // Already in NFC

        // Act
        var sanitized1 = CacheKeySanitizer.SanitizeKeySegment(nfcString);
        var sanitized2 = CacheKeySanitizer.SanitizeKeySegment(sanitized1);

        // Assert
        sanitized1.Should().Be(sanitized2, "already normalized strings should remain unchanged");
    }

    #endregion

    #region Helper Methods

    private static DefaultHttpContext CreateHttpContext(string path)
    {
        var context = new DefaultHttpContext();
        context.Request.Path = path;
        context.Request.Method = "GET";
        return context;
    }

    private class RoutingFeature : IRoutingFeature
    {
        public RouteData? RouteData { get; set; } = new RouteData();
    }

    #endregion
}
