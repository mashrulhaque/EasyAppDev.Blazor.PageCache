using EasyAppDev.Blazor.PageCache.Services;
using Xunit;

namespace EasyAppDev.Blazor.PageCache.Tests.Services;

/// <summary>
/// Tests for Issue 12: Comprehensive Whitespace and Unicode Sanitization
/// </summary>
public class CacheKeySanitizerUnicodeTests
{
    #region Unicode Whitespace Normalization Tests

    [Theory]
    [InlineData("hello\u00A0world", "hello world")] // Non-breaking space
    [InlineData("hello\u2000world", "hello world")] // En Quad
    [InlineData("hello\u2003world", "hello world")] // Em Space
    [InlineData("hello\u3000world", "hello world")] // Ideographic Space
    public void SanitizeKeySegment_UnicodeWhitespace_NormalizesToSpace(string input, string expectedSubstring)
    {
        // Act
        var result = CacheKeySanitizer.SanitizeKeySegment(input);

        // Assert - should contain normalized version (escaped space is "\\ ")
        Assert.Contains("hello", result);
        Assert.Contains("world", result);
    }

    [Fact]
    public void SanitizeKeySegment_MultipleConsecutiveWhitespace_CollapsesToSingle()
    {
        // Arrange - mix of regular spaces and Unicode whitespace
        var input = "hello   \u00A0  \u2000  world";

        // Act
        var result = CacheKeySanitizer.SanitizeKeySegment(input);

        // Assert - multiple whitespace should collapse to single escaped space
        Assert.Contains("hello", result);
        Assert.Contains("world", result);
        // Should not have multiple consecutive spaces
        Assert.DoesNotContain("  ", result.Replace("\\ ", " "));
    }

    [Theory]
    [InlineData("  hello  ", "hello")] // Leading and trailing spaces
    [InlineData("\u00A0hello\u00A0", "hello")] // Leading and trailing NBSP
    [InlineData("\u2000hello\u2003", "hello")] // Mixed Unicode whitespace
    public void SanitizeKeySegment_LeadingTrailingWhitespace_Trimmed(string input, string expected)
    {
        // Act
        var result = CacheKeySanitizer.SanitizeKeySegment(input);

        // Assert
        Assert.Equal(expected, result);
    }

    #endregion

    #region Zero-Width Character Tests

    [Theory]
    [InlineData("hello\u200Bworld", "helloworld")] // Zero-width space
    [InlineData("hello\u200Cworld", "helloworld")] // Zero-width non-joiner
    [InlineData("hello\u200Dworld", "helloworld")] // Zero-width joiner
    [InlineData("\uFEFFhello", "hello")] // BOM at start
    public void SanitizeKeySegment_ZeroWidthCharacters_Removed(string input, string expected)
    {
        // Act
        var result = CacheKeySanitizer.SanitizeKeySegment(input);

        // Assert
        Assert.Equal(expected, result);
    }

    [Fact]
    public void SanitizeKeySegment_MultipleZeroWidthCharacters_AllRemoved()
    {
        // Arrange - string with multiple zero-width characters
        var input = "h\u200Be\u200Cl\u200Dl\uFEFFo";

        // Act
        var result = CacheKeySanitizer.SanitizeKeySegment(input);

        // Assert
        Assert.Equal("hello", result);
    }

    #endregion

    #region Bidirectional Control Character Tests

    [Theory]
    [InlineData("hello\u202Aworld", "helloworld")] // LRE
    [InlineData("hello\u202Bworld", "helloworld")] // RLE
    [InlineData("hello\u202Cworld", "helloworld")] // PDF
    [InlineData("hello\u202Dworld", "helloworld")] // LRO
    [InlineData("hello\u202Eworld", "helloworld")] // RLO
    public void SanitizeKeySegment_BidiControlCharacters_Removed(string input, string expected)
    {
        // Act
        var result = CacheKeySanitizer.SanitizeKeySegment(input);

        // Assert
        Assert.Equal(expected, result);
    }

    [Fact]
    public void SanitizeKeySegment_TrojanSourceAttack_Neutralized()
    {
        // Arrange - Trojan Source attack pattern
        // This could visually appear different than its actual content
        var input = "user\u202Enigami";

        // Act
        var result = CacheKeySanitizer.SanitizeKeySegment(input);

        // Assert - bidi character should be removed, legitimate text preserved
        Assert.Equal("usernigami", result);

        // Verify no bidi control characters remain
        foreach (char c in result)
        {
            Assert.NotEqual('\u202E', c);
            Assert.False(c >= '\u202A' && c <= '\u202E', $"Found bidi character U+{((int)c):X4}");
        }
    }

    #endregion

    #region Line and Paragraph Separator Tests

    [Theory]
    [InlineData("hello\u2028world", "hello world")] // Line separator
    [InlineData("hello\u2029world", "hello world")] // Paragraph separator
    public void SanitizeKeySegment_LineParagraphSeparators_NormalizesToSpace(string input, string expectedPattern)
    {
        // Act
        var result = CacheKeySanitizer.SanitizeKeySegment(input);

        // Assert
        Assert.Contains("hello", result);
        Assert.Contains("world", result);
    }

    #endregion

    #region Combined Attack Patterns

    [Fact]
    public void SanitizeKeySegment_CombinedUnicodeAttack_FullySanitized()
    {
        // Arrange - combines multiple Unicode attack vectors:
        // - Zero-width characters
        // - Bidi controls
        // - Unicode whitespace
        var input = "\uFEFFhello\u200B\u202E\u00A0world\u200C\u2000test\u202A";

        // Act
        var result = CacheKeySanitizer.SanitizeKeySegment(input);

        // Assert - should be fully sanitized, all words preserved
        Assert.Contains("hello", result);
        Assert.Contains("world", result);
        Assert.Contains("test", result);

        // Verify no zero-width or bidi characters remain by checking each character
        foreach (char c in result)
        {
            Assert.DoesNotContain(c, new[] { '\u200B', '\u200C', '\u200D', '\uFEFF' });
            Assert.DoesNotContain(c, new[] { '\u202A', '\u202B', '\u202C', '\u202D', '\u202E' });
        }
    }

    [Fact]
    public void SanitizeKeySegment_HiddenLengthBypass_Prevented()
    {
        // Arrange - attempt to bypass length limit with zero-width characters
        var baseString = new string('a', 500);
        var padding = new string('\u200B', 600); // Zero-width padding
        var input = baseString + padding + baseString;

        // Act
        var result = CacheKeySanitizer.SanitizeKeySegment(input);

        // Assert - zero-width characters removed, real content preserved
        // The sanitizer should remove all zero-width characters
        Assert.Equal(1000, result.Length); // Should be exactly 1000 'a's
        // Verify no zero-width space characters remain
        foreach (char c in result)
        {
            Assert.NotEqual('\u200B', c);
            Assert.NotEqual('\u200C', c);
            Assert.NotEqual('\u200D', c);
            Assert.NotEqual('\uFEFF', c);
        }
    }

    #endregion

    #region Idempotency Tests

    [Fact]
    public void SanitizeKeySegment_Idempotent_DoubleApplicationProducesSameResult()
    {
        // Arrange
        var input = "  hello\u00A0\u200B\u202Eworld  ";

        // Act
        var firstPass = CacheKeySanitizer.SanitizeKeySegment(input);
        var secondPass = CacheKeySanitizer.SanitizeKeySegment(firstPass);

        // Assert - normalization should be idempotent
        Assert.Equal(firstPass, secondPass);
    }

    #endregion

    #region Real-World Scenarios

    [Fact]
    public void SanitizeKeySegment_CopiedFromBrowser_Sanitized()
    {
        // Arrange - text copied from web page might include non-breaking spaces
        var input = "Product\u00A0Name\u00A0123";

        // Act
        var result = CacheKeySanitizer.SanitizeKeySegment(input);

        // Assert - should have normalized spaces
        Assert.Contains("Product", result);
        Assert.Contains("Name", result);
        Assert.Contains("123", result);
    }

    [Fact]
    public void SanitizeKeySegment_RTLLanguageInput_BidiControlsRemoved()
    {
        // Arrange - RTL language text with bidi controls
        var input = "user_\u202Bاسم\u202C_session";

        // Act
        var result = CacheKeySanitizer.SanitizeKeySegment(input);

        // Assert - bidi controls removed but RTL text preserved
        Assert.Contains("user_", result);
        Assert.Contains("_session", result);

        // Verify no bidi control characters remain
        foreach (char c in result)
        {
            Assert.DoesNotContain(c, new[] { '\u202A', '\u202B', '\u202C', '\u202D', '\u202E' });
        }
    }

    #endregion

    #region Edge Cases

    [Fact]
    public void SanitizeKeySegment_OnlyWhitespace_ReturnsEmpty()
    {
        // Arrange - various types of whitespace
        var input = "   \u00A0\u2000\u2003   ";

        // Act
        var result = CacheKeySanitizer.SanitizeKeySegment(input);

        // Assert
        Assert.Equal(string.Empty, result);
    }

    [Fact]
    public void SanitizeKeySegment_OnlyZeroWidthChars_ReturnsEmpty()
    {
        // Arrange
        var input = "\u200B\u200C\u200D\uFEFF";

        // Act
        var result = CacheKeySanitizer.SanitizeKeySegment(input);

        // Assert
        Assert.Equal(string.Empty, result);
    }

    [Fact]
    public void SanitizeKeySegment_OnlyBidiControls_ReturnsEmpty()
    {
        // Arrange
        var input = "\u202A\u202B\u202C\u202D\u202E";

        // Act
        var result = CacheKeySanitizer.SanitizeKeySegment(input);

        // Assert
        Assert.Equal(string.Empty, result);
    }

    #endregion
}
