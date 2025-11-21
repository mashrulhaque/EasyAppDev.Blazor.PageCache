using Xunit;
using EasyAppDev.Blazor.PageCache.Validation;

namespace EasyAppDev.Blazor.PageCache.Tests.Validation;

[Trait("Category", TestCategories.Unit)]
[Trait("Category", TestCategories.Security)]
public sealed class CacheKeyValidatorTests
{
    #region Null and Empty Validation Tests

    [Fact]
    public void Validate_NullCacheKey_ReturnsFailure()
    {
        // Act
        var result = CacheKeyValidator.Validate(null!);

        // Assert
        Assert.False(result.IsValid);
        Assert.Equal(CacheKeyValidationError.NullOrEmpty, result.ErrorType);
        Assert.Contains("cannot be null", result.ErrorMessage, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void ValidateAndThrow_NullCacheKey_ThrowsArgumentNullException()
    {
        // Act & Assert
        var exception = Assert.Throws<ArgumentNullException>(() =>
            CacheKeyValidator.ValidateAndThrow(null!, "testKey"));

        Assert.Contains("cannot be null", exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Theory]
    [InlineData("")]
    [InlineData(" ")]
    [InlineData("   ")]
    [InlineData("\t")]
    [InlineData("\n")]
    public void Validate_EmptyOrWhitespaceCacheKey_ReturnsFailure(string cacheKey)
    {
        // Act
        var result = CacheKeyValidator.Validate(cacheKey);

        // Assert
        Assert.False(result.IsValid);
        Assert.Equal(CacheKeyValidationError.NullOrEmpty, result.ErrorType);
        Assert.Contains("empty or whitespace", result.ErrorMessage, StringComparison.OrdinalIgnoreCase);
    }

    [Theory]
    [InlineData("")]
    [InlineData(" ")]
    [InlineData("   ")]
    public void ValidateAndThrow_EmptyOrWhitespaceCacheKey_ThrowsArgumentNullException(string cacheKey)
    {
        // Act & Assert
        var exception = Assert.Throws<ArgumentNullException>(() =>
            CacheKeyValidator.ValidateAndThrow(cacheKey, "testKey"));

        Assert.Contains("empty or whitespace", exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    #endregion

    #region Length Validation Tests

    [Fact]
    public void Validate_ValidLengthCacheKey_ReturnsSuccess()
    {
        // Arrange
        var cacheKey = "PageCache:home/index";

        // Act
        var result = CacheKeyValidator.Validate(cacheKey);

        // Assert
        Assert.True(result.IsValid);
        Assert.Equal(CacheKeyValidationError.None, result.ErrorType);
    }

    [Fact]
    public void Validate_ExactlyMaxLengthCacheKey_ReturnsSuccess()
    {
        // Arrange - Create a key that's exactly 2048 bytes
        var cacheKey = new string('a', 2048);

        // Act
        var result = CacheKeyValidator.Validate(cacheKey);

        // Assert
        Assert.True(result.IsValid);
    }

    [Fact]
    public void Validate_ExceedsMaxLengthCacheKey_ReturnsFailure()
    {
        // Arrange - Create a key that's 2049 bytes (exceeds 2KB limit)
        var cacheKey = new string('a', 2049);

        // Act
        var result = CacheKeyValidator.Validate(cacheKey);

        // Assert
        Assert.False(result.IsValid);
        Assert.Equal(CacheKeyValidationError.ExceedsMaxLength, result.ErrorType);
        Assert.Contains("exceeds maximum allowed length", result.ErrorMessage, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("2048 bytes", result.ErrorMessage);
        Assert.NotNull(result.ErrorDetails);
        Assert.True(result.ErrorDetails!.ContainsKey("ActualLengthBytes"));
        Assert.Equal("2049", result.ErrorDetails["ActualLengthBytes"]);
    }

    [Fact]
    public void ValidateAndThrow_ExceedsMaxLengthCacheKey_ThrowsArgumentException()
    {
        // Arrange
        var cacheKey = new string('a', 2049);

        // Act & Assert
        var exception = Assert.Throws<ArgumentException>(() =>
            CacheKeyValidator.ValidateAndThrow(cacheKey));

        Assert.Contains("exceeds maximum allowed length", exception.Message, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("2048", exception.Message);
    }

    [Fact]
    public void Validate_MultiByteCharactersExceedsMaxLength_ReturnsFailure()
    {
        // Arrange - UTF-8 characters that take multiple bytes
        // Chinese characters typically use 3 bytes each in UTF-8
        // 700 characters × 3 bytes = 2100 bytes (exceeds 2048)
        var cacheKey = new string('中', 700);

        // Act
        var result = CacheKeyValidator.Validate(cacheKey);

        // Assert
        Assert.False(result.IsValid);
        Assert.Equal(CacheKeyValidationError.ExceedsMaxLength, result.ErrorType);
    }

    #endregion

    #region Character Set Validation Tests

    [Theory]
    [InlineData("PageCache:home")]
    [InlineData("cache-key-123")]
    [InlineData("user_session_abc")]
    [InlineData("api.v1.endpoint")]
    [InlineData("path/to/resource")]
    [InlineData("mixed-chars_123.test")]
    [InlineData("UPPERCASE")]
    [InlineData("lowercase")]
    [InlineData("MixedCase123")]
    [InlineData("key:with:multiple:colons")]
    [InlineData("path/with/slashes/")]
    [InlineData("dots.in.key")]
    [InlineData("with\\escaped\\chars")]
    public void Validate_ValidCharacterSet_ReturnsSuccess(string cacheKey)
    {
        // Act
        var result = CacheKeyValidator.Validate(cacheKey);

        // Assert
        Assert.True(result.IsValid, $"Key '{cacheKey}' should be valid but got: {result.ErrorMessage}");
        Assert.Equal(CacheKeyValidationError.None, result.ErrorType);
    }

    [Theory]
    [InlineData("key with spaces")]
    [InlineData("key@email.com")]
    [InlineData("key#hash")]
    [InlineData("key$dollar")]
    [InlineData("key%percent")]
    [InlineData("key&ampersand")]
    [InlineData("key!exclamation")]
    [InlineData("key=equals")]
    [InlineData("key+plus")]
    [InlineData("key;semicolon")]
    [InlineData("key,comma")]
    [InlineData("key<less")]
    [InlineData("key>greater")]
    [InlineData("key[bracket]")]
    [InlineData("key{brace}")]
    [InlineData("key(paren)")]
    [InlineData("key'quote")]
    [InlineData("key\"doublequote")]
    [InlineData("key`backtick")]
    [InlineData("key~tilde")]
    [InlineData("key|pipe")]
    public void Validate_InvalidCharacters_ReturnsFailure(string cacheKey)
    {
        // Act
        var result = CacheKeyValidator.Validate(cacheKey);

        // Assert
        Assert.False(result.IsValid, $"Key '{cacheKey}' should be invalid");
        Assert.Equal(CacheKeyValidationError.InvalidCharacters, result.ErrorType);
        Assert.Contains("invalid characters", result.ErrorMessage, StringComparison.OrdinalIgnoreCase);
        Assert.NotNull(result.ErrorDetails);
        Assert.True(result.ErrorDetails!.ContainsKey("InvalidCharacters"));
    }

    [Theory]
    [InlineData("key\ttab")]
    [InlineData("key\nnewline")]
    [InlineData("key\rcarriage")]
    [InlineData("key\0null")]
    public void Validate_ControlCharacters_ReturnsFailure(string cacheKey)
    {
        // Act
        var result = CacheKeyValidator.Validate(cacheKey);

        // Assert
        Assert.False(result.IsValid);
        Assert.Equal(CacheKeyValidationError.ContainsControlCharacters, result.ErrorType);
        Assert.Contains("control characters", result.ErrorMessage, StringComparison.OrdinalIgnoreCase);
        Assert.NotNull(result.ErrorDetails);
        Assert.True(result.ErrorDetails!.ContainsKey("ControlCharacters"));
    }

    #endregion

    #region Suspicious Pattern Detection Tests

    [Theory]
    [InlineData("key///multiple///slashes")]
    [InlineData("key\\\\\\many\\\\\\backslashes")]
    public void Validate_MultipleConsecutiveSpecialChars_ReturnsFailure(string cacheKey)
    {
        // Act
        var result = CacheKeyValidator.Validate(cacheKey);

        // Assert
        Assert.False(result.IsValid);
        Assert.Equal(CacheKeyValidationError.SuspiciousPattern, result.ErrorType);
        Assert.Contains("suspicious pattern", result.ErrorMessage, StringComparison.OrdinalIgnoreCase);
    }

    [Theory]
    [InlineData("key\\\\\\\\\\\\\\\\\\\\repeated")]
    public void Validate_RepeatedEscapeSequences_ReturnsFailure(string cacheKey)
    {
        // Act
        var result = CacheKeyValidator.Validate(cacheKey);

        // Assert
        Assert.False(result.IsValid);
        Assert.Equal(CacheKeyValidationError.SuspiciousPattern, result.ErrorType);
        Assert.Contains("suspicious pattern", result.ErrorMessage, StringComparison.OrdinalIgnoreCase);
    }

    [Theory]
    [InlineData("../etc/passwd")]
    [InlineData("..\\windows\\system32")]
    [InlineData("path/../../../etc")]
    public void Validate_PathTraversalPatterns_ReturnsFailure(string cacheKey)
    {
        // Act
        var result = CacheKeyValidator.Validate(cacheKey);

        // Assert
        Assert.False(result.IsValid);
        Assert.Equal(CacheKeyValidationError.SuspiciousPattern, result.ErrorType);
        Assert.Contains("suspicious pattern", result.ErrorMessage, StringComparison.OrdinalIgnoreCase);
    }

    [Theory]
    [InlineData("key\\0injection")]
    [InlineData("key%00injection")]
    public void Validate_NullByteInjection_ReturnsFailure(string cacheKey)
    {
        // Act
        var result = CacheKeyValidator.Validate(cacheKey);

        // Assert
        Assert.False(result.IsValid);
        Assert.Equal(CacheKeyValidationError.SuspiciousPattern, result.ErrorType);
        Assert.Contains("suspicious pattern", result.ErrorMessage, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Validate_ExcessiveColons_ReturnsFailure()
    {
        // Arrange - More than 5 consecutive colons
        var cacheKey = "key::::::value";

        // Act
        var result = CacheKeyValidator.Validate(cacheKey);

        // Assert
        Assert.False(result.IsValid);
        Assert.Equal(CacheKeyValidationError.SuspiciousPattern, result.ErrorType);
    }

    [Theory]
    [InlineData("key:one:two:three:four")]
    [InlineData("key:::value")]
    [InlineData("key::::value")]
    public void Validate_ReasonableColons_ReturnsSuccess(string cacheKey)
    {
        // Act
        var result = CacheKeyValidator.Validate(cacheKey);

        // Assert
        Assert.True(result.IsValid, $"Key should be valid but got: {result.ErrorMessage}");
    }

    #endregion

    #region Boundary Condition Tests

    [Fact]
    public void Validate_SingleCharacter_ReturnsSuccess()
    {
        // Act
        var result = CacheKeyValidator.Validate("a");

        // Assert
        Assert.True(result.IsValid);
    }

    [Fact]
    public void Validate_AllAllowedCharacters_ReturnsSuccess()
    {
        // Arrange
        var cacheKey = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_:./\\";

        // Act
        var result = CacheKeyValidator.Validate(cacheKey);

        // Assert
        Assert.True(result.IsValid);
    }

    [Fact]
    public void Validate_VeryLongValidKey_ReturnsSuccess()
    {
        // Arrange - 2000 bytes (just under the 2048 limit)
        var cacheKey = "PageCache:" + new string('a', 1990);

        // Act
        var result = CacheKeyValidator.Validate(cacheKey);

        // Assert
        Assert.True(result.IsValid);
    }

    [Fact]
    public void Validate_BoundaryAt2047Bytes_ReturnsSuccess()
    {
        // Arrange
        var cacheKey = new string('a', 2047);

        // Act
        var result = CacheKeyValidator.Validate(cacheKey);

        // Assert
        Assert.True(result.IsValid);
    }

    [Fact]
    public void Validate_BoundaryAt2048Bytes_ReturnsSuccess()
    {
        // Arrange
        var cacheKey = new string('a', 2048);

        // Act
        var result = CacheKeyValidator.Validate(cacheKey);

        // Assert
        Assert.True(result.IsValid);
    }

    [Fact]
    public void Validate_BoundaryAt2049Bytes_ReturnsFailure()
    {
        // Arrange
        var cacheKey = new string('a', 2049);

        // Act
        var result = CacheKeyValidator.Validate(cacheKey);

        // Assert
        Assert.False(result.IsValid);
        Assert.Equal(CacheKeyValidationError.ExceedsMaxLength, result.ErrorType);
    }

    #endregion

    #region ValidateAndThrow Tests

    [Fact]
    public void ValidateAndThrow_ValidKey_DoesNotThrow()
    {
        // Arrange
        var cacheKey = "PageCache:home/index";

        // Act & Assert
        var exception = Record.Exception(() => CacheKeyValidator.ValidateAndThrow(cacheKey));
        Assert.Null(exception);
    }

    [Fact]
    public void ValidateAndThrow_InvalidKey_ThrowsArgumentException()
    {
        // Arrange
        var cacheKey = "invalid key with spaces";

        // Act & Assert
        var exception = Assert.Throws<ArgumentException>(() =>
            CacheKeyValidator.ValidateAndThrow(cacheKey, "myKey"));

        Assert.Contains("invalid characters", exception.Message, StringComparison.OrdinalIgnoreCase);
        Assert.Equal("myKey", exception.ParamName);
    }

    [Fact]
    public void ValidateAndThrow_InvalidKeyNoParamName_UsesDefaultParamName()
    {
        // Arrange
        var cacheKey = "invalid key";

        // Act & Assert
        var exception = Assert.Throws<ArgumentException>(() =>
            CacheKeyValidator.ValidateAndThrow(cacheKey));

        Assert.Equal("cacheKey", exception.ParamName);
    }

    [Fact]
    public void ValidateAndThrow_WithErrorDetails_IncludesDetailsInMessage()
    {
        // Arrange
        var cacheKey = new string('a', 2049);

        // Act & Assert
        var exception = Assert.Throws<ArgumentException>(() =>
            CacheKeyValidator.ValidateAndThrow(cacheKey));

        Assert.Contains("ActualLengthBytes", exception.Message);
        Assert.Contains("2049", exception.Message);
    }

    #endregion

    #region Real-World Scenario Tests

    [Theory]
    [InlineData("PageCache:products/list")]
    [InlineData("PageCache:user/123/profile")]
    [InlineData("PageCache:api/v1/users")]
    [InlineData("PageCache:home/en-US")]
    [InlineData("PageCache:search/query-results")]
    [InlineData("Cache-Key-With-Dashes")]
    [InlineData("cache_key_with_underscores")]
    [InlineData("RouteCache:/products/category-123")]
    public void Validate_RealWorldCacheKeys_ReturnsSuccess(string cacheKey)
    {
        // Act
        var result = CacheKeyValidator.Validate(cacheKey);

        // Assert
        Assert.True(result.IsValid, $"Real-world key '{cacheKey}' should be valid but got: {result.ErrorMessage}");
    }

    [Fact]
    public void Validate_CacheKeyWithMultipleSegments_ReturnsSuccess()
    {
        // Arrange
        var cacheKey = "PageCache:products:category-electronics:page-1:sort-price";

        // Act
        var result = CacheKeyValidator.Validate(cacheKey);

        // Assert
        Assert.True(result.IsValid);
    }

    [Fact]
    public void Validate_CacheKeyWithNumericIds_ReturnsSuccess()
    {
        // Arrange
        var cacheKey = "PageCache:user-123456:session-789012:page-home";

        // Act
        var result = CacheKeyValidator.Validate(cacheKey);

        // Assert
        Assert.True(result.IsValid);
    }

    [Fact]
    public void Validate_EscapedSpecialCharacters_ReturnsSuccess()
    {
        // Arrange - Sanitized keys with escaped characters
        var cacheKey = "PageCache:query\\*results";

        // Act
        var result = CacheKeyValidator.Validate(cacheKey);

        // Assert
        Assert.True(result.IsValid);
    }

    #endregion

    #region Error Detail Tests

    [Fact]
    public void Validate_Failure_IncludesErrorDetails()
    {
        // Arrange
        var cacheKey = new string('a', 2100);

        // Act
        var result = CacheKeyValidator.Validate(cacheKey);

        // Assert
        Assert.False(result.IsValid);
        Assert.NotNull(result.ErrorDetails);
        Assert.NotEmpty(result.ErrorDetails!);
        Assert.Contains("ActualLengthBytes", result.ErrorDetails.Keys);
    }

    [Fact]
    public void Validate_InvalidCharacters_IncludesCharacterList()
    {
        // Arrange
        var cacheKey = "key with spaces";

        // Act
        var result = CacheKeyValidator.Validate(cacheKey);

        // Assert
        Assert.False(result.IsValid);
        Assert.NotNull(result.ErrorDetails);
        Assert.Contains("InvalidCharacters", result.ErrorDetails!.Keys);
        Assert.Contains("U+0020", result.ErrorDetails["InvalidCharacters"]); // Space character
    }

    [Fact]
    public void Validate_ControlCharacters_IncludesUnicodeValues()
    {
        // Arrange
        var cacheKey = "key\ttab";

        // Act
        var result = CacheKeyValidator.Validate(cacheKey);

        // Assert
        Assert.False(result.IsValid);
        Assert.NotNull(result.ErrorDetails);
        Assert.Contains("ControlCharacters", result.ErrorDetails!.Keys);
        Assert.Contains("U+0009", result.ErrorDetails["ControlCharacters"]); // Tab character
    }

    [Fact]
    public void Validate_SuspiciousPattern_IncludesDetectedPattern()
    {
        // Arrange
        var cacheKey = "../etc/passwd";

        // Act
        var result = CacheKeyValidator.Validate(cacheKey);

        // Assert
        Assert.False(result.IsValid);
        Assert.NotNull(result.ErrorDetails);
        Assert.Contains("DetectedPattern", result.ErrorDetails!.Keys);
        Assert.NotEmpty(result.ErrorDetails["DetectedPattern"]);
    }

    #endregion

    #region CacheKeyValidationResult Tests

    [Fact]
    public void CacheKeyValidationResult_Success_HasCorrectProperties()
    {
        // Act
        var result = CacheKeyValidationResult.Success();

        // Assert
        Assert.True(result.IsValid);
        Assert.Null(result.ErrorMessage);
        Assert.Null(result.ErrorDetails);
        Assert.Equal(CacheKeyValidationError.None, result.ErrorType);
    }

    [Fact]
    public void CacheKeyValidationResult_Failure_HasCorrectProperties()
    {
        // Arrange
        var errorDetails = new Dictionary<string, string> { ["Key"] = "Value" };

        // Act
        var result = CacheKeyValidationResult.Failure(
            "Test error",
            CacheKeyValidationError.InvalidCharacters,
            errorDetails);

        // Assert
        Assert.False(result.IsValid);
        Assert.Equal("Test error", result.ErrorMessage);
        Assert.Equal(CacheKeyValidationError.InvalidCharacters, result.ErrorType);
        Assert.NotNull(result.ErrorDetails);
        Assert.Equal("Value", result.ErrorDetails!["Key"]);
    }

    #endregion

    #region Performance and Edge Case Tests

    [Fact]
    public void Validate_RepeatedValidation_IsConsistent()
    {
        // Arrange
        var cacheKey = "PageCache:test/key";

        // Act
        var result1 = CacheKeyValidator.Validate(cacheKey);
        var result2 = CacheKeyValidator.Validate(cacheKey);
        var result3 = CacheKeyValidator.Validate(cacheKey);

        // Assert
        Assert.True(result1.IsValid);
        Assert.True(result2.IsValid);
        Assert.True(result3.IsValid);
    }

    [Fact]
    public void Validate_DifferentInvalidKeys_ReturnsDifferentErrors()
    {
        // Arrange
        var nullKey = (string)null!;
        var tooLongKey = new string('a', 2100);
        var invalidCharsKey = "key with spaces";

        // Act
        var result1 = CacheKeyValidator.Validate(nullKey);
        var result2 = CacheKeyValidator.Validate(tooLongKey);
        var result3 = CacheKeyValidator.Validate(invalidCharsKey);

        // Assert
        Assert.Equal(CacheKeyValidationError.NullOrEmpty, result1.ErrorType);
        Assert.Equal(CacheKeyValidationError.ExceedsMaxLength, result2.ErrorType);
        Assert.Equal(CacheKeyValidationError.InvalidCharacters, result3.ErrorType);
    }

    [Fact]
    public void Validate_AllASCIIPrintableCharacters_ValidatesCorrectly()
    {
        // Test each ASCII printable character individually
        for (int i = 33; i <= 126; i++)
        {
            var ch = (char)i;
            var key = $"test{ch}key";
            var result = CacheKeyValidator.Validate(key);

            // Valid characters: a-z, A-Z, 0-9, -, _, :, ., /, \
            var validChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_:./\\";
            var shouldBeValid = validChars.Contains(ch);

            Assert.True(shouldBeValid == result.IsValid,
                $"Character '{ch}' (ASCII {i}) validation mismatch. " +
                $"Expected: {(shouldBeValid ? "valid" : "invalid")}, Got: {(result.IsValid ? "valid" : "invalid")}. " +
                $"Error: {result.ErrorMessage}");
        }
    }

    #endregion
}
