using Xunit;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using EasyAppDev.Blazor.PageCache.Configuration;
using EasyAppDev.Blazor.PageCache.Validation;
using EasyAppDev.Blazor.PageCache.Abstractions;

namespace EasyAppDev.Blazor.PageCache.Tests.Validation;

[Trait("Category", TestCategories.Unit)]
public sealed class HtmlSanitizerValidatorTests
{
    [Fact]
    public async Task ValidateAsync_SafeHtml_ReturnsSuccess()
    {
        // Arrange
        var options = Options.Create(new SecurityOptions { EnableHtmlValidation = true });
        var validator = new HtmlSanitizerValidator(options, NullLogger<HtmlSanitizerValidator>.Instance);
        var content = "<div><p>Hello World</p></div>";

        // Act
        var result = await validator.ValidateAsync(content, "test-key");

        // Assert
        Assert.True(result.IsValid);
    }

    [Fact]
    public async Task ValidateAsync_InlineEventHandler_ReturnsFailure()
    {
        // Arrange
        var options = Options.Create(new SecurityOptions { EnableHtmlValidation = true });
        var validator = new HtmlSanitizerValidator(options, NullLogger<HtmlSanitizerValidator>.Instance);
        var content = "<button onclick='alert(1)'>Click me</button>";

        // Act
        var result = await validator.ValidateAsync(content, "test-key");

        // Assert
        Assert.False(result.IsValid);
        Assert.Equal(ValidationSeverity.Critical, result.Severity);
        Assert.Contains("XSS pattern detected", result.ErrorMessage);
    }

    [Fact]
    public async Task ValidateAsync_JavaScriptProtocol_ReturnsFailure()
    {
        // Arrange
        var options = Options.Create(new SecurityOptions { EnableHtmlValidation = true });
        var validator = new HtmlSanitizerValidator(options, NullLogger<HtmlSanitizerValidator>.Instance);
        var content = "<a href='javascript:void(0)'>Link</a>";

        // Act
        var result = await validator.ValidateAsync(content, "test-key");

        // Assert
        Assert.False(result.IsValid);
        Assert.Equal(ValidationSeverity.Critical, result.Severity);
    }

    [Fact]
    public async Task ValidateAsync_ExcessiveScriptTags_ReturnsWarning()
    {
        // Arrange
        var options = Options.Create(new SecurityOptions
        {
            EnableHtmlValidation = true,
            MaxScriptTagsAllowed = 2
        });
        var validator = new HtmlSanitizerValidator(options, NullLogger<HtmlSanitizerValidator>.Instance);
        var content = "<script>console.log(1)</script><script>console.log(2)</script><script>console.log(3)</script>";

        // Act
        var result = await validator.ValidateAsync(content, "test-key");

        // Assert
        // NOTE: With the ScriptTag pattern added, ANY script tag is now detected immediately as Critical
        // This is more secure than waiting to count them - we catch XSS earlier
        Assert.False(result.IsValid);
        Assert.Equal(ValidationSeverity.Critical, result.Severity);
        Assert.Contains("script", result.ErrorMessage.ToLowerInvariant());
    }

    [Fact]
    public async Task ValidateAsync_ValidationDisabled_AlwaysReturnsSuccess()
    {
        // Arrange
        var options = Options.Create(new SecurityOptions { EnableHtmlValidation = false });
        var validator = new HtmlSanitizerValidator(options, NullLogger<HtmlSanitizerValidator>.Instance);
        var content = "<script>alert('XSS')</script>";

        // Act
        var result = await validator.ValidateAsync(content, "test-key");

        // Assert
        Assert.True(result.IsValid);
    }

    [Fact]
    public async Task ValidateAsync_DefaultSecurityOptions_ValidationIsEnabled()
    {
        // Arrange - Using default SecurityOptions to verify security-by-default
        var options = Options.Create(new SecurityOptions());
        var validator = new HtmlSanitizerValidator(options, NullLogger<HtmlSanitizerValidator>.Instance);
        var maliciousContent = "<button onclick='alert(1)'>Click</button>";

        // Act
        var result = await validator.ValidateAsync(maliciousContent, "test-key");

        // Assert
        Assert.False(result.IsValid);
        Assert.Equal(ValidationSeverity.Critical, result.Severity);
        Assert.Contains("Critical XSS pattern detected", result.ErrorMessage);
    }

    [Fact]
    public async Task ValidateAsync_OptOutConfiguration_ValidationDisabled()
    {
        // Arrange - Explicitly opt-out of HTML validation
        var options = Options.Create(new SecurityOptions
        {
            EnableHtmlValidation = false
        });
        var validator = new HtmlSanitizerValidator(options, NullLogger<HtmlSanitizerValidator>.Instance);
        var maliciousContent = "<button onclick='alert(1)'>Click</button>";

        // Act
        var result = await validator.ValidateAsync(maliciousContent, "test-key");

        // Assert
        Assert.True(result.IsValid);
    }

    [Theory]
    [InlineData("<img src=x onerror='alert(1)'>")]
    [InlineData("<div onload='malicious()'>")]
    [InlineData("<a href='javascript:alert(1)'>")]
    public async Task ValidateAsync_CommonXssPatterns_ReturnsFailure(string maliciousContent)
    {
        // Arrange
        var options = Options.Create(new SecurityOptions { EnableHtmlValidation = true });
        var validator = new HtmlSanitizerValidator(options, NullLogger<HtmlSanitizerValidator>.Instance);

        // Act
        var result = await validator.ValidateAsync(maliciousContent, "test-key");

        // Assert
        Assert.False(result.IsValid);
        Assert.Equal(ValidationSeverity.Critical, result.Severity);
    }

    [Fact]
    public async Task ValidateAsync_AllRequestsValidated_NoSamplingBypass()
    {
        // Arrange - SECURITY FIX: Verify sampling is removed and all requests are validated
        var options = Options.Create(new SecurityOptions
        {
            EnableHtmlValidation = true
        });
        var validator = new HtmlSanitizerValidator(options, NullLogger<HtmlSanitizerValidator>.Instance);
        var maliciousContent = "<button onclick='alert(1)'>Click</button>";

        // Act & Assert - ALL requests should be validated and detect malicious content
        // This verifies that Issue 4.2 is fixed: no 90% bypass vulnerability
        for (int i = 0; i < 100; i++)
        {
            var result = await validator.ValidateAsync(maliciousContent, $"test-key-{i}");
            Assert.False(result.IsValid, $"Request {i} MUST be validated and detect malicious content - no sampling bypass allowed");
            Assert.Equal(ValidationSeverity.Critical, result.Severity);
        }
    }

    [Fact]
    public async Task ValidateAsync_ConsecutiveMaliciousRequests_AllDetected()
    {
        // Arrange
        var options = Options.Create(new SecurityOptions { EnableHtmlValidation = true });
        var validator = new HtmlSanitizerValidator(options, NullLogger<HtmlSanitizerValidator>.Instance);

        // Test multiple XSS patterns to ensure comprehensive validation
        var xssPatterns = new[]
        {
            "<button onclick='alert(1)'>Click</button>",
            "<img src=x onerror='alert(1)'>",
            "<a href='javascript:alert(1)'>Link</a>",
            "<div onload='malicious()'>",
            "<script>alert('XSS')</script>"
        };

        // Act & Assert - Every single request must detect the XSS pattern
        foreach (var pattern in xssPatterns)
        {
            for (int i = 0; i < 20; i++)
            {
                var result = await validator.ValidateAsync(pattern, $"test-key-{pattern}-{i}");
                Assert.False(result.IsValid, $"Pattern '{pattern}' at iteration {i} must be detected");
                Assert.Equal(ValidationSeverity.Critical, result.Severity);
            }
        }
    }

    [Fact]
    public async Task ValidateAsync_SafeContentMultipleRequests_AllSucceed()
    {
        // Arrange
        var options = Options.Create(new SecurityOptions { EnableHtmlValidation = true });
        var validator = new HtmlSanitizerValidator(options, NullLogger<HtmlSanitizerValidator>.Instance);
        var safeContent = "<div><p>Safe content</p></div>";

        // Act & Assert - All safe requests should succeed
        for (int i = 0; i < 50; i++)
        {
            var result = await validator.ValidateAsync(safeContent, $"test-key-{i}");
            Assert.True(result.IsValid, $"Safe content request {i} should succeed");
        }
    }

    [Fact]
    public async Task ValidateAsync_DeprecatedSamplingProperty_HasNoEffect()
    {
        // Arrange - Even if sampling rate is set (deprecated), it should be ignored
        #pragma warning disable CS0618 // Type or member is obsolete
        var options = Options.Create(new SecurityOptions
        {
            EnableHtmlValidation = true,
            HtmlValidationSamplingRate = 100 // This should be ignored
        });
        #pragma warning restore CS0618
        var validator = new HtmlSanitizerValidator(options, NullLogger<HtmlSanitizerValidator>.Instance);
        var maliciousContent = "<button onclick='alert(1)'>Click</button>";

        // Act & Assert - ALL requests should still be validated despite sampling rate setting
        for (int i = 0; i < 10; i++)
        {
            var result = await validator.ValidateAsync(maliciousContent, $"test-key-{i}");
            Assert.False(result.IsValid, $"Request {i} must be validated - sampling should be ignored");
            Assert.Equal(ValidationSeverity.Critical, result.Severity);
        }
    }
}
