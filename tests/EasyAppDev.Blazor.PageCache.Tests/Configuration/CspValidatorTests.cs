using FluentAssertions;
using Microsoft.Extensions.Options;
using EasyAppDev.Blazor.PageCache.Configuration;

namespace EasyAppDev.Blazor.PageCache.Tests.Configuration;

/// <summary>
/// Tests for CSP (Content Security Policy) validation in PageCacheOptionsValidator.
/// </summary>
public class CspValidatorTests
{
    private readonly PageCacheOptionsValidator _validator = new();

    [Fact]
    public void Validate_WithCspDisabled_ReturnsSuccess()
    {
        // Arrange
        var options = new PageCacheOptions
        {
            Security = new SecurityOptions
            {
                EnableContentSecurityPolicy = false,
                ContentSecurityPolicy = null
            }
        };

        // Act
        var result = _validator.Validate(null, options);

        // Assert
        result.Succeeded.Should().BeTrue();
    }

    [Fact]
    public void Validate_WithCspEnabledButNullPolicy_ReturnsFail()
    {
        // Arrange
        var options = new PageCacheOptions
        {
            Security = new SecurityOptions
            {
                EnableContentSecurityPolicy = true,
                ContentSecurityPolicy = null
            }
        };

        // Act
        var result = _validator.Validate(null, options);

        // Assert
        result.Failed.Should().BeTrue();
        result.Failures.Should().Contain(f => f.Contains("ContentSecurityPolicy") && f.Contains("cannot be null"));
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("\t")]
    public void Validate_WithCspEnabledButEmptyPolicy_ReturnsFail(string policy)
    {
        // Arrange
        var options = new PageCacheOptions
        {
            Security = new SecurityOptions
            {
                EnableContentSecurityPolicy = true,
                ContentSecurityPolicy = policy
            }
        };

        // Act
        var result = _validator.Validate(null, options);

        // Assert
        result.Failed.Should().BeTrue();
        result.Failures.Should().Contain(f => f.Contains("ContentSecurityPolicy") && f.Contains("cannot be null"));
    }

    [Fact]
    public void Validate_WithValidCspPolicy_ReturnsSuccess()
    {
        // Arrange
        var options = new PageCacheOptions
        {
            Security = new SecurityOptions
            {
                EnableContentSecurityPolicy = true,
                ContentSecurityPolicy = "default-src 'self'; script-src 'self';"
            }
        };

        // Act
        var result = _validator.Validate(null, options);

        // Assert
        result.Succeeded.Should().BeTrue();
    }

    [Fact]
    public void Validate_WithCspPolicyExceedingMaxLength_ReturnsFail()
    {
        // Arrange
        var longPolicy = new string('a', 5000); // 5000 chars, exceeds 4096 limit
        var options = new PageCacheOptions
        {
            Security = new SecurityOptions
            {
                EnableContentSecurityPolicy = true,
                ContentSecurityPolicy = longPolicy
            }
        };

        // Act
        var result = _validator.Validate(null, options);

        // Assert
        result.Failed.Should().BeTrue();
        result.Failures.Should().Contain(f => f.Contains("exceeds 4096 characters"));
    }

    [Theory]
    [InlineData(";")]
    [InlineData(";;;")]
    [InlineData("   ;   ")]
    public void Validate_WithCspPolicyWithoutDirectives_ReturnsFail(string policy)
    {
        // Arrange
        var options = new PageCacheOptions
        {
            Security = new SecurityOptions
            {
                EnableContentSecurityPolicy = true,
                ContentSecurityPolicy = policy
            }
        };

        // Act
        var result = _validator.Validate(null, options);

        // Assert
        result.Failed.Should().BeTrue();
        result.Failures.Should().Contain(f => f.Contains("does not contain any valid directives"));
    }

    [Fact]
    public void Validate_WithCspPolicyNotEndingWithSemicolon_ReturnsWarning()
    {
        // Arrange
        var options = new PageCacheOptions
        {
            Security = new SecurityOptions
            {
                EnableContentSecurityPolicy = true,
                ContentSecurityPolicy = "default-src 'self'"
            }
        };

        // Act
        var result = _validator.Validate(null, options);

        // Assert
        result.Failed.Should().BeTrue();
        result.Failures.Should().Contain(f => f.Contains("WARNING") && f.Contains("should end with a semicolon"));
    }

    [Fact]
    public void Validate_WithCspUsingBothUnsafeInlineAndUnsafeEval_ReturnsWarning()
    {
        // Arrange
        var options = new PageCacheOptions
        {
            Security = new SecurityOptions
            {
                EnableContentSecurityPolicy = true,
                ContentSecurityPolicy = "script-src 'self' 'unsafe-inline' 'unsafe-eval';"
            }
        };

        // Act
        var result = _validator.Validate(null, options);

        // Assert
        result.Failed.Should().BeTrue();
        result.Failures.Should().Contain(f => f.Contains("WARNING") && f.Contains("unsafe-inline") && f.Contains("unsafe-eval"));
    }

    [Fact]
    public void Validate_WithCspUsingUnsafeEval_ReturnsWarning()
    {
        // Arrange
        var options = new PageCacheOptions
        {
            Security = new SecurityOptions
            {
                EnableContentSecurityPolicy = true,
                ContentSecurityPolicy = "script-src 'self' 'unsafe-eval';"
            }
        };

        // Act
        var result = _validator.Validate(null, options);

        // Assert
        result.Failed.Should().BeTrue();
        result.Failures.Should().Contain(f => f.Contains("WARNING") && f.Contains("unsafe-eval"));
    }

    [Fact]
    public void Validate_WithCspUsingWildcardInScriptSrc_ReturnsWarning()
    {
        // Arrange
        var options = new PageCacheOptions
        {
            Security = new SecurityOptions
            {
                EnableContentSecurityPolicy = true,
                ContentSecurityPolicy = "script-src *;"
            }
        };

        // Act
        var result = _validator.Validate(null, options);

        // Assert
        result.Failed.Should().BeTrue();
        result.Failures.Should().Contain(f => f.Contains("WARNING") && f.Contains("'*' wildcard"));
    }

    [Fact]
    public void Validate_WithCspUsingWildcardInDefaultSrc_ReturnsWarning()
    {
        // Arrange
        var options = new PageCacheOptions
        {
            Security = new SecurityOptions
            {
                EnableContentSecurityPolicy = true,
                ContentSecurityPolicy = "default-src *;"
            }
        };

        // Act
        var result = _validator.Validate(null, options);

        // Assert
        result.Failed.Should().BeTrue();
        result.Failures.Should().Contain(f => f.Contains("WARNING") && f.Contains("'*' wildcard"));
    }

    [Fact]
    public void Validate_WithCspReportOnlyMode_ReturnsWarning()
    {
        // Arrange
        var options = new PageCacheOptions
        {
            Security = new SecurityOptions
            {
                EnableContentSecurityPolicy = true,
                ContentSecurityPolicy = "default-src 'self';",
                CspReportOnlyMode = true
            }
        };

        // Act
        var result = _validator.Validate(null, options);

        // Assert
        result.Failed.Should().BeTrue();
        result.Failures.Should().Contain(f => f.Contains("WARNING") && f.Contains("CspReportOnlyMode"));
    }

    [Fact]
    public void Validate_WithCspMissingDefaultSrc_ReturnsInfo()
    {
        // Arrange
        var options = new PageCacheOptions
        {
            Security = new SecurityOptions
            {
                EnableContentSecurityPolicy = true,
                ContentSecurityPolicy = "script-src 'self';"
            }
        };

        // Act
        var result = _validator.Validate(null, options);

        // Assert
        result.Failed.Should().BeTrue();
        result.Failures.Should().Contain(f => f.Contains("INFO") && f.Contains("default-src"));
    }

    [Fact]
    public void Validate_WithCspContainingReportUri_ReturnsInfo()
    {
        // Arrange
        var options = new PageCacheOptions
        {
            Security = new SecurityOptions
            {
                EnableContentSecurityPolicy = true,
                ContentSecurityPolicy = "default-src 'self'; report-uri /csp-report;"
            }
        };

        // Act
        var result = _validator.Validate(null, options);

        // Assert
        result.Failed.Should().BeTrue();
        result.Failures.Should().Contain(f => f.Contains("INFO") && f.Contains("reporting"));
    }

    [Fact]
    public void Validate_WithCspContainingUnknownDirective_ReturnsWarning()
    {
        // Arrange
        var options = new PageCacheOptions
        {
            Security = new SecurityOptions
            {
                EnableContentSecurityPolicy = true,
                ContentSecurityPolicy = "default-src 'self'; unknown-directive 'self';"
            }
        };

        // Act
        var result = _validator.Validate(null, options);

        // Assert
        result.Failed.Should().BeTrue();
        result.Failures.Should().Contain(f => f.Contains("WARNING") && f.Contains("unrecognized directives"));
    }

    [Fact]
    public void Validate_WithComplexValidCspPolicy_ReturnsSuccess()
    {
        // Arrange
        var options = new PageCacheOptions
        {
            Security = new SecurityOptions
            {
                EnableContentSecurityPolicy = true,
                ContentSecurityPolicy = "default-src 'self'; script-src 'self' https://cdn.example.com; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none';"
            }
        };

        // Act
        var result = _validator.Validate(null, options);

        // Assert
        result.Succeeded.Should().BeTrue();
    }

    [Fact]
    public void Validate_WithMultipleCspIssues_ReturnsMultipleFailures()
    {
        // Arrange
        var options = new PageCacheOptions
        {
            Security = new SecurityOptions
            {
                EnableContentSecurityPolicy = true,
                ContentSecurityPolicy = "script-src 'unsafe-inline' 'unsafe-eval'",
                CspReportOnlyMode = true
            }
        };

        // Act
        var result = _validator.Validate(null, options);

        // Assert
        result.Failed.Should().BeTrue();
        result.Failures.Should().HaveCountGreaterThanOrEqualTo(3); // Missing semicolon, unsafe combo, report-only mode
    }
}
