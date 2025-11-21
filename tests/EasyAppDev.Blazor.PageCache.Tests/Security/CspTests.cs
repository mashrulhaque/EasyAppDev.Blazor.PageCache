using Xunit;
using FluentAssertions;
using EasyAppDev.Blazor.PageCache.Security;

namespace EasyAppDev.Blazor.PageCache.Tests.Security;

/// <summary>
/// Tests for Content Security Policy (CSP) functionality.
/// </summary>
public class CspTests
{
    #region CspBuilder Tests

    [Fact]
    public void Build_WithSingleDirective_ReturnsValidPolicy()
    {
        // Arrange
        var builder = new CspBuilder()
            .WithDefaultSrc("'self'");

        // Act
        var policy = builder.Build();

        // Assert
        policy.Should().Be("default-src 'self'; ");
    }

    [Fact]
    public void Build_WithMultipleDirectives_ReturnsValidPolicy()
    {
        // Arrange
        var builder = new CspBuilder()
            .WithDefaultSrc("'self'")
            .WithScriptSrc("'self'", "https://trusted.com")
            .WithStyleSrc("'self'", "'unsafe-inline'");

        // Act
        var policy = builder.Build();

        // Assert
        policy.Should().Contain("default-src 'self';");
        policy.Should().Contain("script-src 'self' https://trusted.com;");
        policy.Should().Contain("style-src 'self' 'unsafe-inline';");
    }

    [Fact]
    public void Build_WithAllStandardDirectives_ReturnsValidPolicy()
    {
        // Arrange
        var builder = new CspBuilder()
            .WithDefaultSrc("'self'")
            .WithScriptSrc("'self'")
            .WithStyleSrc("'self'")
            .WithImgSrc("'self'", "data:")
            .WithConnectSrc("'self'")
            .WithFontSrc("'self'")
            .WithObjectSrc("'none'")
            .WithMediaSrc("'self'")
            .WithFrameSrc("'self'")
            .WithFrameAncestors("'none'")
            .WithBaseUri("'self'")
            .WithFormAction("'self'");

        // Act
        var policy = builder.Build();

        // Assert
        policy.Should().Contain("default-src 'self';");
        policy.Should().Contain("script-src 'self';");
        policy.Should().Contain("style-src 'self';");
        policy.Should().Contain("img-src 'self' data:;");
        policy.Should().Contain("connect-src 'self';");
        policy.Should().Contain("font-src 'self';");
        policy.Should().Contain("object-src 'none';");
        policy.Should().Contain("media-src 'self';");
        policy.Should().Contain("frame-src 'self';");
        policy.Should().Contain("frame-ancestors 'none';");
        policy.Should().Contain("base-uri 'self';");
        policy.Should().Contain("form-action 'self';");
    }

    [Fact]
    public void Build_WithUpgradeInsecureRequests_ReturnsValidPolicy()
    {
        // Arrange
        var builder = new CspBuilder()
            .WithDefaultSrc("'self'")
            .WithUpgradeInsecureRequests();

        // Act
        var policy = builder.Build();

        // Assert
        policy.Should().Contain("default-src 'self';");
        policy.Should().Contain("upgrade-insecure-requests;");
    }

    [Fact]
    public void Build_WithBlockAllMixedContent_ReturnsValidPolicy()
    {
        // Arrange
        var builder = new CspBuilder()
            .WithDefaultSrc("'self'")
            .WithBlockAllMixedContent();

        // Act
        var policy = builder.Build();

        // Assert
        policy.Should().Contain("default-src 'self';");
        policy.Should().Contain("block-all-mixed-content;");
    }

    [Fact]
    public void Build_WithReportUri_ReturnsValidPolicy()
    {
        // Arrange
        var builder = new CspBuilder()
            .WithDefaultSrc("'self'")
            .WithReportUri("https://example.com/csp-report");

        // Act
        var policy = builder.Build();

        // Assert
        policy.Should().Contain("default-src 'self';");
        policy.Should().Contain("report-uri https://example.com/csp-report;");
    }

    [Fact]
    public void Build_WithCustomDirective_ReturnsValidPolicy()
    {
        // Arrange
        var builder = new CspBuilder()
            .WithDefaultSrc("'self'")
            .WithCustomDirective("worker-src", "'self'", "blob:");

        // Act
        var policy = builder.Build();

        // Assert
        policy.Should().Contain("default-src 'self';");
        policy.Should().Contain("worker-src 'self' blob:;");
    }

    [Fact]
    public void Build_WithEmptyBuilder_ThrowsInvalidOperationException()
    {
        // Arrange
        var builder = new CspBuilder();

        // Act
        Action act = () => builder.Build();

        // Assert
        act.Should().Throw<InvalidOperationException>()
            .WithMessage("*empty CSP policy*");
    }

    [Fact]
    public void Build_WithDuplicateDirective_LastValueWins()
    {
        // Arrange
        var builder = new CspBuilder()
            .WithDefaultSrc("'self'")
            .WithDefaultSrc("'none'");

        // Act
        var policy = builder.Build();

        // Assert
        policy.Should().Contain("default-src 'none';");
        policy.Should().NotContain("default-src 'self';");
    }

    [Fact]
    public void WithReportUri_WithNullUri_ThrowsArgumentException()
    {
        // Arrange
        var builder = new CspBuilder();

        // Act
        Action act = () => builder.WithReportUri(null!);

        // Assert
        act.Should().Throw<ArgumentException>()
            .WithMessage("*Report URI cannot be null*");
    }

    [Fact]
    public void WithReportUri_WithEmptyUri_ThrowsArgumentException()
    {
        // Arrange
        var builder = new CspBuilder();

        // Act
        Action act = () => builder.WithReportUri("");

        // Assert
        act.Should().Throw<ArgumentException>()
            .WithMessage("*Report URI cannot be null*");
    }

    [Fact]
    public void WithCustomDirective_WithInvalidDirectiveName_ThrowsArgumentException()
    {
        // Arrange
        var builder = new CspBuilder();

        // Act
        Action act = () => builder.WithCustomDirective("INVALID-DIRECTIVE", "'self'");

        // Assert
        act.Should().Throw<ArgumentException>()
            .WithMessage("*must contain only lowercase letters*");
    }

    [Fact]
    public void WithCustomDirective_WithSemicolonInDirectiveName_ThrowsArgumentException()
    {
        // Arrange
        var builder = new CspBuilder();

        // Act
        Action act = () => builder.WithCustomDirective("test;src", "'self'");

        // Assert
        act.Should().Throw<ArgumentException>();
    }

    [Fact]
    public void AddDirective_WithNullSource_ThrowsArgumentException()
    {
        // Arrange
        var builder = new CspBuilder();

        // Act
        Action act = () => builder.WithScriptSrc(null!);

        // Assert
        act.Should().Throw<ArgumentException>()
            .WithMessage("*cannot be null*");
    }

    [Fact]
    public void AddDirective_WithEmptySource_ThrowsArgumentException()
    {
        // Arrange
        var builder = new CspBuilder();

        // Act
        Action act = () => builder.WithScriptSrc("");

        // Assert
        act.Should().Throw<ArgumentException>()
            .WithMessage("*cannot be null or whitespace*");
    }

    [Fact]
    public void AddDirective_WithSemicolonInSource_ThrowsArgumentException()
    {
        // Arrange
        var builder = new CspBuilder();

        // Act
        Action act = () => builder.WithScriptSrc("'self'; malicious");

        // Assert
        act.Should().Throw<ArgumentException>()
            .WithMessage("*cannot contain semicolons*");
    }

    [Fact]
    public void AddDirective_WithNewlineInSource_ThrowsArgumentException()
    {
        // Arrange
        var builder = new CspBuilder();

        // Act
        Action act = () => builder.WithScriptSrc("'self'\nmalicious");

        // Assert
        act.Should().Throw<ArgumentException>()
            .WithMessage("*cannot contain semicolons or newlines*");
    }

    [Fact]
    public void AddDirective_WithUnquotedKeyword_ThrowsArgumentException()
    {
        // Arrange
        var builder = new CspBuilder();

        // Act
        Action act = () => builder.WithScriptSrc("self");

        // Assert
        act.Should().Throw<ArgumentException>()
            .WithMessage("*must be single-quoted*");
    }

    [Fact]
    public void AddDirective_WithUnquotedNone_ThrowsArgumentException()
    {
        // Arrange
        var builder = new CspBuilder();

        // Act
        Action act = () => builder.WithObjectSrc("none");

        // Assert
        act.Should().Throw<ArgumentException>()
            .WithMessage("*must be single-quoted*");
    }

    [Fact]
    public void AddDirective_WithUnquotedUnsafeInline_ThrowsArgumentException()
    {
        // Arrange
        var builder = new CspBuilder();

        // Act
        Action act = () => builder.WithScriptSrc("unsafe-inline");

        // Assert
        act.Should().Throw<ArgumentException>()
            .WithMessage("*must be single-quoted*");
    }

    [Fact]
    public void AddDirective_WithUnquotedNonce_ThrowsArgumentException()
    {
        // Arrange
        var builder = new CspBuilder();

        // Act
        Action act = () => builder.WithScriptSrc("nonce-abc123");

        // Assert
        act.Should().Throw<ArgumentException>()
            .WithMessage("*must be single-quoted*");
    }

    [Fact]
    public void AddDirective_WithUnquotedHash_ThrowsArgumentException()
    {
        // Arrange
        var builder = new CspBuilder();

        // Act
        Action act = () => builder.WithScriptSrc("sha256-abc123");

        // Assert
        act.Should().Throw<ArgumentException>()
            .WithMessage("*must be single-quoted*");
    }

    [Fact]
    public void Build_WithExcessivelyLongPolicy_ThrowsInvalidOperationException()
    {
        // Arrange
        var builder = new CspBuilder();
        var longSource = new string('a', 8000);

        // Act
        Action act = () => builder.WithScriptSrc(longSource).Build();

        // Assert
        act.Should().Throw<InvalidOperationException>()
            .WithMessage("*too long*");
    }

    #endregion

    #region Nonce Generation Tests

    [Fact]
    public void GenerateNonce_ForScriptSrc_ReturnsValidNonce()
    {
        // Arrange
        var builder = new CspBuilder().WithDefaultSrc("'self'");

        // Act
        var nonce = builder.GenerateNonce("script-src");

        // Assert
        nonce.Should().NotBeNullOrWhiteSpace();
        nonce.Should().HaveLength(24); // 16 bytes base64 encoded = 24 chars

        var policy = builder.Build();
        policy.Should().Contain($"script-src 'nonce-{nonce}';");
    }

    [Fact]
    public void GenerateNonce_ForStyleSrc_ReturnsValidNonce()
    {
        // Arrange
        var builder = new CspBuilder().WithDefaultSrc("'self'");

        // Act
        var nonce = builder.GenerateNonce("style-src");

        // Assert
        nonce.Should().NotBeNullOrWhiteSpace();

        var policy = builder.Build();
        policy.Should().Contain($"style-src 'nonce-{nonce}';");
    }

    [Fact]
    public void GenerateNonce_Multiple_ReturnsUniqueNonces()
    {
        // Arrange
        var builder = new CspBuilder().WithDefaultSrc("'self'");

        // Act
        var nonce1 = builder.GenerateNonce("script-src");
        var nonce2 = builder.GenerateNonce("style-src");

        // Assert
        nonce1.Should().NotBe(nonce2);
    }

    [Fact]
    public void GenerateNonce_WithExistingDirective_AddsNonceToExisting()
    {
        // Arrange
        var builder = new CspBuilder()
            .WithDefaultSrc("'self'")
            .WithScriptSrc("'self'", "https://trusted.com");

        // Act
        var nonce = builder.GenerateNonce("script-src");
        var policy = builder.Build();

        // Assert
        policy.Should().Contain($"script-src 'self' https://trusted.com 'nonce-{nonce}';");
    }

    [Fact]
    public void GenerateNonce_WithNullDirective_ThrowsArgumentException()
    {
        // Arrange
        var builder = new CspBuilder();

        // Act
        Action act = () => builder.GenerateNonce(null!);

        // Assert
        act.Should().Throw<ArgumentException>();
    }

    [Fact]
    public void GetNonces_AfterGeneratingNonces_ReturnsAllNonces()
    {
        // Arrange
        var builder = new CspBuilder().WithDefaultSrc("'self'");
        var nonce1 = builder.GenerateNonce("script-src");
        var nonce2 = builder.GenerateNonce("style-src");

        // Act
        var nonces = builder.GetNonces();

        // Assert
        nonces.Should().HaveCount(2);
        nonces.Should().Contain(nonce1);
        nonces.Should().Contain(nonce2);
    }

    [Fact]
    public void GetNonces_WithoutGeneratingNonces_ReturnsEmptyList()
    {
        // Arrange
        var builder = new CspBuilder();

        // Act
        var nonces = builder.GetNonces();

        // Assert
        nonces.Should().BeEmpty();
    }

    #endregion

    #region Preset Policies Tests

    [Fact]
    public void CreateStrict_WithoutUnsafeInline_ReturnsStrictPolicy()
    {
        // Arrange & Act
        var builder = CspBuilder.CreateStrict(allowUnsafeInline: false);
        var policy = builder.Build();

        // Assert
        policy.Should().Contain("default-src 'self';");
        policy.Should().Contain("script-src 'self';");
        policy.Should().Contain("style-src 'self';");
        policy.Should().Contain("img-src 'self' data: https:;");
        policy.Should().Contain("font-src 'self';");
        policy.Should().Contain("connect-src 'self';");
        policy.Should().Contain("object-src 'none';");
        policy.Should().Contain("base-uri 'self';");
        policy.Should().Contain("form-action 'self';");
        policy.Should().Contain("frame-ancestors 'none';");
        policy.Should().Contain("upgrade-insecure-requests;");

        policy.Should().NotContain("'unsafe-inline'");
        policy.Should().NotContain("'unsafe-eval'");
    }

    [Fact]
    public void CreateStrict_WithUnsafeInline_IncludesUnsafeInline()
    {
        // Arrange & Act
        var builder = CspBuilder.CreateStrict(allowUnsafeInline: true);
        var policy = builder.Build();

        // Assert
        policy.Should().Contain("script-src 'self' 'unsafe-inline';");
        policy.Should().Contain("style-src 'self' 'unsafe-inline';");
    }

    [Fact]
    public void CreateRelaxed_ReturnsRelaxedPolicy()
    {
        // Arrange & Act
        var builder = CspBuilder.CreateRelaxed();
        var policy = builder.Build();

        // Assert
        policy.Should().Contain("default-src 'self';");
        policy.Should().Contain("script-src 'self' 'unsafe-inline' 'unsafe-eval';");
        policy.Should().Contain("style-src 'self' 'unsafe-inline';");
        policy.Should().Contain("img-src 'self' data: https:;");
        policy.Should().Contain("font-src 'self' data:;");
        policy.Should().Contain("connect-src 'self';");
    }

    [Fact]
    public void CreateStrict_CanBeCustomized()
    {
        // Arrange & Act
        var builder = CspBuilder.CreateStrict()
            .WithScriptSrc("'self'", "https://cdn.example.com");

        var policy = builder.Build();

        // Assert
        policy.Should().Contain("script-src 'self' https://cdn.example.com;");
    }

    [Fact]
    public void CreateRelaxed_CanBeCustomized()
    {
        // Arrange & Act
        var builder = CspBuilder.CreateRelaxed()
            .WithFrameAncestors("'none'");

        var policy = builder.Build();

        // Assert
        policy.Should().Contain("frame-ancestors 'none';");
    }

    #endregion

    #region Fluent API Tests

    [Fact]
    public void FluentAPI_ChainMultipleCalls_BuildsCorrectPolicy()
    {
        // Arrange & Act
        var policy = new CspBuilder()
            .WithDefaultSrc("'self'")
            .WithScriptSrc("'self'", "https://scripts.example.com")
            .WithStyleSrc("'self'", "https://styles.example.com")
            .WithImgSrc("'self'", "data:", "https:")
            .WithConnectSrc("'self'", "wss://websocket.example.com")
            .WithFontSrc("'self'", "https://fonts.example.com")
            .WithObjectSrc("'none'")
            .WithFrameAncestors("'none'")
            .WithBaseUri("'self'")
            .WithFormAction("'self'")
            .WithUpgradeInsecureRequests()
            .Build();

        // Assert
        policy.Should().Contain("default-src 'self';");
        policy.Should().Contain("script-src 'self' https://scripts.example.com;");
        policy.Should().Contain("style-src 'self' https://styles.example.com;");
        policy.Should().Contain("img-src 'self' data: https:;");
        policy.Should().Contain("connect-src 'self' wss://websocket.example.com;");
        policy.Should().Contain("font-src 'self' https://fonts.example.com;");
        policy.Should().Contain("object-src 'none';");
        policy.Should().Contain("frame-ancestors 'none';");
        policy.Should().Contain("base-uri 'self';");
        policy.Should().Contain("form-action 'self';");
        policy.Should().Contain("upgrade-insecure-requests;");
    }

    #endregion

    #region Real-World Scenario Tests

    [Fact]
    public void RealWorld_BlazorWebAssembly_BuildsAppropriatePolicy()
    {
        // Arrange & Act
        var policy = new CspBuilder()
            .WithDefaultSrc("'self'")
            .WithScriptSrc("'self'", "'unsafe-eval'") // WebAssembly requires unsafe-eval
            .WithStyleSrc("'self'", "'unsafe-inline'") // Blazor uses inline styles
            .WithImgSrc("'self'", "data:", "https:")
            .WithConnectSrc("'self'", "https://api.example.com")
            .WithFontSrc("'self'")
            .WithObjectSrc("'none'")
            .WithFrameAncestors("'none'")
            .Build();

        // Assert
        policy.Should().Contain("script-src 'self' 'unsafe-eval';");
        policy.Should().Contain("style-src 'self' 'unsafe-inline';");
    }

    [Fact]
    public void RealWorld_BlazorServer_BuildsAppropriatePolicy()
    {
        // Arrange & Act
        var policy = new CspBuilder()
            .WithDefaultSrc("'self'")
            .WithScriptSrc("'self'", "'unsafe-inline'") // SignalR may need this
            .WithStyleSrc("'self'", "'unsafe-inline'")
            .WithImgSrc("'self'", "data:")
            .WithConnectSrc("'self'", "wss:") // SignalR WebSocket
            .WithFontSrc("'self'")
            .WithObjectSrc("'none'")
            .WithFrameAncestors("'none'")
            .Build();

        // Assert
        policy.Should().Contain("connect-src 'self' wss:;");
    }

    [Fact]
    public void RealWorld_WithReporting_IncludesReportUri()
    {
        // Arrange & Act
        var policy = new CspBuilder()
            .WithDefaultSrc("'self'")
            .WithScriptSrc("'self'")
            .WithReportUri("https://example.com/csp-violations")
            .Build();

        // Assert
        policy.Should().Contain("report-uri https://example.com/csp-violations;");
    }

    [Fact]
    public void RealWorld_WithNonces_SupportsSecureInlineScripts()
    {
        // Arrange
        var builder = new CspBuilder()
            .WithDefaultSrc("'self'")
            .WithStyleSrc("'self'");

        var scriptNonce = builder.GenerateNonce("script-src");
        var styleNonce = builder.GenerateNonce("style-src");

        // Act
        var policy = builder.Build();

        // Assert
        policy.Should().Contain($"script-src 'nonce-{scriptNonce}';");
        policy.Should().Contain($"style-src 'self' 'nonce-{styleNonce}';");
    }

    #endregion
}
