using System.Diagnostics;
using Xunit;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using EasyAppDev.Blazor.PageCache.Configuration;
using EasyAppDev.Blazor.PageCache.Validation;
using EasyAppDev.Blazor.PageCache.Abstractions;

namespace EasyAppDev.Blazor.PageCache.Tests.Validation;

/// <summary>
/// Comprehensive test suite for XSS pattern detection.
/// Tests cover OWASP XSS cheat sheet vectors, browser-specific attacks, and performance requirements.
/// </summary>
[Trait("Category", TestCategories.Unit)]
[Trait("Category", "Security")]
public sealed class XssDetectionTests
{
    private readonly HtmlSanitizerValidator _validator;

    public XssDetectionTests()
    {
        var options = Options.Create(new SecurityOptions { EnableHtmlValidation = true });
        _validator = new HtmlSanitizerValidator(options, NullLogger<HtmlSanitizerValidator>.Instance);
    }

    #region Critical Pattern Tests

    [Theory]
    [InlineData("<button onclick='alert(1)'>Click</button>", "onclick event handler")]
    [InlineData("<div onload='malicious()'>Content</div>", "onload event handler")]
    [InlineData("<img onerror='alert(1)' src=x>", "onerror event handler")]
    [InlineData("<body onpageshow='alert(1)'>", "onpageshow event handler")]
    [InlineData("<input onfocus='alert(1)' autofocus>", "onfocus event handler")]
    [InlineData("<marquee onstart='alert(1)'>", "onstart event handler")]
    [InlineData("<video onloadstart='alert(1)'>", "onloadstart event handler")]
    public async Task InlineEventHandlers_ShouldBeDetected(string maliciousHtml, string description)
    {
        // Act
        var result = await _validator.ValidateAsync(maliciousHtml, "test-key");

        // Assert
        Assert.False(result.IsValid, $"Failed to detect: {description}");
        Assert.Equal(ValidationSeverity.Critical, result.Severity);
        Assert.NotNull(result.ErrorDetails);
        Assert.Contains("InlineEventHandlers", result.ErrorDetails["Pattern"]);
    }

    [Theory]
    [InlineData("<a href='javascript:alert(1)'>Link</a>", "basic javascript: protocol")]
    [InlineData("<a href='  javascript:alert(1)'>Link</a>", "javascript: with leading spaces")]
    [InlineData("<a href='JAVASCRIPT:alert(1)'>Link</a>", "uppercase JAVASCRIPT:")]
    [InlineData("<a href='JaVaScRiPt:alert(1)'>Link</a>", "mixed case javascript:")]
    [InlineData("<form action='javascript:alert(1)'>", "javascript: in form action")]
    public async Task JavaScriptProtocol_ShouldBeDetected(string maliciousHtml, string description)
    {
        // Act
        var result = await _validator.ValidateAsync(maliciousHtml, "test-key");

        // Assert
        Assert.False(result.IsValid, $"Failed to detect: {description}");
        Assert.Equal(ValidationSeverity.Critical, result.Severity);
    }

    [Theory]
    [InlineData("<a href='vbscript:msgbox(1)'>Link</a>", "basic vbscript: protocol")]
    [InlineData("<a href='  vbscript:msgbox(1)'>Link</a>", "vbscript: with spaces")]
    [InlineData("<a href='VBSCRIPT:msgbox(1)'>Link</a>", "uppercase VBSCRIPT:")]
    public async Task VbScriptProtocol_ShouldBeDetected(string maliciousHtml, string description)
    {
        // Act
        var result = await _validator.ValidateAsync(maliciousHtml, "test-key");

        // Assert
        Assert.False(result.IsValid, $"Failed to detect: {description}");
        Assert.Equal(ValidationSeverity.Critical, result.Severity);
    }

    [Theory]
    [InlineData("<script>eval('alert(1)')</script>", "script with eval")]
    [InlineData("<script>document.cookie</script>", "script accessing document.cookie")]
    [InlineData("<script>window.location='http://evil.com'</script>", "script changing window.location")]
    [InlineData("<script>localStorage.setItem('x','y')</script>", "script using localStorage")]
    [InlineData("<script>sessionStorage.getItem('token')</script>", "script using sessionStorage")]
    public async Task DangerousScriptContent_ShouldBeDetected(string maliciousHtml, string description)
    {
        // Act
        var result = await _validator.ValidateAsync(maliciousHtml, "test-key");

        // Assert
        Assert.False(result.IsValid, $"Failed to detect: {description}");
        Assert.Equal(ValidationSeverity.Critical, result.Severity);
    }

    [Theory]
    [InlineData("<script>eval(atob('YWxlcnQoMSk='))</script>", "base64 encoded alert")]
    [InlineData("<script>Function(atob('cmV0dXJuIDEK'))()</script>", "base64 with Function constructor")]
    public async Task Base64EncodedScript_ShouldBeDetected(string maliciousHtml, string description)
    {
        // Act
        var result = await _validator.ValidateAsync(maliciousHtml, "test-key");

        // Assert
        Assert.False(result.IsValid, $"Failed to detect: {description}");
        Assert.Equal(ValidationSeverity.Critical, result.Severity);
    }

    [Theory]
    [InlineData("<style>{width: expression(alert(1));}</style>", "CSS expression")]
    [InlineData("<div style='width: expression(alert(1))'>", "inline CSS expression")]
    public async Task CssExpression_ShouldBeDetected(string maliciousHtml, string description)
    {
        // Act
        var result = await _validator.ValidateAsync(maliciousHtml, "test-key");

        // Assert
        Assert.False(result.IsValid, $"Failed to detect: {description}");
        Assert.Equal(ValidationSeverity.Critical, result.Severity);
    }

    #endregion

    #region SVG-based XSS Tests

    [Theory]
    [InlineData("<svg onload='alert(1)'>", "SVG with onload")]
    [InlineData("<svg><g onload='alert(1)'>", "SVG g element with onload")]
    [InlineData("<svg><circle onload='alert(1)'>", "SVG circle with onload")]
    [InlineData("<svg onmouseover='alert(1)'>", "SVG with onmouseover")]
    public async Task SvgOnLoad_ShouldBeDetected(string maliciousHtml, string description)
    {
        // Act
        var result = await _validator.ValidateAsync(maliciousHtml, "test-key");

        // Assert
        Assert.False(result.IsValid, $"Failed to detect: {description}");
        Assert.Equal(ValidationSeverity.Critical, result.Severity);
    }

    [Theory]
    [InlineData("<svg><script>alert(1)</script></svg>", "script inside SVG")]
    [InlineData("<svg><script xlink:href='data:,alert(1)'/></svg>", "SVG script with xlink")]
    public async Task SvgScript_ShouldBeDetected(string maliciousHtml, string description)
    {
        // Act
        var result = await _validator.ValidateAsync(maliciousHtml, "test-key");

        // Assert
        Assert.False(result.IsValid, $"Failed to detect: {description}");
        Assert.Equal(ValidationSeverity.Critical, result.Severity);
    }

    [Theory]
    [InlineData("<svg><animate onbegin='alert(1)' attributeName='x' dur='1s'>", "animate with onbegin")]
    [InlineData("<svg><set onbegin='alert(1)' attributeName='x' to='0'>", "set with onbegin")]
    public async Task SvgAnimate_ShouldBeDetected(string maliciousHtml, string description)
    {
        // Act
        var result = await _validator.ValidateAsync(maliciousHtml, "test-key");

        // Assert
        Assert.False(result.IsValid, $"Failed to detect: {description}");
        Assert.Equal(ValidationSeverity.Critical, result.Severity);
    }

    [Theory]
    [InlineData("<svg><foreignObject><script>alert(1)</script></foreignObject></svg>", "foreignObject with script")]
    [InlineData("<svg><foreignObject width='100' height='100'><body><script>alert(1)</script></body></foreignObject></svg>", "foreignObject with HTML body")]
    public async Task SvgForeignObject_ShouldBeDetected(string maliciousHtml, string description)
    {
        // Act
        var result = await _validator.ValidateAsync(maliciousHtml, "test-key");

        // Assert
        Assert.False(result.IsValid, $"Failed to detect: {description}");
        Assert.Equal(ValidationSeverity.Critical, result.Severity);
    }

    #endregion

    #region Image-based XSS Tests

    [Theory]
    [InlineData("<img src=x onerror='alert(1)'>", "img with onerror")]
    [InlineData("<img src='invalid' onerror='alert(1)'>", "img with quoted src and onerror")]
    [InlineData("<img src=x onerror=alert(1)>", "img with unquoted onerror")]
    public async Task ImageOnError_ShouldBeDetected(string maliciousHtml, string description)
    {
        // Act
        var result = await _validator.ValidateAsync(maliciousHtml, "test-key");

        // Assert
        Assert.False(result.IsValid, $"Failed to detect: {description}");
        Assert.Equal(ValidationSeverity.Critical, result.Severity);
    }

    [Theory]
    [InlineData("<img onload='alert(1)' src='valid.jpg'>", "img with onload")]
    [InlineData("<img src='x' onload=alert(1)>", "img with unquoted onload")]
    public async Task ImageOnLoad_ShouldBeDetected(string maliciousHtml, string description)
    {
        // Act
        var result = await _validator.ValidateAsync(maliciousHtml, "test-key");

        // Assert
        Assert.False(result.IsValid, $"Failed to detect: {description}");
        Assert.Equal(ValidationSeverity.Critical, result.Severity);
    }

    [Theory]
    [InlineData("<img src='javascript:alert(1)'>", "img with javascript: src")]
    [InlineData("<img src=\"javascript:alert(1)\">", "img with double-quoted javascript: src")]
    public async Task ImageJavaScriptSrc_ShouldBeDetected(string maliciousHtml, string description)
    {
        // Act
        var result = await _validator.ValidateAsync(maliciousHtml, "test-key");

        // Assert
        Assert.False(result.IsValid, $"Failed to detect: {description}");
        Assert.Equal(ValidationSeverity.Critical, result.Severity);
    }

    [Theory]
    [InlineData("<img src='data:text/html,<script>alert(1)</script>'>", "img with data URI HTML")]
    [InlineData("<img src=\"data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==\">", "img with base64 data URI")]
    public async Task ImageDataUri_ShouldBeDetected(string maliciousHtml, string description)
    {
        // Act
        var result = await _validator.ValidateAsync(maliciousHtml, "test-key");

        // Assert
        Assert.False(result.IsValid, $"Failed to detect: {description}");
        Assert.Equal(ValidationSeverity.Critical, result.Severity);
    }

    #endregion

    #region IFrame-based XSS Tests

    [Theory]
    [InlineData("<iframe src='javascript:alert(1)'>", "iframe with javascript: src")]
    [InlineData("<iframe src=\"javascript:alert(1)\">", "iframe with double-quoted javascript:")]
    public async Task IFrameJavaScriptSrc_ShouldBeDetected(string maliciousHtml, string description)
    {
        // Act
        var result = await _validator.ValidateAsync(maliciousHtml, "test-key");

        // Assert
        Assert.False(result.IsValid, $"Failed to detect: {description}");
        Assert.Equal(ValidationSeverity.Critical, result.Severity);
    }

    [Theory]
    [InlineData("<iframe src='data:text/html,<script>alert(1)</script>'>", "iframe with data URI")]
    [InlineData("<iframe src='data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=='>", "iframe with base64 data URI")]
    public async Task IFrameDataUri_ShouldBeDetected(string maliciousHtml, string description)
    {
        // Act
        var result = await _validator.ValidateAsync(maliciousHtml, "test-key");

        // Assert
        Assert.False(result.IsValid, $"Failed to detect: {description}");
        Assert.Equal(ValidationSeverity.Critical, result.Severity);
    }

    [Theory]
    [InlineData("<iframe srcdoc='<script>alert(1)</script>'>", "iframe srcdoc with script")]
    [InlineData("<iframe srcdoc=\"<script>alert(1)</script>\">", "iframe srcdoc with double quotes")]
    public async Task IFrameSrcDocWithScript_ShouldBeDetected(string maliciousHtml, string description)
    {
        // Act
        var result = await _validator.ValidateAsync(maliciousHtml, "test-key");

        // Assert
        Assert.False(result.IsValid, $"Failed to detect: {description}");
        Assert.Equal(ValidationSeverity.Critical, result.Severity);
    }

    #endregion

    #region Form-based XSS Tests

    [Theory]
    [InlineData("<form action='javascript:alert(1)'>", "form with javascript: action")]
    [InlineData("<form action=\"javascript:alert(1)\">", "form with double-quoted javascript:")]
    public async Task FormJavaScriptAction_ShouldBeDetected(string maliciousHtml, string description)
    {
        // Act
        var result = await _validator.ValidateAsync(maliciousHtml, "test-key");

        // Assert
        Assert.False(result.IsValid, $"Failed to detect: {description}");
        Assert.Equal(ValidationSeverity.Critical, result.Severity);
    }

    [Theory]
    [InlineData("<form action='data:text/html,<script>alert(1)</script>'>", "form with data URI action")]
    public async Task FormDataUriAction_ShouldBeDetected(string maliciousHtml, string description)
    {
        // Act
        var result = await _validator.ValidateAsync(maliciousHtml, "test-key");

        // Assert
        Assert.False(result.IsValid, $"Failed to detect: {description}");
        Assert.Equal(ValidationSeverity.Critical, result.Severity);
    }

    [Theory]
    [InlineData("<button formaction='javascript:alert(1)'>Submit</button>", "button with formaction")]
    [InlineData("<input type='submit' formaction='javascript:alert(1)'>", "input with formaction")]
    public async Task FormActionAttribute_ShouldBeDetected(string maliciousHtml, string description)
    {
        // Act
        var result = await _validator.ValidateAsync(maliciousHtml, "test-key");

        // Assert
        Assert.False(result.IsValid, $"Failed to detect: {description}");
        Assert.Equal(ValidationSeverity.Critical, result.Severity);
    }

    #endregion

    #region Data URI Tests

    [Theory]
    [InlineData("data:text/html,<script>alert(1)</script>", "data URI with script")]
    [InlineData("data:text/html;charset=utf-8,<script>alert(1)</script>", "data URI with charset")]
    public async Task HtmlDataUriWithScript_ShouldBeDetected(string maliciousHtml, string description)
    {
        // Act
        var result = await _validator.ValidateAsync(maliciousHtml, "test-key");

        // Assert
        Assert.False(result.IsValid, $"Failed to detect: {description}");
        Assert.Equal(ValidationSeverity.Critical, result.Severity);
    }

    [Theory]
    [InlineData("data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==", "base64 HTML data URI")]
    public async Task Base64HtmlDataUri_ShouldBeDetected(string maliciousHtml, string description)
    {
        // Act
        var result = await _validator.ValidateAsync(maliciousHtml, "test-key");

        // Assert
        Assert.False(result.IsValid, $"Failed to detect: {description}");
        Assert.Equal(ValidationSeverity.Critical, result.Severity);
    }

    [Theory]
    [InlineData("<img src='data:image/svg+xml,<svg onload=alert(1)>'>", "SVG data URI with onload")]
    public async Task SvgDataUri_ShouldBeDetected(string maliciousHtml, string description)
    {
        // Act
        var result = await _validator.ValidateAsync(maliciousHtml, "test-key");

        // Assert
        Assert.False(result.IsValid, $"Failed to detect: {description}");
        Assert.Equal(ValidationSeverity.Critical, result.Severity);
    }

    #endregion

    #region Meta and Link Tag Tests

    [Theory]
    [InlineData("<meta http-equiv='refresh' content='0;url=javascript:alert(1)'>", "meta refresh with javascript:")]
    [InlineData("<meta http-equiv=\"refresh\" content=\"0; url=javascript:alert(1)\">", "meta refresh with spaces")]
    public async Task MetaRefreshJavaScript_ShouldBeDetected(string maliciousHtml, string description)
    {
        // Act
        var result = await _validator.ValidateAsync(maliciousHtml, "test-key");

        // Assert
        Assert.False(result.IsValid, $"Failed to detect: {description}");
        Assert.Equal(ValidationSeverity.Critical, result.Severity);
    }

    [Theory]
    [InlineData("<meta http-equiv='refresh' content='0;url=data:text/html,<script>alert(1)</script>'>", "meta refresh with data URI")]
    public async Task MetaRefreshDataUri_ShouldBeDetected(string maliciousHtml, string description)
    {
        // Act
        var result = await _validator.ValidateAsync(maliciousHtml, "test-key");

        // Assert
        Assert.False(result.IsValid, $"Failed to detect: {description}");
        Assert.Equal(ValidationSeverity.Critical, result.Severity);
    }

    [Theory]
    [InlineData("<base href='javascript:alert(1)'>", "base with javascript:")]
    [InlineData("<base href=\"javascript:alert(1)\">", "base with double quotes")]
    public async Task BaseJavaScript_ShouldBeDetected(string maliciousHtml, string description)
    {
        // Act
        var result = await _validator.ValidateAsync(maliciousHtml, "test-key");

        // Assert
        Assert.False(result.IsValid, $"Failed to detect: {description}");
        Assert.Equal(ValidationSeverity.Critical, result.Severity);
    }

    [Theory]
    [InlineData("<base href='data:text/html,<script>alert(1)</script>'>", "base with data URI")]
    public async Task BaseDataUri_ShouldBeDetected(string maliciousHtml, string description)
    {
        // Act
        var result = await _validator.ValidateAsync(maliciousHtml, "test-key");

        // Assert
        Assert.False(result.IsValid, $"Failed to detect: {description}");
        Assert.Equal(ValidationSeverity.Critical, result.Severity);
    }

    [Theory]
    [InlineData("<link rel='stylesheet' href='javascript:alert(1)'>", "link with javascript:")]
    [InlineData("<link href='javascript:alert(1)'>", "link without rel")]
    public async Task LinkJavaScriptHref_ShouldBeDetected(string maliciousHtml, string description)
    {
        // Act
        var result = await _validator.ValidateAsync(maliciousHtml, "test-key");

        // Assert
        Assert.False(result.IsValid, $"Failed to detect: {description}");
        Assert.Equal(ValidationSeverity.Critical, result.Severity);
    }

    [Theory]
    [InlineData("<link rel='stylesheet' href='data:text/css,body{background:url(javascript:alert(1))}'>", "link with data URI")]
    public async Task LinkDataUri_ShouldBeDetected(string maliciousHtml, string description)
    {
        // Act
        var result = await _validator.ValidateAsync(maliciousHtml, "test-key");

        // Assert
        Assert.False(result.IsValid, $"Failed to detect: {description}");
        Assert.Equal(ValidationSeverity.Critical, result.Severity);
    }

    [Theory]
    [InlineData("<link rel='import' href='malicious.html'>", "link import")]
    public async Task LinkImport_ShouldBeDetected(string maliciousHtml, string description)
    {
        // Act
        var result = await _validator.ValidateAsync(maliciousHtml, "test-key");

        // Assert
        Assert.False(result.IsValid, $"Failed to detect: {description}");
        Assert.Equal(ValidationSeverity.Critical, result.Severity);
    }

    #endregion

    #region DOM Clobbering Tests

    [Theory]
    [InlineData("<img id='location'>", "id=location")]
    [InlineData("<img id='top'>", "id=top")]
    [InlineData("<img id='parent'>", "id=parent")]
    [InlineData("<img id='window'>", "id=window")]
    [InlineData("<img id='document'>", "id=document")]
    [InlineData("<img id='self'>", "id=self")]
    [InlineData("<img id='frames'>", "id=frames")]
    public async Task SuspiciousIdAttributes_ShouldBeDetected(string maliciousHtml, string description)
    {
        // Act
        var result = await _validator.ValidateAsync(maliciousHtml, "test-key");

        // Assert
        Assert.False(result.IsValid, $"Failed to detect: {description}");
        Assert.Equal(ValidationSeverity.Critical, result.Severity);
    }

    [Theory]
    [InlineData("<form name='location'><input name='href'></form>", "form name=location")]
    [InlineData("<input name='window'>", "input name=window")]
    [InlineData("<form name='document'>", "form name=document")]
    public async Task SuspiciousNameAttributes_ShouldBeDetected(string maliciousHtml, string description)
    {
        // Act
        var result = await _validator.ValidateAsync(maliciousHtml, "test-key");

        // Assert
        Assert.False(result.IsValid, $"Failed to detect: {description}");
        Assert.Equal(ValidationSeverity.Critical, result.Severity);
    }

    #endregion

    #region Mutation XSS (mXSS) Tests

    [Theory]
    [InlineData("<a href=\"` onclick=alert(1) `\">Link</a>", "backticks in href")]
    [InlineData("<div title=\"` onmouseover=alert(1) `\">", "backticks in title")]
    public async Task BackticksInAttributes_ShouldBeDetected(string maliciousHtml, string description)
    {
        // Act
        var result = await _validator.ValidateAsync(maliciousHtml, "test-key");

        // Assert
        Assert.False(result.IsValid, $"Failed to detect: {description}");
        Assert.Equal(ValidationSeverity.Critical, result.Severity);
    }

    [Theory]
    [InlineData("<a href='&#106;avascript:alert(1)'>", "HTML entity encoded javascript:")]
    public async Task EncodedJavaScriptProtocol_ShouldBeDetected(string maliciousHtml, string description)
    {
        // Act
        var result = await _validator.ValidateAsync(maliciousHtml, "test-key");

        // Assert
        Assert.False(result.IsValid, $"Failed to detect: {description}");
        Assert.Equal(ValidationSeverity.Critical, result.Severity);
    }

    [Theory]
    [InlineData("<x:script xmlns:x='http://www.w3.org/1999/xhtml'>alert(1)</x:script>", "namespace confusion")]
    public async Task NamespaceConfusion_ShouldBeDetected(string maliciousHtml, string description)
    {
        // Act
        var result = await _validator.ValidateAsync(maliciousHtml, "test-key");

        // Assert
        Assert.False(result.IsValid, $"Failed to detect: {description}");
        Assert.Equal(ValidationSeverity.Critical, result.Severity);
    }

    [Theory]
    [InlineData("</style><script>alert(1)</script>", "malformed style tag")]
    [InlineData("</title><script>alert(1)</script>", "malformed title tag")]
    [InlineData("</textarea><script>alert(1)</script>", "malformed textarea tag")]
    [InlineData("</noscript><script>alert(1)</script>", "malformed noscript tag")]
    public async Task MalformedTags_ShouldBeDetected(string maliciousHtml, string description)
    {
        // Act
        var result = await _validator.ValidateAsync(maliciousHtml, "test-key");

        // Assert
        Assert.False(result.IsValid, $"Failed to detect: {description}");
        Assert.Equal(ValidationSeverity.Critical, result.Severity);
    }

    #endregion

    #region Object and Embed Tests

    [Theory]
    [InlineData("<object data='data:text/html,<script>alert(1)</script>'>", "object with data URI")]
    public async Task ObjectDataUri_ShouldBeDetected(string maliciousHtml, string description)
    {
        // Act
        var result = await _validator.ValidateAsync(maliciousHtml, "test-key");

        // Assert
        Assert.False(result.IsValid, $"Failed to detect: {description}");
        Assert.Equal(ValidationSeverity.Critical, result.Severity);
    }

    [Theory]
    [InlineData("<embed src='javascript:alert(1)'>", "embed with javascript:")]
    [InlineData("<embed src='data:text/html,<script>alert(1)</script>'>", "embed with data URI")]
    public async Task EmbedSuspiciousSrc_ShouldBeDetected(string maliciousHtml, string description)
    {
        // Act
        var result = await _validator.ValidateAsync(maliciousHtml, "test-key");

        // Assert
        Assert.False(result.IsValid, $"Failed to detect: {description}");
        Assert.Equal(ValidationSeverity.Critical, result.Severity);
    }

    #endregion

    #region OWASP XSS Cheat Sheet Vectors

    [Theory]
    [InlineData("<img src=x onerror=\"&#0000106&#0000097&#0000118&#0000097&#0000115&#0000099&#0000114&#0000105&#0000112&#0000116&#0000058&#0000097&#0000108&#0000101&#0000114&#0000116&#0000040&#0000039&#0000088&#0000083&#0000083&#0000039&#0000041\">", "decimal encoding")]
    [InlineData("<IMG SRC=j&#X41vascript:alert('test')>", "hex encoding")]
    [InlineData("<IMG SRC=&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;&#97;&#108;&#101;&#114;&#116;&#40;&#39;&#88;&#83;&#83;&#39;&#41;>", "entity encoding")]
    public async Task OwaspEncodedVectors_ShouldBeDetected(string maliciousHtml, string description)
    {
        // Act
        var result = await _validator.ValidateAsync(maliciousHtml, "test-key");

        // Assert
        Assert.False(result.IsValid, $"Failed to detect OWASP vector: {description}");
    }

    #endregion

    #region Browser-Specific Vectors

    [Theory]
    [InlineData("<marquee onstart=alert(1)>", "IE marquee")]
    [InlineData("<bgsound src='javascript:alert(1)'>", "IE bgsound")]
    [InlineData("<xml onreadystatechange=alert(1)>", "IE XML data island")]
    public async Task InternetExplorerSpecificVectors_ShouldBeDetected(string maliciousHtml, string description)
    {
        // Act
        var result = await _validator.ValidateAsync(maliciousHtml, "test-key");

        // Assert
        Assert.False(result.IsValid, $"Failed to detect IE-specific vector: {description}");
    }

    #endregion

    #region Safe Content Tests

    [Theory]
    [InlineData("<div>Hello World</div>", "simple div")]
    [InlineData("<p>This is a paragraph with <strong>bold</strong> text.</p>", "paragraph with strong")]
    [InlineData("<a href='https://example.com'>Safe Link</a>", "safe link")]
    [InlineData("<img src='image.jpg' alt='Description'>", "safe image")]
    [InlineData("<table><tr><td>Cell</td></tr></table>", "table")]
    [InlineData("<ul><li>Item 1</li><li>Item 2</li></ul>", "list")]
    public async Task SafeContent_ShouldPass(string safeHtml, string description)
    {
        // Act
        var result = await _validator.ValidateAsync(safeHtml, "test-key");

        // Assert
        Assert.True(result.IsValid, $"False positive detected for: {description}");
    }

    #endregion

    #region Performance Tests

    [Fact]
    public async Task Validation_ShouldCompleteWithin50ms_ForTypicalContent()
    {
        // Arrange
        var typicalHtml = @"
<!DOCTYPE html>
<html>
<head>
    <title>Sample Page</title>
    <link rel='stylesheet' href='styles.css'>
</head>
<body>
    <header>
        <h1>Welcome</h1>
        <nav>
            <a href='/home'>Home</a>
            <a href='/about'>About</a>
        </nav>
    </header>
    <main>
        <article>
            <h2>Article Title</h2>
            <p>This is a paragraph with some content.</p>
            <img src='image.jpg' alt='Description'>
        </article>
    </main>
    <footer>
        <p>&copy; 2025 Company Name</p>
    </footer>
</body>
</html>";

        // Act
        var stopwatch = Stopwatch.StartNew();
        var result = await _validator.ValidateAsync(typicalHtml, "test-key");
        stopwatch.Stop();

        // Assert
        Assert.True(result.IsValid);
        Assert.True(stopwatch.ElapsedMilliseconds < 50,
            $"Validation took {stopwatch.ElapsedMilliseconds}ms, expected < 50ms");
    }

    [Fact]
    public async Task Validation_ShouldHandleLargeContent_Efficiently()
    {
        // Arrange - Create a large HTML page with many elements
        var largeHtml = new System.Text.StringBuilder();
        largeHtml.Append("<!DOCTYPE html><html><body>");
        for (int i = 0; i < 1000; i++)
        {
            largeHtml.Append($"<div><p>Paragraph {i}</p><a href='/link{i}'>Link {i}</a></div>");
        }
        largeHtml.Append("</body></html>");

        // Act
        var stopwatch = Stopwatch.StartNew();
        var result = await _validator.ValidateAsync(largeHtml.ToString(), "test-key");
        stopwatch.Stop();

        // Assert
        Assert.True(result.IsValid);
        Assert.True(stopwatch.ElapsedMilliseconds < 100,
            $"Large content validation took {stopwatch.ElapsedMilliseconds}ms, expected < 100ms");
    }

    [Fact]
    public async Task Validation_ShouldDetectMaliciousContent_Quickly()
    {
        // Arrange - Malicious content should be detected early
        var maliciousHtml = "<div onclick='alert(1)'>Click me</div>";

        // Act
        var stopwatch = Stopwatch.StartNew();
        var result = await _validator.ValidateAsync(maliciousHtml, "test-key");
        stopwatch.Stop();

        // Assert
        Assert.False(result.IsValid);
        Assert.True(stopwatch.ElapsedMilliseconds < 10,
            $"Early detection took {stopwatch.ElapsedMilliseconds}ms, expected < 10ms");
    }

    #endregion

    #region Edge Cases

    [Fact]
    public async Task Validation_EmptyContent_ShouldPass()
    {
        // Act
        var result = await _validator.ValidateAsync("", "test-key");

        // Assert
        Assert.True(result.IsValid);
    }

    [Fact]
    public async Task Validation_NullContent_ShouldPass()
    {
        // Act
        var result = await _validator.ValidateAsync(null!, "test-key");

        // Assert
        Assert.True(result.IsValid);
    }

    [Fact]
    public async Task Validation_WhitespaceOnly_ShouldPass()
    {
        // Act
        var result = await _validator.ValidateAsync("   \n\t\r\n   ", "test-key");

        // Assert
        Assert.True(result.IsValid);
    }

    #endregion
}
