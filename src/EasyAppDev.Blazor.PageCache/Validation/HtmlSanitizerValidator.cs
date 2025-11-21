using System.Diagnostics;
using System.Text.RegularExpressions;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using EasyAppDev.Blazor.PageCache.Abstractions;
using EasyAppDev.Blazor.PageCache.Configuration;
using EasyAppDev.Blazor.PageCache.Security;

namespace EasyAppDev.Blazor.PageCache.Validation;

/// <summary>
/// Validates HTML content for potential XSS vulnerabilities and malicious patterns.
/// </summary>
/// <remarks>
/// This validator uses the comprehensive XssPatternLibrary to detect a wide range of XSS attacks.
/// Patterns are evaluated in order of severity (critical first) for optimal performance.
/// Validation is designed to complete in under 50ms for typical page content.
/// </remarks>
public sealed partial class HtmlSanitizerValidator : IContentValidator
{
    private readonly SecurityOptions _securityOptions;
    private readonly ILogger<HtmlSanitizerValidator> _logger;
    private readonly ISecurityAuditLogger? _auditLogger;

    /// <summary>
    /// Cache of all XSS patterns in optimal detection order.
    /// Patterns are organized by severity: critical, high, medium, advanced.
    /// </summary>
    private static readonly Regex[] AllPatterns = XssPatternLibrary.GetAllPatternsOrdered().ToArray();

    /// <summary>
    /// Cache of critical patterns for early exit optimization.
    /// </summary>
    private static readonly Regex[] CriticalPatterns = XssPatternLibrary.GetCriticalPatterns().ToArray();

    public HtmlSanitizerValidator(
        IOptions<SecurityOptions> securityOptions,
        ILogger<HtmlSanitizerValidator> logger,
        ISecurityAuditLogger? auditLogger = null)
    {
        _securityOptions = securityOptions?.Value ?? throw new ArgumentNullException(nameof(securityOptions));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _auditLogger = auditLogger;
    }

    /// <inheritdoc />
    public Task<ValidationResult> ValidateAsync(
        string content,
        string cacheKey,
        CancellationToken cancellationToken = default)
    {
        if (!_securityOptions.EnableHtmlValidation)
        {
            return Task.FromResult(ValidationResult.Success());
        }

        if (string.IsNullOrEmpty(content))
        {
            return Task.FromResult(ValidationResult.Success());
        }

        // CRITICAL SECURITY FIX (Issue 4.2): Removed sampling logic
        // Previously, with samplingRate=10, 90% of requests bypassed validation entirely.
        // This created a critical security vulnerability where XSS attacks could go undetected.
        // ALL requests are now validated to ensure comprehensive XSS protection.

        // Start performance tracking
        var stopwatch = Stopwatch.StartNew();

        // OPTIMIZATION 1: Check critical patterns first for early exit
        // Critical patterns are most common and most dangerous, so we check them first
        foreach (var pattern in CriticalPatterns)
        {
            if (cancellationToken.IsCancellationRequested)
            {
                break;
            }

            try
            {
                var match = pattern.Match(content);
                if (match.Success)
                {
                    stopwatch.Stop();
                    var patternName = GetPatternName(pattern);
                    LogSuspiciousContentDetected(cacheKey, match.Value, stopwatch.ElapsedMilliseconds);

                    // Log to security audit logger
                    _auditLogger?.LogXssDetection(new XssDetectionContext
                    {
                        CacheKey = cacheKey,
                        PatternName = patternName,
                        PatternCategory = "Critical",
                        MatchedContent = match.Value,
                        RequestPath = "[from-cache-key]",
                        ValidationTimeMs = stopwatch.ElapsedMilliseconds
                    });

                    return Task.FromResult(ValidationResult.Failure(
                        $"Critical XSS pattern detected in HTML content: {patternName}",
                        ValidationSeverity.Critical,
                        new Dictionary<string, string>
                        {
                            ["Pattern"] = patternName,
                            ["MatchedContent"] = match.Value.Length > 100
                                ? match.Value.Substring(0, 100) + "..."
                                : match.Value,
                            ["ValidationTimeMs"] = stopwatch.ElapsedMilliseconds.ToString()
                        }));
                }
            }
            catch (RegexMatchTimeoutException ex)
            {
                // ReDoS protection: log and continue
                LogRegexTimeout(cacheKey, pattern.ToString(), ex);
                continue;
            }
        }

        // OPTIMIZATION 2: If no critical patterns found, check remaining patterns
        // Skip critical patterns since we already checked them
        var remainingPatterns = AllPatterns.Skip(CriticalPatterns.Length);

        foreach (var pattern in remainingPatterns)
        {
            if (cancellationToken.IsCancellationRequested)
            {
                break;
            }

            try
            {
                var match = pattern.Match(content);
                if (match.Success)
                {
                    stopwatch.Stop();
                    var patternName = GetPatternName(pattern);
                    LogSuspiciousContentDetected(cacheKey, match.Value, stopwatch.ElapsedMilliseconds);

                    // Log to security audit logger
                    _auditLogger?.LogXssDetection(new XssDetectionContext
                    {
                        CacheKey = cacheKey,
                        PatternName = patternName,
                        PatternCategory = "Standard",
                        MatchedContent = match.Value,
                        RequestPath = "[from-cache-key]",
                        ValidationTimeMs = stopwatch.ElapsedMilliseconds
                    });

                    return Task.FromResult(ValidationResult.Failure(
                        $"Potentially malicious XSS pattern detected in HTML content: {patternName}",
                        ValidationSeverity.Critical,
                        new Dictionary<string, string>
                        {
                            ["Pattern"] = patternName,
                            ["MatchedContent"] = match.Value.Length > 100
                                ? match.Value.Substring(0, 100) + "..."
                                : match.Value,
                            ["ValidationTimeMs"] = stopwatch.ElapsedMilliseconds.ToString()
                        }));
                }
            }
            catch (RegexMatchTimeoutException ex)
            {
                // ReDoS protection: log and continue
                LogRegexTimeout(cacheKey, pattern.ToString(), ex);
                continue;
            }
        }

        // Check script tag count (existing logic)
        var scriptTagCount = Regex.Matches(content, @"<script[^>]*>", RegexOptions.IgnoreCase).Count;
        if (scriptTagCount > _securityOptions.MaxScriptTagsAllowed)
        {
            stopwatch.Stop();
            LogExcessiveScriptTags(cacheKey, scriptTagCount);

            // Log to security audit logger
            _auditLogger?.LogValidationFailure(new ValidationFailureContext
            {
                CacheKey = cacheKey,
                ValidatorType = nameof(HtmlSanitizerValidator),
                Severity = "Warning",
                ErrorMessage = $"Too many script tags: {scriptTagCount}/{_securityOptions.MaxScriptTagsAllowed}",
                MatchedContent = $"{scriptTagCount} script tags",
                RequestPath = "[from-cache-key]",
                ElapsedMs = stopwatch.ElapsedMilliseconds
            });

            return Task.FromResult(ValidationResult.Failure(
                $"Too many script tags detected ({scriptTagCount}), maximum allowed is {_securityOptions.MaxScriptTagsAllowed}",
                ValidationSeverity.Warning,
                new Dictionary<string, string>
                {
                    ["ScriptTagCount"] = scriptTagCount.ToString(),
                    ["MaxAllowed"] = _securityOptions.MaxScriptTagsAllowed.ToString(),
                    ["ValidationTimeMs"] = stopwatch.ElapsedMilliseconds.ToString()
                }));
        }

        stopwatch.Stop();

        // Log performance metrics if validation took longer than expected
        if (stopwatch.ElapsedMilliseconds > 50)
        {
            LogSlowValidation(cacheKey, stopwatch.ElapsedMilliseconds);
        }

        return Task.FromResult(ValidationResult.Success());
    }

    /// <summary>
    /// Gets a friendly name for a regex pattern by matching it against known patterns.
    /// </summary>
    private static string GetPatternName(Regex pattern)
    {
        var patternString = pattern.ToString();

        // Match against known patterns from XssPatternLibrary
        if (pattern == XssPatternLibrary.Critical.ScriptTag) return "ScriptTag";
        if (pattern == XssPatternLibrary.Critical.InlineEventHandlers) return "InlineEventHandlers";
        if (pattern == XssPatternLibrary.Critical.JavaScriptProtocol) return "JavaScriptProtocol";
        if (pattern == XssPatternLibrary.Critical.VbScriptProtocol) return "VbScriptProtocol";
        if (pattern == XssPatternLibrary.Critical.DangerousScriptContent) return "DangerousScriptContent";
        if (pattern == XssPatternLibrary.Critical.Base64EncodedScript) return "Base64EncodedScript";
        if (pattern == XssPatternLibrary.Critical.CssExpression) return "CssExpression";

        if (pattern == XssPatternLibrary.Svg.SvgOnLoad) return "SvgOnLoad";
        if (pattern == XssPatternLibrary.Svg.SvgScript) return "SvgScript";
        if (pattern == XssPatternLibrary.Svg.SvgAnimate) return "SvgAnimate";
        if (pattern == XssPatternLibrary.Svg.SvgForeignObject) return "SvgForeignObject";
        if (pattern == XssPatternLibrary.Svg.MathMLScript) return "MathMLScript";

        if (pattern == XssPatternLibrary.Image.ImageOnError) return "ImageOnError";
        if (pattern == XssPatternLibrary.Image.ImageOnLoad) return "ImageOnLoad";
        if (pattern == XssPatternLibrary.Image.ImageJavaScriptSrc) return "ImageJavaScriptSrc";
        if (pattern == XssPatternLibrary.Image.ImageDataUri) return "ImageDataUri";

        if (pattern == XssPatternLibrary.IFrame.IFrameJavaScriptSrc) return "IFrameJavaScriptSrc";
        if (pattern == XssPatternLibrary.IFrame.IFrameDataUri) return "IFrameDataUri";
        if (pattern == XssPatternLibrary.IFrame.IFrameSrcDocWithScript) return "IFrameSrcDocWithScript";

        if (pattern == XssPatternLibrary.Form.FormJavaScriptAction) return "FormJavaScriptAction";
        if (pattern == XssPatternLibrary.Form.FormDataUriAction) return "FormDataUriAction";
        if (pattern == XssPatternLibrary.Form.FormActionAttribute) return "FormActionAttribute";

        if (pattern == XssPatternLibrary.DataUri.HtmlDataUriWithScript) return "HtmlDataUriWithScript";
        if (pattern == XssPatternLibrary.DataUri.Base64HtmlDataUri) return "Base64HtmlDataUri";
        if (pattern == XssPatternLibrary.DataUri.SvgDataUri) return "SvgDataUri";

        if (pattern == XssPatternLibrary.Meta.MetaRefreshJavaScript) return "MetaRefreshJavaScript";
        if (pattern == XssPatternLibrary.Meta.MetaRefreshDataUri) return "MetaRefreshDataUri";

        if (pattern == XssPatternLibrary.Link.BaseJavaScript) return "BaseJavaScript";
        if (pattern == XssPatternLibrary.Link.BaseDataUri) return "BaseDataUri";
        if (pattern == XssPatternLibrary.Link.LinkJavaScriptHref) return "LinkJavaScriptHref";
        if (pattern == XssPatternLibrary.Link.LinkDataUri) return "LinkDataUri";
        if (pattern == XssPatternLibrary.Link.LinkImport) return "LinkImport";

        if (pattern == XssPatternLibrary.DomClobbering.SuspiciousIdAttributes) return "DomClobbering_SuspiciousId";
        if (pattern == XssPatternLibrary.DomClobbering.SuspiciousNameAttributes) return "DomClobbering_SuspiciousName";
        if (pattern == XssPatternLibrary.DomClobbering.DuplicateIdName) return "DomClobbering_Duplicate";

        if (pattern == XssPatternLibrary.MutationXss.BackticksInAttributes) return "mXSS_Backticks";
        if (pattern == XssPatternLibrary.MutationXss.EncodedJavaScriptProtocol) return "mXSS_EncodedJavaScript";
        if (pattern == XssPatternLibrary.MutationXss.NamespaceConfusion) return "mXSS_NamespaceConfusion";
        if (pattern == XssPatternLibrary.MutationXss.MalformedTags) return "mXSS_MalformedTags";

        if (pattern == XssPatternLibrary.ObjectEmbed.ObjectDataUri) return "ObjectDataUri";
        if (pattern == XssPatternLibrary.ObjectEmbed.EmbedSuspiciousSrc) return "EmbedSuspiciousSrc";

        // Fallback to pattern string
        return patternString.Length > 50 ? patternString.Substring(0, 50) + "..." : patternString;
    }

    [LoggerMessage(EventId = 3010, Level = LogLevel.Warning,
        Message = "Suspicious content detected in cache key '{CacheKey}': {MatchedContent} (validation took {ElapsedMs}ms)")]
    private partial void LogSuspiciousContentDetected(string cacheKey, string matchedContent, long elapsedMs);

    [LoggerMessage(EventId = 3011, Level = LogLevel.Information,
        Message = "Excessive script tags detected in cache key '{CacheKey}': {Count} tags")]
    private partial void LogExcessiveScriptTags(string cacheKey, int count);

    [LoggerMessage(EventId = 3013, Level = LogLevel.Warning,
        Message = "Regex timeout during XSS validation for cache key '{CacheKey}' with pattern '{Pattern}'")]
    private partial void LogRegexTimeout(string cacheKey, string pattern, RegexMatchTimeoutException exception);

    [LoggerMessage(EventId = 3014, Level = LogLevel.Warning,
        Message = "Slow HTML validation detected for cache key '{CacheKey}': {ElapsedMs}ms (threshold: 50ms)")]
    private partial void LogSlowValidation(string cacheKey, long elapsedMs);
}
