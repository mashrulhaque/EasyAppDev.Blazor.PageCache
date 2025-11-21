using Microsoft.Extensions.Options;

namespace EasyAppDev.Blazor.PageCache.Configuration;

/// <summary>
/// Validates <see cref="PageCacheOptions"/> configuration with comprehensive range checks and security validation.
/// </summary>
/// <remarks>
/// This validator ensures that all configuration options are within acceptable ranges and that
/// security-related options are properly configured. It catches configuration errors at startup
/// rather than at runtime, improving application reliability.
/// </remarks>
internal sealed class PageCacheOptionsValidator : IValidateOptions<PageCacheOptions>
{
    // Reasonable limits for configuration values
    private const int MinDurationSeconds = 1;
    private const int MaxDurationSeconds = 86400 * 7; // 7 days
    private const int MinCacheSizeMB = 1;
    private const int MaxCacheSizeMB = 10240; // 10 GB
    private const int MinTimeoutSeconds = 1;
    private const int MaxTimeoutSeconds = 300; // 5 minutes
    private const int MinConcurrentGenerations = 1;
    private const int MaxConcurrentGenerations = 1000;
    private const int MinMaxWildcards = 1;
    private const int MaxMaxWildcards = 10;
    private const int MinPatternLength = 1;
    private const int MaxPatternLength = 1024;

    /// <inheritdoc />
    public ValidateOptionsResult Validate(string? name, PageCacheOptions options)
    {
        var errors = new List<string>();

        // Validate DefaultDurationSeconds with range check
        if (options.DefaultDurationSeconds <= 0)
        {
            errors.Add($"{nameof(options.DefaultDurationSeconds)} must be greater than 0.");
        }
        else if (options.DefaultDurationSeconds < MinDurationSeconds)
        {
            errors.Add($"{nameof(options.DefaultDurationSeconds)} must be at least {MinDurationSeconds} second(s). Current value: {options.DefaultDurationSeconds}");
        }
        else if (options.DefaultDurationSeconds > MaxDurationSeconds)
        {
            errors.Add($"{nameof(options.DefaultDurationSeconds)} must not exceed {MaxDurationSeconds} seconds (7 days). Current value: {options.DefaultDurationSeconds}");
        }

        // Validate MaxCacheSizeMB with range check
        if (options.MaxCacheSizeMB.HasValue)
        {
            if (options.MaxCacheSizeMB.Value <= 0)
            {
                errors.Add($"{nameof(options.MaxCacheSizeMB)} must be greater than 0 or null.");
            }
            else if (options.MaxCacheSizeMB.Value < MinCacheSizeMB)
            {
                errors.Add($"{nameof(options.MaxCacheSizeMB)} must be at least {MinCacheSizeMB} MB. Current value: {options.MaxCacheSizeMB.Value}");
            }
            else if (options.MaxCacheSizeMB.Value > MaxCacheSizeMB)
            {
                errors.Add($"{nameof(options.MaxCacheSizeMB)} must not exceed {MaxCacheSizeMB} MB (10 GB). Current value: {options.MaxCacheSizeMB.Value}");
            }
        }

        // Validate SlidingExpirationSeconds with range check
        if (options.SlidingExpirationSeconds.HasValue)
        {
            if (options.SlidingExpirationSeconds.Value <= 0)
            {
                errors.Add($"{nameof(options.SlidingExpirationSeconds)} must be greater than 0 or null.");
            }
            else if (options.SlidingExpirationSeconds.Value < MinDurationSeconds)
            {
                errors.Add($"{nameof(options.SlidingExpirationSeconds)} must be at least {MinDurationSeconds} second(s). Current value: {options.SlidingExpirationSeconds.Value}");
            }
            else if (options.SlidingExpirationSeconds.Value > MaxDurationSeconds)
            {
                errors.Add($"{nameof(options.SlidingExpirationSeconds)} must not exceed {MaxDurationSeconds} seconds (7 days). Current value: {options.SlidingExpirationSeconds.Value}");
            }

            // Validate sliding expiration is not greater than default duration
            if (options.SlidingExpirationSeconds.Value > options.DefaultDurationSeconds)
            {
                errors.Add($"{nameof(options.SlidingExpirationSeconds)} ({options.SlidingExpirationSeconds.Value}) should not exceed {nameof(options.DefaultDurationSeconds)} ({options.DefaultDurationSeconds}). " +
                          "Sliding expiration should be less than or equal to the absolute expiration.");
            }
        }

        // Validate CacheKeyPrefix
        if (string.IsNullOrWhiteSpace(options.CacheKeyPrefix))
        {
            errors.Add($"{nameof(options.CacheKeyPrefix)} cannot be null or whitespace.");
        }
        else if (options.CacheKeyPrefix.Length > 100)
        {
            errors.Add($"{nameof(options.CacheKeyPrefix)} must not exceed 100 characters. Current length: {options.CacheKeyPrefix.Length}");
        }

        // Validate MaxConcurrentCacheGenerations with range check
        if (options.MaxConcurrentCacheGenerations <= 0)
        {
            errors.Add($"{nameof(options.MaxConcurrentCacheGenerations)} must be greater than 0.");
        }
        else if (options.MaxConcurrentCacheGenerations < MinConcurrentGenerations)
        {
            errors.Add($"{nameof(options.MaxConcurrentCacheGenerations)} must be at least {MinConcurrentGenerations}. Current value: {options.MaxConcurrentCacheGenerations}");
        }
        else if (options.MaxConcurrentCacheGenerations > MaxConcurrentGenerations)
        {
            errors.Add($"{nameof(options.MaxConcurrentCacheGenerations)} must not exceed {MaxConcurrentGenerations}. Current value: {options.MaxConcurrentCacheGenerations}");
        }

        // Validate CacheGenerationTimeoutSeconds with range check
        if (options.CacheGenerationTimeoutSeconds <= 0)
        {
            errors.Add($"{nameof(options.CacheGenerationTimeoutSeconds)} must be greater than 0.");
        }
        else if (options.CacheGenerationTimeoutSeconds < MinTimeoutSeconds)
        {
            errors.Add($"{nameof(options.CacheGenerationTimeoutSeconds)} must be at least {MinTimeoutSeconds} second(s). Current value: {options.CacheGenerationTimeoutSeconds}");
        }
        else if (options.CacheGenerationTimeoutSeconds > MaxTimeoutSeconds)
        {
            errors.Add($"{nameof(options.CacheGenerationTimeoutSeconds)} must not exceed {MaxTimeoutSeconds} seconds. Current value: {options.CacheGenerationTimeoutSeconds}");
        }

        // Validate CacheableStatusCodes
        if (options.CacheableStatusCodes.Count == 0)
        {
            errors.Add($"{nameof(options.CacheableStatusCodes)} must contain at least one status code.");
        }
        else
        {
            // Validate each status code is in valid HTTP range (100-599)
            var invalidCodes = options.CacheableStatusCodes.Where(code => code < 100 || code > 599).ToList();
            if (invalidCodes.Count > 0)
            {
                errors.Add($"{nameof(options.CacheableStatusCodes)} contains invalid HTTP status codes: {string.Join(", ", invalidCodes)}. Status codes must be between 100 and 599.");
            }
        }

        // Validate MaxWildcardsInPattern with range check (ReDoS protection)
        if (options.MaxWildcardsInPattern <= 0)
        {
            errors.Add($"{nameof(options.MaxWildcardsInPattern)} must be greater than 0.");
        }
        else if (options.MaxWildcardsInPattern < MinMaxWildcards)
        {
            errors.Add($"{nameof(options.MaxWildcardsInPattern)} must be at least {MinMaxWildcards}. Current value: {options.MaxWildcardsInPattern}");
        }
        else if (options.MaxWildcardsInPattern > MaxMaxWildcards)
        {
            errors.Add($"{nameof(options.MaxWildcardsInPattern)} must not exceed {MaxMaxWildcards} to prevent ReDoS attacks. Current value: {options.MaxWildcardsInPattern}");
        }

        // Validate MaxPatternLength with range check (ReDoS protection)
        if (options.MaxPatternLength <= 0)
        {
            errors.Add($"{nameof(options.MaxPatternLength)} must be greater than 0.");
        }
        else if (options.MaxPatternLength < MinPatternLength)
        {
            errors.Add($"{nameof(options.MaxPatternLength)} must be at least {MinPatternLength}. Current value: {options.MaxPatternLength}");
        }
        else if (options.MaxPatternLength > MaxPatternLength)
        {
            errors.Add($"{nameof(options.MaxPatternLength)} must not exceed {MaxPatternLength} to prevent ReDoS attacks. Current value: {options.MaxPatternLength}");
        }

        // Validate Security options
        ValidateSecurityOptions(options.Security, errors);

        if (errors.Count > 0)
        {
            return ValidateOptionsResult.Fail(errors);
        }

        return ValidateOptionsResult.Success;
    }

    /// <summary>
    /// Validates security-related configuration options.
    /// </summary>
    private static void ValidateSecurityOptions(SecurityOptions security, List<string> errors)
    {
        // Validate MaxEntrySizeBytes
        if (security.MaxEntrySizeBytes.HasValue)
        {
            if (security.MaxEntrySizeBytes.Value <= 0)
            {
                errors.Add($"Security.{nameof(security.MaxEntrySizeBytes)} must be greater than 0 or null.");
            }
            else if (security.MaxEntrySizeBytes.Value < 1024) // Minimum 1 KB
            {
                errors.Add($"Security.{nameof(security.MaxEntrySizeBytes)} must be at least 1024 bytes (1 KB). Current value: {security.MaxEntrySizeBytes.Value}");
            }
            else if (security.MaxEntrySizeBytes.Value > 104857600) // Maximum 100 MB
            {
                errors.Add($"Security.{nameof(security.MaxEntrySizeBytes)} must not exceed 104,857,600 bytes (100 MB). Current value: {security.MaxEntrySizeBytes.Value}");
            }
        }

        // Validate WarnOnLargeEntrySizeBytes
        if (security.WarnOnLargeEntrySizeBytes.HasValue)
        {
            if (security.WarnOnLargeEntrySizeBytes.Value <= 0)
            {
                errors.Add($"Security.{nameof(security.WarnOnLargeEntrySizeBytes)} must be greater than 0 or null.");
            }

            // Warn threshold should be less than max size
            if (security.MaxEntrySizeBytes.HasValue &&
                security.WarnOnLargeEntrySizeBytes.Value > security.MaxEntrySizeBytes.Value)
            {
                errors.Add($"Security.{nameof(security.WarnOnLargeEntrySizeBytes)} ({security.WarnOnLargeEntrySizeBytes.Value}) " +
                          $"should not exceed Security.{nameof(security.MaxEntrySizeBytes)} ({security.MaxEntrySizeBytes.Value}).");
            }
        }

        // Validate MaxScriptTagsAllowed
        if (security.MaxScriptTagsAllowed <= 0)
        {
            errors.Add($"Security.{nameof(security.MaxScriptTagsAllowed)} must be greater than 0.");
        }
        else if (security.MaxScriptTagsAllowed > 1000)
        {
            errors.Add($"Security.{nameof(security.MaxScriptTagsAllowed)} must not exceed 1000. Current value: {security.MaxScriptTagsAllowed}. " +
                      "If you need more script tags, consider reviewing your security requirements.");
        }

        // Validate HtmlValidationSamplingRate
        // Note: Property is obsolete but we still validate it for backward compatibility
#pragma warning disable CS0618 // Type or member is obsolete
        if (security.HtmlValidationSamplingRate < 1)
        {
            errors.Add($"Security.{nameof(security.HtmlValidationSamplingRate)} must be at least 1. Current value: {security.HtmlValidationSamplingRate}");
        }
        else if (security.HtmlValidationSamplingRate > 1000)
        {
            errors.Add($"Security.{nameof(security.HtmlValidationSamplingRate)} must not exceed 1000. Current value: {security.HtmlValidationSamplingRate}. " +
                      "High sampling rates significantly reduce security effectiveness.");
        }
#pragma warning restore CS0618 // Type or member is obsolete

        // Validate rate limiting configuration
        if (security.EnableRateLimiting)
        {
            if (security.RateLimitMaxAttempts <= 0)
            {
                errors.Add($"Security.{nameof(security.RateLimitMaxAttempts)} must be greater than 0 when rate limiting is enabled.");
            }
            else if (security.RateLimitMaxAttempts > 10000)
            {
                errors.Add($"Security.{nameof(security.RateLimitMaxAttempts)} must not exceed 10,000. Current value: {security.RateLimitMaxAttempts}. " +
                          "Excessive rate limits reduce effectiveness of DoS protection.");
            }

            if (security.RateLimitWindowSeconds <= 0)
            {
                errors.Add($"Security.{nameof(security.RateLimitWindowSeconds)} must be greater than 0 when rate limiting is enabled.");
            }
            else if (security.RateLimitWindowSeconds > 3600) // 1 hour
            {
                errors.Add($"Security.{nameof(security.RateLimitWindowSeconds)} must not exceed 3600 seconds (1 hour). Current value: {security.RateLimitWindowSeconds}");
            }

            // Validate reasonable rate limit ratio
            if (security.RateLimitWindowSeconds > 0)
            {
                var attemptsPerSecond = (double)security.RateLimitMaxAttempts / security.RateLimitWindowSeconds;
                if (attemptsPerSecond > 100)
                {
                    errors.Add($"Rate limit configuration allows {attemptsPerSecond:F2} attempts per second, which may be too permissive. " +
                              $"Consider reducing {nameof(security.RateLimitMaxAttempts)} or increasing {nameof(security.RateLimitWindowSeconds)}.");
                }
            }
        }

        // Validate timing jitter configuration
        if (security.AddTimingJitter)
        {
            if (security.MaxJitterMilliseconds <= 0)
            {
                errors.Add($"Security.{nameof(security.MaxJitterMilliseconds)} must be greater than 0 when timing jitter is enabled.");
            }
            else if (security.MaxJitterMilliseconds > 1000)
            {
                errors.Add($"Security.{nameof(security.MaxJitterMilliseconds)} must not exceed 1000 milliseconds (1 second). Current value: {security.MaxJitterMilliseconds}. " +
                          "Excessive jitter may negatively impact user experience.");
            }
        }

        // Validate Content Security Policy (CSP) configuration
        ValidateCspConfiguration(security, errors);

        // Validate security option combinations
        // NOTE: HtmlValidationSamplingRate validation removed as part of Phase 1 security fixes.
        // The property is deprecated and no longer has any effect. All requests are now validated.

        if (!security.EnableHtmlValidation && !security.EnableSizeValidation)
        {
            errors.Add("WARNING: Both HTML validation and size validation are disabled. This significantly reduces security protection. " +
                      "Consider enabling at least one form of content validation.");
        }

        if (security.ExposeDebugHeaders)
        {
            errors.Add("WARNING: Debug headers are enabled. This may leak information about caching behavior and could be used for timing attacks. " +
                      "Debug headers should only be enabled in development environments.");
        }
    }

    /// <summary>
    /// Validates Content Security Policy (CSP) configuration.
    /// </summary>
    private static void ValidateCspConfiguration(SecurityOptions security, List<string> errors)
    {
        if (!security.EnableContentSecurityPolicy)
        {
            return; // CSP is disabled, no validation needed
        }

        // ERROR: CSP is enabled but policy is null or empty
        if (string.IsNullOrWhiteSpace(security.ContentSecurityPolicy))
        {
            errors.Add($"Security.{nameof(security.ContentSecurityPolicy)} cannot be null or whitespace when " +
                      $"{nameof(security.EnableContentSecurityPolicy)} is enabled. " +
                      "Either provide a valid CSP policy or disable CSP by setting EnableContentSecurityPolicy to false.");
            return; // Cannot perform further validation without a policy
        }

        var policy = security.ContentSecurityPolicy.Trim();

        // ERROR: CSP policy exceeds maximum header size limit
        const int maxCspLength = 4096; // Common header size limit for most proxies/servers
        if (policy.Length > maxCspLength)
        {
            errors.Add($"Security.{nameof(security.ContentSecurityPolicy)} exceeds {maxCspLength} characters (current: {policy.Length}). " +
                      "Long CSP policies may be truncated by proxies or web servers. " +
                      "Consider simplifying your policy or splitting it across multiple strategies.");
        }

        // Validate CSP policy format and directives
        var directives = policy.Split(new[] { ';' }, StringSplitOptions.RemoveEmptyEntries)
                               .Select(d => d.Trim())
                               .Where(d => !string.IsNullOrWhiteSpace(d))
                               .ToList();

        // ERROR: CSP policy has no valid directives
        if (directives.Count == 0)
        {
            errors.Add($"Security.{nameof(security.ContentSecurityPolicy)} does not contain any valid directives. " +
                      "A CSP policy must contain at least one directive (e.g., 'default-src \\'self\\'').");
            return;
        }

        // Validate each directive has a name and value
        foreach (var directive in directives)
        {
            var parts = directive.Split(new[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length < 1)
            {
                errors.Add($"Security.{nameof(security.ContentSecurityPolicy)} contains an invalid directive: '{directive}'. " +
                          "Each directive must have at least a directive name.");
            }
        }

        // WARNING: CSP policy doesn't end with semicolon (best practice)
        if (!policy.TrimEnd().EndsWith(";"))
        {
            errors.Add($"WARNING: Security.{nameof(security.ContentSecurityPolicy)} should end with a semicolon (;) as per CSP best practices. " +
                      "While browsers are lenient, this ensures consistent behavior across implementations.");
        }

        // Check for common CSP directive names to validate format
        var directiveNames = directives
            .Select(d => d.Split(new[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries).FirstOrDefault())
            .Where(name => !string.IsNullOrEmpty(name))
            .ToList();

        var knownDirectives = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "default-src", "script-src", "style-src", "img-src", "font-src", "connect-src",
            "frame-src", "frame-ancestors", "object-src", "media-src", "manifest-src", "worker-src",
            "form-action", "base-uri", "plugin-types", "sandbox", "report-uri", "report-to",
            "upgrade-insecure-requests", "block-all-mixed-content", "require-sri-for", "require-trusted-types-for",
            "trusted-types", "child-src", "prefetch-src", "navigate-to"
        };

        var unknownDirectives = directiveNames.Where(name => name != null && !knownDirectives.Contains(name)).ToList();
        if (unknownDirectives.Any())
        {
            errors.Add($"WARNING: Security.{nameof(security.ContentSecurityPolicy)} contains unrecognized directives: {string.Join(", ", unknownDirectives)}. " +
                      "These may be typos or unsupported directives. Verify your CSP policy is correct.");
        }

        // INFO: Recommend default-src if missing
        if (!directiveNames.Any(name => name != null && name.Equals("default-src", StringComparison.OrdinalIgnoreCase)))
        {
            errors.Add($"INFO: Security.{nameof(security.ContentSecurityPolicy)} does not include a 'default-src' directive. " +
                      "Consider adding 'default-src' as a fallback for resource types not explicitly specified. " +
                      "This is a best practice for comprehensive CSP policies.");
        }

        // WARNING: Using both 'unsafe-inline' and 'unsafe-eval' (very permissive)
        var policyLower = policy.ToLowerInvariant();
        var hasUnsafeInline = policyLower.Contains("'unsafe-inline'");
        var hasUnsafeEval = policyLower.Contains("'unsafe-eval'");

        if (hasUnsafeInline && hasUnsafeEval)
        {
            errors.Add($"WARNING: Security.{nameof(security.ContentSecurityPolicy)} uses both 'unsafe-inline' and 'unsafe-eval', " +
                      "which significantly weakens XSS protection. Consider using nonces or hashes for inline scripts/styles, " +
                      "and avoid 'unsafe-eval' if possible. If these are required, ensure you have compensating security controls.");
        }

        // WARNING: Using 'unsafe-eval' without other restrictions
        if (hasUnsafeEval && !policy.Contains("'nonce-") && !policy.Contains("'sha"))
        {
            errors.Add($"WARNING: Security.{nameof(security.ContentSecurityPolicy)} uses 'unsafe-eval' which allows dangerous JavaScript eval() calls. " +
                      "This can enable XSS attacks. Consider removing 'unsafe-eval' or adding additional restrictions.");
        }

        // WARNING: Using '*' wildcard in security-sensitive directives
        if (policyLower.Contains("script-src *") || policyLower.Contains("default-src *"))
        {
            errors.Add($"WARNING: Security.{nameof(security.ContentSecurityPolicy)} uses '*' wildcard in script-src or default-src, " +
                      "which allows scripts from any origin and defeats the purpose of CSP. " +
                      "Specify explicit trusted sources instead.");
        }

        // WARNING: CSP report-only mode in production
        if (security.CspReportOnlyMode)
        {
            errors.Add($"WARNING: Security.{nameof(security.CspReportOnlyMode)} is enabled. The CSP policy will not be enforced, only violations will be reported. " +
                      "This is useful for testing but provides no actual protection. " +
                      "Consider enforcing the policy in production environments once testing is complete.");
        }

        // INFO: Using report-uri or report-to
        if (policyLower.Contains("report-uri") || policyLower.Contains("report-to"))
        {
            errors.Add("INFO: CSP violation reporting is configured. Ensure your reporting endpoint is properly set up to collect and monitor violations.");
        }
    }
}
