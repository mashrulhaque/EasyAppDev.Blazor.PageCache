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

        // NOTE: Security warnings have been removed from validation errors.
        // Warnings about ExposeDebugHeaders, disabled validations, etc. are informational
        // and should not prevent the application from starting.
        // These warnings will be logged by the application at runtime instead of blocking startup.
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

        // NOTE: CSP warnings and recommendations have been removed from validation errors.
        // These include warnings about:
        // - Missing semicolon at end of policy
        // - Unrecognized directives
        // - Missing default-src directive
        // - Use of 'unsafe-inline' and 'unsafe-eval'
        // - Use of '*' wildcard
        // - CSP report-only mode
        // - CSP violation reporting configuration
        // These are informational messages that should not prevent application startup.
    }
}
