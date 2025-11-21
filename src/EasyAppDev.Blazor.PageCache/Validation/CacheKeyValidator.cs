using System.Text.RegularExpressions;

namespace EasyAppDev.Blazor.PageCache.Validation;

/// <summary>
/// Validates cache keys for security and correctness.
/// </summary>
/// <remarks>
/// <para>
/// This validator ensures that cache keys meet security requirements and prevent various attacks:
/// </para>
/// <list type="bullet">
/// <item><description>Length validation - prevents memory exhaustion (max 2KB)</description></item>
/// <item><description>Character set validation - ensures only safe characters are used</description></item>
/// <item><description>Suspicious pattern detection - identifies potential injection attempts</description></item>
/// <item><description>Control character detection - prevents encoding attacks</description></item>
/// </list>
/// <para>
/// All validation failures provide clear, actionable error messages to help diagnose issues.
/// </para>
/// </remarks>
public static class CacheKeyValidator
{
    /// <summary>
    /// Maximum allowed cache key length in bytes (2KB).
    /// </summary>
    /// <remarks>
    /// This limit prevents memory exhaustion attacks where attackers try to create
    /// excessively long cache keys. 2KB is sufficient for practical cache keys while
    /// providing protection against abuse.
    /// </remarks>
    public const int MaxKeyLengthBytes = 2048;

    /// <summary>
    /// Regex pattern for validating safe cache key characters.
    /// Allows: alphanumeric, hyphens, underscores, colons, periods, forward slashes, backslashes, escape sequences, and percent-encoded sequences.
    /// </summary>
    /// <remarks>
    /// This pattern is intentionally restrictive to prevent injection attacks.
    /// Backslashes and escaped sequences (backslash followed by any printable ASCII character) are allowed to support
    /// sanitized input from CacheKeySanitizer.
    /// Percent-encoded sequences (%XX where XX are hex digits) are allowed to support Unicode normalization (Issue 13).
    /// The pattern uses alternation to allow either safe characters OR escape sequences (\x where x is printable) OR percent-encoded sequences (%XX).
    /// </remarks>
    private static readonly Regex SafeCharacterPattern = new(
        @"^(?:[a-zA-Z0-9\-_:./\\]|\\[\x20-\x7E]|%[0-9A-Fa-f]{2})+$",
        RegexOptions.Compiled,
        TimeSpan.FromMilliseconds(100));

    /// <summary>
    /// Patterns that indicate potential cache key injection attempts or malicious input.
    /// </summary>
    private static readonly Regex[] SuspiciousPatterns = new[]
    {
        // Multiple consecutive special characters (may indicate injection attempt)
        new Regex(@"[\\/]{3,}", RegexOptions.Compiled, TimeSpan.FromMilliseconds(50)),

        // Repeated escape sequences (may indicate encoding attack)
        new Regex(@"(\\\\){5,}", RegexOptions.Compiled, TimeSpan.FromMilliseconds(50)),

        // SQL-like patterns (should never appear in cache keys)
        new Regex(@"(?i)(union\s+select|drop\s+table|exec\s*\(|script\s*>)", RegexOptions.Compiled | RegexOptions.IgnoreCase, TimeSpan.FromMilliseconds(50)),

        // Path traversal patterns
        new Regex(@"\.\./|\.\.\\", RegexOptions.Compiled, TimeSpan.FromMilliseconds(50)),

        // Null byte injection (even if escaped)
        new Regex(@"\\0|%00|\u0000", RegexOptions.Compiled, TimeSpan.FromMilliseconds(50)),

        // Excessive colons (may indicate namespace confusion)
        new Regex(@":{5,}", RegexOptions.Compiled, TimeSpan.FromMilliseconds(50))
    };

    /// <summary>
    /// Validates a cache key for security and correctness.
    /// </summary>
    /// <param name="cacheKey">The cache key to validate.</param>
    /// <returns>A <see cref="CacheKeyValidationResult"/> indicating whether the key is valid.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="cacheKey"/> is null.</exception>
    /// <remarks>
    /// <para>
    /// This method performs comprehensive validation including:
    /// </para>
    /// <list type="number">
    /// <item><description>Null/empty check</description></item>
    /// <item><description>Length validation (max 2KB)</description></item>
    /// <item><description>Character set validation (alphanumeric + safe chars)</description></item>
    /// <item><description>Control character detection</description></item>
    /// <item><description>Suspicious pattern detection</description></item>
    /// </list>
    /// <para>
    /// All validation failures include detailed error messages for debugging.
    /// </para>
    /// </remarks>
    public static CacheKeyValidationResult Validate(string cacheKey)
    {
        if (cacheKey == null)
        {
            return CacheKeyValidationResult.Failure(
                "Cache key cannot be null.",
                CacheKeyValidationError.NullOrEmpty);
        }

        // Validate not empty or whitespace
        if (string.IsNullOrWhiteSpace(cacheKey))
        {
            return CacheKeyValidationResult.Failure(
                "Cache key cannot be empty or whitespace.",
                CacheKeyValidationError.NullOrEmpty);
        }

        // Validate length (use UTF-8 byte count for accurate size)
        var byteCount = System.Text.Encoding.UTF8.GetByteCount(cacheKey);
        if (byteCount > MaxKeyLengthBytes)
        {
            return CacheKeyValidationResult.Failure(
                $"Cache key exceeds maximum allowed length of {MaxKeyLengthBytes} bytes. " +
                $"Actual size: {byteCount} bytes ({cacheKey.Length} characters). " +
                $"This limit prevents memory exhaustion attacks.",
                CacheKeyValidationError.ExceedsMaxLength,
                new Dictionary<string, string>
                {
                    ["MaxLengthBytes"] = MaxKeyLengthBytes.ToString(),
                    ["ActualLengthBytes"] = byteCount.ToString(),
                    ["ActualLengthChars"] = cacheKey.Length.ToString()
                });
        }

        // Check for control characters BEFORE character set validation
        // Control characters should return ContainsControlCharacters error type
        var controlChars = cacheKey.Where(char.IsControl).ToArray();
        if (controlChars.Length > 0)
        {
            return CacheKeyValidationResult.Failure(
                $"Cache key contains control characters which are not allowed. " +
                $"Control characters found: {string.Join(", ", controlChars.Select(c => $"U+{(int)c:X4}"))}",
                CacheKeyValidationError.ContainsControlCharacters,
                new Dictionary<string, string>
                {
                    ["ControlCharacters"] = string.Join(", ", controlChars.Select(c => $"U+{(int)c:X4}"))
                });
        }

        // Check for suspicious patterns BEFORE character set validation
        // This ensures that patterns like "%00" are caught as suspicious rather than just invalid characters
        foreach (var pattern in SuspiciousPatterns)
        {
            try
            {
                var match = pattern.Match(cacheKey);
                if (match.Success)
                {
                    return CacheKeyValidationResult.Failure(
                        $"Cache key contains suspicious pattern that may indicate an injection attempt or malicious input. " +
                        $"Pattern detected: '{match.Value}'. If this is legitimate, consider sanitizing the input before generating the cache key.",
                        CacheKeyValidationError.SuspiciousPattern,
                        new Dictionary<string, string>
                        {
                            ["DetectedPattern"] = match.Value.Length > 50 ? match.Value.Substring(0, 50) + "..." : match.Value,
                            ["PatternPosition"] = match.Index.ToString()
                        });
                }
            }
            catch (RegexMatchTimeoutException)
            {
                // If a suspicious pattern regex times out, treat it as suspicious
                return CacheKeyValidationResult.Failure(
                    "Cache key validation timed out during suspicious pattern detection. The key may contain malicious patterns.",
                    CacheKeyValidationError.ValidationTimeout);
            }
        }

        // Validate character set
        try
        {
            if (!SafeCharacterPattern.IsMatch(cacheKey))
            {
                var invalidChars = GetInvalidCharacters(cacheKey);
                return CacheKeyValidationResult.Failure(
                    $"Cache key contains invalid characters. Only alphanumeric characters, " +
                    $"hyphens, underscores, colons, periods, forward slashes, backslashes, " +
                    $"and properly escaped characters are allowed. " +
                    $"Invalid characters found: {string.Join(", ", invalidChars.Select(c => $"'{c}' (U+{(int)c:X4})"))}",
                    CacheKeyValidationError.InvalidCharacters,
                    new Dictionary<string, string>
                    {
                        ["InvalidCharacters"] = string.Join(", ", invalidChars.Select(c => $"U+{(int)c:X4}"))
                    });
            }
        }
        catch (RegexMatchTimeoutException)
        {
            // If regex times out, the key is likely malicious or malformed
            return CacheKeyValidationResult.Failure(
                "Cache key validation timed out. The key may contain patterns that are too complex to validate safely.",
                CacheKeyValidationError.ValidationTimeout);
        }

        return CacheKeyValidationResult.Success();
    }

    /// <summary>
    /// Validates a cache key and throws an exception if validation fails.
    /// </summary>
    /// <param name="cacheKey">The cache key to validate.</param>
    /// <param name="parameterName">The parameter name to include in the exception (optional).</param>
    /// <exception cref="ArgumentException">Thrown when validation fails.</exception>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="cacheKey"/> is null.</exception>
    /// <remarks>
    /// Use this method when you want to fail fast on invalid cache keys.
    /// For non-throwing validation, use <see cref="Validate"/> instead.
    /// </remarks>
    public static void ValidateAndThrow(string cacheKey, string? parameterName = null)
    {
        var result = Validate(cacheKey);

        if (!result.IsValid)
        {
            var errorMessage = result.ErrorMessage;
            if (result.ErrorDetails != null && result.ErrorDetails.Count > 0)
            {
                var details = string.Join(", ", result.ErrorDetails.Select(kvp => $"{kvp.Key}={kvp.Value}"));
                errorMessage += $" Details: {details}";
            }

            if (result.ErrorType == CacheKeyValidationError.NullOrEmpty)
            {
                throw new ArgumentNullException(parameterName ?? nameof(cacheKey), errorMessage);
            }

            throw new ArgumentException(errorMessage, parameterName ?? nameof(cacheKey));
        }
    }

    /// <summary>
    /// Gets a list of invalid characters in the cache key.
    /// </summary>
    /// <remarks>
    /// This method identifies characters that are not valid in cache keys, excluding those that
    /// are part of valid escape sequences (backslash followed by printable ASCII) or percent-encoded sequences (%XX).
    /// </remarks>
    private static char[] GetInvalidCharacters(string cacheKey)
    {
        // Note: backslash and percent sign are used for escaping/encoding, so we need to handle them specially
        var validChars = new HashSet<char>("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_:./\\");
        var invalidChars = new List<char>();

        for (int i = 0; i < cacheKey.Length; i++)
        {
            var ch = cacheKey[i];

            // If this is a backslash followed by a printable ASCII character, it's an escape sequence - skip both
            if (ch == '\\' && i + 1 < cacheKey.Length)
            {
                var nextChar = cacheKey[i + 1];
                // Check if next char is printable ASCII (0x20-0x7E)
                if (nextChar >= 0x20 && nextChar <= 0x7E)
                {
                    i++; // Skip the escaped character
                    continue;
                }
            }

            // If this is a percent-encoded sequence (%XX where XX are hex digits), skip all three characters
            if (ch == '%' && i + 2 < cacheKey.Length)
            {
                var hex1 = cacheKey[i + 1];
                var hex2 = cacheKey[i + 2];
                if (IsHexDigit(hex1) && IsHexDigit(hex2))
                {
                    i += 2; // Skip the two hex digits
                    continue;
                }
            }

            // Otherwise, check if the character is valid
            if (!validChars.Contains(ch))
            {
                invalidChars.Add(ch);
            }
        }

        return invalidChars.Distinct().ToArray();
    }

    /// <summary>
    /// Checks if a character is a hexadecimal digit (0-9, A-F, a-f).
    /// </summary>
    private static bool IsHexDigit(char c)
    {
        return (c >= '0' && c <= '9') || (c >= 'A' && c <= 'F') || (c >= 'a' && c <= 'f');
    }
}

/// <summary>
/// Represents the result of cache key validation.
/// </summary>
public sealed class CacheKeyValidationResult
{
    /// <summary>
    /// Gets a value indicating whether the cache key is valid.
    /// </summary>
    public bool IsValid { get; init; }

    /// <summary>
    /// Gets the validation error message if validation failed.
    /// </summary>
    public string? ErrorMessage { get; init; }

    /// <summary>
    /// Gets additional details about the validation failure.
    /// </summary>
    public Dictionary<string, string>? ErrorDetails { get; init; }

    /// <summary>
    /// Gets the type of validation error.
    /// </summary>
    public CacheKeyValidationError ErrorType { get; init; }

    /// <summary>
    /// Creates a successful validation result.
    /// </summary>
    public static CacheKeyValidationResult Success() => new() { IsValid = true };

    /// <summary>
    /// Creates a failed validation result.
    /// </summary>
    /// <param name="errorMessage">The error message.</param>
    /// <param name="errorType">The type of validation error.</param>
    /// <param name="errorDetails">Additional error details (optional).</param>
    public static CacheKeyValidationResult Failure(
        string errorMessage,
        CacheKeyValidationError errorType,
        Dictionary<string, string>? errorDetails = null) =>
        new()
        {
            IsValid = false,
            ErrorMessage = errorMessage,
            ErrorType = errorType,
            ErrorDetails = errorDetails
        };
}

/// <summary>
/// Defines the types of cache key validation errors.
/// </summary>
public enum CacheKeyValidationError
{
    /// <summary>
    /// No error - validation succeeded.
    /// </summary>
    None = 0,

    /// <summary>
    /// Cache key is null or empty.
    /// </summary>
    NullOrEmpty,

    /// <summary>
    /// Cache key exceeds maximum allowed length.
    /// </summary>
    ExceedsMaxLength,

    /// <summary>
    /// Cache key contains invalid characters.
    /// </summary>
    InvalidCharacters,

    /// <summary>
    /// Cache key contains control characters.
    /// </summary>
    ContainsControlCharacters,

    /// <summary>
    /// Cache key contains suspicious patterns that may indicate an attack.
    /// </summary>
    SuspiciousPattern,

    /// <summary>
    /// Validation timed out (potential ReDoS attack).
    /// </summary>
    ValidationTimeout
}
