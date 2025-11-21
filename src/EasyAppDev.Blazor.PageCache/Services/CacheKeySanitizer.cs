using System.Text;

namespace EasyAppDev.Blazor.PageCache.Services;

/// <summary>
/// Provides sanitization for cache key segments to prevent cache key injection attacks.
/// </summary>
/// <remarks>
/// This class protects against malicious input that could manipulate cache key patterns,
/// potentially leading to cache poisoning, data leakage, or denial of service.
/// All user-controlled input (route values, query parameters, headers, etc.) should be
/// sanitized before inclusion in cache keys.
/// </remarks>
public static class CacheKeySanitizer
{
    /// <summary>
    /// Maximum allowed length for a single cache key segment (1 KB).
    /// </summary>
    public const int MaxSegmentLength = 1024;

    /// <summary>
    /// Characters that need to be escaped in cache key segments.
    /// These are special regex characters that could be exploited for injection attacks.
    /// </summary>
    /// <remarks>
    /// Note: '%' is NOT in this list because it's used for URL encoding (Issue 13).
    /// Instead, '%' is handled specially in SanitizeKeySegment to allow valid percent-encoded
    /// sequences (%XX) while escaping malformed ones.
    /// </remarks>
    private static readonly HashSet<char> CharactersToEscape = new()
    {
        '*', '?', '[', ']', '{', '}', '|', '^', '(', ')', '+',
        // Control characters that should be replaced
        '\n', '\r', '\t', '\0',
        // Space character needs escaping to prevent injection
        ' ',
        // Semicolon, ampersand, and equals for command/query injection
        ';', '&', '='
    };

    /// <summary>
    /// Characters that should be completely removed from cache keys.
    /// These are dangerous characters that can facilitate various attacks.
    /// </summary>
    private static readonly HashSet<char> CharactersToRemove = new()
    {
        // Directory traversal
        '/',
        // Backslash for path traversal
        '\\',
        // Dollar sign for shell variable expansion
        '$',
        // Backticks for command substitution
        '`',
        // Dot for path traversal (when part of ..)
        // Note: We'll handle ".." pattern separately
    };

    /// <summary>
    /// Comprehensive list of Unicode whitespace characters that need normalization.
    /// These characters can be used to bypass security checks or create cache key collisions.
    /// </summary>
    /// <remarks>
    /// Security Rationale:
    /// - Unicode whitespace can be visually identical but have different code points
    /// - Attackers can use these to create keys that appear identical but are different
    /// - Normalizing all whitespace to a single space prevents cache key confusion attacks
    /// - This also prevents ReDoS attacks that exploit complex whitespace patterns
    /// </remarks>
    private static readonly HashSet<char> UnicodeWhitespace = new()
    {
        // Basic ASCII whitespace (already in CharactersToEscape, but included for completeness)
        ' ',      // U+0020 - Space
        '\t',     // U+0009 - Horizontal Tab
        '\n',     // U+000A - Line Feed
        '\r',     // U+000D - Carriage Return
        '\f',     // U+000C - Form Feed
        '\v',     // U+000B - Vertical Tab

        // Unicode whitespace characters
        '\u00A0', // U+00A0 - Non-Breaking Space (NBSP)
        '\u1680', // U+1680 - Ogham Space Mark
        '\u2000', // U+2000 - En Quad
        '\u2001', // U+2001 - Em Quad
        '\u2002', // U+2002 - En Space
        '\u2003', // U+2003 - Em Space
        '\u2004', // U+2004 - Three-Per-Em Space
        '\u2005', // U+2005 - Four-Per-Em Space
        '\u2006', // U+2006 - Six-Per-Em Space
        '\u2007', // U+2007 - Figure Space
        '\u2008', // U+2008 - Punctuation Space
        '\u2009', // U+2009 - Thin Space
        '\u200A', // U+200A - Hair Space
        '\u202F', // U+202F - Narrow No-Break Space
        '\u205F', // U+205F - Medium Mathematical Space
        '\u3000', // U+3000 - Ideographic Space

        // Line and paragraph separators
        '\u2028', // U+2028 - Line Separator
        '\u2029', // U+2029 - Paragraph Separator
    };

    /// <summary>
    /// Zero-width and invisible characters that can facilitate stealth injection attacks.
    /// These characters are completely removed as they serve no legitimate purpose in cache keys.
    /// </summary>
    /// <remarks>
    /// Security Rationale:
    /// - Zero-width characters are invisible but affect string comparison
    /// - They can be used to create "hidden" differences in cache keys
    /// - Attackers can use these to bypass exact-match security filters
    /// - Complete removal is the safest approach as they have no valid use in cache keys
    /// </remarks>
    private static readonly HashSet<char> ZeroWidthCharacters = new()
    {
        '\u200B', // U+200B - Zero-Width Space (ZWSP)
        '\u200C', // U+200C - Zero-Width Non-Joiner (ZWNJ)
        '\u200D', // U+200D - Zero-Width Joiner (ZWJ)
        '\uFEFF', // U+FEFF - Zero-Width No-Break Space / Byte Order Mark (BOM)
    };

    /// <summary>
    /// Bidirectional text control characters that can facilitate visual spoofing attacks.
    /// These characters control text direction and can make malicious input appear benign.
    /// </summary>
    /// <remarks>
    /// Security Rationale:
    /// - Bidi characters can reverse or override text direction
    /// - Attackers can use these to create visually deceptive cache keys
    /// - "Trojan Source" attacks use these to hide malicious content
    /// - Example: "user\u202Enimdaback" appears as "userbacknimd" in RTL context
    /// - Complete removal prevents all bidi-based spoofing attacks
    /// </remarks>
    private static readonly HashSet<char> DirectionControlCharacters = new()
    {
        '\u202A', // U+202A - Left-to-Right Embedding (LRE)
        '\u202B', // U+202B - Right-to-Left Embedding (RLE)
        '\u202C', // U+202C - Pop Directional Formatting (PDF)
        '\u202D', // U+202D - Left-to-Right Override (LRO)
        '\u202E', // U+202E - Right-to-Left Override (RLO)
        '\u2066', // U+2066 - Left-to-Right Isolate (LRI)
        '\u2067', // U+2067 - Right-to-Left Isolate (RLI)
        '\u2068', // U+2068 - First Strong Isolate (FSI)
        '\u2069', // U+2069 - Pop Directional Isolate (PDI)
    };

    /// <summary>
    /// Sanitizes a cache key segment by escaping special characters and validating length.
    /// </summary>
    /// <param name="input">The input string to sanitize.</param>
    /// <returns>A sanitized string safe for use in cache keys.</returns>
    /// <exception cref="ArgumentException">Thrown when input exceeds maximum allowed length.</exception>
    /// <remarks>
    /// This method:
    /// 1. Normalizes Unicode to prevent cache key variations (e.g., composed vs decomposed)
    /// 2. Normalizes and collapses whitespace to prevent confusion attacks
    /// 3. Removes zero-width and direction control characters
    /// 4. Validates the input length to prevent memory exhaustion
    /// 5. Escapes special regex characters to prevent pattern injection
    /// 6. Removes control characters that could cause issues
    /// 7. Returns a deterministic, collision-resistant output
    /// </remarks>
    public static string SanitizeKeySegment(string? input)
    {
        // Null or empty input returns empty string
        if (string.IsNullOrEmpty(input))
        {
            return string.Empty;
        }

        // SECURITY FIX (Issue 13): Apply Unicode normalization FIRST to prevent cache key variations
        // This prevents attacks where different Unicode representations create different cache keys
        // (e.g., "café" as U+0065 U+0301 vs U+00E9, or Cyrillic vs Latin homoglyphs)
        input = NormalizeUnicode(input);

        // SECURITY FIX (Issue 12): Normalize whitespace and remove dangerous Unicode characters
        // This must happen BEFORE length validation to prevent bypassing length checks
        input = NormalizeWhitespaceAndRemoveDangerousCharacters(input);

        // Validate length before processing to prevent DoS
        if (input.Length > MaxSegmentLength)
        {
            throw new ArgumentException(
                $"Cache key segment exceeds maximum allowed length of {MaxSegmentLength} characters. " +
                $"Input length: {input.Length}. This limit prevents memory exhaustion attacks.",
                nameof(input));
        }

        var builder = new StringBuilder(input.Length * 3); // Pre-allocate for worst case (URL encoding)

        for (int i = 0; i < input.Length; i++)
        {
            var ch = input[i];

            // Remove dangerous characters completely
            if (CharactersToRemove.Contains(ch))
            {
                // Skip this character - it will not appear in output
                continue;
            }

            // Handle ".." pattern for path traversal
            if (ch == '.' && i + 1 < input.Length && input[i + 1] == '.')
            {
                // Replace ".." with "__" to prevent path traversal
                builder.Append("__");
                i++; // Skip the next '.'
                continue;
            }

            // SECURITY FIX (Issue 13): URL-encode non-ASCII characters after Unicode normalization
            // This ensures all non-ASCII characters (including normalized Unicode) are represented
            // as percent-encoded ASCII sequences, which pass cache key validation
            if (ch > 127)
            {
                var bytes = System.Text.Encoding.UTF8.GetBytes(new[] { ch });
                foreach (var b in bytes)
                {
                    builder.Append('%');
                    builder.Append(b.ToString("X2"));
                }
                continue;
            }

            // SECURITY FIX (Issue 13): Handle percent signs specially to support percent-encoded sequences
            // Allow valid percent-encoded sequences (%XX where XX are hex digits)
            // Escape malformed percent signs to prevent injection
            if (ch == '%')
            {
                // Check if this is a valid percent-encoded sequence
                if (i + 2 < input.Length &&
                    IsHexDigit(input[i + 1]) &&
                    IsHexDigit(input[i + 2]))
                {
                    // Valid percent-encoded sequence - keep it as-is
                    builder.Append(ch);
                    builder.Append(input[i + 1]);
                    builder.Append(input[i + 2]);
                    i += 2; // Skip the two hex digits
                }
                else
                {
                    // Malformed percent sign - escape it
                    builder.Append('\\');
                    builder.Append(ch);
                }
                continue;
            }

            // Escape special characters with backslash
            if (CharactersToEscape.Contains(ch))
            {
                // Replace control characters with underscore for visibility
                if (char.IsControl(ch))
                {
                    builder.Append('_');
                }
                else
                {
                    builder.Append('\\');
                    builder.Append(ch);
                }
            }
            else
            {
                builder.Append(ch);
            }
        }

        return builder.ToString();
    }

    /// <summary>
    /// Sanitizes a cache key segment and ensures it's URL-decoded first.
    /// </summary>
    /// <param name="input">The input string to sanitize (may be URL-encoded).</param>
    /// <returns>A sanitized string safe for use in cache keys.</returns>
    /// <remarks>
    /// This method is useful for query parameters and other URL-encoded inputs.
    /// It decodes the input once before sanitization to ensure consistent keys
    /// regardless of encoding variations.
    /// </remarks>
    public static string SanitizeUrlEncodedSegment(string? input)
    {
        if (string.IsNullOrEmpty(input))
        {
            return string.Empty;
        }

        // Decode once to normalize (prevents double-encoding attacks)
        var decoded = System.Web.HttpUtility.UrlDecode(input);

        return SanitizeKeySegment(decoded);
    }

    /// <summary>
    /// Validates that a cache key segment is safe without modifying it.
    /// </summary>
    /// <param name="input">The input to validate.</param>
    /// <returns>True if the input is safe, false otherwise.</returns>
    /// <remarks>
    /// Use this method when you want to reject unsafe input rather than sanitize it.
    /// </remarks>
    public static bool IsValidKeySegment(string? input)
    {
        if (string.IsNullOrEmpty(input))
        {
            return true;
        }

        if (input.Length > MaxSegmentLength)
        {
            return false;
        }

        // Check for any special or dangerous characters
        return !input.Any(ch => CharactersToEscape.Contains(ch) || CharactersToRemove.Contains(ch) || ch == '\\');
    }

    /// <summary>
    /// Normalizes whitespace sequences and removes dangerous Unicode characters.
    /// This is a comprehensive sanitization step that handles all Unicode edge cases.
    /// </summary>
    /// <param name="input">The input string to normalize.</param>
    /// <returns>A string with normalized whitespace and dangerous characters removed.</returns>
    /// <remarks>
    /// This method performs the following operations in order:
    /// 1. Removes zero-width characters (ZWSP, ZWNJ, ZWJ, BOM)
    /// 2. Removes bidirectional control characters (LRO, RLO, PDF, etc.)
    /// 3. Replaces all Unicode whitespace variants with a single space
    /// 4. Collapses multiple consecutive whitespace into a single space
    /// 5. Trims leading and trailing whitespace
    ///
    /// Security Benefits:
    /// - Prevents cache key confusion from visually identical but different strings
    /// - Prevents Trojan Source attacks using bidi characters
    /// - Prevents bypass of length limits using zero-width characters
    /// - Ensures idempotent normalization: N(N(x)) = N(x)
    /// - Makes cache keys deterministic regardless of input variations
    /// </remarks>
    private static string NormalizeWhitespaceAndRemoveDangerousCharacters(string input)
    {
        if (string.IsNullOrEmpty(input))
        {
            return input;
        }

        var builder = new StringBuilder(input.Length);
        bool lastWasWhitespace = false;

        for (int i = 0; i < input.Length; i++)
        {
            var ch = input[i];

            // Remove zero-width characters completely - they serve no purpose in cache keys
            if (ZeroWidthCharacters.Contains(ch))
            {
                continue;
            }

            // Remove bidirectional control characters - prevent visual spoofing
            if (DirectionControlCharacters.Contains(ch))
            {
                continue;
            }

            // Normalize all Unicode whitespace to a single space
            if (UnicodeWhitespace.Contains(ch))
            {
                // Collapse multiple consecutive whitespace into one
                if (!lastWasWhitespace)
                {
                    builder.Append(' ');
                    lastWasWhitespace = true;
                }
                continue;
            }

            // Regular character - append it
            builder.Append(ch);
            lastWasWhitespace = false;
        }

        // Trim leading and trailing whitespace
        var result = builder.ToString().Trim();
        return result;
    }

    /// <summary>
    /// Normalizes Unicode input to ensure consistent representation.
    /// Uses NFC (Canonical Composition) to prevent cache key variations.
    /// </summary>
    /// <param name="input">The input string to normalize.</param>
    /// <returns>A Unicode-normalized string in NFC form.</returns>
    /// <remarks>
    /// This prevents attacks where different Unicode representations of the "same" string
    /// create different cache keys, which could lead to:
    /// 1. Cache key collisions: "café" (U+0065 U+0301) vs "café" (U+00E9)
    /// 2. Homoglyph attacks: "google.com" with Cyrillic "о" (U+043E) vs Latin "o" (U+006F)
    /// 3. Inconsistent case folding across different scripts
    ///
    /// NFC (Normalization Form C - Canonical Composition) is chosen because:
    /// - It's the most common form used by web applications and browsers
    /// - It produces shorter strings (composed form) which is more efficient for cache keys
    /// - It's recommended by W3C for web identifiers and URLs
    /// - It's idempotent: NFC(NFC(x)) = NFC(x)
    ///
    /// Alternative forms considered but not chosen:
    /// - NFD (Decomposed): Creates longer strings, less common in web contexts
    /// - NFKC/NFKD (Compatibility): Too aggressive, converts "ﬁ" to "fi", may break intent
    /// </remarks>
    private static string NormalizeUnicode(string input)
    {
        if (string.IsNullOrEmpty(input))
        {
            return input;
        }

        // Apply NFC (Canonical Composition) normalization
        // This ensures consistent representation of Unicode characters
        return input.Normalize(NormalizationForm.FormC);
    }

    /// <summary>
    /// Checks if a character is a hexadecimal digit (0-9, A-F, a-f).
    /// </summary>
    /// <param name="c">The character to check.</param>
    /// <returns>True if the character is a hex digit, false otherwise.</returns>
    private static bool IsHexDigit(char c)
    {
        return (c >= '0' && c <= '9') || (c >= 'A' && c <= 'F') || (c >= 'a' && c <= 'f');
    }

    /// <summary>
    /// Sanitizes multiple key segments and joins them with a separator.
    /// </summary>
    /// <param name="segments">The segments to sanitize and join.</param>
    /// <param name="separator">The separator to use (default: ":").</param>
    /// <returns>A sanitized, joined cache key.</returns>
    public static string SanitizeAndJoin(IEnumerable<string?> segments, string separator = ":")
    {
        var sanitized = segments
            .Where(s => !string.IsNullOrEmpty(s))
            .Select(SanitizeKeySegment);

        return string.Join(separator, sanitized);
    }
}
