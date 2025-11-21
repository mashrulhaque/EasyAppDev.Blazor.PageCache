using System.Text;
using System.Security.Cryptography;

namespace EasyAppDev.Blazor.PageCache.Security;

/// <summary>
/// A fluent builder for constructing Content Security Policy (CSP) headers.
/// </summary>
/// <remarks>
/// <para>
/// This class provides a type-safe, fluent API for building CSP policies.
/// It supports all standard CSP directives and validates the policy syntax.
/// </para>
/// <para>
/// Example usage:
/// <code>
/// var policy = new CspBuilder()
///     .WithDefaultSrc("'self'")
///     .WithScriptSrc("'self'", "https://trusted.com")
///     .WithStyleSrc("'self'", "'unsafe-inline'")
///     .WithImgSrc("'self'", "data:", "https:")
///     .WithConnectSrc("'self'")
///     .WithFontSrc("'self'")
///     .WithObjectSrc("'none'")
///     .WithMediaSrc("'self'")
///     .WithFrameSrc("'self'")
///     .Build();
/// </code>
/// </para>
/// </remarks>
public sealed class CspBuilder
{
    private readonly Dictionary<string, List<string>> _directives = new();
    private readonly List<string> _nonces = new();

    /// <summary>
    /// Sets the default-src directive, which serves as a fallback for other fetch directives.
    /// </summary>
    /// <param name="sources">One or more source expressions (e.g., "'self'", "https://trusted.com").</param>
    /// <returns>The current builder instance for method chaining.</returns>
    public CspBuilder WithDefaultSrc(params string[] sources)
    {
        AddDirective("default-src", sources);
        return this;
    }

    /// <summary>
    /// Sets the script-src directive, which controls valid sources for JavaScript.
    /// </summary>
    /// <param name="sources">One or more source expressions.</param>
    /// <returns>The current builder instance for method chaining.</returns>
    public CspBuilder WithScriptSrc(params string[] sources)
    {
        AddDirective("script-src", sources);
        return this;
    }

    /// <summary>
    /// Sets the style-src directive, which controls valid sources for stylesheets.
    /// </summary>
    /// <param name="sources">One or more source expressions.</param>
    /// <returns>The current builder instance for method chaining.</returns>
    public CspBuilder WithStyleSrc(params string[] sources)
    {
        AddDirective("style-src", sources);
        return this;
    }

    /// <summary>
    /// Sets the img-src directive, which controls valid sources for images.
    /// </summary>
    /// <param name="sources">One or more source expressions.</param>
    /// <returns>The current builder instance for method chaining.</returns>
    public CspBuilder WithImgSrc(params string[] sources)
    {
        AddDirective("img-src", sources);
        return this;
    }

    /// <summary>
    /// Sets the connect-src directive, which controls valid sources for fetch, XHR, WebSocket, etc.
    /// </summary>
    /// <param name="sources">One or more source expressions.</param>
    /// <returns>The current builder instance for method chaining.</returns>
    public CspBuilder WithConnectSrc(params string[] sources)
    {
        AddDirective("connect-src", sources);
        return this;
    }

    /// <summary>
    /// Sets the font-src directive, which controls valid sources for fonts.
    /// </summary>
    /// <param name="sources">One or more source expressions.</param>
    /// <returns>The current builder instance for method chaining.</returns>
    public CspBuilder WithFontSrc(params string[] sources)
    {
        AddDirective("font-src", sources);
        return this;
    }

    /// <summary>
    /// Sets the object-src directive, which controls valid sources for plugins (object, embed, applet).
    /// </summary>
    /// <param name="sources">One or more source expressions.</param>
    /// <returns>The current builder instance for method chaining.</returns>
    public CspBuilder WithObjectSrc(params string[] sources)
    {
        AddDirective("object-src", sources);
        return this;
    }

    /// <summary>
    /// Sets the media-src directive, which controls valid sources for audio and video.
    /// </summary>
    /// <param name="sources">One or more source expressions.</param>
    /// <returns>The current builder instance for method chaining.</returns>
    public CspBuilder WithMediaSrc(params string[] sources)
    {
        AddDirective("media-src", sources);
        return this;
    }

    /// <summary>
    /// Sets the frame-src directive, which controls valid sources for frames and iframes.
    /// </summary>
    /// <param name="sources">One or more source expressions.</param>
    /// <returns>The current builder instance for method chaining.</returns>
    public CspBuilder WithFrameSrc(params string[] sources)
    {
        AddDirective("frame-src", sources);
        return this;
    }

    /// <summary>
    /// Sets the frame-ancestors directive, which controls valid parents that may embed the page.
    /// </summary>
    /// <param name="sources">One or more source expressions.</param>
    /// <returns>The current builder instance for method chaining.</returns>
    public CspBuilder WithFrameAncestors(params string[] sources)
    {
        AddDirective("frame-ancestors", sources);
        return this;
    }

    /// <summary>
    /// Sets the base-uri directive, which restricts URLs that can be used in a document's base element.
    /// </summary>
    /// <param name="sources">One or more source expressions.</param>
    /// <returns>The current builder instance for method chaining.</returns>
    public CspBuilder WithBaseUri(params string[] sources)
    {
        AddDirective("base-uri", sources);
        return this;
    }

    /// <summary>
    /// Sets the form-action directive, which restricts URLs to which forms can submit.
    /// </summary>
    /// <param name="sources">One or more source expressions.</param>
    /// <returns>The current builder instance for method chaining.</returns>
    public CspBuilder WithFormAction(params string[] sources)
    {
        AddDirective("form-action", sources);
        return this;
    }

    /// <summary>
    /// Sets the upgrade-insecure-requests directive, which instructs browsers to upgrade HTTP to HTTPS.
    /// </summary>
    /// <returns>The current builder instance for method chaining.</returns>
    public CspBuilder WithUpgradeInsecureRequests()
    {
        AddDirective("upgrade-insecure-requests", Array.Empty<string>());
        return this;
    }

    /// <summary>
    /// Sets the block-all-mixed-content directive, which prevents loading any HTTP content on HTTPS pages.
    /// </summary>
    /// <returns>The current builder instance for method chaining.</returns>
    public CspBuilder WithBlockAllMixedContent()
    {
        AddDirective("block-all-mixed-content", Array.Empty<string>());
        return this;
    }

    /// <summary>
    /// Sets the report-uri directive, which specifies a URI where CSP violation reports should be sent.
    /// </summary>
    /// <param name="uri">The URI to receive violation reports.</param>
    /// <returns>The current builder instance for method chaining.</returns>
    /// <remarks>
    /// Note: report-uri is deprecated in favor of report-to, but is still widely supported.
    /// Consider using both for maximum compatibility.
    /// </remarks>
    public CspBuilder WithReportUri(string uri)
    {
        if (string.IsNullOrWhiteSpace(uri))
            throw new ArgumentException("Report URI cannot be null or whitespace.", nameof(uri));

        AddDirective("report-uri", new[] { uri });
        return this;
    }

    /// <summary>
    /// Adds a custom directive to the CSP policy.
    /// </summary>
    /// <param name="directive">The directive name (e.g., "worker-src").</param>
    /// <param name="sources">One or more source expressions.</param>
    /// <returns>The current builder instance for method chaining.</returns>
    /// <remarks>
    /// Use this method to add directives not explicitly supported by the builder,
    /// or to add experimental/browser-specific directives.
    /// </remarks>
    public CspBuilder WithCustomDirective(string directive, params string[] sources)
    {
        if (string.IsNullOrWhiteSpace(directive))
            throw new ArgumentException("Directive name cannot be null or whitespace.", nameof(directive));

        ValidateDirectiveName(directive);
        AddDirective(directive, sources);
        return this;
    }

    /// <summary>
    /// Generates a cryptographically secure nonce and adds it to the specified directive.
    /// </summary>
    /// <param name="directive">The directive to add the nonce to (e.g., "script-src", "style-src").</param>
    /// <returns>The generated nonce value (base64-encoded).</returns>
    /// <remarks>
    /// <para>
    /// Nonces are one-time values that can be used to allow specific inline scripts or styles.
    /// The same nonce must be added to the script or style tag's nonce attribute.
    /// </para>
    /// <para>
    /// Example:
    /// <code>
    /// var builder = new CspBuilder();
    /// var nonce = builder.GenerateNonce("script-src");
    /// // Use nonce in HTML: &lt;script nonce="[nonce]"&gt;...&lt;/script&gt;
    /// </code>
    /// </para>
    /// <para>
    /// Note: For cached pages, nonces should be regenerated on each request for security.
    /// </para>
    /// </remarks>
    public string GenerateNonce(string directive)
    {
        if (string.IsNullOrWhiteSpace(directive))
            throw new ArgumentException("Directive name cannot be null or whitespace.", nameof(directive));

        // Generate a cryptographically secure random nonce (128 bits = 16 bytes)
        var nonceBytes = new byte[16];
        RandomNumberGenerator.Fill(nonceBytes);
        var nonce = Convert.ToBase64String(nonceBytes);

        // Add the nonce to the directive
        var nonceSource = $"'nonce-{nonce}'";
        if (!_directives.TryGetValue(directive, out var sources))
        {
            sources = new List<string>();
            _directives[directive] = sources;
        }

        sources.Add(nonceSource);
        _nonces.Add(nonce);

        return nonce;
    }

    /// <summary>
    /// Gets all nonces that have been generated for this policy.
    /// </summary>
    /// <returns>A read-only list of nonce values.</returns>
    public IReadOnlyList<string> GetNonces() => _nonces.AsReadOnly();

    /// <summary>
    /// Builds the CSP policy string.
    /// </summary>
    /// <returns>A properly formatted CSP policy string.</returns>
    /// <exception cref="InvalidOperationException">Thrown if the policy is invalid or empty.</exception>
    public string Build()
    {
        if (_directives.Count == 0)
        {
            throw new InvalidOperationException(
                "Cannot build an empty CSP policy. Add at least one directive.");
        }

        var sb = new StringBuilder();
        foreach (var kvp in _directives)
        {
            sb.Append(kvp.Key);

            if (kvp.Value.Count > 0)
            {
                sb.Append(' ');
                sb.Append(string.Join(" ", kvp.Value));
            }

            sb.Append("; ");
        }

        var policy = sb.ToString();
        ValidatePolicy(policy);

        return policy;
    }

    /// <summary>
    /// Adds a directive with its sources to the internal dictionary.
    /// </summary>
    private void AddDirective(string directive, string[] sources)
    {
        if (sources == null)
            throw new ArgumentException("Sources array cannot be null.", nameof(sources));

        if (!_directives.TryGetValue(directive, out var sourceList))
        {
            sourceList = new List<string>();
            _directives[directive] = sourceList;
        }
        else
        {
            // Clear existing sources - last call wins
            sourceList.Clear();
        }

        foreach (var source in sources)
        {
            if (string.IsNullOrWhiteSpace(source))
                throw new ArgumentException($"Source value cannot be null or whitespace for directive '{directive}'.");

            ValidateSourceExpression(source, directive);
            sourceList.Add(source);
        }
    }

    /// <summary>
    /// Validates a directive name.
    /// </summary>
    private static void ValidateDirectiveName(string directive)
    {
        // Directive names should only contain lowercase letters, numbers, and hyphens
        foreach (var c in directive)
        {
            if (!char.IsLower(c) && !char.IsDigit(c) && c != '-')
            {
                throw new ArgumentException(
                    $"Invalid directive name '{directive}'. Directive names must contain only lowercase letters, digits, and hyphens.",
                    nameof(directive));
            }
        }
    }

    /// <summary>
    /// Validates a source expression.
    /// </summary>
    private static void ValidateSourceExpression(string source, string directive)
    {
        // Check for obvious injection attempts
        if (source.Contains(';') || source.Contains('\n') || source.Contains('\r'))
        {
            throw new ArgumentException(
                $"Invalid source expression '{source}' for directive '{directive}'. " +
                "Source expressions cannot contain semicolons or newlines.",
                nameof(source));
        }

        // Validate keyword sources are properly quoted
        var keywords = new[] { "none", "self", "unsafe-inline", "unsafe-eval", "strict-dynamic",
            "unsafe-hashes", "report-sample", "unsafe-allow-redirects" };

        foreach (var keyword in keywords)
        {
            if (source.Equals(keyword, StringComparison.OrdinalIgnoreCase))
            {
                throw new ArgumentException(
                    $"Keyword '{keyword}' must be single-quoted ('{keyword}') in directive '{directive}'.",
                    nameof(source));
            }
        }

        // Validate nonce format
        if (source.StartsWith("nonce-", StringComparison.OrdinalIgnoreCase))
        {
            throw new ArgumentException(
                $"Nonce '{source}' must be single-quoted ('nonce-...') in directive '{directive}'. " +
                "Use GenerateNonce() method instead.",
                nameof(source));
        }

        // Validate hash format
        if (source.StartsWith("sha256-", StringComparison.OrdinalIgnoreCase) ||
            source.StartsWith("sha384-", StringComparison.OrdinalIgnoreCase) ||
            source.StartsWith("sha512-", StringComparison.OrdinalIgnoreCase))
        {
            throw new ArgumentException(
                $"Hash '{source}' must be single-quoted ('sha256-...', 'sha384-...', or 'sha512-...') in directive '{directive}'.",
                nameof(source));
        }
    }

    /// <summary>
    /// Validates the complete CSP policy.
    /// </summary>
    private static void ValidatePolicy(string policy)
    {
        // Check policy length (most browsers have limits around 4KB-8KB)
        // Using a conservative limit of 4KB to ensure compatibility
        const int maxPolicyLength = 4096;

        if (policy.Length > maxPolicyLength)
        {
            throw new InvalidOperationException(
                $"CSP policy is too long ({policy.Length} characters). " +
                $"Maximum allowed is {maxPolicyLength} characters. Consider simplifying the policy.");
        }

        // Ensure policy doesn't contain obvious syntax errors
        if (policy.Contains(";;") || policy.EndsWith("; ; "))
        {
            throw new InvalidOperationException(
                "CSP policy contains syntax errors (consecutive semicolons).");
        }
    }

    /// <summary>
    /// Creates a strict CSP policy suitable for modern applications.
    /// </summary>
    /// <param name="allowUnsafeInline">Whether to allow unsafe-inline for scripts and styles (not recommended).</param>
    /// <returns>A CspBuilder instance with a strict policy pre-configured.</returns>
    /// <remarks>
    /// This creates a strict CSP policy with:
    /// <list type="bullet">
    /// <item>default-src 'self'</item>
    /// <item>script-src 'self' (with 'unsafe-inline' if allowUnsafeInline is true)</item>
    /// <item>style-src 'self' (with 'unsafe-inline' if allowUnsafeInline is true)</item>
    /// <item>img-src 'self' data: https:</item>
    /// <item>font-src 'self'</item>
    /// <item>connect-src 'self'</item>
    /// <item>object-src 'none'</item>
    /// <item>base-uri 'self'</item>
    /// <item>form-action 'self'</item>
    /// <item>frame-ancestors 'none'</item>
    /// <item>upgrade-insecure-requests</item>
    /// </list>
    /// </remarks>
    public static CspBuilder CreateStrict(bool allowUnsafeInline = false)
    {
        var builder = new CspBuilder()
            .WithDefaultSrc("'self'")
            .WithImgSrc("'self'", "data:", "https:")
            .WithFontSrc("'self'")
            .WithConnectSrc("'self'")
            .WithObjectSrc("'none'")
            .WithBaseUri("'self'")
            .WithFormAction("'self'")
            .WithFrameAncestors("'none'")
            .WithUpgradeInsecureRequests();

        if (allowUnsafeInline)
        {
            builder
                .WithScriptSrc("'self'", "'unsafe-inline'")
                .WithStyleSrc("'self'", "'unsafe-inline'");
        }
        else
        {
            builder
                .WithScriptSrc("'self'")
                .WithStyleSrc("'self'");
        }

        return builder;
    }

    /// <summary>
    /// Creates a relaxed CSP policy suitable for legacy applications or development.
    /// </summary>
    /// <returns>A CspBuilder instance with a relaxed policy pre-configured.</returns>
    /// <remarks>
    /// This creates a more permissive CSP policy with:
    /// <list type="bullet">
    /// <item>default-src 'self'</item>
    /// <item>script-src 'self' 'unsafe-inline' 'unsafe-eval'</item>
    /// <item>style-src 'self' 'unsafe-inline'</item>
    /// <item>img-src 'self' data: https:</item>
    /// <item>font-src 'self' data:</item>
    /// <item>connect-src 'self'</item>
    /// </list>
    /// Warning: This policy is less secure due to 'unsafe-inline' and 'unsafe-eval'.
    /// </remarks>
    public static CspBuilder CreateRelaxed()
    {
        return new CspBuilder()
            .WithDefaultSrc("'self'")
            .WithScriptSrc("'self'", "'unsafe-inline'", "'unsafe-eval'")
            .WithStyleSrc("'self'", "'unsafe-inline'")
            .WithImgSrc("'self'", "data:", "https:")
            .WithFontSrc("'self'", "data:")
            .WithConnectSrc("'self'");
    }

    /// <summary>
    /// Creates a CSP policy optimized for Blazor Server and WebAssembly applications.
    /// </summary>
    /// <param name="enableSignalR">Whether to enable WebSocket connections for SignalR (Blazor Server).</param>
    /// <returns>A CspBuilder instance with a Blazor-optimized policy pre-configured.</returns>
    /// <remarks>
    /// <para>
    /// This creates a CSP policy specifically tailored for Blazor applications with:
    /// </para>
    /// <list type="bullet">
    /// <item>default-src 'self'</item>
    /// <item>script-src 'self' 'unsafe-inline' - Required for Blazor's inline scripts</item>
    /// <item>style-src 'self' 'unsafe-inline' - Required for Blazor's scoped CSS</item>
    /// <item>img-src 'self' data: https: - Allows embedded images and external images</item>
    /// <item>font-src 'self' data: - Allows embedded fonts</item>
    /// <item>connect-src 'self' - For API calls and SignalR</item>
    /// <item>object-src 'none' - Disallow plugins</item>
    /// <item>base-uri 'self' - Restrict base tag</item>
    /// <item>form-action 'self' - Restrict form submissions</item>
    /// </list>
    /// <para>
    /// Note: Blazor currently requires 'unsafe-inline' for both scripts and styles.
    /// For enhanced security, consider using nonces with GenerateNonce() method.
    /// </para>
    /// </remarks>
    public static CspBuilder CreateBlazorDefault(bool enableSignalR = true)
    {
        var builder = new CspBuilder()
            .WithDefaultSrc("'self'")
            .WithScriptSrc("'self'", "'unsafe-inline'")
            .WithStyleSrc("'self'", "'unsafe-inline'")
            .WithImgSrc("'self'", "data:", "https:")
            .WithFontSrc("'self'", "data:")
            .WithObjectSrc("'none'")
            .WithBaseUri("'self'")
            .WithFormAction("'self'");

        if (enableSignalR)
        {
            // Blazor Server uses WebSockets for SignalR, which requires connect-src
            // to include 'self' and potentially wss: for secure WebSocket connections
            builder.WithConnectSrc("'self'", "wss:");
        }
        else
        {
            builder.WithConnectSrc("'self'");
        }

        return builder;
    }

    /// <summary>
    /// Creates a very strict CSP policy suitable for modern applications with highest security requirements.
    /// </summary>
    /// <returns>A pre-built CSP policy string.</returns>
    /// <remarks>
    /// <para>
    /// This creates the most restrictive CSP policy:
    /// </para>
    /// <list type="bullet">
    /// <item>default-src 'self'</item>
    /// <item>script-src 'self' - No inline scripts allowed</item>
    /// <item>style-src 'self' - No inline styles allowed</item>
    /// <item>img-src 'self' data: - Only self and data URIs</item>
    /// <item>font-src 'self' - Only fonts from same origin</item>
    /// <item>connect-src 'self' - Only connections to same origin</item>
    /// <item>object-src 'none' - No plugins</item>
    /// <item>media-src 'none' - No audio/video</item>
    /// <item>frame-src 'none' - No frames</item>
    /// <item>base-uri 'self' - Restrict base tag</item>
    /// <item>form-action 'self' - Restrict form submissions</item>
    /// <item>frame-ancestors 'none' - Cannot be embedded</item>
    /// <item>upgrade-insecure-requests - Force HTTPS</item>
    /// <item>block-all-mixed-content - Block HTTP on HTTPS</item>
    /// </list>
    /// <para>
    /// This policy provides maximum security but may not work with all applications.
    /// Test thoroughly before deploying to production.
    /// </para>
    /// </remarks>
    public static string Strict()
    {
        return new CspBuilder()
            .WithDefaultSrc("'self'")
            .WithScriptSrc("'self'")
            .WithStyleSrc("'self'")
            .WithImgSrc("'self'", "data:")
            .WithFontSrc("'self'")
            .WithConnectSrc("'self'")
            .WithObjectSrc("'none'")
            .WithMediaSrc("'none'")
            .WithFrameSrc("'none'")
            .WithBaseUri("'self'")
            .WithFormAction("'self'")
            .WithFrameAncestors("'none'")
            .WithUpgradeInsecureRequests()
            .WithBlockAllMixedContent()
            .Build();
    }

    /// <summary>
    /// Creates a relaxed CSP policy suitable for typical web applications.
    /// </summary>
    /// <returns>A pre-built CSP policy string.</returns>
    /// <remarks>
    /// <para>
    /// This creates a more permissive CSP policy:
    /// </para>
    /// <list type="bullet">
    /// <item>default-src 'self'</item>
    /// <item>script-src 'self' 'unsafe-inline' 'unsafe-eval'</item>
    /// <item>style-src 'self' 'unsafe-inline'</item>
    /// <item>img-src 'self' data: https:</item>
    /// <item>font-src 'self' data:</item>
    /// <item>connect-src 'self'</item>
    /// <item>object-src 'none'</item>
    /// </list>
    /// <para>
    /// Warning: This policy includes 'unsafe-inline' and 'unsafe-eval' which reduce security.
    /// Use for development or legacy applications that require these features.
    /// </para>
    /// </remarks>
    public static string Relaxed()
    {
        return new CspBuilder()
            .WithDefaultSrc("'self'")
            .WithScriptSrc("'self'", "'unsafe-inline'", "'unsafe-eval'")
            .WithStyleSrc("'self'", "'unsafe-inline'")
            .WithImgSrc("'self'", "data:", "https:")
            .WithFontSrc("'self'", "data:")
            .WithConnectSrc("'self'")
            .WithObjectSrc("'none'")
            .Build();
    }

    /// <summary>
    /// Creates a CSP policy string optimized for Blazor Server and WebAssembly applications.
    /// </summary>
    /// <returns>A pre-built CSP policy string for Blazor applications.</returns>
    /// <remarks>
    /// <para>
    /// This creates a CSP policy specifically tailored for Blazor applications.
    /// Equivalent to calling CreateBlazorDefault().Build().
    /// </para>
    /// <para>
    /// The policy includes:
    /// </para>
    /// <list type="bullet">
    /// <item>default-src 'self'</item>
    /// <item>script-src 'self' 'unsafe-inline' - Required for Blazor's inline scripts</item>
    /// <item>style-src 'self' 'unsafe-inline' - Required for Blazor's scoped CSS</item>
    /// <item>img-src 'self' data: https:</item>
    /// <item>font-src 'self' data:</item>
    /// <item>connect-src 'self' wss: - Includes WebSocket support for Blazor Server</item>
    /// <item>object-src 'none'</item>
    /// <item>base-uri 'self'</item>
    /// <item>form-action 'self'</item>
    /// </list>
    /// <para>
    /// Note: Blazor currently requires 'unsafe-inline' for both scripts and styles.
    /// </para>
    /// </remarks>
    public static string BlazorDefault()
    {
        return CreateBlazorDefault().Build();
    }
}
