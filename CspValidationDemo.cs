using EasyAppDev.Blazor.PageCache.Configuration;

namespace EasyAppDev.Blazor.PageCache.Demo;

/// <summary>
/// Demonstrates CSP validation in action.
/// </summary>
public class CspValidationDemo
{
    public static void Main()
    {
        var validator = new PageCacheOptionsValidator();

        Console.WriteLine("=== CSP Configuration Validation Demo ===\n");

        // Test 1: CSP enabled but no policy
        Console.WriteLine("Test 1: CSP enabled but no policy provided");
        var options1 = new PageCacheOptions
        {
            Security = new SecurityOptions
            {
                EnableContentSecurityPolicy = true,
                ContentSecurityPolicy = null
            }
        };
        var result1 = validator.Validate(null, options1);
        Console.WriteLine($"Result: {(result1.Succeeded ? "SUCCESS" : "FAILED")}");
        if (result1.Failed)
        {
            foreach (var failure in result1.Failures)
            {
                Console.WriteLine($"  - {failure}");
            }
        }
        Console.WriteLine();

        // Test 2: Valid CSP policy
        Console.WriteLine("Test 2: Valid CSP policy");
        var options2 = new PageCacheOptions
        {
            Security = new SecurityOptions
            {
                EnableContentSecurityPolicy = true,
                ContentSecurityPolicy = "default-src 'self'; script-src 'self' https://cdn.example.com;"
            }
        };
        var result2 = validator.Validate(null, options2);
        Console.WriteLine($"Result: {(result2.Succeeded ? "SUCCESS" : "FAILED")}");
        if (result2.Failed)
        {
            foreach (var failure in result2.Failures)
            {
                Console.WriteLine($"  - {failure}");
            }
        }
        Console.WriteLine();

        // Test 3: CSP with security warnings
        Console.WriteLine("Test 3: CSP with unsafe-inline and unsafe-eval (warnings expected)");
        var options3 = new PageCacheOptions
        {
            Security = new SecurityOptions
            {
                EnableContentSecurityPolicy = true,
                ContentSecurityPolicy = "script-src 'self' 'unsafe-inline' 'unsafe-eval'",
                CspReportOnlyMode = true
            }
        };
        var result3 = validator.Validate(null, options3);
        Console.WriteLine($"Result: {(result3.Succeeded ? "SUCCESS" : "FAILED")}");
        if (result3.Failed)
        {
            foreach (var failure in result3.Failures)
            {
                Console.WriteLine($"  - {failure}");
            }
        }
        Console.WriteLine();

        // Test 4: CSP with wildcard
        Console.WriteLine("Test 4: CSP with wildcard in script-src (warning expected)");
        var options4 = new PageCacheOptions
        {
            Security = new SecurityOptions
            {
                EnableContentSecurityPolicy = true,
                ContentSecurityPolicy = "default-src 'self'; script-src *;"
            }
        };
        var result4 = validator.Validate(null, options4);
        Console.WriteLine($"Result: {(result4.Succeeded ? "SUCCESS" : "FAILED")}");
        if (result4.Failed)
        {
            foreach (var failure in result4.Failures)
            {
                Console.WriteLine($"  - {failure}");
            }
        }
        Console.WriteLine();

        // Test 5: CSP exceeding max length
        Console.WriteLine("Test 5: CSP exceeding maximum length");
        var longPolicy = new string('a', 5000);
        var options5 = new PageCacheOptions
        {
            Security = new SecurityOptions
            {
                EnableContentSecurityPolicy = true,
                ContentSecurityPolicy = longPolicy
            }
        };
        var result5 = validator.Validate(null, options5);
        Console.WriteLine($"Result: {(result5.Succeeded ? "SUCCESS" : "FAILED")}");
        if (result5.Failed)
        {
            foreach (var failure in result5.Failures)
            {
                Console.WriteLine($"  - {failure}");
            }
        }
    }
}
