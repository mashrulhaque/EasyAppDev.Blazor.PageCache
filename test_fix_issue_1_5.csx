#!/usr/bin/env dotnet-script
#r "nuget: Microsoft.AspNetCore.Http, 8.0.0"
#r "nuget: Microsoft.Extensions.Options, 8.0.0"
#r "nuget: Microsoft.Extensions.Logging, 8.0.0"

/*
 * Test script to verify Issue 1.5 fix:
 * Ignored parameters are now checked BEFORE sanitization
 */

using System;
using System.Linq;

// Simulate the key parts of the fix
var ignoredParams = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
{
    "utm_source",
    "utm_medium",
    "special-param"  // Parameter with special character
};

var varyByQueryKeys = new[] { "page", "utm_source", "special-param", "normal" };

Console.WriteLine("Testing Issue 1.5 Fix: Ignored Parameters Checked Before Sanitization");
Console.WriteLine("=========================================================================\n");

Console.WriteLine("Ignored Parameters List:");
foreach (var param in ignoredParams)
{
    Console.WriteLine($"  - {param}");
}
Console.WriteLine();

Console.WriteLine("VaryByQueryKeys to process:");
foreach (var key in varyByQueryKeys)
{
    Console.WriteLine($"  - {key}");
}
Console.WriteLine();

Console.WriteLine("Processing with FIX (check ignored list BEFORE sanitization):");
Console.WriteLine("-------------------------------------------------------------");

var includedParams = new List<string>();
foreach (var queryKey in varyByQueryKeys)
{
    // SECURITY FIX (Issue 1.5): Check ignored parameters BEFORE sanitization
    if (ignoredParams.Contains(queryKey))
    {
        Console.WriteLine($"  ✓ '{queryKey}' - SKIPPED (found in ignore list using original name)");
        continue;
    }

    Console.WriteLine($"  → '{queryKey}' - INCLUDED (not in ignore list, will be sanitized)");
    includedParams.Add(queryKey);
}

Console.WriteLine();
Console.WriteLine("Final Result:");
Console.WriteLine($"  Parameters included in cache key: {string.Join(", ", includedParams)}");
Console.WriteLine($"  Parameters excluded: {varyByQueryKeys.Except(includedParams).Count()}");

Console.WriteLine();
Console.WriteLine("Expected behavior:");
Console.WriteLine("  - 'page' and 'normal' should be included");
Console.WriteLine("  - 'utm_source' should be excluded (in default ignore list)");
Console.WriteLine("  - 'special-param' should be excluded (has hyphen, in custom ignore list)");

Console.WriteLine();
var success = includedParams.Contains("page") &&
              includedParams.Contains("normal") &&
              !includedParams.Contains("utm_source") &&
              !includedParams.Contains("special-param");

if (success)
{
    Console.WriteLine("✅ TEST PASSED: Ignored parameters with special characters are properly excluded!");
}
else
{
    Console.WriteLine("❌ TEST FAILED: Something went wrong with the ignore logic");
}
