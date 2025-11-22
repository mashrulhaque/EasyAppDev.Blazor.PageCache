using InteractiveServerDemo.Components;
using EasyAppDev.Blazor.PageCache.Extensions;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddRazorComponents()
    .AddInteractiveServerComponents();

// Add page caching with configuration optimized for interactive server scenarios
builder.Services.AddPageCache(options =>
{
    options.DefaultDurationSeconds = 300; // 5 minutes default cache duration
    options.EnableStatistics = true; // Track cache hit/miss statistics
    options.CompressCachedContent = false; // Disable compression for demo

    // Security options
    // NOTE: HTML validation is disabled for Blazor apps because framework <script> tags are always present and safe
    // Blazor generates HTML server-side from trusted Razor components, so XSS validation is not needed
    options.Security.EnableHtmlValidation = false; // Disable for Blazor (framework scripts are safe)

    // Rate limiting - relaxed for demo/testing purposes
    options.Security.EnableRateLimiting = true; // Prevent abuse
    options.Security.RateLimitMaxAttempts = 1000; // Allow 1000 requests per window (relaxed for demo)
    options.Security.RateLimitWindowSeconds = 60; // 60 second window

    options.Security.ExposeDebugHeaders = true; // Enable X-Page-Cache headers for testing
});

var app = builder.Build();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error", createScopeForErrors: true);
    app.UseHsts();
}

app.UseHttpsRedirection();

// Enable page cache middleware (must be placed early in pipeline, before UseAntiforgery)
// This caches the initial HTML render of Blazor pages, even for interactive server components
app.UsePageCache();

app.UseAntiforgery();

app.MapStaticAssets();
app.MapRazorComponents<App>()
    .AddInteractiveServerRenderMode();

app.Run();
