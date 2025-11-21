using EasyAppDev.Blazor.PageCache.Abstractions;

namespace EasyAppDev.Blazor.PageCache.Validation;

/// <summary>
/// A no-op validator that always returns success.
/// Used when validation is explicitly disabled.
/// </summary>
internal sealed class NoOpValidator : IContentValidator
{
    /// <inheritdoc />
    public Task<ValidationResult> ValidateAsync(
        string content,
        string cacheKey,
        CancellationToken cancellationToken = default)
    {
        return Task.FromResult(ValidationResult.Success());
    }
}
