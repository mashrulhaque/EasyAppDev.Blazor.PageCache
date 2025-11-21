using EasyAppDev.Blazor.PageCache.Validation;

var cacheKey = "PageCache:query\\*results";
var result = CacheKeyValidator.Validate(cacheKey);

Console.WriteLine($"IsValid: {result.IsValid}");
Console.WriteLine($"ErrorType: {result.ErrorType}");
Console.WriteLine($"ErrorMessage: {result.ErrorMessage}");
if (result.ErrorDetails != null)
{
    foreach (var detail in result.ErrorDetails)
    {
        Console.WriteLine($"  {detail.Key}: {detail.Value}");
    }
}
