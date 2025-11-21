using System.Collections.Concurrent;
using EasyAppDev.Blazor.PageCache.Security;
using FluentAssertions;
using Xunit;

namespace EasyAppDev.Blazor.PageCache.Tests.Security;

public class RateLimiterTests : IDisposable
{
    private readonly SlidingWindowRateLimiter _rateLimiter;

    public RateLimiterTests()
    {
        _rateLimiter = new SlidingWindowRateLimiter();
    }

    public void Dispose()
    {
        _rateLimiter?.Dispose();
    }

    [Fact]
    public void IsAllowed_FirstRequest_ShouldAllow()
    {
        // Arrange
        var key = "test-key";
        var maxAttempts = 10;
        var windowSeconds = 60;

        // Act
        var result = _rateLimiter.IsAllowed(key, maxAttempts, windowSeconds, out var remaining, out var resetTime);

        // Assert
        result.Should().BeTrue();
        remaining.Should().Be(9);
        resetTime.Should().BeAfter(DateTimeOffset.UtcNow);
    }

    [Fact]
    public void IsAllowed_WithinLimit_ShouldAllow()
    {
        // Arrange
        var key = "test-key";
        var maxAttempts = 5;
        var windowSeconds = 60;

        // Act & Assert
        for (int i = 0; i < maxAttempts; i++)
        {
            var result = _rateLimiter.IsAllowed(key, maxAttempts, windowSeconds, out var remaining, out _);
            result.Should().BeTrue($"request {i + 1} should be allowed");
            remaining.Should().Be(maxAttempts - i - 1);
        }
    }

    [Fact]
    public void IsAllowed_ExceedingLimit_ShouldDeny()
    {
        // Arrange
        var key = "test-key";
        var maxAttempts = 3;
        var windowSeconds = 60;

        // Fill up the limit
        for (int i = 0; i < maxAttempts; i++)
        {
            _rateLimiter.IsAllowed(key, maxAttempts, windowSeconds, out _, out _);
        }

        // Act - Try one more request
        var result = _rateLimiter.IsAllowed(key, maxAttempts, windowSeconds, out var remaining, out var resetTime);

        // Assert
        result.Should().BeFalse();
        remaining.Should().Be(0);
        resetTime.Should().BeAfter(DateTimeOffset.UtcNow);
    }

    [Fact]
    public void IsAllowed_DifferentKeys_ShouldBeIndependent()
    {
        // Arrange
        var key1 = "key-1";
        var key2 = "key-2";
        var maxAttempts = 2;
        var windowSeconds = 60;

        // Exhaust limit for key1
        _rateLimiter.IsAllowed(key1, maxAttempts, windowSeconds, out _, out _);
        _rateLimiter.IsAllowed(key1, maxAttempts, windowSeconds, out _, out _);

        // Act - Try key2
        var result = _rateLimiter.IsAllowed(key2, maxAttempts, windowSeconds, out var remaining, out _);

        // Assert
        result.Should().BeTrue();
        remaining.Should().Be(1);
    }

    [Fact]
    public async Task IsAllowed_SlidingWindow_ShouldAllowAfterWindowExpires()
    {
        // Arrange
        var key = "test-key";
        var maxAttempts = 2;
        var windowSeconds = 1; // 1 second window for faster test

        // Fill up the limit
        _rateLimiter.IsAllowed(key, maxAttempts, windowSeconds, out _, out _);
        _rateLimiter.IsAllowed(key, maxAttempts, windowSeconds, out _, out _);

        // Verify limit is reached
        var blockedResult = _rateLimiter.IsAllowed(key, maxAttempts, windowSeconds, out _, out _);
        blockedResult.Should().BeFalse();

        // Wait for window to slide
        await Task.Delay(TimeSpan.FromSeconds(1.1));

        // Act - Try again after window expires
        var result = _rateLimiter.IsAllowed(key, maxAttempts, windowSeconds, out var remaining, out _);

        // Assert
        result.Should().BeTrue();
        remaining.Should().Be(1);
    }

    [Fact]
    public async Task IsAllowed_SlidingWindow_ShouldPartiallyRecover()
    {
        // Arrange
        var key = "test-key";
        var maxAttempts = 3;
        var windowSeconds = 1;

        // Make first request
        _rateLimiter.IsAllowed(key, maxAttempts, windowSeconds, out _, out _);

        // Wait a bit
        await Task.Delay(TimeSpan.FromSeconds(0.6));

        // Make two more requests
        _rateLimiter.IsAllowed(key, maxAttempts, windowSeconds, out _, out _);
        _rateLimiter.IsAllowed(key, maxAttempts, windowSeconds, out _, out _);

        // Verify limit is reached
        var blockedResult = _rateLimiter.IsAllowed(key, maxAttempts, windowSeconds, out _, out _);
        blockedResult.Should().BeFalse();

        // Wait for first request to expire from window
        await Task.Delay(TimeSpan.FromSeconds(0.5));

        // Act - First request should have expired, allowing one more
        var result = _rateLimiter.IsAllowed(key, maxAttempts, windowSeconds, out var remaining, out _);

        // Assert
        result.Should().BeTrue();
        remaining.Should().Be(0); // Still have 2 requests in window
    }

    [Fact]
    public void IsAllowed_ConcurrentRequests_ShouldBeThreadSafe()
    {
        // Arrange
        var key = "test-key";
        var maxAttempts = 100;
        var windowSeconds = 60;
        var concurrentRequests = 200;
        var successCount = 0;

        // Act
        Parallel.For(0, concurrentRequests, _ =>
        {
            if (_rateLimiter.IsAllowed(key, maxAttempts, windowSeconds, out int _, out DateTimeOffset _))
            {
                Interlocked.Increment(ref successCount);
            }
        });

        // Assert
        successCount.Should().Be(maxAttempts);
    }

    [Fact]
    public void IsAllowed_ConcurrentRequestsMultipleKeys_ShouldBeThreadSafe()
    {
        // Arrange
        var maxAttempts = 10;
        var windowSeconds = 60;
        var keysCount = 10;
        var requestsPerKey = 20;
        var results = new ConcurrentDictionary<string, int>();

        // Act
        Parallel.For(0, keysCount, keyIndex =>
        {
            var key = $"key-{keyIndex}";
            var successCount = 0;

            for (int i = 0; i < requestsPerKey; i++)
            {
                if (_rateLimiter.IsAllowed(key, maxAttempts, windowSeconds, out int _, out DateTimeOffset _))
                {
                    successCount++;
                }
            }

            results[key] = successCount;
        });

        // Assert
        results.Should().HaveCount(keysCount);
        results.Values.Should().AllSatisfy(count => count.Should().Be(maxAttempts));
    }

    [Fact]
    public void Reset_ShouldClearStateForKey()
    {
        // Arrange
        var key = "test-key";
        var maxAttempts = 2;
        var windowSeconds = 60;

        // Fill up the limit
        _rateLimiter.IsAllowed(key, maxAttempts, windowSeconds, out _, out _);
        _rateLimiter.IsAllowed(key, maxAttempts, windowSeconds, out _, out _);

        // Verify limit is reached
        var blockedResult = _rateLimiter.IsAllowed(key, maxAttempts, windowSeconds, out _, out _);
        blockedResult.Should().BeFalse();

        // Act
        _rateLimiter.Reset(key);

        // Assert
        var result = _rateLimiter.IsAllowed(key, maxAttempts, windowSeconds, out var remaining, out _);
        result.Should().BeTrue();
        remaining.Should().Be(1);
    }

    [Fact]
    public void Reset_ShouldOnlyAffectSpecificKey()
    {
        // Arrange
        var key1 = "key-1";
        var key2 = "key-2";
        var maxAttempts = 1;
        var windowSeconds = 60;

        // Use up both keys
        _rateLimiter.IsAllowed(key1, maxAttempts, windowSeconds, out _, out _);
        _rateLimiter.IsAllowed(key2, maxAttempts, windowSeconds, out _, out _);

        // Act - Reset only key1
        _rateLimiter.Reset(key1);

        // Assert
        var result1 = _rateLimiter.IsAllowed(key1, maxAttempts, windowSeconds, out _, out _);
        var result2 = _rateLimiter.IsAllowed(key2, maxAttempts, windowSeconds, out _, out _);

        result1.Should().BeTrue();
        result2.Should().BeFalse();
    }

    [Fact]
    public void Clear_ShouldClearAllState()
    {
        // Arrange
        var maxAttempts = 1;
        var windowSeconds = 60;

        // Use up multiple keys
        for (int i = 0; i < 5; i++)
        {
            _rateLimiter.IsAllowed($"key-{i}", maxAttempts, windowSeconds, out _, out _);
        }

        // Act
        _rateLimiter.Clear();

        // Assert
        for (int i = 0; i < 5; i++)
        {
            var result = _rateLimiter.IsAllowed($"key-{i}", maxAttempts, windowSeconds, out _, out _);
            result.Should().BeTrue($"key-{i} should be reset");
        }
    }

    [Fact]
    public void IsAllowed_NullKey_ShouldThrowArgumentException()
    {
        // Act
        var act = () => _rateLimiter.IsAllowed(null!, 10, 60, out _, out _);

        // Assert
        act.Should().Throw<ArgumentException>()
            .WithMessage("*Key*");
    }

    [Fact]
    public void IsAllowed_EmptyKey_ShouldThrowArgumentException()
    {
        // Act
        var act = () => _rateLimiter.IsAllowed(string.Empty, 10, 60, out _, out _);

        // Assert
        act.Should().Throw<ArgumentException>()
            .WithMessage("*Key*");
    }

    [Fact]
    public void IsAllowed_ZeroMaxAttempts_ShouldThrowArgumentException()
    {
        // Act
        var act = () => _rateLimiter.IsAllowed("key", 0, 60, out _, out _);

        // Assert
        act.Should().Throw<ArgumentException>()
            .WithMessage("*Max attempts*");
    }

    [Fact]
    public void IsAllowed_NegativeMaxAttempts_ShouldThrowArgumentException()
    {
        // Act
        var act = () => _rateLimiter.IsAllowed("key", -1, 60, out _, out _);

        // Assert
        act.Should().Throw<ArgumentException>()
            .WithMessage("*Max attempts*");
    }

    [Fact]
    public void IsAllowed_ZeroWindowSeconds_ShouldThrowArgumentException()
    {
        // Act
        var act = () => _rateLimiter.IsAllowed("key", 10, 0, out _, out _);

        // Assert
        act.Should().Throw<ArgumentException>()
            .WithMessage("*Window seconds*");
    }

    [Fact]
    public void IsAllowed_NegativeWindowSeconds_ShouldThrowArgumentException()
    {
        // Act
        var act = () => _rateLimiter.IsAllowed("key", 10, -1, out _, out _);

        // Assert
        act.Should().Throw<ArgumentException>()
            .WithMessage("*Window seconds*");
    }

    [Fact]
    public void Reset_NullKey_ShouldThrowArgumentException()
    {
        // Act
        var act = () => _rateLimiter.Reset(null!);

        // Assert
        act.Should().Throw<ArgumentException>()
            .WithMessage("*Key*");
    }

    [Fact]
    public void Reset_EmptyKey_ShouldThrowArgumentException()
    {
        // Act
        var act = () => _rateLimiter.Reset(string.Empty);

        // Assert
        act.Should().Throw<ArgumentException>()
            .WithMessage("*Key*");
    }

    [Fact]
    public void IsAllowed_AfterDispose_ShouldThrowObjectDisposedException()
    {
        // Arrange
        var rateLimiter = new SlidingWindowRateLimiter();
        rateLimiter.Dispose();

        // Act
        var act = () => rateLimiter.IsAllowed("key", 10, 60, out _, out _);

        // Assert
        act.Should().Throw<ObjectDisposedException>();
    }

    [Fact]
    public void Reset_AfterDispose_ShouldThrowObjectDisposedException()
    {
        // Arrange
        var rateLimiter = new SlidingWindowRateLimiter();
        rateLimiter.Dispose();

        // Act
        var act = () => rateLimiter.Reset("key");

        // Assert
        act.Should().Throw<ObjectDisposedException>();
    }

    [Fact]
    public void Clear_AfterDispose_ShouldThrowObjectDisposedException()
    {
        // Arrange
        var rateLimiter = new SlidingWindowRateLimiter();
        rateLimiter.Dispose();

        // Act
        var act = () => rateLimiter.Clear();

        // Assert
        act.Should().Throw<ObjectDisposedException>();
    }

    [Fact]
    public void IsAllowed_ResetTimeCalculation_ShouldBeAccurate()
    {
        // Arrange
        var key = "test-key";
        var maxAttempts = 1;
        var windowSeconds = 60;

        // Act
        var beforeRequest = DateTimeOffset.UtcNow;
        _rateLimiter.IsAllowed(key, maxAttempts, windowSeconds, out _, out var resetTime);
        var afterRequest = DateTimeOffset.UtcNow;

        // Assert
        var expectedResetMin = beforeRequest.AddSeconds(windowSeconds);
        var expectedResetMax = afterRequest.AddSeconds(windowSeconds);

        resetTime.Should().BeOnOrAfter(expectedResetMin);
        resetTime.Should().BeOnOrBefore(expectedResetMax);
    }

    [Fact]
    public void IsAllowed_RemainingAttemptsCalculation_ShouldBeAccurate()
    {
        // Arrange
        var key = "test-key";
        var maxAttempts = 5;
        var windowSeconds = 60;

        // Act & Assert
        for (int i = 0; i < maxAttempts; i++)
        {
            _rateLimiter.IsAllowed(key, maxAttempts, windowSeconds, out var remaining, out _);
            remaining.Should().Be(maxAttempts - i - 1);
        }

        // Verify no more attempts are allowed
        _rateLimiter.IsAllowed(key, maxAttempts, windowSeconds, out var finalRemaining, out _);
        finalRemaining.Should().Be(0);
    }

    [Fact]
    public void Dispose_MultipleTimesIsAllowed()
    {
        // Arrange
        var rateLimiter = new SlidingWindowRateLimiter();

        // Act & Assert - Should not throw
        rateLimiter.Dispose();
        rateLimiter.Dispose();
        rateLimiter.Dispose();
    }
}
