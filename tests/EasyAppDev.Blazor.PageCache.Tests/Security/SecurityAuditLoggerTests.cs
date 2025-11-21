using Xunit;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using EasyAppDev.Blazor.PageCache.Security;
using System;
using System.Linq;
using FluentAssertions;

namespace EasyAppDev.Blazor.PageCache.Tests.Security;

/// <summary>
/// Tests for the SecurityAuditLogger class.
/// </summary>
public class SecurityAuditLoggerTests
{
    private readonly ILogger<SecurityAuditLogger> _logger;

    public SecurityAuditLoggerTests()
    {
        _logger = NullLogger<SecurityAuditLogger>.Instance;
    }

    [Fact]
    public void Constructor_WithNullLogger_ThrowsArgumentNullException()
    {
        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => new SecurityAuditLogger(null!));
    }

    [Fact]
    public void Constructor_WithValidLogger_CreatesInstance()
    {
        // Act
        var auditLogger = new SecurityAuditLogger(_logger);

        // Assert
        auditLogger.Should().NotBeNull();
    }

    [Fact]
    public void GetMetrics_InitialState_ReturnsZeroCounters()
    {
        // Arrange
        var auditLogger = new SecurityAuditLogger(_logger);

        // Act
        var metrics = auditLogger.GetMetrics();

        // Assert
        metrics.ValidationFailureCount.Should().Be(0);
        metrics.RateLimitViolationCount.Should().Be(0);
        metrics.InjectionAttemptCount.Should().Be(0);
        metrics.SuspiciousPatternCount.Should().Be(0);
        metrics.XssDetectionCount.Should().Be(0);
        metrics.SizeViolationCount.Should().Be(0);
        metrics.TotalSecurityEvents.Should().Be(0);
        metrics.RecentEventCount.Should().Be(0);
    }

    [Fact]
    public void LogValidationFailure_IncrementsCounter()
    {
        // Arrange
        var auditLogger = new SecurityAuditLogger(_logger);
        var context = new ValidationFailureContext
        {
            CacheKey = "test-key",
            ValidatorType = "HtmlSanitizerValidator",
            Severity = "Critical",
            ErrorMessage = "XSS detected",
            MatchedContent = "<script>alert('xss')</script>",
            RequestPath = "/test",
            ElapsedMs = 10
        };

        // Act
        auditLogger.LogValidationFailure(context);
        var metrics = auditLogger.GetMetrics();

        // Assert
        metrics.ValidationFailureCount.Should().Be(1);
        metrics.TotalSecurityEvents.Should().Be(1);
    }

    [Fact]
    public void LogRateLimitViolation_IncrementsCounter()
    {
        // Arrange
        var auditLogger = new SecurityAuditLogger(_logger);
        var context = new RateLimitViolationContext
        {
            CacheKey = "test-key",
            ClientIdentifier = "client-123",
            AttemptCount = 15,
            MaxAttempts = 10,
            WindowSeconds = 60,
            ResetTime = DateTimeOffset.UtcNow.AddSeconds(60),
            RequestPath = "/test"
        };

        // Act
        auditLogger.LogRateLimitViolation(context);
        var metrics = auditLogger.GetMetrics();

        // Assert
        metrics.RateLimitViolationCount.Should().Be(1);
        metrics.TotalSecurityEvents.Should().Be(1);
    }

    [Fact]
    public void LogInjectionAttempt_IncrementsCounter()
    {
        // Arrange
        var auditLogger = new SecurityAuditLogger(_logger);
        var context = new InjectionAttemptContext
        {
            InputType = "QueryParameter",
            SuspiciousInput = "value*",
            DetectedPattern = "Wildcard",
            RequestPath = "/test",
            ClientIdentifier = "client-123"
        };

        // Act
        auditLogger.LogInjectionAttempt(context);
        var metrics = auditLogger.GetMetrics();

        // Assert
        metrics.InjectionAttemptCount.Should().Be(1);
        metrics.TotalSecurityEvents.Should().Be(1);
    }

    [Fact]
    public void LogSuspiciousPattern_IncrementsCounter()
    {
        // Arrange
        var auditLogger = new SecurityAuditLogger(_logger);
        var context = new SuspiciousPatternContext
        {
            CacheKey = "test-key",
            PatternName = "DomClobbering",
            Severity = "Warning",
            MatchedContent = "<input id='location'>",
            RequestPath = "/test"
        };

        // Act
        auditLogger.LogSuspiciousPattern(context);
        var metrics = auditLogger.GetMetrics();

        // Assert
        metrics.SuspiciousPatternCount.Should().Be(1);
        metrics.TotalSecurityEvents.Should().Be(1);
    }

    [Fact]
    public void LogXssDetection_IncrementsCounter()
    {
        // Arrange
        var auditLogger = new SecurityAuditLogger(_logger);
        var context = new XssDetectionContext
        {
            CacheKey = "test-key",
            PatternName = "InlineEventHandlers",
            PatternCategory = "Critical",
            MatchedContent = "onclick='alert(1)'",
            RequestPath = "/test",
            ValidationTimeMs = 5
        };

        // Act
        auditLogger.LogXssDetection(context);
        var metrics = auditLogger.GetMetrics();

        // Assert
        metrics.XssDetectionCount.Should().Be(1);
        metrics.TotalSecurityEvents.Should().Be(1);
    }

    [Fact]
    public void LogSizeViolation_IncrementsCounter()
    {
        // Arrange
        var auditLogger = new SecurityAuditLogger(_logger);
        var context = new SizeViolationContext
        {
            CacheKey = "test-key",
            ActualSize = 10_000_000,
            MaxSize = 5_000_000,
            RequestPath = "/test"
        };

        // Act
        auditLogger.LogSizeViolation(context);
        var metrics = auditLogger.GetMetrics();

        // Assert
        metrics.SizeViolationCount.Should().Be(1);
        metrics.TotalSecurityEvents.Should().Be(1);
    }

    [Fact]
    public void LogMultipleEvents_IncrementsSeparateCounters()
    {
        // Arrange
        var auditLogger = new SecurityAuditLogger(_logger);

        // Act
        auditLogger.LogValidationFailure(new ValidationFailureContext
        {
            CacheKey = "key1",
            ValidatorType = "Test",
            Severity = "Critical",
            ErrorMessage = "Error",
            RequestPath = "/test",
            ElapsedMs = 10
        });

        auditLogger.LogValidationFailure(new ValidationFailureContext
        {
            CacheKey = "key2",
            ValidatorType = "Test",
            Severity = "Critical",
            ErrorMessage = "Error",
            RequestPath = "/test",
            ElapsedMs = 10
        });

        auditLogger.LogXssDetection(new XssDetectionContext
        {
            CacheKey = "key3",
            PatternName = "Test",
            PatternCategory = "Critical",
            RequestPath = "/test",
            ValidationTimeMs = 5
        });

        var metrics = auditLogger.GetMetrics();

        // Assert
        metrics.ValidationFailureCount.Should().Be(2);
        metrics.XssDetectionCount.Should().Be(1);
        metrics.TotalSecurityEvents.Should().Be(3);
    }

    [Fact]
    public void ResetMetrics_ClearsAllCounters()
    {
        // Arrange
        var auditLogger = new SecurityAuditLogger(_logger);

        auditLogger.LogValidationFailure(new ValidationFailureContext
        {
            CacheKey = "key1",
            ValidatorType = "Test",
            Severity = "Critical",
            ErrorMessage = "Error",
            RequestPath = "/test",
            ElapsedMs = 10
        });

        auditLogger.LogXssDetection(new XssDetectionContext
        {
            CacheKey = "key2",
            PatternName = "Test",
            PatternCategory = "Critical",
            RequestPath = "/test",
            ValidationTimeMs = 5
        });

        // Act
        auditLogger.ResetMetrics();
        var metrics = auditLogger.GetMetrics();

        // Assert
        metrics.ValidationFailureCount.Should().Be(0);
        metrics.XssDetectionCount.Should().Be(0);
        metrics.TotalSecurityEvents.Should().Be(0);
        metrics.RecentEventCount.Should().Be(0);
    }

    [Fact]
    public void GetRecentEvents_ReturnsLoggedEvents()
    {
        // Arrange
        var auditLogger = new SecurityAuditLogger(_logger);

        auditLogger.LogValidationFailure(new ValidationFailureContext
        {
            CacheKey = "key1",
            ValidatorType = "Test",
            Severity = "Critical",
            ErrorMessage = "Error",
            RequestPath = "/test",
            ElapsedMs = 10
        });

        auditLogger.LogXssDetection(new XssDetectionContext
        {
            CacheKey = "key2",
            PatternName = "Test",
            PatternCategory = "Critical",
            RequestPath = "/test",
            ValidationTimeMs = 5
        });

        // Act
        var events = auditLogger.GetRecentEvents();

        // Assert
        events.Should().HaveCount(2);
        events.Should().Contain(e => e.EventType == SecurityEventType.ValidationFailure);
        events.Should().Contain(e => e.EventType == SecurityEventType.XssDetection);
    }

    [Fact]
    public void GetRecentEvents_WithLimit_ReturnsLimitedEvents()
    {
        // Arrange
        var auditLogger = new SecurityAuditLogger(_logger);

        for (int i = 0; i < 10; i++)
        {
            auditLogger.LogValidationFailure(new ValidationFailureContext
            {
                CacheKey = $"key{i}",
                ValidatorType = "Test",
                Severity = "Critical",
                ErrorMessage = "Error",
                RequestPath = "/test",
                ElapsedMs = 10
            });
        }

        // Act
        var events = auditLogger.GetRecentEvents(maxEvents: 5);

        // Assert
        events.Should().HaveCount(5);
    }

    [Fact]
    public void GetRecentEvents_ExceedsMaxCapacity_TrimsOldestEvents()
    {
        // Arrange
        var auditLogger = new SecurityAuditLogger(_logger);

        // Log more than 1000 events (max capacity)
        for (int i = 0; i < 1100; i++)
        {
            auditLogger.LogValidationFailure(new ValidationFailureContext
            {
                CacheKey = $"key{i}",
                ValidatorType = "Test",
                Severity = "Critical",
                ErrorMessage = "Error",
                RequestPath = "/test",
                ElapsedMs = 10
            });
        }

        // Act
        var events = auditLogger.GetRecentEvents(maxEvents: 2000);

        // Assert
        // Should be capped at 1000 events
        events.Should().HaveCountLessThanOrEqualTo(1000);
        var metrics = auditLogger.GetMetrics();
        metrics.RecentEventCount.Should().BeLessThanOrEqualTo(1000);
    }

    [Fact]
    public void CorrelationId_SetAndGet_PreservesValue()
    {
        // Arrange
        var auditLogger = new SecurityAuditLogger(_logger);
        var expectedCorrelationId = Guid.NewGuid().ToString();

        // Act
        auditLogger.SetCorrelationId(expectedCorrelationId);
        var actualCorrelationId = auditLogger.GetOrCreateCorrelationId();

        // Assert
        actualCorrelationId.Should().Be(expectedCorrelationId);
    }

    [Fact]
    public void CorrelationId_NotSet_GeneratesNewId()
    {
        // Arrange
        var auditLogger = new SecurityAuditLogger(_logger);

        // Act
        var correlationId = auditLogger.GetOrCreateCorrelationId();

        // Assert
        correlationId.Should().NotBeNullOrEmpty();
        // Should be a valid GUID format (without dashes due to "N" format)
        correlationId.Length.Should().Be(32);
    }

    [Fact]
    public void DisabledLogger_DoesNotLogEvents()
    {
        // Arrange
        var auditLogger = new SecurityAuditLogger(_logger, enabled: false);

        // Act
        auditLogger.LogValidationFailure(new ValidationFailureContext
        {
            CacheKey = "key1",
            ValidatorType = "Test",
            Severity = "Critical",
            ErrorMessage = "Error",
            RequestPath = "/test",
            ElapsedMs = 10
        });

        var metrics = auditLogger.GetMetrics();

        // Assert
        // Counters should still increment even when disabled
        // (metrics are separate from logging)
        // But the actual logging should be suppressed
        metrics.ValidationFailureCount.Should().Be(0);
    }

    [Fact]
    public void SecurityMetrics_CalculatesRatesCorrectly()
    {
        // Arrange
        var auditLogger = new SecurityAuditLogger(_logger);

        // Log 10 validation failures
        for (int i = 0; i < 10; i++)
        {
            auditLogger.LogValidationFailure(new ValidationFailureContext
            {
                CacheKey = $"key{i}",
                ValidatorType = "Test",
                Severity = "Critical",
                ErrorMessage = "Error",
                RequestPath = "/test",
                ElapsedMs = 10
            });
        }

        // Log 5 XSS detections
        for (int i = 0; i < 5; i++)
        {
            auditLogger.LogXssDetection(new XssDetectionContext
            {
                CacheKey = $"key{i}",
                PatternName = "Test",
                PatternCategory = "Critical",
                RequestPath = "/test",
                ValidationTimeMs = 5
            });
        }

        // Log 3 rate limit violations
        for (int i = 0; i < 3; i++)
        {
            auditLogger.LogRateLimitViolation(new RateLimitViolationContext
            {
                CacheKey = $"key{i}",
                ClientIdentifier = "client",
                AttemptCount = 15,
                MaxAttempts = 10,
                WindowSeconds = 60,
                ResetTime = DateTimeOffset.UtcNow.AddSeconds(60),
                RequestPath = "/test"
            });
        }

        // Act
        var metrics = auditLogger.GetMetrics();

        // Assert
        metrics.TotalSecurityEvents.Should().Be(18);
        metrics.ValidationFailureRate.Should().BeApproximately(10.0 / 18.0, 0.01);
        metrics.RateLimitHitRate.Should().BeApproximately(3.0 / 18.0, 0.01);
    }

    [Fact]
    public void SecurityMetrics_ZeroEvents_ReturnsZeroRates()
    {
        // Arrange
        var auditLogger = new SecurityAuditLogger(_logger);

        // Act
        var metrics = auditLogger.GetMetrics();

        // Assert
        metrics.ValidationFailureRate.Should().Be(0);
        metrics.RateLimitHitRate.Should().Be(0);
        metrics.InjectionAttemptRate.Should().Be(0);
    }

    [Fact]
    public void LogValidationFailure_SanitizesLongCacheKey()
    {
        // Arrange
        var auditLogger = new SecurityAuditLogger(_logger);
        var longCacheKey = new string('a', 300);

        var context = new ValidationFailureContext
        {
            CacheKey = longCacheKey,
            ValidatorType = "Test",
            Severity = "Critical",
            ErrorMessage = "Error",
            RequestPath = "/test",
            ElapsedMs = 10
        };

        // Act & Assert
        // Should not throw, even with very long cache key
        var exception = Record.Exception(() => auditLogger.LogValidationFailure(context));
        exception.Should().BeNull();
    }

    [Fact]
    public void LogXssDetection_SanitizesLongMatchedContent()
    {
        // Arrange
        var auditLogger = new SecurityAuditLogger(_logger);
        var longContent = new string('x', 500);

        var context = new XssDetectionContext
        {
            CacheKey = "test-key",
            PatternName = "Test",
            PatternCategory = "Critical",
            MatchedContent = longContent,
            RequestPath = "/test",
            ValidationTimeMs = 5
        };

        // Act & Assert
        // Should not throw, even with very long content
        var exception = Record.Exception(() => auditLogger.LogXssDetection(context));
        exception.Should().BeNull();
    }

    [Fact]
    public void LogValidationFailure_WithNullMatchedContent_DoesNotThrow()
    {
        // Arrange
        var auditLogger = new SecurityAuditLogger(_logger);
        var context = new ValidationFailureContext
        {
            CacheKey = "test-key",
            ValidatorType = "Test",
            Severity = "Critical",
            ErrorMessage = "Error",
            MatchedContent = null,
            RequestPath = "/test",
            ElapsedMs = 10
        };

        // Act & Assert
        var exception = Record.Exception(() => auditLogger.LogValidationFailure(context));
        exception.Should().BeNull();
    }

    [Fact]
    public void LogSuspiciousPattern_WithEmptyMatchedContent_DoesNotThrow()
    {
        // Arrange
        var auditLogger = new SecurityAuditLogger(_logger);
        var context = new SuspiciousPatternContext
        {
            CacheKey = "test-key",
            PatternName = "Test",
            Severity = "Warning",
            MatchedContent = string.Empty,
            RequestPath = "/test"
        };

        // Act & Assert
        var exception = Record.Exception(() => auditLogger.LogSuspiciousPattern(context));
        exception.Should().BeNull();
    }

    [Fact]
    public void ConcurrentLogging_MaintainsAccurateCounters()
    {
        // Arrange
        var auditLogger = new SecurityAuditLogger(_logger);
        const int threadCount = 10;
        const int eventsPerThread = 100;

        // Act
        var tasks = Enumerable.Range(0, threadCount).Select(_ => Task.Run(() =>
        {
            for (int i = 0; i < eventsPerThread; i++)
            {
                auditLogger.LogValidationFailure(new ValidationFailureContext
                {
                    CacheKey = $"key{i}",
                    ValidatorType = "Test",
                    Severity = "Critical",
                    ErrorMessage = "Error",
                    RequestPath = "/test",
                    ElapsedMs = 10
                });
            }
        }));

        Task.WaitAll(tasks.ToArray());

        var metrics = auditLogger.GetMetrics();

        // Assert
        metrics.ValidationFailureCount.Should().Be(threadCount * eventsPerThread);
    }

    [Fact]
    public void SecurityEvent_HasRequiredProperties()
    {
        // Arrange
        var auditLogger = new SecurityAuditLogger(_logger);

        auditLogger.LogValidationFailure(new ValidationFailureContext
        {
            CacheKey = "key1",
            ValidatorType = "Test",
            Severity = "Critical",
            ErrorMessage = "Error",
            RequestPath = "/test",
            ElapsedMs = 10
        });

        // Act
        var events = auditLogger.GetRecentEvents();
        var securityEvent = events.First();

        // Assert
        securityEvent.EventType.Should().Be(SecurityEventType.ValidationFailure);
        securityEvent.Severity.Should().NotBeNullOrEmpty();
        securityEvent.CorrelationId.Should().NotBeNullOrEmpty();
        securityEvent.Timestamp.Should().BeCloseTo(DateTimeOffset.UtcNow, TimeSpan.FromSeconds(5));
    }
}
