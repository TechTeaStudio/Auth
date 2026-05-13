using FluentAssertions;
using TechTeaStudio.Auth.Observability;
using Xunit;

namespace TechTeaStudio.Auth.Tests.Observability;

public class InMemoryAuthAuditLoggerTests
{
    [Fact]
    public async Task Captures_events_in_order()
    {
        var logger = new InMemoryAuthAuditLogger();
        await logger.LogAsync(new LoginSucceededEvent("u", DateTimeOffset.UtcNow));
        await logger.LogAsync(new LoginFailedEvent("u", "bad-password", DateTimeOffset.UtcNow));
        logger.Snapshot().Select(e => e.Kind).Should().ContainInOrder("login.succeeded", "login.failed");
    }

    [Fact]
    public async Task Bounded_to_capacity()
    {
        var logger = new InMemoryAuthAuditLogger(capacity: 2);
        await logger.LogAsync(new LoginSucceededEvent("a", DateTimeOffset.UtcNow));
        await logger.LogAsync(new LoginSucceededEvent("b", DateTimeOffset.UtcNow));
        await logger.LogAsync(new LoginSucceededEvent("c", DateTimeOffset.UtcNow));

        var snap = logger.Snapshot().OfType<LoginSucceededEvent>().Select(e => e.UserId).ToArray();
        snap.Should().BeEquivalentTo(new[] { "b", "c" });
    }

    [Fact]
    public async Task Null_logger_discards()
    {
        var logger = NullAuthAuditLogger.Instance;
        var act = () => logger.LogAsync(new LoginSucceededEvent("u", DateTimeOffset.UtcNow));
        await act.Should().NotThrowAsync();
    }
}
