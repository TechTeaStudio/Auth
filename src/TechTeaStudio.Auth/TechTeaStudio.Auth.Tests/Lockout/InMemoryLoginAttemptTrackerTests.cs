using FluentAssertions;
using Microsoft.Extensions.Options;
using TechTeaStudio.Auth.Lockout;
using Xunit;

namespace TechTeaStudio.Auth.Tests.Lockout;

public class InMemoryLoginAttemptTrackerTests
{
    private static InMemoryLoginAttemptTracker NewTracker(int maxAttempts = 3, TimeSpan? lockout = null)
    {
        var o = new AuthOptions
        {
            SecretKey = new string('x', 32),
            Issuer = "i",
            Audience = "a",
            MaxFailedLoginAttempts = maxAttempts,
            LockoutDuration = lockout ?? TimeSpan.FromMinutes(15),
        };
        return new InMemoryLoginAttemptTracker(Options.Create(o));
    }

    [Fact]
    public async Task First_failure_increments_count_no_lock()
    {
        var tracker = NewTracker();
        var r = await tracker.RecordFailureAsync("u");
        r.FailedAttempts.Should().Be(1);
        r.IsLocked.Should().BeFalse();
        r.LockoutEndsAt.Should().BeNull();
    }

    [Fact]
    public async Task Locks_after_threshold()
    {
        var tracker = NewTracker(maxAttempts: 3);
        await tracker.RecordFailureAsync("u");
        await tracker.RecordFailureAsync("u");
        var r = await tracker.RecordFailureAsync("u");
        r.IsLocked.Should().BeTrue();
        r.FailedAttempts.Should().Be(3);
        r.LockoutEndsAt.Should().NotBeNull();
    }

    [Fact]
    public async Task RecordSuccess_clears_history()
    {
        var tracker = NewTracker();
        await tracker.RecordFailureAsync("u");
        await tracker.RecordSuccessAsync("u");
        (await tracker.GetStatusAsync("u")).Should().BeEquivalentTo(LockoutStatus.Clear);
    }

    [Fact]
    public async Task GetStatus_for_unknown_user_is_clear()
    {
        var tracker = NewTracker();
        (await tracker.GetStatusAsync("nobody")).IsLocked.Should().BeFalse();
    }

    [Fact]
    public async Task Lockout_expires_naturally()
    {
        var tracker = NewTracker(maxAttempts: 1, lockout: TimeSpan.FromMilliseconds(30));
        await tracker.RecordFailureAsync("u"); // locks immediately
        await Task.Delay(60);
        var status = await tracker.GetStatusAsync("u");
        status.IsLocked.Should().BeFalse();
    }
}
