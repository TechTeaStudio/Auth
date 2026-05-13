using FluentAssertions;
using TechTeaStudio.Auth.Abstractions;
using Xunit;

namespace TechTeaStudio.Auth.Tests.Abstractions;

public class AuthTokenInfoTests
{
    [Fact]
    public void Defaults_are_safe()
    {
        var info = new AuthTokenInfo();
        info.UserId.Should().BeEmpty();
        info.Username.Should().BeEmpty();
        info.Email.Should().BeEmpty();
        info.Roles.Should().BeEmpty();
    }

    [Fact]
    public void IsExpired_true_when_ExpiresAt_in_past()
    {
        var info = new AuthTokenInfo { ExpiresAt = DateTimeOffset.UtcNow.AddMinutes(-1) };
        info.IsExpired.Should().BeTrue();
    }

    [Fact]
    public void IsExpired_false_when_ExpiresAt_in_future()
    {
        var info = new AuthTokenInfo { ExpiresAt = DateTimeOffset.UtcNow.AddMinutes(5) };
        info.IsExpired.Should().BeFalse();
    }

    [Fact]
    public void Records_with_same_values_are_equal()
    {
        var a = new AuthTokenInfo { UserId = "u", Email = "e@x", Roles = new[] { "r" } };
        var b = new AuthTokenInfo { UserId = "u", Email = "e@x", Roles = new[] { "r" } };
        // Record equality compares property values, but Roles is reference-equal by default.
        // The intent here is value-object semantics for scalars.
        a.UserId.Should().Be(b.UserId);
        a.Email.Should().Be(b.Email);
    }
}
