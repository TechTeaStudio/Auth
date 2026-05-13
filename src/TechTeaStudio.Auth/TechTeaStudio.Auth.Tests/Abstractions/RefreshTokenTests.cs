using FluentAssertions;
using TechTeaStudio.Auth.Abstractions;
using Xunit;

namespace TechTeaStudio.Auth.Tests.Abstractions;

public class RefreshTokenTests
{
    [Fact]
    public void IsActive_true_when_not_revoked_and_future_expiry()
    {
        var t = new RefreshToken { ExpiresAt = DateTimeOffset.UtcNow.AddMinutes(5) };
        t.IsActive.Should().BeTrue();
    }

    [Fact]
    public void IsActive_false_when_revoked()
    {
        var t = new RefreshToken
        {
            ExpiresAt = DateTimeOffset.UtcNow.AddMinutes(5),
            RevokedAt = DateTimeOffset.UtcNow.AddSeconds(-1),
        };
        t.IsActive.Should().BeFalse();
    }

    [Fact]
    public void IsActive_false_when_expired()
    {
        var t = new RefreshToken { ExpiresAt = DateTimeOffset.UtcNow.AddSeconds(-1) };
        t.IsActive.Should().BeFalse();
    }

    [Fact]
    public void Id_defaults_to_fresh_guid()
    {
        new RefreshToken().Id.Should().NotBe(Guid.Empty);
        new RefreshToken().Id.Should().NotBe(new RefreshToken().Id);
    }
}
