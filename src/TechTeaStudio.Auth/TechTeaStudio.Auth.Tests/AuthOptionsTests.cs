using FluentAssertions;
using TechTeaStudio.Auth.AspNetCore;
using Xunit;

namespace TechTeaStudio.Auth.Tests;

public class AuthOptionsTests
{
    private readonly AuthOptionsValidator _validator = new();

    [Fact]
    public void Defaults_match_production_values()
    {
        var o = new AuthOptions();
        o.Jwt.TokenLifetime.Should().Be(TimeSpan.FromMinutes(30));
        o.RefreshTokens.Lifetime.Should().Be(TimeSpan.FromDays(7));
        o.Jwt.ClockSkew.Should().Be(TimeSpan.FromMinutes(5));
        o.Lockout.MaxFailedAttempts.Should().Be(5);
        o.Lockout.Duration.Should().Be(TimeSpan.FromMinutes(15));
        o.Jwt.Signing.Should().NotBeNull();
        o.Jwt.Signing.Keys.Should().BeEmpty();
        o.Jwt.Signing.KeyRetention.Should().Be(TimeSpan.FromDays(7));
    }

    [Fact]
    public void Empty_SecretKey_with_no_Signing_Keys_fails()
    {
        var o = new AuthOptions { Jwt = { SecretKey = "", Issuer = "i", Audience = "a" } };
        var r = _validator.Validate(null, o);
        r.Failed.Should().BeTrue();
        r.FailureMessage.Should().Contain("SecretKey");
    }

    [Fact]
    public void Short_SecretKey_fails()
    {
        var o = new AuthOptions { Jwt = { SecretKey = new string('x', 31), Issuer = "i", Audience = "a" } };
        var r = _validator.Validate(null, o);
        r.Failed.Should().BeTrue();
        r.FailureMessage.Should().Contain("32 bytes");
    }

    [Fact]
    public void Exactly_32_chars_passes()
    {
        var o = new AuthOptions { Jwt = { SecretKey = new string('x', 32), Issuer = "i", Audience = "a" } };
        _validator.Validate(null, o).Succeeded.Should().BeTrue();
    }

    [Fact]
    public void Missing_Issuer_or_Audience_fails()
    {
        var o = new AuthOptions { Jwt = { SecretKey = new string('x', 32), Issuer = "", Audience = "" } };
        var r = _validator.Validate(null, o);
        r.Failed.Should().BeTrue();
        r.FailureMessage.Should().Contain("Issuer").And.Contain("Audience");
    }

    [Fact]
    public void Zero_max_failed_attempts_fails()
    {
        var o = new AuthOptions
        {
            Jwt = { SecretKey = new string('x', 32), Issuer = "i", Audience = "a" },
            Lockout = { MaxFailedAttempts = 0 },
        };
        var r = _validator.Validate(null, o);
        r.Failed.Should().BeTrue();
        r.FailureMessage.Should().Contain("MaxFailedAttempts");
    }
}
