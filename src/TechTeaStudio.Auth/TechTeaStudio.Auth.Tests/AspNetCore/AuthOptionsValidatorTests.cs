using FluentAssertions;
using TechTeaStudio.Auth.AspNetCore;
using Xunit;

namespace TechTeaStudio.Auth.Tests.AspNetCore;

public class AuthOptionsValidatorTests
{
    private readonly AuthOptionsValidator _v = new();

    [Fact]
    public void Empty_secret_fails()
    {
        var r = _v.Validate(null, new AuthOptions { Jwt = { SecretKey = "", Issuer = "i", Audience = "a" } });
        r.Failed.Should().BeTrue();
    }

    [Fact]
    public void Short_byte_length_fails_even_when_char_length_ok()
    {
        var r = _v.Validate(null, new AuthOptions { Jwt = { SecretKey = new string('a', 31), Issuer = "i", Audience = "a" } });
        r.Failed.Should().BeTrue();
    }

    [Fact]
    public void Refresh_lifetime_must_exceed_access_lifetime()
    {
        var r = _v.Validate(null, new AuthOptions
        {
            Jwt = { SecretKey = new string('a', 32), Issuer = "i", Audience = "a", TokenLifetime = TimeSpan.FromMinutes(30) },
            RefreshTokens = { Lifetime = TimeSpan.FromMinutes(10) },
        });
        r.Failed.Should().BeTrue();
        r.FailureMessage.Should().Contain("Lifetime");
    }

    [Fact]
    public void Valid_options_pass()
    {
        var r = _v.Validate(null, new AuthOptions
        {
            Jwt = { SecretKey = new string('a', 32), Issuer = "i", Audience = "a" },
        });
        r.Succeeded.Should().BeTrue();
    }
}
