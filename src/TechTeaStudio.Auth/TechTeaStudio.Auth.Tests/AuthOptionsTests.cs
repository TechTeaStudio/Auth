using System.ComponentModel.DataAnnotations;
using FluentAssertions;
using TechTeaStudio.Auth.AspNetCore;
using Xunit;

namespace TechTeaStudio.Auth.Tests;

public class AuthOptionsTests
{
    private readonly AuthOptionsValidator _validator = new();

    [Fact]
    public void Defaults_match_hyperion_production_values()
    {
        var o = new AuthOptions();
        o.TokenLifetime.Should().Be(TimeSpan.FromMinutes(30));
        o.RefreshTokenLifetime.Should().Be(TimeSpan.FromDays(7));
        o.ClockSkew.Should().Be(TimeSpan.FromMinutes(5));
        o.MaxFailedLoginAttempts.Should().Be(5);
        o.LockoutDuration.Should().Be(TimeSpan.FromMinutes(15));
        o.Signing.Should().NotBeNull();
        o.Signing.Keys.Should().BeEmpty();
        o.Signing.KeyRetention.Should().Be(TimeSpan.FromDays(7));
    }

    [Fact]
    public void Empty_SecretKey_with_no_Signing_Keys_fails_via_cross_property_validator()
    {
        var o = new AuthOptions { SecretKey = "", Issuer = "i", Audience = "a" };
        var r = _validator.Validate(null, o);
        r.Failed.Should().BeTrue();
        r.FailureMessage.Should().Contain("SecretKey");
    }

    [Fact]
    public void Short_SecretKey_fails_via_cross_property_validator()
    {
        var o = new AuthOptions { SecretKey = new string('x', 31), Issuer = "i", Audience = "a" };
        var r = _validator.Validate(null, o);
        r.Failed.Should().BeTrue();
        r.FailureMessage.Should().Contain("32 bytes");
    }

    [Fact]
    public void Exactly_32_chars_passes()
    {
        var o = new AuthOptions { SecretKey = new string('x', 32), Issuer = "i", Audience = "a" };
        Validate(o).Should().BeEmpty();
        _validator.Validate(null, o).Succeeded.Should().BeTrue();
    }

    [Fact]
    public void Missing_Issuer_or_Audience_fails()
    {
        var o = new AuthOptions { SecretKey = new string('x', 32), Issuer = "", Audience = "" };
        var results = Validate(o);
        results.Should().Contain(r => r.MemberNames.Contains(nameof(AuthOptions.Issuer)));
        results.Should().Contain(r => r.MemberNames.Contains(nameof(AuthOptions.Audience)));
    }

    [Fact]
    public void Zero_max_failed_attempts_fails()
    {
        var o = new AuthOptions { SecretKey = new string('x', 32), Issuer = "i", Audience = "a", MaxFailedLoginAttempts = 0 };
        Validate(o).Should().Contain(r => r.MemberNames.Contains(nameof(AuthOptions.MaxFailedLoginAttempts)));
    }

    private static IReadOnlyList<ValidationResult> Validate(AuthOptions o)
    {
        var ctx = new ValidationContext(o);
        var results = new List<ValidationResult>();
        Validator.TryValidateObject(o, ctx, results, validateAllProperties: true);
        return results;
    }
}
