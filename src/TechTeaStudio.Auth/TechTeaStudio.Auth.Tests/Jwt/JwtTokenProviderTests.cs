using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using FluentAssertions;
using Microsoft.Extensions.Options;
using TechTeaStudio.Auth.Abstractions;
using TechTeaStudio.Auth.Jwt;
using TechTeaStudio.Auth.Tests.TestHelpers;
using Xunit;

namespace TechTeaStudio.Auth.Tests.Jwt;

public class JwtTokenProviderTests
{
    [Fact]
    public void CreateToken_round_trips_through_ValidateToken()
    {
        var provider = new JwtTokenProvider(TestAuthOptions.Wrap());

        var token = provider.CreateToken(
            "user-1",
            new[] { new Claim(AuthClaims.Email, "u@x") },
            TimeSpan.FromMinutes(5));

        var principal = provider.ValidateToken(token);
        principal.Should().NotBeNull();
        principal!.FindFirst(AuthClaims.Subject)!.Value.Should().Be("user-1");
        principal.FindFirst(AuthClaims.Email)!.Value.Should().Be("u@x");
    }

    [Fact]
    public void CreateToken_always_emits_jti_and_iat()
    {
        var provider = new JwtTokenProvider(TestAuthOptions.Wrap());
        var token = provider.CreateToken("u", Array.Empty<Claim>(), TimeSpan.FromMinutes(1));

        var jwt = new JwtSecurityTokenHandler().ReadJwtToken(token);
        jwt.Claims.Should().Contain(c => c.Type == AuthClaims.JwtId);
        jwt.Claims.Should().Contain(c => c.Type == AuthClaims.IssuedAt);
    }

    [Fact]
    public void Two_tokens_have_different_jti()
    {
        var provider = new JwtTokenProvider(TestAuthOptions.Wrap());
        var t1 = provider.CreateToken("u", Array.Empty<Claim>(), TimeSpan.FromMinutes(1));
        var t2 = provider.CreateToken("u", Array.Empty<Claim>(), TimeSpan.FromMinutes(1));

        var jti1 = new JwtSecurityTokenHandler().ReadJwtToken(t1).Claims.First(c => c.Type == AuthClaims.JwtId).Value;
        var jti2 = new JwtSecurityTokenHandler().ReadJwtToken(t2).Claims.First(c => c.Type == AuthClaims.JwtId).Value;
        jti1.Should().NotBe(jti2);
    }

    [Fact]
    public void ValidateToken_returns_null_for_garbage()
    {
        var provider = new JwtTokenProvider(TestAuthOptions.Wrap());
        provider.ValidateToken("not-a-jwt").Should().BeNull();
        provider.ValidateToken("").Should().BeNull();
    }

    [Fact]
    public void ValidateToken_returns_null_for_token_signed_with_different_key()
    {
        var issuer = new JwtTokenProvider(TestAuthOptions.Wrap(TestAuthOptions.Create(
            secret: "ANOTHER-signing-key-that-is-32+!!")));
        var token = issuer.CreateToken("u", Array.Empty<Claim>(), TimeSpan.FromMinutes(5));

        var validator = new JwtTokenProvider(TestAuthOptions.Wrap());
        validator.ValidateToken(token).Should().BeNull();
    }

    [Fact]
    public void ValidateToken_returns_null_for_wrong_audience()
    {
        var issuer = new JwtTokenProvider(TestAuthOptions.Wrap(TestAuthOptions.Create(audience: "other")));
        var token = issuer.CreateToken("u", Array.Empty<Claim>(), TimeSpan.FromMinutes(5));

        var validator = new JwtTokenProvider(TestAuthOptions.Wrap());
        validator.ValidateToken(token).Should().BeNull();
    }

    [Fact]
    public void ValidateToken_returns_null_for_expired_token()
    {
        var opts = TestAuthOptions.Create();
        opts.Jwt.ClockSkew = TimeSpan.Zero;
        var provider = new JwtTokenProvider(opts.ToMonitor());

        // Issue a token that is already expired.
        var token = provider.CreateToken("u", Array.Empty<Claim>(), TimeSpan.FromMilliseconds(1));
        Thread.Sleep(50);

        provider.ValidateToken(token).Should().BeNull();
    }

    [Fact]
    public void Constructor_rejects_short_secret_key()
    {
        var monitor = new AuthOptions { Jwt = { SecretKey = "short", Issuer = "i", Audience = "a" } }.ToMonitor();
        var act = () => new JwtTokenProvider(monitor);
        act.Should().Throw<InvalidOperationException>();
    }

    [Fact]
    public void CreateToken_rejects_invalid_arguments()
    {
        var provider = new JwtTokenProvider(TestAuthOptions.Wrap());
        FluentActions.Invoking(() => provider.CreateToken("", Array.Empty<Claim>(), TimeSpan.FromMinutes(1)))
            .Should().Throw<ArgumentException>();
        FluentActions.Invoking(() => provider.CreateToken("u", Array.Empty<Claim>(), TimeSpan.Zero))
            .Should().Throw<ArgumentOutOfRangeException>();
    }
}
