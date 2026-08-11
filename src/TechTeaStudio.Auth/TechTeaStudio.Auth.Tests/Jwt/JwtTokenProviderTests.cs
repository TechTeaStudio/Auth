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
    public void CreateToken_drops_reserved_claims_but_preserves_nameid_and_custom_claims()
    {
        var provider = new JwtTokenProvider(TestAuthOptions.Wrap());

        var token = provider.CreateToken(
            "user-1",
            new[]
            {
                new Claim(AuthClaims.Subject, "attacker"),
                new Claim("sub", "attacker-2"),
                new Claim(ClaimTypes.NameIdentifier, "legacy-id-123"),
                new Claim(AuthClaims.Role, "admin"),
            },
            TimeSpan.FromMinutes(5));

        var handler = new JwtSecurityTokenHandler { MapInboundClaims = false };
        var jwt = handler.ReadJwtToken(token);

        // The provider's own sub must survive as a single string claim — not a
        // JSON array collapsed from the duplicate caller-supplied "sub" claims.
        var subClaims = jwt.Claims.Where(c => c.Type == AuthClaims.Subject).ToList();
        subClaims.Should().ContainSingle();
        subClaims[0].Value.Should().Be("user-1");

        // A distinct claim type (nameid != sub) must not be swept up by the filter.
        jwt.Claims.Should().Contain(c => c.Type == "nameid" && c.Value == "legacy-id-123");

        // Ordinary custom claims are untouched.
        jwt.Claims.Should().Contain(c => c.Type == AuthClaims.Role && c.Value == "admin");
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

    [Fact]
    public void CreateToken_with_descriptor_overrides_audience_and_issuer()
    {
        var provider = new JwtTokenProvider(TestAuthOptions.Wrap());
        var token = provider.CreateToken(
            "user-1",
            Array.Empty<Claim>(),
            new TokenDescriptor { Audience = "other-aud", Issuer = "other-iss", Lifetime = TimeSpan.FromMinutes(5) });

        var jwt = new JwtSecurityTokenHandler().ReadJwtToken(token);
        jwt.Audiences.Should().ContainSingle().Which.Should().Be("other-aud");
        jwt.Issuer.Should().Be("other-iss");
    }

    [Fact]
    public void CreateToken_with_descriptor_falls_back_to_configured_audience_and_issuer_when_null()
    {
        var opts = TestAuthOptions.Create();
        var provider = new JwtTokenProvider(opts.ToMonitor());
        var token = provider.CreateToken("user-1", Array.Empty<Claim>(), new TokenDescriptor { Lifetime = TimeSpan.FromMinutes(5) });

        var jwt = new JwtSecurityTokenHandler().ReadJwtToken(token);
        jwt.Audiences.Should().ContainSingle().Which.Should().Be(opts.Jwt.Audience);
        jwt.Issuer.Should().Be(opts.Jwt.Issuer);
    }

    [Fact]
    public void CreateToken_with_descriptor_falls_back_to_configured_lifetime_when_null()
    {
        var opts = TestAuthOptions.Create();
        opts.Jwt.TokenLifetime = TimeSpan.FromMinutes(42);
        var provider = new JwtTokenProvider(opts.ToMonitor());
        var token = provider.CreateToken("user-1", Array.Empty<Claim>(), new TokenDescriptor());

        var jwt = new JwtSecurityTokenHandler().ReadJwtToken(token);
        (jwt.ValidTo - jwt.ValidFrom).Should().BeCloseTo(TimeSpan.FromMinutes(42), TimeSpan.FromSeconds(5));
    }

    [Fact]
    public void CreateToken_with_descriptor_still_prepends_sub_and_drops_caller_supplied_sub()
    {
        var provider = new JwtTokenProvider(TestAuthOptions.Wrap());
        var token = provider.CreateToken(
            "user-1",
            new[] { new Claim(AuthClaims.Subject, "attacker") },
            new TokenDescriptor { Audience = "other-aud" });

        var jwt = new JwtSecurityTokenHandler().ReadJwtToken(token);
        var subClaims = jwt.Claims.Where(c => c.Type == AuthClaims.Subject).ToList();
        subClaims.Should().ContainSingle();
        subClaims[0].Value.Should().Be("user-1");
    }

    [Fact]
    public void CreateToken_with_descriptor_round_trips_through_ValidateToken_when_audience_matches_configured()
    {
        var provider = new JwtTokenProvider(TestAuthOptions.Wrap());
        var token = provider.CreateToken("user-1", Array.Empty<Claim>(), new TokenDescriptor());
        provider.ValidateToken(token).Should().NotBeNull();
    }

    [Fact]
    public void CreateToken_with_descriptor_rejects_invalid_arguments()
    {
        var provider = new JwtTokenProvider(TestAuthOptions.Wrap());
        FluentActions.Invoking(() => provider.CreateToken("", Array.Empty<Claim>(), new TokenDescriptor()))
            .Should().Throw<ArgumentException>();
        FluentActions.Invoking(() => provider.CreateToken("u", Array.Empty<Claim>(), (TokenDescriptor)null!))
            .Should().Throw<ArgumentNullException>();
        FluentActions.Invoking(() => provider.CreateToken("u", Array.Empty<Claim>(), new TokenDescriptor { Lifetime = TimeSpan.Zero }))
            .Should().Throw<ArgumentOutOfRangeException>();
    }

    [Fact]
    public void CreateToken_TimeSpan_overload_and_descriptor_overload_produce_equivalent_tokens()
    {
        var opts = TestAuthOptions.Create();
        var provider = new JwtTokenProvider(opts.ToMonitor());

        var claims = new[] { new Claim(AuthClaims.Email, "u@x") };
        var viaTimeSpan = provider.CreateToken("user-1", claims, TimeSpan.FromMinutes(5));
        var viaDescriptor = provider.CreateToken("user-1", claims, new TokenDescriptor { Lifetime = TimeSpan.FromMinutes(5) });

        var handler = new JwtSecurityTokenHandler();
        var jwtA = handler.ReadJwtToken(viaTimeSpan);
        var jwtB = handler.ReadJwtToken(viaDescriptor);

        jwtA.Audiences.Should().BeEquivalentTo(jwtB.Audiences);
        jwtA.Issuer.Should().Be(jwtB.Issuer);
        jwtA.Claims.Select(c => c.Type).Where(t => t != AuthClaims.JwtId).Should()
            .BeEquivalentTo(jwtB.Claims.Select(c => c.Type).Where(t => t != AuthClaims.JwtId));
    }
}
