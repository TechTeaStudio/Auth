using System.Security.Claims;
using FluentAssertions;
using TechTeaStudio.Auth.Abstractions;
using TechTeaStudio.Auth.Jwt;
using TechTeaStudio.Auth.Tests.TestHelpers;
using Xunit;

namespace TechTeaStudio.Auth.Tests.Jwt;

public class JwtTokenReaderTests
{
    [Fact]
    public void TryRead_returns_null_for_garbage()
    {
        var reader = new JwtTokenReader();
        reader.TryRead("").Should().BeNull();
        reader.TryRead("not-a-jwt").Should().BeNull();
    }

    [Fact]
    public void TryRead_extracts_known_claims()
    {
        var provider = new JwtTokenProvider(TestAuthOptions.Wrap());
        var token = provider.CreateToken("user-42", new[]
        {
            new Claim(AuthClaims.Username, "neo"),
            new Claim(AuthClaims.Email, "neo@matrix"),
            new Claim(AuthClaims.Role, "admin"),
            new Claim(AuthClaims.Role, "engineer"),
        }, TimeSpan.FromMinutes(5));

        var info = new JwtTokenReader().TryRead(token);

        info.Should().NotBeNull();
        info!.UserId.Should().Be("user-42");
        info.Username.Should().Be("neo");
        info.Email.Should().Be("neo@matrix");
        info.Roles.Should().BeEquivalentTo(new[] { "admin", "engineer" });
        info.ExpiresAt.Should().BeAfter(DateTimeOffset.UtcNow);
        info.IsExpired.Should().BeFalse();
    }

    [Fact]
    public void TryRead_does_not_validate_signature()
    {
        // Token signed with key A, read with reader that knows nothing about keys — must still parse.
        var provider = new JwtTokenProvider(TestAuthOptions.Wrap());
        var token = provider.CreateToken("u", Array.Empty<Claim>(), TimeSpan.FromMinutes(5));

        // Forge the signature by changing the last char — payload still readable.
        var parts = token.Split('.');
        parts[2] = new string('A', parts[2].Length);
        var tampered = string.Join('.', parts);

        var info = new JwtTokenReader().TryRead(tampered);
        info.Should().NotBeNull();
        info!.UserId.Should().Be("u");
    }
}
