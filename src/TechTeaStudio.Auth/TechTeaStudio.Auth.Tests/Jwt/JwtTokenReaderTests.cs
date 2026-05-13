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
    public void TryRead_falls_back_to_legacy_nameid_for_UserId()
    {
        // Build a token by hand with only the legacy nameid claim, no sub.
        var provider = new JwtTokenProvider(TestAuthOptions.Wrap());
#pragma warning disable CS0618
        var token = provider.CreateToken("ignored-because-overridden", new[]
        {
            new Claim(AuthClaims.LegacyNameId, "legacy-user"),
        }, TimeSpan.FromMinutes(5));
#pragma warning restore CS0618

        // The provider always writes sub from userId; for this test, validate that
        // a synthesized payload missing sub still falls back. We strip the sub.
        var parts = token.Split('.');
        var payloadJson = System.Text.Encoding.UTF8.GetString(Convert.FromBase64String(PadBase64(parts[1])));
        var stripped = payloadJson.Replace("\"sub\":\"ignored-because-overridden\",", "");
        var rebuilt = Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(stripped))
            .TrimEnd('=').Replace('+', '-').Replace('/', '_');
        var rebuiltToken = parts[0] + "." + rebuilt + "." + parts[2];

        var info = new JwtTokenReader().TryRead(rebuiltToken);
        info.Should().NotBeNull();
        info!.UserId.Should().Be("legacy-user");
    }

    private static string PadBase64(string s)
    {
        s = s.Replace('-', '+').Replace('_', '/');
        switch (s.Length % 4) { case 2: s += "=="; break; case 3: s += "="; break; }
        return s;
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
