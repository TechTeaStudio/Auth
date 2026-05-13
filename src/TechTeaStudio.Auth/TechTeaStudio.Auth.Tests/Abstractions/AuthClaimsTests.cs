using FluentAssertions;
using TechTeaStudio.Auth.Abstractions;
using Xunit;

namespace TechTeaStudio.Auth.Tests.Abstractions;

public class AuthClaimsTests
{
    [Fact]
    public void Constants_match_rfc7519_short_names()
    {
        AuthClaims.Subject.Should().Be("sub");
        AuthClaims.JwtId.Should().Be("jti");
        AuthClaims.IssuedAt.Should().Be("iat");
        AuthClaims.Email.Should().Be("email");
    }

    [Fact]
    public void Username_matches_microsoft_unique_name_claim()
    {
        AuthClaims.Username.Should().Be("unique_name");
    }

    [Fact]
    public void Role_uses_short_name()
    {
        AuthClaims.Role.Should().Be("role");
    }

#pragma warning disable CS0618
    [Fact]
    public void LegacyNameId_kept_for_backward_compat()
    {
        AuthClaims.LegacyNameId.Should().Be("nameid");
    }
#pragma warning restore CS0618

    [Fact]
    public void Class_is_static()
    {
        typeof(AuthClaims).IsAbstract.Should().BeTrue();
        typeof(AuthClaims).IsSealed.Should().BeTrue();
    }
}
