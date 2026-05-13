using FluentAssertions;
using TechTeaStudio.Auth.Abstractions;
using TechTeaStudio.Auth.Profiles;
using Xunit;

namespace TechTeaStudio.Auth.Tests.Profiles;

public class HyperionClaimsProfileTests
{
    [Fact]
    public void Emits_sub_username_email_role_and_legacy_nameid()
    {
        var profile = new HyperionClaimsProfile();
        var claims = profile.BuildClaims(new ClaimsBuilderInput
        {
            UserId = "u-1",
            Username = "neo",
            Email = "n@x",
            Roles = new[] { "admin", "engineer" },
        }).ToList();

        claims.Should().Contain(c => c.Type == AuthClaims.Subject && c.Value == "u-1");
        claims.Should().Contain(c => c.Type == AuthClaims.Username && c.Value == "neo");
        claims.Should().Contain(c => c.Type == AuthClaims.Email && c.Value == "n@x");
        claims.Where(c => c.Type == AuthClaims.Role).Select(c => c.Value)
            .Should().BeEquivalentTo(new[] { "admin", "engineer" });

#pragma warning disable CS0618
        claims.Should().Contain(c => c.Type == AuthClaims.LegacyNameId && c.Value == "u-1");
#pragma warning restore CS0618
    }

    [Fact]
    public void Skips_empty_fields()
    {
        var claims = new HyperionClaimsProfile().BuildClaims(new ClaimsBuilderInput()).ToList();
        claims.Should().BeEmpty();
    }

    [Fact]
    public void Extras_passthrough()
    {
        var claims = new HyperionClaimsProfile().BuildClaims(new ClaimsBuilderInput
        {
            UserId = "u",
            Extra = new Dictionary<string, string> { ["tenant"] = "acme" },
        }).ToList();
        claims.Should().Contain(c => c.Type == "tenant" && c.Value == "acme");
    }
}

public class PelloClaimsProfileTests
{
    [Fact]
    public void Emits_email_and_username_only()
    {
        var profile = new PelloClaimsProfile();
        var claims = profile.BuildClaims(new ClaimsBuilderInput
        {
            UserId = "ignored",
            Email = "u@x",
            Username = "Display Name",
            Roles = new[] { "ignored" },
        }).ToList();

        claims.Should().Contain(c => c.Type == AuthClaims.Email && c.Value == "u@x");
        claims.Should().Contain(c => c.Type == AuthClaims.Username && c.Value == "Display Name");
        claims.Should().NotContain(c => c.Type == AuthClaims.Role);
        claims.Should().NotContain(c => c.Type == AuthClaims.Subject);
    }
}

public class ClaimsProfilesTests
{
    [Fact]
    public void Built_in_singletons_exposed()
    {
        ClaimsProfiles.Hyperion.Should().BeOfType<HyperionClaimsProfile>();
        ClaimsProfiles.Pello.Should().BeOfType<PelloClaimsProfile>();
        ClaimsProfiles.Hyperion.Name.Should().Be("Hyperion");
        ClaimsProfiles.Pello.Name.Should().Be("Pello");
    }
}
