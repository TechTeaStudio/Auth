using System.Security.Cryptography;
using FluentAssertions;
using Microsoft.IdentityModel.Tokens;
using TechTeaStudio.Auth.Signing;
using Xunit;

namespace TechTeaStudio.Auth.Tests.Signing;

public class SigningKeyResolverTests
{
    [Fact]
    public void Legacy_SecretKey_path_synthesizes_default_descriptor()
    {
        var o = new AuthOptions { SecretKey = new string('a', 32), Issuer = "i", Audience = "a" };
        var active = SigningKeyResolver.ResolveActive(o);
        active.Kid.Should().Be(SigningKeyResolver.LegacyDefaultKid);
        active.Algorithm.Should().Be(SigningAlgorithm.HS256);
    }

    [Fact]
    public void ActiveKid_selects_matching_descriptor()
    {
        var o = NewWithTwoHmacKeys("kid-a", "kid-b", activeKid: "kid-b");
        var active = SigningKeyResolver.ResolveActive(o);
        active.Kid.Should().Be("kid-b");
    }

    [Fact]
    public void ResolveValidating_includes_keys_within_retention()
    {
        var o = NewWithTwoHmacKeys("old", "new", activeKid: "new");
        // Make "old" older than retention.
        o.Signing.Keys[0].CreatedAt = DateTimeOffset.UtcNow - TimeSpan.FromDays(30);
        o.Signing.KeyRetention = TimeSpan.FromDays(7);

        var kids = SigningKeyResolver.ResolveValidating(o).Select(k => k.Kid).ToHashSet();
        kids.Should().Contain("new");
        kids.Should().NotContain("old"); // outside retention
    }

    [Fact]
    public void ResolveValidating_keeps_active_even_when_old()
    {
        var o = NewWithTwoHmacKeys("active-but-old", "ignored", activeKid: "active-but-old");
        o.Signing.Keys[0].CreatedAt = DateTimeOffset.UtcNow - TimeSpan.FromDays(60);

        SigningKeyResolver.ResolveValidating(o).Should().Contain(k => k.Kid == "active-but-old");
    }

    [Fact]
    public void RS256_round_trips_via_RsaSecurityKey()
    {
        using var rsa = RSA.Create(2048);
        var privatePem = rsa.ExportRSAPrivateKeyPem();
        var publicPem = rsa.ExportSubjectPublicKeyInfoPem();

        var d = new SigningKeyDescriptor
        {
            Kid = "rsa-1",
            Algorithm = SigningAlgorithm.RS256,
            PrivateKeyPem = privatePem,
        };

        var sign = SigningKeyResolver.BuildSigningCredentials(d);
        sign.Key.Should().BeOfType<RsaSecurityKey>();
        sign.Algorithm.Should().Be(SecurityAlgorithms.RsaSha256);

        var validateOnly = new SigningKeyDescriptor
        {
            Kid = "rsa-1",
            Algorithm = SigningAlgorithm.RS256,
            PublicKeyPem = publicPem,
        };
        var v = SigningKeyResolver.BuildValidationKey(validateOnly);
        v.Should().BeOfType<RsaSecurityKey>();
        v.KeyId.Should().Be("rsa-1");
    }

    [Fact]
    public void ES256_round_trips_via_ECDsaSecurityKey()
    {
        using var ec = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var pem = ec.ExportECPrivateKeyPem();

        var d = new SigningKeyDescriptor
        {
            Kid = "ec-1",
            Algorithm = SigningAlgorithm.ES256,
            PrivateKeyPem = pem,
        };

        var sign = SigningKeyResolver.BuildSigningCredentials(d);
        sign.Key.Should().BeOfType<ECDsaSecurityKey>();
        sign.Algorithm.Should().Be(SecurityAlgorithms.EcdsaSha256);
    }

    private static AuthOptions NewWithTwoHmacKeys(string kid1, string kid2, string activeKid) => new()
    {
        Issuer = "i",
        Audience = "a",
        Signing = new SigningOptions
        {
            ActiveKid = activeKid,
            Keys =
            {
                new SigningKeyDescriptor { Kid = kid1, Algorithm = SigningAlgorithm.HS256, SymmetricKey = new string('1', 32) },
                new SigningKeyDescriptor { Kid = kid2, Algorithm = SigningAlgorithm.HS256, SymmetricKey = new string('2', 32) },
            },
        },
    };
}
