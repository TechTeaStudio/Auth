using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using FluentAssertions;
using TechTeaStudio.Auth.Jwt;
using TechTeaStudio.Auth.Signing;
using TechTeaStudio.Auth.Tests.TestHelpers;
using Xunit;

namespace TechTeaStudio.Auth.Tests.Signing;

public class KeyRotationTests
{
    [Fact]
    public void New_token_carries_kid_header()
    {
        var opts = new AuthOptions
        {
            Jwt =
            {
                Issuer = "iss",
                Audience = "aud",
                Signing =
                {
                    ActiveKid = "k1",
                    Keys = { new SigningKeyDescriptor { Kid = "k1", SymmetricKey = new string('1', 32) } },
                },
            },
        };
        var provider = new JwtTokenProvider(opts.ToMonitor());
        var token = provider.CreateToken("u", Array.Empty<Claim>(), TimeSpan.FromMinutes(5));

        var jwt = new JwtSecurityTokenHandler().ReadJwtToken(token);
        jwt.Header.Should().ContainKey("kid");
        jwt.Header["kid"].Should().Be("k1");
    }

    [Fact]
    public void Old_token_still_validates_during_retention_window()
    {
        var k1 = new SigningKeyDescriptor { Kid = "k1", SymmetricKey = new string('1', 32) };
        var k2 = new SigningKeyDescriptor { Kid = "k2", SymmetricKey = new string('2', 32) };

        var optsOld = new AuthOptions { Jwt = { Issuer = "iss", Audience = "aud", Signing = { ActiveKid = "k1", Keys = { k1 } } } };
        var optsNew = new AuthOptions { Jwt = { Issuer = "iss", Audience = "aud", Signing = { ActiveKid = "k2", Keys = { k1, k2 } } } };

        var oldProvider = new JwtTokenProvider(optsOld.ToMonitor());
        var token = oldProvider.CreateToken("u", Array.Empty<Claim>(), TimeSpan.FromMinutes(5));

        var newProvider = new JwtTokenProvider(optsNew.ToMonitor());
        newProvider.ValidateToken(token).Should().NotBeNull();
    }

    [Fact]
    public void RS256_signed_token_validates()
    {
        using var rsa = RSA.Create(2048);
        var pem = rsa.ExportRSAPrivateKeyPem();
        var opts = new AuthOptions
        {
            Jwt =
            {
                Issuer = "iss",
                Audience = "aud",
                Signing =
                {
                    ActiveKid = "r1",
                    Keys = { new SigningKeyDescriptor { Kid = "r1", Algorithm = SigningAlgorithm.RS256, PrivateKeyPem = pem } },
                },
            },
        };
        var provider = new JwtTokenProvider(opts.ToMonitor());
        var token = provider.CreateToken("u", Array.Empty<Claim>(), TimeSpan.FromMinutes(5));
        provider.ValidateToken(token).Should().NotBeNull();
    }

    [Fact]
    public void ES256_signed_token_validates()
    {
        using var ec = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var pem = ec.ExportECPrivateKeyPem();
        var opts = new AuthOptions
        {
            Jwt =
            {
                Issuer = "iss",
                Audience = "aud",
                Signing =
                {
                    ActiveKid = "e1",
                    Keys = { new SigningKeyDescriptor { Kid = "e1", Algorithm = SigningAlgorithm.ES256, PrivateKeyPem = pem } },
                },
            },
        };
        var provider = new JwtTokenProvider(opts.ToMonitor());
        var token = provider.CreateToken("u", Array.Empty<Claim>(), TimeSpan.FromMinutes(5));
        provider.ValidateToken(token).Should().NotBeNull();
    }
}
