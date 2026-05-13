using System.Text;
using FluentAssertions;
using TechTeaStudio.Auth.TwoFactor;
using Xunit;

namespace TechTeaStudio.Auth.Tests.TwoFactor;

public class TotpTests
{
    // RFC 6238 Appendix B test vectors use HMAC-SHA1 with the secret "12345678901234567890"
    // and 8-digit codes. Sampling a couple of them as sanity checks.
    private static readonly byte[] RfcSecret = Encoding.UTF8.GetBytes("12345678901234567890");

    [Theory]
    [InlineData(59L, "94287082")]
    [InlineData(1111111109L, "07081804")]
    [InlineData(1234567890L, "89005924")]
    public void Generate_matches_rfc6238_vectors_for_8_digits(long unixSeconds, string expected)
    {
        var code = TotpGenerator.Generate(RfcSecret, DateTimeOffset.FromUnixTimeSeconds(unixSeconds), digits: 8);
        code.Should().Be(expected);
    }

    [Fact]
    public void Validate_accepts_current_code()
    {
        var secret = Encoding.UTF8.GetBytes("12345678901234567890");
        var now = DateTimeOffset.UtcNow;
        var code = TotpGenerator.Generate(secret, now);
        TotpValidator.Validate(secret, code, now).Should().BeTrue();
    }

    [Fact]
    public void Validate_rejects_wrong_code()
    {
        var secret = Encoding.UTF8.GetBytes("12345678901234567890");
        TotpValidator.Validate(secret, "000000", DateTimeOffset.UtcNow).Should().BeFalse();
    }

    [Fact]
    public void Validate_tolerates_one_step_skew_by_default()
    {
        var secret = Encoding.UTF8.GetBytes("12345678901234567890");
        var now = DateTimeOffset.UtcNow;
        var oneStepBack = now.AddSeconds(-TotpGenerator.DefaultPeriodSeconds);
        var oldCode = TotpGenerator.Generate(secret, oneStepBack);
        TotpValidator.Validate(secret, oldCode, now).Should().BeTrue();
    }

    [Fact]
    public void Validate_rejects_far_in_past_code_when_skew_zero()
    {
        var secret = Encoding.UTF8.GetBytes("12345678901234567890");
        var now = DateTimeOffset.UtcNow;
        var oldCode = TotpGenerator.Generate(secret, now.AddSeconds(-TotpGenerator.DefaultPeriodSeconds * 3));
        TotpValidator.Validate(secret, oldCode, now, allowedSkew: 0).Should().BeFalse();
    }
}

public class OtpAuthUriTests
{
    [Fact]
    public void Base32_round_trip_well_formed()
    {
        var s = OtpAuthUri.ToBase32(new byte[] { 0x48, 0x65, 0x6C, 0x6C, 0x6F });
        // "Hello" — 40 bits = 8 base32 chars exactly, no padding needed.
        s.Should().Be("JBSWY3DP");
    }

    [Fact]
    public void Builds_canonical_otpauth_uri()
    {
        var uri = OtpAuthUri.Build("TechTeaStudio", "u@x", "JBSWY3DPEB");
        uri.Should().StartWith("otpauth://totp/TechTeaStudio%3Au%40x?secret=JBSWY3DPEB&issuer=TechTeaStudio");
        uri.Should().Contain("digits=6");
        uri.Should().Contain("period=30");
    }
}
