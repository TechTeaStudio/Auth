using FluentAssertions;
using TechTeaStudio.Auth.TwoFactor;
using Xunit;

namespace TechTeaStudio.Auth.Tests.TwoFactor;

public class RecoveryCodeServiceTests
{
    [Fact]
    public void Generate_yields_unique_codes_of_expected_shape()
    {
        var codes = RecoveryCodeService.Generate(count: 10, length: 8);
        codes.Should().HaveCount(10);
        codes.Distinct().Should().HaveCount(10);
        foreach (var c in codes)
        {
            c.Length.Should().Be(8);
            c.Should().MatchRegex("^[A-Z2-9]{8}$");
        }
    }

    [Fact]
    public void Hash_is_deterministic_and_case_insensitive()
    {
        RecoveryCodeService.Hash("abcd1234").Should().Be(RecoveryCodeService.Hash("ABCD1234"));
        RecoveryCodeService.Hash("  ab23cd45  ").Should().Be(RecoveryCodeService.Hash("AB23CD45"));
    }

    [Fact]
    public void Verify_round_trips_against_hash()
    {
        var code = "ABCD2345";
        var hash = RecoveryCodeService.Hash(code);
        RecoveryCodeService.Verify(code, hash).Should().BeTrue();
        RecoveryCodeService.Verify("WRONG234", hash).Should().BeFalse();
    }

    [Fact]
    public void Alphabet_excludes_lookalikes()
    {
        RecoveryCodeService.Alphabet.Should().NotContain("0");
        RecoveryCodeService.Alphabet.Should().NotContain("O");
        RecoveryCodeService.Alphabet.Should().NotContain("1");
        RecoveryCodeService.Alphabet.Should().NotContain("I");
        RecoveryCodeService.Alphabet.Should().NotContain("L");
    }
}
