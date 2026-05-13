using FluentAssertions;
using TechTeaStudio.Auth.RefreshTokens;
using Xunit;

namespace TechTeaStudio.Auth.Tests.RefreshTokens;

public class TokenHasherTests
{
    [Fact]
    public void Hash_is_deterministic_per_input()
    {
        var a = TokenHasher.HashRefreshToken("payload");
        var b = TokenHasher.HashRefreshToken("payload");
        a.Should().Be(b);
        a.Length.Should().Be(64);
    }

    [Fact]
    public void Hash_is_lower_case_hex()
    {
        TokenHasher.HashRefreshToken("x").Should().MatchRegex("^[0-9a-f]+$");
    }

    [Fact]
    public void Empty_input_yields_empty_string()
    {
        TokenHasher.HashRefreshToken("").Should().BeEmpty();
    }

    [Fact]
    public void Different_inputs_yield_different_hashes()
    {
        TokenHasher.HashRefreshToken("a").Should().NotBe(TokenHasher.HashRefreshToken("b"));
    }
}
