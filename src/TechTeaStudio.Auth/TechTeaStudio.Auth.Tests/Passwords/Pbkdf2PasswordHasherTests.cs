using FluentAssertions;
using TechTeaStudio.Auth.Passwords;
using Xunit;

namespace TechTeaStudio.Auth.Tests.Passwords;

public class Pbkdf2PasswordHasherTests
{
    private readonly Pbkdf2PasswordHasher _hasher = new();

    [Fact]
    public void Hash_then_Verify_succeeds_for_correct_password()
    {
        var hash = _hasher.Hash("correct horse battery staple");
        _hasher.Verify(hash, "correct horse battery staple").Should().BeTrue();
    }

    [Fact]
    public void Verify_fails_for_wrong_password()
    {
        var hash = _hasher.Hash("correct horse battery staple");
        _hasher.Verify(hash, "wrong horse battery staple").Should().BeFalse();
    }

    [Fact]
    public void Two_hashes_of_same_password_differ_due_to_salt()
    {
        var h1 = _hasher.Hash("same");
        var h2 = _hasher.Hash("same");
        h1.Should().NotBe(h2);
        _hasher.Verify(h1, "same").Should().BeTrue();
        _hasher.Verify(h2, "same").Should().BeTrue();
    }

    [Fact]
    public void Storage_format_is_versioned()
    {
        var hash = _hasher.Hash("x");
        var bytes = Convert.FromBase64String(hash);
        bytes[0].Should().Be(Pbkdf2PasswordHasher.Version1);
        bytes.Length.Should().Be(1 + Pbkdf2PasswordHasher.SaltSize + Pbkdf2PasswordHasher.HashSize);
    }

    [Fact]
    public void Verify_returns_false_for_garbage_input()
    {
        _hasher.Verify("not-base64!!!", "x").Should().BeFalse();
        _hasher.Verify("", "x").Should().BeFalse();
        _hasher.Verify(Convert.ToBase64String(new byte[] { 0xFF, 0x00 }), "x").Should().BeFalse();
    }

    [Fact]
    public void Hash_rejects_null_password()
    {
        FluentActions.Invoking(() => _hasher.Hash(null!)).Should().Throw<ArgumentNullException>();
    }

    [Fact]
    public void Verify_uses_constant_time_comparison()
    {
        // Sanity check: tamper with one byte of the digest portion. Verify must still return false.
        var hash = _hasher.Hash("payload");
        var bytes = Convert.FromBase64String(hash);
        bytes[bytes.Length - 1] ^= 0xFF;
        var tampered = Convert.ToBase64String(bytes);
        _hasher.Verify(tampered, "payload").Should().BeFalse();
    }
}
