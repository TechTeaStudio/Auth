using System.Reflection;
using FluentAssertions;
using TechTeaStudio.Auth.Abstractions;
using Xunit;

namespace TechTeaStudio.Auth.Tests.Abstractions;

public class InterfaceShapeTests
{
    [Fact]
    public void ITokenProvider_has_expected_members()
    {
        var t = typeof(ITokenProvider);
        t.GetMethod("CreateToken").Should().NotBeNull();
        t.GetMethod("ValidateToken").Should().NotBeNull();
    }

    [Fact]
    public void IPasswordHasher_has_expected_members()
    {
        var t = typeof(IPasswordHasher);
        t.GetMethod("Hash").Should().NotBeNull();
        t.GetMethod("Verify").Should().NotBeNull();
    }

    [Fact]
    public void ITokenReader_has_TryRead()
    {
        typeof(ITokenReader).GetMethod("TryRead").Should().NotBeNull();
    }

    [Fact]
    public void IRefreshTokenStore_has_seven_methods()
    {
        var members = typeof(IRefreshTokenStore)
            .GetMethods(BindingFlags.Public | BindingFlags.Instance | BindingFlags.DeclaredOnly)
            .Select(m => m.Name)
            .ToHashSet();

        members.Should().Contain(new[]
        {
            "GetByTokenHashAsync",
            "GetActiveForUserAsync",
            "CreateAsync",
            "RevokeAsync",
            "RevokeAllForUserAsync",
            "CleanupExpiredAsync",
            "DeleteAllForUserAsync",
        });
    }
}
