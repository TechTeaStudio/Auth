using System.Reflection;
using FluentAssertions;
using TechTeaStudio.Auth.OAuth;
using TechTeaStudio.Auth.RefreshTokens;
using Xunit;

namespace TechTeaStudio.Auth.Tests.Abstractions;

/// <summary>
/// The C# 15 union results ship in the <c>net11.0</c> assets only. On every older target the
/// assemblies must not contain a trace of them: that is the guarantee a <c>net10.0</c> consumer
/// (Hyperion) relies on to notice nothing. Everything here goes through reflection by name so
/// the same file compiles on every test target.
/// </summary>
public class UnionSurfaceTests
{
    private static readonly Assembly Core = typeof(RefreshTokenService).Assembly;
    private static readonly Assembly OAuth = typeof(ExternalLoginService).Assembly;

    public static IEnumerable<object[]> CoreUnionTypes() => new[]
    {
        new object[] { "TechTeaStudio.Auth.RefreshTokens.RefreshRotation" },
    };

    public static IEnumerable<object[]> CoreCaseTypes() => new[]
    {
        new object[] { "TechTeaStudio.Auth.RefreshTokens.RefreshRotated" },
        new object[] { "TechTeaStudio.Auth.RefreshTokens.RefreshTokenInvalid" },
        new object[] { "TechTeaStudio.Auth.RefreshTokens.RefreshTokenExpired" },
        new object[] { "TechTeaStudio.Auth.RefreshTokens.RefreshTokenReused" },
        new object[] { "TechTeaStudio.Auth.RefreshTokens.RefreshRotationMapper" },
    };

    public static IEnumerable<object[]> OAuthUnionTypes() => new[]
    {
        new object[] { "TechTeaStudio.Auth.OAuth.ExternalSignIn" },
        new object[] { "TechTeaStudio.Auth.OAuth.ExternalSignInCompletion" },
    };

    public static IEnumerable<object[]> OAuthCaseTypes() => new[]
    {
        new object[] { "TechTeaStudio.Auth.OAuth.ExternalSignedIn" },
        new object[] { "TechTeaStudio.Auth.OAuth.ExternalPasswordRequired" },
        new object[] { "TechTeaStudio.Auth.OAuth.ExternalRegistrationRequired" },
        new object[] { "TechTeaStudio.Auth.OAuth.ExternalSignInFailed" },
    };

    private static readonly string[] OAuthUnionMethods =
    {
        "SignInAsUnionAsync",
        "LinkExistingAccountAsUnionAsync",
        "CompleteRegistrationAsUnionAsync",
        "LinkToUserAsUnionAsync",
    };

    private const BindingFlags AnyMember =
        BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance | BindingFlags.Static;

#if !NET11_0_OR_GREATER
    [Theory]
    [MemberData(nameof(CoreUnionTypes))]
    [MemberData(nameof(CoreCaseTypes))]
    public void Core_assembly_has_no_union_type_before_net11(string typeName) =>
        Core.GetType(typeName).Should().BeNull();

    [Theory]
    [MemberData(nameof(OAuthUnionTypes))]
    [MemberData(nameof(OAuthCaseTypes))]
    public void OAuth_assembly_has_no_union_type_before_net11(string typeName) =>
        OAuth.GetType(typeName).Should().BeNull();

    [Fact]
    public void RefreshTokenService_has_no_union_method_before_net11() =>
        typeof(RefreshTokenService).GetMember("RotateAsUnionAsync", AnyMember).Should().BeEmpty();

    [Fact]
    public void ExternalLoginService_has_no_union_method_before_net11()
    {
        foreach (var name in OAuthUnionMethods)
            typeof(ExternalLoginService).GetMember(name, AnyMember).Should().BeEmpty(name);
    }

    [Fact]
    public void No_member_anywhere_mentions_a_union_before_net11()
    {
        // Belt and braces: whatever a union is called, nothing in either assembly is named for it.
        foreach (var assembly in new[] { Core, OAuth })
        {
            assembly.GetTypes()
                .SelectMany(t => t.GetMembers(AnyMember | BindingFlags.DeclaredOnly))
                .Where(m => m.Name.Contains("Union", StringComparison.Ordinal))
                .Select(m => $"{m.DeclaringType?.FullName}.{m.Name}")
                .Should().BeEmpty();
        }
    }
#else
    private const string UnionAttributeName = "System.Runtime.CompilerServices.UnionAttribute";

    private static void ShouldBeAUnion(Assembly assembly, string typeName)
    {
        var type = assembly.GetType(typeName);
        type.Should().NotBeNull($"{typeName} ships in the net11.0 asset");
        type!.IsPublic.Should().BeTrue();
        type.GetCustomAttributesData().Select(a => a.AttributeType.FullName)
            .Should().Contain(UnionAttributeName);
    }

    [Theory]
    [MemberData(nameof(CoreUnionTypes))]
    public void Core_union_types_carry_UnionAttribute(string typeName) => ShouldBeAUnion(Core, typeName);

    [Theory]
    [MemberData(nameof(OAuthUnionTypes))]
    public void OAuth_union_types_carry_UnionAttribute(string typeName) => ShouldBeAUnion(OAuth, typeName);

    [Theory]
    [MemberData(nameof(CoreCaseTypes))]
    public void Core_case_types_exist_on_net11(string typeName) => Core.GetType(typeName).Should().NotBeNull();

    [Theory]
    [MemberData(nameof(OAuthCaseTypes))]
    public void OAuth_case_types_exist_on_net11(string typeName) => OAuth.GetType(typeName).Should().NotBeNull();

    [Fact]
    public void Union_methods_exist_on_net11()
    {
        typeof(RefreshTokenService).GetMember("RotateAsUnionAsync", BindingFlags.Public | BindingFlags.Instance)
            .Should().HaveCount(2);
        foreach (var name in OAuthUnionMethods)
            typeof(ExternalLoginService).GetMember(name, BindingFlags.Public | BindingFlags.Instance).Should().HaveCount(1, name);
    }

    [Fact]
    public void No_interface_mentions_a_union_type()
    {
        var unions = CoreUnionTypes().Select(o => Core.GetType((string)o[0]))
            .Concat(OAuthUnionTypes().Select(o => OAuth.GetType((string)o[0])))
            .ToHashSet();

        static IEnumerable<Type> Flatten(Type t) =>
            t.IsGenericType ? t.GetGenericArguments().SelectMany(Flatten).Append(t) : new[] { t };

        foreach (var assembly in new[] { Core, OAuth })
        {
            assembly.GetTypes().Where(t => t.IsInterface)
                .SelectMany(t => t.GetMethods())
                .Where(m => m.GetParameters().Select(p => p.ParameterType).Append(m.ReturnType)
                    .SelectMany(Flatten).Any(unions.Contains))
                .Select(m => $"{m.DeclaringType?.FullName}.{m.Name}")
                .Should().BeEmpty();
        }
    }
#endif
}
