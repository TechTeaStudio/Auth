using System.Reflection;
using System.Text.Json;
using FluentAssertions;
using TechTeaStudio.Auth.OAuth;
using TechTeaStudio.Auth.RefreshTokens;
using Xunit;

namespace TechTeaStudio.Auth.Tests.OAuth;

/// <summary>
/// Pins what a consumer can observe of <see cref="ExternalSignInOutcome"/>: its public
/// properties, its printed form, its JSON and its equality. The record also carries internal
/// plumbing for the net11.0 union methods, and none of that may leak into any of the four.
/// </summary>
public class ExternalSignInOutcomeShapeTests
{
    private static readonly TokenPair Pair = new("access", "refresh", new DateTimeOffset(2030, 1, 2, 3, 4, 5, TimeSpan.Zero));

    private static async Task<ExternalSignInOutcome> AuthenticatedFromServiceAsync()
    {
        var (svc, stub, users, store, _, _) = ExternalLoginServiceTests.NewService();
        var seeded = users.SeedPasswordUser("u@x", "irrelevant");
        await store.CreateAsync(new ExternalLogin { UserId = seeded.UserId, Provider = "Google", ProviderUserId = "g-1", Email = "u@x" });
        stub.Responses["good-token"] = ExternalLoginServiceTests.GoogleInfo();

        var outcome = await svc.SignInAsync("Google", "good-token");
        outcome.Status.Should().Be(ExternalSignInStatus.Authenticated);
        return outcome;
    }

    [Fact]
    public void Public_properties_are_exactly_the_six_documented_ones()
    {
        typeof(ExternalSignInOutcome)
            .GetProperties(BindingFlags.Public | BindingFlags.Instance)
            .Select(p => $"{p.PropertyType.Name} {p.Name}")
            .Should().BeEquivalentTo(
                "ExternalSignInStatus Status",
                "TokenPair Tokens",
                "String ContinuationToken",
                "String Email",
                "ExternalLoginInfo Profile",
                "String Error");
    }

    [Fact]
    public void ToString_prints_the_six_public_members_and_nothing_else()
    {
        new ExternalSignInOutcome { Status = ExternalSignInStatus.Failed, Error = "invalid_credential" }.ToString()
            .Should().Be("ExternalSignInOutcome { Status = Failed, Tokens = , ContinuationToken = , Email = , Profile = , Error = invalid_credential }");

        new ExternalSignInOutcome { Status = ExternalSignInStatus.Authenticated, Tokens = Pair }.ToString()
            .Should().Be($"ExternalSignInOutcome {{ Status = Authenticated, Tokens = {Pair}, ContinuationToken = , Email = , Profile = , Error =  }}");
    }

    [Fact]
    public async Task ToString_of_a_service_issued_outcome_matches_a_hand_built_one()
    {
        var outcome = await AuthenticatedFromServiceAsync();

        outcome.ToString().Should().Be(
            new ExternalSignInOutcome { Status = ExternalSignInStatus.Authenticated, Tokens = outcome.Tokens }.ToString());
    }

    [Fact]
    public async Task Json_has_exactly_the_six_public_properties()
    {
        var outcome = await AuthenticatedFromServiceAsync();

        using var doc = JsonDocument.Parse(JsonSerializer.Serialize(outcome));

        doc.RootElement.EnumerateObject().Select(p => p.Name)
            .Should().Equal("Status", "Tokens", "ContinuationToken", "Email", "Profile", "Error");
    }

    [Fact]
    public async Task Equality_looks_only_at_the_public_properties()
    {
        // A consumer can build an outcome from the public init properties (a test double, a cache
        // round trip). It has always compared equal to the service's own outcome with the same
        // public values, and it still does.
        var outcome = await AuthenticatedFromServiceAsync();
        var rebuilt = new ExternalSignInOutcome { Status = ExternalSignInStatus.Authenticated, Tokens = outcome.Tokens };

        rebuilt.Should().Be(outcome);
        rebuilt.GetHashCode().Should().Be(outcome.GetHashCode());
        (rebuilt == outcome).Should().BeTrue();

        rebuilt.Should().NotBe(rebuilt with { Error = "x" });
        rebuilt.Should().NotBe(rebuilt with { Email = "x" });
        rebuilt.Should().NotBe(rebuilt with { ContinuationToken = "x" });
        rebuilt.Should().NotBe(rebuilt with { Status = ExternalSignInStatus.Failed });
        rebuilt.Should().NotBe(rebuilt with { Tokens = Pair });
        rebuilt.Should().NotBe(rebuilt with { Profile = ExternalLoginServiceTests.GoogleInfo() });
    }
}
