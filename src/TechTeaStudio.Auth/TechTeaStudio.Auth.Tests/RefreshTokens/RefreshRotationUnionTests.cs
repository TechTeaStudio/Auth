#if NET11_0_OR_GREATER
// A switch over a union that misses a case must not compile here: that is the whole point of
// the union form. The test project turns CS8509 and CS8655 into errors (see the .csproj).

using System.Diagnostics;
using System.Security.Claims;
using FluentAssertions;
using Microsoft.Extensions.Options;
using TechTeaStudio.Auth.Jwt;
using TechTeaStudio.Auth.RefreshTokens;
using TechTeaStudio.Auth.Tests.TestHelpers;
using Xunit;

namespace TechTeaStudio.Auth.Tests.RefreshTokens;

public class RefreshRotationUnionTests
{
    private static RefreshTokenService NewService(out InMemoryRefreshTokenStore store, AuthOptions? options = null) =>
        RefreshTokenServiceTests.NewService(out store, options);

    /// <summary>
    /// Exhaustive over the four cases with no discard arm and no <c>null</c> arm. If a case is
    /// ever added to the union this stops compiling (CS8509 is an error in this file).
    /// </summary>
    private static RefreshOutcome Describe(RefreshRotation rotation) => rotation switch
    {
        RefreshRotated => RefreshOutcome.Success,
        RefreshTokenInvalid => RefreshOutcome.Invalid,
        RefreshTokenExpired => RefreshOutcome.Expired,
        RefreshTokenReused => RefreshOutcome.ReusedFamilyRevoked,
    };

    [Fact]
    public async Task Success_is_RefreshRotated_with_a_working_pair()
    {
        var service = NewService(out var store);
        var first = await service.IssueAsync("u-1", Array.Empty<Claim>());

        var rotation = await service.RotateAsUnionAsync(first.RefreshToken, Array.Empty<Claim>());

        var rotated = rotation.Value.Should().BeOfType<RefreshRotated>().Subject;
        rotated.Tokens.AccessToken.Should().NotBeNullOrEmpty();
        rotated.Tokens.RefreshToken.Should().NotBe(first.RefreshToken);

        // The presented token is spent...
        var oldRow = await store.GetByTokenHashAsync(TokenHasher.HashRefreshToken(first.RefreshToken));
        oldRow!.RevokedAt.Should().NotBeNull();
        oldRow.ReplacedByTokenHash.Should().Be(TokenHasher.HashRefreshToken(rotated.Tokens.RefreshToken));

        // ...and the new one is a real, live refresh token: it rotates again.
        var again = await service.RotateAsUnionAsync(rotated.Tokens.RefreshToken, Array.Empty<Claim>());
        again.Value.Should().BeOfType<RefreshRotated>();
    }

    [Theory]
    [InlineData("never-issued")]
    [InlineData("")]
    public async Task Unknown_or_empty_token_is_RefreshTokenInvalid(string presented)
    {
        var service = NewService(out _);

        (await service.RotateAsUnionAsync(presented, Array.Empty<Claim>())).Value.Should().BeOfType<RefreshTokenInvalid>();
        (await service.RotateAsUnionAsync(presented)).Value.Should().BeOfType<RefreshTokenInvalid>();
    }

    [Fact]
    public async Task Naturally_expired_token_is_RefreshTokenExpired_and_is_not_revoked()
    {
        var opts = TestAuthOptions.Create();
        opts.RefreshTokens.Lifetime = TimeSpan.FromMilliseconds(1);
        var service = NewService(out var store, opts);

        var pair = await service.IssueAsync("u-exp", Array.Empty<Claim>());
        await Task.Delay(30);

        var rotation = await service.RotateAsUnionAsync(pair.RefreshToken, Array.Empty<Claim>());

        rotation.Value.Should().BeOfType<RefreshTokenExpired>();
        var row = await store.GetByTokenHashAsync(TokenHasher.HashRefreshToken(pair.RefreshToken));
        row!.RevokedAt.Should().BeNull();
    }

    [Fact]
    public async Task Replayed_token_is_RefreshTokenReused_and_the_family_is_revoked()
    {
        var service = NewService(out var store);
        var t1 = await service.IssueAsync("u", Array.Empty<Claim>());
        var t2 = await service.RotateAsync(t1.RefreshToken, Array.Empty<Claim>());
        var t3 = await service.RotateAsync(t2!.RefreshToken, Array.Empty<Claim>());

        var replay = await service.RotateAsUnionAsync(t1.RefreshToken, Array.Empty<Claim>());

        replay.Value.Should().BeOfType<RefreshTokenReused>();
        var t3Row = await store.GetByTokenHashAsync(TokenHasher.HashRefreshToken(t3!.RefreshToken));
        t3Row!.RevokedAt.Should().NotBeNull();
    }

    [Fact]
    public async Task Lost_compare_and_swap_race_is_RefreshTokenInvalid_and_the_family_survives()
    {
        var backingStore = new InMemoryRefreshTokenStore();
        var concrete = TestAuthOptions.Create();
        var provider = new JwtTokenProvider(concrete.ToMonitor());
        var issuingService = new RefreshTokenService(provider, backingStore, Options.Create(concrete));
        var pair = await issuingService.IssueAsync("u-race", Array.Empty<Claim>());

        var racingStore = new RefreshTokenServiceTests.AlwaysLosesRaceStore(backingStore);
        var racingService = new RefreshTokenService(provider, racingStore, Options.Create(concrete));

        var rotation = await racingService.RotateAsUnionAsync(pair.RefreshToken, Array.Empty<Claim>());

        rotation.Value.Should().BeOfType<RefreshTokenInvalid>();
        var row = await backingStore.GetByTokenHashAsync(TokenHasher.HashRefreshToken(pair.RefreshToken));
        row!.RevokedAt.Should().BeNull();
    }

    [Fact]
    public async Task Null_claims_throws_ArgumentNullException_like_RotateWithOutcomeAsync()
    {
        var service = NewService(out _);
        var pair = await service.IssueAsync("u", Array.Empty<Claim>());

        var union = () => service.RotateAsUnionAsync(pair.RefreshToken, null!);
        var classic = () => service.RotateWithOutcomeAsync(pair.RefreshToken, null!);

        (await union.Should().ThrowAsync<ArgumentNullException>()).Which.ParamName
            .Should().Be((await classic.Should().ThrowAsync<ArgumentNullException>()).Which.ParamName);
    }

    public static IEnumerable<object[]> EveryOutcome() =>
        Enum.GetValues<RefreshOutcome>().Select(o => new object[] { o });

    [Theory]
    [MemberData(nameof(EveryOutcome))]
    public void Mapper_maps_every_RefreshOutcome_value(RefreshOutcome outcome)
    {
        var tokens = new TokenPair("access", "refresh", DateTimeOffset.UtcNow.AddDays(1));
        var result = new RefreshRotationResult(outcome, outcome == RefreshOutcome.Success ? tokens : null);

        var rotation = RefreshRotationMapper.ToUnion(result);

        rotation.Value.Should().NotBeNull();
        // Round trip: the union case names the same outcome the result carried.
        Describe(rotation).Should().Be(outcome);
        if (rotation.Value is RefreshRotated rotated) rotated.Tokens.Should().BeSameAs(tokens);
    }

    [Fact]
    public void Mapper_throws_UnreachableException_for_an_unmapped_outcome()
    {
        var act = () => RefreshRotationMapper.ToUnion(new RefreshRotationResult((RefreshOutcome)999, null));
        act.Should().Throw<UnreachableException>().WithMessage("*999*");
    }

    [Fact]
    public void Mapper_refuses_a_success_result_without_tokens()
    {
        // RefreshRotationResult has a public constructor, so the "Tokens is non-null iff Success"
        // rule is a convention there. RefreshRotated makes it a guarantee.
        var act = () => RefreshRotationMapper.ToUnion(new RefreshRotationResult(RefreshOutcome.Success, null));
        act.Should().Throw<InvalidOperationException>();
    }

    [Fact]
    public async Task Value_is_never_null_on_any_path()
    {
        var opts = TestAuthOptions.Create();
        var service = NewService(out _, opts);
        var t1 = await service.IssueAsync("u", Array.Empty<Claim>());

        var rotated = await service.RotateAsUnionAsync(t1.RefreshToken, Array.Empty<Claim>());
        var reused = await service.RotateAsUnionAsync(t1.RefreshToken, Array.Empty<Claim>());
        var invalid = await service.RotateAsUnionAsync("never-issued", Array.Empty<Claim>());
        var empty = await service.RotateAsUnionAsync(string.Empty);

        var expiring = TestAuthOptions.Create();
        expiring.RefreshTokens.Lifetime = TimeSpan.FromMilliseconds(1);
        var shortLived = NewService(out _, expiring);
        var stale = await shortLived.IssueAsync("u", Array.Empty<Claim>());
        await Task.Delay(30);
        var expired = await shortLived.RotateAsUnionAsync(stale.RefreshToken, Array.Empty<Claim>());

        foreach (var rotation in new[] { rotated, reused, invalid, empty, expired })
            rotation.Value.Should().NotBeNull();

        new[] { rotated, reused, invalid, empty, expired }.Select(Describe).Should().Equal(
            RefreshOutcome.Success,
            RefreshOutcome.ReusedFamilyRevoked,
            RefreshOutcome.Invalid,
            RefreshOutcome.Invalid,
            RefreshOutcome.Expired);
    }

    [Fact]
    public async Task Exhaustive_switch_without_a_discard_arm_compiles_and_picks_the_case()
    {
        var service = NewService(out _);
        var pair = await service.IssueAsync("u", Array.Empty<Claim>());

        // The shape a refresh endpoint would have. No `_ =>` arm, no `null =>` arm.
        var status = await service.RotateAsUnionAsync(pair.RefreshToken, Array.Empty<Claim>()) switch
        {
            RefreshRotated ok => $"200 {ok.Tokens.RefreshToken.Length > 0}",
            RefreshTokenInvalid => "401 invalid",
            RefreshTokenExpired => "401 expired",
            RefreshTokenReused => "401 reused",
        };

        status.Should().Be("200 True");
    }

    [Fact]
    public async Task Resolver_overload_agrees_with_RotateWithOutcomeAsync_for_the_same_state()
    {
        // Two services walked through the same history; one is asked the classic way, the other
        // through the union. Every state must name the same outcome.
        async Task<(RefreshTokenService svc, string live, string spent, string unknown)> Prepare()
        {
            var svc = NewService(out _);
            var t1 = await svc.IssueAsync("u", Array.Empty<Claim>());
            var t2 = await svc.RotateAsync(t1.RefreshToken);
            return (svc, t2!.RefreshToken, t1.RefreshToken, "never-issued");
        }

        var classic = await Prepare();
        var union = await Prepare();

        Describe(await union.svc.RotateAsUnionAsync(union.unknown))
            .Should().Be((await classic.svc.RotateWithOutcomeAsync(classic.unknown)).Outcome)
            .And.Be(RefreshOutcome.Invalid);

        var rotated = await union.svc.RotateAsUnionAsync(union.live);
        var classicRotated = await classic.svc.RotateWithOutcomeAsync(classic.live);
        Describe(rotated).Should().Be(classicRotated.Outcome).And.Be(RefreshOutcome.Success);
        ((RefreshRotated)rotated.Value!).Tokens.RefreshToken.Should().NotBeNullOrEmpty();

        Describe(await union.svc.RotateAsUnionAsync(union.spent))
            .Should().Be((await classic.svc.RotateWithOutcomeAsync(classic.spent)).Outcome)
            .And.Be(RefreshOutcome.ReusedFamilyRevoked);

        var expiring = TestAuthOptions.Create();
        expiring.RefreshTokens.Lifetime = TimeSpan.FromMilliseconds(1);
        var classicShort = NewService(out _, expiring);
        var unionShort = NewService(out _, expiring);
        var classicStale = await classicShort.IssueAsync("u", Array.Empty<Claim>());
        var unionStale = await unionShort.IssueAsync("u", Array.Empty<Claim>());
        await Task.Delay(30);

        Describe(await unionShort.RotateAsUnionAsync(unionStale.RefreshToken))
            .Should().Be((await classicShort.RotateWithOutcomeAsync(classicStale.RefreshToken)).Outcome)
            .And.Be(RefreshOutcome.Expired);
    }
}
#endif
