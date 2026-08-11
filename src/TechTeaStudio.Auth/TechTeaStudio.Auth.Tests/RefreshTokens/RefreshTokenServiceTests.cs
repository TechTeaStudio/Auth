using System.Security.Claims;
using FluentAssertions;
using Microsoft.Extensions.Options;
using TechTeaStudio.Auth.Abstractions;
using TechTeaStudio.Auth.Jwt;
using TechTeaStudio.Auth.RefreshTokens;
using TechTeaStudio.Auth.Tests.TestHelpers;
using Xunit;

namespace TechTeaStudio.Auth.Tests.RefreshTokens;

public class RefreshTokenServiceTests
{
    private static RefreshTokenService NewService(out InMemoryRefreshTokenStore store, AuthOptions? options = null)
    {
        var concrete = options ?? TestAuthOptions.Create();
        var opts = Options.Create(concrete);
        var provider = new JwtTokenProvider(concrete.ToMonitor());
        store = new InMemoryRefreshTokenStore();
        return new RefreshTokenService(provider, store, opts);
    }

    /// <summary>
    /// Decorates a real <see cref="IRefreshTokenStore"/> and makes <see cref="CreateAsync"/>
    /// always throw, while <see cref="RevokeAsync"/> forwards to the real store — used to
    /// reproduce a downstream failure that lands strictly AFTER a winning revoke-first CAS.
    /// </summary>
    private sealed class CreateAlwaysThrowsStore : IRefreshTokenStore
    {
        private readonly IRefreshTokenStore _inner;
        public CreateAlwaysThrowsStore(IRefreshTokenStore inner) => _inner = inner;

        public Task<RefreshToken?> GetByTokenHashAsync(string tokenHash, CancellationToken cancellationToken = default) =>
            _inner.GetByTokenHashAsync(tokenHash, cancellationToken);
        public Task<IReadOnlyList<RefreshToken>> GetActiveForUserAsync(string userId, CancellationToken cancellationToken = default) =>
            _inner.GetActiveForUserAsync(userId, cancellationToken);
        public Task CreateAsync(RefreshToken token, CancellationToken cancellationToken = default) =>
            throw new InvalidOperationException("simulated downstream failure after the winning revoke");
        public Task<bool> RevokeAsync(Guid id, string? replacedByTokenHash = null, CancellationToken cancellationToken = default) =>
            _inner.RevokeAsync(id, replacedByTokenHash, cancellationToken);
        public Task RevokeAllForUserAsync(string userId, CancellationToken cancellationToken = default) =>
            _inner.RevokeAllForUserAsync(userId, cancellationToken);
        public Task<int> RevokeFamilyAsync(Guid familyId, CancellationToken cancellationToken = default) =>
            _inner.RevokeFamilyAsync(familyId, cancellationToken);
        public Task<int> CleanupExpiredAsync(DateTimeOffset cutoff, CancellationToken cancellationToken = default) =>
            _inner.CleanupExpiredAsync(cutoff, cancellationToken);
        public Task DeleteAllForUserAsync(string userId, CancellationToken cancellationToken = default) =>
            _inner.DeleteAllForUserAsync(userId, cancellationToken);
    }

    /// <summary>
    /// Decorates a real <see cref="IRefreshTokenStore"/> and makes <see cref="RevokeAsync"/>
    /// always return <c>false</c> — deterministically simulates the calling side of a lost
    /// compare-and-swap race against a concurrent rotation of the same token, without needing
    /// real thread interleaving.
    /// </summary>
    private sealed class AlwaysLosesRaceStore : IRefreshTokenStore
    {
        private readonly IRefreshTokenStore _inner;
        public AlwaysLosesRaceStore(IRefreshTokenStore inner) => _inner = inner;

        public Task<RefreshToken?> GetByTokenHashAsync(string tokenHash, CancellationToken cancellationToken = default) =>
            _inner.GetByTokenHashAsync(tokenHash, cancellationToken);
        public Task<IReadOnlyList<RefreshToken>> GetActiveForUserAsync(string userId, CancellationToken cancellationToken = default) =>
            _inner.GetActiveForUserAsync(userId, cancellationToken);
        public Task CreateAsync(RefreshToken token, CancellationToken cancellationToken = default) =>
            _inner.CreateAsync(token, cancellationToken);
        public Task<bool> RevokeAsync(Guid id, string? replacedByTokenHash = null, CancellationToken cancellationToken = default) =>
            Task.FromResult(false);
        public Task RevokeAllForUserAsync(string userId, CancellationToken cancellationToken = default) =>
            _inner.RevokeAllForUserAsync(userId, cancellationToken);
        public Task<int> RevokeFamilyAsync(Guid familyId, CancellationToken cancellationToken = default) =>
            _inner.RevokeFamilyAsync(familyId, cancellationToken);
        public Task<int> CleanupExpiredAsync(DateTimeOffset cutoff, CancellationToken cancellationToken = default) =>
            _inner.CleanupExpiredAsync(cutoff, cancellationToken);
        public Task DeleteAllForUserAsync(string userId, CancellationToken cancellationToken = default) =>
            _inner.DeleteAllForUserAsync(userId, cancellationToken);
    }

    [Fact]
    public async Task IssueAsync_returns_access_and_refresh()
    {
        var service = NewService(out var store);
        var pair = await service.IssueAsync("u-1", new[] { new Claim(AuthClaims.Email, "u@x") });

        pair.AccessToken.Should().NotBeNullOrEmpty();
        pair.RefreshToken.Should().NotBeNullOrEmpty();
        pair.RefreshTokenExpiresAt.Should().BeAfter(DateTimeOffset.UtcNow);

        (await store.GetActiveForUserAsync("u-1")).Should().HaveCount(1);
    }

    [Fact]
    public async Task IssueAsync_with_device_persists_device_attribution()
    {
        var service = NewService(out var store);
        await service.IssueAsync("u-dev", Array.Empty<Claim>(), deviceId: "dev-42", deviceInfo: "Phone");

        var actives = await store.GetActiveForUserAsync("u-dev");
        actives.Should().HaveCount(1);
        actives[0].DeviceId.Should().Be("dev-42");
        actives[0].DeviceInfo.Should().Be("Phone");
    }

    [Fact]
    public async Task IssueAsync_without_device_writes_null_attribution()
    {
        var service = NewService(out var store);
        await service.IssueAsync("u-nodev", Array.Empty<Claim>());

        var actives = await store.GetActiveForUserAsync("u-nodev");
        actives[0].DeviceId.Should().BeNull();
        actives[0].DeviceInfo.Should().BeNull();
    }

    [Fact]
    public async Task RotateAsync_preserves_device_attribution_across_rotation()
    {
        var service = NewService(out var store);
        var first = await service.IssueAsync("u-rot", Array.Empty<Claim>(), deviceId: "rot-device", deviceInfo: "Tablet");
        var second = await service.RotateAsync(first.RefreshToken, Array.Empty<Claim>());

        second.Should().NotBeNull();
        var newHash = TokenHasher.HashRefreshToken(second!.RefreshToken);
        var newRow = await store.GetByTokenHashAsync(newHash);
        newRow!.DeviceId.Should().Be("rot-device");
        newRow.DeviceInfo.Should().Be("Tablet");
    }

    [Fact]
    public async Task RotateAsync_revokes_old_and_issues_new()
    {
        var service = NewService(out var store);
        var first = await service.IssueAsync("u-1", Array.Empty<Claim>());

        var second = await service.RotateAsync(first.RefreshToken, Array.Empty<Claim>());

        second.Should().NotBeNull();
        second!.RefreshToken.Should().NotBe(first.RefreshToken);

        var oldHash = TokenHasher.HashRefreshToken(first.RefreshToken);
        var oldRow = await store.GetByTokenHashAsync(oldHash);
        oldRow!.RevokedAt.Should().NotBeNull();
        oldRow.ReplacedByTokenHash.Should().Be(TokenHasher.HashRefreshToken(second.RefreshToken));
    }

    [Fact]
    public async Task RotateAsync_returns_null_for_unknown_token()
    {
        var service = NewService(out _);
        (await service.RotateAsync("never-issued", Array.Empty<Claim>())).Should().BeNull();
    }

    [Fact]
    public async Task RotateAsync_returns_null_for_already_revoked()
    {
        var service = NewService(out _);
        var first = await service.IssueAsync("u", Array.Empty<Claim>());
        await service.RotateAsync(first.RefreshToken, Array.Empty<Claim>()); // first rotation OK
        var replay = await service.RotateAsync(first.RefreshToken, Array.Empty<Claim>()); // replay
        replay.Should().BeNull();
    }

    [Fact]
    public async Task RotateAsync_replay_revokes_whole_chain_when_enabled()
    {
        var opts = TestAuthOptions.Create();
        opts.RefreshTokens.RevokeChainOnReuse = true;

        var service = NewService(out var store, opts);
        var t1 = await service.IssueAsync("u", Array.Empty<Claim>());
        var t2 = await service.RotateAsync(t1.RefreshToken, Array.Empty<Claim>());
        var t3 = await service.RotateAsync(t2!.RefreshToken, Array.Empty<Claim>());

        // Replay t1 — chain t1 -> t2 -> t3 should be revoked.
        await service.RotateAsync(t1.RefreshToken, Array.Empty<Claim>());

        var t3Row = await store.GetByTokenHashAsync(TokenHasher.HashRefreshToken(t3!.RefreshToken));
        t3Row!.RevokedAt.Should().NotBeNull();
    }

    [Fact]
    public async Task RevokeAsync_marks_token_revoked()
    {
        var service = NewService(out var store);
        var pair = await service.IssueAsync("u", Array.Empty<Claim>());
        await service.RevokeAsync(pair.RefreshToken);

        var row = await store.GetByTokenHashAsync(TokenHasher.HashRefreshToken(pair.RefreshToken));
        row!.RevokedAt.Should().NotBeNull();
    }

    [Fact]
    public async Task RotateAsync_leaves_presented_token_revoked_when_CreateAsync_fails_after_the_winning_revoke()
    {
        var backingStore = new InMemoryRefreshTokenStore();
        var concrete = TestAuthOptions.Create();
        var provider = new JwtTokenProvider(concrete.ToMonitor());

        var issuingService = new RefreshTokenService(provider, backingStore, Options.Create(concrete));
        var pair = await issuingService.IssueAsync("u-fail-closed", Array.Empty<Claim>());

        var failingStore = new CreateAlwaysThrowsStore(backingStore);
        var rotatingService = new RefreshTokenService(provider, failingStore, Options.Create(concrete));

        var act = () => rotatingService.RotateAsync(pair.RefreshToken, Array.Empty<Claim>());
        await act.Should().ThrowAsync<InvalidOperationException>();

        // Fail-closed: the CAS already won and revoked the presented token before
        // CreateAsync blew up, so there is no live token left for this user at all —
        // strictly better than the old create-then-revoke order, which could have
        // left the pre-rotation token live (or, on a different failure point, forked).
        var row = await backingStore.GetByTokenHashAsync(TokenHasher.HashRefreshToken(pair.RefreshToken));
        row!.RevokedAt.Should().NotBeNull();
        row.IsActive.Should().BeFalse();
        (await backingStore.GetActiveForUserAsync("u-fail-closed")).Should().BeEmpty();
    }

    [Fact]
    public async Task IssueAsync_mints_a_fresh_family_id_each_call()
    {
        var service = NewService(out var store);
        var a = await service.IssueAsync("u-1", Array.Empty<Claim>());
        var b = await service.IssueAsync("u-1", Array.Empty<Claim>());

        var rowA = await store.GetByTokenHashAsync(TokenHasher.HashRefreshToken(a.RefreshToken));
        var rowB = await store.GetByTokenHashAsync(TokenHasher.HashRefreshToken(b.RefreshToken));
        rowA!.FamilyId.Should().NotBe(rowB!.FamilyId);
    }

    [Fact]
    public async Task RotateAsync_preserves_family_id_across_rotation()
    {
        var service = NewService(out var store);
        var first = await service.IssueAsync("u-fam", Array.Empty<Claim>());
        var firstRow = await store.GetByTokenHashAsync(TokenHasher.HashRefreshToken(first.RefreshToken));

        var second = await service.RotateAsync(first.RefreshToken, Array.Empty<Claim>());
        var secondRow = await store.GetByTokenHashAsync(TokenHasher.HashRefreshToken(second!.RefreshToken));

        secondRow!.FamilyId.Should().Be(firstRow!.FamilyId);
    }

    [Fact]
    public async Task RotateWithOutcomeAsync_returns_Invalid_for_unknown_token()
    {
        var service = NewService(out _);
        var result = await service.RotateWithOutcomeAsync("never-issued", Array.Empty<Claim>());
        result.Outcome.Should().Be(RefreshOutcome.Invalid);
        result.Tokens.Should().BeNull();
    }

    [Fact]
    public async Task RotateWithOutcomeAsync_returns_Expired_for_a_naturally_expired_token_and_does_not_revoke_it()
    {
        var opts = TestAuthOptions.Create();
        opts.RefreshTokens.Lifetime = TimeSpan.FromMilliseconds(1);
        var service = NewService(out var store, opts);

        var pair = await service.IssueAsync("u-exp", Array.Empty<Claim>());
        await Task.Delay(30);

        var result = await service.RotateWithOutcomeAsync(pair.RefreshToken, Array.Empty<Claim>());

        result.Outcome.Should().Be(RefreshOutcome.Expired);
        result.Tokens.Should().BeNull();

        var row = await store.GetByTokenHashAsync(TokenHasher.HashRefreshToken(pair.RefreshToken));
        row!.RevokedAt.Should().BeNull();
    }

    [Fact]
    public async Task RotateWithOutcomeAsync_reuse_of_a_rotated_token_revokes_the_entire_family_including_the_newest_token()
    {
        var service = NewService(out var store);
        var t1 = await service.IssueAsync("u", Array.Empty<Claim>());
        var t2 = await service.RotateAsync(t1.RefreshToken, Array.Empty<Claim>());
        var t3 = await service.RotateAsync(t2!.RefreshToken, Array.Empty<Claim>());

        var replay = await service.RotateWithOutcomeAsync(t1.RefreshToken, Array.Empty<Claim>());

        replay.Outcome.Should().Be(RefreshOutcome.ReusedFamilyRevoked);
        replay.Tokens.Should().BeNull();

        var t3Row = await store.GetByTokenHashAsync(TokenHasher.HashRefreshToken(t3!.RefreshToken));
        t3Row!.RevokedAt.Should().NotBeNull();
    }

    [Fact]
    public async Task RotateWithOutcomeAsync_does_not_burn_the_family_when_RevokeChainOnReuse_is_disabled()
    {
        var opts = TestAuthOptions.Create();
        opts.RefreshTokens.RevokeChainOnReuse = false;
        var service = NewService(out var store, opts);

        var t1 = await service.IssueAsync("u", Array.Empty<Claim>());
        var t2 = await service.RotateAsync(t1.RefreshToken, Array.Empty<Claim>());

        var replay = await service.RotateWithOutcomeAsync(t1.RefreshToken, Array.Empty<Claim>());

        replay.Outcome.Should().Be(RefreshOutcome.ReusedFamilyRevoked);
        var t2Row = await store.GetByTokenHashAsync(TokenHasher.HashRefreshToken(t2!.RefreshToken));
        t2Row!.RevokedAt.Should().BeNull();
    }

    [Fact]
    public async Task RotateWithOutcomeAsync_treats_a_lost_CAS_race_as_a_safe_reject_not_a_family_burn()
    {
        // Divergence from a stricter "any lost race is reuse" policy, documented on
        // RefreshTokenService.RotateWithOutcomeAsync: a same-instant lost race (RevokeAsync
        // returns false) is reported as Invalid and does NOT burn the family, so a concurrent
        // winner's brand-new session survives. Only a token whose RevokedAt was ALREADY set by
        // a distinct, completed prior rotation is treated as a genuine replay.
        var backingStore = new InMemoryRefreshTokenStore();
        var concrete = TestAuthOptions.Create();
        var provider = new JwtTokenProvider(concrete.ToMonitor());
        var issuingService = new RefreshTokenService(provider, backingStore, Options.Create(concrete));
        var pair = await issuingService.IssueAsync("u-race", Array.Empty<Claim>());

        var racingStore = new AlwaysLosesRaceStore(backingStore);
        var racingService = new RefreshTokenService(provider, racingStore, Options.Create(concrete));

        var result = await racingService.RotateWithOutcomeAsync(pair.RefreshToken, Array.Empty<Claim>());

        result.Outcome.Should().Be(RefreshOutcome.Invalid);
        result.Tokens.Should().BeNull();

        var row = await backingStore.GetByTokenHashAsync(TokenHasher.HashRefreshToken(pair.RefreshToken));
        row!.RevokedAt.Should().BeNull();
    }

    [Fact]
    public async Task RevokeAllForUserAsync_revokes_every_active_token_for_that_user()
    {
        var service = NewService(out var store);
        await service.IssueAsync("u-logout", Array.Empty<Claim>());
        await service.IssueAsync("u-logout", Array.Empty<Claim>());
        await service.IssueAsync("someone-else", Array.Empty<Claim>());

        await service.RevokeAllForUserAsync("u-logout");

        (await store.GetActiveForUserAsync("u-logout")).Should().BeEmpty();
        (await store.GetActiveForUserAsync("someone-else")).Should().HaveCount(1);
    }
}
