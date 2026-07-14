using FluentAssertions;
using TechTeaStudio.Auth.Abstractions;
using TechTeaStudio.Auth.RefreshTokens;
using Xunit;

namespace TechTeaStudio.Auth.Tests.RefreshTokens;

/// <summary>
/// Conformance test fixture for any <see cref="IRefreshTokenStore"/> implementation.
/// Implementors derive a concrete xUnit class, override <see cref="CreateStore"/>,
/// and inherit every assertion below — guaranteeing wire-level compatibility with
/// the in-memory store, the EF Core store, and any future backend.
/// </summary>
public abstract class RefreshTokenStoreContractTests
{
    protected abstract IRefreshTokenStore CreateStore();

    private static RefreshToken NewToken(string userId = "u-1", TimeSpan? lifetime = null, string? hashOverride = null) => new()
    {
        UserId = userId,
        TokenHash = hashOverride ?? TokenHasher.HashRefreshToken(TokenHasher.NewRawToken()),
        CreatedAt = DateTimeOffset.UtcNow,
        ExpiresAt = DateTimeOffset.UtcNow.Add(lifetime ?? TimeSpan.FromMinutes(5)),
    };

    [Fact]
    public async Task GetByTokenHashAsync_returns_null_for_unknown_hash()
    {
        var store = CreateStore();
        (await store.GetByTokenHashAsync("unknown")).Should().BeNull();
    }

    [Fact]
    public async Task CreateAsync_persists_token_retrievable_by_hash()
    {
        var store = CreateStore();
        var token = NewToken();
        await store.CreateAsync(token);
        var fetched = await store.GetByTokenHashAsync(token.TokenHash);
        fetched.Should().NotBeNull();
        fetched!.Id.Should().Be(token.Id);
        fetched.UserId.Should().Be(token.UserId);
    }

    [Fact]
    public async Task CreateAsync_roundtrips_device_id_and_info()
    {
        var store = CreateStore();
        var token = NewToken() with { DeviceId = "device-uuid-42", DeviceInfo = "Phone" };
        await store.CreateAsync(token);

        var fetched = await store.GetByTokenHashAsync(token.TokenHash);
        fetched!.DeviceId.Should().Be("device-uuid-42");
        fetched.DeviceInfo.Should().Be("Phone");
    }

    [Fact]
    public async Task CreateAsync_allows_null_device_fields_for_backward_compat()
    {
        var store = CreateStore();
        var token = NewToken();
        await store.CreateAsync(token);

        var fetched = await store.GetByTokenHashAsync(token.TokenHash);
        fetched!.DeviceId.Should().BeNull();
        fetched.DeviceInfo.Should().BeNull();
    }

    [Fact]
    public async Task GetActiveForUserAsync_preserves_device_fields()
    {
        var store = CreateStore();
        var token = NewToken("alice") with { DeviceId = "alice-phone", DeviceInfo = "Phone" };
        await store.CreateAsync(token);

        var actives = await store.GetActiveForUserAsync("alice");
        var fetched = actives.Single(t => t.Id == token.Id);
        fetched.DeviceId.Should().Be("alice-phone");
        fetched.DeviceInfo.Should().Be("Phone");
    }

    [Fact]
    public async Task CreateAsync_throws_on_duplicate_hash()
    {
        var store = CreateStore();
        var token = NewToken();
        await store.CreateAsync(token);
        var act = () => store.CreateAsync(token);
        await act.Should().ThrowAsync<InvalidOperationException>();
    }

    [Fact]
    public async Task RevokeAsync_marks_token_inactive()
    {
        var store = CreateStore();
        var token = NewToken();
        await store.CreateAsync(token);

        await store.RevokeAsync(token.Id);
        var fetched = await store.GetByTokenHashAsync(token.TokenHash);
        fetched!.RevokedAt.Should().NotBeNull();
        fetched.IsActive.Should().BeFalse();
    }

    [Fact]
    public async Task RevokeAsync_records_successor_hash_when_supplied()
    {
        var store = CreateStore();
        var token = NewToken();
        await store.CreateAsync(token);

        await store.RevokeAsync(token.Id, "successor-hash");
        var fetched = await store.GetByTokenHashAsync(token.TokenHash);
        fetched!.ReplacedByTokenHash.Should().Be("successor-hash");
    }

    [Fact]
    public async Task RevokeAsync_unknown_id_is_noop()
    {
        var store = CreateStore();
        var act = () => store.RevokeAsync(Guid.NewGuid());
        await act.Should().NotThrowAsync();
    }

    [Fact]
    public async Task RevokeAsync_on_an_already_revoked_token_is_idempotent()
    {
        var store = CreateStore();
        var token = NewToken();
        await store.CreateAsync(token);
        await store.RevokeAsync(token.Id);

        var act = () => store.RevokeAsync(token.Id);
        await act.Should().NotThrowAsync();

        var fetched = await store.GetByTokenHashAsync(token.TokenHash);
        fetched!.RevokedAt.Should().NotBeNull();
    }

    [Fact]
    public async Task RevokeAsync_on_an_already_revoked_token_still_records_a_new_successor_hash()
    {
        var store = CreateStore();
        var token = NewToken();
        await store.CreateAsync(token);
        await store.RevokeAsync(token.Id);

        await store.RevokeAsync(token.Id, "chain-successor-hash");

        var fetched = await store.GetByTokenHashAsync(token.TokenHash);
        fetched!.ReplacedByTokenHash.Should().Be("chain-successor-hash");
    }

    [Fact]
    public async Task RevokeAsync_returns_true_when_it_flips_an_active_token()
    {
        var store = CreateStore();
        var token = NewToken();
        await store.CreateAsync(token);

        (await store.RevokeAsync(token.Id)).Should().BeTrue();
    }

    [Fact]
    public async Task RevokeAsync_returns_false_when_already_revoked()
    {
        var store = CreateStore();
        var token = NewToken();
        await store.CreateAsync(token);
        await store.RevokeAsync(token.Id);

        (await store.RevokeAsync(token.Id)).Should().BeFalse();
    }

    [Fact]
    public async Task RevokeAsync_returns_false_for_unknown_id()
    {
        var store = CreateStore();
        (await store.RevokeAsync(Guid.NewGuid())).Should().BeFalse();
    }

    [Fact]
    public async Task RevokeAsync_does_not_overwrite_an_existing_successor_hash()
    {
        // Guards the RotateAsync-race clobber: the CAS winner records its real
        // successor; a losing racer that reaches the already-revoked backfill with
        // its own phantom hash must NOT overwrite it, or RevokeChainOnReuse breaks.
        var store = CreateStore();
        var token = NewToken();
        await store.CreateAsync(token);

        (await store.RevokeAsync(token.Id, "winner-successor-hash")).Should().BeTrue();
        (await store.RevokeAsync(token.Id, "loser-phantom-hash")).Should().BeFalse();

        var fetched = await store.GetByTokenHashAsync(token.TokenHash);
        fetched!.ReplacedByTokenHash.Should().Be("winner-successor-hash");
    }

    [Fact]
    public async Task GetActiveForUserAsync_returns_only_active_for_that_user()
    {
        var store = CreateStore();
        var active = NewToken("alice");
        var revoked = NewToken("alice");
        var other = NewToken("bob");
        var expired = NewToken("alice", lifetime: TimeSpan.FromMilliseconds(1));

        await store.CreateAsync(active);
        await store.CreateAsync(revoked);
        await store.CreateAsync(other);
        await store.CreateAsync(expired);
        await store.RevokeAsync(revoked.Id);
        await Task.Delay(20);

        var actives = await store.GetActiveForUserAsync("alice");
        actives.Select(t => t.Id).Should().Contain(active.Id);
        actives.Select(t => t.Id).Should().NotContain(revoked.Id);
        actives.Select(t => t.Id).Should().NotContain(expired.Id);
        actives.Select(t => t.UserId).Should().AllBe("alice");
    }

    [Fact]
    public async Task RevokeAllForUserAsync_only_affects_that_user()
    {
        var store = CreateStore();
        var alice1 = NewToken("alice");
        var alice2 = NewToken("alice");
        var bob = NewToken("bob");

        await store.CreateAsync(alice1);
        await store.CreateAsync(alice2);
        await store.CreateAsync(bob);

        await store.RevokeAllForUserAsync("alice");

        (await store.GetActiveForUserAsync("alice")).Should().BeEmpty();
        (await store.GetActiveForUserAsync("bob")).Should().HaveCount(1);
    }

    [Fact]
    public async Task CleanupExpiredAsync_removes_only_expired_rows()
    {
        var store = CreateStore();
        var future = NewToken("alice", lifetime: TimeSpan.FromMinutes(5));
        var pastA = NewToken("alice", lifetime: TimeSpan.FromMilliseconds(1));
        var pastB = NewToken("bob", lifetime: TimeSpan.FromMilliseconds(1));

        await store.CreateAsync(future);
        await store.CreateAsync(pastA);
        await store.CreateAsync(pastB);
        await Task.Delay(30);

        var removed = await store.CleanupExpiredAsync(DateTimeOffset.UtcNow);
        removed.Should().BeGreaterThanOrEqualTo(2);
        (await store.GetByTokenHashAsync(future.TokenHash)).Should().NotBeNull();
        (await store.GetByTokenHashAsync(pastA.TokenHash)).Should().BeNull();
        (await store.GetByTokenHashAsync(pastB.TokenHash)).Should().BeNull();
    }

    [Fact]
    public async Task DeleteAllForUserAsync_hard_deletes_user_rows()
    {
        var store = CreateStore();
        var alice = NewToken("alice");
        var bob = NewToken("bob");
        await store.CreateAsync(alice);
        await store.CreateAsync(bob);

        await store.DeleteAllForUserAsync("alice");

        (await store.GetByTokenHashAsync(alice.TokenHash)).Should().BeNull();
        (await store.GetByTokenHashAsync(bob.TokenHash)).Should().NotBeNull();
    }
}
