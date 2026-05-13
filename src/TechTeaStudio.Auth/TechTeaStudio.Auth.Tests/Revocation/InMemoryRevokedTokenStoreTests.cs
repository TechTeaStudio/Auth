using FluentAssertions;
using TechTeaStudio.Auth.Revocation;
using Xunit;

namespace TechTeaStudio.Auth.Tests.Revocation;

public class InMemoryRevokedTokenStoreTests
{
    [Fact]
    public async Task Unknown_jti_is_not_revoked()
    {
        var store = new InMemoryRevokedTokenStore();
        (await store.IsRevokedAsync("missing")).Should().BeFalse();
    }

    [Fact]
    public async Task Revoke_then_check_returns_true()
    {
        var store = new InMemoryRevokedTokenStore();
        await store.RevokeAsync("jti-1", DateTimeOffset.UtcNow.AddMinutes(5));
        (await store.IsRevokedAsync("jti-1")).Should().BeTrue();
    }

    [Fact]
    public async Task Expired_revocation_is_dropped_on_read()
    {
        var store = new InMemoryRevokedTokenStore();
        await store.RevokeAsync("jti-1", DateTimeOffset.UtcNow.AddMilliseconds(-10));
        (await store.IsRevokedAsync("jti-1")).Should().BeFalse();
    }

    [Fact]
    public async Task Cleanup_removes_expired_entries()
    {
        var store = new InMemoryRevokedTokenStore();
        await store.RevokeAsync("a", DateTimeOffset.UtcNow.AddMilliseconds(-1));
        await store.RevokeAsync("b", DateTimeOffset.UtcNow.AddMinutes(5));
        var removed = await store.CleanupAsync(DateTimeOffset.UtcNow);
        removed.Should().Be(1);
        (await store.IsRevokedAsync("b")).Should().BeTrue();
    }

    [Fact]
    public async Task Null_store_is_always_negative()
    {
        var store = NullRevokedTokenStore.Instance;
        await store.RevokeAsync("x", DateTimeOffset.UtcNow.AddMinutes(5));
        (await store.IsRevokedAsync("x")).Should().BeFalse();
    }
}
