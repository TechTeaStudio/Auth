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
}
