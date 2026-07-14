using FluentAssertions;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using TechTeaStudio.Auth.EFCore;
using Xunit;

namespace TechTeaStudio.Auth.Tests.EfCore;

/// <summary>
/// Reproduces the captive-DbContext / load-then-save race that used to make
/// <see cref="EfCoreRefreshTokenStore{TContext}"/> throw <see cref="DbUpdateConcurrencyException"/>
/// whenever a row's <c>ConcurrencyStamp</c> changed between two independent
/// <see cref="DbContext"/> instances pointed at the same row. Uses the shared
/// Sqlite-backed <see cref="TestDbContext"/> from <see cref="EfCoreRefreshTokenStoreContractTests"/>.
/// </summary>
public sealed class EfCoreRefreshTokenStoreConcurrencyTests : IDisposable
{
    private readonly SqliteConnection _connection;
    private readonly DbContextOptions<TestDbContext> _options;

    public EfCoreRefreshTokenStoreConcurrencyTests()
    {
        _connection = new SqliteConnection("DataSource=:memory:");
        _connection.Open();
        _options = new DbContextOptionsBuilder<TestDbContext>().UseSqlite(_connection).Options;
        using var schemaCtx = new TestDbContext(_options);
        schemaCtx.Database.EnsureCreated();
    }

    public void Dispose() => _connection.Dispose();

    private async Task<Guid> SeedTokenAsync(TimeSpan? lifetime = null)
    {
        var id = Guid.NewGuid();
        using var seedCtx = new TestDbContext(_options);
        seedCtx.RefreshTokens.Add(new RefreshTokenEntity
        {
            Id = id,
            UserId = "u",
            TokenHash = $"hash-{id:N}",
            ExpiresAt = DateTimeOffset.UtcNow.Add(lifetime ?? TimeSpan.FromMinutes(5)),
        });
        await seedCtx.SaveChangesAsync();
        return id;
    }

    [Fact]
    public async Task RevokeAsync_does_not_throw_when_another_context_already_restamped_the_row()
    {
        var tokenId = await SeedTokenAsync();

        using var contextB = new TestDbContext(_options);
        // Context B tracks the row *before* context A touches it — mirrors a
        // long-lived (captive) DbContext whose change tracker holds a stale copy.
        _ = await contextB.RefreshTokens.SingleAsync(t => t.Id == tokenId);

        using (var contextA = new TestDbContext(_options))
        {
            var rowInA = await contextA.RefreshTokens.SingleAsync(t => t.Id == tokenId);
            rowInA.RevokedAt = DateTimeOffset.UtcNow;
            rowInA.ConcurrencyStamp = Guid.NewGuid().ToString();
            await contextA.SaveChangesAsync();
        }

        var storeB = new EfCoreRefreshTokenStore<TestDbContext>(contextB);
        var act = () => storeB.RevokeAsync(tokenId, "successor-hash");
        await act.Should().NotThrowAsync();

        using var verifyCtx = new TestDbContext(_options);
        var final = await verifyCtx.RefreshTokens.AsNoTracking().SingleAsync(t => t.Id == tokenId);
        final.RevokedAt.Should().NotBeNull();
    }

    [Fact]
    public async Task RevokeAsync_is_idempotent_when_row_was_already_deleted_concurrently()
    {
        var tokenId = await SeedTokenAsync();

        using var contextB = new TestDbContext(_options);
        _ = await contextB.RefreshTokens.SingleAsync(t => t.Id == tokenId);

        using (var contextA = new TestDbContext(_options))
        {
            var rowInA = await contextA.RefreshTokens.SingleAsync(t => t.Id == tokenId);
            contextA.RefreshTokens.Remove(rowInA);
            await contextA.SaveChangesAsync();
        }

        var storeB = new EfCoreRefreshTokenStore<TestDbContext>(contextB);
        var act = () => storeB.RevokeAsync(tokenId);
        await act.Should().NotThrowAsync();

        using var verifyCtx = new TestDbContext(_options);
        (await verifyCtx.RefreshTokens.CountAsync(t => t.Id == tokenId)).Should().Be(0);
    }

    [Fact]
    public async Task CleanupExpiredAsync_does_not_throw_when_a_row_was_already_deleted_concurrently()
    {
        var tokenId = await SeedTokenAsync(TimeSpan.FromMilliseconds(-1));

        using var contextB = new TestDbContext(_options);
        _ = await contextB.RefreshTokens.SingleAsync(t => t.Id == tokenId);

        using (var contextA = new TestDbContext(_options))
        {
            var rowInA = await contextA.RefreshTokens.SingleAsync(t => t.Id == tokenId);
            contextA.RefreshTokens.Remove(rowInA);
            await contextA.SaveChangesAsync();
        }

        var storeB = new EfCoreRefreshTokenStore<TestDbContext>(contextB);
        var removed = 0;
        var act = async () => removed = await storeB.CleanupExpiredAsync(DateTimeOffset.UtcNow);
        await act.Should().NotThrowAsync();
        removed.Should().Be(0);

        using var verifyCtx = new TestDbContext(_options);
        (await verifyCtx.RefreshTokens.CountAsync(t => t.Id == tokenId)).Should().Be(0);
    }
}
