using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Storage.ValueConversion;
using TechTeaStudio.Auth.Abstractions;
using TechTeaStudio.Auth.EFCore;
using TechTeaStudio.Auth.Tests.RefreshTokens;

namespace TechTeaStudio.Auth.Tests.EfCore;

/// <summary>
/// <c>DbContext</c> used by every EFCore refresh-token test. Runs on Sqlite
/// rather than the InMemory provider because <see cref="EfCoreRefreshTokenStore{TContext}"/>
/// uses <c>ExecuteUpdateAsync</c>/<c>ExecuteDeleteAsync</c> (net8.0+), which the
/// InMemory provider does not support at all.
/// </summary>
/// <remarks>
/// Sqlite's EF Core provider also refuses to translate ordering comparisons
/// (<c>&lt;=</c>, <c>&gt;</c>, …) on <see cref="DateTimeOffset"/> columns — its
/// offset-aware string representation doesn't sort chronologically across
/// differing offsets. <see cref="EfCoreRefreshTokenStore{TContext}"/>'s
/// <c>GetActiveForUserAsync</c> and <c>CleanupExpiredAsync</c> both compare
/// <c>ExpiresAt</c>, so this test-only context stores the timestamps as UTC
/// ticks instead. Production providers (PostgreSQL, SQL Server) compare
/// <see cref="DateTimeOffset"/> natively and need no such conversion.
/// </remarks>
public sealed class TestDbContext : DbContext
{
    public TestDbContext(DbContextOptions<TestDbContext> options) : base(options) { }

    public DbSet<RefreshTokenEntity> RefreshTokens => Set<RefreshTokenEntity>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.AddTechTeaStudioRefreshTokens();

        var ticks = new ValueConverter<DateTimeOffset, long>(v => v.UtcTicks, v => new DateTimeOffset(v, TimeSpan.Zero));
        var nullableTicks = new ValueConverter<DateTimeOffset?, long?>(
            v => v.HasValue ? v.Value.UtcTicks : null,
            v => v.HasValue ? new DateTimeOffset(v.Value, TimeSpan.Zero) : null);

        var entity = modelBuilder.Entity<RefreshTokenEntity>();
        entity.Property(e => e.CreatedAt).HasConversion(ticks);
        entity.Property(e => e.ExpiresAt).HasConversion(ticks);
        entity.Property(e => e.RevokedAt).HasConversion(nullableTicks);
    }
}

public class EfCoreRefreshTokenStoreContractTests : RefreshTokenStoreContractTests, IDisposable
{
    private readonly SqliteConnection _connection = new("DataSource=:memory:");

    protected override IRefreshTokenStore CreateStore()
    {
        _connection.Open();
        var options = new DbContextOptionsBuilder<TestDbContext>()
            .UseSqlite(_connection)
            .Options;
        using (var schemaCtx = new TestDbContext(options))
            schemaCtx.Database.EnsureCreated();
        var ctx = new TestDbContext(options);
        return new EfCoreRefreshTokenStore<TestDbContext>(ctx);
    }

    public void Dispose() => _connection.Dispose();
}
