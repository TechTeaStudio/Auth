using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using TechTeaStudio.Auth.Abstractions;

namespace TechTeaStudio.Auth.EFCore;

/// <summary>
/// EF Core mapping for <see cref="RefreshToken"/>. Mirrors every field of the
/// domain record one-to-one. Add to your <c>DbContext</c> via
/// <see cref="ModelBuilderExtensions.AddTechTeaStudioRefreshTokens"/>.
/// </summary>
public sealed class RefreshTokenEntity
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public string UserId { get; set; } = string.Empty;
    public string TokenHash { get; set; } = string.Empty;
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset ExpiresAt { get; set; }
    public DateTimeOffset? RevokedAt { get; set; }
    public string? ReplacedByTokenHash { get; set; }

    /// <summary>Originating device/install identifier. See <see cref="RefreshToken.DeviceId"/>.</summary>
    public string? DeviceId { get; set; }

    /// <summary>Human-readable device descriptor. See <see cref="RefreshToken.DeviceInfo"/>.</summary>
    public string? DeviceInfo { get; set; }

    /// <summary>
    /// Optimistic-concurrency token. Stored as a 36-char GUID string so the same
    /// schema works across SQL Server, PostgreSQL, SQLite, MySQL, and any other
    /// provider — no <c>rowversion</c>/<c>xmin</c> magic required. The store
    /// regenerates this on every UPDATE.
    /// </summary>
    public string ConcurrencyStamp { get; set; } = Guid.NewGuid().ToString();

    public RefreshToken ToDomain() => new()
    {
        Id = Id,
        UserId = UserId,
        TokenHash = TokenHash,
        CreatedAt = CreatedAt,
        ExpiresAt = ExpiresAt,
        RevokedAt = RevokedAt,
        ReplacedByTokenHash = ReplacedByTokenHash,
        DeviceId = DeviceId,
        DeviceInfo = DeviceInfo,
    };

    public static RefreshTokenEntity FromDomain(RefreshToken t) => new()
    {
        Id = t.Id,
        UserId = t.UserId,
        TokenHash = t.TokenHash,
        CreatedAt = t.CreatedAt,
        ExpiresAt = t.ExpiresAt,
        RevokedAt = t.RevokedAt,
        ReplacedByTokenHash = t.ReplacedByTokenHash,
        DeviceId = t.DeviceId,
        DeviceInfo = t.DeviceInfo,
    };
}

public static class ModelBuilderExtensions
{
    /// <summary>
    /// Registers <see cref="RefreshTokenEntity"/> with the model and applies the
    /// recommended indexes (unique on <c>TokenHash</c>; composite on
    /// <c>UserId, ExpiresAt</c>) and concurrency-token mapping. Call from <c>OnModelCreating</c>.
    ///
    /// <para>
    /// Schema change in 0.8.0: two new nullable columns <c>DeviceId</c> (varchar(256))
    /// and <c>DeviceInfo</c> (varchar(64)). Existing deployments must run an
    /// <c>ALTER TABLE</c> — see <see cref="SchemaMigrations.AddDeviceColumnsSqlPostgres"/>
    /// (or the SqlServer/Sqlite variants) for ready-made SQL.
    /// </para>
    /// </summary>
    public static EntityTypeBuilder<RefreshTokenEntity> AddTechTeaStudioRefreshTokens(this ModelBuilder modelBuilder, string tableName = "TtsRefreshTokens")
    {
        if (modelBuilder is null) throw new ArgumentNullException(nameof(modelBuilder));

        var b = modelBuilder.Entity<RefreshTokenEntity>();
        b.ToTable(tableName);
        b.HasKey(e => e.Id);

        b.Property(e => e.UserId).IsRequired().HasMaxLength(256);
        b.Property(e => e.TokenHash).IsRequired().HasMaxLength(64);
        b.Property(e => e.ReplacedByTokenHash).HasMaxLength(64);
        b.Property(e => e.DeviceId).HasMaxLength(256);
        b.Property(e => e.DeviceInfo).HasMaxLength(64);
        b.Property(e => e.ConcurrencyStamp).IsRequired().HasMaxLength(64).IsConcurrencyToken();

        b.HasIndex(e => e.TokenHash).IsUnique();
        b.HasIndex(e => new { e.UserId, e.ExpiresAt });
        return b;
    }
}
