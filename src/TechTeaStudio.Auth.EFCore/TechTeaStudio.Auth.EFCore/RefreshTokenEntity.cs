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
    public uint RowVersion { get; set; } // xmin on PostgreSQL, rowversion on SQL Server.

    public RefreshToken ToDomain() => new()
    {
        Id = Id,
        UserId = UserId,
        TokenHash = TokenHash,
        CreatedAt = CreatedAt,
        ExpiresAt = ExpiresAt,
        RevokedAt = RevokedAt,
        ReplacedByTokenHash = ReplacedByTokenHash,
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
    };
}

public static class ModelBuilderExtensions
{
    /// <summary>
    /// Registers <see cref="RefreshTokenEntity"/> with the model and applies the
    /// recommended indexes (unique on <c>TokenHash</c>; composite on
    /// <c>UserId, ExpiresAt</c>). Call from <c>OnModelCreating</c>.
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
        b.Property(e => e.RowVersion).IsConcurrencyToken();

        b.HasIndex(e => e.TokenHash).IsUnique();
        b.HasIndex(e => new { e.UserId, e.ExpiresAt });
        return b;
    }
}
