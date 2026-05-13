using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using TechTeaStudio.Auth.OAuth;

namespace TechTeaStudio.Auth.OAuth.EFCore;

/// <summary>
/// EF Core mapping for <see cref="ExternalLogin"/>. Mirrors every field of the
/// domain record. Add to your <c>DbContext</c> via
/// <see cref="OAuthModelBuilderExtensions.AddTechTeaStudioExternalLogins"/>.
/// </summary>
public sealed class ExternalLoginEntity
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public string UserId { get; set; } = string.Empty;
    public string Provider { get; set; } = string.Empty;
    public string ProviderUserId { get; set; } = string.Empty;
    public string? Email { get; set; }
    public DateTimeOffset CreatedAt { get; set; }

    /// <summary>Optimistic-concurrency token. Cross-provider — works everywhere.</summary>
    public string ConcurrencyStamp { get; set; } = Guid.NewGuid().ToString();

    public ExternalLogin ToDomain() => new()
    {
        Id = Id,
        UserId = UserId,
        Provider = Provider,
        ProviderUserId = ProviderUserId,
        Email = Email,
        CreatedAt = CreatedAt,
    };

    public static ExternalLoginEntity FromDomain(ExternalLogin login) => new()
    {
        Id = login.Id,
        UserId = login.UserId,
        Provider = login.Provider,
        ProviderUserId = login.ProviderUserId,
        Email = login.Email,
        CreatedAt = login.CreatedAt,
    };
}

public static class OAuthModelBuilderExtensions
{
    /// <summary>
    /// Registers <see cref="ExternalLoginEntity"/> with the model and applies the
    /// recommended schema: unique index on <c>(Provider, ProviderUserId)</c>,
    /// composite index on <c>(UserId, Provider)</c>, concurrency token.
    /// Call from <c>OnModelCreating</c>.
    /// </summary>
    public static EntityTypeBuilder<ExternalLoginEntity> AddTechTeaStudioExternalLogins(this ModelBuilder modelBuilder, string tableName = "TtsExternalLogins")
    {
        if (modelBuilder is null) throw new ArgumentNullException(nameof(modelBuilder));

        var b = modelBuilder.Entity<ExternalLoginEntity>();
        b.ToTable(tableName);
        b.HasKey(e => e.Id);

        b.Property(e => e.UserId).IsRequired().HasMaxLength(256);
        b.Property(e => e.Provider).IsRequired().HasMaxLength(64);
        b.Property(e => e.ProviderUserId).IsRequired().HasMaxLength(256);
        b.Property(e => e.Email).HasMaxLength(256);
        b.Property(e => e.ConcurrencyStamp).IsRequired().HasMaxLength(64).IsConcurrencyToken();

        b.HasIndex(e => new { e.Provider, e.ProviderUserId }).IsUnique();
        b.HasIndex(e => new { e.UserId, e.Provider });
        return b;
    }
}
