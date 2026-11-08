using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Storage.ValueConversion;
using TechTeaStudio.Auth.OAuthServer.Abstractions;

namespace TechTeaStudio.Auth.OAuthServer.EFCore;

internal static class Text
{
    public static string JoinScopes(IEnumerable<string> scopes) => string.Join(' ', scopes);

    public static IReadOnlyList<string> SplitScopes(string s) =>
        s.Split(' ', StringSplitOptions.RemoveEmptyEntries);
}

public sealed class OAuthClientEntity
{
    public string ClientId { get; set; } = string.Empty;
    public string? Name { get; set; }
    public string? LogoUri { get; set; }
    public string? ClientUri { get; set; }

    /// <summary>Redirect URIs separated by a newline (a URI cannot contain one).</summary>
    public string RedirectUris { get; set; } = string.Empty;

    public string? SecretHash { get; set; }
    public int Source { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset? LastUsedAt { get; set; }

    public OAuthClient ToDomain() => new()
    {
        ClientId = ClientId, Name = Name, LogoUri = LogoUri, ClientUri = ClientUri,
        RedirectUris = RedirectUris.Split('\n', StringSplitOptions.RemoveEmptyEntries),
        SecretHash = SecretHash, Source = (OAuthClientSource)Source, CreatedAt = CreatedAt, LastUsedAt = LastUsedAt,
    };

    public static OAuthClientEntity FromDomain(OAuthClient c) => new()
    {
        ClientId = c.ClientId, Name = c.Name, LogoUri = c.LogoUri, ClientUri = c.ClientUri,
        RedirectUris = string.Join('\n', c.RedirectUris),
        SecretHash = c.SecretHash, Source = (int)c.Source, CreatedAt = c.CreatedAt, LastUsedAt = c.LastUsedAt,
    };
}

public sealed class OAuthPendingRequestEntity
{
    public string Id { get; set; } = string.Empty;
    public string ClientId { get; set; } = string.Empty;
    public string RedirectUri { get; set; } = string.Empty;
    public string CodeChallenge { get; set; } = string.Empty;
    public string Resource { get; set; } = string.Empty;
    public string Scope { get; set; } = string.Empty;
    public string? State { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset ExpiresAt { get; set; }

    public PendingAuthorization ToDomain() => new()
    {
        Id = Id, ClientId = ClientId, RedirectUri = RedirectUri, CodeChallenge = CodeChallenge, Resource = Resource,
        Scopes = Text.SplitScopes(Scope), State = State, CreatedAt = CreatedAt, ExpiresAt = ExpiresAt,
    };

    public static OAuthPendingRequestEntity FromDomain(PendingAuthorization p) => new()
    {
        Id = p.Id, ClientId = p.ClientId, RedirectUri = p.RedirectUri, CodeChallenge = p.CodeChallenge, Resource = p.Resource,
        Scope = Text.JoinScopes(p.Scopes), State = p.State, CreatedAt = p.CreatedAt, ExpiresAt = p.ExpiresAt,
    };
}

public sealed class OAuthCodeEntity
{
    public string CodeHash { get; set; } = string.Empty;
    public string ClientId { get; set; } = string.Empty;
    public string RedirectUri { get; set; } = string.Empty;
    public string CodeChallenge { get; set; } = string.Empty;
    public string Resource { get; set; } = string.Empty;
    public string Scope { get; set; } = string.Empty;
    public string UserId { get; set; } = string.Empty;
    public Guid FamilyId { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset ExpiresAt { get; set; }
    public DateTimeOffset? ConsumedAt { get; set; }
    public string ConcurrencyStamp { get; set; } = Guid.NewGuid().ToString();

    public AuthorizationCode ToDomain() => new()
    {
        CodeHash = CodeHash, ClientId = ClientId, RedirectUri = RedirectUri, CodeChallenge = CodeChallenge, Resource = Resource,
        Scopes = Text.SplitScopes(Scope), UserId = UserId, FamilyId = FamilyId, CreatedAt = CreatedAt, ExpiresAt = ExpiresAt, ConsumedAt = ConsumedAt,
    };

    public static OAuthCodeEntity FromDomain(AuthorizationCode c) => new()
    {
        CodeHash = c.CodeHash, ClientId = c.ClientId, RedirectUri = c.RedirectUri, CodeChallenge = c.CodeChallenge, Resource = c.Resource,
        Scope = Text.JoinScopes(c.Scopes), UserId = c.UserId, FamilyId = c.FamilyId, CreatedAt = c.CreatedAt, ExpiresAt = c.ExpiresAt, ConsumedAt = c.ConsumedAt,
    };
}

public sealed class OAuthRefreshTokenEntity
{
    public Guid Id { get; set; }
    public string TokenHash { get; set; } = string.Empty;
    public Guid FamilyId { get; set; }
    public string ClientId { get; set; } = string.Empty;
    public string UserId { get; set; } = string.Empty;
    public string Scope { get; set; } = string.Empty;
    public string Resource { get; set; } = string.Empty;
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset ExpiresAt { get; set; }
    public DateTimeOffset? RotatedAt { get; set; }
    public DateTimeOffset? RevokedAt { get; set; }
    public string? ReplacedByTokenHash { get; set; }
    public string ConcurrencyStamp { get; set; } = Guid.NewGuid().ToString();

    public OAuthRefreshToken ToDomain() => new()
    {
        Id = Id, TokenHash = TokenHash, FamilyId = FamilyId, ClientId = ClientId, UserId = UserId,
        Scopes = Text.SplitScopes(Scope), Resource = Resource, CreatedAt = CreatedAt, ExpiresAt = ExpiresAt,
        RotatedAt = RotatedAt, RevokedAt = RevokedAt, ReplacedByTokenHash = ReplacedByTokenHash,
    };

    public static OAuthRefreshTokenEntity FromDomain(OAuthRefreshToken t) => new()
    {
        Id = t.Id, TokenHash = t.TokenHash, FamilyId = t.FamilyId, ClientId = t.ClientId, UserId = t.UserId,
        Scope = Text.JoinScopes(t.Scopes), Resource = t.Resource, CreatedAt = t.CreatedAt, ExpiresAt = t.ExpiresAt,
        RotatedAt = t.RotatedAt, RevokedAt = t.RevokedAt, ReplacedByTokenHash = t.ReplacedByTokenHash,
    };
}

public sealed class OAuthRefreshFamilyEntity
{
    public Guid FamilyId { get; set; }
    public string UserId { get; set; } = string.Empty;
    public string ClientId { get; set; } = string.Empty;
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset ExpiresAt { get; set; }
    public DateTimeOffset? RevokedAt { get; set; }
    public string ConcurrencyStamp { get; set; } = Guid.NewGuid().ToString();

    public OAuthRefreshFamily ToDomain() => new()
    {
        FamilyId = FamilyId, UserId = UserId, ClientId = ClientId, CreatedAt = CreatedAt, ExpiresAt = ExpiresAt, RevokedAt = RevokedAt,
    };

    public static OAuthRefreshFamilyEntity FromDomain(OAuthRefreshFamily f) => new()
    {
        FamilyId = f.FamilyId, UserId = f.UserId, ClientId = f.ClientId, CreatedAt = f.CreatedAt, ExpiresAt = f.ExpiresAt, RevokedAt = f.RevokedAt,
    };
}

public sealed class OAuthGrantEntity
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public string UserId { get; set; } = string.Empty;
    public string ClientId { get; set; } = string.Empty;
    public string? ClientName { get; set; }
    public string Scope { get; set; } = string.Empty;
    public DateTimeOffset FirstGrantedAt { get; set; }
    public DateTimeOffset LastUsedAt { get; set; }
    public string ConcurrencyStamp { get; set; } = Guid.NewGuid().ToString();

    public OAuthGrant ToDomain() => new()
    {
        UserId = UserId, ClientId = ClientId, ClientName = ClientName, Scopes = Text.SplitScopes(Scope),
        FirstGrantedAt = FirstGrantedAt, LastUsedAt = LastUsedAt,
    };
}

public static class OAuthServerModelBuilderExtensions
{
    /// <summary>
    /// Maps the five authorization-server tables: <c>{prefix}Clients</c>, <c>{prefix}PendingRequests</c>,
    /// <c>{prefix}Codes</c>, <c>{prefix}RefreshTokens</c>, <c>{prefix}Grants</c>. Call from <c>OnModelCreating</c>.
    /// </summary>
    public static ModelBuilder AddTechTeaStudioOAuthServerTables(this ModelBuilder modelBuilder, string prefix = "TtsOAuth")
    {
        if (modelBuilder is null) throw new ArgumentNullException(nameof(modelBuilder));

        // Instants are stored as UTC ticks (bigint). SQLite cannot compare DateTimeOffset in SQL, and the cleanup and
        // expiry queries must run in the database on every provider.
        var utcTicks = new ValueConverter<DateTimeOffset, long>(v => v.UtcTicks, v => new DateTimeOffset(v, TimeSpan.Zero));

        var client = modelBuilder.Entity<OAuthClientEntity>();
        client.ToTable(prefix + "Clients");
        client.HasKey(e => e.ClientId);
        client.Property(e => e.ClientId).HasMaxLength(512);
        client.Property(e => e.Name).HasMaxLength(256);
        client.Property(e => e.LogoUri).HasMaxLength(2048);
        client.Property(e => e.ClientUri).HasMaxLength(2048);
        client.Property(e => e.RedirectUris).IsRequired();
        client.Property(e => e.SecretHash).HasMaxLength(64);

        var pending = modelBuilder.Entity<OAuthPendingRequestEntity>();
        pending.ToTable(prefix + "PendingRequests");
        pending.HasKey(e => e.Id);
        pending.Property(e => e.Id).HasMaxLength(64);
        pending.Property(e => e.ClientId).IsRequired().HasMaxLength(512);
        pending.Property(e => e.RedirectUri).IsRequired().HasMaxLength(2048);
        pending.Property(e => e.CodeChallenge).IsRequired().HasMaxLength(128);
        pending.Property(e => e.Resource).IsRequired().HasMaxLength(2048);
        pending.Property(e => e.Scope).IsRequired().HasMaxLength(2048);
        pending.Property(e => e.State).HasMaxLength(2048);
        pending.HasIndex(e => e.ExpiresAt);

        var code = modelBuilder.Entity<OAuthCodeEntity>();
        code.ToTable(prefix + "Codes");
        code.HasKey(e => e.CodeHash);
        code.Property(e => e.CodeHash).HasMaxLength(64);
        code.Property(e => e.ClientId).IsRequired().HasMaxLength(512);
        code.Property(e => e.RedirectUri).IsRequired().HasMaxLength(2048);
        code.Property(e => e.CodeChallenge).IsRequired().HasMaxLength(128);
        code.Property(e => e.Resource).IsRequired().HasMaxLength(2048);
        code.Property(e => e.Scope).IsRequired().HasMaxLength(2048);
        code.Property(e => e.UserId).IsRequired().HasMaxLength(256);
        code.Property(e => e.ConcurrencyStamp).IsRequired().HasMaxLength(64).IsConcurrencyToken();
        code.HasIndex(e => e.ExpiresAt);

        var refresh = modelBuilder.Entity<OAuthRefreshTokenEntity>();
        refresh.ToTable(prefix + "RefreshTokens");
        refresh.HasKey(e => e.Id);
        refresh.Property(e => e.TokenHash).IsRequired().HasMaxLength(64);
        refresh.Property(e => e.ClientId).IsRequired().HasMaxLength(512);
        refresh.Property(e => e.UserId).IsRequired().HasMaxLength(256);
        refresh.Property(e => e.Scope).IsRequired().HasMaxLength(2048);
        refresh.Property(e => e.Resource).IsRequired().HasMaxLength(2048);
        refresh.Property(e => e.ReplacedByTokenHash).HasMaxLength(64);
        refresh.Property(e => e.ConcurrencyStamp).IsRequired().HasMaxLength(64).IsConcurrencyToken();
        refresh.HasIndex(e => e.TokenHash).IsUnique();
        refresh.HasIndex(e => e.FamilyId);
        refresh.HasIndex(e => new { e.UserId, e.ClientId });
        refresh.HasIndex(e => e.ExpiresAt);

        var family = modelBuilder.Entity<OAuthRefreshFamilyEntity>();
        family.ToTable(prefix + "Families");
        family.HasKey(e => e.FamilyId);
        family.Property(e => e.UserId).IsRequired().HasMaxLength(256);
        family.Property(e => e.ClientId).IsRequired().HasMaxLength(512);
        family.Property(e => e.ConcurrencyStamp).IsRequired().HasMaxLength(64).IsConcurrencyToken();
        family.HasIndex(e => new { e.UserId, e.ClientId });
        family.HasIndex(e => e.ExpiresAt);
        family.Property(e => e.CreatedAt).HasConversion(utcTicks);
        family.Property(e => e.ExpiresAt).HasConversion(utcTicks);
        family.Property(e => e.RevokedAt).HasConversion(utcTicks);

        var grant = modelBuilder.Entity<OAuthGrantEntity>();
        grant.ToTable(prefix + "Grants");
        grant.HasKey(e => e.Id);
        grant.Property(e => e.UserId).IsRequired().HasMaxLength(256);
        grant.Property(e => e.ClientId).IsRequired().HasMaxLength(512);
        grant.Property(e => e.ClientName).HasMaxLength(256);
        grant.Property(e => e.Scope).IsRequired().HasMaxLength(2048);
        grant.Property(e => e.ConcurrencyStamp).IsRequired().HasMaxLength(64).IsConcurrencyToken();
        grant.HasIndex(e => new { e.UserId, e.ClientId }).IsUnique();

        client.Property(e => e.CreatedAt).HasConversion(utcTicks);
        client.Property(e => e.LastUsedAt).HasConversion(utcTicks);
        pending.Property(e => e.CreatedAt).HasConversion(utcTicks);
        pending.Property(e => e.ExpiresAt).HasConversion(utcTicks);
        code.Property(e => e.CreatedAt).HasConversion(utcTicks);
        code.Property(e => e.ExpiresAt).HasConversion(utcTicks);
        code.Property(e => e.ConsumedAt).HasConversion(utcTicks);
        refresh.Property(e => e.CreatedAt).HasConversion(utcTicks);
        refresh.Property(e => e.ExpiresAt).HasConversion(utcTicks);
        refresh.Property(e => e.RotatedAt).HasConversion(utcTicks);
        refresh.Property(e => e.RevokedAt).HasConversion(utcTicks);
        grant.Property(e => e.FirstGrantedAt).HasConversion(utcTicks);
        grant.Property(e => e.LastUsedAt).HasConversion(utcTicks);

        return modelBuilder;
    }
}
