using Microsoft.EntityFrameworkCore;
using TechTeaStudio.Auth.Abstractions;

namespace TechTeaStudio.Auth.EFCore;

/// <summary>
/// EF Core-backed <see cref="IRefreshTokenStore"/>. The consumer's
/// <c>DbContext</c> must expose a <see cref="DbSet{TEntity}"/> of
/// <see cref="RefreshTokenEntity"/> (the standard pattern: call
/// <c>modelBuilder.AddTechTeaStudioRefreshTokens()</c> in <c>OnModelCreating</c>).
/// </summary>
public class EfCoreRefreshTokenStore<TContext> : IRefreshTokenStore
    where TContext : DbContext
{
    private readonly TContext _db;
    private readonly DbSet<RefreshTokenEntity> _set;

    public EfCoreRefreshTokenStore(TContext db)
    {
        _db = db ?? throw new ArgumentNullException(nameof(db));
        _set = db.Set<RefreshTokenEntity>();
    }

    public async Task<RefreshToken?> GetByTokenHashAsync(string tokenHash, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrEmpty(tokenHash)) return null;
        var e = await _set.AsNoTracking().FirstOrDefaultAsync(x => x.TokenHash == tokenHash, cancellationToken).ConfigureAwait(false);
        return e?.ToDomain();
    }

    public async Task<IReadOnlyList<RefreshToken>> GetActiveForUserAsync(string userId, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrEmpty(userId)) return Array.Empty<RefreshToken>();
        var now = DateTimeOffset.UtcNow;
        var rows = await _set.AsNoTracking()
            .Where(t => t.UserId == userId && t.RevokedAt == null && t.ExpiresAt > now)
            .ToListAsync(cancellationToken).ConfigureAwait(false);
        return rows.Select(r => r.ToDomain()).ToArray();
    }

    public async Task CreateAsync(RefreshToken token, CancellationToken cancellationToken = default)
    {
        if (token is null) throw new ArgumentNullException(nameof(token));

        if (await _set.AnyAsync(t => t.TokenHash == token.TokenHash, cancellationToken).ConfigureAwait(false))
            throw new InvalidOperationException($"Refresh token with hash '{token.TokenHash}' already exists.");

        _set.Add(RefreshTokenEntity.FromDomain(token));
        await _db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
    }

    public async Task RevokeAsync(Guid id, string? replacedByTokenHash = null, CancellationToken cancellationToken = default)
    {
        var e = await _set.FirstOrDefaultAsync(t => t.Id == id, cancellationToken).ConfigureAwait(false);
        if (e is null) return;
        if (e.RevokedAt is null) e.RevokedAt = DateTimeOffset.UtcNow;
        if (replacedByTokenHash is not null) e.ReplacedByTokenHash = replacedByTokenHash;
        e.ConcurrencyStamp = Guid.NewGuid().ToString();
        await _db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
    }

    public async Task RevokeAllForUserAsync(string userId, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrEmpty(userId)) return;
        var now = DateTimeOffset.UtcNow;
        var active = await _set.Where(t => t.UserId == userId && t.RevokedAt == null).ToListAsync(cancellationToken).ConfigureAwait(false);
        foreach (var e in active)
        {
            e.RevokedAt = now;
            e.ConcurrencyStamp = Guid.NewGuid().ToString();
        }
        await _db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
    }

    public async Task<int> CleanupExpiredAsync(DateTimeOffset cutoff, CancellationToken cancellationToken = default)
    {
        var expired = await _set.Where(t => t.ExpiresAt <= cutoff).ToListAsync(cancellationToken).ConfigureAwait(false);
        if (expired.Count == 0) return 0;
        _set.RemoveRange(expired);
        await _db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
        return expired.Count;
    }

    public async Task DeleteAllForUserAsync(string userId, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrEmpty(userId)) return;
        var rows = await _set.Where(t => t.UserId == userId).ToListAsync(cancellationToken).ConfigureAwait(false);
        if (rows.Count == 0) return;
        _set.RemoveRange(rows);
        await _db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
    }
}
