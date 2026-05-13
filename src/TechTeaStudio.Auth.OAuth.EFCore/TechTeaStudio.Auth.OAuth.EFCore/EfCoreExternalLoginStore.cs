using Microsoft.EntityFrameworkCore;
using TechTeaStudio.Auth.OAuth;

namespace TechTeaStudio.Auth.OAuth.EFCore;

/// <summary>
/// EF Core-backed <see cref="IExternalLoginStore"/>. The consumer's <c>DbContext</c>
/// must expose a <see cref="DbSet{T}"/> of <see cref="ExternalLoginEntity"/>
/// (call <c>modelBuilder.AddTechTeaStudioExternalLogins()</c> in <c>OnModelCreating</c>).
/// </summary>
public class EfCoreExternalLoginStore<TContext> : IExternalLoginStore
    where TContext : DbContext
{
    private readonly TContext _db;
    private readonly DbSet<ExternalLoginEntity> _set;

    public EfCoreExternalLoginStore(TContext db)
    {
        _db = db ?? throw new ArgumentNullException(nameof(db));
        _set = db.Set<ExternalLoginEntity>();
    }

    public async Task<ExternalLogin?> FindAsync(string provider, string providerUserId, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrEmpty(provider) || string.IsNullOrEmpty(providerUserId)) return null;
        var e = await _set.AsNoTracking()
            .FirstOrDefaultAsync(x => x.Provider == provider && x.ProviderUserId == providerUserId, cancellationToken)
            .ConfigureAwait(false);
        return e?.ToDomain();
    }

    public async Task<IReadOnlyList<ExternalLogin>> GetForUserAsync(string userId, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrEmpty(userId)) return Array.Empty<ExternalLogin>();
        var rows = await _set.AsNoTracking()
            .Where(e => e.UserId == userId)
            .ToListAsync(cancellationToken).ConfigureAwait(false);
        return rows.Select(r => r.ToDomain()).ToArray();
    }

    public async Task CreateAsync(ExternalLogin login, CancellationToken cancellationToken = default)
    {
        if (login is null) throw new ArgumentNullException(nameof(login));

        var dup = await _set.AnyAsync(
            x => x.Provider == login.Provider && x.ProviderUserId == login.ProviderUserId,
            cancellationToken).ConfigureAwait(false);
        if (dup) throw new InvalidOperationException(
            $"External login for ({login.Provider}, {login.ProviderUserId}) already exists.");

        _set.Add(ExternalLoginEntity.FromDomain(login));
        await _db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
    }

    public async Task DeleteAsync(Guid id, CancellationToken cancellationToken = default)
    {
        var e = await _set.FirstOrDefaultAsync(x => x.Id == id, cancellationToken).ConfigureAwait(false);
        if (e is null) return;
        _set.Remove(e);
        await _db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
    }

    public async Task DeleteAllForUserAsync(string userId, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrEmpty(userId)) return;
        var rows = await _set.Where(e => e.UserId == userId).ToListAsync(cancellationToken).ConfigureAwait(false);
        if (rows.Count == 0) return;
        _set.RemoveRange(rows);
        await _db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
    }
}
