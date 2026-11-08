using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using TechTeaStudio.Auth.OAuthServer.Abstractions;

namespace TechTeaStudio.Auth.OAuthServer.EFCore;

// Every store works on a scoped DbContext and is written to behave the same on net6 (no ExecuteUpdate):
// load, mutate, SaveChanges, and treat DbUpdateConcurrencyException as "someone else won". The concurrency
// tokens (ConcurrencyStamp) are what make the single-use and compare-and-swap operations atomic.
// SaveChangesAsync flushes the whole context, so do not share a long-lived context across requests.

internal static class EfRetry
{
    public const int MaxAttempts = 4;

    public static void Detach(DbContext db, IEnumerable<object> entities)
    {
        foreach (var e in entities)
        {
            var entry = db.Entry(e);
            if (entry.State != EntityState.Detached) entry.State = EntityState.Detached;
        }
    }

    public static void DetachConflicts(DbContext db, DbUpdateConcurrencyException ex)
    {
        foreach (var entry in ex.Entries) entry.State = EntityState.Detached;
    }
}

public class EfCoreOAuthClientStore<TContext> : IOAuthClientStore where TContext : DbContext
{
    private readonly TContext _db;
    public EfCoreOAuthClientStore(TContext db) => _db = db ?? throw new ArgumentNullException(nameof(db));

    public async Task<OAuthClient?> FindAsync(string clientId, CancellationToken cancellationToken = default)
    {
        var e = await _db.Set<OAuthClientEntity>().AsNoTracking().FirstOrDefaultAsync(c => c.ClientId == clientId, cancellationToken).ConfigureAwait(false);
        return e?.ToDomain();
    }

    public async Task SaveAsync(OAuthClient client, CancellationToken cancellationToken = default)
    {
        var existing = await _db.Set<OAuthClientEntity>().FirstOrDefaultAsync(c => c.ClientId == client.ClientId, cancellationToken).ConfigureAwait(false);
        if (existing is not null) _db.Remove(existing);
        _db.Add(OAuthClientEntity.FromDomain(client));
        await _db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
    }
}

public class EfCoreOAuthPendingRequestStore<TContext> : IOAuthPendingRequestStore where TContext : DbContext
{
    private readonly TContext _db;
    public EfCoreOAuthPendingRequestStore(TContext db) => _db = db ?? throw new ArgumentNullException(nameof(db));

    public async Task SaveAsync(PendingAuthorization request, CancellationToken cancellationToken = default)
    {
        _db.Add(OAuthPendingRequestEntity.FromDomain(request));
        await _db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
    }

    public async Task<PendingAuthorization?> GetAsync(string id, DateTimeOffset now, CancellationToken cancellationToken = default)
    {
        var e = await _db.Set<OAuthPendingRequestEntity>().AsNoTracking().FirstOrDefaultAsync(p => p.Id == id, cancellationToken).ConfigureAwait(false);
        return e is not null && e.ExpiresAt > now ? e.ToDomain() : null;
    }

    public async Task<PendingAuthorization?> TakeAsync(string id, DateTimeOffset now, CancellationToken cancellationToken = default)
    {
        var e = await _db.Set<OAuthPendingRequestEntity>().FirstOrDefaultAsync(p => p.Id == id, cancellationToken).ConfigureAwait(false);
        if (e is null) return null;

        var domain = e.ToDomain();
        _db.Remove(e);
        try
        {
            await _db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (DbUpdateConcurrencyException ex)
        {
            EfRetry.DetachConflicts(_db, ex);
            return null;
        }
        return e.ExpiresAt > now ? domain : null;
    }

    public async Task<int> CleanupExpiredAsync(DateTimeOffset cutoff, CancellationToken cancellationToken = default)
    {
        for (var attempt = 0; ; attempt++)
        {
            var rows = await _db.Set<OAuthPendingRequestEntity>().Where(p => p.ExpiresAt <= cutoff).ToListAsync(cancellationToken).ConfigureAwait(false);
            if (rows.Count == 0) return 0;
            _db.RemoveRange(rows);
            try
            {
                await _db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
                return rows.Count;
            }
            catch (DbUpdateConcurrencyException ex) when (attempt < EfRetry.MaxAttempts)
            {
                EfRetry.DetachConflicts(_db, ex);
            }
        }
    }
}

public class EfCoreOAuthCodeStore<TContext> : IOAuthCodeStore where TContext : DbContext
{
    private readonly TContext _db;
    public EfCoreOAuthCodeStore(TContext db) => _db = db ?? throw new ArgumentNullException(nameof(db));

    public async Task SaveAsync(AuthorizationCode code, CancellationToken cancellationToken = default)
    {
        _db.Add(OAuthCodeEntity.FromDomain(code));
        await _db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
    }

    public async Task<CodeConsumeResult?> TryConsumeAsync(string codeHash, DateTimeOffset now, CancellationToken cancellationToken = default)
    {
        var e = await _db.Set<OAuthCodeEntity>().FirstOrDefaultAsync(c => c.CodeHash == codeHash, cancellationToken).ConfigureAwait(false);
        if (e is null) return null;
        if (e.ConsumedAt is not null)
        {
            var seen = e.ToDomain();
            EfRetry.Detach(_db, new object[] { e });
            return new CodeConsumeResult(seen, true);
        }

        e.ConsumedAt = now;
        e.ConcurrencyStamp = Guid.NewGuid().ToString();
        try
        {
            await _db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (DbUpdateConcurrencyException ex)
        {
            EfRetry.DetachConflicts(_db, ex);
            var winner = await _db.Set<OAuthCodeEntity>().AsNoTracking().FirstOrDefaultAsync(c => c.CodeHash == codeHash, cancellationToken).ConfigureAwait(false);
            return winner is null ? null : new CodeConsumeResult(winner.ToDomain(), true);
        }

        var consumed = e.ToDomain();
        EfRetry.Detach(_db, new object[] { e });
        return new CodeConsumeResult(consumed, false);
    }

    public async Task<int> CleanupExpiredAsync(DateTimeOffset cutoff, CancellationToken cancellationToken = default)
    {
        for (var attempt = 0; ; attempt++)
        {
            var rows = await _db.Set<OAuthCodeEntity>().Where(c => c.ExpiresAt <= cutoff).ToListAsync(cancellationToken).ConfigureAwait(false);
            if (rows.Count == 0) return 0;
            _db.RemoveRange(rows);
            try
            {
                await _db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
                return rows.Count;
            }
            catch (DbUpdateConcurrencyException ex) when (attempt < EfRetry.MaxAttempts)
            {
                EfRetry.DetachConflicts(_db, ex);
            }
        }
    }
}

public class EfCoreOAuthRefreshTokenStore<TContext> : IOAuthRefreshTokenStore where TContext : DbContext
{
    private readonly TContext _db;
    public EfCoreOAuthRefreshTokenStore(TContext db) => _db = db ?? throw new ArgumentNullException(nameof(db));

    private DbSet<OAuthRefreshTokenEntity> Set => _db.Set<OAuthRefreshTokenEntity>();

    public async Task CreateAsync(OAuthRefreshToken token, CancellationToken cancellationToken = default)
    {
        Set.Add(OAuthRefreshTokenEntity.FromDomain(token));
        await _db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
    }

    public async Task<OAuthRefreshToken?> GetByHashAsync(string tokenHash, CancellationToken cancellationToken = default)
    {
        var e = await Set.AsNoTracking().FirstOrDefaultAsync(t => t.TokenHash == tokenHash, cancellationToken).ConfigureAwait(false);
        return e?.ToDomain();
    }

    public async Task<bool> TryRotateAsync(Guid id, string replacedByTokenHash, DateTimeOffset now, CancellationToken cancellationToken = default)
    {
        var e = await Set.FirstOrDefaultAsync(t => t.Id == id, cancellationToken).ConfigureAwait(false);
        if (e is null) return false;
        if (e.RotatedAt is not null || e.RevokedAt is not null)
        {
            EfRetry.Detach(_db, new object[] { e });
            return false;
        }

        e.RotatedAt = now;
        e.ReplacedByTokenHash = replacedByTokenHash;
        e.ConcurrencyStamp = Guid.NewGuid().ToString();
        try
        {
            await _db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (DbUpdateConcurrencyException ex)
        {
            EfRetry.DetachConflicts(_db, ex);
            return false;
        }
        EfRetry.Detach(_db, new object[] { e });
        return true;
    }

    public Task<int> RevokeFamilyAsync(Guid familyId, DateTimeOffset now, CancellationToken cancellationToken = default) =>
        RevokeAsync(t => t.FamilyId == familyId && t.RevokedAt == null, now, cancellationToken);

    public Task<int> RevokeForUserClientAsync(string userId, string clientId, DateTimeOffset now, CancellationToken cancellationToken = default) =>
        RevokeAsync(t => t.UserId == userId && t.ClientId == clientId && t.RevokedAt == null, now, cancellationToken);

    private async Task<int> RevokeAsync(System.Linq.Expressions.Expression<Func<OAuthRefreshTokenEntity, bool>> predicate, DateTimeOffset now, CancellationToken ct)
    {
        for (var attempt = 0; ; attempt++)
        {
            var rows = await Set.Where(predicate).ToListAsync(ct).ConfigureAwait(false);
            if (rows.Count == 0) return 0;
            foreach (var r in rows)
            {
                r.RevokedAt = now;
                r.ConcurrencyStamp = Guid.NewGuid().ToString();
            }
            try
            {
                await _db.SaveChangesAsync(ct).ConfigureAwait(false);
                EfRetry.Detach(_db, rows);
                return rows.Count;
            }
            catch (DbUpdateConcurrencyException ex) when (attempt < EfRetry.MaxAttempts)
            {
                EfRetry.DetachConflicts(_db, ex);
                EfRetry.Detach(_db, rows);
            }
        }
    }

    public async Task<int> CleanupExpiredAsync(DateTimeOffset cutoff, CancellationToken cancellationToken = default)
    {
        for (var attempt = 0; ; attempt++)
        {
            var rows = await Set.Where(t => t.ExpiresAt <= cutoff).ToListAsync(cancellationToken).ConfigureAwait(false);
            if (rows.Count == 0) return 0;
            Set.RemoveRange(rows);
            try
            {
                await _db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
                return rows.Count;
            }
            catch (DbUpdateConcurrencyException ex) when (attempt < EfRetry.MaxAttempts)
            {
                EfRetry.DetachConflicts(_db, ex);
            }
        }
    }
}

public class EfCoreOAuthGrantStore<TContext> : IOAuthGrantStore where TContext : DbContext
{
    private readonly TContext _db;
    public EfCoreOAuthGrantStore(TContext db) => _db = db ?? throw new ArgumentNullException(nameof(db));

    private DbSet<OAuthGrantEntity> Set => _db.Set<OAuthGrantEntity>();

    public async Task<OAuthGrant?> GetAsync(string userId, string clientId, CancellationToken cancellationToken = default)
    {
        var e = await Set.AsNoTracking().FirstOrDefaultAsync(g => g.UserId == userId && g.ClientId == clientId, cancellationToken).ConfigureAwait(false);
        return e?.ToDomain();
    }

    public async Task UpsertAsync(string userId, string clientId, string? clientName, IReadOnlyCollection<string> scopes, DateTimeOffset now, CancellationToken cancellationToken = default)
    {
        for (var attempt = 0; ; attempt++)
        {
            var e = await Set.FirstOrDefaultAsync(g => g.UserId == userId && g.ClientId == clientId, cancellationToken).ConfigureAwait(false);
            if (e is null)
            {
                e = new OAuthGrantEntity
                {
                    UserId = userId, ClientId = clientId, ClientName = clientName,
                    Scope = Text.JoinScopes(scopes.Distinct()), FirstGrantedAt = now, LastUsedAt = now,
                };
                Set.Add(e);
            }
            else
            {
                e.ClientName = clientName ?? e.ClientName;
                e.Scope = Text.JoinScopes(Text.SplitScopes(e.Scope).Union(scopes));
                e.LastUsedAt = now;
                e.ConcurrencyStamp = Guid.NewGuid().ToString();
            }

            try
            {
                await _db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
                EfRetry.Detach(_db, new object[] { e });
                return;
            }
            catch (Exception ex) when (ex is DbUpdateException && attempt < EfRetry.MaxAttempts)
            {
                if (ex is DbUpdateConcurrencyException c) EfRetry.DetachConflicts(_db, c);
                else EfRetry.Detach(_db, new object[] { e });
            }
        }
    }

    public async Task TouchAsync(string userId, string clientId, DateTimeOffset now, CancellationToken cancellationToken = default)
    {
        var e = await Set.FirstOrDefaultAsync(g => g.UserId == userId && g.ClientId == clientId, cancellationToken).ConfigureAwait(false);
        if (e is null) return;
        e.LastUsedAt = now;
        e.ConcurrencyStamp = Guid.NewGuid().ToString();
        try
        {
            await _db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (DbUpdateConcurrencyException ex)
        {
            EfRetry.DetachConflicts(_db, ex);
        }
        EfRetry.Detach(_db, new object[] { e });
    }

    public async Task<IReadOnlyList<OAuthGrant>> ListForUserAsync(string userId, CancellationToken cancellationToken = default)
    {
        var rows = await Set.AsNoTracking().Where(g => g.UserId == userId).ToListAsync(cancellationToken).ConfigureAwait(false);
        return rows.Select(r => r.ToDomain()).OrderByDescending(g => g.LastUsedAt).ToArray();
    }

    public async Task<bool> DeleteAsync(string userId, string clientId, CancellationToken cancellationToken = default)
    {
        var e = await Set.FirstOrDefaultAsync(g => g.UserId == userId && g.ClientId == clientId, cancellationToken).ConfigureAwait(false);
        if (e is null) return false;
        Set.Remove(e);
        try
        {
            await _db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
            return true;
        }
        catch (DbUpdateConcurrencyException ex)
        {
            EfRetry.DetachConflicts(_db, ex);
            return false;
        }
    }
}

public static class OAuthServerEfCoreBuilderExtensions
{
    /// <summary>Replaces all five in-memory stores with the EF Core ones, scoped to <typeparamref name="TContext"/>.</summary>
    public static IOAuthServerBuilder UseEfCoreStores<TContext>(this IOAuthServerBuilder builder) where TContext : DbContext
    {
        if (builder is null) throw new ArgumentNullException(nameof(builder));
        return builder
            .UseClientStore<EfCoreOAuthClientStore<TContext>>()
            .UsePendingRequestStore<EfCoreOAuthPendingRequestStore<TContext>>()
            .UseCodeStore<EfCoreOAuthCodeStore<TContext>>()
            .UseRefreshTokenStore<EfCoreOAuthRefreshTokenStore<TContext>>()
            .UseGrantStore<EfCoreOAuthGrantStore<TContext>>();
    }
}
