using Microsoft.EntityFrameworkCore;
using TechTeaStudio.Auth.Abstractions;
#if !NET8_0_OR_GREATER
using Microsoft.EntityFrameworkCore.ChangeTracking;
#endif

namespace TechTeaStudio.Auth.EFCore;

/// <summary>
/// EF Core-backed <see cref="IRefreshTokenStore"/>. The consumer's
/// <c>DbContext</c> must expose a <see cref="DbSet{TEntity}"/> of
/// <see cref="RefreshTokenEntity"/> (the standard pattern: call
/// <c>modelBuilder.AddTechTeaStudioRefreshTokens()</c> in <c>OnModelCreating</c>).
/// </summary>
/// <remarks>
/// On net8.0+ the mutating methods use set-based <c>ExecuteUpdateAsync</c>/
/// <c>ExecuteDeleteAsync</c>, which bypass the change tracker. If a caller holds a
/// <em>tracked</em> (non-<c>AsNoTracking</c>) query result for the same
/// <see cref="RefreshTokenEntity"/> row on the shared scoped <c>DbContext</c> and
/// later calls <c>SaveChangesAsync</c>, EF may raise a
/// <c>DbUpdateConcurrencyException</c> (a safe, loud failure — never silent
/// corruption). Query refresh-token rows with <c>AsNoTracking</c> outside this store.
/// </remarks>
public class EfCoreRefreshTokenStore<TContext> : IRefreshTokenStore
    where TContext : DbContext
{
#if !NET8_0_OR_GREATER
    private const int MaxConcurrencyRetries = 3;
#endif

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

    /// <remarks>
    /// Add + <c>SaveChangesAsync</c> — a single INSERT of a fresh entity has no
    /// concurrent-update hazard. Note that, like every other write on this store,
    /// it flushes the consumer's <typeparamref name="TContext"/> in full; do not
    /// share a long-lived <typeparamref name="TContext"/> across requests (see
    /// <see cref="RefreshTokens.RefreshTokenService"/> DI lifetime notes).
    /// </remarks>
    public async Task CreateAsync(RefreshToken token, CancellationToken cancellationToken = default)
    {
        if (token is null) throw new ArgumentNullException(nameof(token));

        if (await _set.AnyAsync(t => t.TokenHash == token.TokenHash, cancellationToken).ConfigureAwait(false))
            throw new InvalidOperationException($"Refresh token with hash '{token.TokenHash}' already exists.");

        _set.Add(RefreshTokenEntity.FromDomain(token));
        await _db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
    }

#if NET8_0_OR_GREATER
    /// <remarks>
    /// Set-based <c>ExecuteUpdateAsync</c> — bypasses the change tracker entirely,
    /// so a stale/concurrently-modified <c>ConcurrencyStamp</c> on this
    /// <typeparamref name="TContext"/> can never cause a spurious
    /// <see cref="DbUpdateConcurrencyException"/>. Zero rows matched (unknown id,
    /// already revoked, or already deleted) is treated as success — revocation is
    /// idempotent by contract. The rows-affected count from the WHERE-guarded
    /// UPDATE is itself the compare-and-swap result: it can only be nonzero for
    /// the one caller whose UPDATE actually observed <c>RevokedAt IS NULL</c>.
    /// </remarks>
    public async Task<bool> RevokeAsync(Guid id, string? replacedByTokenHash = null, CancellationToken cancellationToken = default)
    {
        var now = DateTimeOffset.UtcNow;
        var stamp = Guid.NewGuid().ToString();

        var affected = replacedByTokenHash is null
            ? await _set.Where(t => t.Id == id && t.RevokedAt == null)
                .ExecuteUpdateAsync(s => s
                    .SetProperty(t => t.RevokedAt, now)
                    .SetProperty(t => t.ConcurrencyStamp, stamp), cancellationToken)
                .ConfigureAwait(false)
            : await _set.Where(t => t.Id == id && t.RevokedAt == null)
                .ExecuteUpdateAsync(s => s
                    .SetProperty(t => t.RevokedAt, now)
                    .SetProperty(t => t.ReplacedByTokenHash, replacedByTokenHash)
                    .SetProperty(t => t.ConcurrencyStamp, stamp), cancellationToken)
                .ConfigureAwait(false);

        // Chain bookkeeping: the row was already revoked (0 rows matched above)
        // but a successor hash was supplied — record it ONLY when the successor
        // slot is still empty. The `ReplacedByTokenHash == null` guard is critical:
        // in a RotateAsync race the losing caller reaches this branch AFTER the
        // winner has already stamped its own (persisted) successor, and its own
        // `replacedByTokenHash` is a phantom that is never issued (a CAS loser
        // returns null without CreateAsync). Overwriting here would point the
        // revoked row at a non-existent token and break RevokeChainOnReuse.
        // Idempotent no-op when the id does not exist. Never an active→revoked
        // transition, so the CAS result stays false below.
        if (affected == 0 && replacedByTokenHash is not null)
        {
            await _set.Where(t => t.Id == id && t.ReplacedByTokenHash == null)
                .ExecuteUpdateAsync(s => s.SetProperty(t => t.ReplacedByTokenHash, replacedByTokenHash), cancellationToken)
                .ConfigureAwait(false);
        }

        return affected > 0;
    }

    /// <remarks>Set-based <c>ExecuteUpdateAsync</c> — see <see cref="RevokeAsync"/>.</remarks>
    public async Task RevokeAllForUserAsync(string userId, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrEmpty(userId)) return;
        var now = DateTimeOffset.UtcNow;
        var stamp = Guid.NewGuid().ToString();

        await _set.Where(t => t.UserId == userId && t.RevokedAt == null)
            .ExecuteUpdateAsync(s => s
                .SetProperty(t => t.RevokedAt, now)
                .SetProperty(t => t.ConcurrencyStamp, stamp), cancellationToken)
            .ConfigureAwait(false);
    }

    /// <remarks>Set-based <c>ExecuteDeleteAsync</c> — see <see cref="RevokeAsync"/>.</remarks>
    public async Task<int> CleanupExpiredAsync(DateTimeOffset cutoff, CancellationToken cancellationToken = default) =>
        await _set.Where(t => t.ExpiresAt <= cutoff)
            .ExecuteDeleteAsync(cancellationToken)
            .ConfigureAwait(false);

    /// <remarks>Set-based <c>ExecuteDeleteAsync</c> — see <see cref="RevokeAsync"/>.</remarks>
    public async Task DeleteAllForUserAsync(string userId, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrEmpty(userId)) return;
        await _set.Where(t => t.UserId == userId)
            .ExecuteDeleteAsync(cancellationToken)
            .ConfigureAwait(false);
    }
#else
    /// <remarks>
    /// net6.0 has no <c>ExecuteUpdateAsync</c> (EF Core 7+ only), so this falls
    /// back to load-then-save with bounded concurrency-conflict retry: on
    /// <see cref="DbUpdateConcurrencyException"/> the row is reloaded from the
    /// database and the save is retried against the current values. A row that
    /// no longer exists is treated as already revoked — idempotent success. The
    /// compare-and-swap result is captured from the row's <c>RevokedAt</c> at
    /// the moment it was first loaded: <c>true</c> only when that load observed
    /// an active row AND our save subsequently landed as the one that revoked it.
    /// </remarks>
    public async Task<bool> RevokeAsync(Guid id, string? replacedByTokenHash = null, CancellationToken cancellationToken = default)
    {
        var e = await _set.FirstOrDefaultAsync(t => t.Id == id, cancellationToken).ConfigureAwait(false);
        if (e is null) return false;

        var wasActive = e.RevokedAt is null;

        for (var attempt = 0; ; attempt++)
        {
            if (e.RevokedAt is null) e.RevokedAt = DateTimeOffset.UtcNow;
            // Only fill an empty successor slot — never clobber a winner's persisted
            // hash with a losing racer's phantom (see the net8 backfill guard above).
            if (replacedByTokenHash is not null && e.ReplacedByTokenHash is null) e.ReplacedByTokenHash = replacedByTokenHash;
            e.ConcurrencyStamp = Guid.NewGuid().ToString();

            try
            {
                await _db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
                return wasActive;
            }
            catch (DbUpdateConcurrencyException ex) when (attempt < MaxConcurrencyRetries)
            {
                var entry = ex.Entries.Single();
                var dbValues = await entry.GetDatabaseValuesAsync(cancellationToken).ConfigureAwait(false);
                if (dbValues is null)
                {
                    entry.State = EntityState.Detached;
                    return false; // deleted concurrently — nothing left to revoke.
                }

                var dbRevokedAt = dbValues.GetValue<DateTimeOffset?>(nameof(RefreshTokenEntity.RevokedAt));
                if (dbRevokedAt is not null)
                {
                    // Already revoked by a concurrent writer — idempotent success,
                    // but not OUR transition, so the CAS result is false.
                    // We accept the rare miss of not re-attempting a supplied
                    // replacedByTokenHash here; the winning writer's own chain
                    // bookkeeping already reflects a valid rotation state.
                    entry.State = EntityState.Detached;
                    return false;
                }

                entry.OriginalValues.SetValues(dbValues);
            }
        }
    }

    /// <remarks>Load-then-save with bounded concurrency-conflict retry — see <see cref="RevokeAsync"/>.</remarks>
    public async Task RevokeAllForUserAsync(string userId, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrEmpty(userId)) return;

        for (var attempt = 0; ; attempt++)
        {
            var active = await _set.Where(t => t.UserId == userId && t.RevokedAt == null).ToListAsync(cancellationToken).ConfigureAwait(false);
            if (active.Count == 0) return;

            var now = DateTimeOffset.UtcNow;
            foreach (var e in active)
            {
                e.RevokedAt = now;
                e.ConcurrencyStamp = Guid.NewGuid().ToString();
            }

            try
            {
                await _db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
                return;
            }
            catch (DbUpdateConcurrencyException ex) when (attempt < MaxConcurrencyRetries)
            {
                await ReconcileConflictsAsync(ex, cancellationToken).ConfigureAwait(false);
            }
        }
    }

    /// <remarks>Load-then-save with bounded concurrency-conflict retry — see <see cref="RevokeAsync"/>.</remarks>
    public async Task<int> CleanupExpiredAsync(DateTimeOffset cutoff, CancellationToken cancellationToken = default)
    {
        for (var attempt = 0; ; attempt++)
        {
            var expired = await _set.Where(t => t.ExpiresAt <= cutoff).ToListAsync(cancellationToken).ConfigureAwait(false);
            if (expired.Count == 0) return 0;
            _set.RemoveRange(expired);

            try
            {
                await _db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
                return expired.Count;
            }
            catch (DbUpdateConcurrencyException ex) when (attempt < MaxConcurrencyRetries)
            {
                await ReconcileConflictsAsync(ex, cancellationToken).ConfigureAwait(false);
            }
        }
    }

    /// <remarks>Load-then-save with bounded concurrency-conflict retry — see <see cref="RevokeAsync"/>.</remarks>
    public async Task DeleteAllForUserAsync(string userId, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrEmpty(userId)) return;

        for (var attempt = 0; ; attempt++)
        {
            var rows = await _set.Where(t => t.UserId == userId).ToListAsync(cancellationToken).ConfigureAwait(false);
            if (rows.Count == 0) return;
            _set.RemoveRange(rows);

            try
            {
                await _db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
                return;
            }
            catch (DbUpdateConcurrencyException ex) when (attempt < MaxConcurrencyRetries)
            {
                await ReconcileConflictsAsync(ex, cancellationToken).ConfigureAwait(false);
            }
        }
    }

    /// <summary>
    /// Reconciles every conflicting entry from a batch <see cref="DbUpdateConcurrencyException"/>:
    /// rows deleted by another writer are detached (goal already achieved — removal/no-op),
    /// rows still present get their tracked <c>OriginalValues</c> refreshed so the next
    /// <c>SaveChangesAsync</c> retry's optimistic-concurrency check compares against
    /// the row's current database state.
    /// </summary>
    private static async Task ReconcileConflictsAsync(DbUpdateConcurrencyException ex, CancellationToken cancellationToken)
    {
        foreach (var entry in ex.Entries)
        {
            var dbValues = await entry.GetDatabaseValuesAsync(cancellationToken).ConfigureAwait(false);
            if (dbValues is null)
            {
                entry.State = EntityState.Detached;
                continue;
            }
            entry.OriginalValues.SetValues(dbValues);
        }
    }
#endif
}
