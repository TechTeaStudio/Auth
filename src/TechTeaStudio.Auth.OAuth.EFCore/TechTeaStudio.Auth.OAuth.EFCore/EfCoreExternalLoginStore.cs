using Microsoft.EntityFrameworkCore;
using TechTeaStudio.Auth.OAuth;

namespace TechTeaStudio.Auth.OAuth.EFCore;

/// <summary>
/// EF Core-backed <see cref="IExternalLoginStore"/>. The consumer's <c>DbContext</c>
/// must expose a <see cref="DbSet{T}"/> of <see cref="ExternalLoginEntity"/>
/// (call <c>modelBuilder.AddTechTeaStudioExternalLogins()</c> in <c>OnModelCreating</c>).
///
/// <para>Two ways in. Pass a <typeparamref name="TContext"/> and the store shares the caller's
/// context and change tracker, the classic scoped-DbContext shape. Pass an
/// <see cref="IDbContextFactory{TContext}"/> (0.11.0) and every operation opens and disposes its
/// own context instead. The second overload exists because Blazor Server apps register ONLY a
/// factory: a component's lifecycle methods run concurrently on one circuit, so a shared scoped
/// context is a data race. It also keeps <c>SaveChangesAsync</c> here from flushing whatever
/// unrelated entities the caller happened to be tracking.</para>
///
/// <para><b>Registering it.</b> <c>AddDbContextFactory</c> puts BOTH a factory and a scoped
/// <typeparamref name="TContext"/> in the container. With only the two single-argument
/// constructors that made the type unresolvable ("The following constructors are ambiguous"),
/// which would break every host that already registers the store by type. The two-argument
/// constructor settles it: the container prefers it when both services are present, and it
/// keeps the pre-0.11 behaviour of sharing the scoped context. So
/// <c>UseExternalLoginStore&lt;EfCoreExternalLoginStore&lt;AppDbContext&gt;&gt;()</c> resolves in every
/// combination. To get per-operation contexts in such a host, name the factory constructor:
/// <code>
/// authBuilder.UseExternalLoginStore(sp =&gt; new EfCoreExternalLoginStore&lt;AppDbContext&gt;(
///     sp.GetRequiredService&lt;IDbContextFactory&lt;AppDbContext&gt;&gt;()), ServiceLifetime.Scoped);
/// </code></para>
/// </summary>
public class EfCoreExternalLoginStore<TContext> : IExternalLoginStore
    where TContext : DbContext
{
    private readonly TContext? _db;
    private readonly IDbContextFactory<TContext>? _factory;

    public EfCoreExternalLoginStore(TContext db)
    {
        _db = db ?? throw new ArgumentNullException(nameof(db));
    }

    public EfCoreExternalLoginStore(IDbContextFactory<TContext> factory)
    {
        _factory = factory ?? throw new ArgumentNullException(nameof(factory));
    }

    /// <summary>Tie-breaker for dependency injection, not meant to be called by hand. When a
    /// container holds both a scoped <typeparamref name="TContext"/> and its factory, this is the
    /// one constructor whose parameters cover the other two, so the container picks it instead of
    /// refusing to choose. It behaves exactly like the context-only constructor: the scoped
    /// context is used and the factory is ignored, which is what such a host got before the
    /// factory constructor existed.</summary>
    public EfCoreExternalLoginStore(TContext db, IDbContextFactory<TContext> factory)
        : this(db)
    {
        if (factory is null) throw new ArgumentNullException(nameof(factory));
    }

    /// <summary>The context for one operation, plus whether this store owns (and must dispose)
    /// it. Injected-context mode never disposes: the DI scope that handed it over owns it.</summary>
    private async Task<(TContext Db, bool Owned)> LeaseAsync(CancellationToken cancellationToken)
    {
        if (_db is not null) return (_db, false);
        var created = await _factory!.CreateDbContextAsync(cancellationToken).ConfigureAwait(false);
        return (created, true);
    }

    private static async Task ReleaseAsync(TContext db, bool owned)
    {
        if (owned) await db.DisposeAsync().ConfigureAwait(false);
    }

    public async Task<ExternalLogin?> FindAsync(string provider, string providerUserId, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrEmpty(provider) || string.IsNullOrEmpty(providerUserId)) return null;

        var (db, owned) = await LeaseAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var e = await db.Set<ExternalLoginEntity>().AsNoTracking()
                .FirstOrDefaultAsync(x => x.Provider == provider && x.ProviderUserId == providerUserId, cancellationToken)
                .ConfigureAwait(false);
            return e?.ToDomain();
        }
        finally { await ReleaseAsync(db, owned).ConfigureAwait(false); }
    }

    public async Task<IReadOnlyList<ExternalLogin>> GetForUserAsync(string userId, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrEmpty(userId)) return Array.Empty<ExternalLogin>();

        var (db, owned) = await LeaseAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var rows = await db.Set<ExternalLoginEntity>().AsNoTracking()
                .Where(e => e.UserId == userId)
                .ToListAsync(cancellationToken).ConfigureAwait(false);
            return rows.Select(r => r.ToDomain()).ToArray();
        }
        finally { await ReleaseAsync(db, owned).ConfigureAwait(false); }
    }

    public async Task CreateAsync(ExternalLogin login, CancellationToken cancellationToken = default)
    {
        if (login is null) throw new ArgumentNullException(nameof(login));

        var (db, owned) = await LeaseAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var set = db.Set<ExternalLoginEntity>();
            var dup = await set.AnyAsync(
                x => x.Provider == login.Provider && x.ProviderUserId == login.ProviderUserId,
                cancellationToken).ConfigureAwait(false);
            if (dup) throw new InvalidOperationException(
                $"External login for ({login.Provider}, {login.ProviderUserId}) already exists.");

            set.Add(ExternalLoginEntity.FromDomain(login));
            await db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
        }
        finally { await ReleaseAsync(db, owned).ConfigureAwait(false); }
    }

    public async Task DeleteAsync(Guid id, CancellationToken cancellationToken = default)
    {
        var (db, owned) = await LeaseAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var set = db.Set<ExternalLoginEntity>();
            var e = await set.FirstOrDefaultAsync(x => x.Id == id, cancellationToken).ConfigureAwait(false);
            if (e is null) return;
            set.Remove(e);
            await db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
        }
        finally { await ReleaseAsync(db, owned).ConfigureAwait(false); }
    }

    public async Task DeleteAllForUserAsync(string userId, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrEmpty(userId)) return;

        var (db, owned) = await LeaseAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var set = db.Set<ExternalLoginEntity>();
            var rows = await set.Where(e => e.UserId == userId).ToListAsync(cancellationToken).ConfigureAwait(false);
            if (rows.Count == 0) return;
            set.RemoveRange(rows);
            await db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
        }
        finally { await ReleaseAsync(db, owned).ConfigureAwait(false); }
    }
}
