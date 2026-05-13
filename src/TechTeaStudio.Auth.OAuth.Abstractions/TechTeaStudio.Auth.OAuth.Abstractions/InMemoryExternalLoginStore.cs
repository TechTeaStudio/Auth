using System.Collections.Concurrent;

namespace TechTeaStudio.Auth.OAuth;

/// <summary>
/// <para>
/// ⚠️ <b>NOT FOR PRODUCTION MULTI-INSTANCE DEPLOYMENTS.</b> Default in-memory
/// store registered by <c>AddTechTeaStudioAuth(...)</c> when no other
/// <see cref="IExternalLoginStore"/> is wired. Links are lost on restart and
/// invisible across instances behind a load balancer.
/// </para>
/// <para>
/// ✅ <b>Safe to use for:</b> dev / debug builds; unit and integration tests;
/// single-instance pet projects.
/// </para>
/// <para>
/// 🛑 <b>Replace in production:</b> the EF Core store from
/// <c>TechTeaStudio.Auth.OAuth.EFCore</c> via
/// <c>builder.UseExternalLoginStore&lt;EfCoreExternalLoginStore&lt;TContext&gt;&gt;()</c>.
/// </para>
/// </summary>
public sealed class InMemoryExternalLoginStore : IExternalLoginStore
{
    // Keyed by (Provider, ProviderUserId) ordinal-case-sensitive tuple.
    private readonly ConcurrentDictionary<(string Provider, string Subject), ExternalLogin> _byProvider = new();

    public Task<ExternalLogin?> FindAsync(string provider, string providerUserId, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrEmpty(provider) || string.IsNullOrEmpty(providerUserId)) return Task.FromResult<ExternalLogin?>(null);
        _byProvider.TryGetValue((provider, providerUserId), out var login);
        return Task.FromResult<ExternalLogin?>(login);
    }

    public Task<IReadOnlyList<ExternalLogin>> GetForUserAsync(string userId, CancellationToken cancellationToken = default)
    {
        IReadOnlyList<ExternalLogin> result = _byProvider.Values
            .Where(l => l.UserId == userId)
            .ToList();
        return Task.FromResult(result);
    }

    public Task CreateAsync(ExternalLogin login, CancellationToken cancellationToken = default)
    {
        if (login is null) throw new ArgumentNullException(nameof(login));
        if (string.IsNullOrEmpty(login.Provider) || string.IsNullOrEmpty(login.ProviderUserId))
            throw new ArgumentException("Provider and ProviderUserId are required.", nameof(login));
        if (!_byProvider.TryAdd((login.Provider, login.ProviderUserId), login))
            throw new InvalidOperationException($"External login for ({login.Provider}, {login.ProviderUserId}) already exists.");
        return Task.CompletedTask;
    }

    public Task DeleteAsync(Guid id, CancellationToken cancellationToken = default)
    {
        var existing = _byProvider.Values.FirstOrDefault(l => l.Id == id);
        if (existing is not null) _byProvider.TryRemove((existing.Provider, existing.ProviderUserId), out _);
        return Task.CompletedTask;
    }

    public Task DeleteAllForUserAsync(string userId, CancellationToken cancellationToken = default)
    {
        foreach (var l in _byProvider.Values.Where(l => l.UserId == userId).ToList())
            _byProvider.TryRemove((l.Provider, l.ProviderUserId), out _);
        return Task.CompletedTask;
    }
}
