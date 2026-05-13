using System.Collections.Concurrent;
using TechTeaStudio.Auth.Abstractions;

namespace TechTeaStudio.Auth.RefreshTokens;

/// <summary>
/// <para>
/// ⚠️ <b>NOT FOR PRODUCTION MULTI-INSTANCE DEPLOYMENTS.</b> Default in-memory
/// implementation of <see cref="IRefreshTokenStore"/>. Refresh tokens are held
/// in a <c>ConcurrentDictionary</c> inside this process and lost on restart.
/// </para>
/// <para>
/// ✅ <b>Safe to use for:</b> dev / debug builds; unit and integration tests;
/// CLI tools and single-instance pet projects where forced re-login on deploy
/// is acceptable.
/// </para>
/// <para>
/// 🛑 <b>Unsafe — DO NOT USE — when:</b> the service runs as more than one
/// instance behind a load balancer (refresh issued by instance A is unknown to
/// instance B; chain-revocation kicks in; legitimate users get kicked out);
/// any production deployment where users would notice forced re-login.
/// </para>
/// <para>
/// Production replacements:
/// <list type="bullet">
///   <item><c>TechTeaStudio.Auth.EFCore</c> → <c>EfCoreRefreshTokenStore&lt;TContext&gt;</c> (relational DB)</item>
///   <item><c>TechTeaStudio.Auth.Redis</c> → <c>RedisRefreshTokenStore</c> (distributed cache)</item>
/// </list>
/// Wire either via <c>services.AddTechTeaStudioAuth(cfg).UseRefreshTokenStore&lt;TStore&gt;()</c>.
/// </para>
/// </summary>
public sealed class InMemoryRefreshTokenStore : IRefreshTokenStore
{
    // Keyed by TokenHash. The hash is unique because raw tokens are 48 random bytes.
    private readonly ConcurrentDictionary<string, RefreshToken> _byHash = new(StringComparer.Ordinal);

    public Task<RefreshToken?> GetByTokenHashAsync(string tokenHash, CancellationToken cancellationToken = default)
    {
        _byHash.TryGetValue(tokenHash, out var token);
        return Task.FromResult<RefreshToken?>(token);
    }

    public Task<IReadOnlyList<RefreshToken>> GetActiveForUserAsync(string userId, CancellationToken cancellationToken = default)
    {
        IReadOnlyList<RefreshToken> result = _byHash.Values
            .Where(t => t.UserId == userId && t.IsActive)
            .ToList();
        return Task.FromResult(result);
    }

    public Task CreateAsync(RefreshToken token, CancellationToken cancellationToken = default)
    {
        if (token is null) throw new ArgumentNullException(nameof(token));
        if (string.IsNullOrEmpty(token.TokenHash)) throw new ArgumentException("TokenHash is required.", nameof(token));

        if (!_byHash.TryAdd(token.TokenHash, token))
            throw new InvalidOperationException($"Refresh token with hash '{token.TokenHash}' already exists.");
        return Task.CompletedTask;
    }

    public Task RevokeAsync(Guid id, string? replacedByTokenHash = null, CancellationToken cancellationToken = default)
    {
        var existing = _byHash.Values.FirstOrDefault(t => t.Id == id);
        if (existing is null) return Task.CompletedTask;

        var revoked = existing with
        {
            RevokedAt = existing.RevokedAt ?? DateTimeOffset.UtcNow,
            ReplacedByTokenHash = replacedByTokenHash ?? existing.ReplacedByTokenHash,
        };
        _byHash[existing.TokenHash] = revoked;
        return Task.CompletedTask;
    }

    public Task RevokeAllForUserAsync(string userId, CancellationToken cancellationToken = default)
    {
        foreach (var t in _byHash.Values.Where(t => t.UserId == userId && t.RevokedAt is null).ToList())
        {
            var revoked = t with { RevokedAt = DateTimeOffset.UtcNow };
            _byHash[t.TokenHash] = revoked;
        }
        return Task.CompletedTask;
    }

    public Task<int> CleanupExpiredAsync(DateTimeOffset cutoff, CancellationToken cancellationToken = default)
    {
        var expired = _byHash.Values.Where(t => t.ExpiresAt <= cutoff).ToList();
        var removed = 0;
        foreach (var t in expired)
        {
            if (_byHash.TryRemove(t.TokenHash, out _)) removed++;
        }
        return Task.FromResult(removed);
    }

    public Task DeleteAllForUserAsync(string userId, CancellationToken cancellationToken = default)
    {
        foreach (var t in _byHash.Values.Where(t => t.UserId == userId).ToList())
            _byHash.TryRemove(t.TokenHash, out _);
        return Task.CompletedTask;
    }
}
