using System.Collections.Concurrent;
using TechTeaStudio.Auth.OAuthServer.Abstractions;

namespace TechTeaStudio.Auth.OAuthServer.Stores;

// WARNING: the in-memory stores below lose everything on restart and do not span processes.
// They exist for tests and samples. Production hosts use TechTeaStudio.Auth.OAuthServer.EFCore.

/// <summary>IN-MEMORY, NOT FOR PRODUCTION. See <see cref="IOAuthClientStore"/>.</summary>
public sealed class InMemoryOAuthClientStore : IOAuthClientStore
{
    private readonly ConcurrentDictionary<string, OAuthClient> _clients = new(StringComparer.Ordinal);

    public Task<OAuthClient?> FindAsync(string clientId, CancellationToken cancellationToken = default) =>
        Task.FromResult(_clients.TryGetValue(clientId, out var c) ? c : null);

    public Task SaveAsync(OAuthClient client, CancellationToken cancellationToken = default)
    {
        _clients[client.ClientId] = client;
        return Task.CompletedTask;
    }
}

/// <summary>IN-MEMORY, NOT FOR PRODUCTION. See <see cref="IOAuthPendingRequestStore"/>.</summary>
public sealed class InMemoryOAuthPendingRequestStore : IOAuthPendingRequestStore
{
    private readonly ConcurrentDictionary<string, PendingAuthorization> _items = new(StringComparer.Ordinal);

    public Task SaveAsync(PendingAuthorization request, CancellationToken cancellationToken = default)
    {
        _items[request.Id] = request;
        return Task.CompletedTask;
    }

    public Task<PendingAuthorization?> GetAsync(string id, DateTimeOffset now, CancellationToken cancellationToken = default) =>
        Task.FromResult(_items.TryGetValue(id, out var p) && p.ExpiresAt > now ? p : null);

    public Task<PendingAuthorization?> TakeAsync(string id, DateTimeOffset now, CancellationToken cancellationToken = default)
    {
        if (!_items.TryRemove(id, out var p) || p.ExpiresAt <= now) return Task.FromResult<PendingAuthorization?>(null);
        return Task.FromResult<PendingAuthorization?>(p);
    }

    public Task<int> CleanupExpiredAsync(DateTimeOffset cutoff, CancellationToken cancellationToken = default)
    {
        var n = 0;
        foreach (var kv in _items)
            if (kv.Value.ExpiresAt <= cutoff && _items.TryRemove(kv.Key, out _)) n++;
        return Task.FromResult(n);
    }
}

/// <summary>IN-MEMORY, NOT FOR PRODUCTION. See <see cref="IOAuthCodeStore"/>.</summary>
public sealed class InMemoryOAuthCodeStore : IOAuthCodeStore
{
    private readonly object _gate = new();
    private readonly Dictionary<string, AuthorizationCode> _items = new(StringComparer.Ordinal);

    public Task SaveAsync(AuthorizationCode code, CancellationToken cancellationToken = default)
    {
        lock (_gate) _items[code.CodeHash] = code;
        return Task.CompletedTask;
    }

    public Task<CodeConsumeResult?> TryConsumeAsync(string codeHash, DateTimeOffset now, CancellationToken cancellationToken = default)
    {
        lock (_gate)
        {
            if (!_items.TryGetValue(codeHash, out var code)) return Task.FromResult<CodeConsumeResult?>(null);
            if (code.ConsumedAt is not null) return Task.FromResult<CodeConsumeResult?>(new CodeConsumeResult(code, true));
            var consumed = code with { ConsumedAt = now };
            _items[codeHash] = consumed;
            return Task.FromResult<CodeConsumeResult?>(new CodeConsumeResult(consumed, false));
        }
    }

    public Task<int> CleanupExpiredAsync(DateTimeOffset cutoff, CancellationToken cancellationToken = default)
    {
        lock (_gate)
        {
            var dead = _items.Where(kv => kv.Value.ExpiresAt <= cutoff).Select(kv => kv.Key).ToArray();
            foreach (var k in dead) _items.Remove(k);
            return Task.FromResult(dead.Length);
        }
    }
}

/// <summary>IN-MEMORY, NOT FOR PRODUCTION. See <see cref="IOAuthRefreshTokenStore"/>.</summary>
public sealed class InMemoryOAuthRefreshTokenStore : IOAuthRefreshTokenStore
{
    private readonly object _gate = new();
    private readonly Dictionary<string, OAuthRefreshToken> _byHash = new(StringComparer.Ordinal);

    public Task CreateAsync(OAuthRefreshToken token, CancellationToken cancellationToken = default)
    {
        lock (_gate)
        {
            if (!_byHash.TryAdd(token.TokenHash, token))
                throw new InvalidOperationException("A refresh token with this hash already exists.");
        }
        return Task.CompletedTask;
    }

    public Task<OAuthRefreshToken?> GetByHashAsync(string tokenHash, CancellationToken cancellationToken = default)
    {
        lock (_gate) return Task.FromResult(_byHash.TryGetValue(tokenHash, out var t) ? t : null);
    }

    public Task<bool> TryRotateAsync(Guid id, string replacedByTokenHash, DateTimeOffset now, CancellationToken cancellationToken = default)
    {
        lock (_gate)
        {
            var hit = _byHash.FirstOrDefault(kv => kv.Value.Id == id);
            if (hit.Value is null || hit.Value.RotatedAt is not null || hit.Value.RevokedAt is not null) return Task.FromResult(false);
            _byHash[hit.Key] = hit.Value with { RotatedAt = now, ReplacedByTokenHash = replacedByTokenHash };
            return Task.FromResult(true);
        }
    }

    public Task<int> RevokeFamilyAsync(Guid familyId, DateTimeOffset now, CancellationToken cancellationToken = default) =>
        Task.FromResult(RevokeWhere(t => t.FamilyId == familyId, now));

    public Task<int> RevokeForUserClientAsync(string userId, string clientId, DateTimeOffset now, CancellationToken cancellationToken = default) =>
        Task.FromResult(RevokeWhere(t => t.UserId == userId && t.ClientId == clientId, now));

    private int RevokeWhere(Func<OAuthRefreshToken, bool> match, DateTimeOffset now)
    {
        lock (_gate)
        {
            var keys = _byHash.Where(kv => kv.Value.RevokedAt is null && match(kv.Value)).Select(kv => kv.Key).ToArray();
            foreach (var k in keys) _byHash[k] = _byHash[k] with { RevokedAt = now };
            return keys.Length;
        }
    }

    public Task<int> CleanupExpiredAsync(DateTimeOffset cutoff, CancellationToken cancellationToken = default)
    {
        lock (_gate)
        {
            var dead = _byHash.Where(kv => kv.Value.ExpiresAt <= cutoff).Select(kv => kv.Key).ToArray();
            foreach (var k in dead) _byHash.Remove(k);
            return Task.FromResult(dead.Length);
        }
    }
}

/// <summary>IN-MEMORY, NOT FOR PRODUCTION. See <see cref="IOAuthGrantStore"/>.</summary>
public sealed class InMemoryOAuthGrantStore : IOAuthGrantStore
{
    private readonly object _gate = new();
    private readonly Dictionary<(string, string), OAuthGrant> _items = new();

    public Task<OAuthGrant?> GetAsync(string userId, string clientId, CancellationToken cancellationToken = default)
    {
        lock (_gate) return Task.FromResult(_items.TryGetValue((userId, clientId), out var g) ? g : null);
    }

    public Task UpsertAsync(string userId, string clientId, string? clientName, IReadOnlyCollection<string> scopes, DateTimeOffset now, CancellationToken cancellationToken = default)
    {
        lock (_gate)
        {
            if (_items.TryGetValue((userId, clientId), out var old))
                _items[(userId, clientId)] = old with
                {
                    ClientName = clientName ?? old.ClientName,
                    Scopes = old.Scopes.Union(scopes).ToArray(),
                    LastUsedAt = now,
                };
            else
                _items[(userId, clientId)] = new OAuthGrant
                {
                    UserId = userId, ClientId = clientId, ClientName = clientName,
                    Scopes = scopes.Distinct().ToArray(), FirstGrantedAt = now, LastUsedAt = now,
                };
        }
        return Task.CompletedTask;
    }

    public Task TouchAsync(string userId, string clientId, DateTimeOffset now, CancellationToken cancellationToken = default)
    {
        lock (_gate)
            if (_items.TryGetValue((userId, clientId), out var g)) _items[(userId, clientId)] = g with { LastUsedAt = now };
        return Task.CompletedTask;
    }

    public Task<IReadOnlyList<OAuthGrant>> ListForUserAsync(string userId, CancellationToken cancellationToken = default)
    {
        lock (_gate)
            return Task.FromResult<IReadOnlyList<OAuthGrant>>(
                _items.Values.Where(g => g.UserId == userId).OrderByDescending(g => g.LastUsedAt).ToArray());
    }

    public Task<bool> DeleteAsync(string userId, string clientId, CancellationToken cancellationToken = default)
    {
        lock (_gate) return Task.FromResult(_items.Remove((userId, clientId)));
    }
}
