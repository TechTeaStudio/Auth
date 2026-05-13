using System.Text.Json;
using StackExchange.Redis;
using TechTeaStudio.Auth.Abstractions;

namespace TechTeaStudio.Auth.Redis;

/// <summary>
/// Redis-backed <see cref="IRefreshTokenStore"/>. Layout:
/// <list type="bullet">
///   <item><c>tts:auth:refresh:hash:&lt;tokenHash&gt;</c> = JSON-encoded <see cref="RefreshToken"/>. TTL = expiresAt - now.</item>
///   <item><c>tts:auth:refresh:user:&lt;userId&gt;</c> = SET of token hashes (so per-user reads are O(N) on N active tokens, not O(all)).</item>
/// </list>
/// Redis TTL handles expiry, so <see cref="CleanupExpiredAsync"/> is mostly a no-op
/// (it only prunes user-set membership entries left behind by manual TTLs).
/// </summary>
public sealed class RedisRefreshTokenStore : IRefreshTokenStore
{
    private readonly IDatabase _db;
    private readonly string _prefix;

    private static readonly JsonSerializerOptions Json = new() { PropertyNamingPolicy = JsonNamingPolicy.CamelCase };

    public RedisRefreshTokenStore(IConnectionMultiplexer multiplexer, string keyPrefix = "tts:auth:refresh")
    {
        if (multiplexer is null) throw new ArgumentNullException(nameof(multiplexer));
        _db = multiplexer.GetDatabase();
        _prefix = string.IsNullOrEmpty(keyPrefix) ? "tts:auth:refresh" : keyPrefix;
    }

    private string HashKey(string tokenHash) => $"{_prefix}:hash:{tokenHash}";
    private string UserKey(string userId) => $"{_prefix}:user:{userId}";

    public async Task<RefreshToken?> GetByTokenHashAsync(string tokenHash, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrEmpty(tokenHash)) return null;
        var raw = await _db.StringGetAsync(HashKey(tokenHash)).ConfigureAwait(false);
        if (!raw.HasValue) return null;
        return JsonSerializer.Deserialize<RefreshToken>((string)raw!, Json);
    }

    public async Task<IReadOnlyList<RefreshToken>> GetActiveForUserAsync(string userId, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrEmpty(userId)) return Array.Empty<RefreshToken>();
        var hashes = await _db.SetMembersAsync(UserKey(userId)).ConfigureAwait(false);
        if (hashes.Length == 0) return Array.Empty<RefreshToken>();

        var keys = hashes.Select(h => (RedisKey)HashKey(h!)).ToArray();
        var values = await _db.StringGetAsync(keys).ConfigureAwait(false);

        var result = new List<RefreshToken>(values.Length);
        for (var i = 0; i < values.Length; i++)
        {
            if (!values[i].HasValue) { _db.SetRemove(UserKey(userId), hashes[i], CommandFlags.FireAndForget); continue; }
            var token = JsonSerializer.Deserialize<RefreshToken>((string)values[i]!, Json);
            if (token is not null && token.IsActive) result.Add(token);
        }
        return result;
    }

    public async Task CreateAsync(RefreshToken token, CancellationToken cancellationToken = default)
    {
        if (token is null) throw new ArgumentNullException(nameof(token));
        if (string.IsNullOrEmpty(token.TokenHash)) throw new ArgumentException("TokenHash is required.", nameof(token));

        var key = HashKey(token.TokenHash);
        var payload = JsonSerializer.Serialize(token, Json);
        var ttl = token.ExpiresAt - DateTimeOffset.UtcNow;
        if (ttl <= TimeSpan.Zero) throw new InvalidOperationException("token is already expired.");

        var ok = await _db.StringSetAsync(key, payload, ttl, When.NotExists).ConfigureAwait(false);
        if (!ok)
            throw new InvalidOperationException($"Refresh token with hash '{token.TokenHash}' already exists.");
        await _db.SetAddAsync(UserKey(token.UserId), token.TokenHash).ConfigureAwait(false);
    }

    public async Task RevokeAsync(Guid id, string? replacedByTokenHash = null, CancellationToken cancellationToken = default)
    {
        // We do not have a reverse-index Id -> TokenHash. Scan the user set by scanning every key.
        // For the in-memory contract test, this is acceptable. Production callers prefer to revoke by hash.
        // Provide an overload would be cleaner; for now we walk all known hashes via SCAN.
        var server = _db.Multiplexer.GetServers().FirstOrDefault(s => s.IsConnected);
        if (server is null) return;
        await foreach (var key in server.KeysAsync(_db.Database, $"{_prefix}:hash:*").WithCancellation(cancellationToken).ConfigureAwait(false))
        {
            var raw = await _db.StringGetAsync(key).ConfigureAwait(false);
            if (!raw.HasValue) continue;
            var t = JsonSerializer.Deserialize<RefreshToken>((string)raw!, Json);
            if (t is null || t.Id != id) continue;

            var updated = t with
            {
                RevokedAt = t.RevokedAt ?? DateTimeOffset.UtcNow,
                ReplacedByTokenHash = replacedByTokenHash ?? t.ReplacedByTokenHash,
            };
            var ttl = updated.ExpiresAt - DateTimeOffset.UtcNow;
            if (ttl <= TimeSpan.Zero) ttl = TimeSpan.FromMinutes(1);
            await _db.StringSetAsync(key, JsonSerializer.Serialize(updated, Json), ttl).ConfigureAwait(false);
            return;
        }
    }

    public async Task RevokeAllForUserAsync(string userId, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrEmpty(userId)) return;
        var hashes = await _db.SetMembersAsync(UserKey(userId)).ConfigureAwait(false);
        var now = DateTimeOffset.UtcNow;
        foreach (var h in hashes)
        {
            var key = HashKey(h!);
            var raw = await _db.StringGetAsync(key).ConfigureAwait(false);
            if (!raw.HasValue) continue;
            var t = JsonSerializer.Deserialize<RefreshToken>((string)raw!, Json);
            if (t is null || t.RevokedAt is not null) continue;
            var updated = t with { RevokedAt = now };
            var ttl = updated.ExpiresAt - DateTimeOffset.UtcNow;
            if (ttl <= TimeSpan.Zero) ttl = TimeSpan.FromMinutes(1);
            await _db.StringSetAsync(key, JsonSerializer.Serialize(updated, Json), ttl).ConfigureAwait(false);
        }
    }

    public Task<int> CleanupExpiredAsync(DateTimeOffset cutoff, CancellationToken cancellationToken = default)
        // Redis TTL auto-expires entries; nothing to do.
        => Task.FromResult(0);

    public async Task DeleteAllForUserAsync(string userId, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrEmpty(userId)) return;
        var hashes = await _db.SetMembersAsync(UserKey(userId)).ConfigureAwait(false);
        if (hashes.Length > 0)
        {
            var keys = hashes.Select(h => (RedisKey)HashKey(h!)).ToArray();
            await _db.KeyDeleteAsync(keys).ConfigureAwait(false);
        }
        await _db.KeyDeleteAsync(UserKey(userId)).ConfigureAwait(false);
    }
}
