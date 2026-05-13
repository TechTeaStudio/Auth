using Microsoft.Extensions.Options;
using StackExchange.Redis;
using TechTeaStudio.Auth.Lockout;

namespace TechTeaStudio.Auth.Redis;

/// <summary>
/// Redis-backed distributed <see cref="ILoginAttemptTracker"/>. Counter and lockout
/// TTL are managed by Redis itself via <c>INCR</c> + <c>EXPIRE</c>, so the counter
/// auto-resets after <see cref="AuthOptions.LockoutDuration"/>.
/// </summary>
public sealed class RedisLoginAttemptTracker : ILoginAttemptTracker
{
    private const string Script = @"
local count_key = KEYS[1]
local lock_key  = KEYS[2]
local threshold = tonumber(ARGV[1])
local ttl       = tonumber(ARGV[2])

local existing = redis.call('TTL', lock_key)
if existing and existing > 0 then
    return {1, threshold, existing}
end

local count = redis.call('INCR', count_key)
if count == 1 then
    redis.call('EXPIRE', count_key, ttl)
end

if count >= threshold then
    redis.call('SET', lock_key, '1', 'EX', ttl)
    return {1, count, ttl}
end

local remaining = redis.call('TTL', count_key)
return {0, count, remaining}
";

    private readonly IDatabase _db;
    private readonly AuthOptions _options;
    private readonly string _prefix;

    public RedisLoginAttemptTracker(IConnectionMultiplexer multiplexer, IOptions<AuthOptions> options, string keyPrefix = "tts:auth:lockout")
    {
        if (multiplexer is null) throw new ArgumentNullException(nameof(multiplexer));
        _db = multiplexer.GetDatabase();
        _options = options?.Value ?? throw new ArgumentNullException(nameof(options));
        _prefix = string.IsNullOrEmpty(keyPrefix) ? "tts:auth:lockout" : keyPrefix;
    }

    private string CountKey(string userId) => $"{_prefix}:count:{userId}";
    private string LockKey(string userId) => $"{_prefix}:lock:{userId}";

    public async Task<LoginAttemptResult> RecordFailureAsync(string userId, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrEmpty(userId)) throw new ArgumentException("userId is required.", nameof(userId));

        var ttlSeconds = (int)Math.Max(1, _options.LockoutDuration.TotalSeconds);
        var result = (RedisResult[]?)await _db.ScriptEvaluateAsync(
            Script,
            new RedisKey[] { CountKey(userId), LockKey(userId) },
            new RedisValue[] { _options.MaxFailedLoginAttempts, ttlSeconds }).ConfigureAwait(false);

        if (result is null || result.Length < 3) return new LoginAttemptResult(false, 0, null);
        var isLocked = ((int)result[0]!) == 1;
        var count = (int)result[1]!;
        var remaining = (int)result[2]!;
        DateTimeOffset? lockedUntil = isLocked ? DateTimeOffset.UtcNow.AddSeconds(remaining) : null;
        return new LoginAttemptResult(isLocked, count, lockedUntil);
    }

    public async Task RecordSuccessAsync(string userId, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrEmpty(userId)) throw new ArgumentException("userId is required.", nameof(userId));
        await _db.KeyDeleteAsync(new RedisKey[] { CountKey(userId), LockKey(userId) }).ConfigureAwait(false);
    }

    public async Task<LockoutStatus> GetStatusAsync(string userId, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrEmpty(userId)) return LockoutStatus.Clear;
        var lockTtl = await _db.KeyTimeToLiveAsync(LockKey(userId)).ConfigureAwait(false);
        var count = await _db.StringGetAsync(CountKey(userId)).ConfigureAwait(false);
        var countInt = count.HasValue && int.TryParse((string)count!, out var n) ? n : 0;
        DateTimeOffset? lockedUntil = lockTtl is { } ttl && ttl > TimeSpan.Zero
            ? DateTimeOffset.UtcNow.Add(ttl)
            : null;
        return new LockoutStatus(lockedUntil is not null, countInt, lockedUntil);
    }
}
