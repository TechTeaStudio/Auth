using System.Collections.Concurrent;
using Microsoft.Extensions.Options;

namespace TechTeaStudio.Auth.Lockout;

/// <summary>
/// <para>
/// ⚠️ <b>NOT FOR PRODUCTION MULTI-INSTANCE DEPLOYMENTS.</b> Failure counters
/// live in process memory and reset on restart, and — worse — a brute-forcer
/// hitting different instances behind a load balancer bypasses lockout entirely.
/// </para>
/// <para>
/// ✅ <b>Safe to use for:</b> dev builds; unit tests; single-instance deployments
/// where one process sees every login attempt.
/// </para>
/// <para>
/// 🛑 <b>Unsafe — DO NOT USE — when:</b> the service runs as more than one
/// instance and traffic is distributed across them. Use the Redis tracker from
/// <c>TechTeaStudio.Auth.Redis</c> instead, wired via
/// <c>services.AddTechTeaStudioAuth(cfg).UseLoginAttemptTracker&lt;RedisLoginAttemptTracker&gt;()</c>.
/// </para>
/// </summary>
public sealed class InMemoryLoginAttemptTracker : ILoginAttemptTracker
{
    private readonly ConcurrentDictionary<string, Entry> _entries = new(StringComparer.Ordinal);
    private readonly AuthOptions _options;

    public InMemoryLoginAttemptTracker(IOptions<AuthOptions> options) =>
        _options = options?.Value ?? throw new ArgumentNullException(nameof(options));

    public Task<LoginAttemptResult> RecordFailureAsync(string userId, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrEmpty(userId)) throw new ArgumentException("userId is required.", nameof(userId));

        var now = DateTimeOffset.UtcNow;
        var updated = _entries.AddOrUpdate(
            userId,
            _ =>
            {
                var locked = _options.Lockout.MaxFailedAttempts <= 1 ? now.Add(_options.Lockout.Duration) : (DateTimeOffset?)null;
                return new Entry(1, locked);
            },
            (_, current) =>
            {
                if (current.LockedUntil > now)
                    return current; // already locked, no further counting
                var newCount = current.Count + 1;
                var locked = newCount >= _options.Lockout.MaxFailedAttempts
                    ? now.Add(_options.Lockout.Duration)
                    : current.LockedUntil;
                return new Entry(newCount, locked);
            });

        var isLocked = updated.LockedUntil > now;
        return Task.FromResult(new LoginAttemptResult(isLocked, updated.Count, updated.LockedUntil));
    }

    public Task RecordSuccessAsync(string userId, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrEmpty(userId)) throw new ArgumentException("userId is required.", nameof(userId));
        _entries.TryRemove(userId, out _);
        return Task.CompletedTask;
    }

    public Task<LockoutStatus> GetStatusAsync(string userId, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrEmpty(userId)) return Task.FromResult(LockoutStatus.Clear);
        if (!_entries.TryGetValue(userId, out var e)) return Task.FromResult(LockoutStatus.Clear);

        var isLocked = e.LockedUntil > DateTimeOffset.UtcNow;
        return Task.FromResult(new LockoutStatus(isLocked, e.Count, e.LockedUntil));
    }

    private readonly record struct Entry(int Count, DateTimeOffset? LockedUntil);
}
