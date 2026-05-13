using System.Collections.Concurrent;
using Microsoft.Extensions.Options;

namespace TechTeaStudio.Auth.Lockout;

/// <summary>
/// Single-instance, in-memory <see cref="ILoginAttemptTracker"/>. Resets on process
/// restart. For multi-instance deployments use a distributed implementation
/// (Redis is on the roadmap).
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
                var locked = _options.MaxFailedLoginAttempts <= 1 ? now.Add(_options.LockoutDuration) : (DateTimeOffset?)null;
                return new Entry(1, locked);
            },
            (_, current) =>
            {
                if (current.LockedUntil > now)
                    return current; // already locked, no further counting
                var newCount = current.Count + 1;
                var locked = newCount >= _options.MaxFailedLoginAttempts
                    ? now.Add(_options.LockoutDuration)
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
