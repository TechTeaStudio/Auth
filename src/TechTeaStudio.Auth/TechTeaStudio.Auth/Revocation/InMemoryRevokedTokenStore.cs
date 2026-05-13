using System.Collections.Concurrent;

namespace TechTeaStudio.Auth.Revocation;

/// <summary>
/// Process-local deny-list. Entries naturally fall out via
/// <see cref="CleanupAsync"/>, which is exercised by
/// <see cref="RevokedTokenCleanupService"/> in DI-wired hosts.
/// </summary>
public sealed class InMemoryRevokedTokenStore : IRevokedTokenStore
{
    private readonly ConcurrentDictionary<string, DateTimeOffset> _entries = new(StringComparer.Ordinal);

    public Task<bool> IsRevokedAsync(string jti, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrEmpty(jti)) return Task.FromResult(false);
        if (!_entries.TryGetValue(jti, out var expiresAt)) return Task.FromResult(false);
        if (expiresAt <= DateTimeOffset.UtcNow)
        {
            _entries.TryRemove(jti, out _);
            return Task.FromResult(false);
        }
        return Task.FromResult(true);
    }

    public Task RevokeAsync(string jti, DateTimeOffset expiresAt, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrEmpty(jti)) return Task.CompletedTask;
        _entries[jti] = expiresAt;
        return Task.CompletedTask;
    }

    public Task<int> CleanupAsync(DateTimeOffset cutoff, CancellationToken cancellationToken = default)
    {
        var expired = _entries.Where(kvp => kvp.Value <= cutoff).Select(kvp => kvp.Key).ToList();
        var removed = 0;
        foreach (var jti in expired)
            if (_entries.TryRemove(jti, out _)) removed++;
        return Task.FromResult(removed);
    }
}

/// <summary>
/// Singleton no-op store used when the application has not opted into the deny-list.
/// Keeps <see cref="Jwt.JwtTokenProvider"/> ignorant of whether revocation is wired up.
/// </summary>
public sealed class NullRevokedTokenStore : IRevokedTokenStore
{
    public static NullRevokedTokenStore Instance { get; } = new();
    public Task<bool> IsRevokedAsync(string jti, CancellationToken cancellationToken = default) => Task.FromResult(false);
    public Task RevokeAsync(string jti, DateTimeOffset expiresAt, CancellationToken cancellationToken = default) => Task.CompletedTask;
    public Task<int> CleanupAsync(DateTimeOffset cutoff, CancellationToken cancellationToken = default) => Task.FromResult(0);
}
