using System.Collections.Concurrent;

namespace TechTeaStudio.Auth.Observability;

/// <summary>
/// Bounded ring-buffer sink for audit events. Useful in tests and local dev where
/// "show me the last N security events" is more valuable than persisted history.
/// </summary>
public sealed class InMemoryAuthAuditLogger : IAuthAuditLogger
{
    private readonly int _capacity;
    private readonly ConcurrentQueue<AuthEvent> _events = new();

    /// <summary>Creates a logger that keeps at most <paramref name="capacity"/> recent events.</summary>
    public InMemoryAuthAuditLogger(int capacity = 1024)
    {
        if (capacity <= 0) throw new ArgumentOutOfRangeException(nameof(capacity), "capacity must be positive.");
        _capacity = capacity;
    }

    public Task LogAsync(AuthEvent evt, CancellationToken cancellationToken = default)
    {
        if (evt is null) throw new ArgumentNullException(nameof(evt));
        _events.Enqueue(evt);
        while (_events.Count > _capacity && _events.TryDequeue(out _)) { }
        return Task.CompletedTask;
    }

    /// <summary>Snapshot of the buffer in insertion order, most-recent last.</summary>
    public IReadOnlyList<AuthEvent> Snapshot() => _events.ToArray();
}
