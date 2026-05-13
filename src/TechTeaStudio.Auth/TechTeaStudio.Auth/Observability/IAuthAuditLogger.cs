namespace TechTeaStudio.Auth.Observability;

/// <summary>
/// Receives strongly-typed audit events. The default registration is
/// <see cref="NullAuthAuditLogger"/> — callers opt in by replacing the registration
/// (e.g. with a database-backed sink or the in-memory ring buffer).
/// </summary>
public interface IAuthAuditLogger
{
    Task LogAsync(AuthEvent evt, CancellationToken cancellationToken = default);
}

/// <summary>No-op default. Drops every event.</summary>
public sealed class NullAuthAuditLogger : IAuthAuditLogger
{
    public static NullAuthAuditLogger Instance { get; } = new();
    public Task LogAsync(AuthEvent evt, CancellationToken cancellationToken = default) => Task.CompletedTask;
}
