namespace TechTeaStudio.Auth.Lockout;

/// <summary>
/// Tracks failed login attempts per user and locks accounts when the configured
/// threshold is hit. Implementations may be in-memory (single-instance) or distributed.
/// </summary>
public interface ILoginAttemptTracker
{
    /// <summary>Records a failed login and returns the post-update state.</summary>
    Task<LoginAttemptResult> RecordFailureAsync(string userId, CancellationToken cancellationToken = default);

    /// <summary>Clears the failure counter for <paramref name="userId"/> after a successful login.</summary>
    Task RecordSuccessAsync(string userId, CancellationToken cancellationToken = default);

    /// <summary>Returns the current lockout state for <paramref name="userId"/>.</summary>
    Task<LockoutStatus> GetStatusAsync(string userId, CancellationToken cancellationToken = default);
}
