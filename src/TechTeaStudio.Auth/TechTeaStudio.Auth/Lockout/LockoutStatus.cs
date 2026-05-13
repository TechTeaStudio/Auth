namespace TechTeaStudio.Auth.Lockout;

/// <summary>Result of a single failed-attempt record. Carries the post-update state.</summary>
public sealed record LoginAttemptResult(bool IsLocked, int FailedAttempts, DateTimeOffset? LockoutEndsAt);

/// <summary>Read-only snapshot of an account's lockout state.</summary>
public sealed record LockoutStatus(bool IsLocked, int FailedAttempts, DateTimeOffset? LockoutEndsAt)
{
    /// <summary>Shorthand for a fresh / never-locked account.</summary>
    public static LockoutStatus Clear { get; } = new(false, 0, null);
}
