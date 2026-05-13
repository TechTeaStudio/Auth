namespace TechTeaStudio.Auth.Observability;

/// <summary>Strongly-typed audit event records published by <see cref="IAuthAuditLogger"/>.</summary>
public abstract record AuthEvent(DateTimeOffset At)
{
    /// <summary>Stable short string for filtering / metrics.</summary>
    public abstract string Kind { get; }
}

public sealed record LoginSucceededEvent(string UserId, DateTimeOffset At) : AuthEvent(At)
{
    public override string Kind => "login.succeeded";
}

public sealed record LoginFailedEvent(string UserId, string Reason, DateTimeOffset At) : AuthEvent(At)
{
    public override string Kind => "login.failed";
}

public sealed record TokenIssuedEvent(string UserId, string Jti, DateTimeOffset ExpiresAt, DateTimeOffset At) : AuthEvent(At)
{
    public override string Kind => "token.issued";
}

public sealed record TokenRefreshedEvent(string UserId, string OldRefreshHash, string NewRefreshHash, DateTimeOffset At) : AuthEvent(At)
{
    public override string Kind => "token.refreshed";
}

public sealed record TokenRevokedEvent(string Jti, string Reason, DateTimeOffset At) : AuthEvent(At)
{
    public override string Kind => "token.revoked";
}

public sealed record RefreshReuseDetectedEvent(string UserId, string TokenHash, int ChainLength, DateTimeOffset At) : AuthEvent(At)
{
    public override string Kind => "refresh.reuse_detected";
}

public sealed record AccountLockedEvent(string UserId, DateTimeOffset LockoutEndsAt, DateTimeOffset At) : AuthEvent(At)
{
    public override string Kind => "account.locked";
}
