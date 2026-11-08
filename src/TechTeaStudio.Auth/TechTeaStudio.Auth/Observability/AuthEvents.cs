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

// OAuth authorization server events (TechTeaStudio.Auth.OAuthServer). None of them carries a token, code or verifier.

public sealed record OAuthAuthorizeRequestedEvent(string ClientId, string Resource, string Scope, DateTimeOffset At) : AuthEvent(At)
{
    public override string Kind => "oauth.authorize.requested";
}

public sealed record OAuthAuthorizeApprovedEvent(string UserId, string ClientId, string Scope, DateTimeOffset At) : AuthEvent(At)
{
    public override string Kind => "oauth.authorize.approved";
}

public sealed record OAuthAuthorizeDeniedEvent(string ClientId, DateTimeOffset At) : AuthEvent(At)
{
    public override string Kind => "oauth.authorize.denied";
}

public sealed record OAuthCodeExchangedEvent(string UserId, string ClientId, DateTimeOffset At) : AuthEvent(At)
{
    public override string Kind => "oauth.code.exchanged";
}

public sealed record OAuthCodeReplayedEvent(string UserId, string ClientId, Guid FamilyId, DateTimeOffset At) : AuthEvent(At)
{
    public override string Kind => "oauth.code.replayed";
}

public sealed record OAuthRefreshRotatedEvent(string UserId, string ClientId, Guid FamilyId, DateTimeOffset At) : AuthEvent(At)
{
    public override string Kind => "oauth.refresh.rotated";
}

public sealed record OAuthRefreshReusedEvent(string UserId, string ClientId, Guid FamilyId, bool WithinGrace, DateTimeOffset At) : AuthEvent(At)
{
    public override string Kind => "oauth.refresh.reused";
}

public sealed record OAuthFamilyBurnedEvent(string UserId, string ClientId, Guid FamilyId, string Reason, DateTimeOffset At) : AuthEvent(At)
{
    public override string Kind => "oauth.family.burned";
}

public sealed record OAuthClientRegisteredEvent(string ClientId, string? ClientName, DateTimeOffset At) : AuthEvent(At)
{
    public override string Kind => "oauth.client.registered";
}

public sealed record OAuthClientMetadataFetchFailedEvent(string ClientIdUrl, string Reason, DateTimeOffset At) : AuthEvent(At)
{
    public override string Kind => "oauth.client.metadata_fetch_failed";
}

public sealed record OAuthGrantRevokedEvent(string UserId, string ClientId, DateTimeOffset At) : AuthEvent(At)
{
    public override string Kind => "oauth.grant.revoked";
}
