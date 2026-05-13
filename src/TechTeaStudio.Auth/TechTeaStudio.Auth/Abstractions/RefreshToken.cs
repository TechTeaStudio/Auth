namespace TechTeaStudio.Auth.Abstractions;

/// <summary>
/// Persisted refresh-token record. The raw token string is never stored — only
/// <see cref="TokenHash"/> (SHA-256 of the raw value) lives at rest.
/// </summary>
public sealed record RefreshToken
{
    /// <summary>Surrogate primary key for the persisted row.</summary>
    public Guid Id { get; init; } = Guid.NewGuid();

    /// <summary>User this token was issued to.</summary>
    public string UserId { get; init; } = string.Empty;

    /// <summary>SHA-256 of the raw refresh token, hex-encoded lower-case.</summary>
    public string TokenHash { get; init; } = string.Empty;

    /// <summary>UTC timestamp the token was issued.</summary>
    public DateTimeOffset CreatedAt { get; init; } = DateTimeOffset.UtcNow;

    /// <summary>UTC timestamp after which the token must no longer be accepted.</summary>
    public DateTimeOffset ExpiresAt { get; init; }

    /// <summary>UTC timestamp the token was revoked (manual revocation, rotation, or replay detection).</summary>
    public DateTimeOffset? RevokedAt { get; init; }

    /// <summary>
    /// When the token was rotated, this is the SHA-256 hash of the replacement token.
    /// Used by replay detection to walk the chain and revoke every successor.
    /// </summary>
    public string? ReplacedByTokenHash { get; init; }

    /// <summary>True when the token has not been revoked and has not expired.</summary>
    public bool IsActive => RevokedAt is null && ExpiresAt > DateTimeOffset.UtcNow;
}
