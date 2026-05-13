namespace TechTeaStudio.Auth.Abstractions;

/// <summary>
/// Immutable, framework-free view of the claims carried by a JWT.
/// Returned by <see cref="ITokenReader.TryRead"/>; does not imply the token was validated.
/// </summary>
public sealed record AuthTokenInfo
{
    /// <summary>User identifier (the <c>sub</c> claim).</summary>
    public string UserId { get; init; } = string.Empty;

    /// <summary>User display name (the <c>unique_name</c> claim).</summary>
    public string Username { get; init; } = string.Empty;

    /// <summary>User email (the <c>email</c> claim).</summary>
    public string Email { get; init; } = string.Empty;

    /// <summary>Role names extracted from the token.</summary>
    public IReadOnlyList<string> Roles { get; init; } = Array.Empty<string>();

    /// <summary>Token expiry, taken from the <c>exp</c> claim.</summary>
    public DateTimeOffset ExpiresAt { get; init; }

    /// <summary>Token issuance time, taken from the <c>iat</c> claim.</summary>
    public DateTimeOffset IssuedAt { get; init; }

    /// <summary>
    /// True when <see cref="ExpiresAt"/> is in the past relative to <see cref="DateTimeOffset.UtcNow"/>.
    /// Computed property — not a stored value.
    /// </summary>
    public bool IsExpired => ExpiresAt <= DateTimeOffset.UtcNow;
}
