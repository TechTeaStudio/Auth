namespace TechTeaStudio.Auth.OAuth;

/// <summary>
/// Minimal projection of a consumer's user record needed by
/// <see cref="ExternalLoginService"/>. The OAuth library deliberately knows
/// nothing else about the user's domain — bridge this to your repository via
/// <see cref="IExternalUserBridge"/>.
/// </summary>
public sealed record ExternalUserSnapshot
{
    /// <summary>Consumer-side user identifier in string form (becomes the <c>sub</c> claim).</summary>
    public string UserId { get; init; } = string.Empty;

    /// <summary>Primary email. May be empty when an account never had one (rare).</summary>
    public string Email { get; init; } = string.Empty;

    /// <summary>Optional display name / username.</summary>
    public string? Username { get; init; }

    /// <summary>Stored password hash, if any. <c>null</c> means OAuth-only account (no password set).</summary>
    public string? PasswordHash { get; init; }

    /// <summary>Role names — used by the orchestrator to build claims for the access token.</summary>
    public IReadOnlyList<string> Roles { get; init; } = Array.Empty<string>();
}
