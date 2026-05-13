using TechTeaStudio.Auth.RefreshTokens;

namespace TechTeaStudio.Auth.OAuth;

/// <summary>
/// Discriminated outcome of an OAuth sign-in attempt. Use <see cref="Status"/>
/// to switch in your controller; the populated companion fields depend on the
/// status (see XML comments below).
/// </summary>
public sealed record ExternalSignInOutcome
{
    /// <summary>Which branch of the flow the orchestrator landed on.</summary>
    public ExternalSignInStatus Status { get; init; }

    /// <summary>Populated when <see cref="Status"/> is <see cref="ExternalSignInStatus.Authenticated"/>.</summary>
    public TokenPair? Tokens { get; init; }

    /// <summary>Populated when <see cref="Status"/> is <see cref="ExternalSignInStatus.RequiresPassword"/> or <see cref="ExternalSignInStatus.RequiresRegistration"/>.</summary>
    public string? ContinuationToken { get; init; }

    /// <summary>Email returned by the provider — populated on RequiresPassword / RequiresRegistration so the UI can prefill it.</summary>
    public string? Email { get; init; }

    /// <summary>Profile fetched from the provider — populated on RequiresRegistration so the UI can suggest a username and show the avatar.</summary>
    public ExternalLoginInfo? Profile { get; init; }

    /// <summary>Populated when <see cref="Status"/> is <see cref="ExternalSignInStatus.Failed"/> — short stable string suitable for switching client-side.</summary>
    public string? Error { get; init; }

    internal static ExternalSignInOutcome Authenticated(TokenPair tokens) =>
        new() { Status = ExternalSignInStatus.Authenticated, Tokens = tokens };

    internal static ExternalSignInOutcome RequiresPassword(string continuationToken, string email) =>
        new() { Status = ExternalSignInStatus.RequiresPassword, ContinuationToken = continuationToken, Email = email };

    internal static ExternalSignInOutcome RequiresRegistration(string continuationToken, ExternalLoginInfo profile) =>
        new() { Status = ExternalSignInStatus.RequiresRegistration, ContinuationToken = continuationToken, Email = profile.Email, Profile = profile };

    internal static ExternalSignInOutcome Failed(string error) =>
        new() { Status = ExternalSignInStatus.Failed, Error = error };
}

/// <summary>Branches of the OAuth sign-in flow. Stable string values are emitted in <see cref="ExternalSignInOutcome.Status"/> serialization.</summary>
public enum ExternalSignInStatus
{
    /// <summary>The external identity is already linked. <see cref="ExternalSignInOutcome.Tokens"/> carries the issued JWT + refresh.</summary>
    Authenticated,

    /// <summary>The provider's email matches an existing password account. The UI should ask for the password and POST to the link endpoint with <see cref="ExternalSignInOutcome.ContinuationToken"/>.</summary>
    RequiresPassword,

    /// <summary>No matching user. The UI should ask the user to pick a username and POST to the registration endpoint with <see cref="ExternalSignInOutcome.ContinuationToken"/>.</summary>
    RequiresRegistration,

    /// <summary>The provider rejected the credential or the orchestrator failed. <see cref="ExternalSignInOutcome.Error"/> carries a short stable string.</summary>
    Failed,
}
