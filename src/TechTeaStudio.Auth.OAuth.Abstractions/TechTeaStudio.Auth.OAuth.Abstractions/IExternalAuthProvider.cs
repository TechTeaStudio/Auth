namespace TechTeaStudio.Auth.OAuth;

/// <summary>
/// Validates a raw provider-issued credential (Google ID token, GitHub access token,
/// Apple ID token, SAML assertion, …) and normalizes the result into <see cref="ExternalLoginInfo"/>.
/// Concrete implementations live in sibling packages such as
/// <c>TechTeaStudio.Auth.OAuth.Google</c>.
/// </summary>
public interface IExternalAuthProvider
{
    /// <summary>
    /// Stable identifier used in <c>POST /api/auth/oauth/{provider}</c> routing and
    /// stored as <see cref="ExternalLogin.Provider"/>. Match-by-case-ordinal.
    /// </summary>
    string Name { get; }

    /// <summary>
    /// Validates the raw credential. Returns <c>null</c> when the credential is
    /// invalid (bad signature, expired, revoked at provider, network error, …).
    /// Implementations must never throw — every error is normalized to <c>null</c>.
    /// </summary>
    Task<ExternalLoginInfo?> ValidateAsync(string rawCredential, CancellationToken cancellationToken = default);
}
