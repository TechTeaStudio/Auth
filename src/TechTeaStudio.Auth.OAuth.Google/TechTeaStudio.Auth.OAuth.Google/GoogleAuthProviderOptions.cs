namespace TechTeaStudio.Auth.OAuth.Google;

/// <summary>
/// Configuration for <see cref="GoogleAuthProvider"/>. Bind from the
/// <c>Auth:Google</c> section or build inline in the DI registration.
/// </summary>
public sealed class GoogleAuthProviderOptions
{
    /// <summary>
    /// OAuth 2.0 client IDs that Google may have signed the inbound ID token for.
    /// Include every client your app uses (web, Android, iOS, desktop) so one
    /// backend serves every platform.
    /// </summary>
    public IList<string> Audiences { get; set; } = new List<string>();

    /// <summary>
    /// When true (default), require <c>email_verified == true</c> in the ID token.
    /// Set to false only if you intentionally accept unverified emails (rare).
    /// </summary>
    public bool RequireEmailVerified { get; set; } = true;

    /// <summary>
    /// Optional clock skew accepted during ID-token validation. Default: 5 min,
    /// matches Google.Apis.Auth's default.
    /// </summary>
    public TimeSpan ClockSkew { get; set; } = TimeSpan.FromMinutes(5);
}
