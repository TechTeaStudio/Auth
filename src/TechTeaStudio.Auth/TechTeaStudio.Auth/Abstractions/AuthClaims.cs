namespace TechTeaStudio.Auth.Abstractions;

/// <summary>
/// Canonical claim-name constants used across TechTeaStudio.Auth.
/// Values are the standard short names from RFC 7519 (JWT) and the
/// long ASP.NET Identity URIs where they apply.
/// </summary>
public static class AuthClaims
{
    /// <summary>Standard JWT subject claim — opaque user identifier. RFC 7519 §4.1.2.</summary>
    public const string Subject = "sub";

    /// <summary>JWT preferred username claim, written as <c>unique_name</c> by Microsoft handlers.</summary>
    public const string Username = "unique_name";

    /// <summary>User email claim.</summary>
    public const string Email = "email";

    /// <summary>Role claim used by ASP.NET Core role-based authorization.</summary>
    public const string Role = "role";

    /// <summary>JWT ID claim — unique token identifier. RFC 7519 §4.1.7.</summary>
    public const string JwtId = "jti";

    /// <summary>JWT issued-at claim, unix seconds. RFC 7519 §4.1.6.</summary>
    public const string IssuedAt = "iat";

    /// <summary>
    /// Legacy Hyperion claim used as user identifier before the move to the
    /// standard <see cref="Subject"/> claim. Kept for backward-compat token reads only.
    /// </summary>
    [System.Obsolete("Use AuthClaims.Subject for new tokens. LegacyNameId is read-only for backward compatibility with Hyperion tokens issued before TechTeaStudio.Auth.")]
    public const string LegacyNameId = "nameid";
}
