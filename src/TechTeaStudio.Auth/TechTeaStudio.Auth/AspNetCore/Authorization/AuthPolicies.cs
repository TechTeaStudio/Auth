namespace TechTeaStudio.Auth.AspNetCore.Authorization;

/// <summary>
/// Stable policy name constants registered by
/// <see cref="AuthPolicyExtensions.AddTechTeaStudioPolicies"/>. Reference these
/// instead of magic strings in <c>[Authorize(Policy = …)]</c> attributes.
/// </summary>
public static class AuthPolicies
{
    /// <summary>Requires an authenticated identity. Equivalent to no policy at all on <c>[Authorize]</c>, but explicit.</summary>
    public const string Authenticated = "tts.authenticated";

    /// <summary>Requires the <c>sub</c> claim to be present and non-empty.</summary>
    public const string RequireSubject = "tts.require_subject";

    /// <summary>Requires the <c>email</c> claim to be present and non-empty.</summary>
    public const string RequireEmail = "tts.require_email";

    /// <summary>Requires the <c>email_verified</c> claim to equal <c>"true"</c>.</summary>
    public const string EmailVerified = "tts.email_verified";
}
