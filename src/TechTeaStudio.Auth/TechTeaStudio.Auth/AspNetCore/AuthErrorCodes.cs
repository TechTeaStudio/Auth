namespace TechTeaStudio.Auth.AspNetCore;

/// <summary>
/// Stable string codes returned in the JSON 401 body. Consumers may switch
/// on these to drive client behaviour (e.g. "token_expired" → silently refresh).
/// The set is append-only — codes are never repurposed.
/// </summary>
public static class AuthErrorCodes
{
    /// <summary>Generic fallback when no specific reason could be determined.</summary>
    public const string Unauthorized = "unauthorized";

    /// <summary>Token signature is valid but lifetime has elapsed.</summary>
    public const string TokenExpired = "token_expired";

    /// <summary>Token signature could not be verified with the configured key.</summary>
    public const string InvalidSignature = "invalid_signature";

    /// <summary>Token <c>iss</c> claim does not match the configured issuer.</summary>
    public const string InvalidIssuer = "invalid_issuer";

    /// <summary>Token <c>aud</c> claim does not match the configured audience.</summary>
    public const string InvalidAudience = "invalid_audience";

    /// <summary>Token is structurally invalid — not a parseable JWT.</summary>
    public const string MalformedToken = "malformed_token";

    /// <summary>Token <c>nbf</c> claim is in the future.</summary>
    public const string TokenNotYetValid = "token_not_yet_valid";

    /// <summary>No <c>Authorization</c> header was supplied.</summary>
    public const string MissingToken = "missing_token";
}
