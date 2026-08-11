namespace TechTeaStudio.Auth.Abstractions;

/// <summary>
/// Parses tokens into <see cref="AuthTokenInfo"/> without validating the signature
/// or lifetime. Useful for cheap claim inspection in logging or device-detection
/// middleware. **Never** branch on the result for an authentication decision —
/// use <see cref="ITokenProvider.ValidateToken"/> for that.
/// </summary>
/// <remarks>
/// Not descriptor-aware: it never validates <c>aud</c>/<c>iss</c> against anything, so a
/// token minted with a per-call <see cref="TokenDescriptor"/> audience parses here exactly
/// like any other token. Validating a per-call audience — e.g. an "app-api" audience minted
/// alongside the app-wide "app-web" one — is the consumer's job, via their own JwtBearer
/// scheme configuration; the defaults here and on <see cref="ITokenProvider.ValidateToken"/>
/// both stay pinned to the single app-wide configured audience.
/// </remarks>
public interface ITokenReader
{
    /// <summary>
    /// Attempts to parse <paramref name="token"/>. Returns <c>null</c> on any failure
    /// (malformed, missing claims, unparseable). Never throws.
    /// </summary>
    AuthTokenInfo? TryRead(string token);
}
