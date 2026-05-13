namespace TechTeaStudio.Auth.Abstractions;

/// <summary>
/// Parses tokens into <see cref="AuthTokenInfo"/> without validating the signature
/// or lifetime. Useful for cheap claim inspection in logging or device-detection
/// middleware. **Never** branch on the result for an authentication decision —
/// use <see cref="ITokenProvider.ValidateToken"/> for that.
/// </summary>
public interface ITokenReader
{
    /// <summary>
    /// Attempts to parse <paramref name="token"/>. Returns <c>null</c> on any failure
    /// (malformed, missing claims, unparseable). Never throws.
    /// </summary>
    AuthTokenInfo? TryRead(string token);
}
