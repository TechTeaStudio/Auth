using System.Security.Claims;

namespace TechTeaStudio.Auth.Abstractions;

/// <summary>
/// Issues and validates access tokens.
/// </summary>
public interface ITokenProvider
{
    /// <summary>
    /// Creates a signed access token for <paramref name="userId"/> with the supplied
    /// <paramref name="claims"/>, valid for <paramref name="lifetime"/>.
    /// </summary>
    /// <param name="userId">Opaque user identifier written into the <c>sub</c> claim.</param>
    /// <param name="claims">Additional claims to embed. Must not be <c>null</c>; may be empty.</param>
    /// <param name="lifetime">Time-to-live for the token. Must be positive.</param>
    /// <returns>The serialized token string (compact-form JWT for the built-in provider).</returns>
    string CreateToken(string userId, IEnumerable<Claim> claims, TimeSpan lifetime);

    /// <summary>
    /// Creates a signed access token for <paramref name="userId"/> with the supplied
    /// <paramref name="claims"/>, using <paramref name="descriptor"/> to override the
    /// audience, issuer, lifetime, and/or not-before for this call only. Any <c>null</c>
    /// member of <paramref name="descriptor"/> falls back to the configured <c>AuthOptions</c>
    /// value. The <c>sub</c>/<c>jti</c>/<c>iat</c> claim invariant is identical to
    /// <see cref="CreateToken(string, IEnumerable{Claim}, TimeSpan)"/>.
    /// </summary>
    /// <param name="userId">Opaque user identifier written into the <c>sub</c> claim.</param>
    /// <param name="claims">Additional claims to embed. Must not be <c>null</c>; may be empty.</param>
    /// <param name="descriptor">Per-call overrides. Must not be <c>null</c>.</param>
    /// <returns>The serialized token string (compact-form JWT for the built-in provider).</returns>
    string CreateToken(string userId, IEnumerable<Claim> claims, TokenDescriptor descriptor);

    /// <summary>
    /// Validates the token signature, issuer, audience, and lifetime and returns the
    /// resulting <see cref="ClaimsPrincipal"/>. Returns <c>null</c> on any failure —
    /// callers should not branch on the specific reason.
    /// </summary>
    /// <param name="token">The serialized token to validate.</param>
    /// <returns>The principal when valid; <c>null</c> when invalid, expired, or unparseable.</returns>
    ClaimsPrincipal? ValidateToken(string token);
}
