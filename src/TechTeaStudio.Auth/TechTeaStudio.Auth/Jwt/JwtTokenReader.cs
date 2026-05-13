using System.IdentityModel.Tokens.Jwt;
using TechTeaStudio.Auth.Abstractions;

namespace TechTeaStudio.Auth.Jwt;

/// <summary>
/// Parses JWTs without validating signature, issuer, audience, or lifetime.
/// Use only for cheap inspection (logging, claims preview) — never for auth decisions.
/// </summary>
public sealed class JwtTokenReader : ITokenReader
{
    private readonly JwtSecurityTokenHandler _handler = new() { MapInboundClaims = false };

    /// <inheritdoc />
    public AuthTokenInfo? TryRead(string token)
    {
        if (string.IsNullOrEmpty(token)) return null;
        if (!_handler.CanReadToken(token)) return null;

        JwtSecurityToken jwt;
        try
        {
            jwt = _handler.ReadJwtToken(token);
        }
        catch
        {
            return null;
        }

        var roles = jwt.Claims
            .Where(c => c.Type == AuthClaims.Role)
            .Select(c => c.Value)
            .ToArray();

        return new AuthTokenInfo
        {
#pragma warning disable CS0618
            UserId   = FindClaim(jwt, AuthClaims.Subject)
                    ?? FindClaim(jwt, AuthClaims.LegacyNameId)
                    ?? string.Empty,
#pragma warning restore CS0618
            Username = FindClaim(jwt, AuthClaims.Username) ?? string.Empty,
            Email    = FindClaim(jwt, AuthClaims.Email) ?? string.Empty,
            Roles    = roles,
            ExpiresAt = jwt.ValidTo == default ? default : new DateTimeOffset(jwt.ValidTo, TimeSpan.Zero),
            IssuedAt  = jwt.IssuedAt == default ? default : new DateTimeOffset(jwt.IssuedAt, TimeSpan.Zero),
        };
    }

    private static string? FindClaim(JwtSecurityToken jwt, string type) =>
        jwt.Claims.FirstOrDefault(c => c.Type == type)?.Value;
}
