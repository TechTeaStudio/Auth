using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using TechTeaStudio.Auth.Abstractions;

namespace TechTeaStudio.Auth.Jwt;

/// <summary>
/// HS256 implementation of <see cref="ITokenProvider"/>. Reads its signing key,
/// issuer, audience, and clock skew from <see cref="AuthOptions"/> at construction.
/// </summary>
public sealed class JwtTokenProvider : ITokenProvider
{
    private readonly AuthOptions _options;
    private readonly SigningCredentials _credentials;
    private readonly TokenValidationParameters _validationParameters;
    private readonly JwtSecurityTokenHandler _handler;

    public JwtTokenProvider(IOptions<AuthOptions> options)
    {
        if (options is null) throw new ArgumentNullException(nameof(options));
        _options = options.Value ?? throw new ArgumentNullException(nameof(options));

        var keyBytes = Encoding.UTF8.GetBytes(_options.SecretKey);
        if (keyBytes.Length < 32)
            throw new InvalidOperationException("AuthOptions.SecretKey must be at least 32 bytes (256 bits) for HS256.");

        var key = new SymmetricSecurityKey(keyBytes);
        _credentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

        _validationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidIssuer = _options.Issuer,
            ValidateAudience = true,
            ValidAudience = _options.Audience,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = key,
            ClockSkew = _options.ClockSkew,
            NameClaimType = AuthClaims.Username,
            RoleClaimType = AuthClaims.Role,
        };

        _handler = new JwtSecurityTokenHandler { MapInboundClaims = false };
    }

    /// <inheritdoc />
    public string CreateToken(string userId, IEnumerable<Claim> claims, TimeSpan lifetime)
    {
        if (string.IsNullOrEmpty(userId)) throw new ArgumentException("userId is required.", nameof(userId));
        if (claims is null) throw new ArgumentNullException(nameof(claims));
        if (lifetime <= TimeSpan.Zero) throw new ArgumentOutOfRangeException(nameof(lifetime), "lifetime must be positive.");

        var now = DateTime.UtcNow;
        var jti = Guid.NewGuid().ToString("N");
        var iat = DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString();

        var allClaims = new List<Claim>(capacity: 8)
        {
            new(AuthClaims.Subject, userId),
            new(AuthClaims.JwtId, jti),
            new(AuthClaims.IssuedAt, iat, ClaimValueTypes.Integer64),
        };
        foreach (var c in claims)
        {
            if (c is null) continue;
            allClaims.Add(c);
        }

        var descriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(allClaims),
            NotBefore = now,
            IssuedAt = now,
            Expires = now.Add(lifetime),
            Issuer = _options.Issuer,
            Audience = _options.Audience,
            SigningCredentials = _credentials,
        };

        var token = _handler.CreateToken(descriptor);
        return _handler.WriteToken(token);
    }

    /// <inheritdoc />
    public ClaimsPrincipal? ValidateToken(string token)
    {
        if (string.IsNullOrEmpty(token)) return null;
        try
        {
            return _handler.ValidateToken(token, _validationParameters, out _);
        }
        catch
        {
            return null;
        }
    }
}
