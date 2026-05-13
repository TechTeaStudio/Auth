using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using TechTeaStudio.Auth.Abstractions;
using TechTeaStudio.Auth.Signing;

namespace TechTeaStudio.Auth.Jwt;

/// <summary>
/// JWT implementation of <see cref="ITokenProvider"/>. Reads its signing key(s),
/// issuer, audience, and clock skew from <see cref="AuthOptions"/> at construction;
/// re-reads them on every call via <see cref="IOptionsMonitor{TOptions}"/> so a
/// key rotation does not require restart.
/// </summary>
public sealed class JwtTokenProvider : ITokenProvider
{
    private readonly IOptionsMonitor<AuthOptions> _monitor;
    private readonly JwtSecurityTokenHandler _handler = new() { MapInboundClaims = false };

    public JwtTokenProvider(IOptionsMonitor<AuthOptions> monitor)
    {
        _monitor = monitor ?? throw new ArgumentNullException(nameof(monitor));
        // Resolve once at construction to fail fast on a bad signing key (< 32 bytes, bad PEM, ...).
        _ = SigningKeyResolver.BuildSigningCredentials(SigningKeyResolver.ResolveActive(_monitor.CurrentValue));
    }

    /// <summary>
    /// Test / non-DI factory. Wraps a plain <see cref="IOptions{TOptions}"/> in a
    /// snapshot <see cref="IOptionsMonitor{TOptions}"/>. Not used by DI — DI always
    /// supplies the real monitor.
    /// </summary>
    public static JwtTokenProvider ForOptions(IOptions<AuthOptions> options) =>
        new(new StaticOptionsMonitor(options ?? throw new ArgumentNullException(nameof(options))));

    /// <inheritdoc />
    public string CreateToken(string userId, IEnumerable<Claim> claims, TimeSpan lifetime)
    {
        if (string.IsNullOrEmpty(userId)) throw new ArgumentException("userId is required.", nameof(userId));
        if (claims is null) throw new ArgumentNullException(nameof(claims));
        if (lifetime <= TimeSpan.Zero) throw new ArgumentOutOfRangeException(nameof(lifetime), "lifetime must be positive.");

        var options = _monitor.CurrentValue;
        var active = SigningKeyResolver.ResolveActive(options);
        var creds = SigningKeyResolver.BuildSigningCredentials(active);

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
            Issuer = options.Jwt.Issuer,
            Audience = options.Jwt.Audience,
            SigningCredentials = creds,
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
            return _handler.ValidateToken(token, SigningKeyResolver.BuildValidationParameters(_monitor.CurrentValue), out _);
        }
        catch
        {
            return null;
        }
    }

    private sealed class StaticOptionsMonitor : IOptionsMonitor<AuthOptions>
    {
        private readonly IOptions<AuthOptions> _options;
        public StaticOptionsMonitor(IOptions<AuthOptions> options) => _options = options;
        public AuthOptions CurrentValue => _options.Value;
        public AuthOptions Get(string? name) => _options.Value;
        public IDisposable? OnChange(Action<AuthOptions, string?> listener) => null;
    }
}
