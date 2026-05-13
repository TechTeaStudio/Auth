using System.ComponentModel.DataAnnotations;
using TechTeaStudio.Auth.Signing;

namespace TechTeaStudio.Auth;

/// <summary>
/// Top-level configuration for TechTeaStudio.Auth. Bind from
/// <c>IConfiguration.GetSection("Auth")</c> via <c>AddTechTeaStudioAuth(...)</c>.
/// </summary>
public sealed class AuthOptions
{
    /// <summary>JWT-related settings (issuer, audience, lifetimes, signing keys).</summary>
    public JwtOptions Jwt { get; set; } = new();

    /// <summary>Refresh-token settings (lifetime, replay behaviour, cleanup interval).</summary>
    public RefreshTokenOptions RefreshTokens { get; set; } = new();

    /// <summary>Account-lockout settings (threshold, duration).</summary>
    public LockoutOptions Lockout { get; set; } = new();
}

/// <summary>JWT issuance + validation settings.</summary>
public sealed class JwtOptions
{
    /// <summary>
    /// Symmetric signing key (HS256) — required only when <see cref="Signing"/>.<see cref="SigningOptions.Keys"/> is empty.
    /// 32+ UTF-8 bytes. Once <c>Signing.Keys</c> is populated, this field can stay empty.
    /// </summary>
    public string SecretKey { get; set; } = string.Empty;

    /// <summary>JWT <c>iss</c> claim. Validated by the bearer handler on every request.</summary>
    [Required(AllowEmptyStrings = false, ErrorMessage = "Auth:Jwt:Issuer is required.")]
    public string Issuer { get; set; } = string.Empty;

    /// <summary>JWT <c>aud</c> claim. Validated by the bearer handler on every request.</summary>
    [Required(AllowEmptyStrings = false, ErrorMessage = "Auth:Jwt:Audience is required.")]
    public string Audience { get; set; } = string.Empty;

    /// <summary>Access-token lifetime. Default: 30 minutes.</summary>
    public TimeSpan TokenLifetime { get; set; } = TimeSpan.FromMinutes(30);

    /// <summary>Tolerance for clock drift between issuing and validating servers. Default: 5 minutes.</summary>
    public TimeSpan ClockSkew { get; set; } = TimeSpan.FromMinutes(5);

    /// <summary>Multi-key signing configuration (rotation, RS256 / ES256, retention window).</summary>
    public SigningOptions Signing { get; set; } = new();
}

/// <summary>Refresh-token settings.</summary>
public sealed class RefreshTokenOptions
{
    /// <summary>Refresh-token lifetime. Default: 7 days — effective re-login interval.</summary>
    public TimeSpan Lifetime { get; set; } = TimeSpan.FromDays(7);

    /// <summary>
    /// When <c>true</c> (default), presenting an already-revoked refresh token revokes
    /// every successor in its rotation chain — a stolen-and-replayed token kills the whole session.
    /// </summary>
    public bool RevokeChainOnReuse { get; set; } = true;

    /// <summary>
    /// Interval at which the background <c>RefreshTokenCleanupService</c> deletes
    /// expired rows. Default: 1 hour.
    /// </summary>
    public TimeSpan CleanupInterval { get; set; } = TimeSpan.FromHours(1);
}

/// <summary>Login-lockout policy.</summary>
public sealed class LockoutOptions
{
    /// <summary>Failed login attempts before the account is locked. Default: 5.</summary>
    [Range(1, int.MaxValue, ErrorMessage = "Auth:Lockout:MaxFailedAttempts must be at least 1.")]
    public int MaxFailedAttempts { get; set; } = 5;

    /// <summary>How long an account stays locked once the threshold is hit. Default: 15 minutes.</summary>
    public TimeSpan Duration { get; set; } = TimeSpan.FromMinutes(15);
}
