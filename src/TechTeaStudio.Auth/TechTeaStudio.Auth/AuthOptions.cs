using System.ComponentModel.DataAnnotations;

namespace TechTeaStudio.Auth;

/// <summary>
/// Strongly-typed configuration for TechTeaStudio.Auth. Bind from
/// <c>IConfiguration.GetSection("Auth")</c> via <c>AddTechTeaStudioAuth(...)</c>.
/// </summary>
public sealed class AuthOptions
{
    /// <summary>
    /// Symmetric signing key (HS256). Must be at least 32 ASCII characters (256 bits).
    /// A short or empty key would let an attacker forge tokens, so the library refuses
    /// to start without one — there is no anonymous fallback.
    /// </summary>
    [Required(AllowEmptyStrings = false, ErrorMessage = "Auth:SecretKey is required.")]
    [MinLength(32, ErrorMessage = "Auth:SecretKey must be at least 32 characters (256 bits) for HS256.")]
    public string SecretKey { get; set; } = string.Empty;

    /// <summary>JWT <c>iss</c> claim. Validated by the bearer handler on every request.</summary>
    [Required(AllowEmptyStrings = false, ErrorMessage = "Auth:Issuer is required.")]
    public string Issuer { get; set; } = string.Empty;

    /// <summary>JWT <c>aud</c> claim. Validated by the bearer handler on every request.</summary>
    [Required(AllowEmptyStrings = false, ErrorMessage = "Auth:Audience is required.")]
    public string Audience { get; set; } = string.Empty;

    /// <summary>
    /// Lifetime for access tokens. Default: 30 minutes — short enough that revocation
    /// via "stop issuing refresh tokens" remains meaningful, long enough that we don't
    /// hammer the refresh endpoint.
    /// </summary>
    public TimeSpan TokenLifetime { get; set; } = TimeSpan.FromMinutes(30);

    /// <summary>
    /// Lifetime for refresh tokens. Default: 7 days. The refresh token is single-use and
    /// rotated on every call, so this is the effective re-login interval for an active user.
    /// </summary>
    public TimeSpan RefreshTokenLifetime { get; set; } = TimeSpan.FromDays(7);

    /// <summary>
    /// Tolerance for clock drift between the issuing server and any validating server.
    /// Default: 5 minutes (matches the System.IdentityModel default).
    /// </summary>
    public TimeSpan ClockSkew { get; set; } = TimeSpan.FromMinutes(5);

    /// <summary>
    /// Failed login attempts within <see cref="LockoutDuration"/> before the account
    /// is locked. Default: 5. Configured here so apps don't re-implement the policy.
    /// </summary>
    [Range(1, int.MaxValue, ErrorMessage = "Auth:MaxFailedLoginAttempts must be at least 1.")]
    public int MaxFailedLoginAttempts { get; set; } = 5;

    /// <summary>
    /// How long an account stays locked once <see cref="MaxFailedLoginAttempts"/> is hit.
    /// Default: 15 minutes.
    /// </summary>
    public TimeSpan LockoutDuration { get; set; } = TimeSpan.FromMinutes(15);

    /// <summary>
    /// When <c>true</c> (default), presenting an already-revoked refresh token
    /// revokes every successor in its rotation chain — i.e. a stolen token used
    /// in parallel with the legitimate user invalidates the whole session.
    /// </summary>
    public bool RevokeChainOnRefreshReuse { get; set; } = true;

    /// <summary>
    /// Interval at which the background <c>RefreshTokenCleanupService</c> deletes
    /// expired refresh-token rows. Default: 1 hour.
    /// </summary>
    public TimeSpan RefreshTokenCleanupInterval { get; set; } = TimeSpan.FromHours(1);
}
