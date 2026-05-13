namespace TechTeaStudio.Auth.AspNetCore.RateLimit;

/// <summary>
/// Tunes the <c>tts-auth-login</c> rate-limit policy registered by
/// <see cref="AuthRateLimitExtensions.AddTechTeaStudioRateLimit"/>.
/// </summary>
public sealed class AuthRateLimitOptions
{
    /// <summary>Policy name to apply with <c>[EnableRateLimiting]</c> / <c>.RequireRateLimiting()</c>.</summary>
    public const string PolicyName = "tts-auth-login";

    /// <summary>Maximum number of attempts per <see cref="Window"/>. Default: 5.</summary>
    public int PermitLimit { get; set; } = 5;

    /// <summary>Sliding window over which <see cref="PermitLimit"/> applies. Default: 1 minute.</summary>
    public TimeSpan Window { get; set; } = TimeSpan.FromMinutes(1);

    /// <summary>Number of queued requests once the bucket is empty. Default: 0 — fail fast.</summary>
    public int QueueLimit { get; set; } = 0;
}
