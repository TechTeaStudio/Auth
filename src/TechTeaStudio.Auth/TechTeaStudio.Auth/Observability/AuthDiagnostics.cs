using System.Diagnostics;
using System.Diagnostics.Metrics;

namespace TechTeaStudio.Auth.Observability;

/// <summary>
/// Single static <see cref="System.Diagnostics.ActivitySource"/> and
/// <see cref="System.Diagnostics.Metrics.Meter"/> the library uses to publish
/// telemetry. No hard dependency on OpenTelemetry — any OTel listener configured
/// on the application picks up <c>TechTeaStudio.Auth</c> traces and metrics by name.
/// </summary>
public static class AuthDiagnostics
{
    /// <summary>Source name shared by traces and metrics. Stable contract.</summary>
    public const string SourceName = "TechTeaStudio.Auth";

    /// <summary>ActivitySource for tracing login / refresh / verify spans.</summary>
    public static readonly ActivitySource ActivitySource = new(SourceName);

    /// <summary>Meter for counters / histograms. Stable instrument names below.</summary>
    public static readonly Meter Meter = new(SourceName);

    /// <summary>Successful logins (snake_case_total for Prometheus exporter.)</summary>
    public static readonly Counter<long> LoginSucceededTotal = Meter.CreateCounter<long>(
        "tts_auth_login_succeeded_total",
        unit: null,
        description: "Total number of successful logins.");

    /// <summary>Failed logins, tagged with a "reason" label.</summary>
    public static readonly Counter<long> LoginFailedTotal = Meter.CreateCounter<long>(
        "tts_auth_login_failed_total",
        unit: null,
        description: "Total number of failed logins.");

    /// <summary>Access tokens issued.</summary>
    public static readonly Counter<long> TokensIssuedTotal = Meter.CreateCounter<long>(
        "tts_auth_tokens_issued_total",
        unit: null,
        description: "Total number of access tokens issued.");

    /// <summary>Refresh tokens rotated successfully.</summary>
    public static readonly Counter<long> RefreshTokensRotatedTotal = Meter.CreateCounter<long>(
        "tts_auth_refresh_rotated_total",
        unit: null,
        description: "Total number of successful refresh-token rotations.");

    /// <summary>Refresh-token replays caught.</summary>
    public static readonly Counter<long> RefreshReuseDetectedTotal = Meter.CreateCounter<long>(
        "tts_auth_refresh_reuse_total",
        unit: null,
        description: "Total number of refresh-token reuse / replay attempts detected.");

    /// <summary>Accounts that hit the lockout threshold.</summary>
    public static readonly Counter<long> AccountsLockedTotal = Meter.CreateCounter<long>(
        "tts_auth_accounts_locked_total",
        unit: null,
        description: "Total number of accounts locked due to repeated login failures.");

    /// <summary>Starts a child span on <see cref="ActivitySource"/>. Returns <c>null</c> when no listener.</summary>
    public static Activity? StartActivity(string operationName, ActivityKind kind = ActivityKind.Internal)
        => ActivitySource.StartActivity(operationName, kind);
}
