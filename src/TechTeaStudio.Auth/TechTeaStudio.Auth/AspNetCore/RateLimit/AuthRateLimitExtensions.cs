#if NET8_0_OR_GREATER
using System.Text.Json;
using System.Threading.RateLimiting;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.Extensions.DependencyInjection;

namespace TechTeaStudio.Auth.AspNetCore.RateLimit;

/// <summary>
/// IP-keyed rate-limit policy for login / refresh endpoints. Only available on
/// <c>net8.0</c> and later — <c>net6.0</c> consumers must roll their own.
/// </summary>
public static class AuthRateLimitExtensions
{
    private static readonly JsonSerializerOptions JsonOpts = new() { PropertyNamingPolicy = JsonNamingPolicy.CamelCase };

    /// <summary>
    /// Registers a fixed-window rate-limit policy named
    /// <see cref="AuthRateLimitOptions.PolicyName"/> ("tts-auth-login") keyed by
    /// client IP. Pair with <c>app.UseRateLimiter()</c> and
    /// <c>.RequireRateLimiting(AuthRateLimitOptions.PolicyName)</c> on the protected endpoint.
    /// </summary>
    public static IServiceCollection AddTechTeaStudioRateLimit(
        this IServiceCollection services,
        Action<AuthRateLimitOptions>? configure = null)
    {
        if (services is null) throw new ArgumentNullException(nameof(services));

        var opts = new AuthRateLimitOptions();
        configure?.Invoke(opts);

        services.AddRateLimiter(o =>
        {
            o.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
            o.OnRejected = static async (ctx, ct) =>
            {
                ctx.HttpContext.Response.ContentType = "application/json; charset=utf-8";
                await ctx.HttpContext.Response.WriteAsync(
                    JsonSerializer.Serialize(new
                    {
                        error = "rate_limited",
                        message = "Too many requests. Retry later.",
                        traceId = ctx.HttpContext.TraceIdentifier,
                    }, JsonOpts), ct).ConfigureAwait(false);
            };

            o.AddPolicy(AuthRateLimitOptions.PolicyName, http =>
            {
                var key = http.Connection.RemoteIpAddress?.ToString() ?? "anon";
                return RateLimitPartition.GetFixedWindowLimiter(key, _ => new FixedWindowRateLimiterOptions
                {
                    PermitLimit = opts.PermitLimit,
                    Window = opts.Window,
                    QueueLimit = opts.QueueLimit,
                    QueueProcessingOrder = QueueProcessingOrder.OldestFirst,
                    AutoReplenishment = true,
                });
            });
        });
        return services;
    }
}
#endif
