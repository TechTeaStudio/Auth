using System.Text.Json;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;

namespace TechTeaStudio.Auth.AspNetCore.Cookies;

/// <summary>
/// Cookie-based session option that sits alongside the default JWT bearer scheme.
/// Intended for Blazor Server / classic MVC apps where the browser holds the
/// session in an <c>HttpOnly</c>+<c>SameSite=Strict</c> cookie.
/// </summary>
public static class CookieAuthExtensions
{
    /// <summary>
    /// Adds the <see cref="TechTeaStudioCookieDefaults.SchemeName"/> cookie scheme with
    /// security-hardened defaults: <c>HttpOnly</c>, <c>SameSite=Strict</c>,
    /// <c>Secure=Always</c>. For API endpoints the handler returns a JSON 401 instead
    /// of redirecting to a login path.
    /// </summary>
    public static AuthenticationBuilder AddTechTeaStudioCookieAuth(
        this AuthenticationBuilder builder,
        Action<CookieAuthenticationOptions>? configure = null)
    {
        if (builder is null) throw new ArgumentNullException(nameof(builder));

        return builder.AddCookie(TechTeaStudioCookieDefaults.SchemeName, o =>
        {
            o.Cookie.Name = TechTeaStudioCookieDefaults.CookieName;
            o.Cookie.HttpOnly = true;
            o.Cookie.SameSite = SameSiteMode.Strict;
            o.Cookie.SecurePolicy = CookieSecurePolicy.Always;
            o.Cookie.IsEssential = true;

            o.SlidingExpiration = true;
            o.ExpireTimeSpan = TimeSpan.FromDays(7);

            // For API requests, return JSON 401/403 instead of redirecting.
            o.Events.OnRedirectToLogin = ctx =>
            {
                if (IsApiRequest(ctx.Request))
                {
                    return WriteJsonAsync(ctx.HttpContext, StatusCodes.Status401Unauthorized,
                        AuthErrorCodes.MissingToken, "Authentication required.");
                }
                ctx.Response.Redirect(ctx.RedirectUri);
                return Task.CompletedTask;
            };
            o.Events.OnRedirectToAccessDenied = ctx =>
            {
                if (IsApiRequest(ctx.Request))
                {
                    return WriteJsonAsync(ctx.HttpContext, StatusCodes.Status403Forbidden,
                        AuthErrorCodes.Unauthorized, "Insufficient permissions.");
                }
                ctx.Response.Redirect(ctx.RedirectUri);
                return Task.CompletedTask;
            };

            configure?.Invoke(o);
        });
    }

    private static bool IsApiRequest(HttpRequest req) =>
        req.Path.StartsWithSegments("/api", StringComparison.OrdinalIgnoreCase)
        || req.Headers["Accept"].ToString().Contains("application/json", StringComparison.OrdinalIgnoreCase)
        || string.Equals(req.Headers["X-Requested-With"], "XMLHttpRequest", StringComparison.OrdinalIgnoreCase);

    private static readonly JsonSerializerOptions Json = new() { PropertyNamingPolicy = JsonNamingPolicy.CamelCase };

    private static async Task WriteJsonAsync(HttpContext ctx, int status, string error, string message)
    {
        ctx.Response.StatusCode = status;
        ctx.Response.ContentType = "application/json; charset=utf-8";
        await ctx.Response.WriteAsync(JsonSerializer.Serialize(new
        {
            error,
            message,
            traceId = ctx.TraceIdentifier,
        }, Json)).ConfigureAwait(false);
    }
}
