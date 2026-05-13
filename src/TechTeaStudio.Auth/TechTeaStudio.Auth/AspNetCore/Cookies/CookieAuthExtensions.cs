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
    /// Adds the <see cref="TechTeaStudioCookieDefaults.SchemeName"/> cookie scheme.
    /// <para>
    /// Defaults: <c>HttpOnly</c>, <c>SameSite=Strict</c>,
    /// <c>SecurePolicy=SameAsRequest</c> — the cookie is marked <c>Secure</c> when
    /// the request is HTTPS, and is allowed over plain HTTP otherwise. This makes
    /// the library work out of the box in dev (<c>http://localhost</c>) and
    /// domain-less / homelab deployments where there is no TLS certificate.
    /// </para>
    /// <para>
    /// For production over HTTPS, harden by overriding to
    /// <see cref="CookieSecurePolicy.Always"/>:
    /// <code>
    /// services.AddAuthentication(TechTeaStudioCookieDefaults.SchemeName)
    ///     .AddTechTeaStudioCookieAuth(o => o.Cookie.SecurePolicy = CookieSecurePolicy.Always);
    /// </code>
    /// </para>
    /// <para>
    /// API endpoints (path starting with <c>/api</c>, or <c>Accept: application/json</c>,
    /// or <c>X-Requested-With: XMLHttpRequest</c>) receive a JSON <c>401/403</c>
    /// instead of an HTML redirect to a login page.
    /// </para>
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
            // SameAsRequest by default so HTTP-only deployments (localhost, homelab,
            // internal-network apps without TLS) work out of the box. Override to
            // CookieSecurePolicy.Always in production via the configure callback.
            o.Cookie.SecurePolicy = CookieSecurePolicy.SameAsRequest;
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
