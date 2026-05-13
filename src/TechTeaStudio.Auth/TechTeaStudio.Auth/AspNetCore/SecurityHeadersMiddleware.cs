using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;

namespace TechTeaStudio.Auth.AspNetCore;

/// <summary>
/// Adds the common security-related response headers (CSP-friendly defaults).
/// Register with <c>app.UseSecurityHeaders()</c>.
/// </summary>
public sealed class SecurityHeadersMiddleware : IMiddleware
{
    public async Task InvokeAsync(HttpContext context, RequestDelegate next)
    {
        var h = context.Response.Headers;
        h["X-Content-Type-Options"] = "nosniff";
        h["X-Frame-Options"] = "DENY";
        h["X-XSS-Protection"] = "1; mode=block";
        h["Referrer-Policy"] = "strict-origin-when-cross-origin";
        if (context.Request.IsHttps)
            h["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains";

        await next(context).ConfigureAwait(false);
    }
}

/// <summary>Application-builder extensions for <see cref="SecurityHeadersMiddleware"/>.</summary>
public static class SecurityHeadersApplicationBuilderExtensions
{
    /// <summary>
    /// Installs <see cref="SecurityHeadersMiddleware"/> into the pipeline. Call this
    /// early in <c>Configure</c> so the headers are present on every response, including
    /// errors written by later middleware.
    /// </summary>
    public static IApplicationBuilder UseSecurityHeaders(this IApplicationBuilder app)
    {
        if (app is null) throw new ArgumentNullException(nameof(app));
        return app.UseMiddleware<SecurityHeadersMiddleware>();
    }
}
