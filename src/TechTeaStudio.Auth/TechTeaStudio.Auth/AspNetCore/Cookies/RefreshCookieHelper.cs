using Microsoft.AspNetCore.Http;

namespace TechTeaStudio.Auth.AspNetCore.Cookies;

/// <summary>
/// Helpers for placing the refresh token in an <c>HttpOnly</c> + <c>SameSite=Strict</c>
/// cookie so a Blazor / MVC app never has to handle it in JavaScript.
/// </summary>
public static class RefreshCookieHelper
{
    /// <summary>Writes <paramref name="rawRefreshToken"/> as <see cref="TechTeaStudioCookieDefaults.RefreshCookieName"/>.</summary>
    public static void Write(HttpResponse response, string rawRefreshToken, DateTimeOffset expiresAt, string path = "/")
    {
        if (response is null) throw new ArgumentNullException(nameof(response));
        if (string.IsNullOrEmpty(rawRefreshToken)) throw new ArgumentException("token required", nameof(rawRefreshToken));

        response.Cookies.Append(TechTeaStudioCookieDefaults.RefreshCookieName, rawRefreshToken, new CookieOptions
        {
            HttpOnly = true,
            Secure = true,
            SameSite = SameSiteMode.Strict,
            Path = path,
            Expires = expiresAt,
            IsEssential = true,
        });
    }

    /// <summary>Reads the refresh cookie if present, else null.</summary>
    public static string? TryRead(HttpRequest request) =>
        request?.Cookies.TryGetValue(TechTeaStudioCookieDefaults.RefreshCookieName, out var v) == true ? v : null;

    /// <summary>Removes the refresh cookie.</summary>
    public static void Clear(HttpResponse response, string path = "/")
    {
        if (response is null) throw new ArgumentNullException(nameof(response));
        response.Cookies.Delete(TechTeaStudioCookieDefaults.RefreshCookieName, new CookieOptions
        {
            HttpOnly = true,
            Secure = true,
            SameSite = SameSiteMode.Strict,
            Path = path,
        });
    }
}
