namespace TechTeaStudio.Auth.AspNetCore.Cookies;

/// <summary>Stable constants for the cookie scheme registered by <see cref="CookieAuthExtensions"/>.</summary>
public static class TechTeaStudioCookieDefaults
{
    /// <summary>Scheme name. Use in <c>[Authorize(AuthenticationSchemes = TechTeaStudioCookieDefaults.SchemeName)]</c>.</summary>
    public const string SchemeName = "TechTeaStudio.Cookie";

    /// <summary>Cookie name written by the handler.</summary>
    public const string CookieName = "tts_auth";

    /// <summary>Cookie name used to ship the refresh token to the browser. HttpOnly + Strict.</summary>
    public const string RefreshCookieName = "tts_auth_refresh";
}
