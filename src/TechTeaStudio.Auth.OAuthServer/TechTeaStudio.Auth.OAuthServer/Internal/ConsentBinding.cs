using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Http;

namespace TechTeaStudio.Auth.OAuthServer.Internal;

/// <summary>
/// Binds a pending authorization request to the browser that started it. <c>/oauth/authorize</c> adds a hash of the
/// pending id to a <c>__Host-</c> cookie (Secure, HttpOnly, SameSite=Lax, Path=/); approve and deny must present a
/// request whose hash is in that cookie. A forged cross-site POST, or a consent link opened in another browser,
/// carries no matching cookie and is refused.
/// </summary>
internal static class ConsentBinding
{
    private const int MaxBindings = 5;
    private const char Separator = '.';

    public static string Hash(string pendingId) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(pendingId))).Substring(0, 32);

    private static List<string> Read(HttpContext http) =>
        http.Request.Cookies.TryGetValue(OAuthServerPaths.ConsentBindingCookie, out var v) && !string.IsNullOrEmpty(v)
            ? v.Split(Separator, StringSplitOptions.RemoveEmptyEntries).ToList()
            : new List<string>();

    public static bool Matches(HttpContext http, string pendingId)
    {
        if (http is null) throw new ArgumentNullException(nameof(http));
        var hash = Hash(pendingId);
        return Read(http).Any(h => CryptographicOperations.FixedTimeEquals(Encoding.ASCII.GetBytes(h), Encoding.ASCII.GetBytes(hash)));
    }

    public static void Add(HttpContext http, string pendingId, TimeSpan lifetime)
    {
        var all = Read(http);
        all.Add(Hash(pendingId));
        if (all.Count > MaxBindings) all.RemoveRange(0, all.Count - MaxBindings);
        Write(http, all, lifetime);
    }

    public static void Remove(HttpContext http, string pendingId, TimeSpan lifetime)
    {
        if (http.Response.HasStarted) return;
        var hash = Hash(pendingId);
        var all = Read(http);
        all.RemoveAll(h => h == hash);
        Write(http, all, lifetime);
    }

    private static void Write(HttpContext http, List<string> hashes, TimeSpan lifetime)
    {
        var options = new CookieOptions
        {
            Secure = true,
            HttpOnly = true,
            SameSite = SameSiteMode.Lax,
            Path = "/",
            IsEssential = true,
        };
        if (hashes.Count == 0)
        {
            http.Response.Cookies.Delete(OAuthServerPaths.ConsentBindingCookie, options);
            return;
        }
        options.MaxAge = lifetime;
        http.Response.Cookies.Append(OAuthServerPaths.ConsentBindingCookie, string.Join(Separator, hashes), options);
    }
}
