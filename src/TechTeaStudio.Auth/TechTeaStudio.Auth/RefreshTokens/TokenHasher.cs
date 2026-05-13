using System.Security.Cryptography;
using System.Text;

namespace TechTeaStudio.Auth.RefreshTokens;

/// <summary>
/// SHA-256 hashing helper for refresh tokens. The raw token leaves the issuing
/// service only on the wire; only its SHA-256 hash is ever passed to <see cref="Abstractions.IRefreshTokenStore"/>.
/// </summary>
public static class TokenHasher
{
    /// <summary>
    /// Returns the lower-case hex SHA-256 of <paramref name="rawToken"/>. Empty input
    /// returns an empty string so callers can compare freely.
    /// </summary>
    public static string HashRefreshToken(string rawToken)
    {
        if (string.IsNullOrEmpty(rawToken)) return string.Empty;

        Span<byte> digest = stackalloc byte[32];
        var bytes = Encoding.UTF8.GetBytes(rawToken);
#if NET6_0_OR_GREATER
        SHA256.HashData(bytes, digest);
#else
        using var sha = SHA256.Create();
        digest = sha.ComputeHash(bytes);
#endif

        var hex = new StringBuilder(64);
        for (var i = 0; i < digest.Length; i++)
            hex.Append(digest[i].ToString("x2"));
        return hex.ToString();
    }

    internal static string NewRawToken()
    {
        var bytes = RandomNumberGenerator.GetBytes(48);
        // base64url, no padding — URL-safe across browser/header transports.
        return Convert.ToBase64String(bytes)
            .Replace('+', '-')
            .Replace('/', '_')
            .TrimEnd('=');
    }
}
