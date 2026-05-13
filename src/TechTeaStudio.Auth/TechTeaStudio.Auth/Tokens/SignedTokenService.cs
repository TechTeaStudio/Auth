using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Options;
using TechTeaStudio.Auth.Revocation;
using TechTeaStudio.Auth.Signing;

namespace TechTeaStudio.Auth.Tokens;

/// <summary>
/// HMAC-SHA256 signed, one-time-use opaque tokens used for email confirmation,
/// password reset, and similar single-shot flows. Format on the wire is a base64url
/// string of <c>payload-json | "." | hmac</c>. The payload always includes
/// <c>jti</c>, <c>purpose</c>, and <c>exp</c>; callers add purpose-specific fields.
/// One-time-use is enforced via <see cref="IRevokedTokenStore"/> — successful
/// validation revokes the <c>jti</c>.
/// </summary>
public sealed class SignedTokenService
{
    private readonly AuthOptions _options;
    private readonly IRevokedTokenStore _revoked;

    public SignedTokenService(IOptions<AuthOptions> options, IRevokedTokenStore? revoked = null)
    {
        _options = options?.Value ?? throw new ArgumentNullException(nameof(options));
        _revoked = revoked ?? NullRevokedTokenStore.Instance;
    }

    /// <summary>Generates a signed, time-limited token for <paramref name="purpose"/>.</summary>
    public string Generate(string purpose, TimeSpan lifetime, IReadOnlyDictionary<string, string>? extra = null)
    {
        if (string.IsNullOrEmpty(purpose)) throw new ArgumentException("purpose required", nameof(purpose));
        if (lifetime <= TimeSpan.Zero) throw new ArgumentOutOfRangeException(nameof(lifetime));

        var payload = new Dictionary<string, string>(extra ?? new Dictionary<string, string>())
        {
            ["jti"] = Guid.NewGuid().ToString("N"),
            ["purpose"] = purpose,
            ["exp"] = DateTimeOffset.UtcNow.Add(lifetime).ToUnixTimeSeconds().ToString(),
        };

        var json = JsonSerializer.Serialize(payload);
        var sig = Sign(json);
        return $"{Base64UrlEncode(Encoding.UTF8.GetBytes(json))}.{Base64UrlEncode(sig)}";
    }

    /// <summary>
    /// Validates a token against <paramref name="expectedPurpose"/>. Returns the parsed payload
    /// on success and revokes the <c>jti</c> so the token cannot be replayed. Returns <c>null</c>
    /// on any failure (bad signature, wrong purpose, expired, already used).
    /// </summary>
    public async Task<IReadOnlyDictionary<string, string>?> ValidateAsync(string token, string expectedPurpose, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrEmpty(token)) return null;
        var parts = token.Split('.');
        if (parts.Length != 2) return null;

        byte[] payloadBytes, providedSig;
        try
        {
            payloadBytes = Base64UrlDecode(parts[0]);
            providedSig = Base64UrlDecode(parts[1]);
        }
        catch
        {
            return null;
        }

        var json = Encoding.UTF8.GetString(payloadBytes);
        var expectedSig = Sign(json);
        if (!CryptographicOperations.FixedTimeEquals(providedSig, expectedSig)) return null;

        Dictionary<string, string>? payload;
        try
        {
            payload = JsonSerializer.Deserialize<Dictionary<string, string>>(json);
        }
        catch
        {
            return null;
        }
        if (payload is null) return null;

        if (!payload.TryGetValue("purpose", out var purpose) || purpose != expectedPurpose) return null;
        if (!payload.TryGetValue("exp", out var expRaw) || !long.TryParse(expRaw, out var expUnix)) return null;
        if (DateTimeOffset.FromUnixTimeSeconds(expUnix) <= DateTimeOffset.UtcNow) return null;

        if (!payload.TryGetValue("jti", out var jti) || string.IsNullOrEmpty(jti)) return null;
        if (await _revoked.IsRevokedAsync(jti, cancellationToken).ConfigureAwait(false)) return null;

        await _revoked.RevokeAsync(jti, DateTimeOffset.FromUnixTimeSeconds(expUnix), cancellationToken).ConfigureAwait(false);
        return payload;
    }

    private byte[] Sign(string payloadJson)
    {
        var key = SigningKeyResolver.ResolveServerHmacKey(_options);
#if NET6_0_OR_GREATER
        return HMACSHA256.HashData(key, Encoding.UTF8.GetBytes(payloadJson));
#else
        using var hmac = new HMACSHA256(key);
        return hmac.ComputeHash(Encoding.UTF8.GetBytes(payloadJson));
#endif
    }

    internal static string Base64UrlEncode(byte[] bytes) =>
        Convert.ToBase64String(bytes).Replace('+', '-').Replace('/', '_').TrimEnd('=');

    internal static byte[] Base64UrlDecode(string s)
    {
        var padded = s.Replace('-', '+').Replace('_', '/');
        switch (padded.Length % 4)
        {
            case 2: padded += "=="; break;
            case 3: padded += "="; break;
        }
        return Convert.FromBase64String(padded);
    }
}
