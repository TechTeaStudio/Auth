using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using TechTeaStudio.Auth.RefreshTokens;

namespace TechTeaStudio.Auth.OAuthServer.Internal;

internal static class OAuthSecrets
{
    public static string NewToken(int bytes = 32) =>
        Convert.ToBase64String(RandomNumberGenerator.GetBytes(bytes)).Replace('+', '-').Replace('/', '_').TrimEnd('=');

    public static string Hash(string value) => TokenHasher.HashRefreshToken(value);
}

internal static class ScopeList
{
    public static string Join(IEnumerable<string> scopes) => string.Join(' ', scopes);

    public static IReadOnlyList<string> Split(string? scope) =>
        string.IsNullOrWhiteSpace(scope)
            ? Array.Empty<string>()
            : scope.Split(' ', StringSplitOptions.RemoveEmptyEntries).Distinct(StringComparer.Ordinal).ToArray();
}

internal static class Pkce
{
    private static bool AsciiAlnum(char c) => c is (>= 'a' and <= 'z') or (>= 'A' and <= 'Z') or (>= '0' and <= '9');

    public static bool IsValidVerifier(string? v) =>
        v is { Length: >= 43 and <= 128 } && v.All(c => AsciiAlnum(c) || c is '-' or '.' or '_' or '~');

    public static bool IsValidChallenge(string? c) =>
        c is { Length: 43 } && c.All(ch => AsciiAlnum(ch) || ch is '-' or '_');

    public static string ComputeS256(string verifier) =>
        Convert.ToBase64String(SHA256.HashData(Encoding.ASCII.GetBytes(verifier))).Replace('+', '-').Replace('/', '_').TrimEnd('=');

    public static bool Verify(string verifier, string challenge)
    {
        if (!IsValidVerifier(verifier)) return false;
        var expected = Encoding.ASCII.GetBytes(ComputeS256(verifier));
        var actual = Encoding.ASCII.GetBytes(challenge);
        return CryptographicOperations.FixedTimeEquals(expected, actual);
    }
}

internal static class RedirectUriRules
{
    public const int MaxLength = 2048;

    public static bool IsLoopbackHost(string host) =>
        host.Equals("localhost", StringComparison.OrdinalIgnoreCase) || host == "127.0.0.1" || host == "[::1]" || host == "::1";

    /// <summary>https or loopback http; absolute; no fragment; no user info.</summary>
    public static bool IsAcceptable(string? value)
    {
        if (string.IsNullOrEmpty(value) || value.Length > MaxLength) return false;
        if (!Uri.TryCreate(value, UriKind.Absolute, out var uri)) return false;
        if (uri.Fragment.Length > 0 || value.Contains('#') || uri.UserInfo.Length > 0) return false;
        if (uri.Scheme == Uri.UriSchemeHttps) return uri.Host.Length > 0;
        return uri.Scheme == Uri.UriSchemeHttp && IsLoopbackHost(uri.Host);
    }

    /// <summary>Exact match, except loopback URIs where the port is free (RFC 8252 section 7.3).</summary>
    public static bool Matches(IEnumerable<string> registered, string requested)
    {
        if (!IsAcceptable(requested)) return false;
        Uri.TryCreate(requested, UriKind.Absolute, out var req);
        foreach (var r in registered)
        {
            if (string.Equals(r, requested, StringComparison.Ordinal)) return true;
            if (req is null || req.Scheme != Uri.UriSchemeHttp || !IsLoopbackHost(req.Host)) continue;
            if (!Uri.TryCreate(r, UriKind.Absolute, out var reg)) continue;
            if (reg.Scheme == Uri.UriSchemeHttp && IsLoopbackHost(reg.Host)
                && string.Equals(reg.Host, req.Host, StringComparison.OrdinalIgnoreCase)
                && string.Equals(reg.AbsolutePath, req.AbsolutePath, StringComparison.Ordinal)
                && string.Equals(reg.Query, req.Query, StringComparison.Ordinal))
                return true;
        }
        return false;
    }

    public static string HostOf(string redirectUri) =>
        Uri.TryCreate(redirectUri, UriKind.Absolute, out var u) ? u.IdnHost : string.Empty;

    public static string AppendQuery(string baseUri, IEnumerable<KeyValuePair<string, string?>> parameters)
    {
        var sb = new StringBuilder(baseUri);
        var first = !baseUri.Contains('?');
        foreach (var (k, v) in parameters)
        {
            if (v is null) continue;
            sb.Append(first ? '?' : '&');
            first = false;
            sb.Append(Uri.EscapeDataString(k)).Append('=').Append(Uri.EscapeDataString(v));
        }
        return sb.ToString();
    }
}

/// <summary>The outbound address filter of the metadata-document fetcher.</summary>
internal static class OutboundAddressPolicy
{
    public static bool IsPublic(IPAddress address)
    {
        if (address.IsIPv4MappedToIPv6) address = address.MapToIPv4();
        if (IPAddress.IsLoopback(address) || address.Equals(IPAddress.Any) || address.Equals(IPAddress.IPv6Any)) return false;

        var b = address.GetAddressBytes();
        if (address.AddressFamily == AddressFamily.InterNetwork)
        {
            if (b[0] == 0 || b[0] == 10 || b[0] == 127) return false;
            if (b[0] == 100 && b[1] >= 64 && b[1] <= 127) return false;
            if (b[0] == 169 && b[1] == 254) return false;
            if (b[0] == 172 && b[1] >= 16 && b[1] <= 31) return false;
            if (b[0] == 192 && b[1] == 168) return false;
            if (b[0] == 192 && b[1] == 0 && b[2] == 0) return false;
            if (b[0] == 192 && b[1] == 0 && b[2] == 2) return false;
            if (b[0] == 198 && (b[1] == 18 || b[1] == 19)) return false;
            if (b[0] == 198 && b[1] == 51 && b[2] == 100) return false;
            if (b[0] == 203 && b[1] == 0 && b[2] == 113) return false;
            if (b[0] >= 224) return false;
            return true;
        }

        if (address.AddressFamily == AddressFamily.InterNetworkV6)
        {
            if (address.IsIPv6LinkLocal || address.IsIPv6SiteLocal || address.IsIPv6Multicast) return false;
            if ((b[0] & 0xFE) == 0xFC) return false;
            if (b[0] == 0x20 && b[1] == 0x01 && b[2] == 0x0D && b[3] == 0xB8) return false;
            if (b[0] == 0x00 && b[1] == 0x64 && b[2] == 0xFF && b[3] == 0x9B)
                return IsPublic(new IPAddress(new[] { b[12], b[13], b[14], b[15] }));
            return true;
        }

        return false;
    }
}
