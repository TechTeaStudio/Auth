using System.Text.Json;
using TechTeaStudio.Auth.OAuthServer.Abstractions;
using TechTeaStudio.Auth.OAuthServer.Internal;

namespace TechTeaStudio.Auth.OAuthServer.Clients;

internal sealed record ParsedClientMetadata(string? Name, string? LogoUri, string? ClientUri, IReadOnlyList<string> RedirectUris);

internal sealed record ClientMetadataError(string Code, string Description);

/// <summary>Validation shared by Client ID Metadata Documents and RFC 7591 registration bodies.</summary>
internal static class ClientMetadataParser
{
    private const int MaxUriLength = 2048;

    public static ParsedClientMetadata? Parse(JsonElement root, OAuthServerOptions options, out ClientMetadataError? error)
    {
        error = null;
        if (root.ValueKind != JsonValueKind.Object)
        {
            error = new("invalid_client_metadata", "Metadata must be a JSON object.");
            return null;
        }

        if (!root.TryGetProperty("redirect_uris", out var uris) || uris.ValueKind != JsonValueKind.Array || uris.GetArrayLength() == 0)
        {
            error = new("invalid_redirect_uri", "redirect_uris must be a non-empty array.");
            return null;
        }
        if (uris.GetArrayLength() > options.MaxRedirectUrisPerClient)
        {
            error = new("invalid_redirect_uri", "Too many redirect_uris.");
            return null;
        }
        var redirects = new List<string>();
        foreach (var u in uris.EnumerateArray())
        {
            var s = u.ValueKind == JsonValueKind.String ? u.GetString() : null;
            if (!RedirectUriRules.IsAcceptable(s))
            {
                error = new("invalid_redirect_uri", "Each redirect URI must be an absolute https URL or an http loopback URL without a fragment.");
                return null;
            }
            if (!redirects.Contains(s!, StringComparer.Ordinal)) redirects.Add(s!);
        }

        if (root.TryGetProperty("token_endpoint_auth_method", out var am)
            && !(am.ValueKind == JsonValueKind.String && am.GetString() == "none") && am.ValueKind != JsonValueKind.Null)
        {
            error = new("invalid_client_metadata", "Only token_endpoint_auth_method \"none\" is supported for dynamic and metadata-document clients.");
            return null;
        }
        if (root.TryGetProperty("client_secret", out _))
        {
            error = new("invalid_client_metadata", "client_secret must not be present.");
            return null;
        }

        string? name = null;
        if (root.TryGetProperty("client_name", out var n) && n.ValueKind != JsonValueKind.Null)
        {
            if (n.ValueKind != JsonValueKind.String)
            {
                error = new("invalid_client_metadata", "client_name must be a string.");
                return null;
            }
            name = CleanText(n.GetString(), options.MaxClientNameLength);
        }

        return new ParsedClientMetadata(name, HttpsUri(root, "logo_uri"), HttpsUri(root, "client_uri"), redirects);
    }

    public static string? CleanText(string? s, int max)
    {
        if (string.IsNullOrWhiteSpace(s)) return null;
        var clean = new string(s.Where(c => !char.IsControl(c)).ToArray()).Trim();
        if (clean.Length == 0) return null;
        return clean.Length > max ? clean.Substring(0, max) : clean;
    }

    private static string? HttpsUri(JsonElement root, string property)
    {
        if (!root.TryGetProperty(property, out var p) || p.ValueKind != JsonValueKind.String) return null;
        var s = p.GetString();
        if (s is null || s.Length > MaxUriLength) return null;
        return Uri.TryCreate(s, UriKind.Absolute, out var uri) && uri.Scheme == Uri.UriSchemeHttps && uri.UserInfo.Length == 0 ? s : null;
    }

    public static bool IsMetadataDocumentUrl(string clientId, out Uri uri)
    {
        uri = null!;
        if (clientId.Length > 512 || !clientId.StartsWith("https://", StringComparison.OrdinalIgnoreCase)) return false;
        if (!Uri.TryCreate(clientId, UriKind.Absolute, out var u)) return false;
        if (u.Scheme != Uri.UriSchemeHttps || u.Fragment.Length > 0 || clientId.Contains('#') || u.UserInfo.Length > 0) return false;
        if (u.AbsolutePath == "/" || u.AbsolutePath.Length < 2) return false;
        if (clientId.Contains("/./") || clientId.Contains("/../") || clientId.EndsWith("/.") || clientId.EndsWith("/..")) return false;
        uri = u;
        return true;
    }

    public static OAuthClient? ParseDocument(string json, string clientIdUrl, OAuthServerOptions options, DateTimeOffset now, out string? reason)
    {
        reason = null;
        try
        {
            using var doc = JsonDocument.Parse(json, new JsonDocumentOptions { MaxDepth = 8 });
            var root = doc.RootElement;
            if (root.ValueKind != JsonValueKind.Object
                || !root.TryGetProperty("client_id", out var cid) || cid.ValueKind != JsonValueKind.String
                || !string.Equals(cid.GetString(), clientIdUrl, StringComparison.Ordinal))
            {
                reason = "client_id_mismatch";
                return null;
            }

            var parsed = Parse(root, options, out var error);
            if (parsed is null)
            {
                reason = "invalid_document:" + error!.Code;
                return null;
            }

            return new OAuthClient
            {
                ClientId = clientIdUrl,
                Name = parsed.Name,
                LogoUri = parsed.LogoUri,
                ClientUri = parsed.ClientUri,
                RedirectUris = parsed.RedirectUris,
                Source = OAuthClientSource.MetadataDocument,
                CreatedAt = now,
            };
        }
        catch (JsonException)
        {
            reason = "invalid_json";
            return null;
        }
    }
}
