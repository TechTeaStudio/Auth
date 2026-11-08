using System.Collections;
using TechTeaStudio.Auth.OAuthServer.Abstractions;

namespace TechTeaStudio.Auth.OAuthServer;

/// <summary>Endpoint paths the module maps. Constants so the host can add them to its rate limiter.</summary>
public static class OAuthServerPaths
{
    public const string Metadata = "/.well-known/oauth-authorization-server";
    public const string Authorize = "/oauth/authorize";
    public const string Token = "/oauth/token";
    public const string Register = "/oauth/register";
    public const string Revoke = "/oauth/revoke";

    /// <summary>Name to register a rate limiter under and apply with <c>MapTechTeaStudioOAuthServer().RequireRateLimiting(OAuthServerPaths.RateLimitPolicy)</c>.</summary>
    public const string RateLimitPolicy = "tts-oauth";

    /// <summary>Cookie that binds a pending request to the browser that started it.</summary>
    public const string ConsentBindingCookie = "__Host-tts-oauth-consent";
}

/// <summary>Scopes the server can grant. <c>Add(name, description)</c> reads well in an options lambda.</summary>
public sealed class OAuthScopeCollection : IEnumerable<OAuthScope>
{
    private readonly List<OAuthScope> _items = new();

    public int Count => _items.Count;

    public OAuthScopeCollection Add(string name, string? description = null)
    {
        if (string.IsNullOrWhiteSpace(name) || name.Any(c => c <= ' ' || c == '"' || c == '\\' || c > '~'))
            throw new ArgumentException("A scope name must be non-empty printable ASCII without spaces, quotes or backslashes.", nameof(name));
        if (_items.Any(s => s.Name == name)) throw new ArgumentException($"Scope '{name}' is already registered.", nameof(name));
        _items.Add(new OAuthScope(name, description));
        return this;
    }

    public OAuthScope? Find(string name) => _items.FirstOrDefault(s => s.Name == name);

    public IEnumerator<OAuthScope> GetEnumerator() => _items.GetEnumerator();
    IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();
}

/// <summary>A client defined in configuration. Public unless <see cref="ClientSecret"/> is set.</summary>
public sealed class OAuthClientOptions
{
    public string ClientId { get; set; } = string.Empty;
    public string? Name { get; set; }
    public string? LogoUri { get; set; }
    public string? ClientUri { get; set; }
    public List<string> RedirectUris { get; set; } = new();

    /// <summary>Makes the client confidential (<c>client_secret_post</c>). Only its SHA-256 is kept in memory.</summary>
    public string? ClientSecret { get; set; }
}

/// <summary>Configuration of the OAuth 2.1 authorization server module.</summary>
public sealed class OAuthServerOptions
{
    /// <summary>Absolute issuer URL, published verbatim as <c>issuer</c> and <c>iss</c>. Never derived from the request.</summary>
    public string Issuer { get; set; } = string.Empty;

    /// <summary>Protected resource identifiers (RFC 8707). A request's <c>resource</c> must match one exactly. Also the access-token <c>aud</c>.</summary>
    public List<string> ProtectedResources { get; set; } = new();

    public OAuthScopeCollection Scopes { get; } = new();

    /// <summary>Scopes granted when a request names none. Empty means "all <see cref="Scopes"/>".</summary>
    public List<string> DefaultScopes { get; set; } = new();

    /// <summary>Host page that signs the user in and shows consent; receives <c>?request=&lt;id&gt;</c>.</summary>
    public string ConsentPath { get; set; } = "/oauth/consent";

    public List<OAuthClientOptions> Clients { get; set; } = new();

    /// <summary>RFC 7591 registration writes a row per call from an unauthenticated caller, so hosts opt in (and rate limit it).</summary>
    public bool EnableDynamicRegistration { get; set; }
    public bool EnableClientIdMetadataDocuments { get; set; } = true;

    /// <summary>Let a returning user with a covering grant skip the consent screen (host calls <see cref="IOAuthAuthorizationService.TryAutoApproveAsync"/>).</summary>
    public bool RememberConsent { get; set; }

    public TimeSpan AccessTokenLifetime { get; set; } = TimeSpan.FromMinutes(60);
    public TimeSpan RefreshTokenLifetime { get; set; } = TimeSpan.FromDays(30);
    public TimeSpan AuthorizationCodeLifetime { get; set; } = TimeSpan.FromSeconds(60);
    public TimeSpan PendingRequestLifetime { get; set; } = TimeSpan.FromMinutes(10);

    /// <summary>A refresh token rotated less than this long ago answers <c>invalid_grant</c> without burning its family.</summary>
    public TimeSpan RefreshRotationGrace { get; set; } = TimeSpan.FromSeconds(30);

    public TimeSpan MetadataCacheMaxAge { get; set; } = TimeSpan.FromSeconds(300);

    /// <summary>Upper bound for caching a fetched client metadata document, whatever its Cache-Control says.</summary>
    public TimeSpan ClientMetadataMaxCache { get; set; } = TimeSpan.FromHours(24);

    /// <summary>Cache lifetime for a document that sent no Cache-Control.</summary>
    public TimeSpan ClientMetadataDefaultCache { get; set; } = TimeSpan.FromHours(1);

    public int MaxClientNameLength { get; set; } = 100;
    public int MaxRedirectUrisPerClient { get; set; } = 5;

    /// <summary>Live pending authorization requests one client id may hold.</summary>
    public int MaxPendingRequestsPerClient { get; set; } = 50;

    /// <summary>Concurrent client metadata document downloads, process wide.</summary>
    public int MaxConcurrentMetadataFetches { get; set; } = 4;

    /// <summary>A refresh family stops refreshing this long after the first exchange, however often it was used.</summary>
    public TimeSpan RefreshFamilyAbsoluteLifetime { get; set; } = TimeSpan.FromDays(90);
    public int MaxClientMetadataBytes { get; set; } = 64 * 1024;
    public TimeSpan ClientMetadataFetchTimeout { get; set; } = TimeSpan.FromSeconds(5);

    internal IReadOnlyList<string> EffectiveDefaultScopes =>
        DefaultScopes.Count > 0 ? DefaultScopes : Scopes.Select(s => s.Name).ToArray();

    internal string EndpointUrl(string path) => Issuer.TrimEnd('/') + path;
}
