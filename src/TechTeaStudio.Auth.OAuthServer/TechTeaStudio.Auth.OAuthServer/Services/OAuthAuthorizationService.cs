using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using TechTeaStudio.Auth.Observability;
using TechTeaStudio.Auth.OAuthServer.Abstractions;
using TechTeaStudio.Auth.OAuthServer.Clients;
using TechTeaStudio.Auth.OAuthServer.Internal;

namespace TechTeaStudio.Auth.OAuthServer.Services;

/// <summary>What <c>GET /oauth/authorize</c> should answer with.</summary>
internal sealed record AuthorizeOutcome(string? Location, string? PlainError, string? PendingId = null)
{
    public static AuthorizeOutcome Redirect(string url, string? pendingId = null) => new(url, null, pendingId);
    public static AuthorizeOutcome Bad(string message) => new(null, message);
}

internal sealed class OAuthAuthorizationService : IOAuthAuthorizationService
{
    private readonly OAuthServerOptions _options;
    private readonly OAuthClientResolver _clients;
    private readonly IOAuthPendingRequestStore _pending;
    private readonly IOAuthCodeStore _codes;
    private readonly IOAuthGrantStore _grants;
    private readonly IAuthAuditLogger _audit;
    private readonly TimeProvider _time;

    public OAuthAuthorizationService(
        IOptions<OAuthServerOptions> options, OAuthClientResolver clients, IOAuthPendingRequestStore pending,
        IOAuthCodeStore codes, IOAuthGrantStore grants, IAuthAuditLogger audit, TimeProvider time)
    {
        _options = options.Value;
        _clients = clients;
        _pending = pending;
        _codes = codes;
        _grants = grants;
        _audit = audit;
        _time = time;
    }

    public async Task<AuthorizeOutcome> BeginAsync(IQueryCollection query, CancellationToken ct)
    {
        string? One(string key, out bool multiple)
        {
            var v = query[key];
            multiple = v.Count > 1;
            return v.Count == 0 ? null : v[0];
        }

        var clientId = One("client_id", out var m1);
        if (string.IsNullOrEmpty(clientId) || m1) return AuthorizeOutcome.Bad("invalid_request: client_id is required.");

        var client = await _clients.ResolveAsync(clientId, ct).ConfigureAwait(false);
        if (client is null) return AuthorizeOutcome.Bad("invalid_request: unknown client.");

        var redirectUri = One("redirect_uri", out var m2);
        if (string.IsNullOrEmpty(redirectUri) || m2) return AuthorizeOutcome.Bad("invalid_request: redirect_uri is required.");
        if (!RedirectUriRules.Matches(client.RedirectUris, redirectUri))
            return AuthorizeOutcome.Bad("invalid_request: redirect_uri is not registered for this client.");

        var state = One("state", out var mState);
        string Fail(string error, string description) => RedirectUriRules.AppendQuery(redirectUri, new KeyValuePair<string, string?>[]
        {
            new("error", error), new("error_description", description), new("state", state), new("iss", _options.Issuer),
        });
        // Only pre-registered clients are trusted with an error redirect. A self-registered or metadata-document
        // client could otherwise use this endpoint as an open redirector with attacker-chosen error text.
        var trusted = client.Source == OAuthClientSource.PreRegistered;
        AuthorizeOutcome Err(string error, string description) =>
            trusted ? AuthorizeOutcome.Redirect(Fail(error, description)) : AuthorizeOutcome.Bad(error + ": " + description);

        if (mState || state is { Length: > 2048 }) { state = null; return Err("invalid_request", "state is invalid."); }

        var responseType = One("response_type", out var m3);
        if (m3 || responseType != "code") return Err("unsupported_response_type", "response_type must be \"code\".");

        var method = One("code_challenge_method", out var m4);
        if (m4 || method != "S256") return Err("invalid_request", "code_challenge_method must be S256.");

        var challenge = One("code_challenge", out var m5);
        if (m5 || !Pkce.IsValidChallenge(challenge)) return Err("invalid_request", "A valid S256 code_challenge is required.");

        var resource = One("resource", out var m6);
        if (m6 || string.IsNullOrEmpty(resource) || !_options.ProtectedResources.Contains(resource, StringComparer.Ordinal))
            return Err("invalid_target", "resource is missing or not a protected resource of this server.");

        var scopeParam = One("scope", out var m7);
        if (m7) return Err("invalid_request", "scope must appear once.");
        var scopes = ScopeList.Split(scopeParam);
        if (scopes.Count == 0) scopes = _options.EffectiveDefaultScopes;
        else if (scopes.Any(s => _options.Scopes.Find(s) is null)) return Err("invalid_scope", "One or more requested scopes are not supported.");

        var now = _time.GetUtcNow();
        if (await _pending.CountForClientAsync(client.ClientId, now, ct).ConfigureAwait(false) >= _options.MaxPendingRequestsPerClient)
            return Err("temporarily_unavailable", "Too many authorization requests are pending for this client.");

        var pending = new PendingAuthorization
        {
            Id = OAuthSecrets.NewToken(),
            ClientId = client.ClientId,
            RedirectUri = redirectUri,
            CodeChallenge = challenge!,
            Resource = resource,
            Scopes = scopes,
            State = state,
            CreatedAt = now,
            ExpiresAt = now + _options.PendingRequestLifetime,
        };
        await _pending.SaveAsync(pending, ct).ConfigureAwait(false);
        await _audit.LogAsync(new OAuthAuthorizeRequestedEvent(client.ClientId, resource, ScopeList.Join(scopes), now), ct).ConfigureAwait(false);

        return AuthorizeOutcome.Redirect(RedirectUriRules.AppendQuery(_options.ConsentPath, new KeyValuePair<string, string?>[] { new("request", pending.Id) }), pending.Id);
    }

    public async Task<PendingAuthorizationInfo?> GetPendingAsync(string requestId, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrEmpty(requestId)) return null;
        var p = await _pending.GetAsync(requestId, _time.GetUtcNow(), cancellationToken).ConfigureAwait(false);
        if (p is null) return null;
        var client = await _clients.ResolveAsync(p.ClientId, cancellationToken).ConfigureAwait(false);
        if (client is null) return null;

        var host = RedirectUriRules.HostOf(p.RedirectUri);
        var metadataDocument = client.Source == OAuthClientSource.MetadataDocument;
        Uri? clientIdUri = null;
        if (metadataDocument) Uri.TryCreate(client.ClientId, UriKind.Absolute, out clientIdUri);
        metadataDocument = clientIdUri is not null;
        return new PendingAuthorizationInfo
        {
            RequestId = p.Id,
            ClientId = client.ClientId,
            ClientName = client.Name ?? host,
            ClientLogoUri = client.Source == OAuthClientSource.PreRegistered ? client.LogoUri : null,
            ClientUri = client.ClientUri,
            ClientSource = client.Source,
            ClientIdHost = metadataDocument ? clientIdUri!.IdnHost : null,
            RedirectOriginDiffersFromClientId = metadataDocument && !SameOrigin(clientIdUri!, p.RedirectUri),
            RedirectHost = host,
            RedirectUri = p.RedirectUri,
            Resource = p.Resource,
            RequestedScopes = p.Scopes.Select(s => _options.Scopes.Find(s) ?? new OAuthScope(s)).ToArray(),
            ExpiresAt = p.ExpiresAt,
        };
    }

    private static bool SameOrigin(Uri clientId, string redirectUri) =>
        Uri.TryCreate(redirectUri, UriKind.Absolute, out var r)
        && string.Equals(clientId.GetLeftPart(UriPartial.Authority), r.GetLeftPart(UriPartial.Authority), StringComparison.OrdinalIgnoreCase);

    public async Task<string?> ApproveAsync(string requestId, string userId, HttpContext httpContext, IEnumerable<string>? grantedScopes = null, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrEmpty(userId)) throw new ArgumentException("userId is required.", nameof(userId));
        if (httpContext is null) throw new ArgumentNullException(nameof(httpContext));
        if (string.IsNullOrEmpty(requestId)) return null;

        var now = _time.GetUtcNow();
        var peek = await _pending.GetAsync(requestId, now, cancellationToken).ConfigureAwait(false);
        if (peek is null || !ConsentBinding.Matches(httpContext, requestId)) return null;

        var granted = grantedScopes is null ? peek.Scopes : grantedScopes.Distinct(StringComparer.Ordinal).ToArray();
        if (granted.Count == 0) throw new ArgumentException("At least one scope must be granted; deny the request instead.", nameof(grantedScopes));
        if (granted.Any(s => !peek.Scopes.Contains(s, StringComparer.Ordinal)))
            throw new ArgumentException("Granted scopes must be a subset of the requested scopes.", nameof(grantedScopes));

        var p = await _pending.TakeAsync(requestId, now, cancellationToken).ConfigureAwait(false);
        if (p is null) return null;

        var rawCode = OAuthSecrets.NewToken();
        await _codes.SaveAsync(new AuthorizationCode
        {
            CodeHash = OAuthSecrets.Hash(rawCode),
            ClientId = p.ClientId,
            RedirectUri = p.RedirectUri,
            CodeChallenge = p.CodeChallenge,
            Resource = p.Resource,
            Scopes = granted,
            UserId = userId,
            FamilyId = Guid.NewGuid(),
            CreatedAt = now,
            ExpiresAt = now + _options.AuthorizationCodeLifetime,
        }, cancellationToken).ConfigureAwait(false);

        var client = await _clients.ResolveAsync(p.ClientId, cancellationToken).ConfigureAwait(false);
        await _grants.UpsertAsync(userId, p.ClientId, client?.Name ?? RedirectUriRules.HostOf(p.RedirectUri), granted, now, cancellationToken).ConfigureAwait(false);
        await _audit.LogAsync(new OAuthAuthorizeApprovedEvent(userId, p.ClientId, ScopeList.Join(granted), now), cancellationToken).ConfigureAwait(false);
        ConsentBinding.Remove(httpContext, requestId, _options.PendingRequestLifetime);

        return RedirectUriRules.AppendQuery(p.RedirectUri, new KeyValuePair<string, string?>[]
        {
            new("code", rawCode), new("state", p.State), new("iss", _options.Issuer),
        });
    }

    public async Task<string?> DenyAsync(string requestId, HttpContext httpContext, CancellationToken cancellationToken = default)
    {
        if (httpContext is null) throw new ArgumentNullException(nameof(httpContext));
        if (string.IsNullOrEmpty(requestId) || !ConsentBinding.Matches(httpContext, requestId)) return null;
        var now = _time.GetUtcNow();
        var p = await _pending.TakeAsync(requestId, now, cancellationToken).ConfigureAwait(false);
        if (p is null) return null;

        await _audit.LogAsync(new OAuthAuthorizeDeniedEvent(p.ClientId, now), cancellationToken).ConfigureAwait(false);
        ConsentBinding.Remove(httpContext, requestId, _options.PendingRequestLifetime);
        return RedirectUriRules.AppendQuery(p.RedirectUri, new KeyValuePair<string, string?>[]
        {
            new("error", "access_denied"), new("error_description", "The user denied the request."), new("state", p.State), new("iss", _options.Issuer),
        });
    }

    public async Task<string?> TryAutoApproveAsync(string requestId, string userId, HttpContext httpContext, CancellationToken cancellationToken = default)
    {
        if (httpContext is null) throw new ArgumentNullException(nameof(httpContext));
        if (!_options.RememberConsent || string.IsNullOrEmpty(requestId) || string.IsNullOrEmpty(userId)) return null;
        if (!ConsentBinding.Matches(httpContext, requestId)) return null;
        var p = await _pending.GetAsync(requestId, _time.GetUtcNow(), cancellationToken).ConfigureAwait(false);
        if (p is null) return null;
        var grant = await _grants.GetAsync(userId, p.ClientId, cancellationToken).ConfigureAwait(false);
        if (grant is null || p.Scopes.Any(s => !grant.Scopes.Contains(s, StringComparer.Ordinal))) return null;
        return await ApproveAsync(requestId, userId, httpContext, null, cancellationToken).ConfigureAwait(false);
    }
}

internal sealed class OAuthGrantService : IOAuthGrantService
{
    private readonly IOAuthGrantStore _grants;
    private readonly IOAuthRefreshTokenStore _refresh;
    private readonly IAuthAuditLogger _audit;
    private readonly TimeProvider _time;

    public OAuthGrantService(IOAuthGrantStore grants, IOAuthRefreshTokenStore refresh, IAuthAuditLogger audit, TimeProvider time)
    {
        _grants = grants;
        _refresh = refresh;
        _audit = audit;
        _time = time;
    }

    public Task<IReadOnlyList<OAuthGrant>> ListForUserAsync(string userId, CancellationToken cancellationToken = default) =>
        _grants.ListForUserAsync(userId, cancellationToken);

    public async Task<bool> RevokeAsync(string userId, string clientId, CancellationToken cancellationToken = default)
    {
        var now = _time.GetUtcNow();
        var removed = await _grants.DeleteAsync(userId, clientId, cancellationToken).ConfigureAwait(false);
        var killed = await _refresh.RevokeForUserClientAsync(userId, clientId, now, cancellationToken).ConfigureAwait(false);
        if (removed || killed > 0)
            await _audit.LogAsync(new OAuthGrantRevokedEvent(userId, clientId, now), cancellationToken).ConfigureAwait(false);
        return removed || killed > 0;
    }

    public async Task<int> RevokeAllAsync(string userId, CancellationToken cancellationToken = default)
    {
        var now = _time.GetUtcNow();
        var grants = await _grants.ListForUserAsync(userId, cancellationToken).ConfigureAwait(false);
        var removed = await _grants.DeleteAllForUserAsync(userId, cancellationToken).ConfigureAwait(false);
        await _refresh.RevokeForUserAsync(userId, now, cancellationToken).ConfigureAwait(false);
        foreach (var g in grants)
            await _audit.LogAsync(new OAuthGrantRevokedEvent(userId, g.ClientId, now), cancellationToken).ConfigureAwait(false);
        return removed;
    }
}
