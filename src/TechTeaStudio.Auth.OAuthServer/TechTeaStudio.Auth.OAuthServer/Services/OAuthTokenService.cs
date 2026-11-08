using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using TechTeaStudio.Auth.Abstractions;
using TechTeaStudio.Auth.Observability;
using TechTeaStudio.Auth.OAuthServer.Abstractions;
using TechTeaStudio.Auth.OAuthServer.Clients;
using TechTeaStudio.Auth.OAuthServer.Internal;

namespace TechTeaStudio.Auth.OAuthServer.Services;

/// <summary>A token-endpoint answer: HTTP status and an RFC 6749 JSON body.</summary>
internal sealed record TokenEndpointResult(int Status, IReadOnlyDictionary<string, object?> Body)
{
    public static TokenEndpointResult Error(string error, string? description = null, int status = 400) =>
        new(status, new Dictionary<string, object?> { ["error"] = error, ["error_description"] = description });

    public static TokenEndpointResult Empty { get; } = new(200, new Dictionary<string, object?>());
}

internal sealed class OAuthTokenService
{
    public const string AccessTokenType = "at+jwt";

    private readonly OAuthServerOptions _options;
    private readonly OAuthClientResolver _clients;
    private readonly IOAuthCodeStore _codes;
    private readonly IOAuthRefreshTokenStore _refresh;
    private readonly IOAuthGrantStore _grants;
    private readonly ITokenProvider _tokens;
    private readonly IAuthAuditLogger _audit;
    private readonly TimeProvider _time;
    private readonly IOAuthUserValidator? _users;

    public OAuthTokenService(
        IOptions<OAuthServerOptions> options, OAuthClientResolver clients, IOAuthCodeStore codes,
        IOAuthRefreshTokenStore refresh, IOAuthGrantStore grants, ITokenProvider tokens, IAuthAuditLogger audit, TimeProvider time,
        IOAuthUserValidator? users = null)
    {
        _options = options.Value;
        _clients = clients;
        _codes = codes;
        _refresh = refresh;
        _grants = grants;
        _tokens = tokens;
        _audit = audit;
        _time = time;
        _users = users;
    }

    private static TokenEndpointResult Dead => TokenEndpointResult.Error("invalid_grant", "The grant is invalid.");

    public async Task<TokenEndpointResult> HandleAsync(IFormCollection form, CancellationToken ct)
    {
        var grantType = form["grant_type"].ToString();
        if (grantType != "authorization_code" && grantType != "refresh_token")
            return TokenEndpointResult.Error("unsupported_grant_type", "Supported: authorization_code, refresh_token.");

        var client = await _clients.ResolveAsync(form["client_id"].ToString(), ct).ConfigureAwait(false);
        if (client is null || !Authenticate(client, form["client_secret"].ToString()))
            return TokenEndpointResult.Error("invalid_client", "Client authentication failed.", 401);

        return grantType == "authorization_code"
            ? await ExchangeCodeAsync(client, form, ct).ConfigureAwait(false)
            : await RefreshAsync(client, form, ct).ConfigureAwait(false);
    }

    private static bool Authenticate(OAuthClient client, string secret)
    {
        if (!client.IsConfidential) return secret.Length == 0;
        if (secret.Length == 0) return false;
        return CryptographicOperations.FixedTimeEquals(
            Encoding.ASCII.GetBytes(OAuthSecrets.Hash(secret)), Encoding.ASCII.GetBytes(client.SecretHash!));
    }

    private async Task<bool> IsActiveAsync(string userId, CancellationToken ct) =>
        _users is null || await _users.IsActiveAsync(userId, ct).ConfigureAwait(false);

    private async Task<TokenEndpointResult> BurnAsync(Guid familyId, string userId, string clientId, string reason, DateTimeOffset now, CancellationToken ct)
    {
        await _refresh.RevokeFamilyAsync(familyId, now, ct).ConfigureAwait(false);
        await _audit.LogAsync(new OAuthFamilyBurnedEvent(userId, clientId, familyId, reason, now), ct).ConfigureAwait(false);
        return Dead;
    }

    private async Task<TokenEndpointResult> ExchangeCodeAsync(OAuthClient client, IFormCollection form, CancellationToken ct)
    {
        var rawCode = form["code"].ToString();
        var verifier = form["code_verifier"].ToString();
        var redirectUri = form["redirect_uri"].ToString();
        var resource = form["resource"].ToString();
        if (rawCode.Length == 0 || verifier.Length == 0 || redirectUri.Length == 0)
            return TokenEndpointResult.Error("invalid_request", "code, code_verifier and redirect_uri are required.");

        var now = _time.GetUtcNow();
        var hash = OAuthSecrets.Hash(rawCode);
        var code = await _codes.GetAsync(hash, ct).ConfigureAwait(false);
        if (code is null) return Dead;

        // Every binding is verified BEFORE the code is consumed or a replay is acted on, so a request that does
        // not hold the verifier and the client's identity can neither burn a legitimate code nor a legitimate family.
        if (!string.Equals(code.ClientId, client.ClientId, StringComparison.Ordinal)
            || !string.Equals(code.RedirectUri, redirectUri, StringComparison.Ordinal)
            || !Pkce.Verify(verifier, code.CodeChallenge))
            return Dead;

        if (resource.Length > 0 && !string.Equals(resource, code.Resource, StringComparison.Ordinal))
            return TokenEndpointResult.Error("invalid_target", "resource does not match the authorization request.");

        if (code.ConsumedAt is not null) return await ReplayAsync(code, now, ct).ConfigureAwait(false);
        if (code.ExpiresAt <= now) return Dead;

        var consumed = await _codes.TryConsumeAsync(hash, now, ct).ConfigureAwait(false);
        if (consumed is null) return Dead;
        if (consumed.AlreadyConsumed) return await ReplayAsync(consumed.Code, now, ct).ConfigureAwait(false);

        if (!await IsActiveAsync(code.UserId, ct).ConfigureAwait(false))
            return await BurnAsync(code.FamilyId, code.UserId, code.ClientId, "user_inactive", now, ct).ConfigureAwait(false);

        return await IssueFirstAsync(client, code, now, ct).ConfigureAwait(false);
    }

    private async Task<TokenEndpointResult> ReplayAsync(AuthorizationCode code, DateTimeOffset now, CancellationToken ct)
    {
        var burned = await _refresh.RevokeFamilyAsync(code.FamilyId, now, ct).ConfigureAwait(false);
        await _audit.LogAsync(new OAuthCodeReplayedEvent(code.UserId, code.ClientId, code.FamilyId, now), ct).ConfigureAwait(false);
        if (burned > 0)
            await _audit.LogAsync(new OAuthFamilyBurnedEvent(code.UserId, code.ClientId, code.FamilyId, "code_replay", now), ct).ConfigureAwait(false);
        return Dead;
    }

    private async Task<TokenEndpointResult> IssueFirstAsync(OAuthClient client, AuthorizationCode code, DateTimeOffset now, CancellationToken ct)
    {
        await _refresh.EnsureFamilyAsync(new OAuthRefreshFamily
        {
            FamilyId = code.FamilyId,
            UserId = code.UserId,
            ClientId = client.ClientId,
            CreatedAt = now,
            ExpiresAt = now + _options.RefreshFamilyAbsoluteLifetime,
        }, ct).ConfigureAwait(false);

        var raw = OAuthSecrets.NewToken(48);
        await _refresh.CreateAsync(
            NewRefresh(OAuthSecrets.Hash(raw), code.FamilyId, client.ClientId, code.UserId, code.Scopes, code.Resource, now, now + _options.RefreshTokenLifetime), ct).ConfigureAwait(false);

        if (!await StillGrantedAsync(code.FamilyId, code.UserId, client.ClientId, ct).ConfigureAwait(false))
            return await BurnAsync(code.FamilyId, code.UserId, client.ClientId, "revoked_during_issue", now, ct).ConfigureAwait(false);

        await _grants.TouchAsync(code.UserId, client.ClientId, now, ct).ConfigureAwait(false);
        await _audit.LogAsync(new OAuthCodeExchangedEvent(code.UserId, client.ClientId, now), ct).ConfigureAwait(false);
        return Success(MintAccess(client.ClientId, code.UserId, code.Scopes, code.Resource), raw, code.Scopes);
    }

    /// <summary>The re-check that closes the revoke-versus-issue races: the family must not have been revoked, and the user must still hold the grant.</summary>
    private async Task<bool> StillGrantedAsync(Guid familyId, string userId, string clientId, CancellationToken ct)
    {
        var family = await _refresh.GetFamilyAsync(familyId, ct).ConfigureAwait(false);
        if (family?.RevokedAt is not null) return false;
        return await _grants.GetAsync(userId, clientId, ct).ConfigureAwait(false) is not null;
    }

    private async Task<TokenEndpointResult> RefreshAsync(OAuthClient client, IFormCollection form, CancellationToken ct)
    {
        var raw = form["refresh_token"].ToString();
        if (raw.Length == 0) return TokenEndpointResult.Error("invalid_request", "refresh_token is required.");

        var now = _time.GetUtcNow();
        var token = await _refresh.GetByHashAsync(OAuthSecrets.Hash(raw), ct).ConfigureAwait(false);

        if (token is null || !string.Equals(token.ClientId, client.ClientId, StringComparison.Ordinal)) return Dead;
        if (token.RevokedAt is not null || token.ExpiresAt <= now) return Dead;

        if (token.RotatedAt is { } rotatedAt)
        {
            var withinGrace = now - rotatedAt < _options.RefreshRotationGrace;
            await _audit.LogAsync(new OAuthRefreshReusedEvent(token.UserId, token.ClientId, token.FamilyId, withinGrace, now), ct).ConfigureAwait(false);
            if (!withinGrace)
                await BurnAsync(token.FamilyId, token.UserId, token.ClientId, "refresh_reuse", now, ct).ConfigureAwait(false);
            return Dead;
        }

        var family = await _refresh.GetFamilyAsync(token.FamilyId, ct).ConfigureAwait(false);
        if (family is not null)
        {
            if (family.RevokedAt is not null) return Dead;
            if (family.ExpiresAt <= now)
                return await BurnAsync(token.FamilyId, token.UserId, token.ClientId, "family_expired", now, ct).ConfigureAwait(false);
        }

        if (!await IsActiveAsync(token.UserId, ct).ConfigureAwait(false))
            return await BurnAsync(token.FamilyId, token.UserId, token.ClientId, "user_inactive", now, ct).ConfigureAwait(false);

        var resource = form["resource"].ToString();
        if (resource.Length > 0 && !string.Equals(resource, token.Resource, StringComparison.Ordinal))
            return TokenEndpointResult.Error("invalid_target", "resource does not match the original grant.");

        var accessScopes = token.Scopes;
        var requested = ScopeList.Split(form["scope"].ToString());
        if (requested.Count > 0)
        {
            if (requested.Any(s => !token.Scopes.Contains(s, StringComparer.Ordinal)))
                return TokenEndpointResult.Error("invalid_scope", "Requested scope exceeds the original grant.");
            accessScopes = requested;
        }

        var newRaw = OAuthSecrets.NewToken(48);
        var newHash = OAuthSecrets.Hash(newRaw);
        if (!await _refresh.TryRotateAsync(token.Id, newHash, now, ct).ConfigureAwait(false)) return Dead;

        var expires = now + _options.RefreshTokenLifetime;
        if (family is not null && family.ExpiresAt < expires) expires = family.ExpiresAt;
        // The successor keeps the ORIGINAL scopes: narrowing one access token must not shrink the grant.
        await _refresh.CreateAsync(NewRefresh(newHash, token.FamilyId, client.ClientId, token.UserId, token.Scopes, token.Resource, now, expires), ct).ConfigureAwait(false);

        if (!await StillGrantedAsync(token.FamilyId, token.UserId, client.ClientId, ct).ConfigureAwait(false))
            return await BurnAsync(token.FamilyId, token.UserId, client.ClientId, "revoked_during_refresh", now, ct).ConfigureAwait(false);

        await _grants.TouchAsync(token.UserId, client.ClientId, now, ct).ConfigureAwait(false);
        await _audit.LogAsync(new OAuthRefreshRotatedEvent(token.UserId, client.ClientId, token.FamilyId, now), ct).ConfigureAwait(false);
        return Success(MintAccess(client.ClientId, token.UserId, accessScopes, token.Resource), newRaw, accessScopes);
    }

    /// <summary>
    /// RFC 7009. A confidential client authenticates exactly as at the token endpoint (failure: 401 invalid_client).
    /// A token presented by a different client, or by an anonymous caller when its owner is confidential, is left alone
    /// and still answers 200.
    /// </summary>
    public async Task<TokenEndpointResult> RevokeAsync(IFormCollection form, CancellationToken ct)
    {
        var raw = form["token"].ToString();
        var clientId = form["client_id"].ToString();

        OAuthClient? caller = null;
        if (clientId.Length > 0)
        {
            caller = await _clients.ResolveAsync(clientId, ct).ConfigureAwait(false);
            if (caller is null || !Authenticate(caller, form["client_secret"].ToString()))
                return TokenEndpointResult.Error("invalid_client", "Client authentication failed.", 401);
        }

        if (raw.Length == 0) return TokenEndpointResult.Empty;
        var token = await _refresh.GetByHashAsync(OAuthSecrets.Hash(raw), ct).ConfigureAwait(false);
        if (token is null) return TokenEndpointResult.Empty;

        if (caller is null)
        {
            var owner = await _clients.ResolveAsync(token.ClientId, ct).ConfigureAwait(false);
            if (owner is null || owner.IsConfidential) return TokenEndpointResult.Empty;
        }
        else if (!string.Equals(caller.ClientId, token.ClientId, StringComparison.Ordinal))
        {
            return TokenEndpointResult.Empty;
        }

        var now = _time.GetUtcNow();
        if (await _refresh.RevokeFamilyAsync(token.FamilyId, now, ct).ConfigureAwait(false) > 0)
            await _audit.LogAsync(new OAuthFamilyBurnedEvent(token.UserId, token.ClientId, token.FamilyId, "revoked_by_client", now), ct).ConfigureAwait(false);
        return TokenEndpointResult.Empty;
    }

    private static OAuthRefreshToken NewRefresh(
        string hash, Guid familyId, string clientId, string userId, IReadOnlyList<string> scopes, string resource, DateTimeOffset now, DateTimeOffset expires) => new()
    {
        Id = Guid.NewGuid(),
        TokenHash = hash,
        FamilyId = familyId,
        ClientId = clientId,
        UserId = userId,
        Scopes = scopes,
        Resource = resource,
        CreatedAt = now,
        ExpiresAt = expires,
    };

    private string MintAccess(string clientId, string userId, IReadOnlyList<string> scopes, string resource) =>
        _tokens.CreateToken(userId,
            new[] { new Claim("client_id", clientId), new Claim("scope", ScopeList.Join(scopes)) },
            new TokenDescriptor { Audience = resource, Issuer = _options.Issuer, Lifetime = _options.AccessTokenLifetime, TokenType = AccessTokenType });

    private TokenEndpointResult Success(string access, string refresh, IReadOnlyList<string> scopes) =>
        new(200, new Dictionary<string, object?>
        {
            ["access_token"] = access,
            ["token_type"] = "Bearer",
            ["expires_in"] = (int)_options.AccessTokenLifetime.TotalSeconds,
            ["refresh_token"] = refresh,
            ["scope"] = ScopeList.Join(scopes),
        });
}
