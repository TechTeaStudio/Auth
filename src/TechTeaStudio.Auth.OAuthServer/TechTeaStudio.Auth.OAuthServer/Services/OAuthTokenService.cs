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
}

internal sealed class OAuthTokenService
{
    private readonly OAuthServerOptions _options;
    private readonly OAuthClientResolver _clients;
    private readonly IOAuthCodeStore _codes;
    private readonly IOAuthRefreshTokenStore _refresh;
    private readonly IOAuthGrantStore _grants;
    private readonly ITokenProvider _tokens;
    private readonly IAuthAuditLogger _audit;
    private readonly TimeProvider _time;

    public OAuthTokenService(
        IOptions<OAuthServerOptions> options, OAuthClientResolver clients, IOAuthCodeStore codes,
        IOAuthRefreshTokenStore refresh, IOAuthGrantStore grants, ITokenProvider tokens, IAuthAuditLogger audit, TimeProvider time)
    {
        _options = options.Value;
        _clients = clients;
        _codes = codes;
        _refresh = refresh;
        _grants = grants;
        _tokens = tokens;
        _audit = audit;
        _time = time;
    }

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

    private async Task<TokenEndpointResult> ExchangeCodeAsync(OAuthClient client, IFormCollection form, CancellationToken ct)
    {
        var rawCode = form["code"].ToString();
        var verifier = form["code_verifier"].ToString();
        var redirectUri = form["redirect_uri"].ToString();
        var resource = form["resource"].ToString();
        if (rawCode.Length == 0 || verifier.Length == 0 || redirectUri.Length == 0)
            return TokenEndpointResult.Error("invalid_request", "code, code_verifier and redirect_uri are required.");

        var now = _time.GetUtcNow();
        var consumed = await _codes.TryConsumeAsync(OAuthSecrets.Hash(rawCode), now, ct).ConfigureAwait(false);
        if (consumed is null) return TokenEndpointResult.Error("invalid_grant", "The authorization code is invalid.");

        var code = consumed.Code;
        if (consumed.AlreadyConsumed)
        {
            var burned = await _refresh.RevokeFamilyAsync(code.FamilyId, now, ct).ConfigureAwait(false);
            await _audit.LogAsync(new OAuthCodeReplayedEvent(code.UserId, code.ClientId, code.FamilyId, now), ct).ConfigureAwait(false);
            if (burned > 0)
                await _audit.LogAsync(new OAuthFamilyBurnedEvent(code.UserId, code.ClientId, code.FamilyId, "code_replay", now), ct).ConfigureAwait(false);
            return TokenEndpointResult.Error("invalid_grant", "The authorization code is invalid.");
        }

        if (code.ExpiresAt <= now
            || !string.Equals(code.ClientId, client.ClientId, StringComparison.Ordinal)
            || !string.Equals(code.RedirectUri, redirectUri, StringComparison.Ordinal)
            || !Pkce.Verify(verifier, code.CodeChallenge))
            return TokenEndpointResult.Error("invalid_grant", "The authorization code is invalid.");

        if (resource.Length > 0 && !string.Equals(resource, code.Resource, StringComparison.Ordinal))
            return TokenEndpointResult.Error("invalid_target", "resource does not match the authorization request.");

        var response = await IssueAsync(client.ClientId, code.UserId, code.Scopes, code.Resource, code.FamilyId, now, ct).ConfigureAwait(false);
        await _grants.TouchAsync(code.UserId, client.ClientId, now, ct).ConfigureAwait(false);
        await _audit.LogAsync(new OAuthCodeExchangedEvent(code.UserId, client.ClientId, now), ct).ConfigureAwait(false);
        return response;
    }

    private async Task<TokenEndpointResult> RefreshAsync(OAuthClient client, IFormCollection form, CancellationToken ct)
    {
        var raw = form["refresh_token"].ToString();
        if (raw.Length == 0) return TokenEndpointResult.Error("invalid_request", "refresh_token is required.");

        var now = _time.GetUtcNow();
        var hash = OAuthSecrets.Hash(raw);
        var token = await _refresh.GetByHashAsync(hash, ct).ConfigureAwait(false);
        var dead = TokenEndpointResult.Error("invalid_grant", "The refresh token is invalid.");

        if (token is null || !string.Equals(token.ClientId, client.ClientId, StringComparison.Ordinal)) return dead;
        if (token.RevokedAt is not null || token.ExpiresAt <= now) return dead;

        if (token.RotatedAt is { } rotatedAt)
        {
            var withinGrace = now - rotatedAt < _options.RefreshRotationGrace;
            await _audit.LogAsync(new OAuthRefreshReusedEvent(token.UserId, token.ClientId, token.FamilyId, withinGrace, now), ct).ConfigureAwait(false);
            if (!withinGrace)
            {
                await _refresh.RevokeFamilyAsync(token.FamilyId, now, ct).ConfigureAwait(false);
                await _audit.LogAsync(new OAuthFamilyBurnedEvent(token.UserId, token.ClientId, token.FamilyId, "refresh_reuse", now), ct).ConfigureAwait(false);
            }
            return dead;
        }

        var resource = form["resource"].ToString();
        if (resource.Length > 0 && !string.Equals(resource, token.Resource, StringComparison.Ordinal))
            return TokenEndpointResult.Error("invalid_target", "resource does not match the original grant.");

        var scopes = token.Scopes;
        var requested = ScopeList.Split(form["scope"].ToString());
        if (requested.Count > 0)
        {
            if (requested.Any(s => !token.Scopes.Contains(s, StringComparer.Ordinal)))
                return TokenEndpointResult.Error("invalid_scope", "Requested scope exceeds the original grant.");
            scopes = requested;
        }

        var newRaw = OAuthSecrets.NewToken(48);
        var newHash = OAuthSecrets.Hash(newRaw);
        if (!await _refresh.TryRotateAsync(token.Id, newHash, now, ct).ConfigureAwait(false)) return dead;

        await _refresh.CreateAsync(NewRefresh(newHash, token.FamilyId, client.ClientId, token.UserId, scopes, token.Resource, now), ct).ConfigureAwait(false);
        await _grants.TouchAsync(token.UserId, client.ClientId, now, ct).ConfigureAwait(false);
        await _audit.LogAsync(new OAuthRefreshRotatedEvent(token.UserId, client.ClientId, token.FamilyId, now), ct).ConfigureAwait(false);
        return Success(MintAccess(client.ClientId, token.UserId, scopes, token.Resource), newRaw, scopes);
    }

    public async Task RevokeAsync(IFormCollection form, CancellationToken ct)
    {
        var raw = form["token"].ToString();
        if (raw.Length == 0) return;
        var token = await _refresh.GetByHashAsync(OAuthSecrets.Hash(raw), ct).ConfigureAwait(false);
        if (token is null) return;

        var clientId = form["client_id"].ToString();
        if (clientId.Length > 0 && !string.Equals(clientId, token.ClientId, StringComparison.Ordinal)) return;

        var now = _time.GetUtcNow();
        if (await _refresh.RevokeFamilyAsync(token.FamilyId, now, ct).ConfigureAwait(false) > 0)
            await _audit.LogAsync(new OAuthFamilyBurnedEvent(token.UserId, token.ClientId, token.FamilyId, "revoked_by_client", now), ct).ConfigureAwait(false);
    }

    private async Task<TokenEndpointResult> IssueAsync(
        string clientId, string userId, IReadOnlyList<string> scopes, string resource, Guid familyId, DateTimeOffset now, CancellationToken ct)
    {
        var raw = OAuthSecrets.NewToken(48);
        await _refresh.CreateAsync(NewRefresh(OAuthSecrets.Hash(raw), familyId, clientId, userId, scopes, resource, now), ct).ConfigureAwait(false);
        return Success(MintAccess(clientId, userId, scopes, resource), raw, scopes);
    }

    private OAuthRefreshToken NewRefresh(string hash, Guid familyId, string clientId, string userId, IReadOnlyList<string> scopes, string resource, DateTimeOffset now) => new()
    {
        Id = Guid.NewGuid(),
        TokenHash = hash,
        FamilyId = familyId,
        ClientId = clientId,
        UserId = userId,
        Scopes = scopes,
        Resource = resource,
        CreatedAt = now,
        ExpiresAt = now + _options.RefreshTokenLifetime,
    };

    private string MintAccess(string clientId, string userId, IReadOnlyList<string> scopes, string resource) =>
        _tokens.CreateToken(userId,
            new[] { new Claim("client_id", clientId), new Claim("scope", ScopeList.Join(scopes)) },
            new TokenDescriptor { Audience = resource, Issuer = _options.Issuer, Lifetime = _options.AccessTokenLifetime });

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
