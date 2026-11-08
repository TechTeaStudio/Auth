using System.Text.Json;
using Microsoft.Extensions.Options;
using TechTeaStudio.Auth.Observability;
using TechTeaStudio.Auth.OAuthServer.Abstractions;
using TechTeaStudio.Auth.OAuthServer.Clients;
using TechTeaStudio.Auth.OAuthServer.Internal;

namespace TechTeaStudio.Auth.OAuthServer.Services;

/// <summary>RFC 7591 dynamic client registration, public clients only.</summary>
internal sealed class OAuthRegistrationService
{
    private readonly OAuthServerOptions _options;
    private readonly IOAuthClientStore _store;
    private readonly IAuthAuditLogger _audit;
    private readonly TimeProvider _time;

    public OAuthRegistrationService(IOptions<OAuthServerOptions> options, IOAuthClientStore store, IAuthAuditLogger audit, TimeProvider time)
    {
        _options = options.Value;
        _store = store;
        _audit = audit;
        _time = time;
    }

    public async Task<TokenEndpointResult> RegisterAsync(JsonElement body, CancellationToken ct)
    {
        var parsed = ClientMetadataParser.Parse(body, _options, out var error);
        if (parsed is null) return TokenEndpointResult.Error(error!.Code, error.Description);

        var now = _time.GetUtcNow();
        var client = new OAuthClient
        {
            ClientId = "dcr_" + OAuthSecrets.NewToken(16),
            Name = parsed.Name,
            LogoUri = parsed.LogoUri,
            ClientUri = parsed.ClientUri,
            RedirectUris = parsed.RedirectUris,
            Source = OAuthClientSource.Dynamic,
            CreatedAt = now,
        };
        await _store.SaveAsync(client, ct).ConfigureAwait(false);
        await _audit.LogAsync(new OAuthClientRegisteredEvent(client.ClientId, client.Name, now), ct).ConfigureAwait(false);

        var response = new Dictionary<string, object?>
        {
            ["client_id"] = client.ClientId,
            ["client_id_issued_at"] = now.ToUnixTimeSeconds(),
            ["redirect_uris"] = client.RedirectUris,
            ["token_endpoint_auth_method"] = "none",
            ["grant_types"] = new[] { "authorization_code", "refresh_token" },
            ["response_types"] = new[] { "code" },
            ["client_name"] = client.Name,
            ["logo_uri"] = client.LogoUri,
            ["client_uri"] = client.ClientUri,
        };
        return new TokenEndpointResult(201, response);
    }
}
