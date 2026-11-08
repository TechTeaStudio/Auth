# OAuth 2.1 authorization server (MCP clients)

`TechTeaStudio.Auth.OAuthServer` lets your app be the authorization server for MCP clients such as Claude, ChatGPT, Claude Code and Cursor: the user clicks "connect", signs in to your app, approves, and the client receives short-lived access tokens plus a rotating refresh token.

This is the opposite direction of `TechTeaStudio.Auth.OAuth.*` (sign in WITH Google or GitHub, see [OAUTH.md](OAUTH.md)). The two do not interact.

Profile: the MCP authorization spec revision 2026-07-28, which is OAuth 2.1 + RFC 8414 metadata + RFC 7636 PKCE (S256 only) + RFC 8707 resource indicators + RFC 9207 `iss` + Client ID Metadata Documents. RFC 7591 dynamic registration is deprecated in that spec but still used by some clients, so it is on by default and switchable.

## Packages

- `TechTeaStudio.Auth.OAuthServer`: contracts (`Abstractions/`), services, endpoint mapping, in-memory stores.
- `TechTeaStudio.Auth.OAuthServer.EFCore`: EF Core entities, `AddTechTeaStudioOAuthServerTables`, store classes.

## Wiring

```csharp
builder.Services.AddTechTeaStudioAuth(builder.Configuration);   // ITokenProvider + signing keys

builder.Services
    .AddTechTeaStudioOAuthServer(o =>
    {
        o.Issuer = "https://chronos.example.com";                 // absolute, configured, never derived from the request
        o.ProtectedResources.Add("https://chronos.example.com/mcp");
        o.Scopes.Add("tasks:read", "Read your tasks")
                .Add("tasks:write", "Create and edit your tasks");
        o.DefaultScopes.Add("tasks:read");                        // used when a request names no scope
        o.ConsentPath = "/oauth/consent";                         // your page
        // o.RememberConsent = true;                              // opt in to skipping consent for covered grants
        // o.EnableDynamicRegistration = false;
    })
    .UseEfCoreStores<AppDbContext>();                              // omit for in-memory (tests, samples)

// DbContext.OnModelCreating
modelBuilder.AddTechTeaStudioOAuthServerTables();                  // prefix "TtsOAuth"

app.UseRouting();
app.UseAuthentication();
app.UseAuthorization();
app.MapTechTeaStudioOAuthServer();                                // metadata, authorize, token, revoke, register
```

`MapTechTeaStudioOAuthServer()` returns a convention builder, so `.RequireRateLimiting("oauth")` and `.RequireCors("mcp")` apply to every mapped endpoint. The module does neither on its own. Rate limit at least the token, register and authorize endpoints; the paths are constants in `OAuthServerPaths`.

Options are validated at startup (`ValidateOnStart`): absolute https issuer (http only for loopback), at least one protected resource and one scope, sane lifetimes, valid pre-registered clients.

### Options worth knowing

| Option | Default | Meaning |
| --- | --- | --- |
| `AccessTokenLifetime` | 60 min | access token `exp` |
| `RefreshTokenLifetime` | 30 days | each rotation restarts it |
| `AuthorizationCodeLifetime` | 60 s | |
| `PendingRequestLifetime` | 10 min | time the user has on the login and consent pages |
| `RefreshRotationGrace` | 30 s | see "Refresh tokens" |
| `EnableDynamicRegistration` | true | `POST /oauth/register` |
| `EnableClientIdMetadataDocuments` | true | https `client_id` fetched as a document |
| `RememberConsent` | false | see below |
| `Clients` | empty | pre-registered clients; a `ClientSecret` makes one confidential (`client_secret_post`) |

## Endpoints

| Method and path | Purpose |
| --- | --- |
| `GET /.well-known/oauth-authorization-server` | RFC 8414 metadata (also at `.../oauth-authorization-server/<issuer path>` when the issuer has a path). `Cache-Control: public, max-age=300`. |
| `GET /oauth/authorize` | validates the request, stores it, redirects to `ConsentPath?request=<id>` |
| `POST /oauth/token` | `authorization_code` and `refresh_token` grants, form-encoded, RFC 6749 JSON errors, `Cache-Control: no-store` |
| `POST /oauth/revoke` | RFC 7009; refresh tokens revoke their family; unknown tokens still answer 200 |
| `POST /oauth/register` | RFC 7591, public clients only (absent when DCR is off) |

Publishing the protected resource metadata (RFC 9728) of your MCP server, the `WWW-Authenticate` challenge on it, and validating the access tokens (`aud` must equal your resource) stay in your host.

## The consent page contract

The module owns validation; your host owns login and the consent screen. `GET /oauth/authorize` answers `302` to `ConsentPath?request=<id>` and only that id has to survive your login redirect.

On that page, with `IOAuthAuthorizationService`:

```csharp
app.MapGet("/oauth/consent", async (string request, HttpContext ctx, IOAuthAuthorizationService oauth) =>
{
    if (ctx.User.Identity?.IsAuthenticated != true)
        return Results.Challenge(new() { RedirectUri = ctx.Request.GetEncodedPathAndQuery() });  // back to the same URL after login

    var userId = ctx.User.FindFirst("sub")!.Value;

    var auto = await oauth.TryAutoApproveAsync(request, userId);   // null unless RememberConsent and a covering grant
    if (auto is not null) return Results.Redirect(auto);

    var info = await oauth.GetPendingAsync(request);               // null: unknown, expired or used
    if (info is null) return Results.Problem("This authorization request has expired.", statusCode: 410);

    // render info.ClientName, info.ClientLogoUri, info.RedirectHost (REQUIRED, see below),
    // info.RequestedScopes (name + description), info.Resource
    ...
});

// the form posts back:
//   approve: oauth.ApproveAsync(request, userId, grantedScopes)  -> redirect URL (code, state, iss), or null if expired
//   deny:    oauth.DenyAsync(request)                            -> redirect URL (error=access_denied, state, iss)
```

Rules for the consent screen:

- Show `RedirectHost`. The client name is self-asserted (anyone can call themselves "Claude" in a metadata document or a registration); the host name the code will be sent to is the only part of the identity a user can check.
- `ApproveAsync` accepts a subset of the requested scopes (downscoping). Granting a scope that was not requested, or an empty set, throws `ArgumentException` and leaves the request pending. To refuse, call `DenyAsync`.
- `ApproveAsync` and `DenyAsync` are single use: the second call returns `null`. Return the result with a plain `Redirect`; do not render it.
- `RememberConsent` is off by default. When on, `TryAutoApproveAsync` approves without a screen only if the user's stored grant for this client covers every requested scope. Even then you still render consent for first-time clients and widened scope requests.
- Do not log the redirect URL: it carries the authorization code.

## Clients

Resolved in this order:

1. Pre-registered: `o.Clients` or an `IOAuthClientStore` row.
2. Client ID Metadata Document: a `client_id` that is an https URL (with a path, no fragment, no user info). Fetched through `IClientMetadataFetcher`. The document's `client_id` must equal the URL, `redirect_uris` must be present and valid, `token_endpoint_auth_method` must be `none` or absent, `client_secret` must be absent. `client_name` is stripped of control characters and capped (100); `logo_uri` and `client_uri` are kept only if https and short. Cached per `Cache-Control` (max 24 h; 1 h without a header; none for `no-store`); a failed fetch is cached 30 s so a bad `client_id` cannot hammer the fetcher.
3. Dynamic registration (`POST /oauth/register`): public clients only, redirect URIs https or loopback, at most 10, no fragment.

Redirect URIs: exact string match against the client's list, except loopback (`http://localhost/...`, `http://127.0.0.1/...`, `http://[::1]/...`) where any port matches a registered loopback URI with the same host, path and query (RFC 8252 section 7.3; Claude Code picks a random port). Custom schemes are not accepted. The known real redirects work as registered: `https://claude.ai/api/mcp/auth_callback`, `https://chatgpt.com/connector_platform_oauth_redirect`, `https://chatgpt.com/connector/oauth/{id}` (a per-connector id, so register or declare the exact URI).

### The default metadata fetcher

`HttpClientMetadataFetcher`: https only, no redirects, no proxy, no cookies, 5 s timeout over the whole exchange, 64 KB cap, JSON content type required. The SSRF guard runs in `SocketsHttpHandler.ConnectCallback`, so the address the socket actually dials is the address that is checked (a DNS answer cannot change between "check" and "use"). It refuses loopback, private, link-local (including the 169.254.169.254 metadata address), multicast, unique-local, CGNAT, benchmarking and documentation ranges, `0.0.0.0`, and IPv4-mapped or NAT64-embedded forms of all of those. If any resolved address is non-public the connection is refused. The same pass runs on net6.0. Replace it with `.UseClientMetadataFetcher<T>()` if your egress needs a policy of its own.

## Tokens

Authorization codes: 256-bit random, stored as SHA-256, single use, 60 s, bound to client, redirect URI, PKCE challenge, resource, scopes and user. A code presented twice answers `invalid_grant` and revokes the refresh family issued from the first exchange.

Access tokens: minted by `ITokenProvider` with a `TokenDescriptor`: `aud` = the resource, `iss` = the configured issuer, `sub` = the user id, `jti`, plus `client_id` and `scope` (space separated). They are self-contained JWTs signed with the key set of `AuthOptions.Jwt.Signing` and published through `MapTechTeaStudioJwks()`; they cannot be revoked individually, which is why the default lifetime is short.

Refresh tokens: rotate on every use, stored hashed, bound to client, user, scopes and resource. `scope` on refresh may narrow, never widen. The lost-race rule: a token rotated less than `RefreshRotationGrace` ago answers `invalid_grant` but does NOT burn the family (a client that retried after a network error keeps the newest token it already received); presenting it after the grace burns the whole family. Unknown, expired, revoked or foreign refresh tokens always answer `invalid_grant` (Claude depends on exactly that code to start a new authorization).

Token endpoint errors: `invalid_request`, `invalid_client` (401), `invalid_grant`, `unsupported_grant_type`, `invalid_scope`, and `invalid_target` for a `resource` that does not match the grant.

## Connected apps

```csharp
IOAuthGrantService grants;                                   // scoped
var apps = await grants.ListForUserAsync(userId);            // client name, scopes, first and last use
await grants.RevokeAsync(userId, clientId);                  // removes the grant and kills the client's refresh families
```

`IOAuthGrantStore` is the storage behind it; `IOAuthGrantStore.DeleteAsync` only removes the row.

## Stores

Interfaces in `Abstractions/`: `IOAuthClientStore`, `IOAuthPendingRequestStore`, `IOAuthCodeStore`, `IOAuthRefreshTokenStore`, `IOAuthGrantStore`. The in-memory defaults lose everything on restart and do not span processes: tests and samples only. `UseEfCoreStores<TContext>()` replaces all five; the individual `UseClientStore<T>()` ... `UseGrantStore<T>()` swap one. Stores are expected to make `TakeAsync`, `TryConsumeAsync` and `TryRotateAsync` atomic (exactly one concurrent caller wins).

EF tables: `{prefix}Clients`, `{prefix}PendingRequests`, `{prefix}Codes`, `{prefix}RefreshTokens`, `{prefix}Grants`. Instants are bigint UTC ticks. Create the tables with your usual migration flow. Pending requests, codes and refresh tokens are not purged by the module; call each store's `CleanupExpiredAsync(cutoff)` from a job of yours (the refresh store keeps rotated rows until they expire, which is what makes reuse detection possible).

## Audit

Through `IAuthAuditLogger`: `oauth.authorize.requested`, `oauth.authorize.approved`, `oauth.authorize.denied`, `oauth.code.exchanged`, `oauth.code.replayed`, `oauth.refresh.rotated`, `oauth.refresh.reused` (with `WithinGrace`), `oauth.family.burned`, `oauth.client.registered`, `oauth.client.metadata_fetch_failed`, `oauth.grant.revoked`. No event carries a token, code, verifier or pending request id.

## Security notes

- The issuer is configuration, not the request host: the app sits behind a proxy, and a host-derived issuer is a token-confusion bug waiting for a forwarded header.
- Errors before the client and redirect URI are validated are a plain 400. After that, errors go back to the validated redirect with `error`, `error_description`, `state` and `iss` (RFC 9207, advertised as `authorization_response_iss_parameter_supported`).
- `resource` is required and compared as an exact string against `ProtectedResources`; the token audience is that string. A trailing slash is a different resource.
- PKCE S256 is mandatory for every client, `plain` is refused.
- Public clients are the default and the only dynamic kind. Confidential clients exist only in configuration.
- Dynamic registration is unauthenticated by nature: rate limit it, and expect to prune unused client rows.
- Behind Cloudflare or another proxy, configure forwarded headers for your own logging and rate limiting; the module does not read them.
- Never log the consent redirect URL, token endpoint bodies or `Authorization` headers.
