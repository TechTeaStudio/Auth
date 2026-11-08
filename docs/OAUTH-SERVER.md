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
        // o.EnableDynamicRegistration = true;                    // off by default; opt in and rate limit it
    })
    .UseEfCoreStores<AppDbContext>();                              // omit for in-memory (tests, samples)

// DbContext.OnModelCreating
modelBuilder.AddTechTeaStudioOAuthServerTables();                  // prefix "TtsOAuth"

app.UseRouting();
app.UseAuthentication();
app.UseAuthorization();
app.MapTechTeaStudioOAuthServer()                                  // metadata, authorize, token, revoke, register
   .RequireRateLimiting(OAuthServerPaths.RateLimitPolicy);
```

`MapTechTeaStudioOAuthServer()` returns a convention builder, so `.RequireRateLimiting(...)` and `.RequireCors("mcp")` apply to every mapped endpoint. The module does neither on its own. Register a limiter under `OAuthServerPaths.RateLimitPolicy` (`"tts-oauth"`) and apply it as above; at minimum limit the token, register and authorize endpoints per IP. The paths are constants in `OAuthServerPaths`. An unlimited `/oauth/register` and `/oauth/authorize` are write endpoints for anonymous callers.

```csharp
builder.Services.AddRateLimiter(r => r.AddPolicy(OAuthServerPaths.RateLimitPolicy, ctx =>
    RateLimitPartition.GetFixedWindowLimiter(ctx.Connection.RemoteIpAddress?.ToString() ?? "unknown",
        _ => new FixedWindowRateLimiterOptions { PermitLimit = 30, Window = TimeSpan.FromMinutes(1) })));
```

Options are validated at startup (`ValidateOnStart`): absolute https issuer (http only for loopback), at least one protected resource and one scope, sane lifetimes, valid pre-registered clients.

### Options worth knowing

| Option | Default | Meaning |
| --- | --- | --- |
| `AccessTokenLifetime` | 60 min | access token `exp` |
| `RefreshTokenLifetime` | 30 days | each rotation restarts it |
| `AuthorizationCodeLifetime` | 60 s | |
| `PendingRequestLifetime` | 10 min | time the user has on the login and consent pages |
| `RefreshRotationGrace` | 30 s | see "Refresh tokens" |
| `RefreshFamilyAbsoluteLifetime` | 90 days | refresh stops working this long after the first exchange, however often it was used |
| `MaxPendingRequestsPerClient` | 50 | live pending requests one client id may hold |
| `MaxRedirectUrisPerClient` | 5 | also: each redirect URI is at most 512 characters |
| `EnableDynamicRegistration` | false | `POST /oauth/register`; opt in and rate limit it |
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

    var auto = await oauth.TryAutoApproveAsync(request, userId, ctx);  // null unless RememberConsent, a covering grant and a matching binding
    if (auto is not null) return Results.Redirect(auto);

    var info = await oauth.GetPendingAsync(request);               // null: unknown, expired or used
    if (info is null) return Results.Problem("This authorization request has expired.", statusCode: 410);

    ctx.Response.Headers["Content-Security-Policy"] = "frame-ancestors 'none'";   // no clickjacking of the consent button
    ctx.Response.Headers["X-Frame-Options"] = "DENY";

    // render info.ClientName, info.RedirectHost (REQUIRED), info.RequestedScopes (name + description),
    // info.Resource, info.ClientLogoUri (set for pre-registered clients only), and for metadata-document
    // clients info.ClientIdHost plus a warning when info.RedirectOriginDiffersFromClientId
    ...
});

// the form POSTs back (POST only, antiforgery validated):
app.MapPost("/oauth/consent", async (HttpContext ctx, IOAuthAuthorizationService oauth, [FromForm] ConsentForm f) =>
{
    var userId = ctx.User.FindFirst("sub")!.Value;
    var url = f.Approve
        ? await oauth.ApproveAsync(f.Request, userId, ctx, f.GrantedScopes)   // redirect URL (code, state, iss)
        : await oauth.DenyAsync(f.Request, ctx);                              // redirect URL (error=access_denied, state, iss)
    return url is null ? Results.Problem("This authorization request has expired.", statusCode: 410) : Results.Redirect(url);
});
```

### Binding a request to its browser

`GET /oauth/authorize` sets a `__Host-tts-oauth-consent` cookie (Secure, HttpOnly, SameSite=Lax, Path=/) holding a hash of the pending request id. `ApproveAsync`, `DenyAsync` and `TryAutoApproveAsync` take the `HttpContext` of the consent POST and return `null` (nothing is consumed) unless that cookie names the request. A cross-site forged POST, or a consent link opened in a different browser than the one that started the flow, therefore fails. The cookie holds up to five bindings, so parallel flows in one browser work, and a binding is removed when its request is approved or denied. The cookie needs https (browsers treat `localhost` as secure).

Host obligations that go with it: approve and deny by `POST` only, with antiforgery validation on the form; send `Content-Security-Policy: frame-ancestors 'none'` on the consent page (clickjacking); keep the consent page on the same site as `/oauth/authorize` so the Lax cookie is sent.

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
3. Dynamic registration (`POST /oauth/register`, off by default): public clients only, at most 5 redirect URIs of at most 512 characters each, https or loopback, no fragment, name capped at 100. Dynamic clients record `LastUsedAt` (at most hourly); call `IOAuthClientStore.CleanupUnusedAsync(olderThan)` from a job to delete dynamic clients that hold no grant and were not used since.

Only pre-registered clients get validation errors as redirects. For metadata-document and dynamic clients every authorize error (bad `resource`, scope, PKCE, response type) is a plain 400 page, because their redirect URI is attacker-chosen and an error redirect would make `/oauth/authorize` an open redirector. The one redirect they do get is `access_denied` after a real user clicked deny. Display text from documents has control and format characters (bidi overrides, zero-width) stripped.

Redirect URIs: exact string match against the client's list, except loopback (`http://localhost/...`, `http://127.0.0.1/...`, `http://[::1]/...`) where any port matches a registered loopback URI with the same host, path and query (RFC 8252 section 7.3; Claude Code picks a random port). Custom schemes are not accepted. The known real redirects work as registered: `https://claude.ai/api/mcp/auth_callback`, `https://chatgpt.com/connector_platform_oauth_redirect`, `https://chatgpt.com/connector/oauth/{id}` (a per-connector id, so register or declare the exact URI).

### The default metadata fetcher

`HttpClientMetadataFetcher`: https on port 443 only, at most 4 concurrent fetches, every transport error (including `IOException`) is a failed fetch that goes into the 30 s negative cache and never a 500, no redirects, no proxy, no cookies, 5 s timeout over the whole exchange, 64 KB cap, JSON content type required. The SSRF guard runs in `SocketsHttpHandler.ConnectCallback`, so the address the socket actually dials is the address that is checked (a DNS answer cannot change between "check" and "use"). It refuses loopback, private, link-local (including the 169.254.169.254 metadata address), multicast, unique-local, CGNAT, benchmarking and documentation ranges, `0.0.0.0`, IPv4-compatible (`::a.b.c.d`), IPv4-mapped, SIIT, NAT64 (`64:ff9b::/96`, `64:ff9b:1::/48`), 6to4, Teredo and discard ranges. If any resolved address is non-public the connection is refused. The same pass runs on net6.0. Replace it with `.UseClientMetadataFetcher<T>()` if your egress needs a policy of its own.

## Tokens

Authorization codes: 256-bit random, stored as SHA-256, single use, 60 s, bound to client, redirect URI, PKCE challenge, resource, scopes and user. The exchange checks client, redirect URI, resource, PKCE and expiry BEFORE it consumes the code, so a request that lacks the verifier can neither burn a legitimate code nor trigger a family burn. A replay that passes the same checks (it holds the verifier and the client's identity) answers `invalid_grant` and revokes the refresh family issued from the first exchange, even after the code expired.

Access tokens: minted by `ITokenProvider` with a `TokenDescriptor`: header `typ` = `at+jwt` (RFC 9068), `aud` = the resource, `iss` = the configured issuer, `sub` = the user id, `jti`, plus `client_id` and `scope` (space separated). They are self-contained JWTs signed with the key set of `AuthOptions.Jwt.Signing` and published through `MapTechTeaStudioJwks()`; they cannot be revoked individually, which is why the default lifetime is short.

Refresh tokens: rotate on every use, stored hashed, bound to client, user, scopes and resource. `scope` on refresh may narrow the new ACCESS token, never widen; the successor refresh token keeps the original scopes. The family has an absolute lifetime (`RefreshFamilyAbsoluteLifetime`, 90 days) that sliding refresh cannot extend. Revocations are recorded on a family record that issuance re-checks after writing a token, so a disconnect or a code replay racing an in-flight refresh or exchange cannot leave a live successor. The lost-race rule: a token rotated less than `RefreshRotationGrace` ago answers `invalid_grant` but does NOT burn the family (a client that retried after a network error keeps the newest token it already received); presenting it after the grace burns the whole family. Unknown, expired, revoked or foreign refresh tokens always answer `invalid_grant` (Claude depends on exactly that code to start a new authorization).

Token endpoint errors: `invalid_request`, `invalid_client` (401), `invalid_grant`, `unsupported_grant_type`, `invalid_scope`, and `invalid_target` for a `resource` that does not match the grant.

Revocation (`POST /oauth/revoke`): a confidential client authenticates exactly as at the token endpoint (failure: 401 `invalid_client`). A token presented by a different authenticated client, or without a `client_id` when its owner is confidential, is not revoked and still answers 200 (RFC 7009).

## Validating the tokens (resource server and token confusion)

An OAuth access token and a first-party session token are signed with the same keys. Keep them from being interchangeable:

- The options validator refuses any `ProtectedResources` entry equal to `AuthOptions.Jwt.Audience`.
- For the protected resource itself use the shipped scheme, which requires `typ=at+jwt`, `aud == resource`, `iss == OAuthServerOptions.Issuer` and the library's signing keys (rotation included):

```csharp
builder.Services.AddAuthentication()
    .AddTechTeaStudioOAuthResourceServer("mcp", "https://chronos.example.com/mcp");

app.MapMcp("/mcp").RequireAuthorization(p => p.AddAuthenticationSchemes("mcp").RequireAuthenticatedUser());
```

- Your first-party schemes must reject OAuth access tokens. Their audience differs, but make it explicit so a future audience change cannot open the hole:

```csharp
options.Events.OnTokenValidated = ctx =>
{
    var typ = ctx.SecurityToken switch
    {
        System.IdentityModel.Tokens.Jwt.JwtSecurityToken j => j.Header.Typ,
        Microsoft.IdentityModel.JsonWebTokens.JsonWebToken w => w.Typ,
        _ => null,
    };
    if (string.Equals(typ, "at+jwt", StringComparison.OrdinalIgnoreCase) || ctx.Principal?.HasClaim(c => c.Type == "client_id") == true)
        ctx.Fail("OAuth access tokens are not accepted on this scheme.");
    return Task.CompletedTask;
};
```

## Connected apps and account state

```csharp
IOAuthGrantService grants;                                   // scoped
var apps = await grants.ListForUserAsync(userId);            // client name, scopes, first and last use
await grants.RevokeAsync(userId, clientId);                  // removes the grant and kills the client's refresh families
await grants.RevokeAllAsync(userId);                         // sign out everywhere, password reset, account closure
```

Register an `IOAuthUserValidator` (`IsActiveAsync(userId)`) to stop tokens for disabled, deleted or banned users: it is called on every code exchange and every refresh, and `false` answers `invalid_grant` and revokes the family. Without one every user counts as active.

`IOAuthGrantStore` is the storage behind it; `IOAuthGrantStore.DeleteAsync` only removes the row.

## Stores

Interfaces in `Abstractions/`: `IOAuthClientStore`, `IOAuthPendingRequestStore`, `IOAuthCodeStore`, `IOAuthRefreshTokenStore`, `IOAuthGrantStore`. The in-memory defaults lose everything on restart and do not span processes: tests and samples only. `UseEfCoreStores<TContext>()` replaces all five; the individual `UseClientStore<T>()` ... `UseGrantStore<T>()` swap one. Stores are expected to make `TakeAsync`, `TryConsumeAsync` and `TryRotateAsync` atomic (exactly one concurrent caller wins).

EF tables: `{prefix}Clients`, `{prefix}PendingRequests`, `{prefix}Codes`, `{prefix}RefreshTokens`, `{prefix}Families`, `{prefix}Grants`. Instants are bigint UTC ticks. Create the tables with your usual migration flow. Pending requests, codes and refresh tokens are not purged by the module; call each store's `CleanupExpiredAsync(cutoff)` from a job of yours (the refresh store keeps rotated rows until they expire, which is what makes reuse detection possible).

## Audit

Through `IAuthAuditLogger`: `oauth.authorize.requested`, `oauth.authorize.approved`, `oauth.authorize.denied`, `oauth.code.exchanged`, `oauth.code.replayed`, `oauth.refresh.rotated`, `oauth.refresh.reused` (with `WithinGrace`), `oauth.family.burned`, `oauth.client.registered`, `oauth.client.metadata_fetch_failed`, `oauth.grant.revoked`. No event carries a token, code, verifier or pending request id.

## Security notes

- The issuer is configuration, not the request host: the app sits behind a proxy, and a host-derived issuer is a token-confusion bug waiting for a forwarded header.
- Errors before the client and redirect URI are validated are a plain 400. After that, errors for PRE-REGISTERED clients go back to the validated redirect with `error`, `error_description`, `state` and `iss` (RFC 9207, advertised as `authorization_response_iss_parameter_supported`); for self-registered and metadata-document clients they stay a plain 400.
- `resource` is required and compared as an exact string against `ProtectedResources`; the token audience is that string. A trailing slash is a different resource.
- PKCE S256 is mandatory for every client, `plain` is refused.
- Public clients are the default and the only dynamic kind. Confidential clients exist only in configuration.
- Dynamic registration is unauthenticated by nature: rate limit it, and expect to prune unused client rows.
- Behind Cloudflare or another proxy, configure forwarded headers for your own logging and rate limiting; the module does not read them.
- Never log the consent redirect URL, token endpoint bodies or `Authorization` headers.
