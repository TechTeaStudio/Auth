# OAuth — TechTeaStudio.Auth.OAuth.* packages

Provider-agnostic OAuth / OIDC sign-in for `TechTeaStudio.Auth` 0.6+. Three packages:

| Package | Purpose |
|---|---|
| `TechTeaStudio.Auth.OAuth.Abstractions` | `IExternalAuthProvider`, `IExternalLoginStore`, `IExternalUserBridge`, `ExternalLoginService` (three-outcome orchestrator). |
| `TechTeaStudio.Auth.OAuth.Google` | Google Sign-In implementation via `Google.Apis.Auth`. |
| `TechTeaStudio.Auth.OAuth.EFCore` | EF Core mapping for the external-login table. |

Future siblings (same pattern): `Auth.OAuth.GitHub`, `Auth.OAuth.Apple`, `Auth.OAuth.Microsoft`, …

## Three-outcome flow

Every `POST /api/auth/oauth/{provider}` returns one of:

| Status | What client should do |
|---|---|
| `Authenticated` | Save `Tokens.AccessToken` + `Tokens.RefreshToken`, done. |
| `RequiresPassword` | Show password prompt prefilled with `Email`, POST `{ContinuationToken, password}` to `/api/auth/oauth/link`. |
| `RequiresRegistration` | Show username picker prefilled from `Profile.DisplayName`, POST `{ContinuationToken, username}` to `/api/auth/oauth/register`. |
| `Failed` | Show `Error` — stable string like `invalid_credential`, `unknown_provider`. |

Continuation tokens are HMAC-signed by the library, valid for 10 minutes, single-use (replay-protected via the deny-list).

## Wire-up (Hyperion auth-service)

### 1. Packages

```xml
<PackageReference Include="TechTeaStudio.Auth"                    Version="0.6.0" />
<PackageReference Include="TechTeaStudio.Auth.EFCore"             Version="0.6.0" />
<PackageReference Include="TechTeaStudio.Auth.OAuth.Abstractions" Version="0.6.0" />
<PackageReference Include="TechTeaStudio.Auth.OAuth.EFCore"       Version="0.6.0" />
<PackageReference Include="TechTeaStudio.Auth.OAuth.Google"       Version="0.6.0" />
```

### 2. Configuration

```jsonc
{
  "Auth": {
    "Jwt": { "SecretKey": "...", "Issuer": "https://auth.hyperion.example", "Audience": "hyperion-clients" },
    "RefreshTokens": { "Lifetime": "7.00:00:00" },
    "Google": {
      "Audiences": [
        "WEB-CLIENT-ID.apps.googleusercontent.com",
        "ANDROID-CLIENT-ID.apps.googleusercontent.com",
        "IOS-CLIENT-ID.apps.googleusercontent.com"
      ],
      "RequireEmailVerified": true
    }
  }
}
```

### 3. DbContext

```csharp
using TechTeaStudio.Auth.EFCore;
using TechTeaStudio.Auth.OAuth.EFCore;

protected override void OnModelCreating(ModelBuilder b)
{
    base.OnModelCreating(b);
    // ... your domain entities ...

    b.AddTechTeaStudioRefreshTokens("HyperionRefreshTokens");
    b.AddTechTeaStudioExternalLogins("HyperionExternalLogins");
}
```

Run `dotnet ef migrations add AddTtsTables && dotnet ef database update`.

### 4. Bridge between the library and your user table

```csharp
// Hyperion.Infrastructure.AuthService/Auth/HyperionExternalUserBridge.cs
using TechTeaStudio.Auth.OAuth;

public sealed class HyperionExternalUserBridge(IUserRepository users) : IExternalUserBridge
{
    public async Task<ExternalUserSnapshot?> FindByEmailAsync(string email, CancellationToken ct = default)
    {
        var u = await users.FindByEmailAsync(email, ct);
        return u is null ? null : Snap(u);
    }

    public async Task<ExternalUserSnapshot?> GetByIdAsync(string userId, CancellationToken ct = default)
    {
        if (!Guid.TryParse(userId, out var id)) return null;
        var u = await users.GetByIdAsync(id, ct);
        return u is null ? null : Snap(u);
    }

    public async Task<ExternalUserSnapshot> CreateFromExternalAsync(ExternalLoginInfo info, string username, CancellationToken ct = default)
    {
        var u = new UserEntity
        {
            Email          = info.Email ?? "",
            Username       = username,
            EmailConfirmed = info.EmailVerified,
            PasswordHash   = null,                 // OAuth-only account
            DisplayName    = info.DisplayName,
            AvatarUrl      = info.AvatarUrl,
            Roles          = new() { "user" },
        };
        await users.CreateAsync(u, ct);
        return Snap(u);
    }

    private static ExternalUserSnapshot Snap(UserEntity u) => new()
    {
        UserId       = u.Id.ToString(),
        Email        = u.Email,
        Username     = u.Username,
        PasswordHash = u.PasswordHash,
        Roles        = u.Roles,
    };
}
```

### 5. Program.cs

```csharp
using TechTeaStudio.Auth.AspNetCore;
using TechTeaStudio.Auth.EFCore;
using TechTeaStudio.Auth.OAuth;
using TechTeaStudio.Auth.OAuth.EFCore;
using TechTeaStudio.Auth.OAuth.Google;

builder.Services.AddDbContext<HyperionDbContext>(o => o.UseNpgsql(connString));

builder.Services.AddTechTeaStudioAuth(builder.Configuration)
    .UseRefreshTokenStore<EfCoreRefreshTokenStore<HyperionDbContext>>(ServiceLifetime.Scoped)
    .UseClaimsProfile<HyperionClaimsProfile>()
    .UseExternalLoginStore<EfCoreExternalLoginStore<HyperionDbContext>>(ServiceLifetime.Scoped)
    .UseExternalUserBridge<HyperionExternalUserBridge>(ServiceLifetime.Scoped)
    .AddGoogleAuthProvider();
//      ^^^^^^^^^^^^^^^^^^^^^ binds Auth:Google from config; pass an Action<GoogleAuthProviderOptions> to override
```

### 6. Controller

```csharp
[ApiController, Route("api/auth")]
public sealed class OAuthController(ExternalLoginService svc) : ControllerBase
{
    public sealed record SignInRequest(string Token);
    public sealed record LinkRequest(string ContinuationToken, string Password);
    public sealed record RegisterRequest(string ContinuationToken, string Username);

    [HttpPost("oauth/{provider}")]
    public async Task<IActionResult> SignIn(string provider, SignInRequest req, CancellationToken ct)
        => Ok(await svc.SignInAsync(provider, req.Token, ct));

    [HttpPost("oauth/link")]
    public async Task<IActionResult> Link(LinkRequest req, CancellationToken ct)
        => Ok(await svc.LinkExistingAccountAsync(req.ContinuationToken, req.Password, ct));

    [HttpPost("oauth/register")]
    public async Task<IActionResult> Register(RegisterRequest req, CancellationToken ct)
        => Ok(await svc.CompleteRegistrationAsync(req.ContinuationToken, req.Username, ct));

    [HttpPost("oauth/{provider}/link-current"), Authorize]
    public async Task<IActionResult> LinkCurrent(string provider, SignInRequest req, CancellationToken ct)
    {
        var userId = User.FindFirstValue(AuthClaims.Subject)!;
        return Ok(await svc.LinkToUserAsync(provider, req.Token, userId, ct));
    }
}
```

That's it — 4 endpoints, each one line. Three providers (Google + future GitHub + Apple) share the same controller because of the `{provider}` route segment.

## Mobile flow (Android / iOS)

1. Mobile app uses Google's native SDK to do the OAuth dance.
2. SDK gives the app a Google ID token (a JWT signed by Google).
3. Mobile POSTs that token to `POST /api/auth/oauth/Google` with `{"token": "<id_token>"}`.
4. Backend validates signature via Google's JWKS (cached by `Google.Apis.Auth`), checks audience, returns the three-outcome response.
5. Mobile stores `accessToken` + `refreshToken` in Keychain / Keystore. Every subsequent request: `Authorization: Bearer <accessToken>`.

The mobile audience client-id must be in `Auth:Google:Audiences`. One backend serves Android, iOS, and Web by listing every client id in that array.

## Adding GitHub

GitHub doesn't have an OIDC ID-token, so the library will ship `TechTeaStudio.Auth.OAuth.GitHub` later. Until then, write your own provider (~30 lines) — see [github-recipes](RECIPES.md#custom-oauth-provider) or this template:

```csharp
public sealed class GitHubAuthProvider(HttpClient http) : IExternalAuthProvider
{
    public string Name => "GitHub";

    public async Task<ExternalLoginInfo?> ValidateAsync(string accessToken, CancellationToken ct = default)
    {
        var profile = await CallGitHub<GitHubUser>("https://api.github.com/user", accessToken, ct);
        if (profile is null || profile.Id == 0) return null;
        var emails = await CallGitHub<GitHubEmail[]>("https://api.github.com/user/emails", accessToken, ct);
        var primary = emails?.FirstOrDefault(e => e.Primary && e.Verified);

        return new ExternalLoginInfo(
            Provider: "GitHub", ProviderUserId: profile.Id.ToString(),
            Email: primary?.Email ?? profile.Email,
            EmailVerified: primary is not null,
            DisplayName: profile.Name ?? profile.Login, AvatarUrl: profile.AvatarUrl);
    }
    // ... CallGitHub helper, GitHubUser / GitHubEmail records ...
}

// Program.cs
builder.Services.AddHttpClient<GitHubAuthProvider>(c =>
    c.DefaultRequestHeaders.UserAgent.ParseAdd("hyperion-auth"));

builder.Services.AddTechTeaStudioAuth(...)
    .AddExternalAuthProvider<GitHubAuthProvider>();
```

Same `OAuthController` — `POST /api/auth/oauth/GitHub` with the GitHub access token.

## Linking flows

| Scenario | Endpoint |
|---|---|
| First time on Google, new user | `POST /api/auth/oauth/Google` → `RequiresRegistration` → `POST /api/auth/oauth/register` |
| First time on Google, email matches password account | `POST /api/auth/oauth/Google` → `RequiresPassword` → `POST /api/auth/oauth/link` |
| Returning Google user | `POST /api/auth/oauth/Google` → `Authenticated` |
| Authenticated user adds GitHub from Settings → "Connect GitHub" | `POST /api/auth/oauth/GitHub/link-current` (Authorize-required) |
| Account deletion | `IExternalLoginStore.DeleteAllForUserAsync(userId)` |

## What stays your responsibility

- **`UserEntity` and `IUserRepository`** — same as before, library doesn't own users.
- **Sending the "welcome" email** — happens in your `IExternalUserBridge.CreateFromExternalAsync` if you want.
- **Bot detection / IP throttling on `POST /oauth/{provider}`** — wire your own rate-limiter; consider `Microsoft.AspNetCore.RateLimiting`.
- **Provider account suspension** — Google can revoke a token between two of your requests. Treat any `null` return from `ValidateAsync` as "session ended".

## Telemetry

Every successful sign-in (including OAuth) emits `LoginSucceededEvent` via `IAuthAuditLogger` and increments `tts_auth_login_succeeded_total`. Failed attempts in the OAuth path don't currently increment the failed-login counter (we're not exposing the email until it's verified) — track at the controller level if needed.
