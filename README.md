<p align="center">
  <img src="https://raw.githubusercontent.com/TechTeaStudio/Auth/product/icon.png" alt="TechTeaStudio.Auth logo" width="160" />
</p>

<h1 align="center">TechTeaStudio.Auth</h1>

<p align="center">
  Drop-in authentication primitives for .NET. JWT, PBKDF2 password hashing, refresh-token rotation, multi-app claim profiles, lockout, audit, 2FA, and one-line ASP.NET Core wire-up &mdash; without pulling in a full identity framework.
</p>

<p align="center">
  <a href="https://www.nuget.org/packages/TechTeaStudio.Auth"><img alt="NuGet" src="https://img.shields.io/nuget/v/TechTeaStudio.Auth.svg?logo=nuget&label=NuGet" /></a>
  <a href="https://www.nuget.org/packages/TechTeaStudio.Auth"><img alt="Downloads" src="https://img.shields.io/nuget/dt/TechTeaStudio.Auth.svg?logo=nuget&label=Downloads" /></a>
  <img alt=".NET" src="https://img.shields.io/badge/.NET-6.0%20%7C%208.0%20%7C%209.0%20%7C%2010.0-512BD4?logo=dotnet&logoColor=white" />
  <a href="https://github.com/TechTeaStudio/Auth/actions/workflows/dotnet.yml"><img alt="Build" src="https://img.shields.io/github/actions/workflow/status/TechTeaStudio/Auth/dotnet.yml?branch=product&logo=github&label=build" /></a>
  <a href="LICENSE"><img alt="License" src="https://img.shields.io/badge/license-MIT-blue.svg" /></a>
</p>

## Overview

`TechTeaStudio.Auth` solves the handful of problems every .NET service re-implements: issuing and validating JWTs, hashing passwords the way the year you're reading this expects, rotating refresh tokens without leaking them, and wiring all of it into ASP.NET Core without a 200-line `Program.cs` ceremony. It does this with a small, focused public surface, four target frameworks, and no opinion about what the rest of your app looks like.

The package was extracted from the Hyperion Omni Client &mdash; which already shipped its own JWT + PBKDF2 stack &mdash; so that Hyperion, Pello, and any future TTS app can share one hardened implementation instead of three drifting copies.

## When to reach for it

You want this library when you need **first-party authentication primitives** in a .NET service and you'd rather not glue together five `Microsoft.*` packages plus a hand-written hasher. Concretely, that means:

- A web API or BFF you own, where users authenticate against your own user store.
- A small-to-medium app that doesn't need a full IdentityServer / OpenIddict footprint.
- A codebase that values explicit DI registration over magic conventions.
- You're already on Hyperion or Pello and want to stop duplicating the auth stack.

You probably **don't** want this library when you need full OAuth2 / OIDC server semantics (use OpenIddict or Duende IdentityServer), when you're delegating auth entirely to an external IdP (use the matching `Microsoft.AspNetCore.Authentication.*` package directly), or when you need ASP.NET Core Identity's UI scaffolding for users / roles / claims.

## How it compares

| Library / Approach | What it gives you | Footprint | Password hashing | Refresh tokens | Multi-app claim profiles |
|---|---|---|---|---|---|
| **TechTeaStudio.Auth** | JWT + password hashing + refresh tokens + lockout + audit + 2FA + middleware | Small (~one package) | PBKDF2-SHA256, sane defaults | Built-in, single-use, rotated | First-class |
| **ASP.NET Core Identity** | Full user/role store + UI scaffolding | Large (EF Core + UI + scaffolding) | PBKDF2 (configurable) | Via separate add-on | Manual claims transformer |
| **OpenIddict / Duende IdentityServer** | OAuth2 / OIDC server | Large (server-side flows, endpoints) | Delegated to your store | First-class | Via scope/claim mapping |
| **`Microsoft.AspNetCore.Authentication.JwtBearer` (raw)** | JWT validation only | Tiny | None | None | Manual |
| **Roll your own** | Whatever you write | Whatever you write | Whatever you remember | The bug you'll ship | The mess you'll inherit |

The honest pitch: `TechTeaStudio.Auth` sits between **"raw `JwtBearer` + a hand-written hasher"** and **"a full identity framework"**. If you're about to write your fifth `PBKDF2` helper and then realise you also need refresh-token rotation and a way to keep two apps' claim shapes from diverging, this is the package that already did all of that.

## Install

```bash
dotnet add package TechTeaStudio.Auth
```

Or pin a specific version in `.csproj`:

```xml
<PackageReference Include="TechTeaStudio.Auth" Version="0.2.0" />
```

## Quick start

### ASP.NET Core wire-up

```csharp
using TechTeaStudio.Auth.AspNetCore;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddTechTeaStudioAuth(builder.Configuration);

var app = builder.Build();
app.UseSecurityHeaders();   // optional
app.UseAuthentication();
app.UseAuthorization();
```

```jsonc
// appsettings.json
{
  "Auth": {
    "Jwt": {
      "SecretKey": "<32-byte-secret-or-longer>",
      "Issuer": "https://api.example.com",
      "Audience": "example-clients",
      "TokenLifetime": "00:30:00"
    },
    "RefreshTokens": { "Lifetime": "7.00:00:00" },
    "Lockout": { "MaxFailedAttempts": 5, "Duration": "00:15:00" }
  }
}
```

`AddTechTeaStudioAuth` registers `ITokenProvider`, `ITokenReader`, `IPasswordHasher`, `IRefreshTokenStore` (in-memory by default), `RefreshTokenService`, `IRefreshClaimsResolver`, `ILoginAttemptTracker`, `IRevokedTokenStore`, `IAuthAuditLogger` (null sink), the JWT bearer scheme, ASP.NET Core authorization, the `RefreshTokenCleanupService` + `RevokedTokenCleanupService` background workers, and startup validation of `AuthOptions`.

All store / tracker / logger registrations use `TryAdd*`, so prior registrations win. The clean way to swap a default is the **fluent builder** returned by `AddTechTeaStudioAuth(...)`:

```csharp
builder.Services.AddTechTeaStudioAuth(builder.Configuration)
    .UseRefreshTokenStore<EfCoreRefreshTokenStore<MyDbContext>>()
    .UseLoginAttemptTracker<RedisLoginAttemptTracker>()
    .UseAuthAuditLogger<MyDbAuthAuditLogger>()
    .UseClaimsProfile<MyAppClaimsProfile>()
    .UseRefreshClaimsResolver<MyClaimsResolver>();
```

### Issuing a token pair

```csharp
public sealed class LoginEndpoint
{
    private readonly IPasswordHasher _passwords;
    private readonly RefreshTokenService _refresh;
    private readonly IUserRepository _users;

    public LoginEndpoint(IPasswordHasher p, RefreshTokenService r, IUserRepository u)
        => (_passwords, _refresh, _users) = (p, r, u);

    public async Task<IResult> Handle(LoginRequest req, CancellationToken ct)
    {
        var user = await _users.FindAsync(req.Email, ct);
        if (user is null || !_passwords.Verify(user.PasswordHash, req.Password))
            return Results.Unauthorized();

        var claims = new[]
        {
            new Claim(AuthClaims.Username, user.Username),
            new Claim(AuthClaims.Email, user.Email),
        }
        .Concat(user.Roles.Select(r => new Claim(AuthClaims.Role, r)));

        var pair = await _refresh.IssueAsync(user.Id, claims, ct);

        return Results.Ok(new { pair.AccessToken, pair.RefreshToken, pair.RefreshTokenExpiresAt });
    }
}
```

### Rotating refresh tokens

```csharp
// Caller knows the claims to embed:
var pair = await _refresh.RotateAsync(req.RefreshToken, claims, ct);

// Or register an IRefreshClaimsResolver once and use the no-claims overload:
var pair = await _refresh.RotateAsync(req.RefreshToken, ct);

return pair is null ? Results.Unauthorized() : Results.Ok(pair);
```

Refresh tokens are single-use. A successful rotation revokes the presented token and emits a fresh one. Presenting an already-revoked token revokes the **whole rotation chain** when `AuthOptions.RefreshTokens.RevokeChainOnReuse` is on (default).

### Hashing passwords

```csharp
var hash    = _passwords.Hash("correct horse battery staple");
var matches = _passwords.Verify(hash, "correct horse battery staple");   // (hashed, provided)
```

PBKDF2-SHA256 · 600 000 iterations · 16-byte salt · 32-byte digest · constant-time verify.

### One-shot signed tokens

```csharp
// password reset
var token = _resetTokens.Generate(user.Id);          // 30-min default lifetime
var r     = await _resetTokens.ValidateAsync(token); // one-shot — replay returns Success=false

// email confirmation
var token = _emailTokens.Generate(user.Id, user.Email);  // 24-hour default
var r     = await _emailTokens.ValidateAsync(token);
```

Single-use is enforced via the `IRevokedTokenStore` deny-list — the `jti` of the token is revoked on the first successful validation.

### Two-factor (TOTP + recovery codes)

```csharp
var secret        = RandomNumberGenerator.GetBytes(20);
var base32Secret  = OtpAuthUri.ToBase32(secret);
var provisioning  = OtpAuthUri.Build("MyApp", user.Email, base32Secret); // → otpauth://totp/...
var recoveryCodes = RecoveryCodeService.Generate();                       // 10 × 8-char codes

// Verify what the user typed from Google/Microsoft Authenticator:
var ok = TotpValidator.Validate(secret, typedCode, DateTimeOffset.UtcNow);
```

### API-key authentication scheme

```csharp
services.AddSingleton<IApiKeyStore>(new FuncApiKeyStore((raw, ct) =>
    Task.FromResult(LookUp(raw))));
services.AddAuthentication().AddTechTeaStudioApiKey();

app.MapGet("/internal/hooks", () => "ok")
   .RequireAuthorization();
```

Reads `X-Api-Key` by default; also accepts `Authorization: ApiKey <key>` when the option is on.

## Multi-app claim profiles

Different apps publish different claim shapes. The library defines the `IClaimsProfile` abstraction; each app implements its own profile and registers it via DI:

```csharp
public sealed class MyAppClaimsProfile : IClaimsProfile
{
    public string Name => "MyApp";
    public IEnumerable<Claim> BuildClaims(ClaimsBuilderInput input)
    {
        if (!string.IsNullOrEmpty(input.UserId)) yield return new Claim(AuthClaims.Subject, input.UserId);
        if (!string.IsNullOrEmpty(input.Email))  yield return new Claim(AuthClaims.Email, input.Email);
        if (input.Roles is not null)
            foreach (var r in input.Roles) yield return new Claim(AuthClaims.Role, r);
    }
}

builder.Services.AddTechTeaStudioAuth(builder.Configuration)
    .UseClaimsProfile<MyAppClaimsProfile>();
```

The library deliberately does **not** ship product-specific profiles — every consuming app owns its claim shape and the library stays generic.

## ⚠️ In-memory defaults are NOT for multi-instance production

The defaults registered by `AddTechTeaStudioAuth()` are designed for fast dev / single-instance scenarios:

- **`InMemoryRefreshTokenStore`** — lost on restart.
- **`InMemoryLoginAttemptTracker`** — brute-forcer hitting different instances behind a load balancer bypasses lockout entirely.
- **`InMemoryRevokedTokenStore`** — JTI revoked on instance A is unknown to instance B; a stolen access token keeps working everywhere else until natural expiry.

**For any multi-instance production deployment, replace via the builder:**

```csharp
builder.Services.AddTechTeaStudioAuth(builder.Configuration)
    .UseRefreshTokenStore<EfCoreRefreshTokenStore<MyDbContext>>()   // TechTeaStudio.Auth.EFCore
    .UseLoginAttemptTracker<RedisLoginAttemptTracker>();             // TechTeaStudio.Auth.Redis
```

> ⚠️ **`TechTeaStudio.Auth.Redis` is in early-stage (v0.5)** — passes the contract test kit, but `RevokeAsync(Guid)` walks every key (O(N)) and there are no production benchmarks yet. Suitable for a starting point; will be hardened with a reverse-index in v0.6+.

## Security defaults

| Concern | Default | Knob |
|---|---|---|
| Password hashing | PBKDF2-SHA256, 600 000 iterations, 16-byte salt | (algorithm version is fixed; iteration count is fixed in 0.x) |
| Access token lifetime | 30 minutes | `AuthOptions.Jwt.TokenLifetime` |
| Refresh token lifetime | 7 days | `AuthOptions.RefreshTokens.Lifetime` |
| Refresh token reuse | Single-use, rotated; replay revokes the chain | `AuthOptions.RefreshTokens.RevokeChainOnReuse` |
| Signing algorithm | HS256 (RS256, ES256 also supported via `Jwt.Signing.Keys`) | `AuthOptions.Jwt.Signing` |
| Clock skew | 5 minutes | `AuthOptions.Jwt.ClockSkew` |
| Account lockout | 5 failed attempts → 15-minute lockout | `AuthOptions.Lockout.MaxFailedAttempts`, `AuthOptions.Lockout.Duration` |
| Refresh-token cleanup | every 1 hour | `AuthOptions.RefreshTokens.CleanupInterval` |

### HTTP-only / domain-less deployments

The cookie scheme defaults to `CookieSecurePolicy.SameAsRequest`, so plain `http://localhost` and on-prem deployments without TLS work out of the box. For production over HTTPS, harden by passing `o.Cookie.SecurePolicy = CookieSecurePolicy.Always` into `AddTechTeaStudioCookieAuth(...)`. HSTS is only emitted by `SecurityHeadersMiddleware` when the inbound request is HTTPS — never on HTTP.

The library refuses to start with a missing or short signing key (< 32 UTF-8 bytes).

## 401 response contract

When the bearer pipeline rejects a request, the response body is:

```json
{ "error": "token_expired", "message": "Token has expired.", "traceId": "0HMV..." }
```

`error` is a stable string from `AuthErrorCodes`:

- `missing_token`, `unauthorized` &mdash; generic.
- `token_expired`, `token_not_yet_valid` &mdash; lifetime errors.
- `invalid_signature`, `invalid_issuer`, `invalid_audience`, `malformed_token` &mdash; structural errors.

Switch on `error` to drive client behaviour (e.g. `token_expired` → silently refresh).

## Public API (current shipped surface)

```csharp
namespace TechTeaStudio.Auth.Abstractions;

public interface ITokenProvider
{
    string CreateToken(string userId, IEnumerable<Claim> claims, TimeSpan lifetime);
    ClaimsPrincipal? ValidateToken(string token);
}

public interface ITokenReader
{
    AuthTokenInfo? TryRead(string token);
}

public interface IPasswordHasher
{
    string Hash(string password);
    bool Verify(string hashedPassword, string providedPassword);
}

public interface IRefreshTokenStore
{
    Task<RefreshToken?> GetByTokenHashAsync(string tokenHash, CancellationToken ct = default);
    Task<IReadOnlyList<RefreshToken>> GetActiveForUserAsync(string userId, CancellationToken ct = default);
    Task CreateAsync(RefreshToken token, CancellationToken ct = default);
    Task RevokeAsync(Guid id, string? replacedByTokenHash = null, CancellationToken ct = default);
    Task RevokeAllForUserAsync(string userId, CancellationToken ct = default);
    Task<int> CleanupExpiredAsync(DateTimeOffset cutoff, CancellationToken ct = default);
    Task DeleteAllForUserAsync(string userId, CancellationToken ct = default);
}
```

## Observability

`AuthDiagnostics` exposes a `System.Diagnostics.Metrics.Meter` named `TechTeaStudio.Auth` and an `ActivitySource` of the same name. Counter names are Prometheus-friendly:

- `tts_auth_login_succeeded_total`
- `tts_auth_login_failed_total`
- `tts_auth_tokens_issued_total`
- `tts_auth_refresh_rotated_total`
- `tts_auth_refresh_reuse_total`
- `tts_auth_accounts_locked_total`

Plug an OpenTelemetry pipeline at the `TechTeaStudio.Auth` meter and they scrape into a single dashboard.

Replace `NullAuthAuditLogger` with your own `IAuthAuditLogger` to get strongly-typed events (`LoginSucceeded`, `TokenIssued`, `RefreshReuseDetected`, …) to a database or log sink.

## Project layout

```
Auth/
├── src/TechTeaStudio.Auth/
│   ├── TechTeaStudio.Auth.sln
│   ├── TechTeaStudio.Auth/                          <- NuGet package source
│   │   ├── Abstractions/                            <- contracts + value objects
│   │   ├── Jwt/                                     <- JwtTokenProvider / JwtTokenReader
│   │   ├── Passwords/                               <- Pbkdf2PasswordHasher
│   │   ├── RefreshTokens/                           <- service, hasher, store, cleanup
│   │   ├── Lockout/                                 <- ILoginAttemptTracker + in-memory
│   │   ├── Revocation/                              <- deny-list + cleanup
│   │   ├── Tokens/                                  <- signed one-shot tokens
│   │   ├── TwoFactor/                               <- TOTP + recovery codes + enrollment
│   │   ├── Profiles/                                <- multi-app claim profiles
│   │   ├── Observability/                           <- IAuthAuditLogger + AuthDiagnostics
│   │   ├── AspNetCore/                              <- AddTechTeaStudioAuth(), middleware, ApiKey scheme
│   │   └── AuthOptions.cs
│   └── TechTeaStudio.Auth.Tests/                    <- xUnit + FluentAssertions
├── docs/                                            <- recipes + migration guides
├── .github/workflows/dotnet.yml                     <- CI (shared TTS NuGet publish workflow)
├── CHANGELOG.md
├── LICENSE
├── SECURITY.md
└── README.md
```

## Build &amp; test

```bash
dotnet build src/TechTeaStudio.Auth/TechTeaStudio.Auth.sln
dotnet test  src/TechTeaStudio.Auth/TechTeaStudio.Auth.sln
```

The library multi-targets `net6.0;net8.0;net9.0;net10.0`. `net7.0` is intentionally skipped (EOL). The test project targets `net8.0;net9.0;net10.0` only.

## Versioning &amp; release

Version lives in `TechTeaStudio.Auth.csproj` as a 3-part `<Version>X.Y.Z</Version>`. Bump rules:

- Bug fix &rarr; `Z + 1`
- New feature, source-compatible &rarr; `Y + 1`, reset `Z = 0`
- Breaking change in public API &rarr; `X + 1` (after `1.0`), reset `Y = Z = 0`

Commit format is `vX.Y.Z <short description>`. Push to `product` triggers the shared TechTeaStudio NuGet publish workflow, which packs and pushes to nuget.org with `--skip-duplicate`. **Never push to nuget.org manually.**

See [CHANGELOG.md](CHANGELOG.md) for the full release history.

## Further reading

- [docs/RECIPES.md](docs/RECIPES.md) &mdash; common patterns: login, refresh, revoke, reset, 2FA, API keys, audit.
- [docs/MIGRATION-Hyperion.md](docs/MIGRATION-Hyperion.md) &mdash; moving Hyperion Omni Client onto the library.
- [docs/MIGRATION-Pello.md](docs/MIGRATION-Pello.md) &mdash; moving Pello onto the library.
- [SECURITY.md](SECURITY.md) &mdash; threat model and reporting policy.

## License

Licensed under the [MIT License](LICENSE). Copyright &copy; Tech Tea Studio.

<p align="center">
  Built as part of the Hyperion Ecosystem by <a href="https://techteastudio.cc">TechTeaStudio</a>.
</p>
