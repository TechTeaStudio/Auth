<p align="center">
  <img src="https://raw.githubusercontent.com/TechTeaStudio/Auth/product/icon.png" alt="TechTeaStudio.Auth logo" width="160" />
</p>

<h1 align="center">TechTeaStudio.Auth</h1>

<p align="center">
  Drop-in authentication for .NET. Hash passwords, hand out JWT access tokens, rotate refresh tokens, track device sessions, lock out brute-force attackers, and wire it all into ASP.NET Core in one line. No full identity framework required.
</p>

<p align="center">
  <a href="https://www.nuget.org/packages/TechTeaStudio.Auth"><img alt="NuGet" src="https://img.shields.io/nuget/v/TechTeaStudio.Auth.svg?logo=nuget&label=NuGet" /></a>
  <a href="https://www.nuget.org/packages/TechTeaStudio.Auth"><img alt="Downloads" src="https://img.shields.io/nuget/dt/TechTeaStudio.Auth.svg?logo=nuget&label=Downloads" /></a>
  <img alt=".NET" src="https://img.shields.io/badge/.NET-6.0%20%7C%208.0%20%7C%209.0%20%7C%2010.0-512BD4?logo=dotnet&logoColor=white" />
  <a href="https://github.com/TechTeaStudio/Auth/actions/workflows/dotnet.yml"><img alt="Build" src="https://img.shields.io/github/actions/workflow/status/TechTeaStudio/Auth/dotnet.yml?branch=product&logo=github&label=build" /></a>
  <a href="LICENSE"><img alt="License" src="https://img.shields.io/badge/license-MIT-blue.svg" /></a>
</p>

## What this gives you

If you are building a .NET web API that needs to log users in and keep them logged in, you need to solve five problems:

1. **Hash passwords safely** so a database leak does not leak passwords.
2. **Hand out short-lived access tokens** the client puts on every request.
3. **Hand out long-lived refresh tokens** so the client can stay logged in without typing the password again.
4. **Lock out attackers** who try thousands of password guesses.
5. **Wire all of that into ASP.NET Core** without a 200-line `Program.cs`.

`TechTeaStudio.Auth` solves all five with one NuGet package and one line of DI registration. You keep full control of your own user table; the library never tells you what a "user" looks like.

## When to use it (and when not to)

**Use it when** you own a web API or BFF, users log in against your own database, and you want production-ready primitives without pulling in ASP.NET Core Identity or running an OAuth2 server.

**Skip it when** you need a full OAuth2 / OIDC server (use OpenIddict or Duende IdentityServer), when authentication is delegated entirely to Auth0 / Cognito / Entra (use the matching `Microsoft.AspNetCore.Authentication.*` package directly), or when you want ASP.NET Core Identity's built-in UI scaffolding for users and roles.

## Plain-English glossary

If you are new to auth in .NET, here are the terms used throughout this README:

| Term | What it means |
|---|---|
| **Access token** | Short-lived JWT (default 30 min). Client sends it in `Authorization: Bearer ...` on every request. |
| **Refresh token** | Long-lived random string (default 7 days). Client uses it to ask for a fresh access token without re-entering the password. |
| **Rotation** | Every time the client trades a refresh token for a new access token, the old refresh token is killed and a new one is issued. Stops stolen tokens from working forever. |
| **Replay** | An attacker presenting an already-used refresh token. The library detects this and kills the whole session. |
| **Lockout** | After N failed password attempts, the account is locked for some duration. Stops brute-force guessing. |
| **Claims profile** | A small class that decides which user properties (email, roles, custom fields) go into the JWT. Each app owns its own profile. |
| **PBKDF2** | The password-hashing algorithm. Slow on purpose so an attacker with the database cannot crack passwords cheaply. |

## Install

```bash
dotnet add package TechTeaStudio.Auth
```

Or pin a specific version in `.csproj`:

```xml
<PackageReference Include="TechTeaStudio.Auth" Version="0.8.0" />
```

Optional companion packages:

- `TechTeaStudio.Auth.EFCore` — store refresh tokens in your existing EF Core `DbContext`.
- `TechTeaStudio.Auth.Redis` — store refresh tokens, lockout counters, and JWT deny-list in Redis (multi-instance prod).
- `TechTeaStudio.Auth.OAuth.Google` / `TechTeaStudio.Auth.OAuth.GitHub` — sign in with Google or GitHub.
- `TechTeaStudio.Auth.OAuth.EFCore` — store external login links in EF Core.
- `TechTeaStudio.Auth.Swashbuckle` — make the Swagger "Authorize" button work with the library.

## Full lifecycle: from blank project to logged-in user

This is one continuous walkthrough. Each step builds on the last. At the end you will have a small API where a user can sign up, log in, call a protected endpoint, refresh their session, see their devices, and log out, with refresh tokens stored in a real database.

### Step 1: Configure

Add an `Auth` section to `appsettings.json`. The `SecretKey` must be at least 32 UTF-8 bytes; in production keep it in user-secrets or a key vault, never in source.

```jsonc
{
  "Auth": {
    "Jwt": {
      "SecretKey": "replace-with-a-32-byte-secret-or-longer",
      "Issuer":    "https://api.example.com",
      "Audience":  "example-clients",
      "TokenLifetime": "00:30:00"
    },
    "RefreshTokens": { "Lifetime": "7.00:00:00" },
    "Lockout":       { "MaxFailedAttempts": 5, "Duration": "00:15:00" }
  }
}
```

### Step 2: Wire it into `Program.cs`

One call sets up everything: JWT validation, password hashing, the refresh-token service, lockout tracking, the deny-list, the background cleanup workers, and `appsettings` validation at startup.

```csharp
using TechTeaStudio.Auth.AspNetCore;
using TechTeaStudio.Auth.EFCore;
using Microsoft.EntityFrameworkCore;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddDbContext<AppDb>(o => o.UseNpgsql(builder.Configuration.GetConnectionString("Db")));

builder.Services.AddTechTeaStudioAuth(builder.Configuration)
    .UseRefreshTokenStore<EfCoreRefreshTokenStore<AppDb>>();   // persist refresh tokens in your DB

builder.Services.AddControllers();
var app = builder.Build();

app.UseHttpsRedirection();
app.UseAuthentication();
app.UseAuthorization();
app.MapControllers();
app.Run();
```

### Step 3: Plug the refresh-token table into your `DbContext`

```csharp
public sealed class AppDb : DbContext
{
    public AppDb(DbContextOptions<AppDb> options) : base(options) { }

    public DbSet<User> Users => Set<User>();
    public DbSet<RefreshTokenEntity> RefreshTokens => Set<RefreshTokenEntity>();

    protected override void OnModelCreating(ModelBuilder b)
    {
        b.Entity<User>().HasIndex(u => u.Email).IsUnique();
        b.AddTechTeaStudioRefreshTokens();   // adds the TtsRefreshTokens table + indexes
    }
}

public sealed class User
{
    public Guid   Id           { get; set; } = Guid.NewGuid();
    public string Email        { get; set; } = "";
    public string Username     { get; set; } = "";
    public string PasswordHash { get; set; } = "";
}
```

> Already on an older release? The 0.8.0 upgrade adds two nullable columns. Run the pre-baked SQL once before the first deploy:
>
> ```csharp
> await db.Database.ExecuteSqlRawAsync(SchemaMigrations.AddDeviceColumnsSqlPostgres());
> ```
>
> (`AddDeviceColumnsSqlSqlServer()` and `AddDeviceColumnsSqlSqlite()` are also available.) Fresh deployments get the columns automatically.

### Step 4: Sign-up endpoint (hash the password, store the user)

```csharp
[ApiController]
[Route("auth")]
public sealed class AuthController(AppDb db, IPasswordHasher passwords, RefreshTokenService refresh) : ControllerBase
{
    public sealed record SignupRequest(string Email, string Username, string Password);

    [HttpPost("signup")]
    public async Task<IActionResult> Signup([FromBody] SignupRequest req, CancellationToken ct)
    {
        if (await db.Users.AnyAsync(u => u.Email == req.Email, ct))
            return Conflict(new { error = "email_taken" });

        var user = new User
        {
            Email        = req.Email,
            Username     = req.Username,
            PasswordHash = passwords.Hash(req.Password),
        };
        db.Users.Add(user);
        await db.SaveChangesAsync(ct);
        return Ok(new { user.Id });
    }
}
```

`passwords.Hash(...)` is PBKDF2-SHA256 with 600 000 iterations and a 16-byte salt. The output already contains the salt, so you store one string and you are done.

### Step 5: Login endpoint (verify password, issue tokens)

```csharp
public sealed record LoginRequest(string Email, string Password, string? DeviceId, string? DeviceInfo);

[HttpPost("login")]
public async Task<IActionResult> Login([FromBody] LoginRequest req, CancellationToken ct)
{
    var user = await db.Users.SingleOrDefaultAsync(u => u.Email == req.Email, ct);
    if (user is null || !passwords.Verify(user.PasswordHash, req.Password))
        return Unauthorized(new { error = "bad_credentials" });

    var claims = new[]
    {
        new Claim(AuthClaims.Username, user.Username),
        new Claim(AuthClaims.Email,    user.Email),
    };

    // deviceId / deviceInfo are optional. When supplied, they show up on /sessions
    // so the user can tell which device a session belongs to. Preserved across rotations.
    var pair = await refresh.IssueAsync(
        user.Id.ToString(),
        claims,
        deviceId:   req.DeviceId,
        deviceInfo: req.DeviceInfo,
        cancellationToken: ct);

    return Ok(new
    {
        pair.AccessToken,
        pair.RefreshToken,
        pair.RefreshTokenExpiresAt,
    });
}
```

The response gives the client an **access token** (put in `Authorization: Bearer ...` on every request) and a **refresh token** (store securely, send only to `/auth/refresh`).

### Step 6: Protect an endpoint

```csharp
[ApiController]
[Route("me")]
[Authorize]   // requires a valid Bearer token
public sealed class MeController : ControllerBase
{
    [HttpGet]
    public IActionResult Get()
        => Ok(new
        {
            UserId   = User.FindFirstValue(AuthClaims.Subject),
            Username = User.FindFirstValue(AuthClaims.Username),
            Email    = User.FindFirstValue(AuthClaims.Email),
        });
}
```

If the token is missing, expired, or tampered with, the library replies `401` with a structured JSON body (see `401 response contract` below). The frontend can branch on `error == "token_expired"` and silently call `/auth/refresh`.

### Step 7: Refresh endpoint (trade old refresh token for new pair)

```csharp
public sealed record RefreshRequest(string RefreshToken);

[HttpPost("refresh")]
public async Task<IActionResult> Refresh([FromBody] RefreshRequest req, CancellationToken ct)
{
    // No-claims overload: an IRefreshClaimsResolver pulls the latest claims for you.
    var pair = await refresh.RotateAsync(req.RefreshToken, ct);
    if (pair is null) return Unauthorized(new { error = "invalid_refresh_token" });

    return Ok(new { pair.AccessToken, pair.RefreshToken, pair.RefreshTokenExpiresAt });
}
```

Each successful refresh kills the presented token and emits a new one. If the **same** refresh token is presented twice (the second presentation must be a stolen copy), the library kills the entire rotation chain. The client is forced back to the login screen, which is exactly what you want.

To register a claims resolver so `RotateAsync(token, ct)` knows what claims to put in the new JWT:

```csharp
public sealed class MyClaimsResolver(AppDb db) : IRefreshClaimsResolver
{
    public async Task<IEnumerable<Claim>> ResolveClaimsAsync(string userId, CancellationToken ct)
    {
        var u = await db.Users.SingleAsync(u => u.Id == Guid.Parse(userId), ct);
        return new[]
        {
            new Claim(AuthClaims.Username, u.Username),
            new Claim(AuthClaims.Email,    u.Email),
        };
    }
}

// In Program.cs:
builder.Services.AddTechTeaStudioAuth(builder.Configuration)
    .UseRefreshTokenStore<EfCoreRefreshTokenStore<AppDb>>()
    .UseRefreshClaimsResolver<MyClaimsResolver>();
```

### Step 8: List the user's sessions (device attribution)

Because `IssueAsync` accepted `deviceId` / `deviceInfo`, you can show "I am logged in on iPhone 13, Chrome on PC, Firefox on Linux" in a Settings → Sessions screen:

```csharp
[HttpGet("sessions")]
[Authorize]
public async Task<IActionResult> Sessions([FromServices] IRefreshTokenStore store, CancellationToken ct)
{
    var userId = User.FindFirstValue(AuthClaims.Subject)!;
    var tokens = await store.GetActiveForUserAsync(userId, ct);
    return Ok(tokens.Select(t => new
    {
        t.Id,
        t.DeviceId,
        t.DeviceInfo,
        t.CreatedAt,
        t.ExpiresAt,
    }));
}
```

### Step 9: Logout (revoke this session)

```csharp
[HttpPost("logout")]
public async Task<IActionResult> Logout([FromBody] RefreshRequest req, CancellationToken ct)
{
    await refresh.RevokeAsync(req.RefreshToken, ct);
    return NoContent();
}
```

To kill **every** active session for a user (account compromised, password changed):

```csharp
await store.RevokeAllForUserAsync(userId, ct);
```

### Step 10: Try it from the command line

```bash
BASE=http://localhost:5180

# 1. Sign up
curl -sX POST $BASE/auth/signup -H 'content-type: application/json' \
  -d '{"email":"u@x","username":"alice","password":"correct horse battery staple"}'

# 2. Login (capture the tokens)
TOKENS=$(curl -sX POST $BASE/auth/login -H 'content-type: application/json' \
  -d '{"email":"u@x","password":"correct horse battery staple","deviceInfo":"PC","deviceId":"laptop-abc"}')
ACCESS=$(echo $TOKENS | jq -r .accessToken)
REFRESH=$(echo $TOKENS | jq -r .refreshToken)

# 3. Call /me with the Bearer token
curl -s $BASE/me -H "Authorization: Bearer $ACCESS"

# 4. Refresh
TOKENS2=$(curl -sX POST $BASE/auth/refresh -H 'content-type: application/json' \
  -d "{\"refreshToken\":\"$REFRESH\"}")

# 5. Logout
curl -sX POST $BASE/auth/logout -H 'content-type: application/json' \
  -d "{\"refreshToken\":\"$(echo $TOKENS2 | jq -r .refreshToken)\"}"
```

That is the full lifecycle. Everything else in this README is optional polish.

## What the one-line wire-up actually registers

`AddTechTeaStudioAuth(configuration)` registers:

- `ITokenProvider`, `ITokenReader` (issue / read JWTs)
- `IPasswordHasher` (PBKDF2-SHA256)
- `IRefreshTokenStore` (in-memory default; swap via the builder)
- `RefreshTokenService` (issue, rotate, revoke)
- `IRefreshClaimsResolver` (null default; supply your own)
- `ILoginAttemptTracker` (in-memory default; lockout)
- `IRevokedTokenStore` (in-memory default; JWT deny-list)
- `IAuthAuditLogger` (null default; observability sink)
- JWT bearer authentication scheme + ASP.NET Core authorization
- `RefreshTokenCleanupService` + `RevokedTokenCleanupService` background workers
- Startup validation of `AuthOptions`

All store / tracker / logger registrations use `TryAdd*`. Swap defaults via the fluent builder returned by `AddTechTeaStudioAuth(...)`:

```csharp
builder.Services.AddTechTeaStudioAuth(builder.Configuration)
    .UseRefreshTokenStore<EfCoreRefreshTokenStore<MyDbContext>>()
    .UseLoginAttemptTracker<RedisLoginAttemptTracker>()
    .UseAuthAuditLogger<MyDbAuthAuditLogger>()
    .UseClaimsProfile<MyAppClaimsProfile>()
    .UseRefreshClaimsResolver<MyClaimsResolver>();
```

## How it compares

| Library / Approach | What it gives you | Footprint | Password hashing | Refresh tokens | Multi-app claim profiles |
|---|---|---|---|---|---|
| **TechTeaStudio.Auth** | JWT + password hashing + refresh tokens + lockout + audit + 2FA + middleware | Small (~one package) | PBKDF2-SHA256, sane defaults | Built-in, single-use, rotated | First-class |
| **ASP.NET Core Identity** | Full user/role store + UI scaffolding | Large (EF Core + UI + scaffolding) | PBKDF2 (configurable) | Via separate add-on | Manual claims transformer |
| **OpenIddict / Duende IdentityServer** | OAuth2 / OIDC server | Large (server-side flows, endpoints) | Delegated to your store | First-class | Via scope/claim mapping |
| **`Microsoft.AspNetCore.Authentication.JwtBearer` (raw)** | JWT validation only | Tiny | None | None | Manual |
| **Roll your own** | Whatever you write | Whatever you write | Whatever you remember | The bug you'll ship | The mess you'll inherit |

The honest pitch: `TechTeaStudio.Auth` sits between raw `JwtBearer` plus a hand-written hasher and a full identity framework. If you are about to write your fifth `PBKDF2` helper and then realise you also need refresh-token rotation and a way to keep two apps' claim shapes from diverging, this is the package that already did all of that.

## Extras you will probably want

### One-shot signed tokens (password reset, email confirmation)

```csharp
// password reset
var token = _resetTokens.Generate(user.Id);          // 30-min default lifetime
var r     = await _resetTokens.ValidateAsync(token); // one-shot: replay returns Success=false

// email confirmation
var token = _emailTokens.Generate(user.Id, user.Email);  // 24-hour default
var r     = await _emailTokens.ValidateAsync(token);
```

Single-use is enforced via the `IRevokedTokenStore` deny-list: the `jti` of the token is revoked on the first successful validation.

### Two-factor (TOTP + recovery codes)

```csharp
var secret        = RandomNumberGenerator.GetBytes(20);
var base32Secret  = OtpAuthUri.ToBase32(secret);
var provisioning  = OtpAuthUri.Build("MyApp", user.Email, base32Secret); // otpauth://totp/...
var recoveryCodes = RecoveryCodeService.Generate();                       // 10 × 8-char codes

// Verify what the user typed from Google / Microsoft Authenticator:
var ok = TotpValidator.Validate(secret, typedCode, DateTimeOffset.UtcNow);
```

### API-key authentication scheme (machine-to-machine)

```csharp
services.AddSingleton<IApiKeyStore>(new FuncApiKeyStore((raw, ct) =>
    Task.FromResult(LookUp(raw))));
services.AddAuthentication().AddTechTeaStudioApiKey();

app.MapGet("/internal/hooks", () => "ok")
   .RequireAuthorization();
```

Reads `X-Api-Key` by default; also accepts `Authorization: ApiKey <key>` when the option is on.

### Sign in with Google / GitHub

Install `TechTeaStudio.Auth.OAuth.Google` (or `.GitHub`) and wire one extra call. See [docs/OAUTH.md](docs/OAUTH.md) for the full three-outcome flow (authenticate, link-existing, complete-registration).

## Multi-app claim profiles

Different apps want different claim shapes. The library defines `IClaimsProfile`; each app implements its own and registers it via DI:

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

The library deliberately does **not** ship product-specific profiles. Every consuming app owns its claim shape and the library stays generic.

## In-memory defaults are NOT for multi-instance production

The defaults registered by `AddTechTeaStudioAuth()` are designed for fast dev / single-instance scenarios:

- **`InMemoryRefreshTokenStore`**: lost on restart.
- **`InMemoryLoginAttemptTracker`**: a brute-forcer hitting different instances behind a load balancer bypasses lockout entirely.
- **`InMemoryRevokedTokenStore`**: JTI revoked on instance A is unknown to instance B; a stolen access token keeps working everywhere else until natural expiry.

**For any multi-instance production deployment, replace via the builder:**

```csharp
builder.Services.AddTechTeaStudioAuth(builder.Configuration)
    .UseRefreshTokenStore<EfCoreRefreshTokenStore<MyDbContext>>()   // TechTeaStudio.Auth.EFCore
    .UseLoginAttemptTracker<RedisLoginAttemptTracker>();             // TechTeaStudio.Auth.Redis
```

> **Heads up:** `TechTeaStudio.Auth.Redis` is in early-stage (v0.5). It passes the contract test kit, but `RevokeAsync(Guid)` walks every key (O(N)) and there are no production benchmarks yet. Suitable for a starting point; will be hardened with a reverse-index in v0.6+.

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

The cookie scheme defaults to `CookieSecurePolicy.SameAsRequest`, so plain `http://localhost` and on-prem deployments without TLS work out of the box. For production over HTTPS, harden by passing `o.Cookie.SecurePolicy = CookieSecurePolicy.Always` into `AddTechTeaStudioCookieAuth(...)`. HSTS is only emitted by `SecurityHeadersMiddleware` when the inbound request is HTTPS, never on HTTP.

The library refuses to start with a missing or short signing key (< 32 UTF-8 bytes).

## 401 response contract

When the bearer pipeline rejects a request, the response body is:

```json
{ "error": "token_expired", "message": "Token has expired.", "traceId": "0HMV..." }
```

`error` is a stable string from `AuthErrorCodes`:

- `missing_token`, `unauthorized`: generic.
- `token_expired`, `token_not_yet_valid`: lifetime errors.
- `invalid_signature`, `invalid_issuer`, `invalid_audience`, `malformed_token`: structural errors.

Switch on `error` on the client to drive behaviour (e.g. `token_expired` → silently call `/auth/refresh`).

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

`RefreshTokenService` (the orchestrator on top of the store):

```csharp
// Issue: device fields are optional and persisted with the row so /sessions can surface them.
Task<TokenPair> IssueAsync(string userId, IEnumerable<Claim> claims, CancellationToken ct = default);
Task<TokenPair> IssueAsync(string userId, IEnumerable<Claim> claims, string? deviceId, string? deviceInfo, CancellationToken ct = default);

// Rotate: kills the presented token, emits a new pair. Returns null on unknown / expired / replayed.
Task<TokenPair?> RotateAsync(string presentedRefreshToken, CancellationToken ct = default);
Task<TokenPair?> RotateAsync(string presentedRefreshToken, IEnumerable<Claim> claims, CancellationToken ct = default);

// Revoke: kill one session.
Task RevokeAsync(string presentedRefreshToken, CancellationToken ct = default);
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

Replace `NullAuthAuditLogger` with your own `IAuthAuditLogger` to get strongly-typed events (`LoginSucceeded`, `TokenIssued`, `RefreshReuseDetected`, ...) into a database or log sink.

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

## Build & test

```bash
dotnet build src/TechTeaStudio.Auth/TechTeaStudio.Auth.sln
dotnet test  src/TechTeaStudio.Auth/TechTeaStudio.Auth.sln
```

The library multi-targets `net6.0;net8.0;net9.0;net10.0`. `net7.0` is intentionally skipped (EOL). The test project targets `net8.0;net9.0;net10.0` only.

## Versioning & release

Version lives in `TechTeaStudio.Auth.csproj` as a 3-part `<Version>X.Y.Z</Version>`. Bump rules:

- Bug fix → `Z + 1`
- New feature, source-compatible → `Y + 1`, reset `Z = 0`
- Breaking change in public API → `X + 1` (after `1.0`), reset `Y = Z = 0`

Commit format is `vX.Y.Z <short description>`. Push to `product` triggers the shared TechTeaStudio NuGet publish workflow, which packs and pushes to nuget.org with `--skip-duplicate`. **Never push to nuget.org manually.**

See [CHANGELOG.md](CHANGELOG.md) for the full release history.

## Further reading

- [docs/RECIPES.md](docs/RECIPES.md): common patterns: login, refresh, revoke, reset, 2FA, API keys, audit.
- [docs/OAUTH.md](docs/OAUTH.md): Google / GitHub / Apple sign-in via the OAuth sibling packages.
- [docs/MIGRATION-Hyperion.md](docs/MIGRATION-Hyperion.md): moving Hyperion Omni Client onto the library.
- [docs/MIGRATION-Pello.md](docs/MIGRATION-Pello.md): moving Pello onto the library.
- [SECURITY.md](SECURITY.md): threat model and reporting policy.
- [samples/MinimalApi/](samples/MinimalApi/): runnable single-file version of the lifecycle walkthrough above.
- [samples/BlazorServer/](samples/BlazorServer/): cookie + bearer integrated into a Blazor Server app.

## License

Licensed under the [MIT License](LICENSE). Copyright &copy; Tech Tea Studio.

<p align="center">
  Built as part of the Hyperion Ecosystem by <a href="https://techteastudio.cc">TechTeaStudio</a>.
</p>
