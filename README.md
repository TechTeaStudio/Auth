<p align="center">
  <img src="https://raw.githubusercontent.com/TechTeaStudio/Auth/main/icon.png" alt="TechTeaStudio.Auth logo" width="160" />
</p>

<h1 align="center">TechTeaStudio.Auth</h1>

<p align="center">
  Drop-in authentication primitives for .NET. JWT, PBKDF2 password hashing, refresh tokens, multi-app claim profiles, and one-line ASP.NET Core wire-up &mdash; without pulling in a full identity framework.
</p>

<p align="center">
  <a href="https://www.nuget.org/packages/TechTeaStudio.Auth"><img alt="NuGet" src="https://img.shields.io/nuget/v/TechTeaStudio.Auth.svg?logo=nuget&label=NuGet" /></a>
  <a href="https://www.nuget.org/packages/TechTeaStudio.Auth"><img alt="Downloads" src="https://img.shields.io/nuget/dt/TechTeaStudio.Auth.svg?logo=nuget&label=Downloads" /></a>
  <img alt=".NET" src="https://img.shields.io/badge/.NET-6.0%20%7C%208.0%20%7C%209.0%20%7C%2010.0-512BD4?logo=dotnet&logoColor=white" />
  <a href="https://github.com/TechTeaStudio/Auth/actions/workflows/dotnet.yml"><img alt="Build" src="https://img.shields.io/github/actions/workflow/status/TechTeaStudio/Auth/dotnet.yml?branch=main&logo=github&label=build" /></a>
  <a href="LICENSE"><img alt="License" src="https://img.shields.io/badge/license-MIT-blue.svg" /></a>
</p>

> **Status:** early scaffold. Public surface is being defined under the `TSA-*` issue tracker; the first tagged release will lock it in. See [CHANGELOG.md](CHANGELOG.md) for what's planned per release.

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
| **TechTeaStudio.Auth** | JWT + password hashing + refresh tokens + middleware | Small (~one package) | PBKDF2-SHA256, sane defaults | Built-in, single-use, rotated | First-class |
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
<PackageReference Include="TechTeaStudio.Auth" Version="0.1.0" />
```

## Quick start

> The code below describes the **target API surface** (TSA-1, TSA-2, TSA-5). Signatures will be locked in with the first tagged release.

### ASP.NET Core wire-up

```csharp
using TechTeaStudio.Auth;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddTechTeaStudioAuth(options =>
{
    options.Jwt.SigningKey = builder.Configuration["Auth:SigningKey"]!;
    options.Jwt.Issuer     = "https://api.example.com";
    options.Jwt.Audience   = "example-clients";
    options.Jwt.Lifetime   = TimeSpan.FromMinutes(15);

    options.RefreshTokens.Lifetime = TimeSpan.FromDays(30);
});

var app = builder.Build();
app.UseAuthentication();
app.UseAuthorization();
```

### Issuing tokens

```csharp
public sealed class LoginEndpoint
{
    private readonly ITokenProvider _tokens;
    private readonly IPasswordHasher _passwords;
    private readonly IUserRepository _users;
    private readonly IRefreshTokenStore _refresh;

    public async Task<IResult> Handle(LoginRequest req, CancellationToken ct)
    {
        var user = await _users.FindAsync(req.Email, ct);
        if (user is null || !_passwords.Verify(req.Password, user.PasswordHash))
            return Results.Unauthorized();

        var access  = _tokens.Issue(user.Id, user.Email, user.Roles);
        var refresh = await _refresh.IssueAsync(user.Id, ct);

        return Results.Ok(new { access, refresh });
    }
}
```

### Hashing passwords

```csharp
var hash    = _passwords.Hash("correct horse battery staple");
var matches = _passwords.Verify("correct horse battery staple", hash);
```

### Rotating refresh tokens

```csharp
var newPair = await _refresh.RotateAsync(presentedRefreshToken, ct);
// returns a fresh access + refresh pair, marks the old refresh as used
```

## Multi-app claim profiles

Different apps publish different claim shapes; `TechTeaStudio.Auth` lets both work without forking the library (TSA-7).

```csharp
builder.Services.AddTechTeaStudioAuth(options =>
{
    options.ClaimProfile = ClaimProfiles.Hyperion;   // sub / unique_name / role
    // or
    options.ClaimProfile = ClaimProfiles.Pello;      // Email / DisplayName
    // or
    options.ClaimProfile = new ClaimProfile
    {
        SubjectClaim     = "uid",
        UserNameClaim    = "preferred_username",
        RoleClaim        = "role",
    };
});
```

## Security defaults

| Concern | Default | Knob |
|---|---|---|
| Password hashing | PBKDF2-SHA256, 600 000 iterations, 16-byte salt | `options.Passwords.Iterations` |
| Access token lifetime | 15 minutes | `options.Jwt.Lifetime` |
| Refresh token lifetime | 30 days | `options.RefreshTokens.Lifetime` |
| Refresh token reuse | Single-use, rotated on every refresh | not configurable |
| Signing algorithm | HS256 | (RS256 planned post-1.0) |
| Clock skew | 30 seconds | `options.Jwt.ClockSkew` |

The library refuses to start with a missing or short signing key &mdash; there is no anonymous fallback.

## Public API (target)

```csharp
public interface ITokenProvider
{
    string Issue(string subject, string userName, IEnumerable<string> roles, IDictionary<string, string>? extra = null);
    AuthTokenInfo Inspect(string token);
}

public interface ITokenReader
{
    bool TryRead(string token, out AuthTokenInfo info);
}

public interface IPasswordHasher
{
    string Hash(string password);
    bool Verify(string password, string hash);
    bool NeedsRehash(string hash);
}

public interface IRefreshTokenStore
{
    Task<string> IssueAsync(string subject, CancellationToken ct);
    Task<RefreshPair> RotateAsync(string presented, CancellationToken ct);
    Task RevokeAsync(string presented, CancellationToken ct);
    Task RevokeAllAsync(string subject, CancellationToken ct);
}

public sealed class AuthOptions
{
    public JwtOptions Jwt { get; init; } = new();
    public PasswordOptions Passwords { get; init; } = new();
    public RefreshTokenOptions RefreshTokens { get; init; } = new();
    public ClaimProfile ClaimProfile { get; init; } = ClaimProfiles.Default;
}
```

Exceptions that escape the issue/verify paths are wrapped in `AuthException` &mdash; bad signature, expired token, replayed refresh, oversize claim payload.

## Roadmap

Tracked in the `TechTeaStudioAuth` beads database. Highlights:

- **0.1.x** &mdash; core abstractions (TSA-1) + JWT HS256 (TSA-2) + PBKDF2-SHA256 (TSA-3) + in-memory refresh store (TSA-4) + `AddTechTeaStudioAuth()` (TSA-5).
- **0.2.x** &mdash; security hardening (headers, lockout, rate limit) (TSA-6), multi-app claim profiles (TSA-7), audit logger + OpenTelemetry (TSA-43).
- **0.3.x** &mdash; advanced token flows: email confirmation, password reset, M2M API keys (TSA-41).
- **0.4.x** &mdash; two-factor: TOTP + recovery codes (TSA-42).
- **1.0** &mdash; public API freeze, RS256 signing, migration guides for Hyperion and Pello (TSA-44).

## Project layout

```
Auth/
├── src/TechTeaStudio.Auth/                            <- (target shape)
│   ├── TechTeaStudio.Auth.sln
│   ├── TechTeaStudio.Auth/                            <- NuGet package source
│   │   ├── Abstractions/                              <- ITokenProvider, ITokenReader, …
│   │   ├── Jwt/                                       <- HS256 token provider/reader
│   │   ├── Passwords/                                 <- PBKDF2-SHA256 hasher
│   │   ├── RefreshTokens/                             <- store interface + in-memory impl
│   │   ├── AspNetCore/                                <- AddTechTeaStudioAuth(), middleware
│   │   ├── Profiles/                                  <- multi-app claim profiles
│   │   └── AuthOptions.cs
│   ├── TechTeaStudio.Auth.Tests/                      <- xUnit + FluentAssertions
│   └── TechTeaStudio.Auth.Sample/                     <- minimal API + Blazor sample
├── .github/workflows/dotnet.yml                       <- CI publish (shared TTS workflow)
├── CHANGELOG.md
├── LICENSE
└── README.md
```

## Build &amp; test

```bash
dotnet build src/TechTeaStudio.Auth/TechTeaStudio.Auth.sln
dotnet test  src/TechTeaStudio.Auth/TechTeaStudio.Auth.sln
```

The library multi-targets `net6.0;net8.0;net9.0;net10.0`. `net7.0` is intentionally skipped (EOL). The test and sample projects target `net8.0;net9.0;net10.0` only.

## Versioning &amp; release

Version lives in `TechTeaStudio.Auth.csproj` as a 3-part `<Version>X.Y.Z</Version>`. Bump rules:

- Bug fix &rarr; `Z + 1`
- New feature, source-compatible &rarr; `Y + 1`, reset `Z = 0`
- Breaking change in public API &rarr; `X + 1` (after `1.0`), reset `Y = Z = 0`

Commit format is `vX.Y.Z <short description>`. Push to `main` triggers the shared TechTeaStudio NuGet publish workflow, which packs and pushes to nuget.org with `--skip-duplicate`. **Never push to nuget.org manually.**

See [CHANGELOG.md](CHANGELOG.md) for the full release history.

## License

Licensed under the [MIT License](LICENSE). Copyright &copy; Tech Tea Studio.

<p align="center">
  Built as part of the Hyperion Ecosystem by <a href="https://techteastudio.cc">TechTeaStudio</a>.
</p>
