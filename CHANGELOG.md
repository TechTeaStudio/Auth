# Changelog

All notable changes to this package are documented here.
Format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.7.0] — 2026-05-13

New OAuth provider: GitHub. Authorization-code exchange via GitHub's REST API.

### New packages
- **TechTeaStudio.Auth.OAuth.GitHub** — `IExternalAuthProvider` implementation for GitHub OAuth 2.0. Public API:
  - `GitHubAuthProvider` — name `"GitHub"`. `ValidateAsync(code)` exchanges the code for an access token, fetches the user profile and primary verified email, returns `ExternalLoginInfo` or null on any failure.
  - `GitHubAuthProviderOptions` — `ClientId`, `ClientSecret`, `RequireEmailVerified` (default true), `UserAgent`.
  - `AddGitHubAuthProvider(IAuthBuilder, configure?, sectionName="Auth:GitHub")` — wires the provider with a typed `HttpClient` and binds options.

### Notes
- All other TTS packages bumped to 0.7.0 to keep the constellation aligned (following the 0.6.0 precedent when OAuth.Google was introduced).
- The provider uses `System.Text.Json` only — no `Octokit` or other heavy deps. Two HTTP calls per validation: `POST /login/oauth/access_token` then `GET /user` + `GET /user/emails`.

## [0.6.1] — 2026-05-13

NuGet packaging fix. No API changes, no source-compatibility breaks.

### Fixed

- **Hyperion (and any other consumer pinned to EF Core 9.x via Npgsql) couldn't install v0.6.0 because the EFCore packages required EF Core 10.0.0 on `net10.0`**. Dropped `net10.0` from `TechTeaStudio.Auth.EFCore` and `TechTeaStudio.Auth.OAuth.EFCore` — consumers on net10 runtime now resolve the `net9.0` build (EF Core 9.0.0), which still works on EF Core 9.x or 10.x.
- **Base `TechTeaStudio.Auth` net10 build pinned `Microsoft.AspNetCore.Authentication.JwtBearer` at 10.0.0** which conflicted with consumers on JwtBearer 9.x. Relaxed to `9.0.0` — code uses only JwtBearer APIs present since 6.x, so the assembly built against 9.0 runs fine on consumers with JwtBearer 9.x or 10.x.

### Notes

- Test project's `net10.0` TFM was dropped (same EF Core 10 InMemory conflict). net8/net9 cover the contract; net10 runtime behaviour is verified end-to-end via consumer (Hyperion) integration.

## [0.6.0] — 2026-05-13

**New chapter: OAuth / external sign-in.** Three new NuGet packages join the family. Base, EFCore, Redis, and Swashbuckle bump to 0.6.0 alongside (no breaking changes in those — coordinated minor bump).

### New packages

- **`TechTeaStudio.Auth.OAuth.Abstractions`** — provider-agnostic OAuth surface:
  - `IExternalAuthProvider` — validates raw provider credentials, normalizes to `ExternalLoginInfo`.
  - `IExternalLoginStore` — persistence of `(provider, providerUserId) → userId` links. Default `InMemoryExternalLoginStore` with SHOUTY multi-instance warning.
  - `IExternalUserBridge` — adapter to the consumer's `IUserRepository` (3 methods: find-by-email, get-by-id, create-from-external).
  - `ExternalLoginService` — three-outcome orchestrator: `Authenticated` / `RequiresPassword` / `RequiresRegistration`. Continuation tokens are HMAC-signed via `SignedTokenService`, 10-minute lifetime, single-use through `IRevokedTokenStore`.
  - `IAuthBuilder` extensions: `.AddTechTeaStudioOAuth()`, `.UseExternalLoginStore<T>()`, `.UseExternalUserBridge<T>()`, `.AddExternalAuthProvider<T>()`.
- **`TechTeaStudio.Auth.OAuth.Google`** — Google Sign-In:
  - `GoogleAuthProvider : IExternalAuthProvider` (provider name `"Google"`) using `Google.Apis.Auth 1.69.0`.
  - Multi-audience support — one backend serves Web + Android + iOS + Desktop client IDs.
  - `.AddGoogleAuthProvider()` binds `Auth:Google` configuration.
- **`TechTeaStudio.Auth.OAuth.EFCore`** — `ExternalLoginEntity` + `EfCoreExternalLoginStore<TContext>` + `ModelBuilder.AddTechTeaStudioExternalLogins()`. Unique index on `(Provider, ProviderUserId)`, composite index on `(UserId, Provider)`, `ConcurrencyStamp` token.

### Tests

- 20 new tests covering `ExternalLoginService` (all four flows + continuation-token single-use + invalid credential paths), `EfCoreExternalLoginStore` (contract behavior), `GoogleAuthProvider` (error normalization). 161/161 total across net8/9/10.

### Reference docs

- **[docs/OAUTH.md](docs/OAUTH.md)** — end-to-end Hyperion wire-up: csproj, config, `IExternalUserBridge` implementation, controller (four endpoints, one line each), mobile flow, custom-provider template (GitHub).

### Bumped (no API changes)

- `TechTeaStudio.Auth` → 0.6.0
- `TechTeaStudio.Auth.EFCore` → 0.6.0
- `TechTeaStudio.Auth.Redis` → 0.6.0
- `TechTeaStudio.Auth.Swashbuckle` → 0.6.0

## [0.5.0] — 2026-05-13

Breaking-change cleanup release. Driven by a critical self-review of v0.4.0 — fixes a real DI bug, a silent SignedTokenService failure mode, a SQL Server-only EFCore bug, a Swashbuckle Minimal-API miss, plus architectural cleanup (product-specific code out of the library).

### Breaking changes

- **`AuthOptions` is now nested.** Top-level flat properties moved into sections:
  - `Auth:SecretKey` → `Auth:Jwt:SecretKey`
  - `Auth:Issuer` → `Auth:Jwt:Issuer`
  - `Auth:Audience` → `Auth:Jwt:Audience`
  - `Auth:TokenLifetime` → `Auth:Jwt:TokenLifetime`
  - `Auth:ClockSkew` → `Auth:Jwt:ClockSkew`
  - `Auth:Signing` → `Auth:Jwt:Signing`
  - `Auth:RefreshTokenLifetime` → `Auth:RefreshTokens:Lifetime`
  - `Auth:RevokeChainOnRefreshReuse` → `Auth:RefreshTokens:RevokeChainOnReuse`
  - `Auth:RefreshTokenCleanupInterval` → `Auth:RefreshTokens:CleanupInterval`
  - `Auth:MaxFailedLoginAttempts` → `Auth:Lockout:MaxFailedAttempts`
  - `Auth:LockoutDuration` → `Auth:Lockout:Duration`
- **`AddTechTeaStudioAuth(...)` returns `IAuthBuilder`** (was `IServiceCollection`). All default registrations switched to `TryAdd*` so user-provided implementations win. Swap defaults via the fluent builder: `.UseRefreshTokenStore<T>()`, `.UseLoginAttemptTracker<T>()`, `.UseRevokedTokenStore<T>()`, `.UseAuthAuditLogger<T>()`, `.UseClaimsProfile<T>()`, `.UseRefreshClaimsResolver<T>()`. Same builder is extended from sibling packages (EFCore / Redis).
- **Removed `HyperionClaimsProfile`, `PelloClaimsProfile`, `ClaimsProfiles`.** Implement your own `IClaimsProfile` in each app — the library only defines the abstraction. Migration guides show how.
- **Removed `AuthClaims.LegacyNameId` + `JwtTokenReader.TryRead` fallback to `nameid`.** Hyperion-specific. If you consume legacy tokens, wrap `JwtTokenReader` locally.
- **Removed `AuthRateLimit*` extensions.** Wire `Microsoft.AspNetCore.RateLimiting` yourself — every app's "good limits" differ, and the standard middleware is fine.
- **Removed `X-XSS-Protection` from `SecurityHeadersMiddleware`.** Deprecated header; can introduce XSS in legacy browsers (MDN, OWASP).

### Fixed

- **`SignedTokenService` HMAC key resolution.** Previously used `AuthOptions.SecretKey` directly, which broke silently after migrating to `Signing.Keys` (RS256/ES256). Now resolves via `SigningKeyResolver.ResolveServerHmacKey`.
- **`TechTeaStudio.Auth.EFCore` cross-provider concurrency.** Replaced `uint RowVersion` (Postgres-only) with `string ConcurrencyStamp` — works on SQL Server / Postgres / SQLite / MySQL.
- **`TechTeaStudio.Auth.Swashbuckle` Minimal-API support.** `AttachBearerToAuthorizedOperationsFilter` now reads `EndpointMetadata` for `IAuthorizeData`, so `app.MapGet(...).RequireAuthorization()` endpoints get the lock icon.
- **DI overrides actually work.** Default `IRefreshTokenStore`, `ILoginAttemptTracker`, etc. now register via `TryAddSingleton`. Previously a consumer's `AddScoped<IRefreshTokenStore, EfCoreRefreshTokenStore<...>>()` was silently overwritten.
- **`AuthOptionsValidator` registered via `TryAddEnumerable`** so it coexists with the framework's DataAnnotations validator (was being skipped before).

### Added

- **`IRefreshClaimsResolver`** + `RefreshTokenService.RotateAsync(string, CancellationToken)` overload. Caller no longer needs to thread claims through refresh endpoints — register a resolver once and the service rebuilds them from the user id encoded in the refresh-token row.
- **`SigningKeyResolver.BuildValidationParameters(AuthOptions)`** moved here from `JwtTokenProvider` (cleaner home). Plus `ResolveServerHmacKey` for non-JWT signed tokens.
- **SHOUTY XML-doc warnings** on `InMemoryRefreshTokenStore`, `InMemoryLoginAttemptTracker`, `InMemoryRevokedTokenStore` so the multi-instance pitfall is unmissable in IntelliSense.
- **JWKS `Cache-Control: public, max-age=600`** header.
- **Cookie scheme `SecurePolicy = SameAsRequest`** by default — works on `http://localhost` and HTTP-only homelab / on-prem deployments. Production over HTTPS should override to `Always`.
- **`RefreshCookieHelper.Write/Clear`** now accept a `requireHttps` flag.
- **`TokenHasher.NewRawToken()`** promoted to `public` so consumers can mint refresh-token strings without going through `RefreshTokenService`.
- **`MaxChainWalkDepth` constant** + comment in `RefreshTokenService` (replaces the magic `1000`).

### Sibling packages (also at 0.5.0)

- `TechTeaStudio.Auth.Swashbuckle` — Minimal-API support; no longer references the base `TechTeaStudio.Auth` project (uses local string constant + framework reference for ASP.NET Core types).
- `TechTeaStudio.Auth.EFCore` — `ConcurrencyStamp` instead of `RowVersion`.
- `TechTeaStudio.Auth.Redis` — unchanged code; documented as early-stage (`RevokeAsync(Guid)` is O(N); reverse-index pass deferred to v0.6).

## [0.4.0] — 2026-05-13

Signing-key rotation with `kid`, multi-key validation window, optional asymmetric signing (RS256 / ES256), authorization policy helpers, cookie auth scheme, rate-limit integration, and a JWKS endpoint.

### Added
- **Signing-key rotation** — `AuthOptions.Signing.Keys`, `Signing.ActiveKid`, `Signing.KeyRetention` (default 7d). Tokens carry a `kid` header; the bearer pipeline picks the right key by `kid` and accepts every descriptor in the retention window. Rotation is hot-reloaded via `IOptionsMonitor` — no host restart. (TSA-55, TSA-56)
- **RS256 / ES256 asymmetric signing** — `SigningAlgorithm` enum, PEM-loaded private/public keys, `SigningKeyResolver` builds the matching `SecurityKey`. HS256 stays the zero-config default. (TSA-57)
- **JWKS endpoint** — `endpoints.MapTechTeaStudioJwks()` serves `/.well-known/jwks.json` with the public-key half of every RS256/ES256 descriptor in retention. HMAC entries are intentionally excluded. (TSA-57)
- **Authorization policy helpers** — `AuthPolicies` constants + `AddTechTeaStudioPolicies()` extension wires four built-ins: `Authenticated`, `RequireSubject`, `RequireEmail`, `EmailVerified`. Backed by `HasClaimAuthorizationHandler` — no inline `RequireClaim` magic strings. (TSA-67)
- **Cookie auth scheme** — `.AddTechTeaStudioCookieAuth()` registers a hardened cookie scheme (`HttpOnly`, `SameSite=Strict`, `Secure=Always`) alongside the bearer scheme. API requests get a JSON 401/403 instead of a redirect. `RefreshCookieHelper` writes / reads / clears the refresh-token cookie. (TSA-70)
- **Rate-limit integration** (net8+) — `AddTechTeaStudioRateLimit()` registers the `tts-auth-login` fixed-window policy (5 requests / IP / minute by default). 429 response is JSON, matching the 401 contract. (TSA-69)
- **`JwtTokenProvider.BuildValidationParameters(AuthOptions)`** — public helper that mirrors the bearer pipeline's validation parameters. Useful for self-validation in worker / message-bus consumers.

### Changed
- **`JwtTokenProvider` ctor** now takes `IOptionsMonitor<AuthOptions>` (DI provides this automatically). The previous `IOptions<AuthOptions>` ctor was removed because both ctors made DI's resolver ambiguous. For non-DI / test paths use `JwtTokenProvider.ForOptions(IOptions<...>)` or the in-tree `AuthOptions.ToMonitor()` extension.
- **`AuthOptions.SecretKey`** is no longer marked `[Required]` / `[MinLength(32)]` at the DataAnnotations level. The cross-property `AuthOptionsValidator` enforces it conditionally: required only when `Signing.Keys` is empty.
- **Library now references `Microsoft.AspNetCore.App` framework reference** to pick up `Microsoft.AspNetCore.Routing`, `Microsoft.AspNetCore.Authentication.Cookies`, and (on net8+) `Microsoft.AspNetCore.RateLimiting` without per-TFM `PackageReference` entries.

### Backward compatibility
- Apps using the legacy single `SecretKey` HS256 path keep working — when `Signing.Keys` is empty the library synthesizes a single HS256 descriptor with `kid = "default"`.
- Tokens issued by 0.3.x (no `kid` header) keep validating: the bearer middleware's `IssuerSigningKeyResolver` returns the full key set when the header is absent.

## [0.3.1] — 2026-05-13

CI/CD trigger moved to the `product` release branch to match the TechTeaStudio convention.

### Changed
- `.github/workflows/dotnet.yml` now triggers on `push` / `pull_request` to `product` (was `main`).
- README badge URL, raw-image URL, and the "Versioning & release" section updated accordingly.
- `CLAUDE.md` release-flow steps updated to push to `product`.

## [0.3.0] — 2026-05-13

Documentation, CI/CD pipeline, and the Hyperion-legacy `nameid` claim adapter.

### Added
- **CI/CD** — `.github/workflows/dotnet.yml` invokes the shared `TechTeaStudio/.github` reusable NuGet publish workflow on push/PR to `product`. Build, test, pack, and publish with `--skip-duplicate`. (TSA-9, TSA-38, TSA-39, TSA-40)
- **Hyperion-legacy `nameid` fallback** — `JwtTokenReader.TryRead` now reads `UserId` from `nameid` when `sub` is absent. Lets a service that consumes tokens issued by pre-`TechTeaStudio.Auth` Hyperion code parse them without rewrite. (TSA-73)
- **[docs/RECIPES.md](docs/RECIPES.md)** — 10 patterns covering login, refresh, immediate revocation, password reset, email confirmation, 2FA, API-key M2M auth, custom audit sink, metrics scraping, and multi-app claim profiles. (TSA-78)
- **[docs/MIGRATION-Hyperion.md](docs/MIGRATION-Hyperion.md)** — step-by-step migration guide for the Hyperion Omni Client, with a lazy-upgrade strategy for the password hash. (TSA-71)
- **[docs/MIGRATION-Pello.md](docs/MIGRATION-Pello.md)** — three-step migration guide for Pello, including the plain-text → PBKDF2 password backfill. (TSA-72)
- **[SECURITY.md](SECURITY.md)** — threat model, defenses shipped, hardening checklist, and the security-reporting policy. (TSA-75)
- **README rewrite** — re-aligned to the actually shipped public API; replaced the aspirational v0.1 quick-start with working snippets and added 401 contract / observability sections. (TSA-74)

### Deferred to a later release
- Minimal-API and Blazor sample apps. (TSA-76, TSA-77)
- BenchmarkDotNet project. (TSA-79)
- TSA-67..70 (authorization policy helpers, Swagger Bearer integration, rate limiter, cookie scheme), TSA-55..57 (signing-key rotation, multi-key validation, RS256/ES256), TSA-49/TSA-50 (EF Core / Redis stores), TSA-52 (Redis lockout) remain on the roadmap.

## [0.2.0] — 2026-05-13

Security hardening, observability, single-use signed tokens, TOTP, recovery codes, and an API-key authentication scheme.

### Added
- **`SecurityHeadersMiddleware`** + `app.UseSecurityHeaders()` extension. Sets `X-Content-Type-Options`, `X-Frame-Options`, `X-XSS-Protection`, `Referrer-Policy`, and `Strict-Transport-Security` (on HTTPS only). (TSA-28)
- **`ILoginAttemptTracker`** + `InMemoryLoginAttemptTracker` with configurable threshold (`AuthOptions.MaxFailedLoginAttempts`) and duration (`AuthOptions.LockoutDuration`). Registered as a singleton by `AddTechTeaStudioAuth()`. (TSA-29, TSA-30)
- **Revoked-token deny-list** — `IRevokedTokenStore`, `InMemoryRevokedTokenStore`, `NullRevokedTokenStore`, `RevokedTokenCleanupService`. The bearer pipeline consults the store on `OnTokenValidated`; revoked tokens fail authentication immediately. (TSA-53)
- **Audit + observability** — `IAuthAuditLogger` + `NullAuthAuditLogger` (default) + `InMemoryAuthAuditLogger` (bounded ring buffer). Strongly-typed events: `LoginSucceeded`, `LoginFailed`, `TokenIssued`, `TokenRefreshed`, `TokenRevoked`, `RefreshReuseDetected`, `AccountLocked`. (TSA-64)
- **`AuthDiagnostics`** static class — `ActivitySource` and `Meter` named `TechTeaStudio.Auth`, plus six Prometheus-friendly counters (`tts_auth_login_*_total`, `tts_auth_tokens_*_total`, `tts_auth_refresh_*_total`, `tts_auth_accounts_locked_total`). Picked up automatically by any OpenTelemetry listener. `RefreshTokenService` is wired up to emit events and increment counters. (TSA-65, TSA-66)
- **Single-use signed tokens** — `SignedTokenService` (HMAC-SHA256, base64url, purpose + jti + exp) + `EmailConfirmationTokenService` (24h default) + `PasswordResetTokenService` (30min default). Replay is prevented via the deny-list — successful validation revokes the `jti`. (TSA-58, TSA-59)
- **API-key authentication scheme** — `IApiKeyStore` (and `FuncApiKeyStore` for tests), `ApiKeyAuthenticationOptions`, `ApiKeyAuthenticationHandler`. Reads `X-Api-Key` by default and optionally `Authorization: ApiKey <key>`. Registered via `.AddTechTeaStudioApiKey()` on `AuthenticationBuilder`. (TSA-60)
- **TOTP (RFC 6238)** — `TotpGenerator` + `TotpValidator`, pure functions, no I/O. Default 30-second period, 6-digit code, HMAC-SHA1. Validator runs in constant time and tolerates ±1 step of clock skew by default. (TSA-61)
- **Recovery codes** — `RecoveryCodeService.Generate/Hash/Verify`. Friendly alphabet (no `0/O/1/I/L`), SHA-256 hash at rest, constant-time verification. (TSA-62)
- **2FA enrollment contracts** — `I2FaEnrollmentService` interface (consumers bridge to their own user store), `TwoFactorEnrollmentStart` record, and `OtpAuthUri` helper that produces `otpauth://` provisioning URIs and base32 encoding. (TSA-63)

### Changed
- `RefreshTokenService` accepts an optional `IAuthAuditLogger` and now emits `TokenIssued`, `TokenRefreshed`, and `RefreshReuseDetected` events alongside the matching `AuthDiagnostics` counter increments.
- `AddTechTeaStudioAuth()` now registers `ILoginAttemptTracker`, `IRevokedTokenStore`, `IAuthAuditLogger` (null sink), `SecurityHeadersMiddleware`, and the `RevokedTokenCleanupService` background service.

### Deferred to a later release
- Authorization policy helpers, OpenAPI Bearer security scheme, ASP.NET Core rate-limiter integration, cookie scheme. (TSA-67 … TSA-70)
- Signing-key rotation with `kid`, multi-key validation window, RS256/ES256 asymmetric signing. (TSA-55 … TSA-57)
- EF Core / Redis refresh-token stores. (TSA-49, TSA-50)
- BenchmarkDotNet project. (TSA-79)

## [0.1.0] — 2026-05-13

Initial release. Public API may still adjust in 0.1.x before being locked at 1.0.

### Added
- **Core abstractions** under `TechTeaStudio.Auth.Abstractions`: `ITokenProvider`, `ITokenReader`, `IPasswordHasher`, `IRefreshTokenStore`, `RefreshToken`, `AuthTokenInfo`, `AuthClaims`. (TSA-10 … TSA-16)
- **JWT (HS256)** — `JwtTokenProvider` issues and validates tokens against `AuthOptions`; `JwtTokenReader` parses without validation for cheap claim inspection. (TSA-17, TSA-18, TSA-19)
- **PBKDF2-SHA256 password hashing** — `Pbkdf2PasswordHasher`. 600 000 iterations, 16-byte salt, 32-byte digest, single Base64 string with a 1-byte algorithm version prefix. `Verify` runs in constant time via `CryptographicOperations.FixedTimeEquals`. (TSA-20, TSA-21)
- **AuthOptions** with DataAnnotations + a cross-property `AuthOptionsValidator` (`IValidateOptions<AuthOptions>`). Validation runs at host startup via an `IHostedService` shim — no extra package needed. (TSA-12, TSA-27)
- **Refresh-token system** — `RefreshTokenService` (issue / rotate / revoke) on top of a pluggable `IRefreshTokenStore`. Tokens are hashed (SHA-256) at rest via `TokenHasher`; raw tokens never reach the store. Presenting a revoked token revokes the whole rotation chain when `AuthOptions.RevokeChainOnRefreshReuse` is on (default true). (TSA-22, TSA-23, TSA-45, TSA-46, TSA-47)
- **`InMemoryRefreshTokenStore`** as the default store for single-instance apps and tests. (TSA-23)
- **`RefreshTokenCleanupService`** background service deletes expired rows on `AuthOptions.RefreshTokenCleanupInterval` (default 1h). Exceptions are logged and swallowed. (TSA-48)
- **`RefreshTokenStoreContractTests`** — abstract xUnit fixture for any `IRefreshTokenStore` implementation; the in-memory store passes the full kit. Reusable by future EF Core / Redis stores. (TSA-51)
- **Multi-app claim profiles** under `TechTeaStudio.Auth.Profiles`: `IClaimsProfile`, `HyperionClaimsProfile` (`sub` / `unique_name` / `email` / `role` + legacy `nameid`), `PelloClaimsProfile` (`email` / `unique_name`). (TSA-31, TSA-32, TSA-33)
- **ASP.NET Core integration** — `AddTechTeaStudioAuth(IConfiguration, Action<AuthOptions>?)` wires JWT bearer, authorization, the password hasher, the in-memory refresh store, the cleanup background service, and startup validation. `AddTechTeaStudioAuthCore(...)` is the same minus the bearer pipeline for worker / console hosts. (TSA-24, TSA-25)
- **Custom 401 JSON** via `JwtBearerEvents.OnChallenge`. Body is `{ error, message, traceId }`; `error` is a stable string from `AuthErrorCodes`. (TSA-26, TSA-54)
- **Multi-targeting** — library targets `net6.0;net8.0;net9.0;net10.0`. Test project targets `net8.0;net9.0;net10.0`. `net7.0` is intentionally skipped (EOL). (TSA-80)

### Security
- Library refuses to start with a missing or short signing key (< 32 UTF-8 bytes).
- Refresh tokens are single-use, rotated on every refresh, and hashed at rest.
- Password verification uses constant-time comparison.

### Roadmap (subsequent releases, tracked in `TechTeaStudioAuth` / `TSA-*`)
- Security hardening: headers middleware, account-lockout primitives, signing-key rotation with `kid`, optional RS256/ES256. (TSA-28 … TSA-30, TSA-55 … TSA-57)
- Audit + observability: `IAuthAuditLogger`, OpenTelemetry `ActivitySource`, `System.Diagnostics.Metrics` counters. (TSA-43, TSA-64 … TSA-66)
- Advanced token flows: email confirmation, password reset, M2M API keys. (TSA-41, TSA-58 … TSA-60)
- Two-factor auth: TOTP, recovery codes, enrollment workflow. (TSA-42, TSA-61 … TSA-63)
- EF Core / Redis refresh-token stores. (TSA-49, TSA-50)
- ASP.NET Core extras: authorization policy helpers, Swagger Bearer integration, rate limiter, cookie scheme. (TSA-67 … TSA-70)
- Packaging & CI/CD pipeline. (TSA-9, TSA-38 … TSA-40)
- Migration guides for Hyperion and Pello; sample apps; SECURITY.md. (TSA-44, TSA-71 … TSA-78)
