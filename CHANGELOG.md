# Changelog

All notable changes to this package are documented here.
Format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
