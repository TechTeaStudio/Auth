# Changelog

All notable changes to this package are documented here.
Format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
