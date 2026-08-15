# Changelog

All notable changes to this package are documented here.
Format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.11.0] - 2026-08-15

Driven by a real consumer again: Chronos wired up the OAuth stack, and three separate things stopped it from ever completing a sign-in. Two were library defects, the third was a missing provider. All sibling packages version-aligned.

### Fixed

- **`ExternalLoginService` resolves provider names case-insensitively.** The registry was keyed with `StringComparer.Ordinal`, so `SignInAsync("google", ...)` against a registered `GoogleAuthProvider` (whose `Name` is `"Google"`) answered `Failed("unknown_provider")` - indistinguishable from a provider that was never registered. Provider packages pick their own capitalisation while consumers route on lowercase path segments, so the two spellings meet in every integration; nothing in the error named the cause. The stored `ExternalLogin.Provider` still carries the provider's own canonical `Name`, so persisted links keep one spelling and existing rows keep matching.

### Added

- **`EfCoreExternalLoginStore<TContext>` accepts an `IDbContextFactory<TContext>`.** The store previously took a `TContext` directly, which a Blazor Server host cannot supply: those apps register `AddDbContextFactory` and no scoped `DbContext` at all, because component lifecycle methods on one circuit run concurrently and would share a change tracker. The new constructor opens and disposes a context per operation, which also keeps this store's `SaveChangesAsync` from flushing entities the caller happened to be tracking. The original constructor is unchanged.
- **`TechTeaStudio.Auth.OAuth.Microsoft`** - Microsoft Entra ID (Azure AD) v2.0 sign-in, the sibling `docs/OAUTH.md` has promised since 0.6. Takes an authorization code like the GitHub provider, trades it for an id_token, and validates that token against the tenant JWKS: audience pinned to `ClientId`, issuer rebuilt from the token's own `tid` (the only way to check a `common`-authority issuer), a configured tenant GUID additionally pinning that `tid`, and one automatic retry when Entra rolls a signing key. `ProviderUserId` is `tid.oid`, per Microsoft's own guidance that `oid` alone repeats across tenants while `sub` is pairwise per application. Deliberately does NOT depend on `Microsoft.IdentityModel.Protocols.OpenIdConnect`: the JWKS document is one GET and `JsonWebKeySet` parses it, so the discovery dependency would only drag a second IdentityModel version line into every consumer.
- **`UseExternalLoginStore(Func<IServiceProvider, IExternalLoginStore>, lifetime)`** - a delegate overload beside the generic one. Registering `EfCoreExternalLoginStore<TContext>` by type is ambiguous the moment a host calls `AddDbContextFactory`, because that registers a scoped `TContext` alongside the factory and both constructors then resolve: `Microsoft.Extensions.DependencyInjection` refuses to guess and throws "The following constructors are ambiguous" - at resolve time, so a web app meets it on the first request that touches sign-in rather than at startup. Naming the constructor in a delegate removes the guess.
- **`net10.0` builds for `TechTeaStudio.Auth.EFCore` and `TechTeaStudio.Auth.OAuth.EFCore`.** Every other package already multi-targeted it; these two stopped at net9.0 because a net10 build pins EF Core 10.0.0 and `Npgsql.EntityFrameworkCore.PostgreSQL` had no 10.x release, which would have forced net10 consumers onto an EF version their provider could not match. Npgsql 10.0.0 shipped, so the block is gone - and a real net10 asset beats the TFM fallback that was quietly handing net10 apps on EF Core 10 an assembly compiled against EF Core 9. The test project now runs on net10.0 as well as net8.0 and net9.0.
- **`TechTeaStudio.Auth.Providers.Telegram`** - Telegram Login Widget sign-in. Named `Providers`, not `OAuth`, because it is not OAuth: there is no authorization code and no token endpoint, Telegram just signs the profile with an HMAC keyed by `SHA256(bot_token)` and hands it to the browser. `TelegramLoginValidator` is a pure function over the payload (query-string or the JSON shape the `data-onauth` callback receives), with a constant-time digest comparison and a mandatory `auth_date` freshness window - the payload has no nonce and no single-use marker, so that window IS the replay defence. `TelegramLoginProvider` puts it behind the ordinary `IExternalAuthProvider` contract; it never reaches the network. Telegram discloses no address, so `Email` is always null and every first sign-in lands in the host's `RequiresRegistration` branch.

## [0.10.0] - 2026-08-12

Driven by a real consumer: Chronos's /api/v1 mobile surface needed per-call token audiences and stolen-refresh-token detection, and had to build both outside the library. Folded back in as first-class features. All sibling packages version-aligned.

### Added

- **`TokenDescriptor` + `ITokenProvider.CreateToken(userId, claims, TokenDescriptor)`** - per-call `Audience`/`Issuer`/`Lifetime`/`NotBefore` overrides; null members fall back to configured `AuthOptions`. Existing overloads byte-compatible; the sub/jti/iat invariant and reserved-claim stripping apply identically on the new path. Validating a per-call audience is the consumer's job via its own JwtBearer configuration - `ITokenReader` stays pinned to the configured audience (documented).
- **Refresh-token families with reuse detection.** `RefreshToken.FamilyId`: a login mints a family, rotation preserves it, and presenting an already-revoked token burns the ENTIRE family in O(1) via the new `IRefreshTokenStore.RevokeFamilyAsync` (implemented in InMemory, EFCore and Redis stores) - replacing the old N-hop `ReplacedByTokenHash` chain walk and `MaxChainWalkDepth`, now removed.
- **`RefreshOutcome` enum + `RotateWithOutcomeAsync`** - `Success` / `Invalid` / `Expired` / `ReusedFamilyRevoked` are now distinguishable; naturally-expired-but-never-revoked tokens answer `Expired` with no family burn (previously folded into the replay branch). The `TokenPair?`-returning `RotateAsync` overloads forward to the new path and behave as before for existing callers.
- **`RefreshTokenService.RevokeAllForUserAsync(userId)`** - service-level wrapper for password-change / logout-everywhere flows (previously store-only).
- **EFCore `SchemaMigrations`: idempotent `FamilyId` column + index helpers** for Postgres, SqlServer and Sqlite (Sqlite uses a two-statement ALTER+UPDATE because its ADD COLUMN rejects non-constant defaults).

### Changed

- A lost same-instant CAS race during rotation (two concurrent presentations of the SAME still-valid token) reports `Invalid` for the loser and does NOT burn the family - the winner's fresh session survives. Deliberate safer-by-default choice, documented on `RotateWithOutcomeAsync`; consumers wanting stricter treat-lost-race-as-reuse semantics can layer it on top.
- Breaking for hand-written `IRefreshTokenStore` implementations: the interface gained `RevokeFamilyAsync` (minor-version bump per the pre-1.0 policy).

## [0.9.0] — 2026-07-14

Critical production fix. A captive `RefreshTokenService` singleton plus load-then-save races in `EfCoreRefreshTokenStore` caused intermittent `DbUpdateConcurrencyException` on login/refresh/revoke under real traffic, and refused to start at all in Development when a consumer wired up a SCOPED `IRefreshTokenStore` (the documented `EfCoreRefreshTokenStore<TContext>` pattern).

### Fixed

- **`RefreshTokenService` is now `TryAddScoped`, not `TryAddSingleton`.** Swapping in a scoped `IRefreshTokenStore` used to make the singleton `RefreshTokenService` capture ONE store instance — and therefore one `DbContext` — for the entire process lifetime: a shared change tracker across every request, stale tracked `RefreshTokenEntity` rows, and `DbUpdateConcurrencyException` on unrelated requests whenever any `SaveChangesAsync` flushed them. In Development, `BuildServiceProvider(new ServiceProviderOptions { ValidateOnBuild = true, ValidateScopes = true })` refused to start at all ("Cannot consume scoped service ... from singleton ..."). `InMemoryRefreshTokenStore` and `InMemoryRevokedTokenStore` stay singleton by design (process-lifetime stateful); a scoped consumer of a singleton dependency is legal, so this is not a captive dependency.
- **`RefreshTokenCleanupService` and `RevokedTokenCleanupService` no longer take their store as a constructor dependency.** Both are hosted as singletons; a directly-injected scoped store either failed DI validation or became the same captive-dependency bug as above, just on the background cleanup path. They now take an `IServiceScopeFactory` and resolve `IRefreshTokenStore` / `IRevokedTokenStore` from a fresh scope on every tick.
- **`EfCoreRefreshTokenStore<TContext>.RevokeAsync` / `RevokeAllForUserAsync` / `CleanupExpiredAsync` / `DeleteAllForUserAsync` no longer load-then-save.** The previous pattern (query a tracked entity, mutate, `SaveChangesAsync`) threw `DbUpdateConcurrencyException` whenever the row's `ConcurrencyStamp` had already moved — e.g. two requests racing a rotation/revoke, or a captive `DbContext` (see above) holding a stale tracked copy. On `net8.0`/`net9.0` all four methods are now single, set-based `ExecuteUpdateAsync`/`ExecuteDeleteAsync` calls that bypass the change tracker entirely — a concurrently-mutated row can no longer produce a spurious concurrency exception, and 0 rows affected (unknown id, already revoked, already deleted) is treated as success (revocation and cleanup are idempotent by contract). `net6.0` (no `ExecuteUpdate`/`ExecuteDelete` before EF Core 7) keeps the load-then-save shape but now catches `DbUpdateConcurrencyException` and retries — bounded, 3 attempts — against the row's current database values instead of throwing.
- **`RevokeAsync` with a supplied `replacedByTokenHash` backfills the rotation-chain successor only when that slot is still empty.** When a row is already revoked and a successor hash is supplied, it is recorded *only if* `ReplacedByTokenHash` is currently null — never overwriting an existing one. This is load-bearing for the revoke-first `RotateAsync`: the compare-and-swap loser reaches this branch *after* the winner has stamped its own (issued) successor, and the loser's hash is a phantom it never persists. An unconditional overwrite here would point the revoked row at a non-existent token and silently break `RevokeChainOnReuse` — the exact chain this release hardens. Consistent across all three stores.
- **`RefreshTokenService.RotateAsync` no longer double-spends under concurrency or a downstream failure.** It used to read the presented token, `CreateAsync` the successor, then `RevokeAsync` the original — ignoring the outcome. Two parallel rotations of the same token both passed the active check and both created a successor (a session fork visible only in an audit log diff), and if `RevokeAsync` failed/timed out after `CreateAsync` succeeded, both the original and the successor stayed live. `RevokeAsync` is now called **first**, and only the caller whose call transitions the row from active to revoked (the compare-and-swap winner) proceeds to `CreateAsync`; every other concurrent caller gets `null` back, same as presenting an already-revoked token. A failure in `CreateAsync` now leaves the presented token revoked with no successor — fail-closed (forces re-login) instead of forking.
- **`IRefreshTokenStore.RevokeAsync` return value is now meaningful across every implementation.** `InMemoryRefreshTokenStore` uses `ConcurrentDictionary.TryUpdate` with retry as the compare-and-swap; `EfCoreRefreshTokenStore<TContext>` derives it from `ExecuteUpdateAsync`'s rows-affected count (net8+) or from the row's loaded `RevokedAt` state (net6 load-then-save fallback); `RedisRefreshTokenStore` returns `false` without writing when the row is already revoked or unknown (the underlying read-then-write race in that store is unchanged — tracked as a separate finding to make atomic via Lua).

### Breaking

- **`IRefreshTokenStore.RevokeAsync` now returns `Task<bool>` instead of `Task`.** `true` iff that specific call transitioned an active row to revoked; `false` when the row was already revoked or unknown (idempotent). Any external `IRefreshTokenStore` implementation must update its signature and return the compare-and-swap result — callers that ignore the return value (chain-walk revocation, manual `RevokeAsync(string)`) are unaffected.
- `RefreshTokenCleanupService` and `RevokedTokenCleanupService` constructors changed: they take `IServiceScopeFactory` instead of `IRefreshTokenStore` / `IRevokedTokenStore`. Both types are `sealed` and are only ever meant to be constructed by DI via `AddHostedService<T>()`; if you were manually `new`-ing one, update the call site.
- If your app injects `RefreshTokenService` into a singleton of your own, that is no longer valid — resolve it from a scope. (This was already a captive-dependency bug before; it just didn't always throw.)

### Notes

- Audited every other registration that consumes `IRefreshTokenStore` / `IRevokedTokenStore` for the same lifetime mismatch: `TechTeaStudio.Auth.Redis` and `TechTeaStudio.Auth.EFCore` ship no DI registration extensions of their own (consumers wire the store via `.UseRefreshTokenStore<TStore>()`), and `TechTeaStudio.Auth.OAuth.Abstractions`'s `ExternalLoginService` was already `TryAddScoped` — no other lifetime fixes were needed.
- Test project gained a `Microsoft.EntityFrameworkCore.Sqlite` reference (net8.0/net9.0) alongside the existing InMemory one — `Microsoft.EntityFrameworkCore.InMemory` does not support `ExecuteUpdateAsync`/`ExecuteDeleteAsync` at all, so `EfCoreRefreshTokenStoreContractTests` moved from the InMemory provider to a Sqlite in-memory connection. New `EfCoreRefreshTokenStoreConcurrencyTests` reproduces the captive/race scenario directly against two independent `DbContext` instances sharing one Sqlite connection.
- All TTS packages bumped to 0.9.0 to keep the constellation aligned.

## [0.8.2] — 2026-05-19

Critical schema-migration fix. **Anyone on 0.8.0 or 0.8.1 must re-run `SchemaMigrations.AddDeviceColumnsSql*` after upgrading to 0.8.2** (the helper is idempotent — re-running is safe).

### Fixed

- **`SchemaMigrations.AddDeviceColumnsSql*` was missing the `ConcurrencyStamp` column.** The `0.8.0` change to `RefreshTokenEntity` introduced THREE new columns — `DeviceId`, `DeviceInfo`, and `ConcurrencyStamp` — but `SchemaMigrations` shipped with ALTER statements for only the first two. `RefreshTokenEntity.ConcurrencyStamp` is wired through `ModelBuilderExtensions.AddTechTeaStudioRefreshTokens` as `.IsRequired().HasMaxLength(64).IsConcurrencyToken()`, so EF Core attempts to use the column in every INSERT/UPDATE; when the column does not exist in the database, `EfCoreRefreshTokenStore.CreateAsync` throws `DbUpdateConcurrencyException("The database operation was expected to affect 1 row(s), but actually affected 0 row(s)")` and every refresh-token issuance fails — taking down login, register, refresh, and every OAuth flow.

  The Postgres helper now adds:
  ```sql
  ALTER TABLE "TtsRefreshTokens" ADD COLUMN IF NOT EXISTS "ConcurrencyStamp" varchar(64) NOT NULL DEFAULT gen_random_uuid()::text;
  ```
  with equivalent variants for SQL Server (`NEWID()` default) and SQLite (`lower(hex(randomblob(16)))` default), so pre-existing rows backfill safely.

- **Tracked in Hyperion as v0.2.6.12 (commit `ba13401`)** — Hyperion's docker-migrations directory got a separate `028_tts_refresh_tokens_concurrency_stamp.sql` because the bad 0.8.0 helper was already baked into Hyperion's deployed migration `027_tts_refresh_tokens_device_columns.sql`.

### Lesson for future schema-affecting releases

When `RefreshTokenEntity` (or any entity exposed via `ModelBuilderExtensions`) gains a column, `SchemaMigrations` MUST emit a matching ALTER for **every** new column, and the CHANGELOG entry MUST list them all. Test by upgrading a 0.7.0 deployment and exercising the full issue/rotate/revoke path before tagging.

## [0.8.1] — 2026-05-19

Documentation-only release. No code or schema changes; same NuGet binaries as `0.8.0`. Coordinated patch bump across all sibling packages to keep the constellation aligned.

### Documented

- **Critical `IClaimsProfile` contract:** `JwtTokenProvider.CreateToken` already prepends `sub = userId` on every issuance. Consumer `IClaimsProfile` implementations **must not** also emit `AuthClaims.Subject` — duplicate same-type claims collapse into a JSON array (`"sub":["uuid","uuid"]`), which violates RFC 7519 and breaks every Microsoft.IdentityModel validator (`IDX12723` on token readers, `401 Unauthorized` on every `[Authorize]` endpoint, infinite refresh loops on mobile). New README warning under `## Multi-app claim profiles` and matching CLAUDE.md invariant.
- Real production bug: Hyperion's `HyperionClaimsProfile` did exactly this, hidden for weeks behind silent client-side fallback. Fixed in Hyperion v0.2.6.8 (commit `2bb0eaf`).

## [0.8.0] — 2026-05-18

Device attribution for refresh tokens. Lets consumers persist `DeviceId` and `DeviceInfo` alongside each refresh-token row so /sessions endpoints can identify which device a session belongs to. Pre-1.0 minor bump: the `RefreshToken` abstraction grew two fields and the EF Core schema grew two columns.

### Added
- **`RefreshToken.DeviceId`** (`string?`) and **`RefreshToken.DeviceInfo`** (`string?`) in `TechTeaStudio.Auth.Abstractions`. Default `null`; preserved across rotations by `RefreshTokenService.RotateAsync`.
- **`RefreshTokenService.IssueAsync(userId, claims, deviceId, deviceInfo, ct)`** overload. The original `IssueAsync(userId, claims, ct)` overload is preserved and forwards with both device fields `null`, so existing call sites compile unchanged.
- **`RefreshTokenEntity.DeviceId` / `RefreshTokenEntity.DeviceInfo`** columns (nullable `varchar(256)` / `varchar(64)`) in `TechTeaStudio.Auth.EFCore`. Registered by `AddTechTeaStudioRefreshTokens(...)`.
- **`SchemaMigrations`** helper in `TechTeaStudio.Auth.EFCore` exposing ready-made `ALTER TABLE ... ADD COLUMN` snippets for PostgreSQL, SQL Server, and SQLite. Apply via `dbContext.Database.ExecuteSqlRawAsync(SchemaMigrations.AddDeviceColumnsSqlPostgres())` or run by hand.

### Schema migration (existing deployments)

Fresh deployments get the two columns automatically. For existing databases, run the SQL once:

**PostgreSQL:**
```sql
ALTER TABLE "TtsRefreshTokens" ADD COLUMN IF NOT EXISTS "DeviceId"   varchar(256) NULL;
ALTER TABLE "TtsRefreshTokens" ADD COLUMN IF NOT EXISTS "DeviceInfo" varchar(64)  NULL;
```

**SQL Server:**
```sql
IF COL_LENGTH('TtsRefreshTokens', 'DeviceId') IS NULL
    ALTER TABLE [TtsRefreshTokens] ADD [DeviceId] nvarchar(256) NULL;
IF COL_LENGTH('TtsRefreshTokens', 'DeviceInfo') IS NULL
    ALTER TABLE [TtsRefreshTokens] ADD [DeviceInfo] nvarchar(64) NULL;
```

**SQLite:** see `SchemaMigrations.AddDeviceColumnsSqlSqlite` (no native `IF NOT EXISTS` on `ADD COLUMN` — wrap in try/catch or check `pragma_table_info` first).

If you upgrade the NuGet package without running the migration, EF Core will throw on first insert because the model expects columns the table does not have.

### Backward compatibility
- Existing `IssueAsync(userId, claims)` and `IssueAsync(userId, claims, ct)` call sites compile and run identically — device fields default to `null`.
- All other public APIs (`IRefreshTokenStore`, `RotateAsync`, `RevokeAsync`, etc.) are unchanged.
- Stores that already implement `IRefreshTokenStore` keep working — they just stop persisting the new fields. To persist them, route through `EfCoreRefreshTokenStore` (post-upgrade) or update your custom store to copy `RefreshToken.DeviceId` / `RefreshToken.DeviceInfo` to/from its backing storage.

### Notes
- All TTS packages bumped to 0.8.0 to keep the constellation aligned (matches the 0.6.0 / 0.7.0 precedent).
- `InMemoryRefreshTokenStore` needed no code changes — it stores `RefreshToken` records as-is.

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
