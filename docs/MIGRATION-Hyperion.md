# Migration: Hyperion Omni Client → `TechTeaStudio.Auth`

This guide moves an existing Hyperion service from its hand-rolled JWT / PBKDF2 stack onto `TechTeaStudio.Auth`. The wire format on the access token does **not** change — existing tokens issued by Hyperion before the migration still validate, and existing tokens issued by the library still validate against the old Hyperion middleware.

## What stays the same

- HS256 access tokens with the same `sub` / `unique_name` / `email` / `role` claims.
- PBKDF2-SHA256 password hashing with the same iteration count and salt length.
- Legacy `nameid` claim is read (deprecated but accepted) for any token issued before the move.

## What changes

| Before (Hyperion) | After (`TechTeaStudio.Auth`) |
| --- | --- |
| `services.AddJwtGenerator()` + custom `IPasswordHasher` + custom `JwtBearer` setup. | `services.AddTechTeaStudioAuth(configuration)` — single call. |
| `JwtGenerator.Issue(...)` returning a string. | `ITokenProvider.CreateToken(userId, claims, lifetime)` returning a string, or `RefreshTokenService.IssueAsync(...)` for a full pair. |
| Password hash format `pbkdf2$...$...` (no version byte). | New `[0x01][salt:16][digest:32]` Base64 format. **See below.** |
| Refresh tokens stored as raw GUIDs in the database. | SHA-256 hashes only; raw tokens never reach the store. |
| Manual `JwtBearerEvents.OnChallenge` for 401 JSON. | Built-in JSON body with stable `error` codes from `AuthErrorCodes`. |

## Step 1 — Configuration

```jsonc
// appsettings.json
{
  "Auth": {
    "SecretKey": "<32-byte-secret>",
    "Issuer": "https://hyperion.example.com",
    "Audience": "hyperion-clients",
    "TokenLifetime": "00:30:00",
    "RefreshTokenLifetime": "7.00:00:00",
    "MaxFailedLoginAttempts": 5,
    "LockoutDuration": "00:15:00"
  }
}
```

```csharp
// Program.cs
builder.Services.AddTechTeaStudioAuth(builder.Configuration);
builder.Services.AddSingleton<IClaimsProfile>(ClaimsProfiles.Hyperion);

var app = builder.Build();
app.UseSecurityHeaders();   // optional but recommended
app.UseAuthentication();
app.UseAuthorization();
```

`AddTechTeaStudioAuth` registers:

- `ITokenProvider`, `ITokenReader`, `IPasswordHasher`, `IRefreshTokenStore`, `RefreshTokenService`.
- `ILoginAttemptTracker`, `IRevokedTokenStore`, `IAuthAuditLogger` (null sink).
- JWT bearer scheme with validated issuer/audience/lifetime/key.
- Background services for refresh-token cleanup and deny-list cleanup.

Delete the old `JwtGenerator`, `PasswordHasher`, and `JwtBearer` registrations.

## Step 2 — Login endpoint

Replace the existing login flow with the one in [`RECIPES.md` §1](RECIPES.md#1-issue-a-login-token-pair). Key differences:

- Wrap the password check in `ILoginAttemptTracker.RecordFailureAsync` / `RecordSuccessAsync` for lockout.
- Use `RefreshTokenService.IssueAsync` instead of constructing tokens manually — you get the access token, the rotated refresh token, and the refresh expiry in one call.

## Step 3 — Refresh endpoint

```csharp
public async Task<IResult> Refresh(RefreshRequest req, CancellationToken ct)
{
    var pair = await _refresh.RotateAsync(req.RefreshToken,
        ClaimsProfiles.Hyperion.BuildClaims(new ClaimsBuilderInput { UserId = req.UserId }), ct);

    return pair is null ? Results.Unauthorized() : Results.Ok(pair);
}
```

The library:

- Hashes the presented refresh token (SHA-256) before touching the store.
- Marks the old row revoked and chains it to the new hash.
- Detects replay (someone presenting a revoked token) and revokes the entire chain when `AuthOptions.RevokeChainOnRefreshReuse` is `true` (default).

## Step 4 — Password hash migration

The new hash format is incompatible with the old one (different version byte / encoding). Two strategies:

**A. Lazy upgrade on next login.** Keep both hash columns for one release. On login, try the old verifier; on success, write a fresh `Pbkdf2PasswordHasher.Hash(req.Password)` to the new column and null the old one. After every user has logged in once (or after a grace period), drop the old column.

**B. Forced reset.** Send password-reset emails to every user, using `PasswordResetTokenService`. Simpler, but disruptive.

We recommend (A).

## Step 5 — `nameid` legacy claim

Tokens issued by old Hyperion code put the user identifier in the `nameid` claim. `JwtTokenReader.TryRead` already falls back to `nameid` when `sub` is missing, so legacy tokens still parse into `AuthTokenInfo.UserId`.

For **new** tokens, `HyperionClaimsProfile.BuildClaims` writes **both** `sub` and `nameid` (the latter is marked obsolete). After every active token has been refreshed at least once (i.e. after `RefreshTokenLifetime`), you can drop `nameid` by switching to a custom profile that omits it.

## Step 6 — Cleanup

- Remove `Microsoft.IdentityModel.Tokens` direct references in your app — they come transitively from the library.
- Delete the old refresh-token table and replace with the one that stores `(id, user_id, token_hash, created_at, expires_at, revoked_at, replaced_by_token_hash)`. An EF Core sample is on the roadmap (TSA-49).
- Delete any custom `OnChallenge` JSON writer — the library provides a stable contract (`AuthErrorCodes`).

## Verification

After the cutover, you should see:

- `tts_auth_login_succeeded_total` counter incrementing on successful logins.
- `tts_auth_refresh_rotated_total` on every successful refresh.
- A `tts_auth_refresh_reuse_total` increment if anyone presents a stale refresh — investigate.
- Account-lockout entries in `ILoginAttemptTracker` for brute-force attempts.
