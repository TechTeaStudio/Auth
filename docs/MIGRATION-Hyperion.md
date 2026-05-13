# Migration: Hyperion Omni Client → `TechTeaStudio.Auth`

This guide moves an existing Hyperion service from its hand-rolled JWT / PBKDF2 stack onto `TechTeaStudio.Auth` v0.5.0. The wire format on the access token does **not** change — existing tokens issued by Hyperion before the migration still validate, and existing tokens issued by the library still validate against the old Hyperion middleware (provided you keep emitting both `sub` and `nameid` during the transition, see Step 5).

## What stays the same

- HS256 access tokens with the same `sub` / `unique_name` / `email` / `role` claims.
- PBKDF2-SHA256 password hashing with the same iteration count and salt length.

## What changes

| Before (Hyperion) | After (`TechTeaStudio.Auth`) |
| --- | --- |
| `services.AddJwtGenerator()` + custom `IPasswordHasher` + custom `JwtBearer` setup. | `services.AddTechTeaStudioAuth(configuration)` — single call returning an `IAuthBuilder` for overrides. |
| `JwtGenerator.Issue(...)` returning a string. | `ITokenProvider.CreateToken(userId, claims, lifetime)` returning a string, or `RefreshTokenService.IssueAsync(...)` for a full pair. |
| Password hash format `pbkdf2$...$...` (no version byte). | New `[0x01][salt:16][digest:32]` Base64 format. **See Step 4 below.** |
| Refresh tokens stored as raw GUIDs in the database. | SHA-256 hashes only; raw tokens never reach the store. |
| Manual `JwtBearerEvents.OnChallenge` for 401 JSON. | Built-in JSON body with stable `error` codes from `AuthErrorCodes`. |
| Claim profile baked into the library. | Each app implements `IClaimsProfile` itself; library stays generic. |

## Step 1 — Configuration

```jsonc
// appsettings.json (v0.5 nested shape)
{
  "Auth": {
    "Jwt": {
      "SecretKey": "<32-byte-secret>",
      "Issuer":   "https://hyperion.example.com",
      "Audience": "hyperion-clients",
      "TokenLifetime": "00:30:00"
    },
    "RefreshTokens": { "Lifetime": "7.00:00:00" },
    "Lockout":       { "MaxFailedAttempts": 5, "Duration": "00:15:00" }
  }
}
```

```csharp
// Program.cs — keep Hyperion's claim profile local
public sealed class HyperionClaimsProfile : IClaimsProfile
{
    public string Name => "Hyperion";
    public IEnumerable<Claim> BuildClaims(ClaimsBuilderInput input)
    {
        if (!string.IsNullOrEmpty(input.UserId))
        {
            yield return new Claim(AuthClaims.Subject, input.UserId);
            yield return new Claim("nameid", input.UserId);     // legacy compat
        }
        if (!string.IsNullOrEmpty(input.Username)) yield return new Claim(AuthClaims.Username, input.Username);
        if (!string.IsNullOrEmpty(input.Email))    yield return new Claim(AuthClaims.Email, input.Email);
        if (input.Roles is not null)
            foreach (var r in input.Roles) yield return new Claim(AuthClaims.Role, r);
    }
}

builder.Services.AddTechTeaStudioAuth(builder.Configuration)
    .UseClaimsProfile<HyperionClaimsProfile>()
    .UseRefreshTokenStore<EfCoreRefreshTokenStore<HyperionDbContext>>();

var app = builder.Build();
app.UseSecurityHeaders();
app.UseAuthentication();
app.UseAuthorization();
```

`AddTechTeaStudioAuth` registers `ITokenProvider`, `ITokenReader`, `IPasswordHasher`, in-memory `IRefreshTokenStore` / `ILoginAttemptTracker` / `IRevokedTokenStore`, the null `IAuthAuditLogger`, JWT bearer scheme with validated issuer/audience/lifetime, and background services for refresh / deny-list cleanup. The `Use*` calls swap any default — they all use `TryAdd` plus `RemoveAll` so the order in `Program.cs` doesn't matter.

Delete the old `JwtGenerator`, `PasswordHasher`, and `JwtBearer` registrations.

## Step 2 — Login endpoint

Replace the existing login flow with the one in [`RECIPES.md` §1](RECIPES.md#1-issue-a-login-token-pair). Key differences:

- Wrap the password check in `ILoginAttemptTracker.RecordFailureAsync` / `RecordSuccessAsync` for lockout.
- Use `RefreshTokenService.IssueAsync` instead of constructing tokens manually — you get the access token, the rotated refresh token, and the refresh expiry in one call.
- Build claims via your local `HyperionClaimsProfile.BuildClaims(...)`.

## Step 3 — Refresh endpoint

```csharp
public async Task<IResult> Refresh(RefreshRequest req, IRefreshClaimsResolver claims, CancellationToken ct)
{
    // Option A — caller supplies claims:
    // var pair = await _refresh.RotateAsync(req.RefreshToken, _profile.BuildClaims(...), ct);

    // Option B — IRefreshClaimsResolver rebuilds them from the userId in the row:
    var pair = await _refresh.RotateAsync(req.RefreshToken, ct);

    return pair is null ? Results.Unauthorized() : Results.Ok(pair);
}
```

The library:

- Hashes the presented refresh token (SHA-256) before touching the store.
- Marks the old row revoked and chains it to the new hash.
- Detects replay (someone presenting a revoked token) and revokes the entire chain when `Auth:RefreshTokens:RevokeChainOnReuse` is `true` (default).

## Step 4 — Password hash migration

The new hash format is incompatible with the old one (different version byte / encoding). Two strategies:

**A. Lazy upgrade on next login.** Keep both hash columns for one release. On login, try the old verifier; on success, write a fresh `Pbkdf2PasswordHasher.Hash(req.Password)` to the new column and null the old one. After every user has logged in once (or after a grace period), drop the old column.

**B. Forced reset.** Send password-reset emails to every user, using `PasswordResetTokenService`. Simpler, but disruptive.

We recommend (A).

## Step 5 — `nameid` legacy claim

Tokens issued by old Hyperion code put the user identifier in the `nameid` claim. The v0.5 library no longer ships a fallback for `nameid` — it's a Hyperion concern, kept inside Hyperion.

If you have services consuming legacy tokens (issued before this migration), implement a small reader-decorator in Hyperion that wraps `JwtTokenReader` and falls back to `nameid` when `sub` is missing. Three or four lines.

The `HyperionClaimsProfile` shown in Step 1 writes **both** `sub` and `nameid` so legacy receivers keep working. After every active token has been refreshed at least once (i.e. after `Auth:RefreshTokens:Lifetime`), you can drop `nameid` by removing that line from the profile.

## Step 6 — Cleanup

- Remove `Microsoft.IdentityModel.Tokens` direct references in your app — they come transitively from the library.
- Delete the old refresh-token table and replace with the one created by `modelBuilder.AddTechTeaStudioRefreshTokens()`. An EF Core sample is in [`samples/MinimalApi`](../samples/MinimalApi).
- Delete any custom `OnChallenge` JSON writer — the library provides a stable contract (`AuthErrorCodes`).

## Verification

After the cutover, you should see:

- `tts_auth_login_succeeded_total` counter incrementing on successful logins.
- `tts_auth_refresh_rotated_total` on every successful refresh.
- A `tts_auth_refresh_reuse_total` increment if anyone presents a stale refresh — investigate.
- Account-lockout entries in `ILoginAttemptTracker` for brute-force attempts.
