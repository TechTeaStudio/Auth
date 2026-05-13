# Migration: Pello → `TechTeaStudio.Auth`

Pello stores user passwords in plain text and issues tokens without a stable JWT layout. This guide brings it onto `TechTeaStudio.Auth` in three steps; the riskiest part is the password migration, which has to be staged.

## Outcome

After migration:

- Passwords are PBKDF2-SHA256 hashed at rest with a per-user salt.
- Login issues a proper JWT pair with refresh rotation.
- Claims published as `email` + `unique_name` (Pello profile) — no roles, no `sub`. The wire shape downstream services consume stays the same.

## Step 1 — Add the package and wire DI

```csharp
builder.Services.AddTechTeaStudioAuth(builder.Configuration);
builder.Services.AddSingleton<IClaimsProfile>(ClaimsProfiles.Pello);
```

```jsonc
{
  "Auth": {
    "SecretKey": "<32-byte-secret>",
    "Issuer": "https://pello.example.com",
    "Audience": "pello-clients"
  }
}
```

## Step 2 — Password column migration

This is the only invasive change. The existing `users.password` column holds plain-text values; we will replace it with `users.password_hash` (the library's Base64 PBKDF2 string).

1. Add a nullable `password_hash` column.
2. Backfill in one batch:

   ```csharp
   var hasher = serviceProvider.GetRequiredService<IPasswordHasher>();
   foreach (var u in db.Users.AsEnumerable())
       u.PasswordHash = hasher.Hash(u.Password);
   db.SaveChanges();
   ```
3. Make `password_hash` non-null.
4. **Switch login** to verify against `password_hash`:

   ```csharp
   if (!_passwords.Verify(user.PasswordHash, req.Password)) return Results.Unauthorized();
   ```
5. Drop the `password` column after one release.

Do all five steps in a single short window — Pello has no separate auth service, so the login endpoint is the only consumer.

## Step 3 — Token issuance

Replace the existing token endpoint with [`RECIPES.md` §1](RECIPES.md#1-issue-a-login-token-pair), using `ClaimsProfiles.Pello`:

```csharp
var claims = ClaimsProfiles.Pello.BuildClaims(new ClaimsBuilderInput
{
    Email = user.Email,
    Username = user.DisplayName,
});
var pair = await _refresh.IssueAsync(user.Id, claims, ct);
```

Tokens emitted will carry `email` and `unique_name`, matching the shape the Pello frontend already expects.

## Step 4 — Refresh endpoint

Identical to the Hyperion migration ([§3 there](MIGRATION-Hyperion.md#step-3--refresh-endpoint)) but with the Pello profile.

## What to verify after cutover

- Old plain-text values are no longer read by any code path. Grep for `user.Password` and remove every reference.
- Login no longer succeeds when the column is empty — the hasher returns `false` on empty/garbage input.
- Refresh rotation kicks in on every refresh call (check `tts_auth_refresh_rotated_total`).
- Account lockout triggers after `AuthOptions.MaxFailedLoginAttempts` failed logins from the same email.

## Future work

When Pello grows a role system, switch to a custom profile derived from `HyperionClaimsProfile` (or a fresh `IClaimsProfile` implementation) so it can publish roles without forking the library.
