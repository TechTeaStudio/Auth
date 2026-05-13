# MinimalApi sample

End-to-end demonstration of `TechTeaStudio.Auth` on top of EF Core In-Memory + Swashbuckle. The whole app fits in one [`Program.cs`](Program.cs).

## Run

```bash
dotnet run --project samples/MinimalApi
```

Then point your browser at `http://localhost:5180/swagger` and hit "Try it out".

## Curl walkthrough

```bash
BASE=http://localhost:5180

# 1. Sign up
curl -sX POST $BASE/signup -H 'content-type: application/json' \
  -d '{"email":"u@x","password":"correct horse battery staple"}'

# 2. Login → returns { accessToken, refreshToken, refreshTokenExpiresAt }
TOKENS=$(curl -sX POST $BASE/login -H 'content-type: application/json' \
  -d '{"email":"u@x","password":"correct horse battery staple"}')
ACCESS=$(echo $TOKENS | jq -r .accessToken)
REFRESH=$(echo $TOKENS | jq -r .refreshToken)

# 3. /me requires a Bearer token
curl -s $BASE/me -H "Authorization: Bearer $ACCESS"

# 4. Rotate refresh
TOKENS2=$(curl -sX POST $BASE/refresh -H 'content-type: application/json' \
  -d "{\"refreshToken\":\"$REFRESH\"}")

# 5. Logout (revokes the presented refresh token)
curl -sX POST $BASE/logout -H 'content-type: application/json' \
  -d "{\"refreshToken\":\"$(echo $TOKENS2 | jq -r .refreshToken)\"}"
```

## What this shows

- `AddTechTeaStudioAuth(...)` is the single call that wires JWT bearer, the password hasher, the refresh-token service, the deny-list, lockout tracking, and the audit pipeline.
- `EfCoreRefreshTokenStore<TContext>` replaces the default in-memory store — your refresh tokens persist with the rest of your data.
- `AddTechTeaStudioBearerSwagger()` makes the Swagger UI "Authorize" button work end-to-end.
- `ClaimsProfiles.Hyperion.BuildClaims(...)` keeps the Hyperion token shape for any service downstream that already expects it.
- The login endpoint integrates with `ILoginAttemptTracker` — five failed attempts inside `Auth:LockoutDuration` returns `429 Too Many Requests`.

## Production checklist

- Replace `UseInMemoryDatabase` with the real provider (SQL Server / PostgreSQL / SQLite).
- Move `Auth:SecretKey` out of `Program.cs` into user-secrets / env / a key vault.
- Add `app.MapTechTeaStudioJwks()` if downstream services validate without sharing your secret.
- Enable `app.UseRateLimiter()` + the `tts-auth-login` policy on the `/login` route.
