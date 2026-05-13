# Recipes

Patterns we expect most apps will reach for. Each snippet assumes `AddTechTeaStudioAuth(configuration)` has already been called in `Program.cs`.

## 1. Issue a login token pair

```csharp
public sealed class LoginEndpoint
{
    private readonly IPasswordHasher _passwords;
    private readonly RefreshTokenService _refresh;
    private readonly ILoginAttemptTracker _lockout;
    private readonly IUserRepository _users;

    public LoginEndpoint(IPasswordHasher p, RefreshTokenService r, ILoginAttemptTracker l, IUserRepository u)
        => (_passwords, _refresh, _lockout, _users) = (p, r, l, u);

    public async Task<IResult> Handle(LoginRequest req, CancellationToken ct)
    {
        var status = await _lockout.GetStatusAsync(req.Email, ct);
        if (status.IsLocked)
            return Results.StatusCode(StatusCodes.Status429TooManyRequests);

        var user = await _users.FindAsync(req.Email, ct);
        if (user is null || !_passwords.Verify(user.PasswordHash, req.Password))
        {
            await _lockout.RecordFailureAsync(req.Email, ct);
            return Results.Unauthorized();
        }

        await _lockout.RecordSuccessAsync(req.Email, ct);
        var pair = await _refresh.IssueAsync(user.Id, ClaimsProfiles.Hyperion.BuildClaims(new ClaimsBuilderInput
        {
            UserId = user.Id, Username = user.Username, Email = user.Email, Roles = user.Roles,
        }), ct);

        return Results.Ok(new { pair.AccessToken, pair.RefreshToken, pair.RefreshTokenExpiresAt });
    }
}
```

## 2. Refresh the token pair

```csharp
public async Task<IResult> Handle(RefreshRequest req, CancellationToken ct)
{
    var pair = await _refresh.RotateAsync(req.RefreshToken,
        ClaimsProfiles.Hyperion.BuildClaims(new ClaimsBuilderInput { UserId = req.UserId }), ct);

    return pair is null ? Results.Unauthorized() : Results.Ok(pair);
}
```

## 3. Revoke a token immediately

Use the deny-list when you need to kill an access token before its natural `exp`:

```csharp
public async Task<IResult> SignOutEverywhere(string userId, CancellationToken ct)
{
    // Revoke all refresh tokens for the user (forces re-login on every device).
    await _store.DeleteAllForUserAsync(userId, ct);

    // Add the current request's jti to the deny-list until the token's natural exp.
    var jti = httpContext.User.FindFirst(AuthClaims.JwtId)?.Value;
    var exp = httpContext.User.FindFirst("exp")?.Value;
    if (jti is not null && long.TryParse(exp, out var expUnix))
        await _revoked.RevokeAsync(jti, DateTimeOffset.FromUnixTimeSeconds(expUnix), ct);

    return Results.NoContent();
}
```

## 4. Send a password-reset link

```csharp
public async Task<IResult> RequestReset(string email, CancellationToken ct)
{
    var user = await _users.FindAsync(email, ct);
    if (user is null) return Results.Ok(); // intentional: don't leak account existence

    var token = _resetTokens.Generate(user.Id);
    await _mailer.SendAsync(email, $"https://app.example.com/reset?token={token}", ct);
    return Results.Ok();
}

public async Task<IResult> ConsumeReset(ConsumeResetRequest req, CancellationToken ct)
{
    var result = await _resetTokens.ValidateAsync(req.Token, ct);
    if (!result.Success) return Results.BadRequest(new { error = "invalid_or_expired" });

    var hash = _passwords.Hash(req.NewPassword);
    await _users.SetPasswordHashAsync(result.UserId!, hash, ct);
    return Results.NoContent();
}
```

`PasswordResetTokenService` enforces one-shot use via the `IRevokedTokenStore` — the same token cannot reset a password twice.

## 5. Confirm an email address

```csharp
var token = _emailTokens.Generate(user.Id, user.Email);
await _mailer.SendAsync(user.Email, $"https://app.example.com/confirm?token={token}", ct);

// On click:
var result = await _emailTokens.ValidateAsync(token, ct);
if (result.Success && result.UserId == user.Id && result.Email == user.Email)
    await _users.MarkConfirmedAsync(user.Id, ct);
```

## 6. Wire two-factor for a user

```csharp
// Begin: generate secret + provisioning URI + recovery codes.
var secret = RandomNumberGenerator.GetBytes(20);
var base32 = OtpAuthUri.ToBase32(secret);
var uri    = OtpAuthUri.Build("MyApp", user.Email, base32);
var recoveryCodes = RecoveryCodeService.Generate();

await _users.StoreTwoFactorSecretAsync(user.Id, secret, recoveryCodes.Select(RecoveryCodeService.Hash));

// Show `uri` as a QR code and `recoveryCodes` to the user **once**.

// Confirm: validate the code typed from the authenticator app.
if (TotpValidator.Validate(secret, typedCode, DateTimeOffset.UtcNow))
    await _users.MarkTwoFactorEnabledAsync(user.Id);
```

## 7. Protect an endpoint with an API key (machine-to-machine)

```csharp
services.AddSingleton<IApiKeyStore>(sp =>
    new FuncApiKeyStore(async (raw, ct) =>
        await sp.GetRequiredService<IApiKeyRepository>().ValidateAsync(raw, ct)));

services.AddAuthentication()
        .AddTechTeaStudioApiKey(o => o.HeaderName = "X-Api-Key");

services.AddAuthorization(o =>
    o.AddPolicy("machine", p => p.AddAuthenticationSchemes(ApiKeyAuthenticationHandler.SchemeName)
                                  .RequireAuthenticatedUser()));
```

```csharp
app.MapGet("/internal/hooks", () => "ok")
   .RequireAuthorization("machine");
```

## 8. Add a custom audit sink

Replace the default `NullAuthAuditLogger` with your sink (SQL, Loki, Sentry, …):

```csharp
services.AddSingleton<IAuthAuditLogger, MyDatabaseAuthAuditLogger>();
```

Every `RefreshTokenService` operation (issue / rotate / replay) already emits a typed event. Wire your sink and it lights up.

## 9. Surface security metrics

`AuthDiagnostics` exposes a `System.Diagnostics.Metrics.Meter` named `TechTeaStudio.Auth`. Any OpenTelemetry-based pipeline picks it up automatically:

```csharp
builder.Services.AddOpenTelemetry()
    .WithMetrics(b => b
        .AddMeter("TechTeaStudio.Auth")
        .AddPrometheusExporter());
```

Counter names are Prometheus-friendly (`tts_auth_login_succeeded_total`, `tts_auth_refresh_reuse_total`, …) so they scrape cleanly into a single dashboard.

## 10. Plug in a multi-app claim profile

When two apps share the library but publish different claim shapes:

```csharp
// Hyperion service:
var hyperionClaims = ClaimsProfiles.Hyperion.BuildClaims(new ClaimsBuilderInput
{
    UserId = user.Id, Username = user.Username, Email = user.Email, Roles = user.Roles,
});

// Pello service:
var pelloClaims = ClaimsProfiles.Pello.BuildClaims(new ClaimsBuilderInput
{
    Email = user.Email, Username = user.DisplayName,
});
```

Both flow through the same `JwtTokenProvider` — only the published claim names differ.
