# BlazorServer sample

Standard .NET 9 Blazor Server app wired with `TechTeaStudio.Auth`'s cookie scheme (`AddTechTeaStudioCookieAuth`). Demonstrates `<AuthorizeView>`, `[Authorize]` on a routed page, antiforgery on sign-in/sign-out forms, and `HttpContext.SignInAsync` to mint the cookie.

## Run

```bash
dotnet run --project samples/BlazorServer
```

Visit `https://localhost:7180`. Use the Sign-in link to issue a cookie session; the secret page becomes accessible.

## Notable wiring

- `.AddTechTeaStudioCookieAuth()` registers a hardened cookie scheme: `HttpOnly`, `SameSite=Strict`, `SecurePolicy=Always`. API requests still get a JSON 401 — only HTML routes get a redirect.
- `AddCascadingAuthenticationState()` exposes the principal to `<AuthorizeView>` and `<AuthorizeRouteView>`.
- Sign-in form posts to a minimal `/sign-in` endpoint that builds a `ClaimsIdentity` and calls `SignInAsync`. Production apps call `IPasswordHasher.Verify` against the user store first.
- Sign-out posts to `/sign-out` with an `<AntiforgeryToken />` — the standard `app.UseAntiforgery()` middleware blocks CSRF.
