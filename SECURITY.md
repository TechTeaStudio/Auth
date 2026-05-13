# Security policy

## Reporting a vulnerability

If you discover a security issue in `TechTeaStudio.Auth`, please **do not** open a public GitHub issue. Email the maintainer at **`prosakingf@gmail.com`** with:

- A description of the issue.
- Steps to reproduce, ideally with a minimal proof-of-concept.
- Affected version(s).
- Your assessment of impact and exploit conditions.

You will receive an acknowledgement within **72 hours**. We aim to ship a fix or mitigation within **14 days** for high-severity issues. After the patch ships, we publish a `GHSA` advisory and credit the reporter (unless they prefer to stay anonymous).

## Supported versions

| Version | Status |
| ------- | ------ |
| `0.x`   | Active development. Security fixes land on the next minor (`0.x+1.0`). |
| `1.x` (future) | Long-term support once it ships. |

Pre-1.0 releases are considered preview-quality. We will still fix security bugs in 0.x, but minor bumps may include API-breaking changes.

## Threat model

`TechTeaStudio.Auth` is designed for **first-party authentication** — your app, your user store, your servers. The threat model assumes:

- **In scope.** Compromised end-user credentials, stolen access/refresh tokens, replay of refresh tokens, brute-force login attempts, account-enumeration via timing differences, header-injection at the response layer, missing signing keys / weak signing keys.
- **Out of scope.** OAuth2/OIDC server semantics, social-login flows, browser-side XSS in the consuming app, infrastructure-level secrets management (key vaults, container secrets), DDoS at the network layer.

### Defenses shipped

| Concern | Mitigation |
| --- | --- |
| Weak signing keys | `AuthOptionsValidator` refuses to start when `SecretKey` is missing or under 32 bytes. |
| Brute-force login | `ILoginAttemptTracker` + `InMemoryLoginAttemptTracker` lock accounts after `AuthOptions.MaxFailedLoginAttempts`. |
| Stolen refresh token replay | Single-use refresh tokens; presenting a revoked token revokes the entire rotation chain when `AuthOptions.RevokeChainOnRefreshReuse` is on (default). |
| Refresh tokens on disk | `TokenHasher.HashRefreshToken` — only SHA-256 hashes ever reach the `IRefreshTokenStore`. |
| Password storage | PBKDF2-SHA256, 600 000 iterations, 16-byte salt, 32-byte digest; constant-time verify via `CryptographicOperations.FixedTimeEquals`. |
| Stolen access token revocation | `IRevokedTokenStore` deny-list, consulted by the bearer pipeline on every request. |
| Signed one-shot tokens (email, reset) | HMAC-SHA256, purpose-bound, single-use enforced via deny-list. |
| Response-layer hardening | `SecurityHeadersMiddleware` sets `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, and `Strict-Transport-Security` on HTTPS. |
| Audit trail | `IAuthAuditLogger` + strongly-typed events; metrics emitted on the `TechTeaStudio.Auth` `Meter`. |

### Known limitations (tracked in `TechTeaStudio.Auth` roadmap)

- No signing-key rotation with `kid` header yet — see TSA-55 / TSA-56.
- No asymmetric signing (RS256 / ES256) yet — see TSA-57.
- No distributed (Redis-backed) lockout or refresh store yet — see TSA-50 / TSA-52.
- No ASP.NET Core rate-limiter helper — see TSA-69. Apps should add their own rate limit on the login endpoint until then.

## Hardening checklist for consumers

When you wire `AddTechTeaStudioAuth(configuration)` into your app:

1. **Store the signing key outside the repo.** Use a secret manager or environment variable for `Auth:SecretKey`. Never commit a non-throwaway key.
2. **Set explicit issuer and audience.** Empty values disable the corresponding checks.
3. **Keep `TokenLifetime` short (≤ 15 minutes).** Rely on refresh-token rotation for session continuity.
4. **Rate-limit the login endpoint** until TSA-69 ships (or in addition to it).
5. **Enable the deny-list cleanup.** It is on by default via `RevokedTokenCleanupService`; do not turn it off unless you have measured the cost.
6. **Log audit events.** Replace `NullAuthAuditLogger` with your sink (database, Loki, etc.).
7. **Wire `app.UseSecurityHeaders()`** early in the pipeline.
8. **Use HTTPS in production.** Several headers (HSTS) are conditional on the request being HTTPS.
