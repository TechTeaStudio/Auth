using System.Security.Claims;
using Microsoft.Extensions.Options;
using TechTeaStudio.Auth.Abstractions;
using TechTeaStudio.Auth.Observability;

namespace TechTeaStudio.Auth.RefreshTokens;

/// <summary>
/// Issues, rotates, and revokes refresh tokens on top of a pluggable
/// <see cref="IRefreshTokenStore"/>. Refresh tokens are single-use — every
/// successful rotation revokes the presented token and emits a fresh one.
/// Every token issued to a user belongs to a rotation family (<see cref="RefreshToken.FamilyId"/>):
/// a login mints a fresh family, and rotation preserves it. Presenting an
/// already-used/revoked token revokes the whole family when
/// <see cref="RefreshTokenOptions.RevokeChainOnReuse"/> is enabled.
/// </summary>
public sealed class RefreshTokenService
{
    private readonly ITokenProvider _tokens;
    private readonly IRefreshTokenStore _store;
    private readonly AuthOptions _options;
    private readonly IAuthAuditLogger _audit;
    private readonly IRefreshClaimsResolver _claimsResolver;

    public RefreshTokenService(
        ITokenProvider tokens,
        IRefreshTokenStore store,
        IOptions<AuthOptions> options,
        IAuthAuditLogger? audit = null,
        IRefreshClaimsResolver? claimsResolver = null)
    {
        _tokens = tokens ?? throw new ArgumentNullException(nameof(tokens));
        _store = store ?? throw new ArgumentNullException(nameof(store));
        _options = options?.Value ?? throw new ArgumentNullException(nameof(options));
        _audit = audit ?? NullAuthAuditLogger.Instance;
        _claimsResolver = claimsResolver ?? NullRefreshClaimsResolver.Instance;
    }

    /// <summary>Issues a fresh access + refresh token pair for <paramref name="userId"/>.</summary>
    /// <remarks>
    /// Backward-compatible overload (≤0.7.x signature). Forwards to the
    /// device-aware overload with both device fields null.
    /// </remarks>
    public Task<TokenPair> IssueAsync(string userId, IEnumerable<Claim> claims, CancellationToken cancellationToken = default)
        => IssueAsync(userId, claims, deviceId: null, deviceInfo: null, cancellationToken);

    /// <summary>
    /// Issues a fresh access + refresh token pair for <paramref name="userId"/>,
    /// attributing the refresh token to the given device. The DeviceId/DeviceInfo
    /// are persisted with the row and preserved across rotations so /sessions
    /// endpoints can surface device attribution.
    /// </summary>
    public async Task<TokenPair> IssueAsync(string userId, IEnumerable<Claim> claims, string? deviceId, string? deviceInfo, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrEmpty(userId)) throw new ArgumentException("userId is required.", nameof(userId));
        if (claims is null) throw new ArgumentNullException(nameof(claims));

        var raw = TokenHasher.NewRawToken();
        var hash = TokenHasher.HashRefreshToken(raw);
        var expiresAt = DateTimeOffset.UtcNow.Add(_options.RefreshTokens.Lifetime);

        var entity = new RefreshToken
        {
            UserId = userId,
            TokenHash = hash,
            // A login always mints a fresh family — this token has no predecessor.
            FamilyId = Guid.NewGuid(),
            CreatedAt = DateTimeOffset.UtcNow,
            ExpiresAt = expiresAt,
            DeviceId = deviceId,
            DeviceInfo = deviceInfo,
        };
        await _store.CreateAsync(entity, cancellationToken).ConfigureAwait(false);

        var access = _tokens.CreateToken(userId, claims, _options.Jwt.TokenLifetime);

        AuthDiagnostics.TokensIssuedTotal.Add(1);
        await _audit.LogAsync(new TokenIssuedEvent(userId, hash, expiresAt, DateTimeOffset.UtcNow), cancellationToken).ConfigureAwait(false);

        return new TokenPair(access, raw, expiresAt);
    }

    /// <summary>
    /// Rotates the presented refresh token, asking the registered
    /// <see cref="IRefreshClaimsResolver"/> for the claim set to embed in the
    /// new access token. Use this overload when the caller does not already
    /// have a claims list to hand.
    /// </summary>
    public async Task<TokenPair?> RotateAsync(string presentedRefreshToken, CancellationToken cancellationToken = default)
    {
        var result = await RotateWithOutcomeAsync(presentedRefreshToken, cancellationToken).ConfigureAwait(false);
        return result.Tokens;
    }

    /// <summary>
    /// Rotates the presented refresh token, embedding <paramref name="claims"/>
    /// into the new access token. Returns <c>null</c> when the presented token
    /// is unknown, expired, already revoked, or lost a concurrent rotation race — use
    /// <see cref="RotateWithOutcomeAsync(string, IEnumerable{Claim}, CancellationToken)"/>
    /// to tell those cases apart.
    /// </summary>
    public async Task<TokenPair?> RotateAsync(string presentedRefreshToken, IEnumerable<Claim> claims, CancellationToken cancellationToken = default)
    {
        var result = await RotateWithOutcomeAsync(presentedRefreshToken, claims, cancellationToken).ConfigureAwait(false);
        return result.Tokens;
    }

    /// <summary>
    /// Outcome-aware variant of <see cref="RotateAsync(string, CancellationToken)"/>: asks the
    /// registered <see cref="IRefreshClaimsResolver"/> for the claim set to embed in the new
    /// access token. Use this overload when the caller does not already have a claims list to hand.
    /// </summary>
    public async Task<RefreshRotationResult> RotateWithOutcomeAsync(string presentedRefreshToken, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrEmpty(presentedRefreshToken)) return RefreshRotationResult.Invalid;
        var presentedHash = TokenHasher.HashRefreshToken(presentedRefreshToken);
        var existing = await _store.GetByTokenHashAsync(presentedHash, cancellationToken).ConfigureAwait(false);
        if (existing is null) return RefreshRotationResult.Invalid;

        var claims = await _claimsResolver.ResolveClaimsAsync(existing.UserId, cancellationToken).ConfigureAwait(false);
        return await RotateWithOutcomeAsync(presentedRefreshToken, claims, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Rotates the presented refresh token, embedding <paramref name="claims"/> into the new
    /// access token, and reports WHY when it could not: <see cref="RefreshOutcome.Invalid"/>
    /// (unknown token, or a lost same-instant rotation race), <see cref="RefreshOutcome.Expired"/>
    /// (found, never revoked, but past its lifetime), or <see cref="RefreshOutcome.ReusedFamilyRevoked"/>
    /// (a distinct, completed prior operation already used/revoked this exact token — the stolen-token
    /// signal — and the whole family, including whatever it was rotated into, has been revoked
    /// when <see cref="RefreshTokenOptions.RevokeChainOnReuse"/> is on).
    /// </summary>
    /// <remarks>
    /// <para>
    /// Race handling is deliberately asymmetric. Two concurrent presentations of the SAME still-valid
    /// token race on <see cref="IRefreshTokenStore.RevokeAsync"/>'s compare-and-swap: exactly one wins
    /// and mints a successor, and the loser is reported as <see cref="RefreshOutcome.Invalid"/> — a safe
    /// reject that does NOT burn the family, so the winner's brand-new session survives. Only a token
    /// whose <c>RevokedAt</c> was ALREADY set by a separate, completed prior rotation (found on lookup,
    /// before any CAS attempt) is treated as a genuine replay and burns the family.
    /// </para>
    /// <para>
    /// This diverges from a stricter "any lost race is reuse" policy: a same-instant double-fire (e.g. a
    /// flaky-network client retry) is far more often benign than an attacker probing the rotation window,
    /// and nuking the winner's fresh session on every such collision is a worse default trade-off than
    /// asking the loser alone to re-authenticate with its now-superseded token.
    /// </para>
    /// </remarks>
    public async Task<RefreshRotationResult> RotateWithOutcomeAsync(string presentedRefreshToken, IEnumerable<Claim> claims, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrEmpty(presentedRefreshToken)) return RefreshRotationResult.Invalid;
        if (claims is null) throw new ArgumentNullException(nameof(claims));

        var presentedHash = TokenHasher.HashRefreshToken(presentedRefreshToken);
        var existing = await _store.GetByTokenHashAsync(presentedHash, cancellationToken).ConfigureAwait(false);
        if (existing is null) return RefreshRotationResult.Invalid;

        if (existing.RevokedAt is not null)
        {
            // Genuine replay: a distinct, already-completed prior operation revoked this row.
            // Presenting it again proves knowledge of a spent token — burn the whole family.
            await ReportReuseAsync(existing, cancellationToken).ConfigureAwait(false);
            return RefreshRotationResult.ReusedFamilyRevoked;
        }

        if (!existing.IsActive)
        {
            // Never revoked, but its lifetime passed — an ordinary stale token, not a theft signal.
            return RefreshRotationResult.Expired;
        }

        var raw = TokenHasher.NewRawToken();
        var newHash = TokenHasher.HashRefreshToken(raw);
        var expiresAt = DateTimeOffset.UtcNow.Add(_options.RefreshTokens.Lifetime);

        // Revoke-first compare-and-swap: only the caller whose RevokeAsync actually
        // flips this row from active to revoked may issue the successor. This closes
        // both the double-spend window (a downstream CreateAsync failure now leaves
        // the presented token revoked — fail-closed, no forked live token) and the
        // concurrency fork (two parallel rotations of the same token both pass the
        // IsActive check above, but only one of them wins this CAS).
        var claimed = await _store.RevokeAsync(existing.Id, newHash, cancellationToken).ConfigureAwait(false);
        if (!claimed)
        {
            // Lost the race to a concurrent rotation of the same token — see the remarks
            // above for why this is a safe reject rather than a family burn.
            AuthDiagnostics.RefreshReuseDetectedTotal.Add(1);
            await _audit.LogAsync(new RefreshReuseDetectedEvent(existing.UserId, existing.TokenHash, 0, DateTimeOffset.UtcNow), cancellationToken).ConfigureAwait(false);
            return RefreshRotationResult.Invalid;
        }

        var newEntity = new RefreshToken
        {
            UserId = existing.UserId,
            TokenHash = newHash,
            // Rotation stays in the same family as its predecessor.
            FamilyId = existing.FamilyId,
            CreatedAt = DateTimeOffset.UtcNow,
            ExpiresAt = expiresAt,
            // Preserve device attribution across rotations: a rotated token still
            // represents the same device install as its predecessor.
            DeviceId = existing.DeviceId,
            DeviceInfo = existing.DeviceInfo,
        };
        await _store.CreateAsync(newEntity, cancellationToken).ConfigureAwait(false);

        var access = _tokens.CreateToken(existing.UserId, claims, _options.Jwt.TokenLifetime);

        AuthDiagnostics.RefreshTokensRotatedTotal.Add(1);
        AuthDiagnostics.TokensIssuedTotal.Add(1);
        await _audit.LogAsync(new TokenRefreshedEvent(existing.UserId, existing.TokenHash, newHash, DateTimeOffset.UtcNow), cancellationToken).ConfigureAwait(false);

        return RefreshRotationResult.Success(new TokenPair(access, raw, expiresAt));
    }

    /// <summary>Revokes <paramref name="presentedRefreshToken"/>. No-op when the token is unknown.</summary>
    public async Task RevokeAsync(string presentedRefreshToken, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrEmpty(presentedRefreshToken)) return;
        var hash = TokenHasher.HashRefreshToken(presentedRefreshToken);
        var existing = await _store.GetByTokenHashAsync(hash, cancellationToken).ConfigureAwait(false);
        if (existing is null) return;
        await _store.RevokeAsync(existing.Id, null, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>Revokes every active token issued to <paramref name="userId"/>. Used by logout-everywhere / password-change flows.</summary>
    public Task RevokeAllForUserAsync(string userId, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrEmpty(userId)) return Task.CompletedTask;
        return _store.RevokeAllForUserAsync(userId, cancellationToken);
    }

    private async Task ReportReuseAsync(RefreshToken existing, CancellationToken cancellationToken)
    {
        var revokedCount = 0;
        if (_options.RefreshTokens.RevokeChainOnReuse)
            revokedCount = await _store.RevokeFamilyAsync(existing.FamilyId, cancellationToken).ConfigureAwait(false);

        AuthDiagnostics.RefreshReuseDetectedTotal.Add(1);
        await _audit.LogAsync(new RefreshReuseDetectedEvent(existing.UserId, existing.TokenHash, revokedCount, DateTimeOffset.UtcNow), cancellationToken).ConfigureAwait(false);
    }
}
