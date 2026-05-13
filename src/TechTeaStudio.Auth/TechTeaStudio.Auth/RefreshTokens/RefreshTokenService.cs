using System.Security.Claims;
using Microsoft.Extensions.Options;
using TechTeaStudio.Auth.Abstractions;
using TechTeaStudio.Auth.Observability;

namespace TechTeaStudio.Auth.RefreshTokens;

/// <summary>
/// Issues, rotates, and revokes refresh tokens on top of a pluggable
/// <see cref="IRefreshTokenStore"/>. Refresh tokens are single-use — every
/// successful rotation revokes the presented token and emits a fresh one.
/// Presenting an already-revoked token revokes the whole rotation chain when
/// <see cref="RefreshTokenOptions.RevokeChainOnReuse"/> is enabled.
/// </summary>
public sealed class RefreshTokenService
{
    /// <summary>
    /// Hard cap on rotation-chain length walked during replay detection. Any chain
    /// longer than this is treated as corrupt data and we stop walking to avoid an
    /// infinite loop. 1000 is comfortably above any legitimate use (one rotation
    /// per minute for 16 hours).
    /// </summary>
    private const int MaxChainWalkDepth = 1000;

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
    public async Task<TokenPair> IssueAsync(string userId, IEnumerable<Claim> claims, CancellationToken cancellationToken = default)
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
            CreatedAt = DateTimeOffset.UtcNow,
            ExpiresAt = expiresAt,
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
        if (string.IsNullOrEmpty(presentedRefreshToken)) return null;
        var presentedHash = TokenHasher.HashRefreshToken(presentedRefreshToken);
        var existing = await _store.GetByTokenHashAsync(presentedHash, cancellationToken).ConfigureAwait(false);
        if (existing is null) return null;

        var claims = await _claimsResolver.ResolveClaimsAsync(existing.UserId, cancellationToken).ConfigureAwait(false);
        return await RotateAsync(presentedRefreshToken, claims, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Rotates the presented refresh token, embedding <paramref name="claims"/>
    /// into the new access token. Returns <c>null</c> when the presented token
    /// is unknown, expired, or already revoked (in which case the rotation
    /// chain is also revoked if <see cref="RefreshTokenOptions.RevokeChainOnReuse"/> is on).
    /// </summary>
    public async Task<TokenPair?> RotateAsync(string presentedRefreshToken, IEnumerable<Claim> claims, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrEmpty(presentedRefreshToken)) return null;
        if (claims is null) throw new ArgumentNullException(nameof(claims));

        var presentedHash = TokenHasher.HashRefreshToken(presentedRefreshToken);
        var existing = await _store.GetByTokenHashAsync(presentedHash, cancellationToken).ConfigureAwait(false);
        if (existing is null) return null;

        if (!existing.IsActive)
        {
            // Replay attack candidate: presenter showed a token that was already revoked or expired.
            var chainLength = 0;
            if (_options.RefreshTokens.RevokeChainOnReuse)
                chainLength = await RevokeChainAsync(existing, cancellationToken).ConfigureAwait(false);

            AuthDiagnostics.RefreshReuseDetectedTotal.Add(1);
            await _audit.LogAsync(new RefreshReuseDetectedEvent(existing.UserId, existing.TokenHash, chainLength, DateTimeOffset.UtcNow), cancellationToken).ConfigureAwait(false);
            return null;
        }

        var raw = TokenHasher.NewRawToken();
        var newHash = TokenHasher.HashRefreshToken(raw);
        var expiresAt = DateTimeOffset.UtcNow.Add(_options.RefreshTokens.Lifetime);

        var newEntity = new RefreshToken
        {
            UserId = existing.UserId,
            TokenHash = newHash,
            CreatedAt = DateTimeOffset.UtcNow,
            ExpiresAt = expiresAt,
        };
        await _store.CreateAsync(newEntity, cancellationToken).ConfigureAwait(false);
        await _store.RevokeAsync(existing.Id, newHash, cancellationToken).ConfigureAwait(false);

        var access = _tokens.CreateToken(existing.UserId, claims, _options.Jwt.TokenLifetime);

        AuthDiagnostics.RefreshTokensRotatedTotal.Add(1);
        AuthDiagnostics.TokensIssuedTotal.Add(1);
        await _audit.LogAsync(new TokenRefreshedEvent(existing.UserId, existing.TokenHash, newHash, DateTimeOffset.UtcNow), cancellationToken).ConfigureAwait(false);

        return new TokenPair(access, raw, expiresAt);
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

    private async Task<int> RevokeChainAsync(RefreshToken start, CancellationToken cancellationToken)
    {
        var current = start;
        var safety = 0;
        while (current is not null && safety < MaxChainWalkDepth)
        {
            await _store.RevokeAsync(current.Id, current.ReplacedByTokenHash, cancellationToken).ConfigureAwait(false);
            safety++;
            if (string.IsNullOrEmpty(current.ReplacedByTokenHash)) break;
            current = await _store.GetByTokenHashAsync(current.ReplacedByTokenHash!, cancellationToken).ConfigureAwait(false);
        }
        return safety;
    }
}
