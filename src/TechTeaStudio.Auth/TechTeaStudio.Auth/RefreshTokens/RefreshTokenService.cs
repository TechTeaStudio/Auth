using System.Security.Claims;
using Microsoft.Extensions.Options;
using TechTeaStudio.Auth.Abstractions;

namespace TechTeaStudio.Auth.RefreshTokens;

/// <summary>
/// Issues, rotates, and revokes refresh tokens on top of a pluggable
/// <see cref="IRefreshTokenStore"/>. Refresh tokens are single-use — every
/// successful <see cref="RotateAsync"/> revokes the presented token and emits
/// a fresh one. Presenting an already-revoked token revokes the whole rotation
/// chain when <see cref="AuthOptions.RevokeChainOnRefreshReuse"/> is enabled.
/// </summary>
public sealed class RefreshTokenService
{
    private readonly ITokenProvider _tokens;
    private readonly IRefreshTokenStore _store;
    private readonly AuthOptions _options;

    public RefreshTokenService(ITokenProvider tokens, IRefreshTokenStore store, IOptions<AuthOptions> options)
    {
        _tokens = tokens ?? throw new ArgumentNullException(nameof(tokens));
        _store = store ?? throw new ArgumentNullException(nameof(store));
        _options = options?.Value ?? throw new ArgumentNullException(nameof(options));
    }

    /// <summary>
    /// Issues a fresh access + refresh token pair for <paramref name="userId"/>.
    /// </summary>
    public async Task<TokenPair> IssueAsync(string userId, IEnumerable<Claim> claims, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrEmpty(userId)) throw new ArgumentException("userId is required.", nameof(userId));
        if (claims is null) throw new ArgumentNullException(nameof(claims));

        var raw = TokenHasher.NewRawToken();
        var hash = TokenHasher.HashRefreshToken(raw);
        var expiresAt = DateTimeOffset.UtcNow.Add(_options.RefreshTokenLifetime);

        var entity = new RefreshToken
        {
            UserId = userId,
            TokenHash = hash,
            CreatedAt = DateTimeOffset.UtcNow,
            ExpiresAt = expiresAt,
        };
        await _store.CreateAsync(entity, cancellationToken).ConfigureAwait(false);

        var access = _tokens.CreateToken(userId, claims, _options.TokenLifetime);
        return new TokenPair(access, raw, expiresAt);
    }

    /// <summary>
    /// Validates <paramref name="presentedRefreshToken"/>, revokes it, and issues a
    /// fresh pair. Returns <c>null</c> when the presented token is unknown, expired,
    /// or already revoked (in which case the rotation chain is also revoked if the
    /// option is on).
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
            if (_options.RevokeChainOnRefreshReuse)
                await RevokeChainAsync(existing, cancellationToken).ConfigureAwait(false);
            return null;
        }

        var raw = TokenHasher.NewRawToken();
        var newHash = TokenHasher.HashRefreshToken(raw);
        var expiresAt = DateTimeOffset.UtcNow.Add(_options.RefreshTokenLifetime);

        var newEntity = new RefreshToken
        {
            UserId = existing.UserId,
            TokenHash = newHash,
            CreatedAt = DateTimeOffset.UtcNow,
            ExpiresAt = expiresAt,
        };
        await _store.CreateAsync(newEntity, cancellationToken).ConfigureAwait(false);
        await _store.RevokeAsync(existing.Id, newHash, cancellationToken).ConfigureAwait(false);

        var access = _tokens.CreateToken(existing.UserId, claims, _options.TokenLifetime);
        return new TokenPair(access, raw, expiresAt);
    }

    /// <summary>
    /// Revokes <paramref name="presentedRefreshToken"/>. No-op when the token is unknown.
    /// </summary>
    public async Task RevokeAsync(string presentedRefreshToken, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrEmpty(presentedRefreshToken)) return;
        var hash = TokenHasher.HashRefreshToken(presentedRefreshToken);
        var existing = await _store.GetByTokenHashAsync(hash, cancellationToken).ConfigureAwait(false);
        if (existing is null) return;
        await _store.RevokeAsync(existing.Id, null, cancellationToken).ConfigureAwait(false);
    }

    private async Task RevokeChainAsync(RefreshToken start, CancellationToken cancellationToken)
    {
        var current = start;
        var safety = 0;
        while (current is not null && safety++ < 1000)
        {
            await _store.RevokeAsync(current.Id, current.ReplacedByTokenHash, cancellationToken).ConfigureAwait(false);
            if (string.IsNullOrEmpty(current.ReplacedByTokenHash)) break;
            current = await _store.GetByTokenHashAsync(current.ReplacedByTokenHash!, cancellationToken).ConfigureAwait(false);
        }
    }
}
