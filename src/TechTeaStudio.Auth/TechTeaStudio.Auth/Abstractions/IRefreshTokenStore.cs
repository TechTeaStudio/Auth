namespace TechTeaStudio.Auth.Abstractions;

/// <summary>
/// Persistence contract for refresh tokens. Implementations only ever see token
/// **hashes** (<see cref="RefreshToken.TokenHash"/>) — raw token strings live only
/// inside the rotation service and on the wire.
/// </summary>
public interface IRefreshTokenStore
{
    /// <summary>Returns the row whose <see cref="RefreshToken.TokenHash"/> equals <paramref name="tokenHash"/>, or <c>null</c>.</summary>
    Task<RefreshToken?> GetByTokenHashAsync(string tokenHash, CancellationToken cancellationToken = default);

    /// <summary>Returns every non-revoked, non-expired token currently issued to <paramref name="userId"/>.</summary>
    Task<IReadOnlyList<RefreshToken>> GetActiveForUserAsync(string userId, CancellationToken cancellationToken = default);

    /// <summary>Persists a freshly issued <paramref name="token"/>.</summary>
    Task CreateAsync(RefreshToken token, CancellationToken cancellationToken = default);

    /// <summary>
    /// Marks the token identified by <paramref name="id"/> as revoked. When
    /// <paramref name="replacedByTokenHash"/> is supplied, it records the successor
    /// in the rotation chain.
    /// </summary>
    /// <returns>
    /// <c>true</c> iff THIS call transitioned a currently-active row to revoked;
    /// <c>false</c> when the row was already revoked or does not exist (idempotent).
    /// Callers use this as a compare-and-swap to detect a lost race against a
    /// concurrent revoke/rotation of the same token — only the caller that gets
    /// <c>true</c> may treat itself as the sole owner of the revocation.
    /// </returns>
    Task<bool> RevokeAsync(Guid id, string? replacedByTokenHash = null, CancellationToken cancellationToken = default);

    /// <summary>Revokes every active token currently issued to <paramref name="userId"/>.</summary>
    Task RevokeAllForUserAsync(string userId, CancellationToken cancellationToken = default);

    /// <summary>
    /// Revokes every active token in <paramref name="familyId"/>'s rotation family — the
    /// whole login-to-latest-refresh chain, not just one row. Used by stolen-token (reuse)
    /// detection: presenting an already-used/revoked token proves knowledge of a leaked
    /// token, so the entire family, including whatever token it was rotated into, is
    /// burned, forcing re-login on every device sharing that family. Implementations
    /// should make this a single atomic set-based operation where the backing store
    /// supports one (e.g. a guarded UPDATE in a relational store); see each store's own
    /// remarks for its actual atomicity guarantee (the Redis store, like its other bulk
    /// operations, is a documented best-effort read-then-write, not a single atomic op).
    /// </summary>
    /// <returns>The number of rows this call transitioned from active to revoked.</returns>
    Task<int> RevokeFamilyAsync(Guid familyId, CancellationToken cancellationToken = default);

    /// <summary>Deletes every token whose <see cref="RefreshToken.ExpiresAt"/> is at or before <paramref name="cutoff"/>.</summary>
    /// <returns>The number of rows deleted.</returns>
    Task<int> CleanupExpiredAsync(DateTimeOffset cutoff, CancellationToken cancellationToken = default);

    /// <summary>Hard-deletes every refresh token for <paramref name="userId"/> (e.g. on account deletion).</summary>
    Task DeleteAllForUserAsync(string userId, CancellationToken cancellationToken = default);
}
