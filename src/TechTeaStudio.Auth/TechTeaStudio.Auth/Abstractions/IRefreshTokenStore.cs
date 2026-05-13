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
    Task RevokeAsync(Guid id, string? replacedByTokenHash = null, CancellationToken cancellationToken = default);

    /// <summary>Revokes every active token currently issued to <paramref name="userId"/>.</summary>
    Task RevokeAllForUserAsync(string userId, CancellationToken cancellationToken = default);

    /// <summary>Deletes every token whose <see cref="RefreshToken.ExpiresAt"/> is at or before <paramref name="cutoff"/>.</summary>
    /// <returns>The number of rows deleted.</returns>
    Task<int> CleanupExpiredAsync(DateTimeOffset cutoff, CancellationToken cancellationToken = default);

    /// <summary>Hard-deletes every refresh token for <paramref name="userId"/> (e.g. on account deletion).</summary>
    Task DeleteAllForUserAsync(string userId, CancellationToken cancellationToken = default);
}
