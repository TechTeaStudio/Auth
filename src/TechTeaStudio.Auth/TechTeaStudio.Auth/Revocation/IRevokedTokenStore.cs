namespace TechTeaStudio.Auth.Revocation;

/// <summary>
/// Deny-list for individual access tokens (by <c>jti</c>). Lets a service kill a
/// stolen token before its natural expiry. The store is consulted by
/// <see cref="Jwt.JwtTokenProvider.ValidateToken"/> after the signature and
/// lifetime checks succeed.
/// </summary>
public interface IRevokedTokenStore
{
    /// <summary>Returns <c>true</c> when <paramref name="jti"/> is currently in the deny-list.</summary>
    Task<bool> IsRevokedAsync(string jti, CancellationToken cancellationToken = default);

    /// <summary>Adds <paramref name="jti"/> to the deny-list until <paramref name="expiresAt"/>.</summary>
    Task RevokeAsync(string jti, DateTimeOffset expiresAt, CancellationToken cancellationToken = default);

    /// <summary>Removes entries that expired at or before <paramref name="cutoff"/>. Returns the count.</summary>
    Task<int> CleanupAsync(DateTimeOffset cutoff, CancellationToken cancellationToken = default);
}
