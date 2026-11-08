namespace TechTeaStudio.Auth.OAuthServer.Abstractions;

/// <summary>Registered clients (dynamic registrations and any host-seeded rows).</summary>
public interface IOAuthClientStore
{
    Task<OAuthClient?> FindAsync(string clientId, CancellationToken cancellationToken = default);
    Task SaveAsync(OAuthClient client, CancellationToken cancellationToken = default);
}

/// <summary>Validated authorization requests waiting for login and consent.</summary>
public interface IOAuthPendingRequestStore
{
    Task SaveAsync(PendingAuthorization request, CancellationToken cancellationToken = default);

    /// <summary>Returns the request without consuming it; <c>null</c> when unknown or expired.</summary>
    Task<PendingAuthorization?> GetAsync(string id, DateTimeOffset now, CancellationToken cancellationToken = default);

    /// <summary>Atomically removes and returns the request. Exactly one concurrent caller gets it; <c>null</c> when unknown or expired.</summary>
    Task<PendingAuthorization?> TakeAsync(string id, DateTimeOffset now, CancellationToken cancellationToken = default);

    Task<int> CleanupExpiredAsync(DateTimeOffset cutoff, CancellationToken cancellationToken = default);
}

/// <summary>Authorization codes, keyed by the hash of the code.</summary>
public interface IOAuthCodeStore
{
    Task SaveAsync(AuthorizationCode code, CancellationToken cancellationToken = default);

    /// <summary>
    /// Atomically marks the code consumed. Returns <c>null</c> for an unknown hash. When the code was already
    /// consumed the result has <see cref="CodeConsumeResult.AlreadyConsumed"/> set and nothing changes.
    /// Expiry is the caller's check.
    /// </summary>
    Task<CodeConsumeResult?> TryConsumeAsync(string codeHash, DateTimeOffset now, CancellationToken cancellationToken = default);

    Task<int> CleanupExpiredAsync(DateTimeOffset cutoff, CancellationToken cancellationToken = default);
}

/// <summary>Refresh tokens, keyed by the hash of the token.</summary>
public interface IOAuthRefreshTokenStore
{
    Task CreateAsync(OAuthRefreshToken token, CancellationToken cancellationToken = default);
    Task<OAuthRefreshToken?> GetByHashAsync(string tokenHash, CancellationToken cancellationToken = default);

    /// <summary>
    /// Compare-and-swap: marks the token rotated only if it is neither rotated nor revoked yet.
    /// <c>true</c> for exactly one concurrent caller.
    /// </summary>
    Task<bool> TryRotateAsync(Guid id, string replacedByTokenHash, DateTimeOffset now, CancellationToken cancellationToken = default);

    /// <summary>Revokes every still-active token of the family. Returns how many rows changed.</summary>
    Task<int> RevokeFamilyAsync(Guid familyId, DateTimeOffset now, CancellationToken cancellationToken = default);

    /// <summary>Revokes every still-active token of a (user, client) pair. Returns how many rows changed.</summary>
    Task<int> RevokeForUserClientAsync(string userId, string clientId, DateTimeOffset now, CancellationToken cancellationToken = default);

    Task<int> CleanupExpiredAsync(DateTimeOffset cutoff, CancellationToken cancellationToken = default);
}

/// <summary>
/// Per (user, client) grant records, for the host's "connected apps" list. <see cref="DeleteAsync"/> only removes
/// the row; <see cref="IOAuthGrantService.RevokeAsync"/> is the call that also kills the client's refresh tokens.
/// </summary>
public interface IOAuthGrantStore
{
    Task<OAuthGrant?> GetAsync(string userId, string clientId, CancellationToken cancellationToken = default);

    /// <summary>Creates the grant or widens it: stored scopes become the union of old and new; <c>LastUsedAt</c> moves to <paramref name="now"/>.</summary>
    Task UpsertAsync(string userId, string clientId, string? clientName, IReadOnlyCollection<string> scopes, DateTimeOffset now, CancellationToken cancellationToken = default);

    Task TouchAsync(string userId, string clientId, DateTimeOffset now, CancellationToken cancellationToken = default);
    Task<IReadOnlyList<OAuthGrant>> ListForUserAsync(string userId, CancellationToken cancellationToken = default);
    Task<bool> DeleteAsync(string userId, string clientId, CancellationToken cancellationToken = default);
}

/// <summary>Host-facing: the connected-apps settings page.</summary>
public interface IOAuthGrantService
{
    Task<IReadOnlyList<OAuthGrant>> ListForUserAsync(string userId, CancellationToken cancellationToken = default);

    /// <summary>Removes the grant and revokes every refresh token the client holds for the user. Access tokens already issued live out their short lifetime.</summary>
    Task<bool> RevokeAsync(string userId, string clientId, CancellationToken cancellationToken = default);
}

/// <summary>
/// Host-facing contract of the two-step authorize flow. The module validates and stores the request, the host
/// signs the user in and shows the consent screen, then calls one of these methods.
/// </summary>
public interface IOAuthAuthorizationService
{
    /// <summary>Describes the pending request for the consent screen; <c>null</c> when unknown, expired or already used.</summary>
    Task<PendingAuthorizationInfo?> GetPendingAsync(string requestId, CancellationToken cancellationToken = default);

    /// <summary>
    /// Approves the request for <paramref name="userId"/> and returns the URL to redirect the browser to (carries
    /// <c>code</c>, <c>state</c>, <c>iss</c>). <paramref name="grantedScopes"/> may be a subset of the requested
    /// scopes (downscoping); <c>null</c> grants all requested. Returns <c>null</c> when the request is unknown,
    /// expired or already used.
    /// </summary>
    Task<string?> ApproveAsync(string requestId, string userId, IEnumerable<string>? grantedScopes = null, CancellationToken cancellationToken = default);

    /// <summary>Denies the request and returns the redirect URL carrying <c>error=access_denied</c>; <c>null</c> when the request is unknown.</summary>
    Task<string?> DenyAsync(string requestId, CancellationToken cancellationToken = default);

    /// <summary>
    /// When <see cref="OAuthServerOptions.RememberConsent"/> is on and the user already granted every requested
    /// scope to this client, approves without a consent screen and returns the redirect URL. Otherwise <c>null</c>
    /// and the request stays pending.
    /// </summary>
    Task<string?> TryAutoApproveAsync(string requestId, string userId, CancellationToken cancellationToken = default);
}

/// <summary>Outcome of fetching a Client ID Metadata Document.</summary>
public sealed record ClientMetadataFetchResult
{
    public string? Json { get; init; }

    /// <summary>Cache lifetime requested by the document server; <c>null</c> when it sent none, <see cref="TimeSpan.Zero"/> for no-store.</summary>
    public TimeSpan? MaxAge { get; init; }

    public string? Error { get; init; }
    public bool Succeeded => Error is null && Json is not null;

    public static ClientMetadataFetchResult Ok(string json, TimeSpan? maxAge) => new() { Json = json, MaxAge = maxAge };
    public static ClientMetadataFetchResult Fail(string error) => new() { Error = error };
}

/// <summary>Downloads a Client ID Metadata Document. Replace in tests or when a host needs its own egress policy.</summary>
public interface IClientMetadataFetcher
{
    Task<ClientMetadataFetchResult> FetchAsync(Uri url, CancellationToken cancellationToken = default);
}
