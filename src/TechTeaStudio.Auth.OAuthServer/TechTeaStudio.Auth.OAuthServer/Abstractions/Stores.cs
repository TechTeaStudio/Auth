namespace TechTeaStudio.Auth.OAuthServer.Abstractions;

/// <summary>Registered clients (dynamic registrations and any host-seeded rows).</summary>
public interface IOAuthClientStore
{
    Task<OAuthClient?> FindAsync(string clientId, CancellationToken cancellationToken = default);
    Task SaveAsync(OAuthClient client, CancellationToken cancellationToken = default);

    /// <summary>Records <see cref="OAuthClient.LastUsedAt"/>. The module calls it at most hourly per client.</summary>
    Task TouchAsync(string clientId, DateTimeOffset now, CancellationToken cancellationToken = default);

    /// <summary>
    /// Deletes dynamically registered clients that have no grant and were last used (or, never used, created)
    /// before <paramref name="olderThan"/>. Pre-registered and metadata-document rows are never touched.
    /// Returns the number deleted. Call it from a job of the host's.
    /// </summary>
    Task<int> CleanupUnusedAsync(DateTimeOffset olderThan, CancellationToken cancellationToken = default);
}

/// <summary>Validated authorization requests waiting for login and consent.</summary>
public interface IOAuthPendingRequestStore
{
    Task SaveAsync(PendingAuthorization request, CancellationToken cancellationToken = default);

    /// <summary>Returns the request without consuming it; <c>null</c> when unknown or expired.</summary>
    Task<PendingAuthorization?> GetAsync(string id, DateTimeOffset now, CancellationToken cancellationToken = default);

    /// <summary>Atomically removes and returns the request. Exactly one concurrent caller gets it; <c>null</c> when unknown or expired.</summary>
    Task<PendingAuthorization?> TakeAsync(string id, DateTimeOffset now, CancellationToken cancellationToken = default);

    /// <summary>Live (unexpired) pending requests of one client; used to cap what a single client id can store.</summary>
    Task<int> CountForClientAsync(string clientId, DateTimeOffset now, CancellationToken cancellationToken = default);

    Task<int> CleanupExpiredAsync(DateTimeOffset cutoff, CancellationToken cancellationToken = default);
}

/// <summary>Authorization codes, keyed by the hash of the code.</summary>
public interface IOAuthCodeStore
{
    Task SaveAsync(AuthorizationCode code, CancellationToken cancellationToken = default);

    /// <summary>Reads a code without consuming it; <c>null</c> for an unknown hash.</summary>
    Task<AuthorizationCode?> GetAsync(string codeHash, CancellationToken cancellationToken = default);

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

    /// <summary>
    /// Revokes every still-active token of the family AND flags the family itself as revoked (creating the family
    /// record if it does not exist yet, so a revoke that wins a race against the first issuance still sticks).
    /// Returns how many token rows changed.
    /// </summary>
    Task<int> RevokeFamilyAsync(Guid familyId, DateTimeOffset now, CancellationToken cancellationToken = default);

    /// <summary>Like <see cref="RevokeFamilyAsync"/> for every family and token of a (user, client) pair.</summary>
    Task<int> RevokeForUserClientAsync(string userId, string clientId, DateTimeOffset now, CancellationToken cancellationToken = default);

    /// <summary>Like <see cref="RevokeFamilyAsync"/> for every family and token of a user.</summary>
    Task<int> RevokeForUserAsync(string userId, DateTimeOffset now, CancellationToken cancellationToken = default);

    Task<OAuthRefreshFamily?> GetFamilyAsync(Guid familyId, CancellationToken cancellationToken = default);

    /// <summary>Inserts the family if absent. An existing record (revoked or not) is left exactly as it is.</summary>
    Task EnsureFamilyAsync(OAuthRefreshFamily family, CancellationToken cancellationToken = default);

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

    /// <summary>Whether any user still holds a grant for the client (spares it from unused-client cleanup).</summary>
    Task<bool> AnyForClientAsync(string clientId, CancellationToken cancellationToken = default);

    /// <summary>Deletes every grant of the user; returns how many.</summary>
    Task<int> DeleteAllForUserAsync(string userId, CancellationToken cancellationToken = default);
}

/// <summary>
/// Optional host hook: is this user still allowed to hold tokens? Called on code exchange and on every refresh.
/// <c>false</c> answers <c>invalid_grant</c> and revokes the refresh family. Register it with
/// <c>services.AddScoped&lt;IOAuthUserValidator, ...&gt;()</c>; without one every user counts as active.
/// </summary>
public interface IOAuthUserValidator
{
    Task<bool> IsActiveAsync(string userId, CancellationToken cancellationToken = default);
}

/// <summary>Host-facing: the connected-apps settings page.</summary>
public interface IOAuthGrantService
{
    Task<IReadOnlyList<OAuthGrant>> ListForUserAsync(string userId, CancellationToken cancellationToken = default);

    /// <summary>Removes the grant and revokes every refresh token the client holds for the user. Access tokens already issued live out their short lifetime.</summary>
    Task<bool> RevokeAsync(string userId, string clientId, CancellationToken cancellationToken = default);

    /// <summary>For "sign out everywhere", password reset and account closure: removes every grant of the user and revokes every refresh family. Returns the number of grants removed.</summary>
    Task<int> RevokeAllAsync(string userId, CancellationToken cancellationToken = default);
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
    /// expired, already used, or not bound to the browser that started it. <paramref name="httpContext"/> is the
    /// consent POST: the module compares its <c>__Host-</c> binding cookie with the pending request (consent CSRF
    /// defence) and removes the binding on success.
    /// </summary>
    Task<string?> ApproveAsync(string requestId, string userId, Microsoft.AspNetCore.Http.HttpContext httpContext, IEnumerable<string>? grantedScopes = null, CancellationToken cancellationToken = default);

    /// <summary>Denies the request and returns the redirect URL carrying <c>error=access_denied</c>; <c>null</c> when the request is unknown or not bound to this browser.</summary>
    Task<string?> DenyAsync(string requestId, Microsoft.AspNetCore.Http.HttpContext httpContext, CancellationToken cancellationToken = default);

    /// <summary>
    /// When <see cref="OAuthServerOptions.RememberConsent"/> is on and the user already granted every requested
    /// scope to this client, approves without a consent screen and returns the redirect URL. Otherwise <c>null</c>
    /// and the request stays pending.
    /// </summary>
    Task<string?> TryAutoApproveAsync(string requestId, string userId, Microsoft.AspNetCore.Http.HttpContext httpContext, CancellationToken cancellationToken = default);
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
