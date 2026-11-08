namespace TechTeaStudio.Auth.OAuthServer.Abstractions;

/// <summary>Where a resolved client definition came from.</summary>
public enum OAuthClientSource
{
    PreRegistered = 0,
    MetadataDocument = 1,
    Dynamic = 2,
}

/// <summary>A resolved OAuth client. Public clients carry no <see cref="SecretHash"/>.</summary>
public sealed record OAuthClient
{
    public string ClientId { get; init; } = string.Empty;
    public string? Name { get; init; }
    public string? LogoUri { get; init; }
    public string? ClientUri { get; init; }
    public IReadOnlyList<string> RedirectUris { get; init; } = Array.Empty<string>();

    /// <summary>Lower-case hex SHA-256 of the client secret; <c>null</c> for public clients.</summary>
    public string? SecretHash { get; init; }

    public OAuthClientSource Source { get; init; }
    public DateTimeOffset CreatedAt { get; init; }

    /// <summary>Last authorize or token request seen for the client (recorded at most hourly). <c>null</c> until first use.</summary>
    public DateTimeOffset? LastUsedAt { get; init; }

    public bool IsConfidential => SecretHash is not null;
}

/// <summary>
/// One refresh-token family. It exists so a revocation can be recorded before, or while, the family's tokens are
/// created: every revoke sets <see cref="RevokedAt"/> and issuance re-checks it after writing a token.
/// </summary>
public sealed record OAuthRefreshFamily
{
    public Guid FamilyId { get; init; }
    public string UserId { get; init; } = string.Empty;
    public string ClientId { get; init; } = string.Empty;
    public DateTimeOffset CreatedAt { get; init; }

    /// <summary>End of the family's absolute lifetime; sliding refresh cannot extend past it.</summary>
    public DateTimeOffset ExpiresAt { get; init; }

    public DateTimeOffset? RevokedAt { get; init; }
}

/// <summary>A scope the server can grant, with the text the consent screen shows.</summary>
public sealed record OAuthScope(string Name, string? Description = null);

/// <summary>
/// An authorization request that passed validation and waits for the host's login and consent UI.
/// Single use, short lived.
/// </summary>
public sealed record PendingAuthorization
{
    public string Id { get; init; } = string.Empty;
    public string ClientId { get; init; } = string.Empty;
    public string RedirectUri { get; init; } = string.Empty;
    public string CodeChallenge { get; init; } = string.Empty;
    public string Resource { get; init; } = string.Empty;
    public IReadOnlyList<string> Scopes { get; init; } = Array.Empty<string>();
    public string? State { get; init; }
    public DateTimeOffset CreatedAt { get; init; }
    public DateTimeOffset ExpiresAt { get; init; }
}

/// <summary>An issued authorization code. Only the hash of the code is ever stored.</summary>
public sealed record AuthorizationCode
{
    public string CodeHash { get; init; } = string.Empty;
    public string ClientId { get; init; } = string.Empty;
    public string RedirectUri { get; init; } = string.Empty;
    public string CodeChallenge { get; init; } = string.Empty;
    public string Resource { get; init; } = string.Empty;
    public IReadOnlyList<string> Scopes { get; init; } = Array.Empty<string>();
    public string UserId { get; init; } = string.Empty;

    /// <summary>Refresh-token family the tokens issued from this code belong to.</summary>
    public Guid FamilyId { get; init; }

    public DateTimeOffset CreatedAt { get; init; }
    public DateTimeOffset ExpiresAt { get; init; }
    public DateTimeOffset? ConsumedAt { get; init; }
}

/// <summary>Outcome of <see cref="IOAuthCodeStore.TryConsumeAsync"/>.</summary>
public sealed record CodeConsumeResult(AuthorizationCode Code, bool AlreadyConsumed);

/// <summary>A stored OAuth refresh token (hashed).</summary>
public sealed record OAuthRefreshToken
{
    public Guid Id { get; init; }
    public string TokenHash { get; init; } = string.Empty;
    public Guid FamilyId { get; init; }
    public string ClientId { get; init; } = string.Empty;
    public string UserId { get; init; } = string.Empty;
    public IReadOnlyList<string> Scopes { get; init; } = Array.Empty<string>();
    public string Resource { get; init; } = string.Empty;
    public DateTimeOffset CreatedAt { get; init; }
    public DateTimeOffset ExpiresAt { get; init; }

    /// <summary>Set when this token was exchanged for a successor.</summary>
    public DateTimeOffset? RotatedAt { get; init; }

    public DateTimeOffset? RevokedAt { get; init; }
    public string? ReplacedByTokenHash { get; init; }
}

/// <summary>What a user granted to a client. One row per (user, client).</summary>
public sealed record OAuthGrant
{
    public string UserId { get; init; } = string.Empty;
    public string ClientId { get; init; } = string.Empty;
    public string? ClientName { get; init; }
    public IReadOnlyList<string> Scopes { get; init; } = Array.Empty<string>();
    public DateTimeOffset FirstGrantedAt { get; init; }
    public DateTimeOffset LastUsedAt { get; init; }
}

/// <summary>Everything the host's consent screen needs about a pending request.</summary>
public sealed record PendingAuthorizationInfo
{
    public string RequestId { get; init; } = string.Empty;
    public string ClientId { get; init; } = string.Empty;
    public string ClientName { get; init; } = string.Empty;

    /// <summary>Only ever set for pre-registered clients; a self-asserted logo is a spoofing tool.</summary>
    public string? ClientLogoUri { get; init; }

    /// <summary>Host of the https <c>client_id</c> for metadata-document clients; <c>null</c> otherwise.</summary>
    public string? ClientIdHost { get; init; }

    /// <summary>Metadata-document clients only: the redirect URI is on a different origin than the client_id URL. The consent screen should warn.</summary>
    public bool RedirectOriginDiffersFromClientId { get; init; }

    public string? ClientUri { get; init; }
    public OAuthClientSource ClientSource { get; init; }

    /// <summary>Host name of the redirect URI. The consent screen must show it: it is the only part of the client identity a user can check.</summary>
    public string RedirectHost { get; init; } = string.Empty;

    public string RedirectUri { get; init; } = string.Empty;
    public string Resource { get; init; } = string.Empty;
    public IReadOnlyList<OAuthScope> RequestedScopes { get; init; } = Array.Empty<OAuthScope>();
    public DateTimeOffset ExpiresAt { get; init; }
}
