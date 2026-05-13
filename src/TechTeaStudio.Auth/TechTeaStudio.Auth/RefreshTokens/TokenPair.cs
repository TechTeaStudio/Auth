namespace TechTeaStudio.Auth.RefreshTokens;

/// <summary>
/// Bundle of access + refresh tokens returned by <see cref="RefreshTokenService"/>.
/// The raw <see cref="RefreshToken"/> is only ever returned here — it is never read back from the store.
/// </summary>
public sealed record TokenPair(
    string AccessToken,
    string RefreshToken,
    DateTimeOffset RefreshTokenExpiresAt);
