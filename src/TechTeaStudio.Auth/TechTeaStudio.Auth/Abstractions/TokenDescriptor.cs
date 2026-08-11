namespace TechTeaStudio.Auth.Abstractions;

/// <summary>
/// Per-call overrides for <see cref="ITokenProvider.CreateToken(string, System.Collections.Generic.IEnumerable{System.Security.Claims.Claim}, TokenDescriptor)"/>.
/// Every member left <c>null</c> falls back to the app-wide configured <c>AuthOptions.Jwt</c> value.
/// </summary>
/// <remarks>
/// Use this when the SAME signing key needs to mint tokens for more than one audience —
/// e.g. an app whose default audience is "app-web", but whose mobile/API surface needs a
/// distinct "app-api" audience without reconfiguring <c>Auth:Jwt:Audience</c> app-wide.
/// Validating a per-call audience is the consumer's job: point a dedicated JwtBearer scheme
/// (or a custom <c>TokenValidationParameters.ValidAudience</c>) at it. <see cref="ITokenProvider.ValidateToken"/>
/// and <see cref="ITokenReader"/> both keep validating/reading against the single app-wide
/// configured audience — they are not descriptor-aware.
/// </remarks>
public sealed record TokenDescriptor
{
    /// <summary>Overrides the <c>aud</c> claim. <c>null</c> falls back to <see cref="JwtOptions.Audience"/>.</summary>
    public string? Audience { get; init; }

    /// <summary>Overrides the <c>iss</c> claim. <c>null</c> falls back to <see cref="JwtOptions.Issuer"/>.</summary>
    public string? Issuer { get; init; }

    /// <summary>Overrides the token time-to-live. <c>null</c> falls back to <see cref="JwtOptions.TokenLifetime"/>.</summary>
    public TimeSpan? Lifetime { get; init; }

    /// <summary>Overrides <c>nbf</c> (not valid before). <c>null</c> defaults to the moment of issuance.</summary>
    public DateTimeOffset? NotBefore { get; init; }
}
