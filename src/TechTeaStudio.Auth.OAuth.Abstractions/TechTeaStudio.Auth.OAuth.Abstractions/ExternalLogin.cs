namespace TechTeaStudio.Auth.OAuth;

/// <summary>
/// Persisted link between an external identity (provider + provider-user-id) and a
/// local <see cref="UserId"/>. Indexed by <c>(Provider, ProviderUserId)</c> unique-constraint
/// at the store level.
/// </summary>
public sealed record ExternalLogin
{
    /// <summary>Surrogate primary key for the persisted row.</summary>
    public Guid Id { get; init; } = Guid.NewGuid();

    /// <summary>Consumer-side user identifier (string form so any id type fits).</summary>
    public string UserId { get; init; } = string.Empty;

    /// <summary>Provider name. Match <see cref="IExternalAuthProvider.Name"/>.</summary>
    public string Provider { get; init; } = string.Empty;

    /// <summary>Provider-side stable user id (e.g. Google <c>sub</c>, GitHub <c>id</c>).</summary>
    public string ProviderUserId { get; init; } = string.Empty;

    /// <summary>Email observed at the provider at the time of linking. Snapshot — not kept in sync.</summary>
    public string? Email { get; init; }

    /// <summary>UTC timestamp the link was created.</summary>
    public DateTimeOffset CreatedAt { get; init; } = DateTimeOffset.UtcNow;
}
