namespace TechTeaStudio.Auth.Profiles;

/// <summary>
/// Input bag for <see cref="IClaimsProfile.BuildClaims"/>. All fields are optional;
/// each profile picks the ones it cares about and ignores the rest. This keeps the
/// profile interface flexible without forcing a stringly-typed dictionary.
/// </summary>
public sealed record ClaimsBuilderInput
{
    /// <summary>Opaque user identifier.</summary>
    public string? UserId { get; init; }

    /// <summary>User-facing display name / login.</summary>
    public string? Username { get; init; }

    /// <summary>User email address.</summary>
    public string? Email { get; init; }

    /// <summary>Role names the user holds. <c>null</c> is treated as "no roles".</summary>
    public IReadOnlyList<string>? Roles { get; init; }

    /// <summary>Extra app-specific claims to merge in. Keys are claim types.</summary>
    public IReadOnlyDictionary<string, string>? Extra { get; init; }
}
