using System.Security.Claims;

namespace TechTeaStudio.Auth.Profiles;

/// <summary>
/// Maps app-specific user properties into the JWT claim shape that app expects.
/// Allows Hyperion and Pello (and future apps) to share the same library without
/// forking just to publish different claim names.
/// </summary>
public interface IClaimsProfile
{
    /// <summary>Stable identifier for this profile, used in registration.</summary>
    string Name { get; }

    /// <summary>Builds the claim set this profile publishes for the given input.</summary>
    IEnumerable<Claim> BuildClaims(ClaimsBuilderInput input);
}
