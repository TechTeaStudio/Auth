namespace TechTeaStudio.Auth.Profiles;

/// <summary>
/// Shorthand factory for the built-in claim profiles. Use these as the default
/// argument to <c>AddTechTeaStudioAuth(...)</c> so consumers don't need to <c>new</c>
/// up a profile themselves.
/// </summary>
public static class ClaimsProfiles
{
    /// <summary>Hyperion Omni Client profile (<c>sub</c>, <c>unique_name</c>, <c>email</c>, <c>role</c>, legacy <c>nameid</c>).</summary>
    public static IClaimsProfile Hyperion { get; } = new HyperionClaimsProfile();

    /// <summary>Pello profile (<c>email</c>, <c>unique_name</c>).</summary>
    public static IClaimsProfile Pello { get; } = new PelloClaimsProfile();
}
