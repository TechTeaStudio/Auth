using System.Security.Claims;
using TechTeaStudio.Auth.Abstractions;

namespace TechTeaStudio.Auth.Profiles;

/// <summary>
/// Hyperion Omni Client claim shape: <c>sub</c>, <c>unique_name</c>, <c>email</c>,
/// one <c>role</c> per role, and a legacy <c>nameid</c> equal to <c>sub</c> so
/// pre-Auth-package tokens stay readable.
/// </summary>
public sealed class HyperionClaimsProfile : IClaimsProfile
{
    public string Name => "Hyperion";

    public IEnumerable<Claim> BuildClaims(ClaimsBuilderInput input)
    {
        if (input is null) throw new ArgumentNullException(nameof(input));

        if (!string.IsNullOrEmpty(input.UserId))
        {
            yield return new Claim(AuthClaims.Subject, input.UserId);
#pragma warning disable CS0618
            yield return new Claim(AuthClaims.LegacyNameId, input.UserId);
#pragma warning restore CS0618
        }
        if (!string.IsNullOrEmpty(input.Username))
            yield return new Claim(AuthClaims.Username, input.Username);
        if (!string.IsNullOrEmpty(input.Email))
            yield return new Claim(AuthClaims.Email, input.Email);

        if (input.Roles is { Count: > 0 })
        {
            foreach (var role in input.Roles)
            {
                if (!string.IsNullOrEmpty(role))
                    yield return new Claim(AuthClaims.Role, role);
            }
        }

        if (input.Extra is { Count: > 0 })
        {
            foreach (var kvp in input.Extra)
                yield return new Claim(kvp.Key, kvp.Value);
        }
    }
}
