using System.Security.Claims;
using TechTeaStudio.Auth.Abstractions;

namespace TechTeaStudio.Auth.Profiles;

/// <summary>
/// Pello claim shape: <c>email</c> and <c>unique_name</c> (display name). No role
/// claims — Pello does not have a role system today. Extras still pass through.
/// </summary>
public sealed class PelloClaimsProfile : IClaimsProfile
{
    public string Name => "Pello";

    public IEnumerable<Claim> BuildClaims(ClaimsBuilderInput input)
    {
        if (input is null) throw new ArgumentNullException(nameof(input));

        if (!string.IsNullOrEmpty(input.Email))
            yield return new Claim(AuthClaims.Email, input.Email);
        if (!string.IsNullOrEmpty(input.Username))
            yield return new Claim(AuthClaims.Username, input.Username);

        if (input.Extra is { Count: > 0 })
        {
            foreach (var kvp in input.Extra)
                yield return new Claim(kvp.Key, kvp.Value);
        }
    }
}
