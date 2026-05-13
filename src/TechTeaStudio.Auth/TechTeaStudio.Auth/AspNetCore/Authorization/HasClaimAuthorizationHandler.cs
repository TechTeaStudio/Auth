using Microsoft.AspNetCore.Authorization;

namespace TechTeaStudio.Auth.AspNetCore.Authorization;

/// <summary>
/// Generic requirement: the principal must carry a claim of the given type, optionally
/// matching a specific value. Used by the built-in policies and reusable for custom
/// app-specific ones via <see cref="AuthorizationPolicyBuilder.AddRequirements"/>.
/// </summary>
public sealed class HasClaimRequirement : IAuthorizationRequirement
{
    public string ClaimType { get; }
    public string? RequiredValue { get; }

    public HasClaimRequirement(string claimType, string? requiredValue = null)
    {
        if (string.IsNullOrEmpty(claimType)) throw new ArgumentException("claimType required", nameof(claimType));
        ClaimType = claimType;
        RequiredValue = requiredValue;
    }
}

internal sealed class HasClaimAuthorizationHandler : AuthorizationHandler<HasClaimRequirement>
{
    protected override Task HandleRequirementAsync(AuthorizationHandlerContext context, HasClaimRequirement requirement)
    {
        var match = context.User.Claims.FirstOrDefault(c =>
            string.Equals(c.Type, requirement.ClaimType, StringComparison.Ordinal));
        if (match is null) return Task.CompletedTask;

        if (string.IsNullOrEmpty(match.Value)) return Task.CompletedTask;

        if (requirement.RequiredValue is null ||
            string.Equals(match.Value, requirement.RequiredValue, StringComparison.Ordinal))
        {
            context.Succeed(requirement);
        }

        return Task.CompletedTask;
    }
}
