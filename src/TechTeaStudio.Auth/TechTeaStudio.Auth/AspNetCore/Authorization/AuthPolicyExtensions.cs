using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using TechTeaStudio.Auth.Abstractions;

namespace TechTeaStudio.Auth.AspNetCore.Authorization;

/// <summary>
/// Extensions that register the built-in TechTeaStudio policies on
/// <see cref="AuthorizationOptions"/>. Call from <c>AddAuthorization(o =&gt; o.AddTechTeaStudioPolicies())</c>.
/// </summary>
public static class AuthPolicyExtensions
{
    /// <summary>
    /// Adds the four built-in policies: <see cref="AuthPolicies.Authenticated"/>,
    /// <see cref="AuthPolicies.RequireSubject"/>, <see cref="AuthPolicies.RequireEmail"/>,
    /// <see cref="AuthPolicies.EmailVerified"/>.
    /// </summary>
    public static AuthorizationOptions AddTechTeaStudioPolicies(this AuthorizationOptions options)
    {
        if (options is null) throw new ArgumentNullException(nameof(options));

        options.AddPolicy(AuthPolicies.Authenticated, p => p
            .RequireAuthenticatedUser());

        options.AddPolicy(AuthPolicies.RequireSubject, p => p
            .RequireAuthenticatedUser()
            .AddRequirements(new HasClaimRequirement(AuthClaims.Subject)));

        options.AddPolicy(AuthPolicies.RequireEmail, p => p
            .RequireAuthenticatedUser()
            .AddRequirements(new HasClaimRequirement(AuthClaims.Email)));

        options.AddPolicy(AuthPolicies.EmailVerified, p => p
            .RequireAuthenticatedUser()
            .AddRequirements(new HasClaimRequirement("email_verified", "true")));

        return options;
    }

    /// <summary>
    /// Registers <see cref="HasClaimAuthorizationHandler"/> with DI. Called from
    /// <c>AddTechTeaStudioAuth</c> so consumers do not need to wire it themselves.
    /// </summary>
    internal static IServiceCollection AddTechTeaStudioAuthorizationHandlers(this IServiceCollection services)
    {
        services.TryAddEnumerable(ServiceDescriptor.Singleton<IAuthorizationHandler, HasClaimAuthorizationHandler>());
        return services;
    }
}
