using Microsoft.Extensions.DependencyInjection;
using TechTeaStudio.Auth.AspNetCore;

namespace TechTeaStudio.Auth.OAuth.Google;

/// <summary>
/// Fluent registration for <see cref="GoogleAuthProvider"/>. Call from the
/// <see cref="IAuthBuilder"/> chain returned by <c>AddTechTeaStudioAuth(...)</c>.
/// </summary>
public static class GoogleAuthBuilderExtensions
{
    /// <summary>
    /// Registers <see cref="GoogleAuthProvider"/> as an <see cref="IExternalAuthProvider"/>
    /// and binds <see cref="GoogleAuthProviderOptions"/> from the <c>Auth:Google</c>
    /// configuration section. <paramref name="configure"/> may override / extend
    /// the bound values in code.
    /// </summary>
    public static IAuthBuilder AddGoogleAuthProvider(
        this IAuthBuilder builder,
        Action<GoogleAuthProviderOptions>? configure = null,
        string sectionName = "Auth:Google")
    {
        if (builder is null) throw new ArgumentNullException(nameof(builder));

        var opts = builder.Services.AddOptions<GoogleAuthProviderOptions>()
            .BindConfiguration(sectionName);
        if (configure is not null)
            opts.Configure(configure);

        builder.AddExternalAuthProvider<GoogleAuthProvider>();
        return builder;
    }
}
