using Microsoft.Extensions.DependencyInjection;
using TechTeaStudio.Auth.AspNetCore;

namespace TechTeaStudio.Auth.OAuth.Microsoft;

/// <summary>
/// Fluent registration for <see cref="MicrosoftAuthProvider"/>. Call from the
/// <see cref="IAuthBuilder"/> chain returned by <c>AddTechTeaStudioAuthCore(...)</c>.
/// </summary>
public static class MicrosoftAuthBuilderExtensions
{
    /// <summary>
    /// Registers <see cref="MicrosoftAuthProvider"/> as an <see cref="IExternalAuthProvider"/>
    /// with a typed <see cref="HttpClient"/> and binds <see cref="MicrosoftAuthProviderOptions"/>
    /// from the <c>Auth:Microsoft</c> configuration section.
    /// </summary>
    public static IAuthBuilder AddMicrosoftAuthProvider(
        this IAuthBuilder builder,
        Action<MicrosoftAuthProviderOptions>? configure = null,
        string sectionName = "Auth:Microsoft")
    {
        if (builder is null) throw new ArgumentNullException(nameof(builder));

        builder.Services.AddOptions<MicrosoftAuthProviderOptions>()
            .BindConfiguration(sectionName);

        if (configure is not null)
            builder.Services.Configure(configure);

        builder.Services.AddHttpClient<MicrosoftAuthProvider>(client =>
        {
            client.DefaultRequestHeaders.UserAgent.ParseAdd("TechTeaStudio.Auth.OAuth.Microsoft");
            client.Timeout = TimeSpan.FromSeconds(15);
        });

        builder.AddExternalAuthProvider<MicrosoftAuthProvider>(ServiceLifetime.Transient);
        return builder;
    }
}
