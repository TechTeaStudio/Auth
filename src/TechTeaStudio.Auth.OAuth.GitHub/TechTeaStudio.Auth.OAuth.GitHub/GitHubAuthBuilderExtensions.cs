using Microsoft.Extensions.DependencyInjection;
using TechTeaStudio.Auth.AspNetCore;

namespace TechTeaStudio.Auth.OAuth.GitHub;

/// <summary>
/// Fluent registration for <see cref="GitHubAuthProvider"/>. Call from the
/// <see cref="IAuthBuilder"/> chain returned by <c>AddTechTeaStudioAuth(...)</c>.
/// </summary>
public static class GitHubAuthBuilderExtensions
{
    /// <summary>
    /// Registers <see cref="GitHubAuthProvider"/> as an <see cref="IExternalAuthProvider"/>
    /// with a typed <see cref="HttpClient"/> and binds <see cref="GitHubAuthProviderOptions"/>
    /// from the <c>Auth:GitHub</c> configuration section.
    /// </summary>
    public static IAuthBuilder AddGitHubAuthProvider(
        this IAuthBuilder builder,
        Action<GitHubAuthProviderOptions>? configure = null,
        string sectionName = "Auth:GitHub")
    {
        if (builder is null) throw new ArgumentNullException(nameof(builder));

        builder.Services.AddOptions<GitHubAuthProviderOptions>()
            .BindConfiguration(sectionName);

        if (configure is not null)
            builder.Services.Configure(configure);

        builder.Services.AddHttpClient<GitHubAuthProvider>(client =>
        {
            client.DefaultRequestHeaders.UserAgent.ParseAdd("TechTeaStudio.Auth.OAuth.GitHub");
            client.Timeout = TimeSpan.FromSeconds(15);
        });

        builder.AddExternalAuthProvider<GitHubAuthProvider>(ServiceLifetime.Transient);
        return builder;
    }
}
