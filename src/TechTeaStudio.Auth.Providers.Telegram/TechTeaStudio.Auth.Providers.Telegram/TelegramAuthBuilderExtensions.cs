using Microsoft.Extensions.DependencyInjection;
using TechTeaStudio.Auth.AspNetCore;
using TechTeaStudio.Auth.OAuth;

namespace TechTeaStudio.Auth.Providers.Telegram;

/// <summary>
/// Fluent registration for <see cref="TelegramLoginProvider"/>. Call from the
/// <see cref="IAuthBuilder"/> chain returned by <c>AddTechTeaStudioAuthCore(...)</c>.
/// </summary>
public static class TelegramAuthBuilderExtensions
{
    /// <summary>
    /// Registers <see cref="TelegramLoginProvider"/> as an <see cref="IExternalAuthProvider"/> and
    /// binds <see cref="TelegramLoginOptions"/> from the <c>Auth:Telegram</c> configuration
    /// section. No <see cref="HttpClient"/> is registered: validation never leaves the process.
    /// </summary>
    public static IAuthBuilder AddTelegramLoginProvider(
        this IAuthBuilder builder,
        Action<TelegramLoginOptions>? configure = null,
        string sectionName = "Auth:Telegram")
    {
        if (builder is null) throw new ArgumentNullException(nameof(builder));

        builder.Services.AddOptions<TelegramLoginOptions>()
            .BindConfiguration(sectionName);

        if (configure is not null)
            builder.Services.Configure(configure);

        builder.AddExternalAuthProvider<TelegramLoginProvider>(ServiceLifetime.Transient);
        return builder;
    }
}
