using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using TechTeaStudio.Auth.AspNetCore;

namespace TechTeaStudio.Auth.OAuth;

/// <summary>
/// Fluent extensions on <see cref="IAuthBuilder"/> for the OAuth stack. These
/// register the in-memory <see cref="IExternalLoginStore"/> default and the
/// <see cref="ExternalLoginService"/> orchestrator; consumers must additionally
/// register an <see cref="IExternalUserBridge"/> and one or more
/// <see cref="IExternalAuthProvider"/> implementations (from sibling packages
/// such as <c>TechTeaStudio.Auth.OAuth.Google</c>).
/// </summary>
public static class OAuthAuthBuilderExtensions
{
    /// <summary>
    /// Registers <see cref="ExternalLoginService"/> + in-memory default
    /// <see cref="IExternalLoginStore"/>. Idempotent — safe to call multiple
    /// times. The first <see cref="AddExternalAuthProvider{T}"/> call from a
    /// sibling package will invoke this if it has not been wired yet.
    /// </summary>
    public static IAuthBuilder AddTechTeaStudioOAuth(this IAuthBuilder builder)
    {
        if (builder is null) throw new ArgumentNullException(nameof(builder));
        builder.Services.TryAddSingleton<IExternalLoginStore, InMemoryExternalLoginStore>();
        builder.Services.TryAddScoped<ExternalLoginService>();
        return builder;
    }

    /// <summary>
    /// Replaces the default <see cref="IExternalLoginStore"/>. Use this from
    /// <c>TechTeaStudio.Auth.OAuth.EFCore</c> /
    /// <c>TechTeaStudio.Auth.OAuth.Redis</c>.
    /// </summary>
    public static IAuthBuilder UseExternalLoginStore<TStore>(this IAuthBuilder builder, ServiceLifetime lifetime = ServiceLifetime.Scoped)
        where TStore : class, IExternalLoginStore
    {
        if (builder is null) throw new ArgumentNullException(nameof(builder));
        builder.AddTechTeaStudioOAuth();
        builder.Services.RemoveAll<IExternalLoginStore>();
        builder.Services.Add(ServiceDescriptor.Describe(typeof(IExternalLoginStore), typeof(TStore), lifetime));
        return builder;
    }

    /// <summary>
    /// Registers the consumer's bridge to its own user table. Required for any
    /// OAuth flow — without it, the orchestrator cannot create / look up users.
    /// </summary>
    public static IAuthBuilder UseExternalUserBridge<TBridge>(this IAuthBuilder builder, ServiceLifetime lifetime = ServiceLifetime.Scoped)
        where TBridge : class, IExternalUserBridge
    {
        if (builder is null) throw new ArgumentNullException(nameof(builder));
        builder.AddTechTeaStudioOAuth();
        builder.Services.RemoveAll<IExternalUserBridge>();
        builder.Services.Add(ServiceDescriptor.Describe(typeof(IExternalUserBridge), typeof(TBridge), lifetime));
        return builder;
    }

    /// <summary>
    /// Registers an <see cref="IExternalAuthProvider"/>. Called by the
    /// <c>AddGoogleAuthProvider</c> / <c>AddGitHubAuthProvider</c> /
    /// <c>AddAppleAuthProvider</c> extensions of the provider-specific packages.
    /// </summary>
    public static IAuthBuilder AddExternalAuthProvider<TProvider>(this IAuthBuilder builder, ServiceLifetime lifetime = ServiceLifetime.Singleton)
        where TProvider : class, IExternalAuthProvider
    {
        if (builder is null) throw new ArgumentNullException(nameof(builder));
        builder.AddTechTeaStudioOAuth();
        builder.Services.TryAddEnumerable(ServiceDescriptor.Describe(typeof(IExternalAuthProvider), typeof(TProvider), lifetime));
        return builder;
    }

    /// <summary>
    /// Registers an instance-based <see cref="IExternalAuthProvider"/> (e.g.
    /// constructed from a configured <c>HttpClient</c>). Same semantics as the
    /// generic overload.
    /// </summary>
    public static IAuthBuilder AddExternalAuthProvider(this IAuthBuilder builder, IExternalAuthProvider instance)
    {
        if (builder is null) throw new ArgumentNullException(nameof(builder));
        if (instance is null) throw new ArgumentNullException(nameof(instance));
        builder.AddTechTeaStudioOAuth();
        // Use Add (not TryAddEnumerable) so several instance-based providers can coexist.
        builder.Services.Add(ServiceDescriptor.Singleton<IExternalAuthProvider>(instance));
        return builder;
    }
}
