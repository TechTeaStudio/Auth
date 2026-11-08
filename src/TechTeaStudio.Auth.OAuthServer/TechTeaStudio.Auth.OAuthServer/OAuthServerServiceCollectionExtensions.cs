using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using TechTeaStudio.Auth.Observability;
using TechTeaStudio.Auth.OAuthServer.Abstractions;
using TechTeaStudio.Auth.OAuthServer.Clients;
using TechTeaStudio.Auth.OAuthServer.Internal;
using TechTeaStudio.Auth.OAuthServer.Services;
using TechTeaStudio.Auth.OAuthServer.Stores;

namespace TechTeaStudio.Auth.OAuthServer;

/// <summary>Fluent surface returned by <see cref="OAuthServerServiceCollectionExtensions.AddTechTeaStudioOAuthServer"/>.</summary>
public interface IOAuthServerBuilder
{
    IServiceCollection Services { get; }
}

internal sealed class OAuthServerBuilder : IOAuthServerBuilder
{
    public OAuthServerBuilder(IServiceCollection services) => Services = services;
    public IServiceCollection Services { get; }
}

public static class OAuthServerServiceCollectionExtensions
{
    /// <summary>
    /// Registers the authorization server with in-memory stores (swap them with the <c>Use*Store</c> methods or
    /// <c>UseEfCoreStores</c>). Requires <c>AddTechTeaStudioAuth</c> / <c>AddTechTeaStudioAuthCore</c> for
    /// <see cref="TechTeaStudio.Auth.Abstractions.ITokenProvider"/>.
    /// </summary>
    public static IOAuthServerBuilder AddTechTeaStudioOAuthServer(this IServiceCollection services, Action<OAuthServerOptions> configure)
    {
        if (services is null) throw new ArgumentNullException(nameof(services));
        if (configure is null) throw new ArgumentNullException(nameof(configure));

        services.AddOptions<OAuthServerOptions>()
            .Configure(configure)
            .ValidateOnStart();
        services.TryAddEnumerable(ServiceDescriptor.Singleton<IValidateOptions<OAuthServerOptions>, OAuthServerOptionsValidator>());

        services.TryAddSingleton(TimeProvider.System);
        services.TryAddSingleton<IAuthAuditLogger>(NullAuthAuditLogger.Instance);
        services.TryAddSingleton<ClientMetadataCache>();
        services.TryAddSingleton<IClientMetadataFetcher, HttpClientMetadataFetcher>();

        services.TryAddSingleton<IOAuthClientStore, InMemoryOAuthClientStore>();
        services.TryAddSingleton<IOAuthPendingRequestStore, InMemoryOAuthPendingRequestStore>();
        services.TryAddSingleton<IOAuthCodeStore, InMemoryOAuthCodeStore>();
        services.TryAddSingleton<IOAuthRefreshTokenStore, InMemoryOAuthRefreshTokenStore>();
        services.TryAddSingleton<IOAuthGrantStore, InMemoryOAuthGrantStore>();

        services.TryAddScoped<OAuthClientResolver>();
        services.TryAddScoped<OAuthAuthorizationService>();
        services.TryAddScoped<IOAuthAuthorizationService>(sp => sp.GetRequiredService<OAuthAuthorizationService>());
        services.TryAddScoped<IOAuthGrantService, OAuthGrantService>();
        services.TryAddScoped<OAuthTokenService>();
        services.TryAddScoped<OAuthRegistrationService>();

        return new OAuthServerBuilder(services);
    }

    internal static string? Validate(OAuthServerOptions o)
    {
        if (!Uri.TryCreate(o.Issuer, UriKind.Absolute, out var issuer) || (issuer.Scheme != Uri.UriSchemeHttps && !RedirectUriRules.IsLoopbackHost(issuer.Host)) || issuer.Query.Length > 0 || issuer.Fragment.Length > 0)
            return "Issuer must be an absolute https URL (http only for loopback) without query or fragment.";
        if (o.ProtectedResources.Count == 0) return "At least one protected resource is required.";
        if (o.ProtectedResources.Any(r => !Uri.TryCreate(r, UriKind.Absolute, out var u) || u.Fragment.Length > 0)) return "Protected resources must be absolute URLs without a fragment.";
        if (o.Scopes.Count == 0) return "At least one scope is required.";
        if (o.DefaultScopes.Any(s => o.Scopes.Find(s) is null)) return "DefaultScopes must be registered scopes.";
        if (string.IsNullOrEmpty(o.ConsentPath)) return "ConsentPath is required.";
        if (o.AccessTokenLifetime <= TimeSpan.Zero || o.RefreshTokenLifetime <= TimeSpan.Zero || o.AuthorizationCodeLifetime <= TimeSpan.Zero
            || o.PendingRequestLifetime <= TimeSpan.Zero || o.RefreshRotationGrace < TimeSpan.Zero) return "Lifetimes must be positive.";
        foreach (var c in o.Clients)
        {
            if (string.IsNullOrEmpty(c.ClientId) || c.RedirectUris.Count == 0 || c.RedirectUris.Any(u => !RedirectUriRules.IsAcceptable(u)))
                return $"Pre-registered client '{c.ClientId}' needs a client id and https or loopback redirect URIs.";
        }
        return null;
    }

    public static IOAuthServerBuilder UseClientStore<T>(this IOAuthServerBuilder b, ServiceLifetime lifetime = ServiceLifetime.Scoped) where T : class, IOAuthClientStore => Swap<IOAuthClientStore, T>(b, lifetime);
    public static IOAuthServerBuilder UsePendingRequestStore<T>(this IOAuthServerBuilder b, ServiceLifetime lifetime = ServiceLifetime.Scoped) where T : class, IOAuthPendingRequestStore => Swap<IOAuthPendingRequestStore, T>(b, lifetime);
    public static IOAuthServerBuilder UseCodeStore<T>(this IOAuthServerBuilder b, ServiceLifetime lifetime = ServiceLifetime.Scoped) where T : class, IOAuthCodeStore => Swap<IOAuthCodeStore, T>(b, lifetime);
    public static IOAuthServerBuilder UseRefreshTokenStore<T>(this IOAuthServerBuilder b, ServiceLifetime lifetime = ServiceLifetime.Scoped) where T : class, IOAuthRefreshTokenStore => Swap<IOAuthRefreshTokenStore, T>(b, lifetime);
    public static IOAuthServerBuilder UseGrantStore<T>(this IOAuthServerBuilder b, ServiceLifetime lifetime = ServiceLifetime.Scoped) where T : class, IOAuthGrantStore => Swap<IOAuthGrantStore, T>(b, lifetime);
    public static IOAuthServerBuilder UseClientMetadataFetcher<T>(this IOAuthServerBuilder b, ServiceLifetime lifetime = ServiceLifetime.Singleton) where T : class, IClientMetadataFetcher => Swap<IClientMetadataFetcher, T>(b, lifetime);

    private static IOAuthServerBuilder Swap<TService, TImpl>(IOAuthServerBuilder builder, ServiceLifetime lifetime)
        where TService : class where TImpl : class, TService
    {
        if (builder is null) throw new ArgumentNullException(nameof(builder));
        builder.Services.RemoveAll<TService>();
        builder.Services.Add(ServiceDescriptor.Describe(typeof(TService), typeof(TImpl), lifetime));
        return builder;
    }
}

internal sealed class OAuthServerOptionsValidator : IValidateOptions<OAuthServerOptions>
{
    public ValidateOptionsResult Validate(string? name, OAuthServerOptions options)
    {
        var problem = OAuthServerServiceCollectionExtensions.Validate(options);
        return problem is null ? ValidateOptionsResult.Success : ValidateOptionsResult.Fail(problem);
    }
}
