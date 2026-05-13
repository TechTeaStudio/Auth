using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;
using TechTeaStudio.Auth.Abstractions;
using TechTeaStudio.Auth.AspNetCore.Authorization;
using TechTeaStudio.Auth.Jwt;
using TechTeaStudio.Auth.Lockout;
using TechTeaStudio.Auth.Observability;
using TechTeaStudio.Auth.Passwords;
using TechTeaStudio.Auth.RefreshTokens;
using TechTeaStudio.Auth.Revocation;
using TechTeaStudio.Auth.Signing;

namespace TechTeaStudio.Auth.AspNetCore;

/// <summary>
/// One-call DI bootstrap for TechTeaStudio.Auth. Registers the JWT provider,
/// password hasher, in-memory refresh-token / lockout / revocation defaults,
/// background cleanup services, JWT bearer authentication, authorization,
/// and startup validation of <see cref="AuthOptions"/>.
/// </summary>
/// <remarks>
/// All "store" / "tracker" / "logger" registrations are <c>TryAdd*</c> — if a
/// consumer registered their own implementation before this call, the
/// consumer's wins. The clean way to swap defaults is via the returned
/// <see cref="IAuthBuilder"/>: <c>services.AddTechTeaStudioAuth(cfg).UseRefreshTokenStore&lt;…&gt;()</c>.
/// </remarks>
public static class AuthServiceCollectionExtensions
{
    /// <summary>
    /// Wires the full TechTeaStudio.Auth stack onto <paramref name="services"/>.
    /// <paramref name="configuration"/> is read at the given <paramref name="sectionName"/>
    /// (default <c>"Auth"</c>) and may be tuned via <paramref name="configure"/>.
    /// </summary>
    public static IAuthBuilder AddTechTeaStudioAuth(
        this IServiceCollection services,
        IConfiguration configuration,
        Action<AuthOptions>? configure = null,
        string sectionName = "Auth")
    {
        if (services is null) throw new ArgumentNullException(nameof(services));
        if (configuration is null) throw new ArgumentNullException(nameof(configuration));

        var optsBuilder = services.AddOptions<AuthOptions>()
            .Bind(configuration.GetSection(sectionName))
            .ValidateDataAnnotations();
        if (configure is not null)
            optsBuilder.Configure(configure);

        services.TryAddEnumerable(ServiceDescriptor.Singleton<IValidateOptions<AuthOptions>, AuthOptionsValidator>());
        services.AddHostedService<OptionsValidationHostedService<AuthOptions>>();

        services.TryAddCoreServices();
        services.AddTechTeaStudioJwtBearer();
        services.AddAuthorization(o => o.AddTechTeaStudioPolicies());
        services.AddTechTeaStudioAuthorizationHandlers();

        return new AuthBuilder(services);
    }

    /// <summary>
    /// Registers the JWT provider, password hasher, and in-memory refresh-token
    /// stack without touching ASP.NET Core authentication. Useful for non-web
    /// hosts (background workers, console apps) that still need to issue tokens.
    /// </summary>
    public static IAuthBuilder AddTechTeaStudioAuthCore(
        this IServiceCollection services,
        IConfiguration configuration,
        Action<AuthOptions>? configure = null,
        string sectionName = "Auth")
    {
        if (services is null) throw new ArgumentNullException(nameof(services));
        if (configuration is null) throw new ArgumentNullException(nameof(configuration));

        var optsBuilder = services.AddOptions<AuthOptions>()
            .Bind(configuration.GetSection(sectionName))
            .ValidateDataAnnotations();
        if (configure is not null)
            optsBuilder.Configure(configure);

        services.TryAddEnumerable(ServiceDescriptor.Singleton<IValidateOptions<AuthOptions>, AuthOptionsValidator>());
        services.AddHostedService<OptionsValidationHostedService<AuthOptions>>();
        services.TryAddCoreServices();
        return new AuthBuilder(services);
    }

    private static void TryAddCoreServices(this IServiceCollection services)
    {
        services.TryAddSingleton<ITokenProvider, JwtTokenProvider>();
        services.TryAddSingleton<ITokenReader, JwtTokenReader>();
        services.TryAddSingleton<IPasswordHasher, Pbkdf2PasswordHasher>();
        services.TryAddSingleton<IRefreshTokenStore, InMemoryRefreshTokenStore>();
        services.TryAddSingleton<RefreshTokenService>();
        services.TryAddSingleton<IRefreshClaimsResolver>(NullRefreshClaimsResolver.Instance);
        services.TryAddSingleton<ILoginAttemptTracker, InMemoryLoginAttemptTracker>();
        services.TryAddSingleton<IRevokedTokenStore, InMemoryRevokedTokenStore>();
        services.TryAddSingleton<IAuthAuditLogger>(NullAuthAuditLogger.Instance);
        services.TryAddTransient<SecurityHeadersMiddleware>();

        // Hosted services do not de-dupe via TryAdd; guard manually.
        if (services.All(d => d.ImplementationType != typeof(RefreshTokenCleanupService)))
            services.AddHostedService<RefreshTokenCleanupService>();
        if (services.All(d => d.ImplementationType != typeof(RevokedTokenCleanupService)))
            services.AddHostedService<RevokedTokenCleanupService>();
    }

    private static void AddTechTeaStudioJwtBearer(this IServiceCollection services)
    {
        services.TryAddEnumerable(ServiceDescriptor.Singleton<IConfigureOptions<JwtBearerOptions>, ConfigureTechTeaStudioJwtBearer>());
        services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
            .AddJwtBearer();
    }
}

/// <summary>
/// Hooks the JwtBearer default scheme up to <see cref="AuthOptions"/>. Uses
/// <see cref="IOptionsMonitor{TOptions}"/> + an <c>IssuerSigningKeyResolver</c>
/// so a signing-key rotation is picked up without restarting the host.
/// </summary>
internal sealed class ConfigureTechTeaStudioJwtBearer : IConfigureNamedOptions<JwtBearerOptions>
{
    private readonly IOptionsMonitor<AuthOptions> _auth;
    private readonly IHostEnvironment? _env;

    public ConfigureTechTeaStudioJwtBearer(IOptionsMonitor<AuthOptions> auth, IHostEnvironment? env = null)
    {
        _auth = auth ?? throw new ArgumentNullException(nameof(auth));
        _env = env;
    }

    public void Configure(JwtBearerOptions options) =>
        Configure(JwtBearerDefaults.AuthenticationScheme, options);

    public void Configure(string? name, JwtBearerOptions options)
    {
        if (name != JwtBearerDefaults.AuthenticationScheme) return;

        var snapshot = _auth.CurrentValue;
        options.RequireHttpsMetadata = _env?.IsDevelopment() != true;
        options.SaveToken = true;
        options.MapInboundClaims = false;

        options.TokenValidationParameters = SigningKeyResolver.BuildValidationParameters(snapshot);
        // Refresh the key list on every request so IOptionsMonitor updates propagate.
        var monitor = _auth;
        options.TokenValidationParameters.IssuerSigningKeyResolver = (_, _, _, _) =>
            SigningKeyResolver.ResolveValidating(monitor.CurrentValue)
                .Select(SigningKeyResolver.BuildValidationKey);

        options.Events ??= new JwtBearerEvents();
        var inner = options.Events.OnChallenge;
        options.Events.OnChallenge = async ctx =>
        {
            if (inner is not null) await inner(ctx).ConfigureAwait(false);
            if (ctx.Handled) return;
            await JwtChallengeWriter.WriteAsync(ctx).ConfigureAwait(false);
        };

        var innerValidated = options.Events.OnTokenValidated;
        options.Events.OnTokenValidated = async ctx =>
        {
            if (innerValidated is not null) await innerValidated(ctx).ConfigureAwait(false);
            var store = ctx.HttpContext.RequestServices.GetService(typeof(IRevokedTokenStore)) as IRevokedTokenStore;
            if (store is null or NullRevokedTokenStore) return;

            var jti = ctx.Principal?.FindFirst(AuthClaims.JwtId)?.Value;
            if (string.IsNullOrEmpty(jti)) return;

            if (await store.IsRevokedAsync(jti, ctx.HttpContext.RequestAborted).ConfigureAwait(false))
                ctx.Fail("Token has been revoked.");
        };
    }
}
