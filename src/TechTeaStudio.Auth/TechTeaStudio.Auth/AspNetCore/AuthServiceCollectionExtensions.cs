using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
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
/// password hasher, refresh-token store (in-memory), the cleanup background
/// service, JWT bearer authentication, authorization, and startup validation
/// of <see cref="AuthOptions"/>.
/// </summary>
public static class AuthServiceCollectionExtensions
{
    /// <summary>
    /// Wires the full TechTeaStudio.Auth stack onto <paramref name="services"/>.
    /// <paramref name="configuration"/> is read at the given <paramref name="sectionName"/>
    /// (default <c>"Auth"</c>) and may be tuned via <paramref name="configure"/>.
    /// </summary>
    public static IServiceCollection AddTechTeaStudioAuth(
        this IServiceCollection services,
        IConfiguration configuration,
        Action<AuthOptions>? configure = null,
        string sectionName = "Auth")
    {
        if (services is null) throw new ArgumentNullException(nameof(services));
        if (configuration is null) throw new ArgumentNullException(nameof(configuration));

        var builder = services.AddOptions<AuthOptions>()
            .Bind(configuration.GetSection(sectionName))
            .ValidateDataAnnotations();
        if (configure is not null)
            builder.Configure(configure);

        services.AddSingleton<IValidateOptions<AuthOptions>, AuthOptionsValidator>();
        services.AddHostedService<OptionsValidationHostedService<AuthOptions>>();

        services.TryAddCoreServices();
        services.AddTechTeaStudioJwtBearer();
        services.AddAuthorization(o => o.AddTechTeaStudioPolicies());
        services.AddTechTeaStudioAuthorizationHandlers();

        return services;
    }

    /// <summary>
    /// Registers the JWT provider, password hasher, and in-memory refresh-token
    /// stack without touching ASP.NET Core authentication. Useful for non-web
    /// hosts (background workers, console apps) that still need to issue tokens.
    /// </summary>
    public static IServiceCollection AddTechTeaStudioAuthCore(
        this IServiceCollection services,
        IConfiguration configuration,
        Action<AuthOptions>? configure = null,
        string sectionName = "Auth")
    {
        if (services is null) throw new ArgumentNullException(nameof(services));
        if (configuration is null) throw new ArgumentNullException(nameof(configuration));

        var builder = services.AddOptions<AuthOptions>()
            .Bind(configuration.GetSection(sectionName))
            .ValidateDataAnnotations();
        if (configure is not null)
            builder.Configure(configure);

        services.AddSingleton<IValidateOptions<AuthOptions>, AuthOptionsValidator>();
        services.AddHostedService<OptionsValidationHostedService<AuthOptions>>();
        services.TryAddCoreServices();
        return services;
    }

    private static void TryAddCoreServices(this IServiceCollection services)
    {
        services.AddSingleton<ITokenProvider, JwtTokenProvider>();
        services.AddSingleton<ITokenReader, JwtTokenReader>();
        services.AddSingleton<IPasswordHasher, Pbkdf2PasswordHasher>();
        services.AddSingleton<IRefreshTokenStore, InMemoryRefreshTokenStore>();
        services.AddSingleton<RefreshTokenService>();
        services.AddSingleton<ILoginAttemptTracker, InMemoryLoginAttemptTracker>();
        services.AddSingleton<IRevokedTokenStore, InMemoryRevokedTokenStore>();
        services.AddSingleton<IAuthAuditLogger>(NullAuthAuditLogger.Instance);
        services.AddTransient<SecurityHeadersMiddleware>();
        services.AddHostedService<RefreshTokenCleanupService>();
        services.AddHostedService<RevokedTokenCleanupService>();
    }

    private static void AddTechTeaStudioJwtBearer(this IServiceCollection services)
    {
        services.AddSingleton<IConfigureOptions<JwtBearerOptions>, ConfigureTechTeaStudioJwtBearer>();
        services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
            .AddJwtBearer();
    }
}

/// <summary>
/// Hooks the JwtBearer default scheme up to <see cref="AuthOptions"/>. Uses
/// <see cref="IOptionsMonitor{TOptions}"/> + an <c>IssuerSigningKeyResolver</c>
/// so that a signing-key rotation is picked up without restarting the host.
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

        options.TokenValidationParameters = JwtTokenProvider.BuildValidationParameters(snapshot);
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
