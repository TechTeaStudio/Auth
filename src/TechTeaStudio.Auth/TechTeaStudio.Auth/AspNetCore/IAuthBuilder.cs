using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using TechTeaStudio.Auth.Abstractions;
using TechTeaStudio.Auth.Lockout;
using TechTeaStudio.Auth.Observability;
using TechTeaStudio.Auth.RefreshTokens;
using TechTeaStudio.Auth.Revocation;

namespace TechTeaStudio.Auth.AspNetCore;

/// <summary>
/// Fluent surface returned by <c>AddTechTeaStudioAuth(...)</c>. Every
/// substitutable component (refresh store, lockout tracker, deny-list, audit
/// sink, claims resolver) is overridden through a <c>Use*</c> extension on this
/// builder. Sibling packages (<c>TechTeaStudio.Auth.EFCore</c>,
/// <c>TechTeaStudio.Auth.Redis</c>, …) ship their own <c>Use*</c> extensions.
/// </summary>
public interface IAuthBuilder
{
    /// <summary>The underlying service collection. Use this to register unrelated services.</summary>
    IServiceCollection Services { get; }
}

internal sealed class AuthBuilder : IAuthBuilder
{
    public AuthBuilder(IServiceCollection services) => Services = services;
    public IServiceCollection Services { get; }
}

/// <summary>
/// Built-in <c>Use*</c> overrides on <see cref="IAuthBuilder"/>. Each removes
/// the default in-memory registration and registers the supplied implementation
/// with the given lifetime — the only correct way to swap a default.
/// </summary>
public static class AuthBuilderExtensions
{
    /// <summary>Replaces the default refresh-token store. Use this from sibling packages (EFCore / Redis).</summary>
    public static IAuthBuilder UseRefreshTokenStore<TStore>(this IAuthBuilder builder, ServiceLifetime lifetime = ServiceLifetime.Scoped)
        where TStore : class, IRefreshTokenStore
    {
        if (builder is null) throw new ArgumentNullException(nameof(builder));
        builder.Services.RemoveAll<IRefreshTokenStore>();
        builder.Services.Add(ServiceDescriptor.Describe(typeof(IRefreshTokenStore), typeof(TStore), lifetime));
        return builder;
    }

    /// <summary>Replaces the default login-attempt tracker.</summary>
    public static IAuthBuilder UseLoginAttemptTracker<TTracker>(this IAuthBuilder builder, ServiceLifetime lifetime = ServiceLifetime.Singleton)
        where TTracker : class, ILoginAttemptTracker
    {
        if (builder is null) throw new ArgumentNullException(nameof(builder));
        builder.Services.RemoveAll<ILoginAttemptTracker>();
        builder.Services.Add(ServiceDescriptor.Describe(typeof(ILoginAttemptTracker), typeof(TTracker), lifetime));
        return builder;
    }

    /// <summary>Replaces the default revoked-token deny-list.</summary>
    public static IAuthBuilder UseRevokedTokenStore<TStore>(this IAuthBuilder builder, ServiceLifetime lifetime = ServiceLifetime.Singleton)
        where TStore : class, IRevokedTokenStore
    {
        if (builder is null) throw new ArgumentNullException(nameof(builder));
        builder.Services.RemoveAll<IRevokedTokenStore>();
        builder.Services.Add(ServiceDescriptor.Describe(typeof(IRevokedTokenStore), typeof(TStore), lifetime));
        return builder;
    }

    /// <summary>Replaces the default audit logger (which is a no-op).</summary>
    public static IAuthBuilder UseAuthAuditLogger<TLogger>(this IAuthBuilder builder, ServiceLifetime lifetime = ServiceLifetime.Singleton)
        where TLogger : class, IAuthAuditLogger
    {
        if (builder is null) throw new ArgumentNullException(nameof(builder));
        builder.Services.RemoveAll<IAuthAuditLogger>();
        builder.Services.Add(ServiceDescriptor.Describe(typeof(IAuthAuditLogger), typeof(TLogger), lifetime));
        return builder;
    }

    /// <summary>Registers a claims resolver used by <see cref="RefreshTokenService.RotateAsync(string, System.Threading.CancellationToken)"/>.</summary>
    public static IAuthBuilder UseRefreshClaimsResolver<TResolver>(this IAuthBuilder builder, ServiceLifetime lifetime = ServiceLifetime.Scoped)
        where TResolver : class, IRefreshClaimsResolver
    {
        if (builder is null) throw new ArgumentNullException(nameof(builder));
        builder.Services.RemoveAll<IRefreshClaimsResolver>();
        builder.Services.Add(ServiceDescriptor.Describe(typeof(IRefreshClaimsResolver), typeof(TResolver), lifetime));
        return builder;
    }

    /// <summary>Registers an <see cref="IClaimsProfile"/> used by consumers building claim sets.</summary>
    public static IAuthBuilder UseClaimsProfile<TProfile>(this IAuthBuilder builder, ServiceLifetime lifetime = ServiceLifetime.Singleton)
        where TProfile : class, Profiles.IClaimsProfile
    {
        if (builder is null) throw new ArgumentNullException(nameof(builder));
        builder.Services.RemoveAll<Profiles.IClaimsProfile>();
        builder.Services.Add(ServiceDescriptor.Describe(typeof(Profiles.IClaimsProfile), typeof(TProfile), lifetime));
        return builder;
    }
}
