using FluentAssertions;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using TechTeaStudio.Auth.Abstractions;
using TechTeaStudio.Auth.AspNetCore;
using TechTeaStudio.Auth.RefreshTokens;
using TechTeaStudio.Auth.Revocation;
using Xunit;

namespace TechTeaStudio.Auth.Tests.AspNetCore;

/// <summary>
/// Guards against captive-dependency regressions: a consumer swapping in a
/// SCOPED <see cref="IRefreshTokenStore"/> (e.g. <c>EfCoreRefreshTokenStore&lt;TContext&gt;</c>)
/// must not poison a singleton <see cref="RefreshTokenService"/> or the
/// background cleanup services with a captured scoped instance.
/// </summary>
public class AuthServiceCollectionExtensionsLifetimeTests
{
    private sealed class FakeScopedRefreshTokenStore : IRefreshTokenStore
    {
        public Task<RefreshToken?> GetByTokenHashAsync(string tokenHash, CancellationToken cancellationToken = default) =>
            Task.FromResult<RefreshToken?>(null);
        public Task<IReadOnlyList<RefreshToken>> GetActiveForUserAsync(string userId, CancellationToken cancellationToken = default) =>
            Task.FromResult<IReadOnlyList<RefreshToken>>(Array.Empty<RefreshToken>());
        public Task CreateAsync(RefreshToken token, CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task<bool> RevokeAsync(Guid id, string? replacedByTokenHash = null, CancellationToken cancellationToken = default) => Task.FromResult(true);
        public Task RevokeAllForUserAsync(string userId, CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task<int> RevokeFamilyAsync(Guid familyId, CancellationToken cancellationToken = default) => Task.FromResult(0);
        public Task<int> CleanupExpiredAsync(DateTimeOffset cutoff, CancellationToken cancellationToken = default) => Task.FromResult(0);
        public Task DeleteAllForUserAsync(string userId, CancellationToken cancellationToken = default) => Task.CompletedTask;
    }

    private static IServiceCollection BuildServices()
    {
        var config = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["Auth:Jwt:SecretKey"] = "test-key-that-is-32-characters!!",
            ["Auth:Jwt:Issuer"] = "tts-lifetime",
            ["Auth:Jwt:Audience"] = "tts-lifetime",
        }).Build();

        var services = new ServiceCollection();
        services.AddTechTeaStudioAuthCore(config).UseRefreshTokenStore<FakeScopedRefreshTokenStore>();
        return services;
    }

    [Fact]
    public void BuildServiceProvider_does_not_throw_when_refresh_token_store_is_scoped()
    {
        var services = BuildServices();

        var act = () => services.BuildServiceProvider(new ServiceProviderOptions
        {
            ValidateScopes = true,
            ValidateOnBuild = true,
        });

        act.Should().NotThrow();
    }

    [Fact]
    public void RefreshTokenService_resolves_inside_a_scope()
    {
        var services = BuildServices();
        using var provider = services.BuildServiceProvider(new ServiceProviderOptions
        {
            ValidateScopes = true,
            ValidateOnBuild = true,
        });

        using var scope = provider.CreateScope();
        scope.ServiceProvider.GetRequiredService<RefreshTokenService>().Should().NotBeNull();
    }

    [Fact]
    public void Cleanup_hosted_services_construct_without_a_scope()
    {
        var services = BuildServices();
        using var provider = services.BuildServiceProvider(new ServiceProviderOptions
        {
            ValidateScopes = true,
            ValidateOnBuild = true,
        });

        var hosted = provider.GetServices<IHostedService>().ToList();
        hosted.Should().Contain(s => s is RefreshTokenCleanupService);
        hosted.Should().Contain(s => s is RevokedTokenCleanupService);
    }
}
