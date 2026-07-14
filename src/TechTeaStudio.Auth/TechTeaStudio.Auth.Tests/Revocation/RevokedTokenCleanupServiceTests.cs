using FluentAssertions;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using TechTeaStudio.Auth.Revocation;
using Xunit;

namespace TechTeaStudio.Auth.Tests.Revocation;

public class RevokedTokenCleanupServiceTests
{
    private sealed class ResolutionCounter
    {
        public int Count;
    }

    private sealed class CountingRevokedTokenStore : IRevokedTokenStore
    {
        public CountingRevokedTokenStore(ResolutionCounter counter) => counter.Count++;

        public Task<bool> IsRevokedAsync(string jti, CancellationToken cancellationToken = default) => Task.FromResult(false);
        public Task RevokeAsync(string jti, DateTimeOffset expiresAt, CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task<int> CleanupAsync(DateTimeOffset cutoff, CancellationToken cancellationToken = default) => Task.FromResult(0);
    }

    [Fact]
    public async Task ExecuteAsync_resolves_the_store_from_a_fresh_scope_on_every_tick()
    {
        var counter = new ResolutionCounter();
        var services = new ServiceCollection();
        services.AddSingleton(counter);
        services.AddScoped<IRevokedTokenStore, CountingRevokedTokenStore>();
        await using var provider = services.BuildServiceProvider(new ServiceProviderOptions
        {
            ValidateScopes = true,
            ValidateOnBuild = true,
        });

        var options = Options.Create(new AuthOptions
        {
            RefreshTokens = { CleanupInterval = TimeSpan.FromMilliseconds(20) },
        });
        var service = new RevokedTokenCleanupService(provider.GetRequiredService<IServiceScopeFactory>(), options);

        await service.StartAsync(CancellationToken.None);
        await Task.Delay(TimeSpan.FromMilliseconds(100));
        await service.StopAsync(CancellationToken.None);

        counter.Count.Should().BeGreaterThanOrEqualTo(2);
    }
}
