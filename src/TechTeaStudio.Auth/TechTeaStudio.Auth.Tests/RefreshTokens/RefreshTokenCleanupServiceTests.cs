using FluentAssertions;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using TechTeaStudio.Auth.Abstractions;
using TechTeaStudio.Auth.RefreshTokens;
using Xunit;

namespace TechTeaStudio.Auth.Tests.RefreshTokens;

public class RefreshTokenCleanupServiceTests
{
    private sealed class ResolutionCounter
    {
        public int Count;
    }

    private sealed class CountingRefreshTokenStore : IRefreshTokenStore
    {
        public CountingRefreshTokenStore(ResolutionCounter counter) => counter.Count++;

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

    [Fact]
    public async Task ExecuteAsync_resolves_the_store_from_a_fresh_scope_on_every_tick()
    {
        var counter = new ResolutionCounter();
        var services = new ServiceCollection();
        services.AddSingleton(counter);
        services.AddScoped<IRefreshTokenStore, CountingRefreshTokenStore>();
        await using var provider = services.BuildServiceProvider(new ServiceProviderOptions
        {
            ValidateScopes = true,
            ValidateOnBuild = true,
        });

        var options = Options.Create(new AuthOptions
        {
            RefreshTokens = { CleanupInterval = TimeSpan.FromMilliseconds(20) },
        });
        var service = new RefreshTokenCleanupService(provider.GetRequiredService<IServiceScopeFactory>(), options);

        await service.StartAsync(CancellationToken.None);
        await Task.Delay(TimeSpan.FromMilliseconds(100));
        await service.StopAsync(CancellationToken.None);

        counter.Count.Should().BeGreaterThanOrEqualTo(2);
    }
}
