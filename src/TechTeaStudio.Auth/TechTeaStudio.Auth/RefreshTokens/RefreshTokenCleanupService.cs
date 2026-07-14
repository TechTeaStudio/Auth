using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using TechTeaStudio.Auth.Abstractions;

namespace TechTeaStudio.Auth.RefreshTokens;

/// <summary>
/// Background service that periodically removes expired refresh tokens from the
/// configured <see cref="IRefreshTokenStore"/>. Period is
/// <see cref="RefreshTokenOptions.CleanupInterval"/> (default 1h).
/// Exceptions are logged and swallowed — the service never crashes the host.
/// </summary>
/// <remarks>
/// Resolves <see cref="IRefreshTokenStore"/> from a fresh <see cref="IServiceScope"/>
/// on every tick instead of taking it as a constructor dependency — this service is
/// hosted as a singleton, and a directly-injected SCOPED store (e.g.
/// <c>EfCoreRefreshTokenStore&lt;TContext&gt;</c>) would either fail DI validation or
/// become a captive dependency pinned to one <c>DbContext</c> for the process lifetime.
/// </remarks>
public sealed class RefreshTokenCleanupService : BackgroundService
{
    private readonly IServiceScopeFactory _scopeFactory;
    private readonly AuthOptions _options;
    private readonly ILogger<RefreshTokenCleanupService>? _logger;

    public RefreshTokenCleanupService(
        IServiceScopeFactory scopeFactory,
        IOptions<AuthOptions> options,
        ILogger<RefreshTokenCleanupService>? logger = null)
    {
        _scopeFactory = scopeFactory ?? throw new ArgumentNullException(nameof(scopeFactory));
        _options = options?.Value ?? throw new ArgumentNullException(nameof(options));
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                using var scope = _scopeFactory.CreateScope();
                var store = scope.ServiceProvider.GetRequiredService<IRefreshTokenStore>();
                var removed = await store.CleanupExpiredAsync(DateTimeOffset.UtcNow, stoppingToken).ConfigureAwait(false);
                if (removed > 0)
                    _logger?.LogInformation("Cleaned up {Removed} expired refresh tokens.", removed);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                return;
            }
            catch (Exception ex)
            {
                _logger?.LogError(ex, "Refresh token cleanup failed.");
            }

            try
            {
                await Task.Delay(_options.RefreshTokens.CleanupInterval, stoppingToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                return;
            }
        }
    }
}
