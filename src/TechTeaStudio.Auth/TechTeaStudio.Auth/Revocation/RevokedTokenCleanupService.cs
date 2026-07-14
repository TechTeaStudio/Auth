using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace TechTeaStudio.Auth.Revocation;

/// <summary>
/// Background worker that prunes expired entries from <see cref="IRevokedTokenStore"/>.
/// Period reuses <see cref="RefreshTokenOptions.CleanupInterval"/> (default 1h)
/// to avoid yet another knob.
/// </summary>
/// <remarks>
/// Resolves <see cref="IRevokedTokenStore"/> from a fresh <see cref="IServiceScope"/>
/// on every tick instead of taking it as a constructor dependency — this service is
/// hosted as a singleton, and a directly-injected SCOPED store would either fail DI
/// validation or become a captive dependency pinned for the process lifetime.
/// </remarks>
public sealed class RevokedTokenCleanupService : BackgroundService
{
    private readonly IServiceScopeFactory _scopeFactory;
    private readonly AuthOptions _options;
    private readonly ILogger<RevokedTokenCleanupService>? _logger;

    public RevokedTokenCleanupService(
        IServiceScopeFactory scopeFactory,
        IOptions<AuthOptions> options,
        ILogger<RevokedTokenCleanupService>? logger = null)
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
                var store = scope.ServiceProvider.GetRequiredService<IRevokedTokenStore>();
                var removed = await store.CleanupAsync(DateTimeOffset.UtcNow, stoppingToken).ConfigureAwait(false);
                if (removed > 0)
                    _logger?.LogInformation("Cleaned up {Removed} revoked-token entries.", removed);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { return; }
            catch (Exception ex)
            {
                _logger?.LogError(ex, "Revoked-token cleanup failed.");
            }

            try
            {
                await Task.Delay(_options.RefreshTokens.CleanupInterval, stoppingToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException) { return; }
        }
    }
}
