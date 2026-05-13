using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace TechTeaStudio.Auth.Revocation;

/// <summary>
/// Background worker that prunes expired entries from <see cref="IRevokedTokenStore"/>.
/// Period reuses <see cref="AuthOptions.RefreshTokenCleanupInterval"/> (default 1h)
/// to avoid yet another knob.
/// </summary>
public sealed class RevokedTokenCleanupService : BackgroundService
{
    private readonly IRevokedTokenStore _store;
    private readonly AuthOptions _options;
    private readonly ILogger<RevokedTokenCleanupService>? _logger;

    public RevokedTokenCleanupService(
        IRevokedTokenStore store,
        IOptions<AuthOptions> options,
        ILogger<RevokedTokenCleanupService>? logger = null)
    {
        _store = store ?? throw new ArgumentNullException(nameof(store));
        _options = options?.Value ?? throw new ArgumentNullException(nameof(options));
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                var removed = await _store.CleanupAsync(DateTimeOffset.UtcNow, stoppingToken).ConfigureAwait(false);
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
                await Task.Delay(_options.RefreshTokenCleanupInterval, stoppingToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException) { return; }
        }
    }
}
