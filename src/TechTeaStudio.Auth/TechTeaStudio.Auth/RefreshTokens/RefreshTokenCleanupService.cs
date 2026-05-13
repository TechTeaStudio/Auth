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
public sealed class RefreshTokenCleanupService : BackgroundService
{
    private readonly IRefreshTokenStore _store;
    private readonly AuthOptions _options;
    private readonly ILogger<RefreshTokenCleanupService>? _logger;

    public RefreshTokenCleanupService(
        IRefreshTokenStore store,
        IOptions<AuthOptions> options,
        ILogger<RefreshTokenCleanupService>? logger = null)
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
                var removed = await _store.CleanupExpiredAsync(DateTimeOffset.UtcNow, stoppingToken).ConfigureAwait(false);
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
