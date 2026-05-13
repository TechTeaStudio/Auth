using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;

namespace TechTeaStudio.Auth.AspNetCore;

/// <summary>
/// Resolves <see cref="IOptions{TOptions}.Value"/> on startup so that any registered
/// <see cref="IValidateOptions{TOptions}"/> runs before the host accepts traffic.
/// Equivalent in spirit to <c>OptionsBuilder.ValidateOnStart()</c> from
/// <c>Microsoft.Extensions.Hosting</c>, but does not require that extra package.
/// </summary>
internal sealed class OptionsValidationHostedService<TOptions> : IHostedService
    where TOptions : class
{
    private readonly IOptions<TOptions> _options;

    public OptionsValidationHostedService(IOptions<TOptions> options) =>
        _options = options;

    public Task StartAsync(CancellationToken cancellationToken)
    {
        // Touching .Value runs every IValidateOptions<TOptions> registered.
        _ = _options.Value;
        return Task.CompletedTask;
    }

    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
}
