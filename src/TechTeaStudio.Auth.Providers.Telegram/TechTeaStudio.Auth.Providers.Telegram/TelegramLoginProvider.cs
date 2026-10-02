using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using TechTeaStudio.Auth.OAuth;

namespace TechTeaStudio.Auth.Providers.Telegram;

/// <summary>
/// Telegram Login Widget sign-in behind the ordinary <see cref="IExternalAuthProvider"/> contract,
/// so a host wires it exactly like Google or GitHub and <c>ExternalLoginService</c> needs no idea
/// that this one is not OAuth.
///
/// <para><b>Two things differ from every OAuth sibling.</b> There is no code to exchange: the raw
/// credential IS the signed profile, already in the browser's hands. And there is no email at all -
/// Telegram never discloses one - so <see cref="ExternalLoginInfo.Email"/> is always null and every
/// first sign-in lands in the host's <c>RequiresRegistration</c> branch.</para>
/// </summary>
public sealed class TelegramLoginProvider : IExternalAuthProvider
{
    public const string ProviderName = "Telegram";
    public string Name => ProviderName;

    private readonly IOptionsMonitor<TelegramLoginOptions> _options;
    private readonly ILogger<TelegramLoginProvider>? _logger;
    private readonly Func<DateTimeOffset> _clock;

    public TelegramLoginProvider(
        IOptionsMonitor<TelegramLoginOptions> options,
        ILogger<TelegramLoginProvider>? logger = null,
        Func<DateTimeOffset>? clock = null)
    {
        _options = options;
        _logger = logger;
        _clock = clock ?? (() => DateTimeOffset.UtcNow);
    }

    public Task<ExternalLoginInfo?> ValidateAsync(string rawCredential, CancellationToken cancellationToken = default)
    {
        var opts = _options.CurrentValue;
        if (string.IsNullOrWhiteSpace(opts.BotToken))
        {
            _logger?.LogWarning("Telegram login not configured (missing BotToken)");
            return Task.FromResult<ExternalLoginInfo?>(null);
        }

        // Fail closed. The validator reads a zero window as "skip the freshness check", which is
        // a test convenience; from configuration ("00:00:00", a typo, a negative value) it would
        // make every captured payload a credential that never expires.
        if (opts.MaxAge <= TimeSpan.Zero)
        {
            _logger?.LogWarning("Telegram login refused: MaxAge must be positive, it is the only replay defence the payload has");
            return Task.FromResult<ExternalLoginInfo?>(null);
        }

        if (!TelegramLoginValidator.TryValidate(rawCredential, opts.BotToken, opts.MaxAge, _clock(), out var fields, out var failure))
        {
            // The payload itself is never logged: it is a valid credential for whoever holds it.
            _logger?.LogInformation("Telegram login payload rejected: {Failure}", failure);
            return Task.FromResult<ExternalLoginInfo?>(null);
        }

        if (!fields.TryGetValue("id", out var id) || string.IsNullOrWhiteSpace(id))
        {
            _logger?.LogInformation("Telegram login payload rejected: signed but carries no id");
            return Task.FromResult<ExternalLoginInfo?>(null);
        }

        var info = new ExternalLoginInfo(
            Provider: ProviderName,
            ProviderUserId: id,
            // Telegram discloses no address, ever. A host that requires one must invent it.
            Email: null,
            EmailVerified: false,
            DisplayName: DisplayNameOf(fields),
            AvatarUrl: Value(fields, "photo_url"),
            Extra: fields);

        return Task.FromResult<ExternalLoginInfo?>(info);
    }

    /// <summary>@username when there is one, otherwise the given plus family name. Telegram
    /// guarantees only <c>first_name</c>; the rest is optional and often absent.</summary>
    private static string? DisplayNameOf(IReadOnlyDictionary<string, string> fields)
    {
        var username = Value(fields, "username");
        if (username is not null) return username;

        var first = Value(fields, "first_name");
        var last = Value(fields, "last_name");
        return (first, last) switch
        {
            (not null, not null) => $"{first} {last}",
            (not null, null) => first,
            (null, not null) => last,
            _ => null,
        };
    }

    private static string? Value(IReadOnlyDictionary<string, string> fields, string key) =>
        fields.TryGetValue(key, out var value) && !string.IsNullOrWhiteSpace(value) ? value : null;
}
