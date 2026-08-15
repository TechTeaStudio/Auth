namespace TechTeaStudio.Auth.Providers.Telegram;

/// <summary>
/// Options for <see cref="TelegramLoginProvider"/>, bound from <c>Auth:Telegram</c> by default.
/// </summary>
public sealed class TelegramLoginOptions
{
    /// <summary>The bot token from BotFather. It is both the credential the widget is bound to and
    /// the HMAC key material, so a bot whose token was rotated invalidates every payload minted
    /// before the rotation.</summary>
    public string? BotToken { get; set; }

    /// <summary>The bot's @name without the @. Only the host's markup needs it (the widget's
    /// <c>data-telegram-login</c> attribute); the validator never reads it. Kept here so one
    /// section configures the whole feature.</summary>
    public string? BotUsername { get; set; }

    /// <summary>How old <c>auth_date</c> may be before the payload is refused. Telegram's payload
    /// has no nonce and no single-use marker, so this window IS the replay defence: a captured
    /// payload is a working credential until it expires.</summary>
    public TimeSpan MaxAge { get; set; } = TimeSpan.FromMinutes(5);
}
