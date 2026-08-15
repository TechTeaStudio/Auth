using FluentAssertions;
using Microsoft.Extensions.Options;
using TechTeaStudio.Auth.Providers.Telegram;
using Xunit;

namespace TechTeaStudio.Auth.Tests.OAuth;

public class TelegramLoginValidatorTests
{
    private const string BotToken = "123456:AAH-test-bot-token-not-a-real-one";
    private static readonly DateTimeOffset Now = DateTimeOffset.FromUnixTimeSeconds(1_800_000_000);

    private static Dictionary<string, string> Payload(long? authDate = null) => new(StringComparer.Ordinal)
    {
        ["id"] = "424242",
        ["first_name"] = "Iaroslav",
        ["username"] = "ioannterrible",
        ["photo_url"] = "https://t.me/i/userpic/320/abc.jpg",
        ["auth_date"] = (authDate ?? Now.ToUnixTimeSeconds()).ToString(),
    };

    private static string QueryString(IReadOnlyDictionary<string, string> fields) =>
        string.Join("&", fields.Select(kv => $"{Uri.EscapeDataString(kv.Key)}={Uri.EscapeDataString(kv.Value)}"));

    private static string Signed(Dictionary<string, string> fields)
    {
        fields["hash"] = TelegramLoginValidator.Sign(fields, BotToken);
        return QueryString(fields);
    }

    [Fact]
    public void Signed_payload_validates()
    {
        var ok = TelegramLoginValidator.TryValidate(
            Signed(Payload()), BotToken, TimeSpan.FromMinutes(5), Now, out var fields, out var failure);

        ok.Should().BeTrue();
        failure.Should().Be(TelegramLoginFailure.None);
        fields["id"].Should().Be("424242");
        fields["username"].Should().Be("ioannterrible");
    }

    [Fact]
    public void Json_payload_from_the_onauth_callback_validates()
    {
        var fields = Payload();
        fields["hash"] = TelegramLoginValidator.Sign(fields, BotToken);
        var json = "{" + string.Join(",", fields.Select(kv => $"\"{kv.Key}\":\"{kv.Value}\"")) + "}";

        TelegramLoginValidator.TryValidate(json, BotToken, TimeSpan.FromMinutes(5), Now, out _, out var failure)
            .Should().BeTrue();
        failure.Should().Be(TelegramLoginFailure.None);
    }

    [Fact]
    public void Tampered_field_breaks_the_signature()
    {
        var fields = Payload();
        fields["hash"] = TelegramLoginValidator.Sign(fields, BotToken);
        // The whole point of the scheme: swap the identity after signing and it must not pass.
        fields["id"] = "999999";

        TelegramLoginValidator.TryValidate(
            QueryString(fields), BotToken, TimeSpan.FromMinutes(5), Now, out _, out var failure)
            .Should().BeFalse();
        failure.Should().Be(TelegramLoginFailure.BadSignature);
    }

    [Fact]
    public void Payload_signed_with_another_bot_token_is_refused()
    {
        var fields = Payload();
        fields["hash"] = TelegramLoginValidator.Sign(fields, "999999:some-other-bot");

        TelegramLoginValidator.TryValidate(
            QueryString(fields), BotToken, TimeSpan.FromMinutes(5), Now, out _, out var failure)
            .Should().BeFalse();
        failure.Should().Be(TelegramLoginFailure.BadSignature);
    }

    [Fact]
    public void Stale_payload_is_refused_even_though_the_signature_is_valid()
    {
        var stale = Signed(Payload(Now.AddMinutes(-30).ToUnixTimeSeconds()));

        TelegramLoginValidator.TryValidate(stale, BotToken, TimeSpan.FromMinutes(5), Now, out _, out var failure)
            .Should().BeFalse();
        failure.Should().Be(TelegramLoginFailure.Expired);
    }

    [Fact]
    public void Payload_from_the_future_is_refused()
    {
        var ahead = Signed(Payload(Now.AddMinutes(30).ToUnixTimeSeconds()));

        TelegramLoginValidator.TryValidate(ahead, BotToken, TimeSpan.FromMinutes(5), Now, out _, out var failure)
            .Should().BeFalse();
        failure.Should().Be(TelegramLoginFailure.Expired);
    }

    [Fact]
    public void Missing_hash_is_refused()
    {
        TelegramLoginValidator.TryValidate(
            QueryString(Payload()), BotToken, TimeSpan.FromMinutes(5), Now, out _, out var failure)
            .Should().BeFalse();
        failure.Should().Be(TelegramLoginFailure.MissingHash);
    }

    [Fact]
    public void Garbage_is_refused_without_throwing()
    {
        TelegramLoginValidator.TryValidate("not a payload", BotToken, TimeSpan.FromMinutes(5), Now, out _, out var failure)
            .Should().BeFalse();
        failure.Should().Be(TelegramLoginFailure.Malformed);
    }

    [Fact]
    public void Extra_unknown_fields_are_part_of_the_signature()
    {
        // Telegram may add fields; they must sign and verify without this library knowing them.
        var fields = Payload();
        fields["last_name"] = "Ulantikov";
        fields["some_future_field"] = "42";
        var raw = Signed(fields);

        TelegramLoginValidator.TryValidate(raw, BotToken, TimeSpan.FromMinutes(5), Now, out var parsed, out _)
            .Should().BeTrue();
        parsed["some_future_field"].Should().Be("42");
    }
}

public class TelegramLoginProviderTests
{
    private const string BotToken = "123456:AAH-test-bot-token-not-a-real-one";
    private static readonly DateTimeOffset Now = DateTimeOffset.FromUnixTimeSeconds(1_800_000_000);

    private sealed class Monitor : IOptionsMonitor<TelegramLoginOptions>
    {
        public TelegramLoginOptions Current { get; set; } = new();
        public TelegramLoginOptions CurrentValue => Current;
        public TelegramLoginOptions Get(string? _) => Current;
        public IDisposable? OnChange(Action<TelegramLoginOptions, string?> _) => null;
    }

    private static string SignedPayload()
    {
        var fields = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["id"] = "424242",
            ["first_name"] = "Iaroslav",
            ["username"] = "ioannterrible",
            ["photo_url"] = "https://t.me/i/userpic/320/abc.jpg",
            ["auth_date"] = Now.ToUnixTimeSeconds().ToString(),
        };
        fields["hash"] = TelegramLoginValidator.Sign(fields, BotToken);
        return string.Join("&", fields.Select(kv => $"{kv.Key}={Uri.EscapeDataString(kv.Value)}"));
    }

    private static TelegramLoginProvider Sut(TelegramLoginOptions options) =>
        new(new Monitor { Current = options }, logger: null, clock: () => Now);

    [Fact]
    public void Name_is_Telegram() =>
        Sut(new TelegramLoginOptions { BotToken = BotToken }).Name.Should().Be("Telegram");

    [Fact]
    public async Task Valid_payload_maps_onto_ExternalLoginInfo()
    {
        var info = await Sut(new TelegramLoginOptions { BotToken = BotToken }).ValidateAsync(SignedPayload());

        info.Should().NotBeNull();
        info!.Provider.Should().Be("Telegram");
        info.ProviderUserId.Should().Be("424242");
        info.DisplayName.Should().Be("ioannterrible");
        info.AvatarUrl.Should().Be("https://t.me/i/userpic/320/abc.jpg");
        // Telegram never discloses an address - the host has to cope with that, not guess one.
        info.Email.Should().BeNull();
        info.EmailVerified.Should().BeFalse();
    }

    [Fact]
    public async Task Unconfigured_bot_token_returns_null()
    {
        var info = await Sut(new TelegramLoginOptions { BotToken = null }).ValidateAsync(SignedPayload());
        info.Should().BeNull();
    }

    [Fact]
    public async Task Empty_payload_returns_null()
    {
        var info = await Sut(new TelegramLoginOptions { BotToken = BotToken }).ValidateAsync("");
        info.Should().BeNull();
    }
}
