using Microsoft.Extensions.Options;

namespace TechTeaStudio.Auth.Tests.TestHelpers;

internal static class TestAuthOptions
{
    public static AuthOptions Create(
        string secret = "this-is-a-test-signing-key-32ch!!",
        string issuer = "tts-tests",
        string audience = "tts-tests-aud") => new()
        {
            Jwt =
            {
                SecretKey = secret,
                Issuer = issuer,
                Audience = audience,
            },
        };

    public static IOptionsMonitor<AuthOptions> Wrap(AuthOptions? opts = null) =>
        new SnapshotMonitor(opts ?? Create());

    public static IOptions<AuthOptions> WrapOptions(AuthOptions? opts = null) =>
        Options.Create(opts ?? Create());

    public static IOptionsMonitor<AuthOptions> ToMonitor(this AuthOptions opts) =>
        new SnapshotMonitor(opts);

    private sealed class SnapshotMonitor : IOptionsMonitor<AuthOptions>
    {
        private readonly AuthOptions _value;
        public SnapshotMonitor(AuthOptions value) => _value = value;
        public AuthOptions CurrentValue => _value;
        public AuthOptions Get(string? name) => _value;
        public IDisposable? OnChange(Action<AuthOptions, string?> listener) => null;
    }
}
