using Microsoft.Extensions.Options;

namespace TechTeaStudio.Auth.Tests.TestHelpers;

internal static class TestAuthOptions
{
    public static AuthOptions Create(
        string secret = "this-is-a-test-signing-key-32ch!!",
        string issuer = "tts-tests",
        string audience = "tts-tests-aud") => new()
        {
            SecretKey = secret,
            Issuer = issuer,
            Audience = audience,
        };

    public static IOptions<AuthOptions> Wrap(AuthOptions? opts = null) =>
        Options.Create(opts ?? Create());
}
