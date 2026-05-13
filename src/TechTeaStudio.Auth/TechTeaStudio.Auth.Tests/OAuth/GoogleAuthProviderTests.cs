using FluentAssertions;
using Microsoft.Extensions.Options;
using TechTeaStudio.Auth.OAuth.Google;
using Xunit;

namespace TechTeaStudio.Auth.Tests.OAuth;

public class GoogleAuthProviderTests
{
    private static GoogleAuthProvider NewProvider(IList<string>? audiences = null)
    {
        var opts = new GoogleAuthProviderOptions
        {
            Audiences = audiences ?? new List<string>(),
        };
        IOptionsMonitor<GoogleAuthProviderOptions> monitor = new TestMonitor(opts);
        return new GoogleAuthProvider(monitor);
    }

    [Fact]
    public void Provider_name_is_stable_constant()
    {
        GoogleAuthProvider.ProviderName.Should().Be("Google");
        NewProvider().Name.Should().Be("Google");
    }

    [Fact]
    public async Task ValidateAsync_returns_null_for_empty_token()
    {
        var p = NewProvider(new[] { "any-client-id" });
        (await p.ValidateAsync("")).Should().BeNull();
    }

    [Fact]
    public async Task ValidateAsync_returns_null_when_no_audiences_configured()
    {
        var p = NewProvider();   // no audiences
        (await p.ValidateAsync("some-token")).Should().BeNull();
    }

    [Fact]
    public async Task ValidateAsync_returns_null_for_garbage_token()
    {
        var p = NewProvider(new[] { "test.apps.googleusercontent.com" });
        (await p.ValidateAsync("not-a-jwt-at-all")).Should().BeNull();
    }

    // Note: full happy-path testing of Google.Apis.Auth.ValidateAsync requires
    // a real Google-signed ID token. We trust their library for the signature
    // check; this suite only verifies our error-path normalization.

    private sealed class TestMonitor : IOptionsMonitor<GoogleAuthProviderOptions>
    {
        private readonly GoogleAuthProviderOptions _value;
        public TestMonitor(GoogleAuthProviderOptions value) => _value = value;
        public GoogleAuthProviderOptions CurrentValue => _value;
        public GoogleAuthProviderOptions Get(string? name) => _value;
        public IDisposable? OnChange(Action<GoogleAuthProviderOptions, string?> listener) => null;
    }
}
