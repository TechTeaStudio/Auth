using FluentAssertions;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using TechTeaStudio.Auth.OAuth.GitHub;
using Xunit;

namespace TechTeaStudio.Auth.Tests.OAuth;

public class GitHubAuthProviderTests
{
    private sealed class TestMonitor : IOptionsMonitor<GitHubAuthProviderOptions>
    {
        public GitHubAuthProviderOptions Current { get; set; } = new();
        public GitHubAuthProviderOptions CurrentValue => Current;
        public GitHubAuthProviderOptions Get(string? _) => Current;
        public IDisposable? OnChange(Action<GitHubAuthProviderOptions, string?> _) => null;
    }

    [Fact]
    public async Task ValidateAsync_EmptyCode_ReturnsNull()
    {
        var http = new HttpClient();
        var monitor = new TestMonitor { Current = new GitHubAuthProviderOptions { ClientId = "x", ClientSecret = "y" } };
        var sut = new GitHubAuthProvider(http, monitor, NullLogger<GitHubAuthProvider>.Instance);

        var result = await sut.ValidateAsync("");
        result.Should().BeNull();
    }

    [Fact]
    public async Task ValidateAsync_MissingClientId_ReturnsNull()
    {
        var http = new HttpClient();
        var monitor = new TestMonitor { Current = new GitHubAuthProviderOptions { ClientId = null, ClientSecret = "y" } };
        var sut = new GitHubAuthProvider(http, monitor);

        var result = await sut.ValidateAsync("abc");
        result.Should().BeNull();
    }

    [Fact]
    public async Task ValidateAsync_GarbageCode_ReturnsNull()
    {
        var http = new HttpClient();
        var monitor = new TestMonitor { Current = new GitHubAuthProviderOptions { ClientId = "bogus", ClientSecret = "bogus" } };
        var sut = new GitHubAuthProvider(http, monitor);

        var result = await sut.ValidateAsync("definitely-not-a-real-code");
        result.Should().BeNull();
    }

    [Fact]
    public void Name_IsGitHub()
    {
        var http = new HttpClient();
        var monitor = new TestMonitor();
        var sut = new GitHubAuthProvider(http, monitor);
        sut.Name.Should().Be("GitHub");
    }
}
