using System.Net;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Text.Json;
using FluentAssertions;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;
using TechTeaStudio.Auth.Abstractions;
using TechTeaStudio.Auth.AspNetCore;
using Xunit;

namespace TechTeaStudio.Auth.Tests.AspNetCore;

public class AddTechTeaStudioAuthIntegrationTests
{
    private static async Task<IHost> StartHostAsync(Action<AuthOptions>? configure = null)
    {
        var host = await new HostBuilder()
            .ConfigureWebHost(web =>
            {
                web.UseTestServer();
                web.ConfigureAppConfiguration(c =>
                {
                    c.AddInMemoryCollection(new Dictionary<string, string?>
                    {
                        ["Auth:SecretKey"] = "test-key-that-is-32-characters!!",
                        ["Auth:Issuer"] = "tts-it",
                        ["Auth:Audience"] = "tts-it",
                    });
                });
                web.ConfigureServices((ctx, services) =>
                {
                    services.AddRouting();
                    services.AddTechTeaStudioAuth(ctx.Configuration, configure);
                });
                web.Configure(app =>
                {
                    app.UseRouting();
                    app.UseAuthentication();
                    app.UseAuthorization();
                    app.UseEndpoints(endpoints =>
                    {
                        endpoints.MapGet("/secret",
                            (HttpContext ctx) => ctx.User.Identity?.Name ?? string.Empty)
                            .RequireAuthorization();
                        endpoints.MapGet("/open", () => "hi");
                    });
                });
            })
            .StartAsync();
        return host;
    }

    private static string IssueToken(IHost host, string userId = "u-1")
    {
        var provider = host.Services.GetRequiredService<ITokenProvider>();
        return provider.CreateToken(userId, new[] { new Claim(AuthClaims.Username, userId) }, TimeSpan.FromMinutes(5));
    }

    [Fact]
    public async Task Open_endpoint_returns_200_without_token()
    {
        using var host = await StartHostAsync();
        var client = host.GetTestClient();
        var r = await client.GetAsync("/open");
        r.StatusCode.Should().Be(HttpStatusCode.OK);
    }

    [Fact]
    public async Task Protected_endpoint_returns_401_json_without_token()
    {
        using var host = await StartHostAsync();
        var client = host.GetTestClient();

        var r = await client.GetAsync("/secret");
        r.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
        r.Content.Headers.ContentType!.MediaType.Should().Be("application/json");

        var body = await r.Content.ReadAsStringAsync();
        var doc = JsonDocument.Parse(body);
        doc.RootElement.GetProperty("error").GetString().Should().Be(AuthErrorCodes.MissingToken);
        doc.RootElement.GetProperty("traceId").GetString().Should().NotBeNullOrEmpty();
    }

    [Fact]
    public async Task Protected_endpoint_returns_200_with_valid_token()
    {
        using var host = await StartHostAsync();
        var client = host.GetTestClient();
        var token = IssueToken(host, "alice");

        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
        var r = await client.GetAsync("/secret");
        r.StatusCode.Should().Be(HttpStatusCode.OK);

        var body = await r.Content.ReadAsStringAsync();
        body.Should().Contain("alice");
    }

    [Fact]
    public async Task Bad_signature_yields_invalid_signature_code()
    {
        using var host = await StartHostAsync();
        var client = host.GetTestClient();
        var token = IssueToken(host);

        // Forge signature
        var parts = token.Split('.');
        parts[2] = new string('A', parts[2].Length);
        var tampered = string.Join('.', parts);

        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", tampered);
        var r = await client.GetAsync("/secret");
        r.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
        var body = await r.Content.ReadAsStringAsync();
        var doc = JsonDocument.Parse(body);
        doc.RootElement.GetProperty("error").GetString().Should().Be(AuthErrorCodes.InvalidSignature);
    }

    [Fact]
    public async Task Malformed_token_yields_unauthorized_code()
    {
        using var host = await StartHostAsync();
        var client = host.GetTestClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", "not-a-jwt");
        var r = await client.GetAsync("/secret");
        r.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
        var body = await r.Content.ReadAsStringAsync();
        var doc = JsonDocument.Parse(body);
        doc.RootElement.GetProperty("error").GetString().Should().NotBeNullOrEmpty();
    }

    [Fact]
    public async Task Startup_fails_when_secret_key_invalid()
    {
        var act = async () =>
        {
            using var host = await new HostBuilder()
                .ConfigureWebHost(web =>
                {
                    web.UseTestServer();
                    web.ConfigureAppConfiguration(c =>
                    {
                        c.AddInMemoryCollection(new Dictionary<string, string?>
                        {
                            ["Auth:SecretKey"] = "short",
                            ["Auth:Issuer"] = "tts",
                            ["Auth:Audience"] = "tts",
                        });
                    });
                    web.ConfigureServices((ctx, services) =>
                    {
                        services.AddRouting();
                        services.AddTechTeaStudioAuth(ctx.Configuration);
                    });
                    web.Configure(app => { });
                })
                .StartAsync();
        };
        await act.Should().ThrowAsync<OptionsValidationException>();
    }
}
