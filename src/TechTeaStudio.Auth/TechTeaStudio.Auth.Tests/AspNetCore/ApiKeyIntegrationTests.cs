using System.Net;
using System.Net.Http.Headers;
using FluentAssertions;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using TechTeaStudio.Auth.AspNetCore.ApiKey;
using Xunit;

namespace TechTeaStudio.Auth.Tests.AspNetCore;

public class ApiKeyIntegrationTests
{
    private static async Task<IHost> StartHostAsync()
    {
        return await new HostBuilder()
            .ConfigureWebHost(web =>
            {
                web.UseTestServer();
                web.ConfigureServices(s =>
                {
                    s.AddRouting();
                    s.AddSingleton<IApiKeyStore>(new FuncApiKeyStore((key, _) =>
                        Task.FromResult(key == "let-me-in"
                            ? new ApiKeyValidationResult(true, "robot-1")
                            : new ApiKeyValidationResult(false, null))));
                    s.AddAuthentication(ApiKeyAuthenticationHandler.SchemeName)
                        .AddTechTeaStudioApiKey();
                    s.AddAuthorization(o => o.DefaultPolicy = new AuthorizationPolicyBuilder()
                        .AddAuthenticationSchemes(ApiKeyAuthenticationHandler.SchemeName)
                        .RequireAuthenticatedUser()
                        .Build());
                });
                web.Configure(app =>
                {
                    app.UseRouting();
                    app.UseAuthentication();
                    app.UseAuthorization();
                    app.UseEndpoints(e => e.MapGet("/api/robot", () => "ok").RequireAuthorization());
                });
            })
            .StartAsync();
    }

    [Fact]
    public async Task Missing_key_returns_401()
    {
        using var host = await StartHostAsync();
        var r = await host.GetTestClient().GetAsync("/api/robot");
        r.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
    }

    [Fact]
    public async Task Wrong_key_returns_401()
    {
        using var host = await StartHostAsync();
        var c = host.GetTestClient();
        c.DefaultRequestHeaders.Add("X-Api-Key", "nope");
        var r = await c.GetAsync("/api/robot");
        r.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
    }

    [Fact]
    public async Task Valid_key_in_header_returns_200()
    {
        using var host = await StartHostAsync();
        var c = host.GetTestClient();
        c.DefaultRequestHeaders.Add("X-Api-Key", "let-me-in");
        var r = await c.GetAsync("/api/robot");
        r.StatusCode.Should().Be(HttpStatusCode.OK);
    }

    [Fact]
    public async Task Valid_key_in_Authorization_ApiKey_returns_200()
    {
        using var host = await StartHostAsync();
        var c = host.GetTestClient();
        c.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("ApiKey", "let-me-in");
        var r = await c.GetAsync("/api/robot");
        r.StatusCode.Should().Be(HttpStatusCode.OK);
    }
}
