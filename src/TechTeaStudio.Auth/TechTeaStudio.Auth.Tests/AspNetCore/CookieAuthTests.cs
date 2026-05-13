using System.Net;
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
using TechTeaStudio.Auth.AspNetCore.Cookies;
using Xunit;

namespace TechTeaStudio.Auth.Tests.AspNetCore;

public class CookieAuthTests
{
    [Fact]
    public async Task Api_endpoint_returns_json_401_instead_of_redirect()
    {
        using var host = await new HostBuilder()
            .ConfigureWebHost(web =>
            {
                web.UseTestServer();
                web.ConfigureServices(s =>
                {
                    s.AddRouting();
                    s.AddAuthentication(TechTeaStudioCookieDefaults.SchemeName).AddTechTeaStudioCookieAuth();
                    s.AddAuthorization(o => o.DefaultPolicy = new AuthorizationPolicyBuilder()
                        .AddAuthenticationSchemes(TechTeaStudioCookieDefaults.SchemeName)
                        .RequireAuthenticatedUser()
                        .Build());
                });
                web.Configure(app =>
                {
                    app.UseRouting();
                    app.UseAuthentication();
                    app.UseAuthorization();
                    app.UseEndpoints(e => e.MapGet("/api/secret", () => "ok").RequireAuthorization());
                });
            })
            .StartAsync();

        var r = await host.GetTestClient().GetAsync("/api/secret");
        r.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
        r.Content.Headers.ContentType!.MediaType.Should().Be("application/json");
    }
}
