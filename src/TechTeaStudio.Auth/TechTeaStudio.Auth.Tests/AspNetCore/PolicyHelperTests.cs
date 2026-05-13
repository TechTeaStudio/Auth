using System.Net;
using System.Net.Http.Headers;
using System.Security.Claims;
using FluentAssertions;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using TechTeaStudio.Auth.Abstractions;
using TechTeaStudio.Auth.AspNetCore;
using TechTeaStudio.Auth.AspNetCore.Authorization;
using Xunit;

namespace TechTeaStudio.Auth.Tests.AspNetCore;

public class PolicyHelperTests
{
    private static async Task<IHost> StartHostAsync()
    {
        return await new HostBuilder()
            .ConfigureWebHost(web =>
            {
                web.UseTestServer();
                web.ConfigureAppConfiguration(c => c.AddInMemoryCollection(new Dictionary<string, string?>
                {
                    ["Auth:Jwt:SecretKey"] = "test-key-that-is-32-characters!!",
                    ["Auth:Jwt:Issuer"] = "tts",
                    ["Auth:Jwt:Audience"] = "tts",
                }));
                web.ConfigureServices((ctx, s) =>
                {
                    s.AddRouting();
                    s.AddTechTeaStudioAuth(ctx.Configuration);
                });
                web.Configure(app =>
                {
                    app.UseRouting();
                    app.UseAuthentication();
                    app.UseAuthorization();
                    app.UseEndpoints(e =>
                    {
                        e.MapGet("/email-verified", () => "ok")
                            .RequireAuthorization(AuthPolicies.EmailVerified);
                        e.MapGet("/require-subject", () => "ok")
                            .RequireAuthorization(AuthPolicies.RequireSubject);
                    });
                });
            })
            .StartAsync();
    }

    private static string IssueToken(IHost host, IEnumerable<Claim> claims)
    {
        var provider = host.Services.GetRequiredService<ITokenProvider>();
        return provider.CreateToken("u-1", claims, TimeSpan.FromMinutes(5));
    }

    [Fact]
    public async Task EmailVerified_policy_blocks_when_claim_missing()
    {
        using var host = await StartHostAsync();
        var client = host.GetTestClient();
        var token = IssueToken(host, new[] { new Claim(AuthClaims.Email, "u@x") });

        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
        var r = await client.GetAsync("/email-verified");
        r.StatusCode.Should().Be(HttpStatusCode.Forbidden);
    }

    [Fact]
    public async Task EmailVerified_policy_allows_when_claim_equals_true()
    {
        using var host = await StartHostAsync();
        var client = host.GetTestClient();
        var token = IssueToken(host, new[] { new Claim("email_verified", "true") });

        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
        var r = await client.GetAsync("/email-verified");
        r.StatusCode.Should().Be(HttpStatusCode.OK);
    }

    [Fact]
    public async Task RequireSubject_passes_for_any_authenticated_token()
    {
        using var host = await StartHostAsync();
        var client = host.GetTestClient();
        var token = IssueToken(host, Array.Empty<Claim>()); // sub is always written by JwtTokenProvider

        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
        var r = await client.GetAsync("/require-subject");
        r.StatusCode.Should().Be(HttpStatusCode.OK);
    }
}
