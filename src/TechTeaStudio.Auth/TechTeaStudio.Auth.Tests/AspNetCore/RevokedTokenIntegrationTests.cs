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
using TechTeaStudio.Auth.Revocation;
using Xunit;

namespace TechTeaStudio.Auth.Tests.AspNetCore;

public class RevokedTokenIntegrationTests
{
    [Fact]
    public async Task Revoked_jti_returns_401_on_protected_endpoint()
    {
        using var host = await new HostBuilder()
            .ConfigureWebHost(web =>
            {
                web.UseTestServer();
                web.ConfigureAppConfiguration(c => c.AddInMemoryCollection(new Dictionary<string, string?>
                {
                    ["Auth:SecretKey"] = "test-key-that-is-32-characters!!",
                    ["Auth:Issuer"] = "tts",
                    ["Auth:Audience"] = "tts",
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
                    app.UseEndpoints(e => e.MapGet("/secret", () => "ok").RequireAuthorization());
                });
            })
            .StartAsync();

        var client = host.GetTestClient();
        var provider = host.Services.GetRequiredService<ITokenProvider>();
        var token = provider.CreateToken("u", new[] { new Claim(AuthClaims.Username, "u") }, TimeSpan.FromMinutes(5));

        // Extract jti from the issued token.
        var jwt = new System.IdentityModel.Tokens.Jwt.JwtSecurityTokenHandler().ReadJwtToken(token);
        var jti = jwt.Claims.First(c => c.Type == AuthClaims.JwtId).Value;

        // Add it to the deny-list.
        var revStore = host.Services.GetRequiredService<IRevokedTokenStore>();
        await revStore.RevokeAsync(jti, jwt.ValidTo);

        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
        var r = await client.GetAsync("/secret");
        r.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
    }
}
