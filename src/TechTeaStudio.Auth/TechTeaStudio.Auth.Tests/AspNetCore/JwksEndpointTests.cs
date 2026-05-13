using System.Net;
using System.Security.Cryptography;
using System.Text.Json;
using FluentAssertions;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using TechTeaStudio.Auth.AspNetCore;
using TechTeaStudio.Auth.AspNetCore.Jwks;
using TechTeaStudio.Auth.Signing;
using Xunit;

namespace TechTeaStudio.Auth.Tests.AspNetCore;

public class JwksEndpointTests
{
    [Fact]
    public async Task Endpoint_returns_RSA_key_excluding_HMAC()
    {
        using var rsa = RSA.Create(2048);
        var pem = rsa.ExportRSAPrivateKeyPem();

        using var host = await new HostBuilder()
            .ConfigureWebHost(web =>
            {
                web.UseTestServer();
                web.ConfigureAppConfiguration(c => c.AddInMemoryCollection(new Dictionary<string, string?>
                {
                    ["Auth:Jwt:Issuer"] = "tts",
                    ["Auth:Jwt:Audience"] = "tts",
                }));
                web.ConfigureServices((ctx, s) =>
                {
                    s.AddRouting();
                    s.AddTechTeaStudioAuth(ctx.Configuration, o =>
                    {
                        o.Jwt.Signing.ActiveKid = "rsa-1";
                        o.Jwt.Signing.Keys.Add(new SigningKeyDescriptor
                        {
                            Kid = "hmac-1",
                            Algorithm = SigningAlgorithm.HS256,
                            SymmetricKey = new string('s', 32),
                        });
                        o.Jwt.Signing.Keys.Add(new SigningKeyDescriptor
                        {
                            Kid = "rsa-1",
                            Algorithm = SigningAlgorithm.RS256,
                            PrivateKeyPem = pem,
                        });
                    });
                });
                web.Configure(app =>
                {
                    app.UseRouting();
                    app.UseAuthentication();
                    app.UseAuthorization();
                    app.UseEndpoints(e => e.MapTechTeaStudioJwks());
                });
            })
            .StartAsync();

        var client = host.GetTestClient();
        var r = await client.GetAsync("/.well-known/jwks.json");
        r.StatusCode.Should().Be(HttpStatusCode.OK);
        r.Content.Headers.ContentType!.MediaType.Should().Be("application/jwk-set+json");

        var body = await r.Content.ReadAsStringAsync();
        var doc = JsonDocument.Parse(body);
        var keys = doc.RootElement.GetProperty("keys").EnumerateArray().ToList();
        keys.Should().HaveCount(1);
        keys[0].GetProperty("kty").GetString().Should().Be("RSA");
        keys[0].GetProperty("kid").GetString().Should().Be("rsa-1");
        keys[0].GetProperty("alg").GetString().Should().Be("RS256");
    }
}
