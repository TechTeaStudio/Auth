using FluentAssertions;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using TechTeaStudio.Auth.AspNetCore;
using Xunit;

namespace TechTeaStudio.Auth.Tests.AspNetCore;

public class SecurityHeadersMiddlewareTests
{
    [Fact]
    public async Task Adds_expected_headers_on_every_response()
    {
        using var host = await new HostBuilder()
            .ConfigureWebHost(web =>
            {
                web.UseTestServer();
                web.ConfigureServices(s =>
                {
                    s.AddTransient<SecurityHeadersMiddleware>();
                });
                web.Configure(app =>
                {
                    app.UseSecurityHeaders();
                    app.Run(ctx => ctx.Response.WriteAsync("ok"));
                });
            })
            .StartAsync();

        var client = host.GetTestClient();
        var r = await client.GetAsync("/");
        r.Headers.GetValues("X-Content-Type-Options").Should().Contain("nosniff");
        r.Headers.GetValues("X-Frame-Options").Should().Contain("DENY");
        r.Headers.GetValues("Referrer-Policy").Should().Contain("strict-origin-when-cross-origin");
        // X-XSS-Protection is intentionally omitted in v0.5+ — header is deprecated
        // and modern browsers ignore it. We rely on CSP / X-Frame-Options instead.
        r.Headers.Contains("X-XSS-Protection").Should().BeFalse();
    }
}
