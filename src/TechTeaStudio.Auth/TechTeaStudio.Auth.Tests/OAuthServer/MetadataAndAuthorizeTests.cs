using System.Net;
using System.Text.Json;
using FluentAssertions;
using Xunit;
using TechTeaStudio.Auth.Observability;
using TechTeaStudio.Auth.OAuthServer;

namespace TechTeaStudio.Auth.Tests.OAuthServer;

public class MetadataTests
{
    [Fact]
    public async Task Metadata_document_has_the_required_fields()
    {
        await using var host = await OAuthTestHost.StartAsync();
        var r = await host.Client.GetAsync(OAuthServerPaths.Metadata);

        r.StatusCode.Should().Be(HttpStatusCode.OK);
        r.Headers.CacheControl!.MaxAge.Should().Be(TimeSpan.FromSeconds(300));
        var j = (await OAuthTestHost.ToResult(r)).Json;

        j.GetProperty("issuer").GetString().Should().Be(OAuthTestHost.Issuer);
        j.GetProperty("authorization_endpoint").GetString().Should().Be("https://auth.example.com/oauth/authorize");
        j.GetProperty("token_endpoint").GetString().Should().Be("https://auth.example.com/oauth/token");
        j.GetProperty("revocation_endpoint").GetString().Should().Be("https://auth.example.com/oauth/revoke");
        j.GetProperty("registration_endpoint").GetString().Should().Be("https://auth.example.com/oauth/register");
        j.GetProperty("response_types_supported").EnumerateArray().Select(x => x.GetString()).Should().Equal("code");
        j.GetProperty("grant_types_supported").EnumerateArray().Select(x => x.GetString()).Should().Equal("authorization_code", "refresh_token");
        j.GetProperty("code_challenge_methods_supported").EnumerateArray().Select(x => x.GetString()).Should().Equal("S256");
        j.GetProperty("scopes_supported").EnumerateArray().Select(x => x.GetString()).Should().Equal("tasks:read", "tasks:write");
        j.GetProperty("client_id_metadata_document_supported").GetBoolean().Should().BeTrue();
        j.GetProperty("authorization_response_iss_parameter_supported").GetBoolean().Should().BeTrue();
    }

    [Fact]
    public async Task Issuer_is_the_configured_value_not_the_request_host()
    {
        await using var host = await OAuthTestHost.StartAsync();
        using var req = new HttpRequestMessage(HttpMethod.Get, OAuthServerPaths.Metadata);
        req.Headers.Host = "evil.example.net";
        req.Headers.Add("X-Forwarded-Host", "evil.example.net");
        var j = (await OAuthTestHost.ToResult(await host.Client.SendAsync(req))).Json;
        j.GetProperty("issuer").GetString().Should().Be(OAuthTestHost.Issuer);
        j.GetProperty("token_endpoint").GetString().Should().StartWith(OAuthTestHost.Issuer);
    }

    [Fact]
    public async Task Auth_methods_include_client_secret_post_only_with_a_confidential_client()
    {
        await using var withSecret = await OAuthTestHost.StartAsync();
        var a = (await OAuthTestHost.ToResult(await withSecret.Client.GetAsync(OAuthServerPaths.Metadata))).Json;
        a.GetProperty("token_endpoint_auth_methods_supported").EnumerateArray().Select(x => x.GetString())
            .Should().Equal("none", "client_secret_post");

        await using var publicOnly = await OAuthTestHost.StartAsync(o => o.Clients.RemoveAll(c => c.ClientSecret != null));
        var b = (await OAuthTestHost.ToResult(await publicOnly.Client.GetAsync(OAuthServerPaths.Metadata))).Json;
        b.GetProperty("token_endpoint_auth_methods_supported").EnumerateArray().Select(x => x.GetString()).Should().Equal("none");
    }

    [Fact]
    public async Task Registration_endpoint_is_absent_when_dcr_is_off()
    {
        await using var host = await OAuthTestHost.StartAsync(o => o.EnableDynamicRegistration = false);
        var j = (await OAuthTestHost.ToResult(await host.Client.GetAsync(OAuthServerPaths.Metadata))).Json;
        j.TryGetProperty("registration_endpoint", out _).Should().BeFalse();
    }

    [Fact]
    public async Task Issuer_with_a_path_is_also_served_at_the_rfc8414_path_form()
    {
        await using var host = await OAuthTestHost.StartAsync(o => o.Issuer = "https://auth.example.com/tenant");
        var r = await host.Client.GetAsync(OAuthServerPaths.Metadata + "/tenant");
        r.StatusCode.Should().Be(HttpStatusCode.OK);
        (await OAuthTestHost.ToResult(r)).Json.GetProperty("token_endpoint").GetString().Should().Be("https://auth.example.com/tenant/oauth/token");
    }

    [Fact]
    public async Task Invalid_options_fail_at_startup()
    {
        var act = () => OAuthTestHost.StartAsync(o => o.ProtectedResources.Clear());
        await act.Should().ThrowAsync<Exception>();
    }
}

public class AuthorizeValidationTests
{
    [Fact]
    public async Task Valid_request_redirects_to_the_consent_path_with_a_request_id()
    {
        await using var host = await OAuthTestHost.StartAsync();
        var (_, challenge) = OAuthTestHost.NewPkce();
        var r = await host.AuthorizeAsync(OAuthTestHost.BaseQuery(challenge));

        r.StatusCode.Should().Be(HttpStatusCode.Found);
        r.Headers.Location!.OriginalString.Should().StartWith("/oauth/consent?request=");
        r.Headers.CacheControl!.NoStore.Should().BeTrue();
        OAuthTestHost.QueryOf(OAuthTestHost.Absolute(r))["request"].Length.Should().BeGreaterThan(30);
        host.Audit.Snapshot().OfType<OAuthAuthorizeRequestedEvent>().Should().ContainSingle();
    }

    [Fact]
    public async Task Unknown_client_is_a_400_and_never_a_redirect()
    {
        await using var host = await OAuthTestHost.StartAsync();
        var q = OAuthTestHost.BaseQuery(OAuthTestHost.NewPkce().Challenge, clientId: "nobody");
        var r = await host.AuthorizeAsync(q);
        r.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        r.Headers.Location.Should().BeNull();
    }

    [Theory]
    [InlineData("https://evil.example.com/cb")]
    [InlineData("https://claude.ai/api/mcp/auth_callback/extra")]
    [InlineData("https://claude.ai/api/mcp/auth_callback?x=1")]
    [InlineData("http://claude.ai/api/mcp/auth_callback")]
    [InlineData("")]
    public async Task Mismatched_redirect_is_a_400_and_never_a_redirect(string redirect)
    {
        await using var host = await OAuthTestHost.StartAsync();
        var q = OAuthTestHost.BaseQuery(OAuthTestHost.NewPkce().Challenge);
        q["redirect_uri"] = redirect;
        var r = await host.AuthorizeAsync(q);
        r.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        r.Headers.Location.Should().BeNull();
    }

    [Fact]
    public async Task Missing_client_id_or_redirect_is_a_400()
    {
        await using var host = await OAuthTestHost.StartAsync();
        var q = OAuthTestHost.BaseQuery(OAuthTestHost.NewPkce().Challenge);
        q.Remove("client_id");
        (await host.AuthorizeAsync(q)).StatusCode.Should().Be(HttpStatusCode.BadRequest);

        q = OAuthTestHost.BaseQuery(OAuthTestHost.NewPkce().Challenge);
        q.Remove("redirect_uri");
        (await host.AuthorizeAsync(q)).StatusCode.Should().Be(HttpStatusCode.BadRequest);
    }

    [Fact]
    public async Task Duplicate_client_id_is_a_400()
    {
        await using var host = await OAuthTestHost.StartAsync();
        var q = OAuthTestHost.BaseQuery(OAuthTestHost.NewPkce().Challenge);
        var r = await host.Client.GetAsync(OAuthServerPaths.Authorize + OAuthTestHost.Qs(q) + "&client_id=other");
        r.StatusCode.Should().Be(HttpStatusCode.BadRequest);
    }

    [Theory]
    [InlineData("code_challenge", null, "invalid_request")]
    [InlineData("code_challenge", "short", "invalid_request")]
    [InlineData("code_challenge_method", "plain", "invalid_request")]
    [InlineData("code_challenge_method", null, "invalid_request")]
    [InlineData("response_type", "token", "unsupported_response_type")]
    [InlineData("resource", null, "invalid_target")]
    [InlineData("resource", "https://mcp.example.com/mcp/", "invalid_target")]
    [InlineData("resource", "https://evil.example.com/mcp", "invalid_target")]
    [InlineData("scope", "tasks:read admin", "invalid_scope")]
    public async Task Bad_parameters_after_the_redirect_is_trusted_redirect_with_error_state_and_iss(string key, string? value, string error)
    {
        await using var host = await OAuthTestHost.StartAsync();
        var q = OAuthTestHost.BaseQuery(OAuthTestHost.NewPkce().Challenge);
        q[key] = value;

        var r = await host.AuthorizeAsync(q);

        r.StatusCode.Should().Be(HttpStatusCode.Found);
        var loc = OAuthTestHost.Absolute(r);
        loc.GetLeftPart(UriPartial.Path).Should().Be(OAuthTestHost.ClaudeRedirect);
        var back = OAuthTestHost.QueryOf(loc);
        back["error"].Should().Be(error);
        back["state"].Should().Be("st-123");
        back["iss"].Should().Be(OAuthTestHost.Issuer);
        back.Should().ContainKey("error_description");
        back.Should().NotContainKey("request");
    }

    [Fact]
    public async Task Empty_scope_gets_the_host_default()
    {
        await using var host = await OAuthTestHost.StartAsync(o => o.DefaultScopes.Add("tasks:read"));
        var q = OAuthTestHost.BaseQuery(OAuthTestHost.NewPkce().Challenge);
        q["scope"] = null;
        var id = await host.StartRequestAsync(q);

        var info = (await OAuthTestHost.ToResult(await host.Client.GetAsync("/oauth/pending?request=" + id))).Json;
        info.GetProperty("RequestedScopes").EnumerateArray().Select(s => s.GetProperty("Name").GetString()).Should().Equal("tasks:read");
    }

    [Fact]
    public async Task Pending_info_carries_client_scopes_resource_and_the_redirect_host()
    {
        await using var host = await OAuthTestHost.StartAsync();
        var id = await host.StartRequestAsync(OAuthTestHost.BaseQuery(OAuthTestHost.NewPkce().Challenge));

        var info = (await OAuthTestHost.ToResult(await host.Client.GetAsync("/oauth/pending?request=" + id))).Json;
        info.GetProperty("ClientName").GetString().Should().Be("Test Client");
        info.GetProperty("RedirectHost").GetString().Should().Be("claude.ai");
        info.GetProperty("Resource").GetString().Should().Be(OAuthTestHost.Resource);
        info.GetProperty("RequestedScopes").EnumerateArray().Select(s => s.GetProperty("Description").GetString())
            .Should().Equal("Read your tasks", "Create and edit your tasks");
    }

    [Fact]
    public async Task Unknown_request_id_has_no_pending_info()
    {
        await using var host = await OAuthTestHost.StartAsync();
        (await host.Client.GetAsync("/oauth/pending?request=nope")).StatusCode.Should().Be(HttpStatusCode.NotFound);
    }

    [Theory]
    [InlineData(OAuthTestHost.ClaudeRedirect)]
    [InlineData(OAuthTestHost.ChatGptRedirect)]
    [InlineData(OAuthTestHost.ChatGptConnectorRedirect)]
    public async Task Known_real_client_redirects_are_accepted(string redirect)
    {
        await using var host = await OAuthTestHost.StartAsync();
        var q = OAuthTestHost.BaseQuery(OAuthTestHost.NewPkce().Challenge, redirect: redirect);
        (await host.AuthorizeAsync(q)).StatusCode.Should().Be(HttpStatusCode.Found);
    }

    [Theory]
    [InlineData("http://127.0.0.1:54321/callback", true)]
    [InlineData("http://127.0.0.1:1/callback", true)]
    [InlineData("http://127.0.0.1/callback", true)]
    [InlineData("http://127.0.0.1:54321/other", false)]
    [InlineData("http://localhost:54321/callback", false)]
    [InlineData("http://127.0.0.2:54321/callback", false)]
    [InlineData("https://127.0.0.1:54321/callback", false)]
    public async Task Loopback_redirects_match_on_any_port_but_not_on_another_path_or_host(string redirect, bool accepted)
    {
        await using var host = await OAuthTestHost.StartAsync();
        var q = OAuthTestHost.BaseQuery(OAuthTestHost.NewPkce().Challenge, redirect: redirect);
        var r = await host.AuthorizeAsync(q);
        r.StatusCode.Should().Be(accepted ? HttpStatusCode.Found : HttpStatusCode.BadRequest);
        if (accepted) r.Headers.Location!.OriginalString.Should().StartWith("/oauth/consent");
    }

    [Fact]
    public async Task Loopback_code_is_delivered_to_the_requested_port()
    {
        await using var host = await OAuthTestHost.StartAsync();
        var (code, verifier, _) = await host.ApproveAsync(redirect: "http://127.0.0.1:61000/callback");
        code.Should().NotBeNullOrEmpty();
        (await host.ExchangeAsync(code, verifier, "http://127.0.0.1:61000/callback")).Status.Should().Be(HttpStatusCode.OK);
    }
}

public class RedirectUriRulesTests
{
    [Theory]
    [InlineData("https://claude.ai/api/mcp/auth_callback", true)]
    [InlineData("http://localhost:3000/cb", true)]
    [InlineData("http://127.0.0.1/cb", true)]
    [InlineData("http://[::1]:8080/cb", true)]
    [InlineData("http://example.com/cb", false)]
    [InlineData("myapp://callback", false)]
    [InlineData("https://claude.ai/cb#frag", false)]
    [InlineData("https://user:pw@claude.ai/cb", false)]
    [InlineData("/relative", false)]
    [InlineData("", false)]
    public void Acceptable_is_https_or_loopback_only(string uri, bool expected) =>
        TechTeaStudio.Auth.OAuthServer.Internal.RedirectUriRules.IsAcceptable(uri).Should().Be(expected);

    [Fact]
    public void Ipv6_loopback_matches_any_port()
    {
        var reg = new[] { "http://[::1]/cb" };
        TechTeaStudio.Auth.OAuthServer.Internal.RedirectUriRules.Matches(reg, "http://[::1]:5555/cb").Should().BeTrue();
        TechTeaStudio.Auth.OAuthServer.Internal.RedirectUriRules.Matches(reg, "http://[::1]:5555/x").Should().BeFalse();
    }

    [Fact]
    public void Non_loopback_requires_an_exact_match_including_the_port()
    {
        var reg = new[] { "https://app.example.com/cb" };
        var m = TechTeaStudio.Auth.OAuthServer.Internal.RedirectUriRules.Matches(reg, "https://app.example.com:8443/cb");
        m.Should().BeFalse();
    }
}
