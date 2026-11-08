using System.Net;
using System.Text;
using System.Text.Json;
using FluentAssertions;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Xunit;
using TechTeaStudio.Auth.Observability;
using TechTeaStudio.Auth.OAuthServer;
using TechTeaStudio.Auth.OAuthServer.Abstractions;
using TechTeaStudio.Auth.OAuthServer.Clients;
using TechTeaStudio.Auth.OAuthServer.Internal;

namespace TechTeaStudio.Auth.Tests.OAuthServer;

public class ClientIdMetadataDocumentTests
{
    private const string DocUrl = "https://app.example.org/oauth/client.json";

    private static string Doc(string? clientId = DocUrl, string redirects = "[\"https://app.example.org/cb\",\"http://127.0.0.1/cb\"]", string extra = "") =>
        "{" + (clientId is null ? "" : $"\"client_id\":\"{clientId}\",") + $"\"redirect_uris\":{redirects},\"client_name\":\"Example App\"" + extra + "}";

    private static async Task<HttpResponseMessage> AuthorizeAsync(OAuthTestHost host, string clientId = DocUrl, string redirect = "https://app.example.org/cb") =>
        await host.AuthorizeAsync(OAuthTestHost.BaseQuery(OAuthTestHost.NewPkce().Challenge, clientId, redirect));

    [Fact]
    public async Task A_valid_document_makes_the_url_a_usable_client_id()
    {
        await using var host = await OAuthTestHost.StartAsync();
        host.Fetcher.Responses[DocUrl] = ClientMetadataFetchResult.Ok(Doc(), TimeSpan.FromMinutes(5));

        var r = await AuthorizeAsync(host);
        r.StatusCode.Should().Be(HttpStatusCode.Found);
        r.Headers.Location!.OriginalString.Should().StartWith("/oauth/consent");

        var id = OAuthTestHost.QueryOf(OAuthTestHost.Absolute(r))["request"];
        var info = (await OAuthTestHost.ToResult(await host.Client.GetAsync("/oauth/pending?request=" + id))).Json;
        info.GetProperty("ClientName").GetString().Should().Be("Example App");
        info.GetProperty("RedirectHost").GetString().Should().Be("app.example.org");
        info.GetProperty("ClientSource").GetInt32().Should().Be((int)OAuthClientSource.MetadataDocument);
    }

    [Fact]
    public async Task A_cimd_client_can_complete_the_whole_flow_including_loopback_ports()
    {
        await using var host = await OAuthTestHost.StartAsync();
        host.Fetcher.Responses[DocUrl] = ClientMetadataFetchResult.Ok(Doc(), null);

        var t = await host.LoginAsync(DocUrl, "http://127.0.0.1:50505/cb");
        OAuthTestHost.Jwt(t.Access).Claims.Single(c => c.Type == "client_id").Value.Should().Be(DocUrl);
        (await host.RefreshAsync(t.Refresh, DocUrl)).Status.Should().Be(HttpStatusCode.OK);
    }

    [Fact]
    public async Task A_redirect_outside_the_documents_list_is_a_400()
    {
        await using var host = await OAuthTestHost.StartAsync();
        host.Fetcher.Responses[DocUrl] = ClientMetadataFetchResult.Ok(Doc(), null);
        (await AuthorizeAsync(host, redirect: "https://evil.example.com/cb")).StatusCode.Should().Be(HttpStatusCode.BadRequest);
    }

    [Theory]
    [InlineData("mismatch")]
    [InlineData("missing_id")]
    [InlineData("no_redirects")]
    [InlineData("empty_redirects")]
    [InlineData("http_redirect")]
    [InlineData("secret_basic")]
    [InlineData("has_secret")]
    [InlineData("not_json")]
    [InlineData("array_root")]
    [InlineData("name_not_string")]
    public async Task Invalid_documents_are_refused_and_audited(string kind)
    {
        await using var host = await OAuthTestHost.StartAsync();
        var body = kind switch
        {
            "mismatch" => Doc("https://app.example.org/other.json"),
            "missing_id" => Doc(null),
            "no_redirects" => "{\"client_id\":\"" + DocUrl + "\"}",
            "empty_redirects" => Doc(redirects: "[]"),
            "http_redirect" => Doc(redirects: "[\"http://app.example.org/cb\"]"),
            "secret_basic" => Doc(extra: ",\"token_endpoint_auth_method\":\"client_secret_basic\""),
            "has_secret" => Doc(extra: ",\"client_secret\":\"x\""),
            "not_json" => "<html>",
            "array_root" => "[]",
            _ => "{\"client_id\":\"" + DocUrl + "\",\"redirect_uris\":[\"https://app.example.org/cb\"],\"client_name\":5}",
        };
        host.Fetcher.Responses[DocUrl] = ClientMetadataFetchResult.Ok(body, null);

        (await AuthorizeAsync(host)).StatusCode.Should().Be(HttpStatusCode.BadRequest);
        host.Audit.Snapshot().OfType<OAuthClientMetadataFetchFailedEvent>().Should().ContainSingle(e => e.ClientIdUrl == DocUrl);
    }

    [Fact]
    public async Task Auth_method_none_is_accepted_explicitly()
    {
        await using var host = await OAuthTestHost.StartAsync();
        host.Fetcher.Responses[DocUrl] = ClientMetadataFetchResult.Ok(Doc(extra: ",\"token_endpoint_auth_method\":\"none\""), null);
        (await AuthorizeAsync(host)).StatusCode.Should().Be(HttpStatusCode.Found);
    }

    [Fact]
    public async Task A_fetch_failure_is_a_400_and_audited()
    {
        await using var host = await OAuthTestHost.StartAsync();
        host.Fetcher.Responses[DocUrl] = ClientMetadataFetchResult.Fail("blocked_address");

        (await AuthorizeAsync(host)).StatusCode.Should().Be(HttpStatusCode.BadRequest);
        host.Audit.Snapshot().OfType<OAuthClientMetadataFetchFailedEvent>().Single().Reason.Should().Be("blocked_address");
    }

    [Fact]
    public async Task Failures_are_cached_briefly_so_a_bad_client_cannot_hammer_the_fetcher()
    {
        await using var host = await OAuthTestHost.StartAsync();
        host.Fetcher.Responses[DocUrl] = ClientMetadataFetchResult.Fail("http_500");

        await AuthorizeAsync(host);
        await AuthorizeAsync(host);
        host.Fetcher.Requested.Should().HaveCount(1);

        host.Time.Advance(TimeSpan.FromSeconds(31));
        await AuthorizeAsync(host);
        host.Fetcher.Requested.Should().HaveCount(2);
    }

    [Fact]
    public async Task The_document_is_cached_for_its_max_age_then_refetched()
    {
        await using var host = await OAuthTestHost.StartAsync();
        host.Fetcher.Responses[DocUrl] = ClientMetadataFetchResult.Ok(Doc(), TimeSpan.FromMinutes(10));

        await AuthorizeAsync(host);
        host.Time.Advance(TimeSpan.FromMinutes(9));
        await AuthorizeAsync(host);
        host.Fetcher.Requested.Should().HaveCount(1);

        host.Time.Advance(TimeSpan.FromMinutes(2));
        await AuthorizeAsync(host);
        host.Fetcher.Requested.Should().HaveCount(2);
    }

    [Fact]
    public async Task Cache_lifetime_is_capped_at_24_hours()
    {
        await using var host = await OAuthTestHost.StartAsync();
        host.Fetcher.Responses[DocUrl] = ClientMetadataFetchResult.Ok(Doc(), TimeSpan.FromDays(30));

        await AuthorizeAsync(host);
        host.Time.Advance(TimeSpan.FromHours(23));
        await AuthorizeAsync(host);
        host.Fetcher.Requested.Should().HaveCount(1);

        host.Time.Advance(TimeSpan.FromHours(2));
        await AuthorizeAsync(host);
        host.Fetcher.Requested.Should().HaveCount(2);
    }

    [Fact]
    public async Task No_store_is_never_cached()
    {
        await using var host = await OAuthTestHost.StartAsync();
        host.Fetcher.Responses[DocUrl] = ClientMetadataFetchResult.Ok(Doc(), TimeSpan.Zero);

        await AuthorizeAsync(host);
        await AuthorizeAsync(host);
        host.Fetcher.Requested.Should().HaveCount(2);
    }

    [Fact]
    public async Task Without_cache_control_the_default_applies()
    {
        await using var host = await OAuthTestHost.StartAsync();
        host.Fetcher.Responses[DocUrl] = ClientMetadataFetchResult.Ok(Doc(), null);

        await AuthorizeAsync(host);
        host.Time.Advance(TimeSpan.FromMinutes(59));
        await AuthorizeAsync(host);
        host.Fetcher.Requested.Should().HaveCount(1);
        host.Time.Advance(TimeSpan.FromMinutes(2));
        await AuthorizeAsync(host);
        host.Fetcher.Requested.Should().HaveCount(2);
    }

    [Fact]
    public async Task The_feature_can_be_switched_off()
    {
        await using var host = await OAuthTestHost.StartAsync(o => o.EnableClientIdMetadataDocuments = false);
        host.Fetcher.Responses[DocUrl] = ClientMetadataFetchResult.Ok(Doc(), null);

        (await AuthorizeAsync(host)).StatusCode.Should().Be(HttpStatusCode.BadRequest);
        host.Fetcher.Requested.Should().BeEmpty();
        var meta = (await OAuthTestHost.ToResult(await host.Client.GetAsync(OAuthServerPaths.Metadata))).Json;
        meta.GetProperty("client_id_metadata_document_supported").GetBoolean().Should().BeFalse();
    }

    [Theory]
    [InlineData("http://app.example.org/oauth/client.json")]
    [InlineData("https://app.example.org/")]
    [InlineData("https://app.example.org")]
    [InlineData("https://app.example.org/a/../client.json")]
    [InlineData("https://app.example.org/client.json#frag")]
    [InlineData("https://user@app.example.org/client.json")]
    [InlineData("ftp://app.example.org/client.json")]
    public async Task Only_clean_https_urls_with_a_path_are_fetched(string clientId)
    {
        await using var host = await OAuthTestHost.StartAsync();
        host.Fetcher.Responses[clientId] = ClientMetadataFetchResult.Ok(Doc(clientId), null);

        (await AuthorizeAsync(host, clientId)).StatusCode.Should().Be(HttpStatusCode.BadRequest);
        host.Fetcher.Requested.Should().BeEmpty();
    }

    [Fact]
    public async Task A_preregistered_client_wins_over_the_fetcher()
    {
        await using var host = await OAuthTestHost.StartAsync(o =>
            o.Clients.Add(new OAuthClientOptions { ClientId = DocUrl, Name = "Pinned", RedirectUris = { "https://pinned.example.org/cb" } }));
        host.Fetcher.Responses[DocUrl] = ClientMetadataFetchResult.Ok(Doc(), null);

        (await AuthorizeAsync(host, redirect: "https://pinned.example.org/cb")).StatusCode.Should().Be(HttpStatusCode.Found);
        (await AuthorizeAsync(host, redirect: "https://app.example.org/cb")).StatusCode.Should().Be(HttpStatusCode.BadRequest);
        host.Fetcher.Requested.Should().BeEmpty();
    }

    [Fact]
    public void Display_fields_are_length_capped_and_unsafe_uris_dropped()
    {
        var longName = new string('x', 500);
        var json = "{\"client_id\":\"" + DocUrl + "\",\"redirect_uris\":[\"https://app.example.org/cb\"],\"client_name\":\"" + longName + "\","
                   + "\"logo_uri\":\"http://insecure.example.org/logo.png\",\"client_uri\":\"https://app.example.org\"}";
        var client = ClientMetadataParser.ParseDocument(json, DocUrl, new OAuthServerOptions(), DateTimeOffset.UnixEpoch, out var reason);

        reason.Should().BeNull();
        client!.Name!.Length.Should().Be(100);
        client.LogoUri.Should().BeNull();
        client.ClientUri.Should().Be("https://app.example.org");
    }

    [Fact]
    public void Control_characters_are_stripped_from_the_name()
    {
        ClientMetadataParser.CleanText("Evil\r\nName\u0007", 100).Should().Be("EvilName");
        ClientMetadataParser.CleanText("   ", 100).Should().BeNull();
    }
}

public class SsrfGuardTests
{
    [Theory]
    [InlineData("127.0.0.1")]
    [InlineData("127.1.2.3")]
    [InlineData("10.0.0.1")]
    [InlineData("10.255.255.255")]
    [InlineData("172.16.0.1")]
    [InlineData("172.31.255.255")]
    [InlineData("192.168.1.1")]
    [InlineData("169.254.169.254")]
    [InlineData("100.64.0.1")]
    [InlineData("0.0.0.0")]
    [InlineData("224.0.0.1")]
    [InlineData("239.255.255.250")]
    [InlineData("255.255.255.255")]
    [InlineData("198.18.0.1")]
    [InlineData("192.0.2.1")]
    [InlineData("::1")]
    [InlineData("::")]
    [InlineData("fe80::1")]
    [InlineData("fc00::1")]
    [InlineData("fd12:3456::1")]
    [InlineData("ff02::1")]
    [InlineData("::ffff:127.0.0.1")]
    [InlineData("::ffff:10.1.2.3")]
    [InlineData("::ffff:169.254.169.254")]
    [InlineData("2001:db8::1")]
    [InlineData("64:ff9b::7f00:1")]
    public void Non_public_addresses_are_refused(string ip) =>
        OutboundAddressPolicy.IsPublic(IPAddress.Parse(ip)).Should().BeFalse();

    [Theory]
    [InlineData("8.8.8.8")]
    [InlineData("1.1.1.1")]
    [InlineData("172.15.255.255")]
    [InlineData("172.32.0.1")]
    [InlineData("100.63.255.255")]
    [InlineData("100.128.0.1")]
    [InlineData("93.184.216.34")]
    [InlineData("2606:4700:4700::1111")]
    [InlineData("::ffff:8.8.8.8")]
    public void Public_addresses_are_allowed(string ip) =>
        OutboundAddressPolicy.IsPublic(IPAddress.Parse(ip)).Should().BeTrue();

    private static HttpClientMetadataFetcher Fetcher() => new(Options.Create(new OAuthServerOptions()));

    [Theory]
    [InlineData("https://127.0.0.1/client.json")]
    [InlineData("https://10.0.0.5/client.json")]
    [InlineData("https://[::1]/client.json")]
    [InlineData("https://169.254.169.254/latest/meta-data")]
    public async Task The_default_fetcher_refuses_private_ip_literals_before_any_connection(string url)
    {
        using var f = Fetcher();
        var r = await f.FetchAsync(new Uri(url));
        r.Succeeded.Should().BeFalse();
        r.Error.Should().Be("blocked_address");
    }

    [Fact]
    public async Task The_default_fetcher_refuses_plain_http()
    {
        using var f = Fetcher();
        (await f.FetchAsync(new Uri("http://example.com/client.json"))).Error.Should().Be("not_https");
    }

    [Fact]
    public async Task A_hostname_resolving_to_loopback_is_blocked_at_connect_time()
    {
        using var f = Fetcher();
        var r = await f.FetchAsync(new Uri("https://localhost/client.json"));
        r.Succeeded.Should().BeFalse();
        r.Error.Should().Be("unreachable_or_blocked");
    }
}

public class DynamicRegistrationTests
{
    private static async Task<FormResult> Register(OAuthTestHost host, string json, string contentType = "application/json")
    {
        var r = await host.Client.PostAsync(OAuthServerPaths.Register, new StringContent(json, Encoding.UTF8, contentType));
        return await OAuthTestHost.ToResult(r);
    }

    [Fact]
    public async Task A_valid_registration_returns_201_and_a_usable_public_client()
    {
        await using var host = await OAuthTestHost.StartAsync();
        var reg = await Register(host, "{\"redirect_uris\":[\"https://chatgpt.com/connector/oauth/xyz\"],\"client_name\":\"ChatGPT\",\"token_endpoint_auth_method\":\"none\",\"grant_types\":[\"authorization_code\",\"refresh_token\"],\"response_types\":[\"code\"]}");

        reg.Status.Should().Be(HttpStatusCode.Created);
        reg.Response.Headers.CacheControl!.NoStore.Should().BeTrue();
        var clientId = reg.Str("client_id")!;
        clientId.Should().StartWith("dcr_");
        reg.Str("token_endpoint_auth_method").Should().Be("none");
        reg.Json.TryGetProperty("client_secret", out _).Should().BeFalse();
        host.Audit.Snapshot().OfType<OAuthClientRegisteredEvent>().Should().ContainSingle(e => e.ClientId == clientId);

        var t = await host.LoginAsync(clientId, "https://chatgpt.com/connector/oauth/xyz");
        t.Access.Should().NotBeNullOrEmpty();
    }

    [Theory]
    [InlineData("https://claude.ai/api/mcp/auth_callback")]
    [InlineData("https://chatgpt.com/connector_platform_oauth_redirect")]
    [InlineData("http://localhost/callback")]
    [InlineData("http://127.0.0.1/callback")]
    [InlineData("http://[::1]/callback")]
    public async Task Https_and_loopback_redirects_register(string redirect)
    {
        await using var host = await OAuthTestHost.StartAsync();
        (await Register(host, "{\"redirect_uris\":[\"" + redirect + "\"]}")).Status.Should().Be(HttpStatusCode.Created);
    }

    [Theory]
    [InlineData("{\"redirect_uris\":[\"http://example.com/cb\"]}", "invalid_redirect_uri")]
    [InlineData("{\"redirect_uris\":[\"myapp://cb\"]}", "invalid_redirect_uri")]
    [InlineData("{\"redirect_uris\":[\"https://a.example/cb#x\"]}", "invalid_redirect_uri")]
    [InlineData("{\"redirect_uris\":[]}", "invalid_redirect_uri")]
    [InlineData("{}", "invalid_redirect_uri")]
    [InlineData("{\"redirect_uris\":\"https://a.example/cb\"}", "invalid_redirect_uri")]
    [InlineData("{\"redirect_uris\":[\"https://a.example/cb\"],\"token_endpoint_auth_method\":\"client_secret_post\"}", "invalid_client_metadata")]
    [InlineData("{\"redirect_uris\":[\"https://a.example/cb\"],\"client_name\":42}", "invalid_client_metadata")]
    [InlineData("[]", "invalid_client_metadata")]
    [InlineData("not json", "invalid_client_metadata")]
    public async Task Invalid_registrations_are_rejected_with_rfc7591_errors(string json, string error)
    {
        await using var host = await OAuthTestHost.StartAsync();
        var reg = await Register(host, json);
        reg.Status.Should().Be(HttpStatusCode.BadRequest);
        reg.Str("error").Should().Be(error);
    }

    [Fact]
    public async Task Too_many_redirect_uris_are_rejected()
    {
        await using var host = await OAuthTestHost.StartAsync();
        var uris = string.Join(',', Enumerable.Range(0, 11).Select(i => $"\"https://a.example/cb{i}\""));
        (await Register(host, "{\"redirect_uris\":[" + uris + "]}")).Str("error").Should().Be("invalid_redirect_uri");
    }

    [Fact]
    public async Task Long_names_are_capped()
    {
        await using var host = await OAuthTestHost.StartAsync();
        var reg = await Register(host, "{\"redirect_uris\":[\"https://a.example/cb\"],\"client_name\":\"" + new string('n', 400) + "\"}");
        reg.Str("client_name")!.Length.Should().Be(100);
    }

    [Fact]
    public async Task A_non_json_content_type_is_refused()
    {
        await using var host = await OAuthTestHost.StartAsync();
        (await Register(host, "{\"redirect_uris\":[\"https://a.example/cb\"]}", "text/plain")).Str("error").Should().Be("invalid_client_metadata");
    }

    [Fact]
    public async Task An_oversized_body_is_refused()
    {
        await using var host = await OAuthTestHost.StartAsync();
        var reg = await Register(host, "{\"redirect_uris\":[\"https://a.example/cb\"],\"pad\":\"" + new string('p', 20000) + "\"}");
        reg.Status.Should().Be(HttpStatusCode.BadRequest);
    }

    [Fact]
    public async Task The_endpoint_does_not_exist_when_dcr_is_disabled()
    {
        await using var host = await OAuthTestHost.StartAsync(o => o.EnableDynamicRegistration = false);
        var r = await host.Client.PostAsync(OAuthServerPaths.Register, new StringContent("{}", Encoding.UTF8, "application/json"));
        r.StatusCode.Should().Be(HttpStatusCode.NotFound);
    }

    [Fact]
    public async Task Each_registration_gets_its_own_unguessable_id()
    {
        await using var host = await OAuthTestHost.StartAsync();
        var a = await Register(host, "{\"redirect_uris\":[\"https://a.example/cb\"]}");
        var b = await Register(host, "{\"redirect_uris\":[\"https://a.example/cb\"]}");
        a.Str("client_id").Should().NotBe(b.Str("client_id"));
        a.Str("client_id")!.Length.Should().BeGreaterThan(20);
    }

    [Fact]
    public async Task A_registered_client_cannot_use_a_redirect_it_did_not_register()
    {
        await using var host = await OAuthTestHost.StartAsync();
        var reg = await Register(host, "{\"redirect_uris\":[\"https://a.example/cb\"]}");
        var q = OAuthTestHost.BaseQuery(OAuthTestHost.NewPkce().Challenge, reg.Str("client_id")!, "https://b.example/cb");
        (await host.AuthorizeAsync(q)).StatusCode.Should().Be(HttpStatusCode.BadRequest);
    }
}
