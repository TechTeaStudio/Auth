using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using TechTeaStudio.Auth.AspNetCore;
using TechTeaStudio.Auth.Observability;
using TechTeaStudio.Auth.OAuthServer;
using TechTeaStudio.Auth.OAuthServer.Abstractions;

namespace TechTeaStudio.Auth.Tests.OAuthServer;

public sealed class FakeTime : TimeProvider
{
    private DateTimeOffset _now = new(2026, 11, 1, 12, 0, 0, TimeSpan.Zero);
    public override DateTimeOffset GetUtcNow() => _now;
    public void Advance(TimeSpan by) => _now += by;
}

public sealed class FakeMetadataFetcher : IClientMetadataFetcher
{
    public Dictionary<string, ClientMetadataFetchResult> Responses { get; } = new();
    public List<string> Requested { get; } = new();

    public Task<ClientMetadataFetchResult> FetchAsync(Uri url, CancellationToken cancellationToken = default)
    {
        Requested.Add(url.ToString());
        return Task.FromResult(Responses.TryGetValue(url.ToString(), out var r) ? r : ClientMetadataFetchResult.Fail("http_404"));
    }
}

public sealed record FormResult(HttpResponseMessage Response, JsonElement Json)
{
    public HttpStatusCode Status => Response.StatusCode;
    public string? Str(string name) => Json.ValueKind == JsonValueKind.Object && Json.TryGetProperty(name, out var p) && p.ValueKind == JsonValueKind.String ? p.GetString() : null;
}

public sealed record Tokens(string Access, string Refresh, string Scope, string ClientId);

public sealed class OAuthTestHost : IAsyncDisposable
{
    public const string Issuer = "https://auth.example.com";
    public const string Resource = "https://mcp.example.com/mcp";
    public const string Resource2 = "https://mcp.example.com/other";
    public const string ClaudeRedirect = "https://claude.ai/api/mcp/auth_callback";
    public const string ChatGptRedirect = "https://chatgpt.com/connector_platform_oauth_redirect";
    public const string ChatGptConnectorRedirect = "https://chatgpt.com/connector/oauth/abc123";
    public const string ClientId = "test-client";
    public const string ConfidentialClientId = "conf-client";
    public const string ConfidentialRedirect = "https://conf.example.com/cb";

    public IHost Host { get; private set; } = null!;
    public HttpClient Client { get; private set; } = null!;
    public FakeTime Time { get; } = new();
    public FakeMetadataFetcher Fetcher { get; } = new();
    public InMemoryAuthAuditLogger Audit { get; } = new(4096);

    public static async Task<OAuthTestHost> StartAsync(
        Action<OAuthServerOptions>? configure = null,
        Func<IOAuthServerBuilder, IOAuthServerBuilder>? stores = null,
        Action<IServiceCollection>? services = null)
    {
        var t = new OAuthTestHost();
        t.Host = await new HostBuilder()
            .ConfigureWebHost(web =>
            {
                web.UseTestServer();
                web.ConfigureServices(s =>
                {
                    s.AddRouting();
                    s.AddSingleton<TimeProvider>(t.Time);
                    s.AddSingleton<IAuthAuditLogger>(t.Audit);
                    s.AddSingleton<IClientMetadataFetcher>(t.Fetcher);
                    services?.Invoke(s);
                    s.AddTechTeaStudioAuthCore(new Microsoft.Extensions.Configuration.ConfigurationBuilder().Build(), o =>
                    {
                        o.Jwt.SecretKey = "this-is-a-test-signing-key-32ch!!";
                        o.Jwt.Issuer = "ignored-default-issuer";
                        o.Jwt.Audience = "ignored-default-audience";
                    });
                    var builder = s.AddTechTeaStudioOAuthServer(o =>
                    {
                        o.Issuer = Issuer;
                        o.ProtectedResources.Add(Resource);
                        o.ProtectedResources.Add(Resource2);
                        o.Scopes.Add("tasks:read", "Read your tasks").Add("tasks:write", "Create and edit your tasks");
                        o.ConsentPath = "/oauth/consent";
                        o.Clients.Add(new OAuthClientOptions
                        {
                            ClientId = ClientId,
                            Name = "Test Client",
                            RedirectUris = { ClaudeRedirect, ChatGptRedirect, ChatGptConnectorRedirect, "http://127.0.0.1/callback" },
                        });
                        o.Clients.Add(new OAuthClientOptions
                        {
                            ClientId = ConfidentialClientId,
                            Name = "Confidential",
                            ClientSecret = "s3cret",
                            RedirectUris = { ConfidentialRedirect },
                        });
                        configure?.Invoke(o);
                    });
                    stores?.Invoke(builder);
                });
                web.Configure(app =>
                {
                    app.UseRouting();
                    app.UseEndpoints(e =>
                    {
                        e.MapTechTeaStudioOAuthServer();
                        e.MapGet("/oauth/consent", ConsentAsync);
                        e.MapGet("/oauth/pending", PendingAsync);
                    });
                });
            })
            .StartAsync();
        t.Client = t.Host.GetTestClient();
        return t;
    }

    private static async Task ConsentAsync(HttpContext ctx)
    {
        var svc = ctx.RequestServices.GetRequiredService<IOAuthAuthorizationService>();
        var id = ctx.Request.Query["request"].ToString();
        var action = ctx.Request.Query["action"].ToString();
        var user = ctx.Request.Query["user"].ToString();
        if (user.Length == 0) user = "user-1";
        var grant = ctx.Request.Query["grant"].ToString();

        var url = action switch
        {
            "deny" => await svc.DenyAsync(id),
            "auto" => await svc.TryAutoApproveAsync(id, user),
            _ => await svc.ApproveAsync(id, user, grant.Length == 0 ? null : grant.Split(' ')),
        };
        if (url is null)
        {
            ctx.Response.StatusCode = action == "auto" ? StatusCodes.Status204NoContent : StatusCodes.Status410Gone;
            return;
        }
        ctx.Response.Redirect(url);
    }

    private static async Task PendingAsync(HttpContext ctx)
    {
        var svc = ctx.RequestServices.GetRequiredService<IOAuthAuthorizationService>();
        var info = await svc.GetPendingAsync(ctx.Request.Query["request"].ToString());
        if (info is null) { ctx.Response.StatusCode = 404; return; }
        ctx.Response.ContentType = "application/json";
        await ctx.Response.WriteAsync(JsonSerializer.Serialize(info));
    }

    public IServiceScope Scope() => Host.Services.CreateScope();

    public static (string Verifier, string Challenge) NewPkce()
    {
        var verifier = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)).Replace('+', '-').Replace('/', '_').TrimEnd('=');
        var challenge = Convert.ToBase64String(SHA256.HashData(Encoding.ASCII.GetBytes(verifier))).Replace('+', '-').Replace('/', '_').TrimEnd('=');
        return (verifier, challenge);
    }

    public static Dictionary<string, string?> BaseQuery(string challenge, string clientId = ClientId, string redirect = ClaudeRedirect) => new()
    {
        ["response_type"] = "code",
        ["client_id"] = clientId,
        ["redirect_uri"] = redirect,
        ["code_challenge"] = challenge,
        ["code_challenge_method"] = "S256",
        ["resource"] = Resource,
        ["scope"] = "tasks:read tasks:write",
        ["state"] = "st-123",
    };

    public static string Qs(IDictionary<string, string?> q) =>
        "?" + string.Join('&', q.Where(kv => kv.Value is not null).Select(kv => Uri.EscapeDataString(kv.Key) + "=" + Uri.EscapeDataString(kv.Value!)));

    public Task<HttpResponseMessage> AuthorizeAsync(IDictionary<string, string?> query) =>
        Client.GetAsync(OAuthServerPaths.Authorize + Qs(query));

    public static Uri Absolute(HttpResponseMessage r)
    {
        var loc = r.Headers.Location!;
        return loc.IsAbsoluteUri ? loc : new Uri("https://host.test" + loc.OriginalString);
    }

    public static Dictionary<string, string> QueryOf(Uri uri) =>
        QueryHelpers.ParseQuery(uri.Query).ToDictionary(kv => kv.Key, kv => kv.Value.ToString());

    public async Task<string> StartRequestAsync(IDictionary<string, string?> query)
    {
        var r = await AuthorizeAsync(query);
        r.StatusCode.Should_Be(HttpStatusCode.Found);
        return QueryOf(Absolute(r))["request"];
    }

    public async Task<HttpResponseMessage> ConsentAsync(string requestId, string action = "approve", string user = "user-1", string? grant = null)
    {
        var q = new Dictionary<string, string?> { ["request"] = requestId, ["action"] = action, ["user"] = user, ["grant"] = grant };
        return await Client.GetAsync("/oauth/consent" + Qs(q));
    }

    public async Task<(string Code, string Verifier, string Redirect)> ApproveAsync(
        string clientId = ClientId, string redirect = ClaudeRedirect, string user = "user-1", string? scope = "tasks:read tasks:write", string? grant = null)
    {
        var (verifier, challenge) = NewPkce();
        var q = BaseQuery(challenge, clientId, redirect);
        q["scope"] = scope;
        var id = await StartRequestAsync(q);
        var r = await ConsentAsync(id, "approve", user, grant);
        r.StatusCode.Should_Be(HttpStatusCode.Found);
        var back = QueryOf(Absolute(r));
        return (back["code"], verifier, redirect);
    }

    public async Task<FormResult> PostFormAsync(string path, IDictionary<string, string> form)
    {
        var r = await Client.PostAsync(path, new FormUrlEncodedContent(form));
        return await ToResult(r);
    }

    public static async Task<FormResult> ToResult(HttpResponseMessage r)
    {
        var body = await r.Content.ReadAsStringAsync();
        JsonElement json = default;
        if (body.Length > 0 && body.TrimStart().StartsWith('{'))
            json = JsonDocument.Parse(body).RootElement.Clone();
        return new FormResult(r, json);
    }

    public Task<FormResult> ExchangeAsync(string code, string verifier, string redirect, string clientId = ClientId, string? resource = Resource, string? secret = null)
    {
        var f = new Dictionary<string, string>
        {
            ["grant_type"] = "authorization_code", ["code"] = code, ["code_verifier"] = verifier,
            ["redirect_uri"] = redirect, ["client_id"] = clientId,
        };
        if (resource is not null) f["resource"] = resource;
        if (secret is not null) f["client_secret"] = secret;
        return PostFormAsync(OAuthServerPaths.Token, f);
    }

    public Task<FormResult> RefreshAsync(string refresh, string clientId = ClientId, string? scope = null) =>
        PostFormAsync(OAuthServerPaths.Token, scope is null
            ? new Dictionary<string, string> { ["grant_type"] = "refresh_token", ["refresh_token"] = refresh, ["client_id"] = clientId }
            : new Dictionary<string, string> { ["grant_type"] = "refresh_token", ["refresh_token"] = refresh, ["client_id"] = clientId, ["scope"] = scope });

    public async Task<Tokens> LoginAsync(string clientId = ClientId, string redirect = ClaudeRedirect, string user = "user-1", string? scope = "tasks:read tasks:write", string? grant = null)
    {
        var (code, verifier, _) = await ApproveAsync(clientId, redirect, user, scope, grant);
        var t = await ExchangeAsync(code, verifier, redirect, clientId, secret: clientId == ConfidentialClientId ? "s3cret" : null);
        t.Status.Should_Be(HttpStatusCode.OK);
        return new Tokens(t.Str("access_token")!, t.Str("refresh_token")!, t.Str("scope")!, clientId);
    }

    public static JwtSecurityToken Jwt(string token) => new JwtSecurityTokenHandler().ReadJwtToken(token);

    public async ValueTask DisposeAsync()
    {
        Client.Dispose();
        await Host.StopAsync();
        Host.Dispose();
    }
}

internal static class StatusAssert
{
    public static void Should_Be(this HttpStatusCode actual, HttpStatusCode expected) =>
        FluentAssertions.AssertionExtensions.Should(actual).Be(expected);
}
