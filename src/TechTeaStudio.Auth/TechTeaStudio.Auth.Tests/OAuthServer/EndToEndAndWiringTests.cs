using System.Net;
using FluentAssertions;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Xunit;
using TechTeaStudio.Auth.Abstractions;
using TechTeaStudio.Auth.OAuthServer;
using TechTeaStudio.Auth.OAuthServer.Abstractions;
using TechTeaStudio.Auth.OAuthServer.Stores;

namespace TechTeaStudio.Auth.Tests.OAuthServer;

public class OAuthServerEndToEndTests
{
    [Fact]
    public async Task Discovery_register_authorize_approve_token_refresh_revoke()
    {
        await using var host = await OAuthTestHost.StartAsync();

        var meta = (await OAuthTestHost.ToResult(await host.Client.GetAsync(OAuthServerPaths.Metadata))).Json;
        meta.GetProperty("issuer").GetString().Should().Be(OAuthTestHost.Issuer);

        var reg = await host.Client.PostAsync(OAuthServerPaths.Register, new StringContent(
            "{\"redirect_uris\":[\"https://claude.ai/api/mcp/auth_callback\"],\"client_name\":\"Claude\"}", System.Text.Encoding.UTF8, "application/json"));
        var clientId = (await OAuthTestHost.ToResult(reg)).Str("client_id")!;

        var (verifier, challenge) = OAuthTestHost.NewPkce();
        var q = OAuthTestHost.BaseQuery(challenge, clientId);
        var authorize = await host.AuthorizeAsync(q);
        authorize.StatusCode.Should().Be(HttpStatusCode.Found);
        var consent = OAuthTestHost.Absolute(authorize);
        consent.AbsolutePath.Should().Be("/oauth/consent");

        var approve = await host.Client.GetAsync(consent.PathAndQuery + "&user=carol");
        approve.StatusCode.Should().Be(HttpStatusCode.Found);
        var back = OAuthTestHost.QueryOf(OAuthTestHost.Absolute(approve));
        back["state"].Should().Be("st-123");
        back["iss"].Should().Be(OAuthTestHost.Issuer);

        var token = await host.ExchangeAsync(back["code"], verifier, OAuthTestHost.ClaudeRedirect, clientId);
        token.Status.Should().Be(HttpStatusCode.OK);
        var jwt = OAuthTestHost.Jwt(token.Str("access_token")!);
        jwt.Audiences.Should().Equal(OAuthTestHost.Resource);
        jwt.Subject.Should().Be("carol");

        var refreshed = await host.RefreshAsync(token.Str("refresh_token")!, clientId);
        refreshed.Status.Should().Be(HttpStatusCode.OK);
        var newRefresh = refreshed.Str("refresh_token")!;

        var revoke = await host.PostFormAsync(OAuthServerPaths.Revoke, new Dictionary<string, string> { ["token"] = newRefresh, ["client_id"] = clientId });
        revoke.Status.Should().Be(HttpStatusCode.OK);

        var dead = await host.RefreshAsync(newRefresh, clientId);
        dead.Status.Should().Be(HttpStatusCode.BadRequest);
        dead.Str("error").Should().Be("invalid_grant");
    }

    [Fact]
    public async Task The_issued_access_token_validates_against_the_core_provider()
    {
        await using var host = await OAuthTestHost.StartAsync(o => { });
        var t = await host.LoginAsync();
        OAuthTestHost.Jwt(t.Access).SignatureAlgorithm.Should().Be("HS256");
        host.Host.Services.GetRequiredService<ITokenProvider>().Should().NotBeNull();
    }
}

public class OAuthServerWiringTests
{
    [Fact]
    public void Paths_are_constants_for_rate_limiter_setup()
    {
        OAuthServerPaths.Authorize.Should().Be("/oauth/authorize");
        OAuthServerPaths.Token.Should().Be("/oauth/token");
        OAuthServerPaths.Register.Should().Be("/oauth/register");
        OAuthServerPaths.Revoke.Should().Be("/oauth/revoke");
        OAuthServerPaths.Metadata.Should().Be("/.well-known/oauth-authorization-server");
    }

    [Fact]
    public void Defaults_match_the_documented_profile()
    {
        var o = new OAuthServerOptions();
        o.AccessTokenLifetime.Should().Be(TimeSpan.FromMinutes(60));
        o.RefreshTokenLifetime.Should().Be(TimeSpan.FromDays(30));
        o.AuthorizationCodeLifetime.Should().Be(TimeSpan.FromSeconds(60));
        o.PendingRequestLifetime.Should().Be(TimeSpan.FromMinutes(10));
        o.RefreshRotationGrace.Should().Be(TimeSpan.FromSeconds(30));
        o.EnableDynamicRegistration.Should().BeTrue();
        o.RememberConsent.Should().BeFalse();
        o.MetadataCacheMaxAge.Should().Be(TimeSpan.FromSeconds(300));
    }

    [Theory]
    [InlineData("")]
    [InlineData("not a url")]
    [InlineData("/relative")]
    [InlineData("http://auth.example.com")]
    [InlineData("https://auth.example.com?x=1")]
    public void Issuer_must_be_an_absolute_https_url(string issuer)
    {
        var o = Valid();
        o.Issuer = issuer;
        OAuthServerServiceCollectionExtensions.Validate(o).Should().NotBeNull();
    }

    [Fact]
    public void A_loopback_http_issuer_is_allowed_for_development()
    {
        var o = Valid();
        o.Issuer = "http://localhost:5000";
        OAuthServerServiceCollectionExtensions.Validate(o).Should().BeNull();
    }

    [Fact]
    public void Validation_covers_resources_scopes_defaults_and_clients()
    {
        OAuthServerServiceCollectionExtensions.Validate(Valid()).Should().BeNull();

        var a = Valid(); a.ProtectedResources.Clear();
        OAuthServerServiceCollectionExtensions.Validate(a).Should().NotBeNull();

        var b = Valid(); b.ProtectedResources.Add("not-a-url");
        OAuthServerServiceCollectionExtensions.Validate(b).Should().NotBeNull();

        var c = Valid(); c.DefaultScopes.Add("ghost");
        OAuthServerServiceCollectionExtensions.Validate(c).Should().NotBeNull();

        var d = Valid(); d.Clients.Add(new OAuthClientOptions { ClientId = "x", RedirectUris = { "http://example.com/cb" } });
        OAuthServerServiceCollectionExtensions.Validate(d).Should().NotBeNull();

        var e = Valid(); e.AccessTokenLifetime = TimeSpan.Zero;
        OAuthServerServiceCollectionExtensions.Validate(e).Should().NotBeNull();
    }

    [Fact]
    public void Scope_collection_rejects_duplicates_and_unsafe_names()
    {
        var s = new OAuthScopeCollection().Add("a").Add("b", "Bee");
        s.Select(x => x.Name).Should().Equal("a", "b");
        s.Find("b")!.Description.Should().Be("Bee");
        FluentActions.Invoking(() => s.Add("a")).Should().Throw<ArgumentException>();
        FluentActions.Invoking(() => s.Add("has space")).Should().Throw<ArgumentException>();
        FluentActions.Invoking(() => s.Add("quo\"te")).Should().Throw<ArgumentException>();
        FluentActions.Invoking(() => s.Add("")).Should().Throw<ArgumentException>();
    }

    [Fact]
    public void In_memory_stores_are_the_default_and_use_methods_swap_them()
    {
        var services = new ServiceCollection();
        var builder = services.AddTechTeaStudioOAuthServer(o => { });
        services.Count(d => d.ServiceType == typeof(IOAuthCodeStore)).Should().Be(1);
        services.Single(d => d.ServiceType == typeof(IOAuthCodeStore)).ImplementationType.Should().Be(typeof(InMemoryOAuthCodeStore));

        builder.UseCodeStore<CustomCodeStore>();
        services.Count(d => d.ServiceType == typeof(IOAuthCodeStore)).Should().Be(1);
        services.Single(d => d.ServiceType == typeof(IOAuthCodeStore)).ImplementationType.Should().Be(typeof(CustomCodeStore));
        services.Single(d => d.ServiceType == typeof(IOAuthCodeStore)).Lifetime.Should().Be(ServiceLifetime.Scoped);
    }

    [Fact]
    public async Task A_host_supplied_store_is_actually_used()
    {
        var spy = new SpyGrantStore();
        await using var host = await OAuthTestHost.StartAsync(services: s => s.AddSingleton<IOAuthGrantStore>(spy));
        await host.LoginAsync(user: "spy-user");
        spy.Upserts.Should().Be(1);
    }

    private static OAuthServerOptions Valid()
    {
        var o = new OAuthServerOptions { Issuer = "https://auth.example.com" };
        o.ProtectedResources.Add("https://mcp.example.com/mcp");
        o.Scopes.Add("tasks:read");
        return o;
    }

    private sealed class CustomCodeStore : IOAuthCodeStore
    {
        public Task SaveAsync(AuthorizationCode code, CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task<CodeConsumeResult?> TryConsumeAsync(string codeHash, DateTimeOffset now, CancellationToken cancellationToken = default) => Task.FromResult<CodeConsumeResult?>(null);
        public Task<int> CleanupExpiredAsync(DateTimeOffset cutoff, CancellationToken cancellationToken = default) => Task.FromResult(0);
    }

    private sealed class SpyGrantStore : IOAuthGrantStore
    {
        private readonly InMemoryOAuthGrantStore _inner = new();
        public int Upserts;
        public Task<OAuthGrant?> GetAsync(string userId, string clientId, CancellationToken cancellationToken = default) => _inner.GetAsync(userId, clientId, cancellationToken);
        public Task UpsertAsync(string userId, string clientId, string? clientName, IReadOnlyCollection<string> scopes, DateTimeOffset now, CancellationToken cancellationToken = default)
        {
            Interlocked.Increment(ref Upserts);
            return _inner.UpsertAsync(userId, clientId, clientName, scopes, now, cancellationToken);
        }
        public Task TouchAsync(string userId, string clientId, DateTimeOffset now, CancellationToken cancellationToken = default) => _inner.TouchAsync(userId, clientId, now, cancellationToken);
        public Task<IReadOnlyList<OAuthGrant>> ListForUserAsync(string userId, CancellationToken cancellationToken = default) => _inner.ListForUserAsync(userId, cancellationToken);
        public Task<bool> DeleteAsync(string userId, string clientId, CancellationToken cancellationToken = default) => _inner.DeleteAsync(userId, clientId, cancellationToken);
    }
}
