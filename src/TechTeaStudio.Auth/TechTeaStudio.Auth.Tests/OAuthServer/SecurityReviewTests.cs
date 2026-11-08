using System.Net;
using System.Security.Claims;
using System.Text;
using FluentAssertions;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Xunit;
using TechTeaStudio.Auth.Abstractions;
using TechTeaStudio.Auth.AspNetCore;
using TechTeaStudio.Auth.Observability;
using TechTeaStudio.Auth.OAuthServer;
using TechTeaStudio.Auth.OAuthServer.Abstractions;
using TechTeaStudio.Auth.OAuthServer.Clients;
using TechTeaStudio.Auth.OAuthServer.Internal;
using TechTeaStudio.Auth.OAuthServer.Stores;

namespace TechTeaStudio.Auth.Tests.OAuthServer;

public sealed class RacingRefreshStore : IOAuthRefreshTokenStore
{
    public RacingRefreshStore(InMemoryOAuthRefreshTokenStore inner) => Inner = inner;
    public InMemoryOAuthRefreshTokenStore Inner { get; }
    public Func<OAuthRefreshToken, Task>? BeforeCreate { get; set; }

    public async Task CreateAsync(OAuthRefreshToken token, CancellationToken cancellationToken = default)
    {
        var hook = BeforeCreate;
        if (hook is not null) await hook(token);
        await Inner.CreateAsync(token, cancellationToken);
    }

    public Task<OAuthRefreshToken?> GetByHashAsync(string tokenHash, CancellationToken cancellationToken = default) => Inner.GetByHashAsync(tokenHash, cancellationToken);
    public Task<bool> TryRotateAsync(Guid id, string replacedByTokenHash, DateTimeOffset now, CancellationToken cancellationToken = default) => Inner.TryRotateAsync(id, replacedByTokenHash, now, cancellationToken);
    public Task<int> RevokeFamilyAsync(Guid familyId, DateTimeOffset now, CancellationToken cancellationToken = default) => Inner.RevokeFamilyAsync(familyId, now, cancellationToken);
    public Task<int> RevokeForUserClientAsync(string userId, string clientId, DateTimeOffset now, CancellationToken cancellationToken = default) => Inner.RevokeForUserClientAsync(userId, clientId, now, cancellationToken);
    public Task<int> RevokeForUserAsync(string userId, DateTimeOffset now, CancellationToken cancellationToken = default) => Inner.RevokeForUserAsync(userId, now, cancellationToken);
    public Task<OAuthRefreshFamily?> GetFamilyAsync(Guid familyId, CancellationToken cancellationToken = default) => Inner.GetFamilyAsync(familyId, cancellationToken);
    public Task EnsureFamilyAsync(OAuthRefreshFamily family, CancellationToken cancellationToken = default) => Inner.EnsureFamilyAsync(family, cancellationToken);
    public Task<int> CleanupExpiredAsync(DateTimeOffset cutoff, CancellationToken cancellationToken = default) => Inner.CleanupExpiredAsync(cutoff, cancellationToken);
}

public sealed class FakeUserValidator : IOAuthUserValidator
{
    public HashSet<string> Inactive { get; } = new();
    public Task<bool> IsActiveAsync(string userId, CancellationToken cancellationToken = default) => Task.FromResult(!Inactive.Contains(userId));
}

public sealed class ThrowingFetcher : IClientMetadataFetcher
{
    public int Calls;
    public Task<ClientMetadataFetchResult> FetchAsync(Uri url, CancellationToken cancellationToken = default)
    {
        Interlocked.Increment(ref Calls);
        throw new IOException("connection reset");
    }
}

public sealed class StubHandler : HttpMessageHandler
{
    private readonly Func<HttpRequestMessage, Task<HttpResponseMessage>> _send;
    public StubHandler(Func<HttpRequestMessage, Task<HttpResponseMessage>> send) => _send = send;
    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) => _send(request);
}

public class DynamicClientRedirectTests
{
    private static async Task<string> RegisterAsync(OAuthTestHost host, string redirect = "https://a.example/cb")
    {
        var r = await host.Client.PostAsync(OAuthServerPaths.Register, new StringContent("{\"redirect_uris\":[\"" + redirect + "\"]}", Encoding.UTF8, "application/json"));
        return (await OAuthTestHost.ToResult(r)).Str("client_id")!;
    }

    [Theory]
    [InlineData("code_challenge", null)]
    [InlineData("code_challenge_method", "plain")]
    [InlineData("response_type", "token")]
    [InlineData("resource", "https://evil.example.com/mcp")]
    [InlineData("scope", "admin")]
    public async Task Dynamic_client_validation_errors_are_a_plain_400_never_a_redirect(string key, string? value)
    {
        await using var host = await OAuthTestHost.StartAsync();
        var id = await RegisterAsync(host);
        var q = OAuthTestHost.BaseQuery(OAuthTestHost.NewPkce().Challenge, id, "https://a.example/cb");
        q[key] = value;

        var r = await host.AuthorizeAsync(q);
        r.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        r.Headers.Location.Should().BeNull();
    }

    [Theory]
    [InlineData("code_challenge", null)]
    [InlineData("resource", "https://evil.example.com/mcp")]
    public async Task Metadata_document_client_validation_errors_are_a_plain_400(string key, string? value)
    {
        await using var host = await OAuthTestHost.StartAsync();
        const string url = "https://app.example.org/client.json";
        host.Fetcher.Responses[url] = ClientMetadataFetchResult.Ok("{\"client_id\":\"" + url + "\",\"redirect_uris\":[\"https://app.example.org/cb\"]}", null);
        var q = OAuthTestHost.BaseQuery(OAuthTestHost.NewPkce().Challenge, url, "https://app.example.org/cb");
        q[key] = value;

        var r = await host.AuthorizeAsync(q);
        r.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        r.Headers.Location.Should().BeNull();
    }

    [Fact]
    public async Task A_dynamic_clients_user_denial_still_redirects_with_access_denied()
    {
        await using var host = await OAuthTestHost.StartAsync();
        var id = await RegisterAsync(host);
        var pending = await host.StartRequestAsync(OAuthTestHost.BaseQuery(OAuthTestHost.NewPkce().Challenge, id, "https://a.example/cb"));
        var back = OAuthTestHost.QueryOf(OAuthTestHost.Absolute(await host.ConsentAsync(pending, "deny")));
        back["error"].Should().Be("access_denied");
        back["iss"].Should().Be(OAuthTestHost.Issuer);
    }
}

public class ConsentBindingTests
{
    [Fact]
    public async Task Authorize_sets_a_host_prefixed_secure_httponly_lax_cookie_that_hides_the_id()
    {
        await using var host = await OAuthTestHost.StartAsync();
        var (_, challenge) = OAuthTestHost.NewPkce();
        var r = await host.AuthorizeAsync(OAuthTestHost.BaseQuery(challenge));
        var id = OAuthTestHost.QueryOf(OAuthTestHost.Absolute(r))["request"];

        var set = r.Headers.GetValues("Set-Cookie").Single(c => c.StartsWith(OAuthTestHost.CookieName + "=")).ToLowerInvariant();
        set.Should().Contain("secure").And.Contain("httponly").And.Contain("samesite=lax").And.Contain("path=/");
        set.Should().NotContain("domain=");
        set.Should().NotContain(id.ToLowerInvariant());
        OAuthServerPaths.ConsentBindingCookie.Should().Be(OAuthTestHost.CookieName);
    }

    [Fact]
    public async Task Approve_without_the_cookie_is_refused_and_leaves_the_request_usable()
    {
        await using var host = await OAuthTestHost.StartAsync();
        var id = await host.StartRequestAsync(OAuthTestHost.BaseQuery(OAuthTestHost.NewPkce().Challenge));

        (await host.ConsentAsync(id, sendCookie: false)).StatusCode.Should().Be(HttpStatusCode.Gone);
        (await host.ConsentAsync(id, "deny", sendCookie: false)).StatusCode.Should().Be(HttpStatusCode.Gone);
        (await host.ConsentAsync(id)).StatusCode.Should().Be(HttpStatusCode.Found);
    }

    [Fact]
    public async Task A_cookie_bound_to_another_request_does_not_authorize_this_one()
    {
        await using var host = await OAuthTestHost.StartAsync();
        var victim = await host.StartRequestAsync(OAuthTestHost.BaseQuery(OAuthTestHost.NewPkce().Challenge));
        var victimCookie = host.Cookie;

        await using var other = await OAuthTestHost.StartAsync();
        await other.StartRequestAsync(OAuthTestHost.BaseQuery(OAuthTestHost.NewPkce().Challenge));
        var attackerCookie = other.Cookie;

        (await host.ConsentAsync(victim, cookie: attackerCookie)).StatusCode.Should().Be(HttpStatusCode.Gone);
        (await host.ConsentAsync(victim, cookie: victimCookie)).StatusCode.Should().Be(HttpStatusCode.Found);
    }

    [Fact]
    public async Task Two_pending_requests_in_one_browser_are_both_approvable_and_the_cookie_shrinks()
    {
        await using var host = await OAuthTestHost.StartAsync();
        var a = await host.StartRequestAsync(OAuthTestHost.BaseQuery(OAuthTestHost.NewPkce().Challenge));
        var b = await host.StartRequestAsync(OAuthTestHost.BaseQuery(OAuthTestHost.NewPkce().Challenge));

        (await host.ConsentAsync(a)).StatusCode.Should().Be(HttpStatusCode.Found);
        host.Cookie.Should().NotBeNull();
        (await host.ConsentAsync(b)).StatusCode.Should().Be(HttpStatusCode.Found);
        host.Cookie.Should().BeNull("the last binding is removed with the request");
    }

    [Fact]
    public async Task Auto_approve_also_requires_the_binding()
    {
        await using var host = await OAuthTestHost.StartAsync(o => o.RememberConsent = true);
        await host.LoginAsync(user: "alice");
        var id = await host.StartRequestAsync(OAuthTestHost.BaseQuery(OAuthTestHost.NewPkce().Challenge));

        (await host.ConsentAsync(id, "auto", "alice", sendCookie: false)).StatusCode.Should().Be(HttpStatusCode.NoContent);
        (await host.ConsentAsync(id, "auto", "alice")).StatusCode.Should().Be(HttpStatusCode.Found);
    }
}

public class TokenConfusionTests
{
    [Fact]
    public async Task Access_tokens_carry_the_at_jwt_type_header()
    {
        await using var host = await OAuthTestHost.StartAsync();
        var t = await host.LoginAsync();
        OAuthTestHost.Jwt(t.Access).Header.Typ.Should().Be("at+jwt");
    }

    [Fact]
    public void A_protected_resource_equal_to_the_first_party_audience_is_refused()
    {
        var o = new OAuthServerOptions { Issuer = "https://auth.example.com" };
        o.ProtectedResources.Add("https://mcp.example.com/mcp");
        o.Scopes.Add("a");
        OAuthServerServiceCollectionExtensions.Validate(o, "https://other.example.com").Should().BeNull();
        OAuthServerServiceCollectionExtensions.Validate(o, "https://mcp.example.com/mcp").Should().NotBeNull();
    }

    [Fact]
    public async Task Startup_fails_when_a_resource_equals_the_configured_jwt_audience()
    {
        var act = () => OAuthTestHost.StartAsync(o => o.ProtectedResources.Add("https://first-party.example.com"),
            services: s => s.PostConfigure<AuthOptions>(a => a.Jwt.Audience = "https://first-party.example.com"));
        await act.Should().ThrowAsync<Exception>();
    }

    private static Task<OAuthTestHost> ResourceServerHost() => OAuthTestHost.StartAsync(
        services: s => s.AddAuthentication().AddTechTeaStudioOAuthResourceServer("mcp", OAuthTestHost.Resource));

    private static async Task<HttpStatusCode> CallAsync(OAuthTestHost host, string token)
    {
        using var req = new HttpRequestMessage(HttpMethod.Get, "/mcp");
        req.Headers.Authorization = new("Bearer", token);
        return (await host.Client.SendAsync(req)).StatusCode;
    }

    [Fact]
    public async Task The_resource_server_scheme_accepts_a_token_issued_for_its_resource()
    {
        await using var host = await ResourceServerHost();
        var t = await host.LoginAsync();
        (await CallAsync(host, t.Access)).Should().Be(HttpStatusCode.OK);
    }

    [Fact]
    public async Task The_resource_server_scheme_rejects_a_token_for_another_resource()
    {
        await using var host = await ResourceServerHost();
        var (verifier, challenge) = OAuthTestHost.NewPkce();
        var q = OAuthTestHost.BaseQuery(challenge);
        q["resource"] = OAuthTestHost.Resource2;
        var code = OAuthTestHost.QueryOf(OAuthTestHost.Absolute(await host.ConsentAsync(await host.StartRequestAsync(q))))["code"];
        var t = await host.ExchangeAsync(code, verifier, OAuthTestHost.ClaudeRedirect, resource: null);
        (await CallAsync(host, t.Str("access_token")!)).Should().Be(HttpStatusCode.Unauthorized);
    }

    [Fact]
    public async Task The_resource_server_scheme_rejects_a_first_party_token_without_the_at_jwt_type()
    {
        await using var host = await ResourceServerHost();
        var provider = host.Host.Services.GetRequiredService<ITokenProvider>();
        var plain = provider.CreateToken("u", Array.Empty<Claim>(), new TokenDescriptor { Audience = OAuthTestHost.Resource, Issuer = OAuthTestHost.Issuer });
        (await CallAsync(host, plain)).Should().Be(HttpStatusCode.Unauthorized);

        var typed = provider.CreateToken("u", Array.Empty<Claim>(), new TokenDescriptor { Audience = OAuthTestHost.Resource, Issuer = OAuthTestHost.Issuer, TokenType = "at+jwt" });
        (await CallAsync(host, typed)).Should().Be(HttpStatusCode.OK);
    }

    [Fact]
    public async Task The_resource_server_scheme_rejects_a_foreign_issuer()
    {
        await using var host = await ResourceServerHost();
        var provider = host.Host.Services.GetRequiredService<ITokenProvider>();
        var evil = provider.CreateToken("u", Array.Empty<Claim>(), new TokenDescriptor { Audience = OAuthTestHost.Resource, Issuer = "https://evil.example.com", TokenType = "at+jwt" });
        (await CallAsync(host, evil)).Should().Be(HttpStatusCode.Unauthorized);
    }
}

public class UserStateTests
{
    [Fact]
    public async Task An_inactive_user_cannot_exchange_a_code()
    {
        var users = new FakeUserValidator();
        await using var host = await OAuthTestHost.StartAsync(services: s => s.AddSingleton<IOAuthUserValidator>(users));
        var (code, verifier, redirect) = await host.ApproveAsync(user: "mallory");
        users.Inactive.Add("mallory");

        var t = await host.ExchangeAsync(code, verifier, redirect);
        t.Status.Should().Be(HttpStatusCode.BadRequest);
        t.Str("error").Should().Be("invalid_grant");
    }

    [Fact]
    public async Task An_inactive_user_loses_the_refresh_family_for_good()
    {
        var users = new FakeUserValidator();
        await using var host = await OAuthTestHost.StartAsync(services: s => s.AddSingleton<IOAuthUserValidator>(users));
        var t = await host.LoginAsync(user: "mallory");
        var r1 = await host.RefreshAsync(t.Refresh);
        r1.Status.Should().Be(HttpStatusCode.OK);

        users.Inactive.Add("mallory");
        (await host.RefreshAsync(r1.Str("refresh_token")!)).Str("error").Should().Be("invalid_grant");

        users.Inactive.Clear();
        (await host.RefreshAsync(r1.Str("refresh_token")!)).Str("error").Should().Be("invalid_grant", "the family was revoked, not just refused");
        host.Audit.Snapshot().OfType<OAuthFamilyBurnedEvent>().Should().Contain(e => e.Reason == "user_inactive");
    }

    [Fact]
    public async Task RevokeAll_removes_every_grant_and_family_of_the_user_only()
    {
        await using var host = await OAuthTestHost.StartAsync();
        var a1 = await host.LoginAsync(OAuthTestHost.ClientId, user: "alice");
        var a2 = await host.LoginAsync(OAuthTestHost.ConfidentialClientId, OAuthTestHost.ConfidentialRedirect, user: "alice");
        var bob = await host.LoginAsync(user: "bob");

        using (var scope = host.Scope())
        {
            var svc = scope.ServiceProvider.GetRequiredService<IOAuthGrantService>();
            (await svc.RevokeAllAsync("alice")).Should().Be(2);
            (await svc.ListForUserAsync("alice")).Should().BeEmpty();
        }

        (await host.RefreshAsync(a1.Refresh)).Str("error").Should().Be("invalid_grant");
        var conf = await host.PostFormAsync(OAuthServerPaths.Token, new Dictionary<string, string>
        {
            ["grant_type"] = "refresh_token", ["refresh_token"] = a2.Refresh, ["client_id"] = OAuthTestHost.ConfidentialClientId, ["client_secret"] = "s3cret",
        });
        conf.Str("error").Should().Be("invalid_grant");
        (await host.RefreshAsync(bob.Refresh)).Status.Should().Be(HttpStatusCode.OK);
    }

    [Fact]
    public async Task The_family_has_an_absolute_lifetime_that_sliding_refresh_cannot_extend()
    {
        await using var host = await OAuthTestHost.StartAsync();
        var t = await host.LoginAsync();
        var refresh = t.Refresh;
        for (var day = 20; day <= 80; day += 20)
        {
            host.Time.Advance(TimeSpan.FromDays(20));
            var r = await host.RefreshAsync(refresh);
            r.Status.Should().Be(HttpStatusCode.OK, $"day {day} is inside the 90 day window");
            refresh = r.Str("refresh_token")!;
        }

        host.Time.Advance(TimeSpan.FromDays(20));
        var late = await host.RefreshAsync(refresh);
        late.Status.Should().Be(HttpStatusCode.BadRequest);
        late.Str("error").Should().Be("invalid_grant");
    }

    [Fact]
    public async Task The_absolute_lifetime_is_configurable()
    {
        await using var host = await OAuthTestHost.StartAsync(o => o.RefreshFamilyAbsoluteLifetime = TimeSpan.FromDays(2));
        var t = await host.LoginAsync();
        host.Time.Advance(TimeSpan.FromDays(3));
        (await host.RefreshAsync(t.Refresh)).Str("error").Should().Be("invalid_grant");
    }
}

public class RevocationRaceTests
{
    [Fact]
    public async Task Disconnecting_during_a_refresh_leaves_no_live_successor()
    {
        var racing = new RacingRefreshStore(new InMemoryOAuthRefreshTokenStore());
        await using var host = await OAuthTestHost.StartAsync(services: s => s.AddSingleton<IOAuthRefreshTokenStore>(racing));
        var t = await host.LoginAsync(user: "alice");

        OAuthRefreshToken? successor = null;
        racing.BeforeCreate = async tok =>
        {
            successor = tok;
            racing.BeforeCreate = null;
            using var scope = host.Scope();
            await scope.ServiceProvider.GetRequiredService<IOAuthGrantService>().RevokeAsync("alice", OAuthTestHost.ClientId);
        };

        var r = await host.RefreshAsync(t.Refresh);

        r.Str("error").Should().Be("invalid_grant");
        successor.Should().NotBeNull();
        (await racing.GetByHashAsync(successor!.TokenHash))!.RevokedAt.Should().NotBeNull();
    }

    [Fact]
    public async Task A_replay_racing_the_first_exchange_leaves_no_live_tokens()
    {
        var racing = new RacingRefreshStore(new InMemoryOAuthRefreshTokenStore());
        await using var host = await OAuthTestHost.StartAsync(services: s => s.AddSingleton<IOAuthRefreshTokenStore>(racing));
        var (code, verifier, redirect) = await host.ApproveAsync();

        OAuthRefreshToken? first = null;
        FormResult? replay = null;
        racing.BeforeCreate = async tok =>
        {
            first = tok;
            racing.BeforeCreate = null;
            replay = await host.ExchangeAsync(code, verifier, redirect);
        };

        var a = await host.ExchangeAsync(code, verifier, redirect);

        replay!.Str("error").Should().Be("invalid_grant");
        a.Str("error").Should().Be("invalid_grant");
        (await racing.GetByHashAsync(first!.TokenHash))!.RevokedAt.Should().NotBeNull();
    }

    [Fact]
    public async Task Revoking_a_family_before_its_first_token_exists_still_marks_the_family()
    {
        var store = new InMemoryOAuthRefreshTokenStore();
        var family = Guid.NewGuid();
        await store.RevokeFamilyAsync(family, DateTimeOffset.UnixEpoch);
        (await store.GetFamilyAsync(family))!.RevokedAt.Should().NotBeNull();

        await store.EnsureFamilyAsync(new OAuthRefreshFamily { FamilyId = family, UserId = "u", ClientId = "c" });
        (await store.GetFamilyAsync(family))!.RevokedAt.Should().NotBeNull("ensure never un-revokes");
    }
}

public class CodeBindingOrderTests
{
    [Fact]
    public async Task A_replay_with_the_wrong_verifier_does_not_burn_the_family()
    {
        await using var host = await OAuthTestHost.StartAsync();
        var (code, verifier, redirect) = await host.ApproveAsync();
        var first = await host.ExchangeAsync(code, verifier, redirect);

        (await host.ExchangeAsync(code, OAuthTestHost.NewPkce().Verifier, redirect)).Str("error").Should().Be("invalid_grant");
        (await host.ExchangeAsync(code, verifier, OAuthTestHost.ChatGptRedirect)).Str("error").Should().Be("invalid_grant");

        (await host.RefreshAsync(first.Str("refresh_token")!)).Status.Should().Be(HttpStatusCode.OK);
        host.Audit.Snapshot().OfType<OAuthCodeReplayedEvent>().Should().BeEmpty();
    }

    [Fact]
    public async Task A_replay_by_another_client_does_not_burn_the_family()
    {
        await using var host = await OAuthTestHost.StartAsync(o =>
            o.Clients.Add(new OAuthClientOptions { ClientId = "other", RedirectUris = { OAuthTestHost.ClaudeRedirect } }));
        var (code, verifier, redirect) = await host.ApproveAsync();
        var first = await host.ExchangeAsync(code, verifier, redirect);

        (await host.ExchangeAsync(code, verifier, redirect, clientId: "other")).Str("error").Should().Be("invalid_grant");
        (await host.RefreshAsync(first.Str("refresh_token")!)).Status.Should().Be(HttpStatusCode.OK);
    }

    [Fact]
    public async Task A_replay_that_passes_the_binding_checks_burns_the_family_even_after_the_code_expired()
    {
        await using var host = await OAuthTestHost.StartAsync();
        var (code, verifier, redirect) = await host.ApproveAsync();
        var first = await host.ExchangeAsync(code, verifier, redirect);
        host.Time.Advance(TimeSpan.FromMinutes(5));

        (await host.ExchangeAsync(code, verifier, redirect)).Str("error").Should().Be("invalid_grant");
        (await host.RefreshAsync(first.Str("refresh_token")!)).Str("error").Should().Be("invalid_grant");
    }

    [Fact]
    public async Task A_resource_mismatch_does_not_consume_the_code()
    {
        await using var host = await OAuthTestHost.StartAsync();
        var (code, verifier, redirect) = await host.ApproveAsync();
        (await host.ExchangeAsync(code, verifier, redirect, resource: OAuthTestHost.Resource2)).Str("error").Should().Be("invalid_target");
        (await host.ExchangeAsync(code, verifier, redirect)).Status.Should().Be(HttpStatusCode.OK);
    }
}

public class UnboundedWriteTests
{
    private static Task<HttpResponseMessage> Post(OAuthTestHost host, string json) =>
        host.Client.PostAsync(OAuthServerPaths.Register, new StringContent(json, Encoding.UTF8, "application/json"));

    [Fact]
    public async Task At_most_five_redirect_uris_are_accepted()
    {
        await using var host = await OAuthTestHost.StartAsync();
        string Body(int n) => "{\"redirect_uris\":[" + string.Join(',', Enumerable.Range(0, n).Select(i => $"\"https://a.example/cb{i}\"")) + "]}";
        (await Post(host, Body(5))).StatusCode.Should().Be(HttpStatusCode.Created);
        (await Post(host, Body(6))).StatusCode.Should().Be(HttpStatusCode.BadRequest);
    }

    [Fact]
    public async Task A_redirect_uri_is_capped_at_512_characters()
    {
        await using var host = await OAuthTestHost.StartAsync();
        string Body(int len) => "{\"redirect_uris\":[\"https://a.example/" + new string('p', len - "https://a.example/".Length) + "\"]}";
        (await Post(host, Body(512))).StatusCode.Should().Be(HttpStatusCode.Created);
        (await Post(host, Body(513))).StatusCode.Should().Be(HttpStatusCode.BadRequest);
    }

    [Fact]
    public async Task Dynamic_clients_record_last_use_at_most_hourly()
    {
        await using var host = await OAuthTestHost.StartAsync();
        var id = (await OAuthTestHost.ToResult(await Post(host, "{\"redirect_uris\":[\"https://a.example/cb\"]}"))).Str("client_id")!;
        var query = () => OAuthTestHost.BaseQuery(OAuthTestHost.NewPkce().Challenge, id, "https://a.example/cb");

        async Task<DateTimeOffset?> LastUsed()
        {
            using var scope = host.Scope();
            return (await scope.ServiceProvider.GetRequiredService<IOAuthClientStore>().FindAsync(id))!.LastUsedAt;
        }

        (await LastUsed()).Should().BeNull();
        var t0 = host.Time.GetUtcNow();
        await host.AuthorizeAsync(query());
        (await LastUsed()).Should().Be(t0);

        host.Time.Advance(TimeSpan.FromMinutes(30));
        await host.AuthorizeAsync(query());
        (await LastUsed()).Should().Be(t0);

        host.Time.Advance(TimeSpan.FromMinutes(31));
        await host.AuthorizeAsync(query());
        (await LastUsed()).Should().Be(host.Time.GetUtcNow());
    }

    [Fact]
    public async Task Cleanup_deletes_only_dynamic_clients_that_are_unused_and_have_no_grants()
    {
        await using var host = await OAuthTestHost.StartAsync();
        async Task<string> Reg() => (await OAuthTestHost.ToResult(await Post(host, "{\"redirect_uris\":[\"https://a.example/cb\"]}"))).Str("client_id")!;
        var idle = await Reg();
        var granted = await Reg();
        var recent = await Reg();
        await host.LoginAsync(granted, "https://a.example/cb");

        host.Time.Advance(TimeSpan.FromDays(40));
        await host.AuthorizeAsync(OAuthTestHost.BaseQuery(OAuthTestHost.NewPkce().Challenge, recent, "https://a.example/cb"));

        using var scope = host.Scope();
        var store = scope.ServiceProvider.GetRequiredService<IOAuthClientStore>();
        (await store.CleanupUnusedAsync(host.Time.GetUtcNow() - TimeSpan.FromDays(30))).Should().Be(1);

        (await store.FindAsync(idle)).Should().BeNull();
        (await store.FindAsync(granted)).Should().NotBeNull();
        (await store.FindAsync(recent)).Should().NotBeNull();
    }

    [Fact]
    public async Task Live_pending_requests_per_client_are_capped()
    {
        await using var host = await OAuthTestHost.StartAsync(o => o.MaxPendingRequestsPerClient = 3);
        var reg = (await OAuthTestHost.ToResult(await Post(host, "{\"redirect_uris\":[\"https://a.example/cb\"]}"))).Str("client_id")!;
        for (var i = 0; i < 3; i++)
            (await host.AuthorizeAsync(OAuthTestHost.BaseQuery(OAuthTestHost.NewPkce().Challenge, reg, "https://a.example/cb"))).StatusCode.Should().Be(HttpStatusCode.Found);

        var over = await host.AuthorizeAsync(OAuthTestHost.BaseQuery(OAuthTestHost.NewPkce().Challenge, reg, "https://a.example/cb"));
        over.StatusCode.Should().Be(HttpStatusCode.BadRequest);

        host.Time.Advance(TimeSpan.FromMinutes(11));
        (await host.AuthorizeAsync(OAuthTestHost.BaseQuery(OAuthTestHost.NewPkce().Challenge, reg, "https://a.example/cb"))).StatusCode.Should().Be(HttpStatusCode.Found);
    }

    [Fact]
    public async Task A_preregistered_client_over_the_pending_cap_gets_a_redirect_error()
    {
        await using var host = await OAuthTestHost.StartAsync(o => o.MaxPendingRequestsPerClient = 1);
        await host.AuthorizeAsync(OAuthTestHost.BaseQuery(OAuthTestHost.NewPkce().Challenge));
        var over = await host.AuthorizeAsync(OAuthTestHost.BaseQuery(OAuthTestHost.NewPkce().Challenge));
        over.StatusCode.Should().Be(HttpStatusCode.Found);
        OAuthTestHost.QueryOf(OAuthTestHost.Absolute(over))["error"].Should().Be("temporarily_unavailable");
    }

    [Fact]
    public async Task The_named_rate_limit_policy_constant_is_applied_through_the_convention_builder()
    {
        OAuthServerPaths.RateLimitPolicy.Should().NotBeNullOrEmpty();
        await using var host = await OAuthTestHost.StartAsync();
        var marked = host.Host.Services.GetRequiredService<Microsoft.AspNetCore.Routing.EndpointDataSource>().Endpoints
            .Count(e => e.Metadata.GetMetadata<OAuthTestHost.EndpointMarker>() is not null);
        marked.Should().Be(5, "metadata, authorize, token, revoke and register all receive conventions");
    }
}

public class ConsentSpoofingTests
{
    [Fact]
    public void Format_characters_and_separators_are_stripped_from_display_text()
    {
        var dirty = "Cla" + (char)0x202E + "ude" + (char)0x200B + (char)0x200D + (char)0xFEFF + " App" + (char)0x2028;
        ClientMetadataParser.CleanText(dirty, 100).Should().Be("Claude App");
    }

    private static async Task<System.Text.Json.JsonElement> Pending(OAuthTestHost host, string clientId, string redirect)
    {
        var id = await host.StartRequestAsync(OAuthTestHost.BaseQuery(OAuthTestHost.NewPkce().Challenge, clientId, redirect));
        return (await OAuthTestHost.ToResult(await host.Client.GetAsync("/oauth/pending?request=" + id))).Json;
    }

    [Fact]
    public async Task The_logo_is_shown_only_for_preregistered_clients()
    {
        await using var host = await OAuthTestHost.StartAsync(o =>
            o.Clients.First(c => c.ClientId == OAuthTestHost.ClientId).LogoUri = "https://test.example/logo.png");
        const string url = "https://app.example.org/client.json";
        host.Fetcher.Responses[url] = ClientMetadataFetchResult.Ok(
            "{\"client_id\":\"" + url + "\",\"redirect_uris\":[\"https://app.example.org/cb\"],\"logo_uri\":\"https://app.example.org/logo.png\"}", null);

        (await Pending(host, OAuthTestHost.ClientId, OAuthTestHost.ClaudeRedirect)).GetProperty("ClientLogoUri").GetString().Should().Be("https://test.example/logo.png");
        (await Pending(host, url, "https://app.example.org/cb")).GetProperty("ClientLogoUri").ValueKind.Should().Be(System.Text.Json.JsonValueKind.Null);
    }

    [Fact]
    public async Task Metadata_document_clients_expose_the_client_id_host_and_an_origin_mismatch_flag()
    {
        await using var host = await OAuthTestHost.StartAsync();
        const string url = "https://app.example.org/client.json";
        host.Fetcher.Responses[url] = ClientMetadataFetchResult.Ok(
            "{\"client_id\":\"" + url + "\",\"redirect_uris\":[\"https://app.example.org/cb\",\"https://elsewhere.example.net/cb\"]}", null);

        var same = await Pending(host, url, "https://app.example.org/cb");
        same.GetProperty("ClientIdHost").GetString().Should().Be("app.example.org");
        same.GetProperty("RedirectOriginDiffersFromClientId").GetBoolean().Should().BeFalse();

        var different = await Pending(host, url, "https://elsewhere.example.net/cb");
        different.GetProperty("RedirectOriginDiffersFromClientId").GetBoolean().Should().BeTrue();

        var pre = await Pending(host, OAuthTestHost.ClientId, OAuthTestHost.ClaudeRedirect);
        pre.GetProperty("ClientIdHost").ValueKind.Should().Be(System.Text.Json.JsonValueKind.Null);
        pre.GetProperty("RedirectOriginDiffersFromClientId").GetBoolean().Should().BeFalse();
    }
}

public class FetcherHardeningTests
{
    private static HttpClientMetadataFetcher Fetcher(Func<HttpRequestMessage, Task<HttpResponseMessage>> send, Action<OAuthServerOptions>? cfg = null)
    {
        var o = new OAuthServerOptions();
        cfg?.Invoke(o);
        return new HttpClientMetadataFetcher(Options.Create(o), new StubHandler(send));
    }

    private static HttpResponseMessage Json(string body) =>
        new(HttpStatusCode.OK) { Content = new StringContent(body, Encoding.UTF8, "application/json") };

    [Theory]
    [InlineData("https://example.com:8443/client.json")]
    [InlineData("https://example.com:80/client.json")]
    public async Task Only_port_443_is_fetched(string url)
    {
        var calls = 0;
        using var f = Fetcher(_ => { calls++; return Task.FromResult(Json("{}")); });
        var r = await f.FetchAsync(new Uri(url));
        r.Error.Should().Be("port_not_allowed");
        calls.Should().Be(0);
    }

    [Fact]
    public async Task Port_443_succeeds_through_the_handler()
    {
        using var f = Fetcher(_ => Task.FromResult(Json("{\"a\":1}")));
        (await f.FetchAsync(new Uri("https://example.com/client.json"))).Succeeded.Should().BeTrue();
    }

    [Theory]
    [InlineData(typeof(IOException))]
    [InlineData(typeof(HttpRequestException))]
    [InlineData(typeof(InvalidOperationException))]
    public async Task Transport_exceptions_are_fetch_failures_never_exceptions(Type exception)
    {
        using var f = Fetcher(_ => throw (Exception)Activator.CreateInstance(exception, "boom")!);
        var r = await f.FetchAsync(new Uri("https://example.com/client.json"));
        r.Succeeded.Should().BeFalse();
        r.Error.Should().NotBeNullOrEmpty();
    }

    [Fact]
    public async Task A_connection_reset_while_reading_the_body_is_a_fetch_failure()
    {
        using var f = Fetcher(_ => Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StreamContent(new ThrowingStream()) { Headers = { ContentType = new("application/json") } },
        }));
        (await f.FetchAsync(new Uri("https://example.com/client.json"))).Succeeded.Should().BeFalse();
    }

    private sealed class ThrowingStream : Stream
    {
        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => 0; set => throw new NotSupportedException(); }
        public override void Flush() { }
        public override int Read(byte[] buffer, int offset, int count) => throw new IOException("reset");
        public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) => throw new IOException("reset");
        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default) => throw new IOException("reset");
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }

    [Fact]
    public async Task At_most_four_fetches_run_at_once()
    {
        var current = 0;
        var peak = 0;
        using var f = Fetcher(async _ =>
        {
            var now = Interlocked.Increment(ref current);
            int seen;
            while ((seen = Volatile.Read(ref peak)) < now && Interlocked.CompareExchange(ref peak, now, seen) != seen) { }
            await Task.Delay(100);
            Interlocked.Decrement(ref current);
            return Json("{}");
        }, o => o.ClientMetadataFetchTimeout = TimeSpan.FromSeconds(30));

        var results = await Task.WhenAll(Enumerable.Range(0, 12).Select(i => f.FetchAsync(new Uri($"https://example.com/c{i}.json"))));
        results.Should().OnlyContain(r => r.Succeeded);
        peak.Should().BeLessThanOrEqualTo(4).And.BeGreaterThan(1);
    }

    [Fact]
    public async Task A_throwing_custom_fetcher_is_a_400_and_is_negatively_cached()
    {
        var throwing = new ThrowingFetcher();
        await using var host = await OAuthTestHost.StartAsync(services: s => s.AddSingleton<IClientMetadataFetcher>(throwing));
        const string url = "https://app.example.org/client.json";
        var q = () => OAuthTestHost.BaseQuery(OAuthTestHost.NewPkce().Challenge, url, "https://app.example.org/cb");

        (await host.AuthorizeAsync(q())).StatusCode.Should().Be(HttpStatusCode.BadRequest);
        (await host.AuthorizeAsync(q())).StatusCode.Should().Be(HttpStatusCode.BadRequest);
        throwing.Calls.Should().Be(1);
    }

    [Fact]
    public async Task A_metadata_document_url_on_another_port_is_never_fetched()
    {
        await using var host = await OAuthTestHost.StartAsync();
        const string url = "https://app.example.org:8443/client.json";
        host.Fetcher.Responses[url] = ClientMetadataFetchResult.Ok("{}", null);
        var r = await host.AuthorizeAsync(OAuthTestHost.BaseQuery(OAuthTestHost.NewPkce().Challenge, url, "https://app.example.org/cb"));
        r.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        host.Fetcher.Requested.Should().BeEmpty();
    }

    [Theory]
    [InlineData("::1.2.3.4")]
    [InlineData("::8.8.8.8")]
    [InlineData("64:ff9b::808:808")]
    [InlineData("64:ff9b:1::1")]
    [InlineData("64:ff9b:1:ffff::1")]
    [InlineData("2002:7f00:1::")]
    [InlineData("2002:808:808::")]
    [InlineData("2001::1")]
    [InlineData("100::1")]
    [InlineData("::ffff:0:808:808")]
    [InlineData("3fff::1")]
    [InlineData("192.88.99.1")]
    public void More_non_public_ranges_are_refused(string ip) =>
        OutboundAddressPolicy.IsPublic(IPAddress.Parse(ip)).Should().BeFalse();

    [Theory]
    [InlineData("2a00:1450:4001::1")]
    [InlineData("2606:4700::1")]
    [InlineData("64:ff9a::1")]
    public void Ordinary_global_addresses_stay_allowed(string ip) =>
        OutboundAddressPolicy.IsPublic(IPAddress.Parse(ip)).Should().BeTrue();
}

public class RevocationAuthTests
{
    private static Task<FormResult> Revoke(OAuthTestHost host, string token, string? clientId, string? secret) =>
        host.PostFormAsync(OAuthServerPaths.Revoke, new Dictionary<string, string?> { ["token"] = token, ["client_id"] = clientId, ["client_secret"] = secret }
            .Where(kv => kv.Value is not null).ToDictionary(kv => kv.Key, kv => kv.Value!));

    private static Task<FormResult> RefreshConf(OAuthTestHost host, string refresh) =>
        host.PostFormAsync(OAuthServerPaths.Token, new Dictionary<string, string>
        {
            ["grant_type"] = "refresh_token", ["refresh_token"] = refresh, ["client_id"] = OAuthTestHost.ConfidentialClientId, ["client_secret"] = "s3cret",
        });

    [Fact]
    public async Task A_confidential_client_revokes_with_its_secret()
    {
        await using var host = await OAuthTestHost.StartAsync();
        var t = await host.LoginAsync(OAuthTestHost.ConfidentialClientId, OAuthTestHost.ConfidentialRedirect);

        (await Revoke(host, t.Refresh, OAuthTestHost.ConfidentialClientId, "s3cret")).Status.Should().Be(HttpStatusCode.OK);
        (await RefreshConf(host, t.Refresh)).Str("error").Should().Be("invalid_grant");
    }

    [Fact]
    public async Task A_confidential_client_with_a_wrong_or_missing_secret_is_invalid_client_and_nothing_is_revoked()
    {
        await using var host = await OAuthTestHost.StartAsync();
        var t = await host.LoginAsync(OAuthTestHost.ConfidentialClientId, OAuthTestHost.ConfidentialRedirect);

        var wrong = await Revoke(host, t.Refresh, OAuthTestHost.ConfidentialClientId, "nope");
        wrong.Status.Should().Be(HttpStatusCode.Unauthorized);
        wrong.Str("error").Should().Be("invalid_client");
        (await Revoke(host, t.Refresh, OAuthTestHost.ConfidentialClientId, null)).Status.Should().Be(HttpStatusCode.Unauthorized);

        (await RefreshConf(host, t.Refresh)).Status.Should().Be(HttpStatusCode.OK);
    }

    [Fact]
    public async Task Without_a_client_id_a_confidential_clients_token_is_not_revoked()
    {
        await using var host = await OAuthTestHost.StartAsync();
        var t = await host.LoginAsync(OAuthTestHost.ConfidentialClientId, OAuthTestHost.ConfidentialRedirect);

        (await Revoke(host, t.Refresh, null, null)).Status.Should().Be(HttpStatusCode.OK);
        (await RefreshConf(host, t.Refresh)).Status.Should().Be(HttpStatusCode.OK);
    }

    [Fact]
    public async Task Another_authenticated_client_gets_200_but_revokes_nothing()
    {
        await using var host = await OAuthTestHost.StartAsync();
        var t = await host.LoginAsync(OAuthTestHost.ConfidentialClientId, OAuthTestHost.ConfidentialRedirect);

        (await Revoke(host, t.Refresh, OAuthTestHost.ConfidentialClientId2, "s3cret2")).Status.Should().Be(HttpStatusCode.OK);
        (await RefreshConf(host, t.Refresh)).Status.Should().Be(HttpStatusCode.OK);
    }

    [Fact]
    public async Task A_public_client_cannot_revoke_a_confidential_clients_token()
    {
        await using var host = await OAuthTestHost.StartAsync();
        var t = await host.LoginAsync(OAuthTestHost.ConfidentialClientId, OAuthTestHost.ConfidentialRedirect);
        (await Revoke(host, t.Refresh, OAuthTestHost.ClientId, null)).Status.Should().Be(HttpStatusCode.OK);
        (await RefreshConf(host, t.Refresh)).Status.Should().Be(HttpStatusCode.OK);
    }

    [Fact]
    public async Task An_unknown_client_id_on_revoke_is_invalid_client()
    {
        await using var host = await OAuthTestHost.StartAsync();
        (await Revoke(host, "x", "ghost", null)).Status.Should().Be(HttpStatusCode.Unauthorized);
    }
}

public class RefreshScopeTests
{
    [Fact]
    public async Task A_narrowed_refresh_does_not_shrink_the_grant_for_later_refreshes()
    {
        await using var host = await OAuthTestHost.StartAsync();
        var t = await host.LoginAsync();

        var narrow = await host.RefreshAsync(t.Refresh, scope: "tasks:read");
        narrow.Str("scope").Should().Be("tasks:read");
        OAuthTestHost.Jwt(narrow.Str("access_token")!).Claims.Single(c => c.Type == "scope").Value.Should().Be("tasks:read");

        var again = await host.RefreshAsync(narrow.Str("refresh_token")!);
        again.Str("scope").Should().Be("tasks:read tasks:write");

        var widenedByRequest = await host.RefreshAsync(again.Str("refresh_token")!, scope: "tasks:write");
        widenedByRequest.Str("scope").Should().Be("tasks:write");
    }
}
