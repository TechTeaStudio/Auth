using System.Net;
using FluentAssertions;
using Microsoft.Extensions.DependencyInjection;
using Xunit;
using TechTeaStudio.Auth.Observability;
using TechTeaStudio.Auth.OAuthServer;
using TechTeaStudio.Auth.OAuthServer.Abstractions;

namespace TechTeaStudio.Auth.Tests.OAuthServer;

public class AuthorizationCodeTests
{
    [Fact]
    public async Task Approve_redirect_carries_code_state_and_iss()
    {
        await using var host = await OAuthTestHost.StartAsync();
        var id = await host.StartRequestAsync(OAuthTestHost.BaseQuery(OAuthTestHost.NewPkce().Challenge));
        var r = await host.ConsentAsync(id);

        var loc = OAuthTestHost.Absolute(r);
        loc.GetLeftPart(UriPartial.Path).Should().Be(OAuthTestHost.ClaudeRedirect);
        var q = OAuthTestHost.QueryOf(loc);
        q["code"].Length.Should().BeGreaterThanOrEqualTo(43);
        q["state"].Should().Be("st-123");
        q["iss"].Should().Be(OAuthTestHost.Issuer);
    }

    [Fact]
    public async Task Deny_redirects_with_access_denied_state_and_iss()
    {
        await using var host = await OAuthTestHost.StartAsync();
        var id = await host.StartRequestAsync(OAuthTestHost.BaseQuery(OAuthTestHost.NewPkce().Challenge));
        var q = OAuthTestHost.QueryOf(OAuthTestHost.Absolute(await host.ConsentAsync(id, "deny")));

        q["error"].Should().Be("access_denied");
        q["state"].Should().Be("st-123");
        q["iss"].Should().Be(OAuthTestHost.Issuer);
        q.Should().NotContainKey("code");
        host.Audit.Snapshot().OfType<OAuthAuthorizeDeniedEvent>().Should().ContainSingle();
    }

    [Fact]
    public async Task A_pending_request_is_single_use()
    {
        await using var host = await OAuthTestHost.StartAsync();
        var id = await host.StartRequestAsync(OAuthTestHost.BaseQuery(OAuthTestHost.NewPkce().Challenge));

        (await host.ConsentAsync(id)).StatusCode.Should().Be(HttpStatusCode.Found);
        (await host.ConsentAsync(id)).StatusCode.Should().Be(HttpStatusCode.Gone);
        (await host.ConsentAsync(id, "deny")).StatusCode.Should().Be(HttpStatusCode.Gone);
    }

    [Fact]
    public async Task A_pending_request_expires_after_ten_minutes()
    {
        await using var host = await OAuthTestHost.StartAsync();
        var id = await host.StartRequestAsync(OAuthTestHost.BaseQuery(OAuthTestHost.NewPkce().Challenge));
        host.Time.Advance(TimeSpan.FromMinutes(10) + TimeSpan.FromSeconds(1));

        (await host.Client.GetAsync("/oauth/pending?request=" + id)).StatusCode.Should().Be(HttpStatusCode.NotFound);
        (await host.ConsentAsync(id)).StatusCode.Should().Be(HttpStatusCode.Gone);
    }

    [Fact]
    public async Task Exchange_issues_a_bearer_access_token_a_refresh_token_and_scope()
    {
        await using var host = await OAuthTestHost.StartAsync();
        var (code, verifier, redirect) = await host.ApproveAsync();
        var t = await host.ExchangeAsync(code, verifier, redirect);

        t.Status.Should().Be(HttpStatusCode.OK);
        t.Response.Headers.CacheControl!.NoStore.Should().BeTrue();
        t.Str("token_type").Should().Be("Bearer");
        t.Str("scope").Should().Be("tasks:read tasks:write");
        t.Json.GetProperty("expires_in").GetInt32().Should().Be(3600);
        t.Str("refresh_token").Should().NotBeNullOrEmpty();
    }

    [Fact]
    public async Task Access_token_is_bound_to_the_resource_issuer_user_client_and_scope()
    {
        await using var host = await OAuthTestHost.StartAsync();
        var tokens = await host.LoginAsync(user: "user-77");
        var jwt = OAuthTestHost.Jwt(tokens.Access);

        jwt.Audiences.Should().Equal(OAuthTestHost.Resource);
        jwt.Issuer.Should().Be(OAuthTestHost.Issuer);
        jwt.Subject.Should().Be("user-77");
        jwt.Claims.Single(c => c.Type == "client_id").Value.Should().Be(OAuthTestHost.ClientId);
        jwt.Claims.Single(c => c.Type == "scope").Value.Should().Be("tasks:read tasks:write");
        jwt.Id.Should().NotBeNullOrEmpty();
        (jwt.ValidTo - DateTime.UtcNow).Should().BeCloseTo(TimeSpan.FromMinutes(60), TimeSpan.FromSeconds(30));
    }

    [Fact]
    public async Task Token_audience_follows_the_requested_resource()
    {
        await using var host = await OAuthTestHost.StartAsync();
        var (verifier, challenge) = OAuthTestHost.NewPkce();
        var q = OAuthTestHost.BaseQuery(challenge);
        q["resource"] = OAuthTestHost.Resource2;
        var id = await host.StartRequestAsync(q);
        var code = OAuthTestHost.QueryOf(OAuthTestHost.Absolute(await host.ConsentAsync(id)))["code"];

        var t = await host.ExchangeAsync(code, verifier, OAuthTestHost.ClaudeRedirect, resource: OAuthTestHost.Resource2);
        OAuthTestHost.Jwt(t.Str("access_token")!).Audiences.Should().Equal(OAuthTestHost.Resource2);
    }

    [Fact]
    public async Task A_code_is_single_use_and_replay_revokes_the_tokens_issued_from_it()
    {
        await using var host = await OAuthTestHost.StartAsync();
        var (code, verifier, redirect) = await host.ApproveAsync();
        var first = await host.ExchangeAsync(code, verifier, redirect);
        first.Status.Should().Be(HttpStatusCode.OK);

        var replay = await host.ExchangeAsync(code, verifier, redirect);
        replay.Status.Should().Be(HttpStatusCode.BadRequest);
        replay.Str("error").Should().Be("invalid_grant");

        var refresh = await host.RefreshAsync(first.Str("refresh_token")!);
        refresh.Str("error").Should().Be("invalid_grant");
        host.Audit.Snapshot().OfType<OAuthCodeReplayedEvent>().Should().ContainSingle();
        host.Audit.Snapshot().OfType<OAuthFamilyBurnedEvent>().Should().Contain(e => e.Reason == "code_replay");
    }

    [Fact]
    public async Task A_code_expires_after_sixty_seconds()
    {
        await using var host = await OAuthTestHost.StartAsync();
        var (code, verifier, redirect) = await host.ApproveAsync();
        host.Time.Advance(TimeSpan.FromSeconds(61));

        var t = await host.ExchangeAsync(code, verifier, redirect);
        t.Status.Should().Be(HttpStatusCode.BadRequest);
        t.Str("error").Should().Be("invalid_grant");
    }

    [Fact]
    public async Task A_code_is_still_good_just_inside_its_lifetime()
    {
        await using var host = await OAuthTestHost.StartAsync();
        var (code, verifier, redirect) = await host.ApproveAsync();
        host.Time.Advance(TimeSpan.FromSeconds(59));
        (await host.ExchangeAsync(code, verifier, redirect)).Status.Should().Be(HttpStatusCode.OK);
    }

    [Fact]
    public async Task Wrong_pkce_verifier_fails_and_burns_the_code()
    {
        await using var host = await OAuthTestHost.StartAsync();
        var (code, verifier, redirect) = await host.ApproveAsync();
        var wrong = OAuthTestHost.NewPkce().Verifier;

        (await host.ExchangeAsync(code, wrong, redirect)).Str("error").Should().Be("invalid_grant");
        (await host.ExchangeAsync(code, verifier, redirect)).Str("error").Should().Be("invalid_grant");
    }

    [Fact]
    public async Task Malformed_verifier_fails()
    {
        await using var host = await OAuthTestHost.StartAsync();
        var (code, _, redirect) = await host.ApproveAsync();
        (await host.ExchangeAsync(code, "short", redirect)).Str("error").Should().Be("invalid_grant");
    }

    [Fact]
    public async Task Redirect_uri_must_match_the_authorization_request_exactly()
    {
        await using var host = await OAuthTestHost.StartAsync();
        var (code, verifier, _) = await host.ApproveAsync();
        (await host.ExchangeAsync(code, verifier, OAuthTestHost.ChatGptRedirect)).Str("error").Should().Be("invalid_grant");
    }

    [Fact]
    public async Task Another_client_cannot_redeem_the_code()
    {
        await using var host = await OAuthTestHost.StartAsync(o =>
            o.Clients.Add(new OAuthClientOptions { ClientId = "other", RedirectUris = { OAuthTestHost.ClaudeRedirect } }));
        var (code, verifier, redirect) = await host.ApproveAsync();
        (await host.ExchangeAsync(code, verifier, redirect, clientId: "other")).Str("error").Should().Be("invalid_grant");
    }

    [Fact]
    public async Task Resource_at_the_token_endpoint_must_equal_the_codes_resource()
    {
        await using var host = await OAuthTestHost.StartAsync();
        var (code, verifier, redirect) = await host.ApproveAsync();
        var t = await host.ExchangeAsync(code, verifier, redirect, resource: OAuthTestHost.Resource2);
        t.Status.Should().Be(HttpStatusCode.BadRequest);
        t.Str("error").Should().Be("invalid_target");
    }

    [Fact]
    public async Task Resource_may_be_omitted_at_the_token_endpoint()
    {
        await using var host = await OAuthTestHost.StartAsync();
        var (code, verifier, redirect) = await host.ApproveAsync();
        var t = await host.ExchangeAsync(code, verifier, redirect, resource: null);
        t.Status.Should().Be(HttpStatusCode.OK);
        OAuthTestHost.Jwt(t.Str("access_token")!).Audiences.Should().Equal(OAuthTestHost.Resource);
    }

    [Fact]
    public async Task Downscoping_narrows_the_issued_scope()
    {
        await using var host = await OAuthTestHost.StartAsync();
        var tokens = await host.LoginAsync(grant: "tasks:read");

        tokens.Scope.Should().Be("tasks:read");
        OAuthTestHost.Jwt(tokens.Access).Claims.Single(c => c.Type == "scope").Value.Should().Be("tasks:read");
    }

    [Fact]
    public async Task Granting_a_scope_that_was_not_requested_is_refused()
    {
        await using var host = await OAuthTestHost.StartAsync();
        var q = OAuthTestHost.BaseQuery(OAuthTestHost.NewPkce().Challenge);
        q["scope"] = "tasks:read";
        var id = await host.StartRequestAsync(q);

        using var scope = host.Scope();
        var svc = scope.ServiceProvider.GetRequiredService<IOAuthAuthorizationService>();
        var act = () => svc.ApproveAsync(id, "user-1", new[] { "tasks:read", "tasks:write" });
        await act.Should().ThrowAsync<ArgumentException>();
        var none = () => svc.ApproveAsync(id, "user-1", Array.Empty<string>());
        await none.Should().ThrowAsync<ArgumentException>();
        (await svc.GetPendingAsync(id)).Should().NotBeNull("a host bug must not burn the user's request");
    }

    [Fact]
    public async Task Approve_without_a_user_id_is_refused()
    {
        await using var host = await OAuthTestHost.StartAsync();
        var id = await host.StartRequestAsync(OAuthTestHost.BaseQuery(OAuthTestHost.NewPkce().Challenge));
        using var scope = host.Scope();
        var svc = scope.ServiceProvider.GetRequiredService<IOAuthAuthorizationService>();
        var act = () => svc.ApproveAsync(id, "");
        await act.Should().ThrowAsync<ArgumentException>();
    }

    [Fact]
    public async Task Audit_records_the_flow_and_never_a_secret()
    {
        await using var host = await OAuthTestHost.StartAsync();
        var (verifier, challenge) = OAuthTestHost.NewPkce();
        var id = await host.StartRequestAsync(OAuthTestHost.BaseQuery(challenge));
        var code = OAuthTestHost.QueryOf(OAuthTestHost.Absolute(await host.ConsentAsync(id)))["code"];
        var t = await host.ExchangeAsync(code, verifier, OAuthTestHost.ClaudeRedirect);
        var refresh = t.Str("refresh_token")!;
        await host.RefreshAsync(refresh);

        var events = host.Audit.Snapshot();
        events.Select(e => e.Kind).Should().Contain(new[]
        {
            "oauth.authorize.requested", "oauth.authorize.approved", "oauth.code.exchanged", "oauth.refresh.rotated",
        });
        var dump = string.Join('\n', events.Select(e => System.Text.Json.JsonSerializer.Serialize((object)e)));
        dump.Should().NotContain(code).And.NotContain(verifier).And.NotContain(refresh).And.NotContain(t.Str("access_token")!);
        dump.Should().NotContain(id);
    }
}

public class TokenEndpointTests
{
    [Fact]
    public async Task Unsupported_grant_type()
    {
        await using var host = await OAuthTestHost.StartAsync();
        var t = await host.PostFormAsync(OAuthServerPaths.Token, new Dictionary<string, string> { ["grant_type"] = "client_credentials", ["client_id"] = OAuthTestHost.ClientId });
        t.Status.Should().Be(HttpStatusCode.BadRequest);
        t.Str("error").Should().Be("unsupported_grant_type");
        t.Response.Headers.CacheControl!.NoStore.Should().BeTrue();
    }

    [Fact]
    public async Task Unknown_client_is_invalid_client()
    {
        await using var host = await OAuthTestHost.StartAsync();
        var t = await host.PostFormAsync(OAuthServerPaths.Token, new Dictionary<string, string> { ["grant_type"] = "refresh_token", ["refresh_token"] = "x", ["client_id"] = "ghost" });
        t.Status.Should().Be(HttpStatusCode.Unauthorized);
        t.Str("error").Should().Be("invalid_client");
    }

    [Fact]
    public async Task Json_body_is_an_invalid_request()
    {
        await using var host = await OAuthTestHost.StartAsync();
        var r = await host.Client.PostAsync(OAuthServerPaths.Token, new StringContent("{}", System.Text.Encoding.UTF8, "application/json"));
        var t = await OAuthTestHost.ToResult(r);
        t.Status.Should().Be(HttpStatusCode.BadRequest);
        t.Str("error").Should().Be("invalid_request");
    }

    [Fact]
    public async Task Missing_code_parameters_are_an_invalid_request()
    {
        await using var host = await OAuthTestHost.StartAsync();
        var t = await host.PostFormAsync(OAuthServerPaths.Token, new Dictionary<string, string> { ["grant_type"] = "authorization_code", ["client_id"] = OAuthTestHost.ClientId });
        t.Str("error").Should().Be("invalid_request");
    }

    [Fact]
    public async Task A_confidential_client_must_present_its_secret()
    {
        await using var host = await OAuthTestHost.StartAsync();
        var (code, verifier, redirect) = await host.ApproveAsync(OAuthTestHost.ConfidentialClientId, OAuthTestHost.ConfidentialRedirect);

        var none = await host.ExchangeAsync(code, verifier, redirect, OAuthTestHost.ConfidentialClientId);
        none.Status.Should().Be(HttpStatusCode.Unauthorized);
        none.Str("error").Should().Be("invalid_client");

        var wrong = await host.ExchangeAsync(code, verifier, redirect, OAuthTestHost.ConfidentialClientId, secret: "nope");
        wrong.Str("error").Should().Be("invalid_client");

        var right = await host.ExchangeAsync(code, verifier, redirect, OAuthTestHost.ConfidentialClientId, secret: "s3cret");
        right.Status.Should().Be(HttpStatusCode.OK);
    }

    [Fact]
    public async Task A_public_client_must_not_send_a_secret()
    {
        await using var host = await OAuthTestHost.StartAsync();
        var (code, verifier, redirect) = await host.ApproveAsync();
        (await host.ExchangeAsync(code, verifier, redirect, secret: "whatever")).Str("error").Should().Be("invalid_client");
    }
}

public class RefreshTokenTests
{
    [Fact]
    public async Task Refresh_rotates_the_token_and_retires_the_old_one()
    {
        await using var host = await OAuthTestHost.StartAsync();
        var t = await host.LoginAsync();

        var r1 = await host.RefreshAsync(t.Refresh);
        r1.Status.Should().Be(HttpStatusCode.OK);
        r1.Str("refresh_token").Should().NotBe(t.Refresh);
        r1.Str("scope").Should().Be("tasks:read tasks:write");
        OAuthTestHost.Jwt(r1.Str("access_token")!).Audiences.Should().Equal(OAuthTestHost.Resource);

        var r2 = await host.RefreshAsync(r1.Str("refresh_token")!);
        r2.Status.Should().Be(HttpStatusCode.OK);
        host.Audit.Snapshot().OfType<OAuthRefreshRotatedEvent>().Should().HaveCount(2);
    }

    [Fact]
    public async Task Reusing_a_rotated_token_inside_the_grace_window_is_invalid_grant_without_burning_the_family()
    {
        await using var host = await OAuthTestHost.StartAsync();
        var t = await host.LoginAsync();
        var r1 = await host.RefreshAsync(t.Refresh);

        host.Time.Advance(TimeSpan.FromSeconds(29));
        var again = await host.RefreshAsync(t.Refresh);
        again.Status.Should().Be(HttpStatusCode.BadRequest);
        again.Str("error").Should().Be("invalid_grant");

        (await host.RefreshAsync(r1.Str("refresh_token")!)).Status.Should().Be(HttpStatusCode.OK, "the newest token must survive a lost race");
        host.Audit.Snapshot().OfType<OAuthRefreshReusedEvent>().Should().ContainSingle(e => e.WithinGrace);
        host.Audit.Snapshot().OfType<OAuthFamilyBurnedEvent>().Should().BeEmpty();
    }

    [Fact]
    public async Task Reusing_a_rotated_token_after_the_grace_window_burns_the_whole_family()
    {
        await using var host = await OAuthTestHost.StartAsync();
        var t = await host.LoginAsync();
        var r1 = await host.RefreshAsync(t.Refresh);

        host.Time.Advance(TimeSpan.FromSeconds(31));
        (await host.RefreshAsync(t.Refresh)).Str("error").Should().Be("invalid_grant");

        var newest = await host.RefreshAsync(r1.Str("refresh_token")!);
        newest.Status.Should().Be(HttpStatusCode.BadRequest);
        newest.Str("error").Should().Be("invalid_grant");
        host.Audit.Snapshot().OfType<OAuthFamilyBurnedEvent>().Should().ContainSingle(e => e.Reason == "refresh_reuse");
    }

    [Fact]
    public async Task Dead_tokens_always_answer_invalid_grant()
    {
        await using var host = await OAuthTestHost.StartAsync();
        var t = await host.LoginAsync();

        (await host.RefreshAsync("not-a-token")).Str("error").Should().Be("invalid_grant");
        (await host.RefreshAsync(t.Refresh, clientId: "ghost")).Str("error").Should().Be("invalid_client");

        host.Time.Advance(TimeSpan.FromDays(30) + TimeSpan.FromMinutes(1));
        var expired = await host.RefreshAsync(t.Refresh);
        expired.Status.Should().Be(HttpStatusCode.BadRequest);
        expired.Str("error").Should().Be("invalid_grant");
    }

    [Fact]
    public async Task A_refresh_token_belongs_to_its_client()
    {
        await using var host = await OAuthTestHost.StartAsync(o =>
            o.Clients.Add(new OAuthClientOptions { ClientId = "other", RedirectUris = { OAuthTestHost.ClaudeRedirect } }));
        var t = await host.LoginAsync();
        (await host.RefreshAsync(t.Refresh, clientId: "other")).Str("error").Should().Be("invalid_grant");
        (await host.RefreshAsync(t.Refresh)).Status.Should().Be(HttpStatusCode.OK);
    }

    [Fact]
    public async Task Refresh_can_narrow_the_scope_but_never_widen_it()
    {
        await using var host = await OAuthTestHost.StartAsync();
        var t = await host.LoginAsync(grant: "tasks:read");

        (await host.RefreshAsync(t.Refresh, scope: "tasks:read tasks:write")).Str("error").Should().Be("invalid_scope");
        var ok = await host.RefreshAsync(t.Refresh, scope: "tasks:read");
        ok.Str("scope").Should().Be("tasks:read");
    }

    [Fact]
    public async Task Refresh_lifetime_is_configurable()
    {
        await using var host = await OAuthTestHost.StartAsync(o => o.RefreshTokenLifetime = TimeSpan.FromHours(1));
        var t = await host.LoginAsync();
        host.Time.Advance(TimeSpan.FromMinutes(61));
        (await host.RefreshAsync(t.Refresh)).Str("error").Should().Be("invalid_grant");
    }

    [Fact]
    public async Task Concurrent_refreshes_of_one_token_yield_exactly_one_success()
    {
        await using var host = await OAuthTestHost.StartAsync();
        var t = await host.LoginAsync();

        var results = await Task.WhenAll(Enumerable.Range(0, 8).Select(_ => host.RefreshAsync(t.Refresh)));

        results.Count(r => r.Status == HttpStatusCode.OK).Should().Be(1);
        results.Where(r => r.Status != HttpStatusCode.OK).Should().OnlyContain(r => r.Str("error") == "invalid_grant");
    }

    [Fact]
    public async Task The_access_token_audience_survives_rotation_for_a_second_resource()
    {
        await using var host = await OAuthTestHost.StartAsync();
        var (verifier, challenge) = OAuthTestHost.NewPkce();
        var q = OAuthTestHost.BaseQuery(challenge);
        q["resource"] = OAuthTestHost.Resource2;
        var code = OAuthTestHost.QueryOf(OAuthTestHost.Absolute(await host.ConsentAsync(await host.StartRequestAsync(q))))["code"];
        var t = await host.ExchangeAsync(code, verifier, OAuthTestHost.ClaudeRedirect, resource: null);

        var r = await host.RefreshAsync(t.Str("refresh_token")!);
        OAuthTestHost.Jwt(r.Str("access_token")!).Audiences.Should().Equal(OAuthTestHost.Resource2);
    }
}

public class RevocationTests
{
    [Fact]
    public async Task Revoking_a_refresh_token_kills_its_family()
    {
        await using var host = await OAuthTestHost.StartAsync();
        var t = await host.LoginAsync();
        var r1 = await host.RefreshAsync(t.Refresh);

        var rev = await host.PostFormAsync(OAuthServerPaths.Revoke, new Dictionary<string, string> { ["token"] = r1.Str("refresh_token")!, ["client_id"] = OAuthTestHost.ClientId });
        rev.Status.Should().Be(HttpStatusCode.OK);
        (await host.RefreshAsync(r1.Str("refresh_token")!)).Str("error").Should().Be("invalid_grant");
    }

    [Fact]
    public async Task Revoking_an_unknown_token_still_answers_200()
    {
        await using var host = await OAuthTestHost.StartAsync();
        var rev = await host.PostFormAsync(OAuthServerPaths.Revoke, new Dictionary<string, string> { ["token"] = "who-knows" });
        rev.Status.Should().Be(HttpStatusCode.OK);
    }

    [Fact]
    public async Task Another_client_cannot_revoke_the_token()
    {
        await using var host = await OAuthTestHost.StartAsync();
        var t = await host.LoginAsync();
        var rev = await host.PostFormAsync(OAuthServerPaths.Revoke, new Dictionary<string, string> { ["token"] = t.Refresh, ["client_id"] = "someone-else" });
        rev.Status.Should().Be(HttpStatusCode.OK);
        (await host.RefreshAsync(t.Refresh)).Status.Should().Be(HttpStatusCode.OK);
    }

    [Fact]
    public async Task Revoke_without_a_token_is_an_invalid_request()
    {
        await using var host = await OAuthTestHost.StartAsync();
        var rev = await host.PostFormAsync(OAuthServerPaths.Revoke, new Dictionary<string, string> { ["client_id"] = "x" });
        rev.Status.Should().Be(HttpStatusCode.BadRequest);
    }
}

public class GrantTests
{
    [Fact]
    public async Task Approval_creates_a_grant_that_the_user_can_list()
    {
        await using var host = await OAuthTestHost.StartAsync();
        await host.LoginAsync(user: "alice", grant: "tasks:read");
        await host.LoginAsync(user: "bob");

        using var scope = host.Scope();
        var svc = scope.ServiceProvider.GetRequiredService<IOAuthGrantService>();
        var grants = await svc.ListForUserAsync("alice");

        grants.Should().ContainSingle();
        grants[0].ClientId.Should().Be(OAuthTestHost.ClientId);
        grants[0].ClientName.Should().Be("Test Client");
        grants[0].Scopes.Should().Equal("tasks:read");
        grants[0].FirstGrantedAt.Should().Be(host.Time.GetUtcNow());
    }

    [Fact]
    public async Task Last_used_moves_forward_on_refresh()
    {
        await using var host = await OAuthTestHost.StartAsync();
        var t = await host.LoginAsync(user: "alice");
        var start = host.Time.GetUtcNow();
        host.Time.Advance(TimeSpan.FromHours(2));
        await host.RefreshAsync(t.Refresh);

        using var scope = host.Scope();
        var g = (await scope.ServiceProvider.GetRequiredService<IOAuthGrantService>().ListForUserAsync("alice")).Single();
        g.FirstGrantedAt.Should().Be(start);
        g.LastUsedAt.Should().Be(start + TimeSpan.FromHours(2));
    }

    [Fact]
    public async Task A_second_approval_widens_the_grant()
    {
        await using var host = await OAuthTestHost.StartAsync();
        await host.LoginAsync(user: "alice", grant: "tasks:read");
        await host.LoginAsync(user: "alice", grant: "tasks:write");

        using var scope = host.Scope();
        var g = (await scope.ServiceProvider.GetRequiredService<IOAuthGrantService>().ListForUserAsync("alice")).Single();
        g.Scopes.Should().BeEquivalentTo("tasks:read", "tasks:write");
    }

    [Fact]
    public async Task Revoking_a_grant_kills_the_clients_refresh_tokens_but_not_other_users()
    {
        await using var host = await OAuthTestHost.StartAsync();
        var alice = await host.LoginAsync(user: "alice");
        var bob = await host.LoginAsync(user: "bob");

        using (var scope = host.Scope())
        {
            var svc = scope.ServiceProvider.GetRequiredService<IOAuthGrantService>();
            (await svc.RevokeAsync("alice", OAuthTestHost.ClientId)).Should().BeTrue();
            (await svc.ListForUserAsync("alice")).Should().BeEmpty();
            (await svc.RevokeAsync("alice", OAuthTestHost.ClientId)).Should().BeFalse();
        }

        (await host.RefreshAsync(alice.Refresh)).Str("error").Should().Be("invalid_grant");
        (await host.RefreshAsync(bob.Refresh)).Status.Should().Be(HttpStatusCode.OK);
        host.Audit.Snapshot().OfType<OAuthGrantRevokedEvent>().Should().ContainSingle(e => e.UserId == "alice");
    }

    [Fact]
    public async Task Remembered_consent_is_off_by_default()
    {
        await using var host = await OAuthTestHost.StartAsync();
        await host.LoginAsync(user: "alice");

        var id = await host.StartRequestAsync(OAuthTestHost.BaseQuery(OAuthTestHost.NewPkce().Challenge));
        (await host.ConsentAsync(id, "auto", "alice")).StatusCode.Should().Be(HttpStatusCode.NoContent);
        (await host.Client.GetAsync("/oauth/pending?request=" + id)).StatusCode.Should().Be(HttpStatusCode.OK, "a declined auto-approval leaves the request pending");
    }

    [Fact]
    public async Task Remembered_consent_skips_the_screen_only_when_the_grant_covers_the_request()
    {
        await using var host = await OAuthTestHost.StartAsync(o => o.RememberConsent = true);
        await host.LoginAsync(user: "alice", grant: "tasks:read");

        var narrow = OAuthTestHost.BaseQuery(OAuthTestHost.NewPkce().Challenge);
        narrow["scope"] = "tasks:read";
        var covered = await host.StartRequestAsync(narrow);
        var auto = await host.ConsentAsync(covered, "auto", "alice");
        auto.StatusCode.Should().Be(HttpStatusCode.Found);
        OAuthTestHost.QueryOf(OAuthTestHost.Absolute(auto)).Should().ContainKey("code");

        var wide = await host.StartRequestAsync(OAuthTestHost.BaseQuery(OAuthTestHost.NewPkce().Challenge));
        (await host.ConsentAsync(wide, "auto", "alice")).StatusCode.Should().Be(HttpStatusCode.NoContent);
        (await host.ConsentAsync(wide, "auto", "bob")).StatusCode.Should().Be(HttpStatusCode.NoContent);
    }
}
