using System.Net;
using FluentAssertions;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Xunit;
using TechTeaStudio.Auth.OAuthServer;
using TechTeaStudio.Auth.OAuthServer.Abstractions;
using TechTeaStudio.Auth.OAuthServer.EFCore;
using TechTeaStudio.Auth.OAuthServer.Stores;

namespace TechTeaStudio.Auth.Tests.OAuthServer;

public sealed class OAuthServerTestDb : DbContext
{
    public OAuthServerTestDb(DbContextOptions<OAuthServerTestDb> options) : base(options) { }
    protected override void OnModelCreating(ModelBuilder b) => b.AddTechTeaStudioOAuthServerTables();
}

public sealed class SqliteFixture : IDisposable
{
    private readonly SqliteConnection _conn = new("DataSource=:memory:");

    public SqliteFixture()
    {
        _conn.Open();
        using var db = NewContext();
        db.Database.EnsureCreated();
    }

    public OAuthServerTestDb NewContext() =>
        new(new DbContextOptionsBuilder<OAuthServerTestDb>().UseSqlite(_conn).Options);

    public void Dispose() => _conn.Dispose();
}

/// <summary>The same behavioural contract runs against the in-memory and the EF Core stores.</summary>
public abstract class OAuthStoreContract
{
    protected abstract IOAuthClientStore Clients { get; }
    protected abstract IOAuthPendingRequestStore Pending { get; }
    protected abstract IOAuthCodeStore Codes { get; }
    protected abstract IOAuthRefreshTokenStore Refresh { get; }
    protected abstract IOAuthGrantStore Grants { get; }

    private static readonly DateTimeOffset Now = new(2026, 11, 1, 12, 0, 0, TimeSpan.Zero);

    private static PendingAuthorization NewPending(string id, DateTimeOffset expires) => new()
    {
        Id = id, ClientId = "c", RedirectUri = "https://a.example/cb", CodeChallenge = new string('a', 43), Resource = "https://r.example",
        Scopes = new[] { "a", "b" }, State = "s", CreatedAt = Now, ExpiresAt = expires,
    };

    private static AuthorizationCode NewCode(string hash, DateTimeOffset expires) => new()
    {
        CodeHash = hash, ClientId = "c", RedirectUri = "https://a.example/cb", CodeChallenge = new string('a', 43), Resource = "https://r.example",
        Scopes = new[] { "a" }, UserId = "u", FamilyId = Guid.NewGuid(), CreatedAt = Now, ExpiresAt = expires,
    };

    private static OAuthRefreshToken NewRefresh(string hash, Guid family, string user = "u", string client = "c", DateTimeOffset? expires = null) => new()
    {
        Id = Guid.NewGuid(), TokenHash = hash, FamilyId = family, ClientId = client, UserId = user,
        Scopes = new[] { "a", "b" }, Resource = "https://r.example", CreatedAt = Now, ExpiresAt = expires ?? Now.AddDays(30),
    };

    [Fact]
    public async Task Client_round_trips()
    {
        var c = new OAuthClient
        {
            ClientId = "dcr_1", Name = "N", LogoUri = "https://l.example/x.png", ClientUri = "https://c.example",
            RedirectUris = new[] { "https://a.example/cb", "http://127.0.0.1/cb" }, Source = OAuthClientSource.Dynamic, CreatedAt = Now,
        };
        await Clients.SaveAsync(c);

        var back = await Clients.FindAsync("dcr_1");
        back!.Name.Should().Be("N");
        back.RedirectUris.Should().Equal(c.RedirectUris);
        back.Source.Should().Be(OAuthClientSource.Dynamic);
        back.IsConfidential.Should().BeFalse();
        (await Clients.FindAsync("missing")).Should().BeNull();
    }

    [Fact]
    public async Task Pending_is_single_use_and_expires()
    {
        await Pending.SaveAsync(NewPending("p1", Now.AddMinutes(10)));
        (await Pending.GetAsync("p1", Now))!.Scopes.Should().Equal("a", "b");
        (await Pending.GetAsync("p1", Now)).Should().NotBeNull("peeking must not consume");

        (await Pending.TakeAsync("p1", Now)).Should().NotBeNull();
        (await Pending.TakeAsync("p1", Now)).Should().BeNull();
        (await Pending.GetAsync("p1", Now)).Should().BeNull();

        await Pending.SaveAsync(NewPending("p2", Now.AddMinutes(10)));
        (await Pending.GetAsync("p2", Now.AddMinutes(11))).Should().BeNull();
        (await Pending.TakeAsync("p2", Now.AddMinutes(11))).Should().BeNull();
    }

    [Fact]
    public async Task Pending_cleanup_removes_only_expired_rows()
    {
        await Pending.SaveAsync(NewPending("old", Now.AddMinutes(1)));
        await Pending.SaveAsync(NewPending("new", Now.AddMinutes(30)));
        (await Pending.CleanupExpiredAsync(Now.AddMinutes(5))).Should().Be(1);
        (await Pending.GetAsync("new", Now)).Should().NotBeNull();
    }

    [Fact]
    public async Task Code_is_consumed_once_and_the_second_look_is_a_replay()
    {
        await Codes.SaveAsync(NewCode("h1", Now.AddSeconds(60)));

        var first = await Codes.TryConsumeAsync("h1", Now);
        first!.AlreadyConsumed.Should().BeFalse();
        first.Code.UserId.Should().Be("u");
        first.Code.Scopes.Should().Equal("a");

        var second = await Codes.TryConsumeAsync("h1", Now);
        second!.AlreadyConsumed.Should().BeTrue();
        second.Code.FamilyId.Should().Be(first.Code.FamilyId);

        (await Codes.TryConsumeAsync("unknown", Now)).Should().BeNull();
    }

    [Fact]
    public async Task Code_cleanup_removes_expired_codes()
    {
        await Codes.SaveAsync(NewCode("old", Now.AddSeconds(60)));
        await Codes.SaveAsync(NewCode("new", Now.AddHours(1)));
        (await Codes.CleanupExpiredAsync(Now.AddMinutes(5))).Should().Be(1);
        (await Codes.TryConsumeAsync("old", Now)).Should().BeNull();
        (await Codes.TryConsumeAsync("new", Now)).Should().NotBeNull();
    }

    [Fact]
    public async Task Refresh_rotation_is_a_compare_and_swap()
    {
        var t = NewRefresh("r1", Guid.NewGuid());
        await Refresh.CreateAsync(t);

        (await Refresh.TryRotateAsync(t.Id, "r2", Now)).Should().BeTrue();
        (await Refresh.TryRotateAsync(t.Id, "r3", Now)).Should().BeFalse();

        var back = await Refresh.GetByHashAsync("r1");
        back!.RotatedAt.Should().Be(Now);
        back.ReplacedByTokenHash.Should().Be("r2");
        back.Scopes.Should().Equal("a", "b");
        (await Refresh.GetByHashAsync("nope")).Should().BeNull();
    }

    [Fact]
    public async Task A_revoked_token_cannot_be_rotated()
    {
        var fam = Guid.NewGuid();
        var t = NewRefresh("r1", fam);
        await Refresh.CreateAsync(t);
        (await Refresh.RevokeFamilyAsync(fam, Now)).Should().Be(1);
        (await Refresh.TryRotateAsync(t.Id, "r2", Now)).Should().BeFalse();
    }

    [Fact]
    public async Task Family_revoke_hits_every_active_row_of_the_family_only()
    {
        var fam = Guid.NewGuid();
        await Refresh.CreateAsync(NewRefresh("a1", fam));
        await Refresh.CreateAsync(NewRefresh("a2", fam));
        await Refresh.CreateAsync(NewRefresh("b1", Guid.NewGuid()));

        (await Refresh.RevokeFamilyAsync(fam, Now.AddMinutes(1))).Should().Be(2);
        (await Refresh.RevokeFamilyAsync(fam, Now.AddMinutes(2))).Should().Be(0);
        (await Refresh.GetByHashAsync("a1"))!.RevokedAt.Should().Be(Now.AddMinutes(1));
        (await Refresh.GetByHashAsync("b1"))!.RevokedAt.Should().BeNull();
    }

    [Fact]
    public async Task Revoke_for_user_and_client_is_scoped_to_the_pair()
    {
        await Refresh.CreateAsync(NewRefresh("x1", Guid.NewGuid(), "alice", "c1"));
        await Refresh.CreateAsync(NewRefresh("x2", Guid.NewGuid(), "alice", "c2"));
        await Refresh.CreateAsync(NewRefresh("x3", Guid.NewGuid(), "bob", "c1"));

        (await Refresh.RevokeForUserClientAsync("alice", "c1", Now)).Should().Be(1);
        (await Refresh.GetByHashAsync("x1"))!.RevokedAt.Should().NotBeNull();
        (await Refresh.GetByHashAsync("x2"))!.RevokedAt.Should().BeNull();
        (await Refresh.GetByHashAsync("x3"))!.RevokedAt.Should().BeNull();
    }

    [Fact]
    public async Task Refresh_cleanup_removes_expired_rows()
    {
        await Refresh.CreateAsync(NewRefresh("e1", Guid.NewGuid(), expires: Now.AddDays(1)));
        await Refresh.CreateAsync(NewRefresh("e2", Guid.NewGuid(), expires: Now.AddDays(60)));
        (await Refresh.CleanupExpiredAsync(Now.AddDays(2))).Should().Be(1);
        (await Refresh.GetByHashAsync("e1")).Should().BeNull();
        (await Refresh.GetByHashAsync("e2")).Should().NotBeNull();
    }

    [Fact]
    public async Task Grants_upsert_widens_lists_touches_and_deletes()
    {
        await Grants.UpsertAsync("u", "c", "Client", new[] { "a" }, Now);
        await Grants.UpsertAsync("u", "c", null, new[] { "b" }, Now.AddHours(1));
        await Grants.UpsertAsync("u", "c2", "Other", new[] { "a" }, Now.AddHours(2));
        await Grants.UpsertAsync("someone", "c", "Client", new[] { "a" }, Now);

        var g = await Grants.GetAsync("u", "c");
        g!.Scopes.Should().BeEquivalentTo("a", "b");
        g.ClientName.Should().Be("Client");
        g.FirstGrantedAt.Should().Be(Now);
        g.LastUsedAt.Should().Be(Now.AddHours(1));

        await Grants.TouchAsync("u", "c", Now.AddHours(5));
        (await Grants.GetAsync("u", "c"))!.LastUsedAt.Should().Be(Now.AddHours(5));

        var list = await Grants.ListForUserAsync("u");
        list.Select(x => x.ClientId).Should().Equal("c", "c2");

        (await Grants.DeleteAsync("u", "c")).Should().BeTrue();
        (await Grants.DeleteAsync("u", "c")).Should().BeFalse();
        (await Grants.GetAsync("u", "c")).Should().BeNull();
        (await Grants.GetAsync("someone", "c")).Should().NotBeNull();
    }
}

public class InMemoryOAuthStoreTests : OAuthStoreContract
{
    protected override IOAuthClientStore Clients { get; } = new InMemoryOAuthClientStore();
    protected override IOAuthPendingRequestStore Pending { get; } = new InMemoryOAuthPendingRequestStore();
    protected override IOAuthCodeStore Codes { get; } = new InMemoryOAuthCodeStore();
    protected override IOAuthRefreshTokenStore Refresh { get; } = new InMemoryOAuthRefreshTokenStore();
    protected override IOAuthGrantStore Grants { get; } = new InMemoryOAuthGrantStore();
}

public class EfCoreOAuthStoreTests : OAuthStoreContract, IDisposable
{
    private readonly SqliteFixture _fx = new();
    private readonly OAuthServerTestDb _db;

    public EfCoreOAuthStoreTests()
    {
        _db = _fx.NewContext();
        Clients = new EfCoreOAuthClientStore<OAuthServerTestDb>(_db);
        Pending = new EfCoreOAuthPendingRequestStore<OAuthServerTestDb>(_db);
        Codes = new EfCoreOAuthCodeStore<OAuthServerTestDb>(_db);
        Refresh = new EfCoreOAuthRefreshTokenStore<OAuthServerTestDb>(_db);
        Grants = new EfCoreOAuthGrantStore<OAuthServerTestDb>(_db);
    }

    protected override IOAuthClientStore Clients { get; }
    protected override IOAuthPendingRequestStore Pending { get; }
    protected override IOAuthCodeStore Codes { get; }
    protected override IOAuthRefreshTokenStore Refresh { get; }
    protected override IOAuthGrantStore Grants { get; }

    public void Dispose()
    {
        _db.Dispose();
        _fx.Dispose();
    }

    [Fact]
    public void Tables_use_the_prefix_and_are_all_mapped()
    {
        var names = _db.Model.GetEntityTypes().Select(e => e.GetTableName()).ToArray();
        names.Should().BeEquivalentTo("TtsOAuthClients", "TtsOAuthPendingRequests", "TtsOAuthCodes", "TtsOAuthRefreshTokens", "TtsOAuthGrants");
    }

    [Fact]
    public async Task A_code_consumed_through_one_context_is_a_replay_through_another()
    {
        await Codes.SaveAsync(new AuthorizationCode
        {
            CodeHash = "x", ClientId = "c", RedirectUri = "https://a.example/cb", CodeChallenge = new string('a', 43), Resource = "r",
            Scopes = new[] { "a" }, UserId = "u", FamilyId = Guid.NewGuid(), ExpiresAt = DateTimeOffset.UtcNow.AddMinutes(1),
        });

        using var other = _fx.NewContext();
        var racer = new EfCoreOAuthCodeStore<OAuthServerTestDb>(other);
        (await Codes.TryConsumeAsync("x", DateTimeOffset.UtcNow))!.AlreadyConsumed.Should().BeFalse();
        (await racer.TryConsumeAsync("x", DateTimeOffset.UtcNow))!.AlreadyConsumed.Should().BeTrue();
    }

    [Fact]
    public async Task A_stale_context_loses_the_rotation_race()
    {
        var family = Guid.NewGuid();
        var t = new OAuthRefreshToken
        {
            Id = Guid.NewGuid(), TokenHash = "rr", FamilyId = family, ClientId = "c", UserId = "u", Scopes = new[] { "a" },
            Resource = "r", CreatedAt = DateTimeOffset.UtcNow, ExpiresAt = DateTimeOffset.UtcNow.AddDays(1),
        };
        await Refresh.CreateAsync(t);

        using var a = _fx.NewContext();
        using var b = _fx.NewContext();
        var entityA = await a.Set<OAuthRefreshTokenEntity>().FirstAsync(x => x.Id == t.Id);
        var entityB = await b.Set<OAuthRefreshTokenEntity>().FirstAsync(x => x.Id == t.Id);
        entityA.RotatedAt = DateTimeOffset.UtcNow;
        entityA.ConcurrencyStamp = Guid.NewGuid().ToString();
        await a.SaveChangesAsync();

        entityB.RotatedAt = DateTimeOffset.UtcNow;
        entityB.ConcurrencyStamp = Guid.NewGuid().ToString();
        var act = () => b.SaveChangesAsync();
        await act.Should().ThrowAsync<DbUpdateConcurrencyException>();
    }
}

public class OAuthServerEfEndToEndTests
{
    [Fact]
    public async Task Full_flow_runs_on_the_ef_core_stores()
    {
        using var fx = new SqliteFixture();
        await using var host = await OAuthTestHost.StartAsync(
            stores: b => b.UseEfCoreStores<OAuthServerTestDb>(),
            services: s => s.AddScoped(_ => fx.NewContext()));

        var t = await host.LoginAsync(user: "ef-user", grant: "tasks:read");
        OAuthTestHost.Jwt(t.Access).Subject.Should().Be("ef-user");

        var r1 = await host.RefreshAsync(t.Refresh);
        r1.Status.Should().Be(HttpStatusCode.OK);
        host.Time.Advance(TimeSpan.FromMinutes(5));
        (await host.RefreshAsync(t.Refresh)).Str("error").Should().Be("invalid_grant");
        (await host.RefreshAsync(r1.Str("refresh_token")!)).Str("error").Should().Be("invalid_grant");

        using var scope = host.Scope();
        var grants = await scope.ServiceProvider.GetRequiredService<IOAuthGrantService>().ListForUserAsync("ef-user");
        grants.Should().ContainSingle().Which.Scopes.Should().Equal("tasks:read");
    }

    [Fact]
    public async Task Replay_and_revoke_work_on_the_ef_core_stores()
    {
        using var fx = new SqliteFixture();
        await using var host = await OAuthTestHost.StartAsync(
            stores: b => b.UseEfCoreStores<OAuthServerTestDb>(),
            services: s => s.AddScoped(_ => fx.NewContext()));

        var (code, verifier, redirect) = await host.ApproveAsync();
        var first = await host.ExchangeAsync(code, verifier, redirect);
        (await host.ExchangeAsync(code, verifier, redirect)).Str("error").Should().Be("invalid_grant");
        (await host.RefreshAsync(first.Str("refresh_token")!)).Str("error").Should().Be("invalid_grant");

        var t = await host.LoginAsync();
        (await host.PostFormAsync(OAuthServerPaths.Revoke, new Dictionary<string, string> { ["token"] = t.Refresh })).Status.Should().Be(HttpStatusCode.OK);
        (await host.RefreshAsync(t.Refresh)).Str("error").Should().Be("invalid_grant");
    }
}
