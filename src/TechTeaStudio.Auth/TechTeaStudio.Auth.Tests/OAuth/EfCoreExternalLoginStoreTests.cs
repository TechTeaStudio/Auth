using FluentAssertions;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using TechTeaStudio.Auth.OAuth;
using TechTeaStudio.Auth.OAuth.EFCore;
using Xunit;

namespace TechTeaStudio.Auth.Tests.OAuth;

public sealed class OAuthTestDbContext : DbContext
{
    public OAuthTestDbContext(DbContextOptions<OAuthTestDbContext> options) : base(options) { }
    public DbSet<ExternalLoginEntity> ExternalLogins => Set<ExternalLoginEntity>();
    protected override void OnModelCreating(ModelBuilder b) => b.AddTechTeaStudioExternalLogins();
}

public class EfCoreExternalLoginStoreTests
{
    private static EfCoreExternalLoginStore<OAuthTestDbContext> NewStore()
    {
        var options = new DbContextOptionsBuilder<OAuthTestDbContext>()
            .UseInMemoryDatabase(Guid.NewGuid().ToString())
            .Options;
        var ctx = new OAuthTestDbContext(options);
        return new EfCoreExternalLoginStore<OAuthTestDbContext>(ctx);
    }

    [Fact]
    public async Task Find_returns_null_when_missing()
    {
        var store = NewStore();
        (await store.FindAsync("Google", "missing")).Should().BeNull();
    }

    [Fact]
    public async Task Create_then_find_round_trips()
    {
        var store = NewStore();
        var link = new ExternalLogin
        {
            UserId = "user-1", Provider = "Google", ProviderUserId = "g-42", Email = "u@x",
        };
        await store.CreateAsync(link);

        var fetched = await store.FindAsync("Google", "g-42");
        fetched.Should().NotBeNull();
        fetched!.UserId.Should().Be("user-1");
        fetched.Email.Should().Be("u@x");
    }

    [Fact]
    public async Task Duplicate_provider_subject_throws()
    {
        var store = NewStore();
        var link = new ExternalLogin { UserId = "u1", Provider = "Google", ProviderUserId = "same" };
        await store.CreateAsync(link);
        var dup  = new ExternalLogin { UserId = "u2", Provider = "Google", ProviderUserId = "same" };
        var act = () => store.CreateAsync(dup);
        await act.Should().ThrowAsync<InvalidOperationException>();
    }

    [Fact]
    public async Task GetForUser_returns_only_that_users_links()
    {
        var store = NewStore();
        await store.CreateAsync(new ExternalLogin { UserId = "alice", Provider = "Google", ProviderUserId = "g-a" });
        await store.CreateAsync(new ExternalLogin { UserId = "alice", Provider = "GitHub", ProviderUserId = "gh-a" });
        await store.CreateAsync(new ExternalLogin { UserId = "bob",   Provider = "Google", ProviderUserId = "g-b" });

        var aliceLinks = await store.GetForUserAsync("alice");
        aliceLinks.Select(l => l.Provider).Should().BeEquivalentTo(new[] { "Google", "GitHub" });
    }

    [Fact]
    public async Task DeleteAllForUser_removes_only_that_user()
    {
        var store = NewStore();
        await store.CreateAsync(new ExternalLogin { UserId = "alice", Provider = "Google", ProviderUserId = "g-a" });
        await store.CreateAsync(new ExternalLogin { UserId = "bob",   Provider = "Google", ProviderUserId = "g-b" });
        await store.DeleteAllForUserAsync("alice");
        (await store.FindAsync("Google", "g-a")).Should().BeNull();
        (await store.FindAsync("Google", "g-b")).Should().NotBeNull();
    }
}

/// <summary>
/// 0.11.0: the same store driven by an <see cref="IDbContextFactory{TContext}"/> instead of an
/// injected context. Blazor Server hosts register only a factory - a scoped context shared by
/// concurrently running component lifecycle methods is a data race - so without this overload the
/// store simply cannot be resolved there.
/// </summary>
public class EfCoreExternalLoginStoreFactoryTests
{
    private sealed class TestContextFactory : IDbContextFactory<OAuthTestDbContext>
    {
        private readonly DbContextOptions<OAuthTestDbContext> _options;

        public TestContextFactory(string databaseName) =>
            _options = new DbContextOptionsBuilder<OAuthTestDbContext>()
                .UseInMemoryDatabase(databaseName)
                .Options;

        public int Created { get; private set; }

        public OAuthTestDbContext CreateDbContext()
        {
            Created++;
            return new OAuthTestDbContext(_options);
        }
    }

    private static (EfCoreExternalLoginStore<OAuthTestDbContext> Store, TestContextFactory Factory) NewStore()
    {
        var factory = new TestContextFactory(Guid.NewGuid().ToString());
        return (new EfCoreExternalLoginStore<OAuthTestDbContext>(factory), factory);
    }

    [Fact]
    public async Task Create_then_find_round_trips_across_separate_contexts()
    {
        var (store, factory) = NewStore();

        await store.CreateAsync(new ExternalLogin
        {
            UserId = "user-1", Provider = "Telegram", ProviderUserId = "424242",
        });

        var fetched = await store.FindAsync("Telegram", "424242");
        fetched.Should().NotBeNull();
        fetched!.UserId.Should().Be("user-1");
        // Each call opened and disposed its own context - that is the whole point of the overload.
        factory.Created.Should().BeGreaterThan(1);
    }

    [Fact]
    public async Task Duplicate_provider_subject_still_throws()
    {
        var (store, _) = NewStore();
        await store.CreateAsync(new ExternalLogin { UserId = "u1", Provider = "Microsoft", ProviderUserId = "same" });

        var act = () => store.CreateAsync(new ExternalLogin { UserId = "u2", Provider = "Microsoft", ProviderUserId = "same" });
        await act.Should().ThrowAsync<InvalidOperationException>();
    }

    [Fact]
    public async Task DeleteAllForUser_removes_only_that_user()
    {
        var (store, _) = NewStore();
        await store.CreateAsync(new ExternalLogin { UserId = "alice", Provider = "Google", ProviderUserId = "g-a" });
        await store.CreateAsync(new ExternalLogin { UserId = "bob", Provider = "Google", ProviderUserId = "g-b" });

        await store.DeleteAllForUserAsync("alice");

        (await store.FindAsync("Google", "g-a")).Should().BeNull();
        (await store.FindAsync("Google", "g-b")).Should().NotBeNull();
    }

    [Fact]
    public void Null_factory_is_rejected()
    {
        var act = () => new EfCoreExternalLoginStore<OAuthTestDbContext>((IDbContextFactory<OAuthTestDbContext>)null!);
        act.Should().Throw<ArgumentNullException>();
    }

    /// <summary>
    /// AddDbContextFactory registers a scoped context ALONGSIDE the factory. With only the two
    /// single-argument constructors the container refused to pick one ("constructors are
    /// ambiguous") - at resolve time, so a host that registered the store by type and upgraded
    /// met it on the first request that touched sign-in. The two-argument constructor covers both
    /// parameter sets, which is the one shape the container resolves without guessing.
    /// </summary>
    [Fact]
    public async Task Registration_by_type_resolves_in_a_container_holding_both_the_context_and_its_factory()
    {
        var services = new ServiceCollection();
        services.AddDbContextFactory<OAuthTestDbContext>(o => o.UseInMemoryDatabase("both-registered"));
        services.AddScoped<IExternalLoginStore, EfCoreExternalLoginStore<OAuthTestDbContext>>();

        using var provider = services.BuildServiceProvider();
        using var scope = provider.CreateScope();
        var store = scope.ServiceProvider.GetRequiredService<IExternalLoginStore>();

        store.Should().BeOfType<EfCoreExternalLoginStore<OAuthTestDbContext>>();
        await store.CreateAsync(new ExternalLogin { UserId = "alice", Provider = "Google", ProviderUserId = "g-a" });
        (await store.FindAsync("Google", "g-a")).Should().NotBeNull();
    }

    [Fact]
    public void Registration_by_type_shares_the_scoped_context_when_both_are_registered()
    {
        // The tie-breaker keeps what such a host had before the factory constructor existed: the
        // scoped context, so the store still takes part in the caller's unit of work.
        var services = new ServiceCollection();
        var factory = new TestContextFactory("shared-scoped");
        services.AddSingleton<IDbContextFactory<OAuthTestDbContext>>(factory);
        services.AddScoped(_ => new OAuthTestDbContext(
            new DbContextOptionsBuilder<OAuthTestDbContext>().UseInMemoryDatabase("shared-scoped").Options));
        services.AddScoped<IExternalLoginStore, EfCoreExternalLoginStore<OAuthTestDbContext>>();

        using var provider = services.BuildServiceProvider();
        using var scope = provider.CreateScope();
        var store = scope.ServiceProvider.GetRequiredService<IExternalLoginStore>();
        store.FindAsync("Google", "nobody").GetAwaiter().GetResult();

        factory.Created.Should().Be(0);
    }

    [Fact]
    public void Registration_by_type_still_resolves_with_only_a_context()
    {
        var services = new ServiceCollection();
        services.AddDbContext<OAuthTestDbContext>(o => o.UseInMemoryDatabase("context-only"));
        services.AddScoped<IExternalLoginStore, EfCoreExternalLoginStore<OAuthTestDbContext>>();

        using var provider = services.BuildServiceProvider();
        using var scope = provider.CreateScope();
        scope.ServiceProvider.GetRequiredService<IExternalLoginStore>()
            .Should().BeOfType<EfCoreExternalLoginStore<OAuthTestDbContext>>();
    }

    [Fact]
    public void Delegate_registration_selects_the_factory_constructor()
    {
        var services = new ServiceCollection();
        services.AddDbContextFactory<OAuthTestDbContext>(o => o.UseInMemoryDatabase("delegate"));
        services.AddScoped<IExternalLoginStore>(sp => new EfCoreExternalLoginStore<OAuthTestDbContext>(
            sp.GetRequiredService<IDbContextFactory<OAuthTestDbContext>>()));

        using var provider = services.BuildServiceProvider();
        provider.CreateScope().ServiceProvider.GetRequiredService<IExternalLoginStore>()
            .Should().BeOfType<EfCoreExternalLoginStore<OAuthTestDbContext>>();
    }
}
