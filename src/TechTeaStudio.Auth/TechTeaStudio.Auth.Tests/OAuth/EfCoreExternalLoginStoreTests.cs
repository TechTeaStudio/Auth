using FluentAssertions;
using Microsoft.EntityFrameworkCore;
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
