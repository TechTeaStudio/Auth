using Microsoft.EntityFrameworkCore;
using TechTeaStudio.Auth.Abstractions;
using TechTeaStudio.Auth.EFCore;
using TechTeaStudio.Auth.Tests.RefreshTokens;

namespace TechTeaStudio.Auth.Tests.EfCore;

public sealed class TestDbContext : DbContext
{
    public TestDbContext(DbContextOptions<TestDbContext> options) : base(options) { }

    public DbSet<RefreshTokenEntity> RefreshTokens => Set<RefreshTokenEntity>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.AddTechTeaStudioRefreshTokens();
    }
}

public class EfCoreRefreshTokenStoreContractTests : RefreshTokenStoreContractTests
{
    protected override IRefreshTokenStore CreateStore()
    {
        var options = new DbContextOptionsBuilder<TestDbContext>()
            .UseInMemoryDatabase(Guid.NewGuid().ToString())
            .Options;
        var ctx = new TestDbContext(options);
        return new EfCoreRefreshTokenStore<TestDbContext>(ctx);
    }
}
