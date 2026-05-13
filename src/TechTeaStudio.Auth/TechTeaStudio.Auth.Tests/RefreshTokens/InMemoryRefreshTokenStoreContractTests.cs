using TechTeaStudio.Auth.Abstractions;
using TechTeaStudio.Auth.RefreshTokens;

namespace TechTeaStudio.Auth.Tests.RefreshTokens;

public class InMemoryRefreshTokenStoreContractTests : RefreshTokenStoreContractTests
{
    protected override IRefreshTokenStore CreateStore() => new InMemoryRefreshTokenStore();
}
