using FluentAssertions;
using Microsoft.Extensions.Options;
using TechTeaStudio.Auth.Abstractions;
using TechTeaStudio.Auth.Jwt;
using TechTeaStudio.Auth.OAuth;
using TechTeaStudio.Auth.Passwords;
using TechTeaStudio.Auth.RefreshTokens;
using TechTeaStudio.Auth.Revocation;
using TechTeaStudio.Auth.Tests.TestHelpers;
using Xunit;

namespace TechTeaStudio.Auth.Tests.OAuth;

public class ExternalLoginServiceTests
{
    private static (ExternalLoginService svc, StubExternalAuthProvider provider, TestExternalUserBridge users,
        IExternalLoginStore loginStore, IPasswordHasher hasher, IRevokedTokenStore revoked) NewService()
    {
        var concrete = TestAuthOptions.Create();
        var opts = Options.Create(concrete);
        var provider = new JwtTokenProvider(concrete.ToMonitor());
        var refreshStore = new InMemoryRefreshTokenStore();
        var refresh = new RefreshTokenService(provider, refreshStore, opts);
        var hasher = new Pbkdf2PasswordHasher();
        var revoked = new InMemoryRevokedTokenStore();
        var users = new TestExternalUserBridge();
        var loginStore = new InMemoryExternalLoginStore();
        var stub = new StubExternalAuthProvider("Google");

        var svc = new ExternalLoginService(
            providers: new[] { (IExternalAuthProvider)stub },
            store: loginStore,
            users: users,
            refresh: refresh,
            options: opts,
            passwords: hasher,
            revoked: revoked);

        return (svc, stub, users, loginStore, hasher, revoked);
    }

    private static ExternalLoginInfo GoogleInfo(string sub = "g-1", string email = "u@x", bool verified = true) =>
        new("Google", sub, email, verified, "User", null);

    [Fact]
    public async Task SignIn_unknown_provider_fails()
    {
        var (svc, _, _, _, _, _) = NewService();
        var r = await svc.SignInAsync("Microsoft", "anything");
        r.Status.Should().Be(ExternalSignInStatus.Failed);
        r.Error.Should().Be("unknown_provider");
    }

    [Fact]
    public async Task SignIn_invalid_credential_fails()
    {
        var (svc, _, _, _, _, _) = NewService();
        var r = await svc.SignInAsync("Google", "junk-token");
        r.Status.Should().Be(ExternalSignInStatus.Failed);
        r.Error.Should().Be("invalid_credential");
    }

    [Fact]
    public async Task SignIn_new_user_returns_RequiresRegistration()
    {
        var (svc, stub, _, _, _, _) = NewService();
        stub.Responses["good-token"] = GoogleInfo();

        var r = await svc.SignInAsync("Google", "good-token");
        r.Status.Should().Be(ExternalSignInStatus.RequiresRegistration);
        r.ContinuationToken.Should().NotBeNullOrEmpty();
        r.Profile!.Email.Should().Be("u@x");
    }

    [Fact]
    public async Task SignIn_email_collision_returns_RequiresPassword()
    {
        var (svc, stub, users, _, hasher, _) = NewService();
        users.SeedPasswordUser("u@x", hasher.Hash("pwd"));
        stub.Responses["good-token"] = GoogleInfo();

        var r = await svc.SignInAsync("Google", "good-token");
        r.Status.Should().Be(ExternalSignInStatus.RequiresPassword);
        r.Email.Should().Be("u@x");
        r.ContinuationToken.Should().NotBeNullOrEmpty();
    }

    [Fact]
    public async Task SignIn_existing_link_returns_Authenticated()
    {
        var (svc, stub, users, store, _, _) = NewService();
        var seeded = users.SeedPasswordUser("u@x", "irrelevant");
        await store.CreateAsync(new ExternalLogin
        {
            UserId = seeded.UserId, Provider = "Google", ProviderUserId = "g-1", Email = "u@x",
        });
        stub.Responses["good-token"] = GoogleInfo();

        var r = await svc.SignInAsync("Google", "good-token");
        r.Status.Should().Be(ExternalSignInStatus.Authenticated);
        r.Tokens!.AccessToken.Should().NotBeNullOrEmpty();
        r.Tokens.RefreshToken.Should().NotBeNullOrEmpty();
    }

    [Fact]
    public async Task LinkExistingAccount_with_correct_password_links_and_authenticates()
    {
        var (svc, stub, users, store, hasher, _) = NewService();
        users.SeedPasswordUser("u@x", hasher.Hash("pwd"));
        stub.Responses["good-token"] = GoogleInfo();

        var step1 = await svc.SignInAsync("Google", "good-token");
        step1.Status.Should().Be(ExternalSignInStatus.RequiresPassword);

        var step2 = await svc.LinkExistingAccountAsync(step1.ContinuationToken!, "pwd");
        step2.Status.Should().Be(ExternalSignInStatus.Authenticated);

        // Link is now stored — second SignIn with same Google token returns Authenticated immediately.
        var step3 = await svc.SignInAsync("Google", "good-token");
        step3.Status.Should().Be(ExternalSignInStatus.Authenticated);
    }

    [Fact]
    public async Task LinkExistingAccount_with_wrong_password_fails()
    {
        var (svc, stub, users, _, hasher, _) = NewService();
        users.SeedPasswordUser("u@x", hasher.Hash("pwd"));
        stub.Responses["good-token"] = GoogleInfo();

        var step1 = await svc.SignInAsync("Google", "good-token");
        var step2 = await svc.LinkExistingAccountAsync(step1.ContinuationToken!, "wrong");
        step2.Status.Should().Be(ExternalSignInStatus.Failed);
        step2.Error.Should().Be("invalid_password");
    }

    [Fact]
    public async Task CompleteRegistration_creates_user_and_link()
    {
        var (svc, stub, _, store, _, _) = NewService();
        stub.Responses["good-token"] = GoogleInfo();

        var step1 = await svc.SignInAsync("Google", "good-token");
        step1.Status.Should().Be(ExternalSignInStatus.RequiresRegistration);

        var step2 = await svc.CompleteRegistrationAsync(step1.ContinuationToken!, "neo");
        step2.Status.Should().Be(ExternalSignInStatus.Authenticated);

        // Link now exists.
        (await store.FindAsync("Google", "g-1")).Should().NotBeNull();
    }

    [Fact]
    public async Task Continuation_token_is_single_use()
    {
        var (svc, stub, _, _, _, _) = NewService();
        stub.Responses["good-token"] = GoogleInfo();

        var step1 = await svc.SignInAsync("Google", "good-token");
        await svc.CompleteRegistrationAsync(step1.ContinuationToken!, "neo");

        // Replay same continuation token — must fail.
        var replay = await svc.CompleteRegistrationAsync(step1.ContinuationToken!, "neo2");
        replay.Status.Should().Be(ExternalSignInStatus.Failed);
        replay.Error.Should().Be("invalid_or_expired_continuation");
    }

    [Fact]
    public async Task LinkToUser_attaches_provider_to_authenticated_user()
    {
        var (svc, stub, users, store, hasher, _) = NewService();
        var u = users.SeedPasswordUser("u@x", hasher.Hash("pwd"));
        stub.Responses["good-token"] = GoogleInfo();

        var r = await svc.LinkToUserAsync("Google", "good-token", u.UserId);
        r.Status.Should().Be(ExternalSignInStatus.Authenticated);
        (await store.FindAsync("Google", "g-1"))!.UserId.Should().Be(u.UserId);
    }

    [Fact]
    public async Task LinkToUser_rejects_already_linked_to_other_user()
    {
        var (svc, stub, users, store, hasher, _) = NewService();
        var alice = users.SeedPasswordUser("alice@x", hasher.Hash("pwd"));
        var bob   = users.SeedPasswordUser("bob@x",   hasher.Hash("pwd"));
        await store.CreateAsync(new ExternalLogin
            { UserId = alice.UserId, Provider = "Google", ProviderUserId = "g-1", Email = "alice@x" });
        stub.Responses["good-token"] = GoogleInfo();

        var r = await svc.LinkToUserAsync("Google", "good-token", bob.UserId);
        r.Status.Should().Be(ExternalSignInStatus.Failed);
        r.Error.Should().Be("already_linked_to_other_user");
    }
}
