#if NET11_0_OR_GREATER
// A switch over a union that misses a case must not compile here: that is the whole point of
// the union form. The test project turns CS8509 and CS8655 into errors (see the .csproj).

using System.IdentityModel.Tokens.Jwt;
using FluentAssertions;
using TechTeaStudio.Auth.OAuth;
using Xunit;

namespace TechTeaStudio.Auth.Tests.OAuth;

/// <summary>
/// Every scenario runs twice on identically prepared services: once through the union method
/// and once through the classic <see cref="ExternalSignInOutcome"/> method (the "twin"), and the
/// union case must name the same <see cref="ExternalSignInStatus"/>.
/// </summary>
public class ExternalSignInUnionTests
{
    private static ExternalLoginInfo GoogleInfo(string sub = "g-1", string email = "u@x") =>
        ExternalLoginServiceTests.GoogleInfo(sub, email);

    /// <summary>Exhaustive over the four cases: no discard arm, no <c>null</c> arm.</summary>
    private static ExternalSignInStatus Kind(ExternalSignIn result) => result switch
    {
        ExternalSignedIn => ExternalSignInStatus.Authenticated,
        ExternalPasswordRequired => ExternalSignInStatus.RequiresPassword,
        ExternalRegistrationRequired => ExternalSignInStatus.RequiresRegistration,
        ExternalSignInFailed => ExternalSignInStatus.Failed,
    };

    /// <summary>Exhaustive over the two cases a completion step can end in.</summary>
    private static ExternalSignInStatus Kind(ExternalSignInCompletion result) => result switch
    {
        ExternalSignedIn => ExternalSignInStatus.Authenticated,
        ExternalSignInFailed => ExternalSignInStatus.Failed,
    };

    private static string SubjectOf(string accessToken) =>
        new JwtSecurityTokenHandler().ReadJwtToken(accessToken).Claims.Single(c => c.Type == "sub").Value;

    [Fact]
    public async Task Unknown_provider_is_ExternalSignInFailed_with_the_same_error()
    {
        var (svc, _, _, _, _, _) = ExternalLoginServiceTests.NewService();
        var (twin, _, _, _, _, _) = ExternalLoginServiceTests.NewService();

        var result = await svc.SignInAsUnionAsync("Microsoft", "anything");
        var classic = await twin.SignInAsync("Microsoft", "anything");

        result.Value.Should().BeOfType<ExternalSignInFailed>().Which.Error.Should().Be("unknown_provider");
        classic.Error.Should().Be("unknown_provider");
        Kind(result).Should().Be(classic.Status);
    }

    [Fact]
    public async Task Invalid_credential_is_ExternalSignInFailed_with_the_same_error()
    {
        var (svc, _, _, _, _, _) = ExternalLoginServiceTests.NewService();
        var (twin, _, _, _, _, _) = ExternalLoginServiceTests.NewService();

        var result = await svc.SignInAsUnionAsync("Google", "junk-token");
        var classic = await twin.SignInAsync("Google", "junk-token");

        result.Value.Should().BeOfType<ExternalSignInFailed>().Which.Error.Should().Be("invalid_credential");
        classic.Error.Should().Be("invalid_credential");
        Kind(result).Should().Be(classic.Status);
    }

    [Fact]
    public async Task New_user_is_ExternalRegistrationRequired_with_token_and_profile()
    {
        var (svc, stub, _, _, _, _) = ExternalLoginServiceTests.NewService();
        var (twin, twinStub, _, _, _, _) = ExternalLoginServiceTests.NewService();
        stub.Responses["good-token"] = GoogleInfo();
        twinStub.Responses["good-token"] = GoogleInfo();

        var result = await svc.SignInAsUnionAsync("Google", "good-token");
        var classic = await twin.SignInAsync("Google", "good-token");

        var registration = result.Value.Should().BeOfType<ExternalRegistrationRequired>().Subject;
        registration.ContinuationToken.Should().NotBeNullOrEmpty();
        registration.Profile.Should().Be(GoogleInfo());
        registration.Profile.Should().Be(classic.Profile);
        Kind(result).Should().Be(classic.Status);
    }

    [Fact]
    public async Task Email_collision_is_ExternalPasswordRequired_with_token_and_email()
    {
        var (svc, stub, users, _, hasher, _) = ExternalLoginServiceTests.NewService();
        var (twin, twinStub, twinUsers, _, twinHasher, _) = ExternalLoginServiceTests.NewService();
        users.SeedPasswordUser("u@x", hasher.Hash("pwd"));
        twinUsers.SeedPasswordUser("u@x", twinHasher.Hash("pwd"));
        stub.Responses["good-token"] = GoogleInfo();
        twinStub.Responses["good-token"] = GoogleInfo();

        var result = await svc.SignInAsUnionAsync("Google", "good-token");
        var classic = await twin.SignInAsync("Google", "good-token");

        var password = result.Value.Should().BeOfType<ExternalPasswordRequired>().Subject;
        password.ContinuationToken.Should().NotBeNullOrEmpty();
        password.Email.Should().Be("u@x");
        password.Email.Should().Be(classic.Email);
        Kind(result).Should().Be(classic.Status);
    }

    [Fact]
    public async Task Existing_link_is_ExternalSignedIn_with_tokens_and_the_linked_UserId()
    {
        var (svc, stub, users, store, _, _) = ExternalLoginServiceTests.NewService();
        var (twin, twinStub, twinUsers, twinStore, _, _) = ExternalLoginServiceTests.NewService();
        var seeded = users.SeedPasswordUser("u@x", "irrelevant");
        var twinSeeded = twinUsers.SeedPasswordUser("u@x", "irrelevant");
        await store.CreateAsync(new ExternalLogin { UserId = seeded.UserId, Provider = "Google", ProviderUserId = "g-1", Email = "u@x" });
        await twinStore.CreateAsync(new ExternalLogin { UserId = twinSeeded.UserId, Provider = "Google", ProviderUserId = "g-1", Email = "u@x" });
        stub.Responses["good-token"] = GoogleInfo();
        twinStub.Responses["good-token"] = GoogleInfo();

        var result = await svc.SignInAsUnionAsync("Google", "good-token");
        var classic = await twin.SignInAsync("Google", "good-token");

        var signedIn = result.Value.Should().BeOfType<ExternalSignedIn>().Subject;
        signedIn.Tokens.AccessToken.Should().NotBeNullOrEmpty();
        signedIn.Tokens.RefreshToken.Should().NotBeNullOrEmpty();
        signedIn.UserId.Should().Be(seeded.UserId);
        // The id handed to the caller is the one the access token was issued for.
        signedIn.UserId.Should().Be(SubjectOf(signedIn.Tokens.AccessToken));
        Kind(result).Should().Be(classic.Status);
    }

    [Fact]
    public async Task LinkExistingAccount_with_the_correct_password_is_ExternalSignedIn()
    {
        var (svc, stub, users, store, hasher, _) = ExternalLoginServiceTests.NewService();
        var (twin, twinStub, twinUsers, _, twinHasher, _) = ExternalLoginServiceTests.NewService();
        var seeded = users.SeedPasswordUser("u@x", hasher.Hash("pwd"));
        twinUsers.SeedPasswordUser("u@x", twinHasher.Hash("pwd"));
        stub.Responses["good-token"] = GoogleInfo();
        twinStub.Responses["good-token"] = GoogleInfo();

        var step1 = (ExternalPasswordRequired)(await svc.SignInAsUnionAsync("Google", "good-token")).Value!;
        var twinStep1 = await twin.SignInAsync("Google", "good-token");

        var result = await svc.LinkExistingAccountAsUnionAsync(step1.ContinuationToken, "pwd");
        var classic = await twin.LinkExistingAccountAsync(twinStep1.ContinuationToken!, "pwd");

        var signedIn = result.Value.Should().BeOfType<ExternalSignedIn>().Subject;
        signedIn.UserId.Should().Be(seeded.UserId);
        signedIn.UserId.Should().Be(SubjectOf(signedIn.Tokens.AccessToken));
        (await store.FindAsync("Google", "g-1"))!.UserId.Should().Be(seeded.UserId);
        Kind(result).Should().Be(classic.Status);
    }

    [Fact]
    public async Task LinkExistingAccount_with_a_wrong_password_is_ExternalSignInFailed_and_consumes_the_continuation()
    {
        var (svc, stub, users, store, hasher, _) = ExternalLoginServiceTests.NewService();
        var (twin, twinStub, twinUsers, _, twinHasher, _) = ExternalLoginServiceTests.NewService();
        users.SeedPasswordUser("u@x", hasher.Hash("pwd"));
        twinUsers.SeedPasswordUser("u@x", twinHasher.Hash("pwd"));
        stub.Responses["good-token"] = GoogleInfo();
        twinStub.Responses["good-token"] = GoogleInfo();

        var step1 = (ExternalPasswordRequired)(await svc.SignInAsUnionAsync("Google", "good-token")).Value!;
        var twinStep1 = await twin.SignInAsync("Google", "good-token");

        var wrong = await svc.LinkExistingAccountAsUnionAsync(step1.ContinuationToken, "wrong");
        var classicWrong = await twin.LinkExistingAccountAsync(twinStep1.ContinuationToken!, "wrong");

        wrong.Value.Should().BeOfType<ExternalSignInFailed>().Which.Error.Should().Be("invalid_password");
        classicWrong.Error.Should().Be("invalid_password");
        Kind(wrong).Should().Be(classicWrong.Status);
        (await store.FindAsync("Google", "g-1")).Should().BeNull();

        // The continuation is single-use and was spent by the failed attempt, exactly as with the
        // classic method: the right password on the same token is too late.
        var retry = await svc.LinkExistingAccountAsUnionAsync(step1.ContinuationToken, "pwd");
        var classicRetry = await twin.LinkExistingAccountAsync(twinStep1.ContinuationToken!, "pwd");

        retry.Value.Should().BeOfType<ExternalSignInFailed>().Which.Error.Should().Be("invalid_or_expired_continuation");
        classicRetry.Error.Should().Be("invalid_or_expired_continuation");
        Kind(retry).Should().Be(classicRetry.Status);
    }

    [Fact]
    public async Task CompleteRegistration_creates_the_user_and_is_ExternalSignedIn_with_the_new_UserId()
    {
        var (svc, stub, users, store, _, _) = ExternalLoginServiceTests.NewService();
        var (twin, twinStub, _, _, _, _) = ExternalLoginServiceTests.NewService();
        stub.Responses["good-token"] = GoogleInfo();
        twinStub.Responses["good-token"] = GoogleInfo();

        var step1 = (ExternalRegistrationRequired)(await svc.SignInAsUnionAsync("Google", "good-token")).Value!;
        var twinStep1 = await twin.SignInAsync("Google", "good-token");

        var result = await svc.CompleteRegistrationAsUnionAsync(step1.ContinuationToken, "neo");
        var classic = await twin.CompleteRegistrationAsync(twinStep1.ContinuationToken!, "neo");

        var signedIn = result.Value.Should().BeOfType<ExternalSignedIn>().Subject;
        var link = await store.FindAsync("Google", "g-1");
        link.Should().NotBeNull();
        signedIn.UserId.Should().Be(link!.UserId);
        (await users.GetByIdAsync(signedIn.UserId))!.Username.Should().Be("neo");
        signedIn.UserId.Should().Be(SubjectOf(signedIn.Tokens.AccessToken));
        Kind(result).Should().Be(classic.Status);
    }

    [Fact]
    public async Task LinkToUser_attaches_the_provider_and_is_ExternalSignedIn_for_that_user()
    {
        var (svc, stub, users, store, hasher, _) = ExternalLoginServiceTests.NewService();
        var (twin, twinStub, twinUsers, _, twinHasher, _) = ExternalLoginServiceTests.NewService();
        var user = users.SeedPasswordUser("u@x", hasher.Hash("pwd"));
        var twinUser = twinUsers.SeedPasswordUser("u@x", twinHasher.Hash("pwd"));
        stub.Responses["good-token"] = GoogleInfo();
        twinStub.Responses["good-token"] = GoogleInfo();

        var result = await svc.LinkToUserAsUnionAsync("Google", "good-token", user.UserId);
        var classic = await twin.LinkToUserAsync("Google", "good-token", twinUser.UserId);

        var signedIn = result.Value.Should().BeOfType<ExternalSignedIn>().Subject;
        signedIn.UserId.Should().Be(user.UserId);
        signedIn.UserId.Should().Be(SubjectOf(signedIn.Tokens.AccessToken));
        (await store.FindAsync("Google", "g-1"))!.UserId.Should().Be(user.UserId);
        Kind(result).Should().Be(classic.Status);
    }

    [Fact]
    public async Task LinkToUser_when_the_identity_is_linked_to_another_user_is_ExternalSignInFailed()
    {
        var (svc, stub, users, store, hasher, _) = ExternalLoginServiceTests.NewService();
        var (twin, twinStub, twinUsers, twinStore, twinHasher, _) = ExternalLoginServiceTests.NewService();
        var alice = users.SeedPasswordUser("alice@x", hasher.Hash("pwd"));
        var bob = users.SeedPasswordUser("bob@x", hasher.Hash("pwd"));
        var twinAlice = twinUsers.SeedPasswordUser("alice@x", twinHasher.Hash("pwd"));
        var twinBob = twinUsers.SeedPasswordUser("bob@x", twinHasher.Hash("pwd"));
        await store.CreateAsync(new ExternalLogin { UserId = alice.UserId, Provider = "Google", ProviderUserId = "g-1", Email = "alice@x" });
        await twinStore.CreateAsync(new ExternalLogin { UserId = twinAlice.UserId, Provider = "Google", ProviderUserId = "g-1", Email = "alice@x" });
        stub.Responses["good-token"] = GoogleInfo();
        twinStub.Responses["good-token"] = GoogleInfo();

        var result = await svc.LinkToUserAsUnionAsync("Google", "good-token", bob.UserId);
        var classic = await twin.LinkToUserAsync("Google", "good-token", twinBob.UserId);

        result.Value.Should().BeOfType<ExternalSignInFailed>().Which.Error.Should().Be("already_linked_to_other_user");
        classic.Error.Should().Be("already_linked_to_other_user");
        Kind(result).Should().Be(classic.Status);
    }

    [Fact]
    public async Task Exhaustive_switches_compile_for_both_unions_and_pick_the_case()
    {
        var (svc, stub, _, _, _, _) = ExternalLoginServiceTests.NewService();
        stub.Responses["good-token"] = GoogleInfo();

        // The shape of a sign-in endpoint: four arms, no `_ =>`, no `null =>`.
        var first = await svc.SignInAsUnionAsync("Google", "good-token");
        var next = first switch
        {
            ExternalSignedIn ok => $"done:{ok.UserId}",
            ExternalPasswordRequired p => $"password:{p.Email}",
            ExternalRegistrationRequired r => $"register:{r.Profile.DisplayName}",
            ExternalSignInFailed f => $"failed:{f.Error}",
        };
        next.Should().Be("register:User");

        // A completion step can only end two ways, and the type says so.
        var token = ((ExternalRegistrationRequired)first.Value!).ContinuationToken;
        var done = await svc.CompleteRegistrationAsUnionAsync(token, "neo") switch
        {
            ExternalSignedIn ok => ok.Tokens.AccessToken.Length > 0,
            ExternalSignInFailed => false,
        };
        done.Should().BeTrue();
    }
}
#endif
