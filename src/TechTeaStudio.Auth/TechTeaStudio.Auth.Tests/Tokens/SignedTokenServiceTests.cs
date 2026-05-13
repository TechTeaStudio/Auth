using FluentAssertions;
using TechTeaStudio.Auth.Revocation;
using TechTeaStudio.Auth.Tests.TestHelpers;
using TechTeaStudio.Auth.Tokens;
using Xunit;

namespace TechTeaStudio.Auth.Tests.Tokens;

public class SignedTokenServiceTests
{
    [Fact]
    public async Task Generate_then_validate_round_trips()
    {
        var store = new InMemoryRevokedTokenStore();
        var svc = new SignedTokenService(TestAuthOptions.WrapOptions(), store);

        var token = svc.Generate("test", TimeSpan.FromMinutes(5), new Dictionary<string, string> { ["x"] = "y" });
        var payload = await svc.ValidateAsync(token, "test");

        payload.Should().NotBeNull();
        payload!["x"].Should().Be("y");
    }

    [Fact]
    public async Task Cannot_replay_after_use()
    {
        var store = new InMemoryRevokedTokenStore();
        var svc = new SignedTokenService(TestAuthOptions.WrapOptions(), store);
        var token = svc.Generate("p", TimeSpan.FromMinutes(5));

        (await svc.ValidateAsync(token, "p")).Should().NotBeNull();
        (await svc.ValidateAsync(token, "p")).Should().BeNull();
    }

    [Fact]
    public async Task Wrong_purpose_fails()
    {
        var store = new InMemoryRevokedTokenStore();
        var svc = new SignedTokenService(TestAuthOptions.WrapOptions(), store);
        var token = svc.Generate("password_reset", TimeSpan.FromMinutes(5));
        (await svc.ValidateAsync(token, "email_confirmation")).Should().BeNull();
    }

    [Fact]
    public async Task Expired_token_fails()
    {
        var store = new InMemoryRevokedTokenStore();
        var svc = new SignedTokenService(TestAuthOptions.WrapOptions(), store);
        var token = svc.Generate("p", TimeSpan.FromMilliseconds(20));
        await Task.Delay(50);
        (await svc.ValidateAsync(token, "p")).Should().BeNull();
    }

    [Fact]
    public async Task Tampered_signature_fails()
    {
        var store = new InMemoryRevokedTokenStore();
        var svc = new SignedTokenService(TestAuthOptions.WrapOptions(), store);
        var token = svc.Generate("p", TimeSpan.FromMinutes(5));
        var parts = token.Split('.');
        var tampered = parts[0] + "." + new string(parts[1].Reverse().ToArray());
        (await svc.ValidateAsync(tampered, "p")).Should().BeNull();
    }
}

public class EmailConfirmationTokenServiceTests
{
    [Fact]
    public async Task Round_trips_userId_and_email()
    {
        var svc = new EmailConfirmationTokenService(TestAuthOptions.WrapOptions(), new InMemoryRevokedTokenStore());
        var token = svc.Generate("u-1", "u@x");
        var r = await svc.ValidateAsync(token);
        r.Success.Should().BeTrue();
        r.UserId.Should().Be("u-1");
        r.Email.Should().Be("u@x");
    }
}

public class PasswordResetTokenServiceTests
{
    [Fact]
    public async Task Round_trips_userId()
    {
        var svc = new PasswordResetTokenService(TestAuthOptions.WrapOptions(), new InMemoryRevokedTokenStore());
        var token = svc.Generate("u-1");
        var r = await svc.ValidateAsync(token);
        r.Success.Should().BeTrue();
        r.UserId.Should().Be("u-1");
    }

    [Fact]
    public async Task Reset_token_rejected_by_email_service()
    {
        var revoked = new InMemoryRevokedTokenStore();
        var reset = new PasswordResetTokenService(TestAuthOptions.WrapOptions(), revoked);
        var email = new EmailConfirmationTokenService(TestAuthOptions.WrapOptions(), revoked);

        var t = reset.Generate("u");
        (await email.ValidateAsync(t)).Success.Should().BeFalse();
    }
}
