using FluentAssertions;
using TechTeaStudio.Auth.Observability;
using Xunit;

namespace TechTeaStudio.Auth.Tests.Observability;

public class AuthDiagnosticsTests
{
    [Fact]
    public void Source_and_meter_share_stable_name()
    {
        AuthDiagnostics.SourceName.Should().Be("TechTeaStudio.Auth");
        AuthDiagnostics.ActivitySource.Name.Should().Be("TechTeaStudio.Auth");
        AuthDiagnostics.Meter.Name.Should().Be("TechTeaStudio.Auth");
    }

    [Fact]
    public void Counter_names_are_snake_case_total()
    {
        AuthDiagnostics.LoginSucceededTotal.Name.Should().Be("tts_auth_login_succeeded_total");
        AuthDiagnostics.LoginFailedTotal.Name.Should().Be("tts_auth_login_failed_total");
        AuthDiagnostics.TokensIssuedTotal.Name.Should().Be("tts_auth_tokens_issued_total");
        AuthDiagnostics.RefreshTokensRotatedTotal.Name.Should().Be("tts_auth_refresh_rotated_total");
        AuthDiagnostics.RefreshReuseDetectedTotal.Name.Should().Be("tts_auth_refresh_reuse_total");
        AuthDiagnostics.AccountsLockedTotal.Name.Should().Be("tts_auth_accounts_locked_total");
    }
}
