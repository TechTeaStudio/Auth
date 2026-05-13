using Microsoft.Extensions.Options;
using TechTeaStudio.Auth.Revocation;

namespace TechTeaStudio.Auth.Tokens;

/// <summary>Result of validating a password-reset token.</summary>
public sealed record PasswordResetResult(bool Success, string? UserId);

/// <summary>
/// Issues and validates single-use, signed password-reset tokens. Default
/// lifetime is 30 minutes — short enough that a stolen reset email is unusable
/// after a coffee break.
/// </summary>
public sealed class PasswordResetTokenService
{
    public const string Purpose = "password_reset";
    public static readonly TimeSpan DefaultLifetime = TimeSpan.FromMinutes(30);

    private readonly SignedTokenService _inner;

    public PasswordResetTokenService(IOptions<AuthOptions> options, IRevokedTokenStore? revoked = null)
        => _inner = new SignedTokenService(options, revoked);

    public string Generate(string userId, TimeSpan? lifetime = null)
    {
        if (string.IsNullOrEmpty(userId)) throw new ArgumentException("userId required", nameof(userId));
        return _inner.Generate(Purpose, lifetime ?? DefaultLifetime, new Dictionary<string, string>
        {
            ["uid"] = userId,
        });
    }

    public async Task<PasswordResetResult> ValidateAsync(string token, CancellationToken cancellationToken = default)
    {
        var payload = await _inner.ValidateAsync(token, Purpose, cancellationToken).ConfigureAwait(false);
        if (payload is null) return new PasswordResetResult(false, null);
        payload.TryGetValue("uid", out var uid);
        return new PasswordResetResult(true, uid);
    }
}
