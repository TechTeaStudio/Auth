using Microsoft.Extensions.Options;
using TechTeaStudio.Auth.Revocation;

namespace TechTeaStudio.Auth.Tokens;

/// <summary>Result of validating an email-confirmation token.</summary>
public sealed record EmailConfirmationResult(bool Success, string? UserId, string? Email);

/// <summary>
/// Issues and validates single-use, signed email-confirmation tokens. Default
/// lifetime is 24 hours; pass <see cref="EmailConfirmationTokenService"/>.Generate
/// a different lifetime to override per-call.
/// </summary>
public sealed class EmailConfirmationTokenService
{
    public const string Purpose = "email_confirmation";
    public static readonly TimeSpan DefaultLifetime = TimeSpan.FromHours(24);

    private readonly SignedTokenService _inner;

    public EmailConfirmationTokenService(IOptions<AuthOptions> options, IRevokedTokenStore? revoked = null)
        => _inner = new SignedTokenService(options, revoked);

    public string Generate(string userId, string email, TimeSpan? lifetime = null)
    {
        if (string.IsNullOrEmpty(userId)) throw new ArgumentException("userId required", nameof(userId));
        if (string.IsNullOrEmpty(email)) throw new ArgumentException("email required", nameof(email));
        return _inner.Generate(Purpose, lifetime ?? DefaultLifetime, new Dictionary<string, string>
        {
            ["uid"] = userId,
            ["email"] = email,
        });
    }

    public async Task<EmailConfirmationResult> ValidateAsync(string token, CancellationToken cancellationToken = default)
    {
        var payload = await _inner.ValidateAsync(token, Purpose, cancellationToken).ConfigureAwait(false);
        if (payload is null) return new EmailConfirmationResult(false, null, null);
        payload.TryGetValue("uid", out var uid);
        payload.TryGetValue("email", out var email);
        return new EmailConfirmationResult(true, uid, email);
    }
}
