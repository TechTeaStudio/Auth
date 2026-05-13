namespace TechTeaStudio.Auth.TwoFactor;

/// <summary>Bundle returned at the start of a 2FA enrollment.</summary>
public sealed record TwoFactorEnrollmentStart(string Secret, string OtpAuthUri, string[] RecoveryCodes);

/// <summary>
/// Contract for the per-app 2FA enrollment workflow. The library does not
/// mandate a user table — concrete implementations bridge to the consuming app's
/// user store and persist <c>TwoFactorSecret</c>, <c>TwoFactorEnabled</c>, and
/// the recovery-code hashes.
/// </summary>
public interface I2FaEnrollmentService
{
    /// <summary>Generates a secret + provisioning URI + recovery codes. Returns them to the UI exactly once.</summary>
    Task<TwoFactorEnrollmentStart> BeginEnrollmentAsync(string userId, string issuer, string accountName, CancellationToken cancellationToken = default);

    /// <summary>Verifies the TOTP code typed by the user and marks 2FA enabled when correct.</summary>
    Task<bool> ConfirmEnrollmentAsync(string userId, string code, CancellationToken cancellationToken = default);

    /// <summary>Disables 2FA for the user (e.g. after recovery-code use). Removes the stored secret.</summary>
    Task DisableAsync(string userId, CancellationToken cancellationToken = default);
}

/// <summary>Helper for building <c>otpauth://</c> provisioning URIs consumed by Authenticator apps.</summary>
public static class OtpAuthUri
{
    /// <summary>Builds a TOTP <c>otpauth://</c> URI. Secret must be Base32-encoded.</summary>
    public static string Build(string issuer, string accountName, string base32Secret, int digits = TotpGenerator.DefaultDigits, int periodSeconds = TotpGenerator.DefaultPeriodSeconds)
    {
        if (string.IsNullOrEmpty(issuer)) throw new ArgumentException("issuer required", nameof(issuer));
        if (string.IsNullOrEmpty(accountName)) throw new ArgumentException("accountName required", nameof(accountName));
        if (string.IsNullOrEmpty(base32Secret)) throw new ArgumentException("base32Secret required", nameof(base32Secret));

        var label = Uri.EscapeDataString($"{issuer}:{accountName}");
        var issuerEsc = Uri.EscapeDataString(issuer);
        return $"otpauth://totp/{label}?secret={base32Secret}&issuer={issuerEsc}&algorithm=SHA1&digits={digits}&period={periodSeconds}";
    }

    /// <summary>RFC 4648 base32, padding stripped. Used for TOTP secrets in provisioning URIs.</summary>
    public static string ToBase32(byte[] bytes)
    {
        const string alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        var sb = new System.Text.StringBuilder();
        int buffer = 0, bits = 0;
        for (var i = 0; i < bytes.Length; i++)
        {
            buffer = (buffer << 8) | bytes[i];
            bits += 8;
            while (bits >= 5)
            {
                bits -= 5;
                sb.Append(alphabet[(buffer >> bits) & 0x1F]);
            }
        }
        if (bits > 0) sb.Append(alphabet[(buffer << (5 - bits)) & 0x1F]);
        return sb.ToString();
    }
}
